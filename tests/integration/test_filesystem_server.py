"""Integration and security test suite for FilesystemMCPServer."""
import asyncio
import json
import os
import sys
from pathlib import Path
import pytest

from mcp.types import CallToolRequestParams, PaginatedRequestParams
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession

from toolbridge.upstreams.filesystem.server import FilesystemMCPServer, ALL_FILESYSTEM_TOOLS


@pytest.fixture
def fs_server(tmp_path: Path):
    """Fixture initializing a FilesystemMCPServer with a temporary sandbox."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    # Pre-populate sample structure
    docs = sandbox / "docs"
    docs.mkdir()
    (docs / "intro.md").write_text("# Welcome to ToolBridge\nSafe workspace test.", encoding="utf-8")
    (sandbox / "data.json").write_text('{"status": "ok"}', encoding="utf-8")

    server_app = FilesystemMCPServer(sandbox_root=sandbox)
    return server_app, sandbox


@pytest.mark.integration
@pytest.mark.asyncio
async def test_filesystem_tool_discovery(fs_server):
    """Verify tool discovery exposes all five filesystem tools with valid schemas."""
    server_app, _ = fs_server
    result = await server_app._handle_list_tools(None, PaginatedRequestParams())

    tool_names = [t.name for t in result.tools]
    assert "list_directory" in tool_names
    assert "read_file" in tool_names
    assert "write_file" in tool_names
    assert "search_files" in tool_names
    assert "get_file_info" in tool_names

    for t in result.tools:
        assert t.description
        assert "type" in t.input_schema
        assert t.input_schema["type"] == "object"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_list_directory_tool(fs_server):
    """Verify directory listing works for root and subdirectories."""
    server_app, _ = fs_server

    # List root
    params = CallToolRequestParams(name="list_directory", arguments={"path": "."})
    res = await server_app._handle_call_tool(None, params)
    assert res.is_error is False

    data = json.loads(res.content[0].text)
    assert data["total_entries"] == 2
    names = [e["name"] for e in data["entries"]]
    assert "docs" in names
    assert "data.json" in names

    # Recursive list
    rec_params = CallToolRequestParams(name="list_directory", arguments={"path": ".", "recursive": True})
    rec_res = await server_app._handle_call_tool(None, rec_params)
    assert rec_res.is_error is False
    rec_data = json.loads(rec_res.content[0].text)
    rec_paths = [e["path"] for e in rec_data["entries"]]
    assert "docs/intro.md" in rec_paths


@pytest.mark.integration
@pytest.mark.asyncio
async def test_read_file_tool(fs_server):
    """Verify reading existing files returns correct text content."""
    server_app, _ = fs_server

    params = CallToolRequestParams(name="read_file", arguments={"path": "docs/intro.md"})
    res = await server_app._handle_call_tool(None, params)
    assert res.is_error is False
    assert "# Welcome to ToolBridge" in res.content[0].text


@pytest.mark.integration
@pytest.mark.asyncio
async def test_write_file_tool_and_atomic_replace(fs_server):
    """Verify writing files creates parent directories and writes content atomically."""
    server_app, sandbox = fs_server

    # Write new nested file
    write_args = {
        "path": "reports/2026/summary.txt",
        "content": "Quarterly summary: secure operations.",
        "create_parents": True,
        "overwrite": True,
    }
    params = CallToolRequestParams(name="write_file", arguments=write_args)
    res = await server_app._handle_call_tool(None, params)
    assert res.is_error is False

    result_json = json.loads(res.content[0].text)
    assert result_json["status"] == "success"
    assert result_json["path"] == "reports/2026/summary.txt"

    # Verify content on disk
    created_path = sandbox / "reports" / "2026" / "summary.txt"
    assert created_path.exists()
    assert created_path.read_text(encoding="utf-8") == "Quarterly summary: secure operations."

    # Test overwrite=False
    no_overwrite_args = {
        "path": "reports/2026/summary.txt",
        "content": "New content that should fail",
        "overwrite": False,
    }
    fail_res = await server_app._handle_call_tool(
        None, CallToolRequestParams(name="write_file", arguments=no_overwrite_args)
    )
    assert fail_res.is_error is True
    assert "File already exists" in fail_res.content[0].text


@pytest.mark.integration
@pytest.mark.asyncio
async def test_search_files_tool(fs_server):
    """Verify searching files by pattern and content."""
    server_app, _ = fs_server

    # Name search
    name_params = CallToolRequestParams(
        name="search_files", arguments={"query": "*.md", "search_content": False}
    )
    name_res = await server_app._handle_call_tool(None, name_params)
    assert name_res.is_error is False
    name_data = json.loads(name_res.content[0].text)
    assert name_data["total_matches"] == 1
    assert name_data["results"][0]["path"] == "docs/intro.md"

    # Content search
    content_params = CallToolRequestParams(
        name="search_files", arguments={"query": "ToolBridge", "search_content": True}
    )
    content_res = await server_app._handle_call_tool(None, content_params)
    assert content_res.is_error is False
    content_data = json.loads(content_res.content[0].text)
    assert content_data["total_matches"] >= 1
    assert content_data["results"][0]["matches"][0]["line_number"] == 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_file_info_tool(fs_server):
    """Verify file info returns accurate metadata."""
    server_app, _ = fs_server

    params = CallToolRequestParams(name="get_file_info", arguments={"path": "docs/intro.md"})
    res = await server_app._handle_call_tool(None, params)
    assert res.is_error is False

    info = json.loads(res.content[0].text)
    assert info["name"] == "intro.md"
    assert info["is_file"] is True
    assert info["is_directory"] is False
    assert info["size_bytes"] > 0
    assert "created_at" in info
    assert "modified_at" in info


@pytest.mark.security
@pytest.mark.asyncio
@pytest.mark.parametrize("malicious_path", [
    "../../outside_secret.txt",
    "..\\..\\outside_secret.txt",
    "/etc/passwd",
    "C:/Windows/System32",
    "docs/../../../outside_secret.txt",
    "docs/intro.md\0.txt",
    "CON",
    "NUL",
])
async def test_filesystem_server_traversal_attacks_prevented(fs_server, malicious_path: str):
    """Verify all tools intercept and report security errors for malicious paths."""
    server_app, _ = fs_server

    for tool in ["read_file", "get_file_info", "list_directory"]:
        params = CallToolRequestParams(name=tool, arguments={"path": malicious_path})
        res = await server_app._handle_call_tool(None, params)
        assert res.is_error is True, f"Tool {tool} failed to reject malicious path {malicious_path}"
        assert "Security Violation" in res.content[0].text

    # Test write_file also blocks malicious destination
    write_params = CallToolRequestParams(
        name="write_file", arguments={"path": malicious_path, "content": "malicious"}
    )
    write_res = await server_app._handle_call_tool(None, write_params)
    assert write_res.is_error is True
    assert "Security Violation" in write_res.content[0].text


@pytest.mark.integration
@pytest.mark.asyncio
async def test_stdio_filesystem_server_e2e(tmp_path: Path):
    """End-to-End test running the Filesystem Server in a subprocess via MCP stdio_client."""
    sandbox = tmp_path / "e2e_sandbox"
    sandbox.mkdir()
    (sandbox / "hello.txt").write_text("Hello from End-to-End MCP Client!", encoding="utf-8")

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "toolbridge.upstreams.filesystem.server"],
        env={
            **os.environ,
            "FILESYSTEM_SANDBOX_ROOT": str(sandbox),
            "PYTHONUNBUFFERED": "1",
        },
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # 1. Initialize Handshake
            await session.initialize()

            # 2. Tool Discovery
            tools_res = await session.list_tools()
            tool_names = [t.name for t in tools_res.tools]
            assert "read_file" in tool_names
            assert "write_file" in tool_names

            # 3. Read File Execution
            read_res = await session.call_tool("read_file", {"path": "hello.txt"})
            assert read_res.is_error is False
            assert read_res.content[0].text == "Hello from End-to-End MCP Client!"

            # 4. Write File Execution
            write_res = await session.call_tool(
                "write_file",
                {"path": "e2e_output.txt", "content": "Written via stdio MCP Client"},
            )
            assert write_res.is_error is False

            # Verify file created on disk
            written_file = sandbox / "e2e_output.txt"
            assert written_file.exists()
            assert written_file.read_text(encoding="utf-8") == "Written via stdio MCP Client"

            # 5. Security Traversal Blocked Over stdio
            attack_res = await session.call_tool("read_file", {"path": "../../outside.txt"})
            assert attack_res.is_error is True
            assert "Security Violation" in attack_res.content[0].text


@pytest.mark.security
@pytest.mark.asyncio
async def test_search_files_bounds_and_depth(fs_server):
    """Verify search_files enforces depth bounds and result count limits."""
    server_app, sandbox = fs_server

    # Create deep nested structure
    deep_path = sandbox / "a" / "b" / "c" / "d" / "e" / "f"
    deep_path.mkdir(parents=True)
    (deep_path / "deep_target.txt").write_text("deep content", encoding="utf-8")

    # Search with max_depth=2 should NOT find deep_target.txt
    res = await server_app._handle_call_tool(
        None,
        CallToolRequestParams(
            name="search_files",
            arguments={"query": "deep_target.txt", "max_depth": 2},
        ),
    )
    assert res.is_error is False
    data = json.loads(res.content[0].text)
    assert data["total_matches"] == 0

    # Search with max_depth=10 should find it
    res2 = await server_app._handle_call_tool(
        None,
        CallToolRequestParams(
            name="search_files",
            arguments={"query": "deep_target.txt", "max_depth": 10},
        ),
    )
    assert res2.is_error is False
    data2 = json.loads(res2.content[0].text)
    assert data2["total_matches"] == 1


@pytest.mark.security
@pytest.mark.asyncio
async def test_write_file_refuses_symlink_overwrite(fs_server, monkeypatch):
    """Verify write_file strictly refuses to overwrite symlink destinations."""
    server_app, _ = fs_server

    # Mock Path.is_symlink to simulate symlink destination
    real_is_symlink = Path.is_symlink

    def mock_is_symlink(self):
        if self.name == "symlink_file.txt":
            return True
        return real_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", mock_is_symlink)

    res = await server_app._handle_call_tool(
        None,
        CallToolRequestParams(
            name="write_file",
            arguments={"path": "symlink_file.txt", "content": "malicious payload"},
        ),
    )
    assert res.is_error is True
    assert "symlink" in res.content[0].text.lower()

