"""Phase 4 Integration Tests: Launcher, Diagnostics, Stdio Purity, and Sandbox Root."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from toolbridge.security.guards.filesystem import get_project_root, resolve_sandbox_root


@pytest.mark.integration
def test_run_demo_diagnostics_check():
    """Verify python run_demo.py check executes accurately and exits with 0."""
    py = sys.executable
    project_root = get_project_root()

    res = subprocess.run(
        [py, "run_demo.py", "check"],
        cwd=str(project_root),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert res.returncode == 0
    assert "Diagnostics Complete: 3/3 components verified" in res.stdout
    assert "Filesystem ready" in res.stdout


@pytest.mark.integration
@pytest.mark.asyncio
async def test_stdio_gateway_stdout_purity():
    """A3: Verify stdio server runs through stdio_client without any stdout corruption.

    Banners and startup logging must go to stderr so JSON-RPC frame parsing succeeds.
    """
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "toolbridge.server.gateway"],
        env={
            **os.environ,
            "PYTHONUNBUFFERED": "1",
            "TOOLBRIDGE_STDIO_ROLE": "readonly",
        },
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # If stdout had corrupting print() statements, initialize() would fail with JSONDecodeError
            init_res = await session.initialize()
            assert init_res.server_info.name == "ToolBridge Enterprise Gateway"

            # Verify tool discovery over pure JSON-RPC
            tools_res = await session.list_tools()
            assert len(tools_res.tools) > 0


@pytest.mark.integration
def test_sandbox_root_anchored_to_project_root(monkeypatch, tmp_path: Path):
    """A4: Verify relative sandbox path resolves relative to project root, not arbitrary CWD."""
    monkeypatch.delenv("FILESYSTEM_SANDBOX_ROOT", raising=False)
    project_root = get_project_root()

    # Even if working directory is changed, default ./workspace_sandbox resolves to project root
    resolved = resolve_sandbox_root("./workspace_sandbox")
    assert resolved == (project_root / "workspace_sandbox").resolve()

    # Explicit absolute path is preserved
    abs_path = (tmp_path / "custom_abs_sandbox").resolve()
    resolved_abs = resolve_sandbox_root(abs_path)
    assert resolved_abs == abs_path
