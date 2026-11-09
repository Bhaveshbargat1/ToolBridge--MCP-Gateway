"""Controlled, restricted Filesystem MCP Server adhering strictly to MCP SDK v2."""
from __future__ import annotations

import asyncio
import fnmatch
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from mcp.server.lowlevel.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)

from toolbridge.security.guards.filesystem import FilesystemGuard, PathSecurityError

# Standard Tool Definitions
TOOL_LIST_DIRECTORY = Tool(
    name="list_directory",
    description="List files and subdirectories inside the designated workspace.",
    input_schema={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Relative directory path to list. Leave empty or '.' for workspace root.",
                "default": "",
            },
            "recursive": {
                "type": "boolean",
                "description": "Whether to list subdirectories recursively.",
                "default": False,
            },
            "max_depth": {
                "type": "integer",
                "description": "Maximum directory depth for recursive listing (1-10).",
                "default": 3,
                "minimum": 1,
                "maximum": 10,
            },
        },
    },
)

TOOL_READ_FILE = Tool(
    name="read_file",
    description="Read text content from a file inside the designated workspace.",
    input_schema={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Relative path of the file to read.",
            },
            "encoding": {
                "type": "string",
                "description": "File character encoding (default: utf-8).",
                "default": "utf-8",
            },
            "max_bytes": {
                "type": "integer",
                "description": "Maximum bytes to read (cannot exceed server limit).",
                "default": 5 * 1024 * 1024,
            },
        },
        "required": ["path"],
    },
)

TOOL_WRITE_FILE = Tool(
    name="write_file",
    description="Write text content to a file inside the designated workspace using atomic write.",
    input_schema={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Relative destination path of the file to write.",
            },
            "content": {
                "type": "string",
                "description": "The text content to write into the file.",
            },
            "overwrite": {
                "type": "boolean",
                "description": "Whether to overwrite the file if it already exists.",
                "default": True,
            },
            "create_parents": {
                "type": "boolean",
                "description": "Whether to automatically create missing parent directories.",
                "default": True,
            },
        },
        "required": ["path", "content"],
    },
)

TOOL_SEARCH_FILES = Tool(
    name="search_files",
    description="Search for files by name/glob pattern or content inside the designated workspace.",
    input_schema={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Filename pattern (e.g. '*.py' or substring) or text to search for.",
            },
            "path": {
                "type": "string",
                "description": "Relative path to start searching from. Default is workspace root.",
                "default": "",
            },
            "search_content": {
                "type": "boolean",
                "description": "If True, searches inside file contents instead of just matching filenames.",
                "default": False,
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum matching entries to return (default: 50).",
                "default": 50,
                "minimum": 1,
                "maximum": 500,
            },
            "max_depth": {
                "type": "integer",
                "description": "Maximum directory traversal depth (1-10, default: 5).",
                "default": 5,
                "minimum": 1,
                "maximum": 10,
            },
            "timeout_seconds": {
                "type": "number",
                "description": "Maximum wall-clock execution time in seconds (default: 5.0, max: 15.0).",
                "default": 5.0,
                "minimum": 0.1,
                "maximum": 15.0,
            },
        },
        "required": ["query"],
    },
)

TOOL_GET_FILE_INFO = Tool(
    name="get_file_info",
    description="Retrieve detailed metadata (size, timestamps, permissions) for a workspace path.",
    input_schema={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Relative path of the file or directory.",
            },
        },
        "required": ["path"],
    },
)

ALL_FILESYSTEM_TOOLS: list[Tool] = [
    TOOL_LIST_DIRECTORY,
    TOOL_READ_FILE,
    TOOL_WRITE_FILE,
    TOOL_SEARCH_FILES,
    TOOL_GET_FILE_INFO,
]


class FilesystemMCPServer:
    """Encapsulates the controlled Filesystem MCP Server and its security-guarded tool handlers."""

    def __init__(self, sandbox_root: str | Path | None = None) -> None:
        """Initialize the server with a dedicated sandbox root directory."""
        root = sandbox_root or os.environ.get("FILESYSTEM_SANDBOX_ROOT", "./workspace_sandbox")
        self.guard = FilesystemGuard(sandbox_root=root)
        self.server = Server(
            name="toolbridge-filesystem",
            version="0.1.0",
            on_list_tools=self._handle_list_tools,
            on_call_tool=self._handle_call_tool,
        )

    async def _handle_list_tools(
        self,
        ctx: ServerRequestContext,
        params: PaginatedRequestParams | None,
    ) -> ListToolsResult:
        """Return the catalog of filesystem tools."""
        return ListToolsResult(tools=ALL_FILESYSTEM_TOOLS)

    async def _handle_call_tool(
        self,
        ctx: ServerRequestContext,
        params: CallToolRequestParams,
    ) -> CallToolResult:
        """Intercept and route tool calls to secured implementation methods."""
        tool_name = params.name
        args = params.arguments or {}

        try:
            if tool_name == "list_directory":
                return await self.tool_list_directory(args)
            elif tool_name == "read_file":
                return await self.tool_read_file(args)
            elif tool_name == "write_file":
                return await self.tool_write_file(args)
            elif tool_name == "search_files":
                return await self.tool_search_files(args)
            elif tool_name == "get_file_info":
                return await self.tool_get_file_info(args)
            else:
                return self._error_result(f"Unknown filesystem tool: '{tool_name}'")
        except PathSecurityError as e:
            return self._error_result(f"Security Violation: {e}")
        except FileNotFoundError as e:
            return self._error_result(f"Not Found: {e}")
        except FileExistsError as e:
            return self._error_result(f"File Exists: {e}")
        except PermissionError as e:
            return self._error_result(f"Permission Denied: {e}")
        except Exception as e:
            return self._error_result(f"Execution Error: {e}")

    # --- Tool Implementations ---

    async def tool_list_directory(self, args: Mapping[str, Any]) -> CallToolResult:
        """List contents of a directory safely within the sandbox."""
        untrusted_path = args.get("path", "")
        recursive = bool(args.get("recursive", False))
        max_depth = min(max(int(args.get("max_depth", 3)), 1), 10)

        safe_dir = self.guard.resolve_safe_path(untrusted_path, must_exist=True)
        if not safe_dir.is_dir():
            raise NotADirectoryError(f"Target is not a directory: '{untrusted_path}'")

        entries: list[dict[str, Any]] = []

        if not recursive:
            for item in sorted(safe_dir.iterdir()):
                entries.append(self._entry_metadata(item))
        else:
            base_parts_len = len(safe_dir.parts)
            for root, dirs, files in os.walk(safe_dir):
                root_path = Path(root)
                current_depth = len(root_path.parts) - base_parts_len
                if current_depth >= max_depth:
                    dirs.clear()  # Do not descend further

                for d in sorted(dirs):
                    dir_path = root_path / d
                    entries.append(self._entry_metadata(dir_path))
                for f in sorted(files):
                    file_path = root_path / f
                    entries.append(self._entry_metadata(file_path))

        payload = {
            "directory": self.guard.get_relative_path(safe_dir) or ".",
            "total_entries": len(entries),
            "entries": entries,
        }
        return self._success_result(json.dumps(payload, indent=2))

    async def tool_read_file(self, args: Mapping[str, Any]) -> CallToolResult:
        """Read file contents safely, enforcing max size limits."""
        untrusted_path = args.get("path")
        if not untrusted_path:
            return self._error_result("Missing required argument: 'path'")

        encoding = str(args.get("encoding", "utf-8"))
        max_bytes = min(
            int(args.get("max_bytes", self.guard.max_file_size_bytes)),
            self.guard.max_file_size_bytes,
        )

        safe_path = self.guard.resolve_safe_path(untrusted_path, must_exist=True, allow_root=False)
        if not safe_path.is_file():
            return self._error_result(f"Target is not a regular file: '{untrusted_path}'")

        if safe_path.is_symlink():
            return self._error_result(f"Target is a symlink: '{untrusted_path}'")

        file_size = safe_path.stat().st_size
        if file_size > max_bytes:
            return self._error_result(
                f"File size ({file_size} bytes) exceeds the allowed limit ({max_bytes} bytes)."
            )

        open_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            open_flags |= os.O_NOFOLLOW

        try:
            fd = os.open(str(safe_path), open_flags)
            try:
                with open(fd, mode="r", encoding=encoding, errors="strict", closefd=False) as f:
                    content = f.read(max_bytes + 1)
                    if len(content.encode(encoding)) > max_bytes:
                        return self._error_result(
                            f"File size exceeds the allowed limit ({max_bytes} bytes)."
                        )
            finally:
                os.close(fd)
        except OSError as e:
            return self._error_result(f"Failed to read file: {e}")
        except UnicodeDecodeError as e:
            return self._error_result(
                f"Binary or unsupported encoding: Unable to decode file as '{encoding}': {e}"
            )

        return self._success_result(content)

    async def tool_write_file(self, args: Mapping[str, Any]) -> CallToolResult:
        """Atomically write text into a file within the sandbox."""
        untrusted_path = args.get("path")
        if not untrusted_path:
            return self._error_result("Missing required argument: 'path'")

        content = args.get("content")
        if content is None:
            return self._error_result("Missing required argument: 'content'")

        overwrite = bool(args.get("overwrite", True))
        create_parents = bool(args.get("create_parents", True))

        safe_path = self.guard.resolve_safe_path(untrusted_path, must_exist=False, allow_root=False)

        # Check existing file overwrite policy and reject existing symlinks
        if safe_path.is_symlink():
            raise PathSecurityError(f"Target path '{untrusted_path}' is a symlink. Overwriting symlinks is prohibited.")

        if safe_path.exists():
            if not overwrite:
                raise FileExistsError(f"File already exists and overwrite=False: '{untrusted_path}'")
            if safe_path.is_dir():
                return self._error_result(f"Destination is an existing directory: '{untrusted_path}'")

        # Create parent directories safely if requested
        parent_dir = safe_path.parent
        if not parent_dir.exists():
            if not create_parents:
                return self._error_result(f"Parent directory does not exist: '{parent_dir.name}'")
            # Verify parent resolves within sandbox before creating
            self.guard.resolve_safe_path(self.guard.get_relative_path(parent_dir), must_exist=False)
            parent_dir.mkdir(parents=True, exist_ok=True)

        content_bytes = content.encode("utf-8")
        if len(content_bytes) > self.guard.max_file_size_bytes:
            return self._error_result(
                f"Content size ({len(content_bytes)} bytes) exceeds max limit ({self.guard.max_file_size_bytes} bytes)."
            )

        # Atomic write: use tempfile.mkstemp inside parent directory, fsync, then replace
        fd, tmp_path_str = tempfile.mkstemp(
            dir=parent_dir,
            prefix=".tb_atomic_",
            suffix=".tmp",
        )
        try:
            with open(fd, "w", encoding="utf-8", closefd=True) as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())

            # Double-check target is not a symlink right before atomic replace
            if safe_path.is_symlink():
                raise PathSecurityError(f"Target path '{untrusted_path}' is a symlink. Overwriting symlinks is prohibited.")

            os.replace(tmp_path_str, safe_path)
        except Exception:
            if os.path.exists(tmp_path_str):
                try:
                    os.unlink(tmp_path_str)
                except OSError:
                    pass
            raise

        res_info = {
            "status": "success",
            "path": self.guard.get_relative_path(safe_path),
            "bytes_written": len(content_bytes),
            "overwritten": safe_path.exists(),
        }
        return self._success_result(json.dumps(res_info, indent=2))

    async def tool_search_files(self, args: Mapping[str, Any]) -> CallToolResult:
        """Search for files by name/glob or content within the sandbox."""
        query = args.get("query")
        if not query:
            return self._error_result("Missing required argument: 'query'")

        search_path = args.get("path", "")
        search_content = bool(args.get("search_content", False))
        max_results = min(max(int(args.get("max_results", 50)), 1), 500)
        max_depth = min(max(int(args.get("max_depth", 5)), 1), 10)
        timeout_seconds = min(max(float(args.get("timeout_seconds", 5.0)), 0.1), 15.0)
        start_time = time.monotonic()

        safe_start = self.guard.resolve_safe_path(search_path, must_exist=True)
        if not safe_start.is_dir():
            safe_start = safe_start.parent

        matches: list[dict[str, Any]] = []
        timed_out = False
        base_depth = len(safe_start.parts)

        for root, dirs, files in os.walk(safe_start):
            current_depth = len(Path(root).parts) - base_depth
            if current_depth >= max_depth:
                dirs.clear()  # Do not descend further

            if time.monotonic() - start_time > timeout_seconds:
                timed_out = True
                break

            for filename in sorted(files):
                if time.monotonic() - start_time > timeout_seconds:
                    timed_out = True
                    break

                if len(matches) >= max_results:
                    break

                file_path = Path(root) / filename
                rel_path = self.guard.get_relative_path(file_path)

                # Match by filename pattern / substring
                is_name_match = fnmatch.fnmatch(filename, query) or (query.lower() in filename.lower())

                if not search_content:
                    if is_name_match:
                        matches.append({
                            "path": rel_path,
                            "type": "filename_match",
                            "size_bytes": file_path.stat().st_size,
                        })
                else:
                    # Content search inside text files
                    if file_path.stat().st_size > 1024 * 1024:
                        continue  # Skip files > 1MB during grep to prevent lag

                    try:
                        text = file_path.read_text(encoding="utf-8", errors="ignore")
                        if query.lower() in text.lower():
                            # Find matching line numbers
                            matching_lines = []
                            for idx, line in enumerate(text.splitlines(), start=1):
                                if query.lower() in line.lower():
                                    matching_lines.append({
                                        "line_number": idx,
                                        "snippet": line.strip()[:150],
                                    })
                                    if len(matching_lines) >= 3:
                                        break
                            matches.append({
                                "path": rel_path,
                                "type": "content_match",
                                "matches": matching_lines,
                            })
                    except Exception:
                        continue

            if len(matches) >= max_results or timed_out:
                break

        payload = {
            "query": query,
            "search_content": search_content,
            "total_matches": len(matches),
            "timed_out": timed_out,
            "results": matches,
        }
        return self._success_result(json.dumps(payload, indent=2))

    async def tool_get_file_info(self, args: Mapping[str, Any]) -> CallToolResult:
        """Inspect file or directory metadata."""
        untrusted_path = args.get("path")
        if not untrusted_path:
            return self._error_result("Missing required argument: 'path'")

        safe_path = self.guard.resolve_safe_path(untrusted_path, must_exist=True)
        stat = safe_path.stat()

        created_dt = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat()
        modified_dt = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()

        info = {
            "name": safe_path.name or ".",
            "relative_path": self.guard.get_relative_path(safe_path) or ".",
            "is_file": safe_path.is_file(),
            "is_directory": safe_path.is_dir(),
            "size_bytes": stat.st_size if safe_path.is_file() else None,
            "created_at": created_dt,
            "modified_at": modified_dt,
            "permissions": oct(stat.st_mode)[-3:],
        }
        return self._success_result(json.dumps(info, indent=2))

    # --- Helpers ---

    def _entry_metadata(self, path: Path) -> dict[str, Any]:
        """Generate summary metadata dictionary for a file or directory entry."""
        stat = path.stat()
        return {
            "name": path.name,
            "path": self.guard.get_relative_path(path),
            "is_directory": path.is_dir(),
            "size_bytes": stat.st_size if path.is_file() else None,
            "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        }

    def _success_result(self, text: str) -> CallToolResult:
        """Format a successful CallToolResult."""
        return CallToolResult(
            content=[TextContent(type="text", text=text)],
            is_error=False,
        )

    def _error_result(self, error_message: str) -> CallToolResult:
        """Format an error CallToolResult."""
        return CallToolResult(
            content=[TextContent(type="text", text=error_message)],
            is_error=True,
        )


def create_filesystem_server(sandbox_root: str | Path | None = None) -> Server:
    """Factory creating an MCP SDK v2 low-level Server for the sandboxed filesystem."""
    if sandbox_root is None:
        sandbox_root = os.environ.get("FILESYSTEM_SANDBOX_ROOT", "./workspace_sandbox")
    app = FilesystemMCPServer(sandbox_root=sandbox_root)
    return app.server


async def main() -> None:
    """Run the sandboxed Filesystem MCP server over stdio."""
    sandbox_root = os.environ.get("FILESYSTEM_SANDBOX_ROOT", "./workspace_sandbox")
    app = FilesystemMCPServer(sandbox_root=sandbox_root)

    async with stdio_server() as (read_stream, write_stream):
        init_options = app.server.create_initialization_options()
        await app.server.run(read_stream, write_stream, init_options)


if __name__ == "__main__":
    asyncio.run(main())
