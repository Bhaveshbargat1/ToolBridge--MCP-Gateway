"""Baseline verification test for ToolBridge environment."""
import sys
import pytest


@pytest.mark.unit
def test_python_version() -> None:
    """Ensure Python version is 3.12 or newer."""
    assert sys.version_info >= (3, 12), f"Expected Python 3.12+, got {sys.version_info}"


@pytest.mark.unit
def test_mcp_sdk_v2_imports() -> None:
    """Verify that official MCP Python SDK v2 core modules are present."""
    import mcp
    from mcp.server.lowlevel import Server
    from mcp.client.session import ClientSession
    from mcp.types import Tool, TextContent, CallToolResult

    assert Server is not None
    assert ClientSession is not None
    assert Tool is not None
    assert TextContent is not None
    assert CallToolResult is not None


@pytest.mark.unit
def test_toolbridge_package_imported() -> None:
    """Verify that toolbridge package can be imported."""
    import toolbridge
    assert toolbridge is not None
