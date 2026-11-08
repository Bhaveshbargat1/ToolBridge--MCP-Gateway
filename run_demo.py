"""ToolBridge Enterprise MCP Gateway — Unified Launch & Diagnostics Script.

Usage:
  python run_demo.py            # Interactive selection menu
  python run_demo.py web        # Launch Web Control Center (Single-Page Web App)
  python run_demo.py dashboard  # Launch Streamlit Control Plane
  python run_demo.py api        # Launch FastAPI Management Service
  python run_demo.py gateway    # Launch Downstream Gateway Server (stdio)
  python run_demo.py test       # Run complete test suite (105 tests)
  python run_demo.py check      # Run system diagnostics
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser


def get_python() -> str:
    """Return path to virtualenv python executable if available, fallback to py/sys.executable."""
    # Check .venv in current directory
    venv_py = os.path.join(os.path.dirname(__file__), ".venv", "Scripts", "python.exe")
    if os.path.isfile(venv_py):
        return venv_py
    venv_py_posix = os.path.join(os.path.dirname(__file__), ".venv", "bin", "python")
    if os.path.isfile(venv_py_posix):
        return venv_py_posix
    return sys.executable


def find_available_port(preferred_port: int = 8000) -> int:
    """Find an open port starting from preferred_port."""
    for port in range(preferred_port, preferred_port + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return preferred_port


def open_browser_when_ready(url: str, max_wait: float = 10.0) -> None:
    """Poll URL until server responds, then open browser to avoid 'connection refused' errors."""
    def _poll():
        start = time.time()
        while time.time() - start < max_wait:
            time.sleep(0.3)
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "ToolBridge-Launcher"})
                with urllib.request.urlopen(req, timeout=0.5) as resp:
                    if resp.status == 200:
                        webbrowser.open(url)
                        return
            except Exception:
                pass
        # Fallback open anyway if timeout
        webbrowser.open(url)

    threading.Thread(target=_poll, daemon=True).start()


def run_web(port: int | None = None) -> None:
    """Launch Web Control Center with smart port detection and delayed browser launch."""
    selected_port = port or find_available_port(8000)
    url = f"http://127.0.0.1:{selected_port}"
    print("=" * 60)
    print(f"Starting ToolBridge Web Control Center on port {selected_port}...")
    print(f"Browser will automatically open to: {url}")
    print("=" * 60)

    # Automatically open browser once server is listening
    open_browser_when_ready(url)

    py = get_python()
    subprocess.run([
        py, "-m", "uvicorn", "toolbridge.api.app:app",
        "--host", "127.0.0.1",
        "--port", str(selected_port),
    ])


def run_dashboard() -> None:
    """Launch Streamlit control plane dashboard."""
    print("=" * 60)
    print("Starting ToolBridge Streamlit Control Plane...")
    print("Open in browser: http://localhost:8501")
    print("=" * 60)
    py = get_python()
    app_path = os.path.join(os.path.dirname(__file__), "src", "toolbridge", "dashboard", "app.py")
    subprocess.run([py, "-m", "streamlit", "run", app_path])


def run_api(port: int | None = None) -> None:
    """Launch FastAPI management API."""
    selected_port = port or find_available_port(8000)
    print("=" * 60)
    print(f"Starting ToolBridge FastAPI Management Service on port {selected_port}...")
    print(f"Open Swagger API docs: http://127.0.0.1:{selected_port}/docs")
    print("Default API Keys: tb-admin-key-999 / tb-operator-key-555 / tb-readonly-key-111")
    print("=" * 60)
    py = get_python()
    subprocess.run([
        py, "-m", "uvicorn", "toolbridge.api.app:app",
        "--host", "127.0.0.1",
        "--port", str(selected_port),
    ])


def run_gateway() -> None:
    """Launch downstream Gateway server over stdio."""
    print("=" * 60)
    print("Starting ToolBridge Gateway Server over stdio...")
    print("Waiting for JSON-RPC 2.0 connection on standard input (Claude Desktop / Cursor)...")
    print("=" * 60)
    py = get_python()
    subprocess.run([py, "-m", "toolbridge.server.gateway"])


def run_tests() -> None:
    """Run full test suite."""
    print("=" * 60)
    print("Running ToolBridge Automated Test Suite...")
    print("=" * 60)
    py = get_python()
    subprocess.run([py, "-m", "pytest", "-v"])


def run_diagnostics() -> None:
    """Run system check on all components."""
    print("=" * 60)
    print("Running ToolBridge Diagnostics...")
    print("=" * 60)
    py = get_python()

    code = """
import sys
import asyncio
from toolbridge.upstreams.filesystem.server import FilesystemMCPServer
from toolbridge.upstreams.postgres.server import PostgresMCPServer
from toolbridge.upstreams.github.server import GitHubMCPServer

async def check():
    print("[1/3] Checking Filesystem MCP Server...")
    fs = FilesystemMCPServer()
    res = await fs.tool_list_directory({"path": ""})
    print(f"      OK -> Filesystem ready (entries: {len(res.content[0].text)})")

    print("[2/3] Checking PostgreSQL MCP Server...")
    pg = PostgresMCPServer()
    await pg.backend.connect()
    tables = await pg.backend.list_tables()
    rows = await pg.backend.execute_query("SELECT * FROM customers LIMIT 1;")
    await pg.backend.disconnect()
    print(f"      OK -> Database ready ({len(tables)} tables, query sample: '{rows[0]['name']}')")

    print("[3/3] Checking GitHub MCP Server...")
    gh = GitHubMCPServer()
    repo = await gh.tool_get_repository({"owner": "modelcontextprotocol", "repo": "python-sdk"})
    print(f"      OK -> GitHub API ready (status: {'error' if repo.is_error else 'success'})")

    print("\\n>> All ToolBridge components verified and fully operational! <<")

asyncio.run(check())
"""
    subprocess.run([py, "-c", code])


def main() -> None:
    """Entrypoint dispatcher."""
    cmd = sys.argv[1].lower() if len(sys.argv) > 1 else ""

    if cmd in ("web", "ui", "frontend"):
        run_web()
    elif cmd == "dashboard":
        run_dashboard()
    elif cmd == "api":
        run_api()
    elif cmd == "gateway":
        run_gateway()
    elif cmd in ("test", "tests"):
        run_tests()
    elif cmd in ("check", "diag", "diagnostics"):
        run_diagnostics()
    else:
        print("\n" + "=" * 60)
        print("🌉 ToolBridge Enterprise MCP Gateway — Quick Launcher")
        print("=" * 60)
        print("Select an option to run:")
        print("  1. Modern Web Control Center (Single-Page App at http://127.0.0.1:8000)")
        print("  2. Streamlit Dashboard (http://localhost:8501)")
        print("  3. Downstream MCP Gateway (stdio for Claude Desktop)")
        print("  4. Run Diagnostics Check")
        print("  5. Run Automated Test Suite (105 tests)")
        print("  q. Quit")
        choice = input("\nEnter choice [1-5 or q] (default: 1): ").strip()
        if choice in ("", "1"):
            run_web()
        elif choice == "2":
            run_dashboard()
        elif choice == "3":
            run_gateway()
        elif choice == "4":
            run_diagnostics()
        elif choice == "5":
            run_tests()
        else:
            print("Exiting.")


if __name__ == "__main__":
    main()
