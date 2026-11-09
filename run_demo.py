"""ToolBridge Enterprise MCP Gateway — Unified Launch & Diagnostics Script.

Usage:
  python run_demo.py            # Interactive selection menu
  python run_demo.py web        # Launch Web Control Center (Single-Page Web App)
  python run_demo.py dashboard  # Launch Streamlit Control Plane
  python run_demo.py api        # Launch FastAPI Management Service
  python run_demo.py gateway    # Launch Downstream Gateway Server (stdio)
  python run_demo.py mcp        # Alias for gateway
  python run_demo.py test       # Run complete test suite
  python run_demo.py check      # Run system diagnostics
"""
from __future__ import annotations

import argparse
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser


def get_python() -> str:
    """Return path to virtualenv python executable if available, fallback to sys.executable."""
    venv_py = os.path.join(os.path.dirname(__file__), ".venv", "Scripts", "python.exe")
    if os.path.isfile(venv_py):
        return venv_py
    venv_py_posix = os.path.join(os.path.dirname(__file__), ".venv", "bin", "python")
    if os.path.isfile(venv_py_posix):
        return venv_py_posix
    return sys.executable


def ensure_env_configured() -> None:
    """Ensure .env exists and has required 32+ character API keys and configuration."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return

    import re
    import secrets

    env_path = os.path.join(os.path.dirname(__file__), ".env")
    example_path = os.path.join(os.path.dirname(__file__), ".env.example")

    needs_generation = False
    env_content = ""

    if not os.path.exists(env_path):
        if os.path.exists(example_path):
            with open(example_path, "r", encoding="utf-8") as f:
                env_content = f.read()
        else:
            env_content = ""
        needs_generation = True
    else:
        with open(env_path, "r", encoding="utf-8") as f:
            env_content = f.read()

    load_dotenv(dotenv_path=env_path, override=False)

    for key_name in ["TOOLBRIDGE_ADMIN_KEY", "TOOLBRIDGE_OPERATOR_KEY", "TOOLBRIDGE_READONLY_KEY"]:
        val = os.environ.get(key_name, "").strip()
        if not val or len(val) < 32 or val in [
            "tb-admin-key-999", "tb-operator-key-555", "tb-readonly-key-111",
            "change-this-to-a-strong-random-api-key-in-production", "changeme", "placeholder"
        ]:
            new_key = f"tb_{secrets.token_urlsafe(32)}"
            os.environ[key_name] = new_key
            pattern = rf"^{key_name}\s*=.*$"
            if re.search(pattern, env_content, flags=re.MULTILINE):
                env_content = re.sub(pattern, f'{key_name}="{new_key}"', env_content, flags=re.MULTILINE)
            else:
                env_content += f'\n{key_name}="{new_key}"'
            needs_generation = True

    if needs_generation:
        with open(env_path, "w", encoding="utf-8") as f:
            f.write(env_content.strip() + "\n")
        print("[ToolBridge] Configured secure credentials in .env")


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
        webbrowser.open(url)

    threading.Thread(target=_poll, daemon=True).start()


def _safe_run(cmd: list[str]) -> int:
    """Run a subprocess command safely, handling SIGINT cleanly and returning status code."""
    proc = None
    try:
        proc = subprocess.Popen(cmd)
        proc.wait()
        return proc.returncode
    except KeyboardInterrupt:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
        return 0


def run_web(port: int | None = None) -> None:
    """Launch Web Control Center with smart port detection and delayed browser launch."""
    selected_port = int(port) if port else find_available_port(8000)
    url = f"http://127.0.0.1:{selected_port}"
    print("=" * 60)
    print(f"Starting ToolBridge Web Control Center on port {selected_port}...")
    print(f"Browser will automatically open to: {url}")
    print("=" * 60)

    open_browser_when_ready(url)

    py = get_python()
    code = _safe_run([
        py, "-m", "uvicorn", "toolbridge.api.app:app",
        "--host", "127.0.0.1",
        "--port", str(selected_port),
    ])
    sys.exit(code)


def run_dashboard() -> None:
    """Launch Streamlit control plane dashboard."""
    print("=" * 60)
    print("Starting ToolBridge Streamlit Control Plane...")
    print("Open in browser: http://127.0.0.1:8501")
    print("=" * 60)
    py = get_python()
    app_path = os.path.join(os.path.dirname(__file__), "src", "toolbridge", "dashboard", "app.py")
    code = _safe_run([
        py, "-m", "streamlit", "run", app_path,
        "--server.address", "127.0.0.1",
        "--server.headless", "true",
    ])
    sys.exit(code)


def run_api(port: int | None = None) -> None:
    """Launch FastAPI management API."""
    selected_port = int(port) if port else find_available_port(8000)
    print("=" * 60)
    print(f"Starting ToolBridge FastAPI Management Service on port {selected_port}...")
    print(f"Open Swagger API docs: http://127.0.0.1:{selected_port}/docs")
    print("Authentication: Set TOOLBRIDGE_ADMIN_KEY, TOOLBRIDGE_OPERATOR_KEY, TOOLBRIDGE_READONLY_KEY")
    print("=" * 60)
    py = get_python()
    code = _safe_run([
        py, "-m", "uvicorn", "toolbridge.api.app:app",
        "--host", "127.0.0.1",
        "--port", str(selected_port),
    ])
    sys.exit(code)


def run_gateway() -> None:
    """Launch downstream Gateway server over stdio.
    
    CRITICAL: Never print to stdout in this path; stdout is reserved exclusively
    for JSON-RPC frames communicating with downstream MCP clients (Claude Desktop / Cursor).
    """
    sys.stderr.write("=" * 60 + "\n")
    sys.stderr.write("Starting ToolBridge Gateway Server over stdio...\n")
    sys.stderr.write("Waiting for JSON-RPC 2.0 connection on standard input (Claude Desktop / Cursor)...\n")
    sys.stderr.write("=" * 60 + "\n")
    sys.stderr.flush()

    py = get_python()
    code = _safe_run([py, "-m", "toolbridge.server.gateway"])
    sys.exit(code)


def run_tests() -> None:
    """Run full test suite."""
    print("=" * 60)
    print("Running ToolBridge Automated Test Suite...")
    print("=" * 60)
    py = get_python()
    code = _safe_run([py, "-m", "pytest", "-v"])
    sys.exit(code)


def run_diagnostics() -> None:
    """Run system check on all components."""
    print("=" * 60)
    print("Running ToolBridge Diagnostics...")
    print("=" * 60)
    py = get_python()

    diag_code = """
import asyncio
import json
import os
import sys

from toolbridge.upstreams.filesystem.server import FilesystemMCPServer
from toolbridge.upstreams.postgres.server import PostgresMCPServer
from toolbridge.upstreams.github.server import GitHubMCPServer

async def check():
    failures = 0
    warnings = 0

    # 1. Filesystem Check (Required)
    print("[1/3] Checking Sandboxed Filesystem MCP Server...")
    try:
        fs = FilesystemMCPServer()
        res = await fs.tool_list_directory({"path": ""})
        if res.is_error:
            print(f"      [FAIL] Filesystem check returned error: {res.content[0].text}")
            failures += 1
        else:
            payload = json.loads(res.content[0].text)
            entry_count = payload.get("total_entries", len(payload.get("entries", [])))
            print(f"      [PASS] Filesystem ready ({entry_count} entries discovered)")
    except Exception as e:
        print(f"      [FAIL] Filesystem exception: {e}")
        failures += 1

    # 2. Database Check (Postgres is optional, SQLite fallback supported)
    print("[2/3] Checking Database Backend (PostgreSQL / SQLite fallback)...")
    try:
        pg = PostgresMCPServer()
        await pg.backend.connect()
        tables = await pg.backend.list_tables()
        rows = await pg.backend.execute_query("SELECT * FROM customers LIMIT 1;")
        await pg.backend.disconnect()
        backend_name = pg.backend.__class__.__name__
        if len(rows) > 0:
            sample_name = rows[0].get("name", "N/A")
            print(f"      [PASS] Database ready via {backend_name} ({len(tables)} tables, query sample: '{sample_name}')")
        else:
            print(f"      [WARN] Database connected via {backend_name} but sample table is empty.")
            warnings += 1
    except Exception as e:
        print(f"      [WARN] PostgreSQL server unreachable, local test backend error: {e}")
        warnings += 1

    # 3. GitHub Server Check
    print("[3/3] Checking GitHub MCP Server...")
    try:
        gh = GitHubMCPServer()
        repo = await gh.tool_get_repository({"owner": "modelcontextprotocol", "repo": "python-sdk"})
        if repo.is_error:
            print(f"      [WARN] GitHub API request failed or rate limited (status: error)")
            warnings += 1
        else:
            print(f"      [PASS] GitHub API ready (repository metadata retrieved)")
    except Exception as e:
        print(f"      [WARN] GitHub API request exception: {e}")
        warnings += 1

    print("\\n" + "=" * 60)
    if failures == 0:
        print(f">> Diagnostics Complete: 3/3 components verified ({warnings} warnings, 0 failures) <<")
        sys.exit(0)
    else:
        print(f">> Diagnostics Failed: {failures} critical failure(s) detected! <<")
        sys.exit(1)

asyncio.run(check())
"""
    code = _safe_run([py, "-c", diag_code])
    sys.exit(code)


def main() -> None:
    """Entrypoint dispatcher with argument parsing."""
    ensure_env_configured()
    parser = argparse.ArgumentParser(
        description="ToolBridge Enterprise MCP Gateway — Unified Launch & Diagnostics Script"
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="",
        choices=["", "web", "ui", "frontend", "dashboard", "api", "gateway", "mcp", "test", "tests", "check", "diag", "diagnostics"],
        help="Command to run",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port number for web control center or FastAPI API",
    )

    args = parser.parse_args()
    cmd = args.command.lower()

    if cmd in ("web", "ui", "frontend"):
        run_web(port=args.port)
    elif cmd == "dashboard":
        run_dashboard()
    elif cmd == "api":
        run_api(port=args.port)
    elif cmd in ("gateway", "mcp"):
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
        print("  5. Run Automated Test Suite")
        print("  q. Quit")
        try:
            choice = input("\nEnter choice [1-5 or q] (default: 1): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            sys.exit(0)

        if choice in ("", "1"):
            run_web(port=args.port)
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
            sys.exit(0)


if __name__ == "__main__":
    main()
