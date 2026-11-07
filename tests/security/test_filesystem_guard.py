"""Security and penetration test suite for FilesystemGuard."""
import os
import sys
import tempfile
from pathlib import Path
import pytest

from toolbridge.security.guards.filesystem import FilesystemGuard, PathSecurityError


@pytest.fixture
def sandbox_env(tmp_path: Path):
    """Create an isolated temporary sandbox directory with sample files."""
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir()

    # Create safe internal directory structure
    sub_dir = sandbox_dir / "docs"
    sub_dir.mkdir()
    (sub_dir / "guide.txt").write_text("ToolBridge safe guide content", encoding="utf-8")
    (sandbox_dir / "root_file.txt").write_text("Hello from sandbox root", encoding="utf-8")

    outside_dir = tmp_path / "outside_forbidden"
    outside_dir.mkdir()
    (outside_dir / "secret.key").write_text("CRITICAL_OUTSIDE_SECRET", encoding="utf-8")

    guard = FilesystemGuard(sandbox_root=sandbox_dir, allow_symlinks=False)
    return guard, sandbox_dir, outside_dir


@pytest.mark.security
def test_valid_path_resolution(sandbox_env):
    """Ensure safe paths inside the sandbox resolve correctly."""
    guard, sandbox_dir, _ = sandbox_env

    # Relative root
    res_root = guard.resolve_safe_path(".")
    assert res_root == sandbox_dir

    # Relative file
    res_file = guard.resolve_safe_path("root_file.txt", must_exist=True)
    assert res_file == sandbox_dir / "root_file.txt"
    assert guard.get_relative_path(res_file) == "root_file.txt"

    # Nested subfolder file
    res_sub = guard.resolve_safe_path("docs/guide.txt", must_exist=True)
    assert res_sub == sandbox_dir / "docs" / "guide.txt"
    assert guard.get_relative_path(res_sub) == "docs/guide.txt"


@pytest.mark.security
@pytest.mark.parametrize("traversal_payload", [
    "../outside_forbidden/secret.key",
    "..\\outside_forbidden\\secret.key",
    "docs/../../outside_forbidden/secret.key",
    "docs/../../../secret.key",
    "/etc/passwd",
    "C:/Windows/System32/cmd.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "....//....//outside_forbidden/secret.key",
])
def test_path_traversal_attacks_blocked(sandbox_env, traversal_payload: str):
    """Test various directory traversal and absolute escape payloads are strictly blocked."""
    guard, _, _ = sandbox_env

    with pytest.raises(PathSecurityError) as exc_info:
        guard.resolve_safe_path(traversal_payload)

    err_msg = str(exc_info.value).lower()
    assert any(term in err_msg for term in ["resolves outside", "disallowed", "prohibited", "invalid path component"])


@pytest.mark.security
def test_null_byte_injection_blocked(sandbox_env):
    """Verify null-byte injection attempts are immediately rejected."""
    guard, _, _ = sandbox_env

    with pytest.raises(PathSecurityError, match="Null bytes are prohibited"):
        guard.resolve_safe_path("docs/guide.txt\0.pdf")


@pytest.mark.security
@pytest.mark.parametrize("device_name", ["CON", "con.txt", "PRN", "aux", "NUL", "COM1", "lpt2.dat"])
def test_windows_reserved_device_names_blocked(sandbox_env, device_name: str):
    """Verify Windows reserved device names are rejected to prevent system lockup."""
    guard, _, _ = sandbox_env

    with pytest.raises(PathSecurityError, match="reserved Windows device name"):
        guard.resolve_safe_path(device_name)


@pytest.mark.security
def test_symlink_escape_blocked(sandbox_env):
    """Verify that a symlink pointing outside the sandbox is detected and rejected."""
    guard, sandbox_dir, outside_dir = sandbox_env

    symlink_path = sandbox_dir / "malicious_link"
    try:
        os.symlink(outside_dir, symlink_path, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not supported in this environment / permissions")

    # Guard with allow_symlinks=False rejects any symlink
    with pytest.raises(PathSecurityError, match="Symlinks are disallowed"):
        guard.resolve_safe_path("malicious_link/secret.key")

    # Guard with allow_symlinks=True must still reject if target points outside sandbox
    permissive_guard = FilesystemGuard(sandbox_root=sandbox_dir, allow_symlinks=True)
    with pytest.raises(PathSecurityError, match="Symlink escape detected"):
        permissive_guard.resolve_safe_path("malicious_link/secret.key")


@pytest.mark.security
def test_nonexistent_file_with_must_exist(sandbox_env):
    """Verify FileNotFoundError is raised when must_exist=True for nonexistent safe path."""
    guard, _, _ = sandbox_env

    with pytest.raises(FileNotFoundError):
        guard.resolve_safe_path("docs/nonexistent.txt", must_exist=True)

    # When must_exist=False, path resolves safely without error (used for new write operations)
    safe_new = guard.resolve_safe_path("docs/new_file.txt", must_exist=False)
    assert safe_new.name == "new_file.txt"
