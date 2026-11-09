"""Filesystem security guard: path traversal, symlink escape, and jail enforcement."""
import os
import re
from pathlib import Path
from typing import Final

# Reserved Windows device names that must never be created or accessed
_WINDOWS_RESERVED_NAMES: Final[frozenset[str]] = frozenset({
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
})


def get_project_root() -> Path:
    """Return the absolute path to the ToolBridge project root directory."""
    curr = Path(__file__).resolve().parent
    for p in [curr, *curr.parents]:
        if (p / "pyproject.toml").exists():
            return p
    return Path.cwd()


def resolve_sandbox_root(raw_path: str | Path | None = None) -> Path:
    """Resolve sandbox root relative to project root unless explicitly absolute."""
    path_str = str(raw_path) if raw_path else os.environ.get("FILESYSTEM_SANDBOX_ROOT", "./workspace_sandbox")
    candidate = Path(path_str)
    if candidate.is_absolute():
        return candidate.resolve()
    return (get_project_root() / candidate).resolve()


class PathSecurityError(PermissionError):
    """Raised when a path violates security constraints or sandbox boundaries."""
    pass


class FilesystemGuard:
    """Enforces strict isolation of filesystem operations within a designated sandbox root."""

    def __init__(
        self,
        sandbox_root: str | Path,
        allow_symlinks: bool = False,
        max_file_size_bytes: int = 5 * 1024 * 1024,  # 5 MB default
    ) -> None:
        """Initialize the guard with a resolved canonical sandbox root directory.

        Args:
            sandbox_root: Path to the dedicated sandbox directory.
            allow_symlinks: If True, symlinks are permitted only if their targets
                           remain strictly within the sandbox. If False, all symlinks
                           are strictly rejected.
            max_file_size_bytes: Maximum allowed file read/write size in bytes.
        """
        self._sandbox_root = resolve_sandbox_root(sandbox_root)
        self._allow_symlinks = allow_symlinks

        env_max_bytes = os.environ.get("FILESYSTEM_MAX_WRITE_BYTES")
        if env_max_bytes:
            try:
                self._max_file_size_bytes = int(env_max_bytes)
            except ValueError:
                self._max_file_size_bytes = max_file_size_bytes
        else:
            self._max_file_size_bytes = max_file_size_bytes

        # Ensure sandbox root directory exists
        self._sandbox_root.mkdir(parents=True, exist_ok=True)

    @property
    def sandbox_root(self) -> Path:
        """Return the canonical sandbox root path."""
        return self._sandbox_root

    @property
    def max_file_size_bytes(self) -> int:
        """Return the maximum allowed file size in bytes."""
        return self._max_file_size_bytes

    def resolve_safe_path(
        self,
        untrusted_path: str | Path,
        must_exist: bool = False,
        allow_root: bool = True,
    ) -> Path:
        """Validate, sanitize, and resolve an untrusted path against the sandbox root.

        Security checks enforced:
        1. Null-byte rejection (C-string injection defense).
        2. Windows reserved device name check (e.g. CON, NUL, AUX).
        3. Canonical path resolution to defeat relative traversal ('../', '..\\').
        4. Absolute drive / root escape rejection.
        5. Containment check ensuring target is relative to the sandbox root.
        6. Symlink escape detection for target and all parent components.

        Args:
            untrusted_path: The user-supplied or LLM-supplied path string or Path.
            must_exist: If True, raises FileNotFoundError if the target does not exist.
            allow_root: If True, pointing to the sandbox root itself is allowed.

        Returns:
            The fully resolved, safe canonical Path object.

        Raises:
            PathSecurityError: If any security check fails.
            FileNotFoundError: If must_exist is True and path does not exist.
        """
        raw_str = str(untrusted_path)

        # 1. Null-byte injection check
        if "\0" in raw_str:
            raise PathSecurityError("Null bytes are prohibited in file paths.")

        # 2. Reject Alternate Data Streams (':' anywhere in path)
        if ":" in raw_str:
            raise PathSecurityError(
                f"Alternate data streams and drive identifiers are prohibited in paths: '{untrusted_path}'."
            )

        # 3. Strict absolute path check
        # Paths must be strictly relative to the sandbox root.
        raw_stripped = raw_str.strip()
        if raw_stripped.startswith("/") or raw_stripped.startswith("\\"):
            raise PathSecurityError(
                f"Absolute paths are prohibited: '{untrusted_path}'. Paths must be relative to the workspace."
            )

        # 4. Windows reserved name check on any path component & obfuscated dot sequences
        normalized_str = raw_stripped.replace("\\", "/")
        parts = [p.strip() for p in normalized_str.split("/") if p.strip()]
        for part in parts:
            if re.match(r"^\.{3,}$", part):
                raise PathSecurityError(f"Invalid path component '{part}' with multiple dots.")
            # Check reserved Windows device names (CON, AUX, NUL, COM1-9, LPT1-9)
            # Defends against extensions (CON.txt) and trailing dots/spaces ("aux .txt", "nul.")
            clean_part = part.rstrip(" .")
            base_stem = clean_part.split(".")[0].rstrip(" .").upper()
            if base_stem in _WINDOWS_RESERVED_NAMES or clean_part.upper() in _WINDOWS_RESERVED_NAMES:
                raise PathSecurityError(f"Access to reserved Windows device name '{part}' is prohibited.")

        # 4. Canonical path resolution
        if not parts or parts == ["."]:
            if not allow_root:
                raise PathSecurityError("Access to the sandbox root itself is disallowed for this operation.")
            target_path = self._sandbox_root
        else:
            rel_path = "/".join(parts)
            unresolved_candidate = self._sandbox_root / rel_path

            # Symlink check on unresolved path components
            check_node = unresolved_candidate
            while check_node != self._sandbox_root and check_node.parent != check_node:
                if check_node.is_symlink():
                    if not self._allow_symlinks:
                        raise PathSecurityError(
                            f"Symlinks are disallowed: Component '{check_node.name}' is a symbolic link."
                        )
                    try:
                        resolved_target = check_node.resolve()
                        resolved_target.relative_to(self._sandbox_root)
                    except ValueError:
                        raise PathSecurityError(
                            f"Symlink escape detected: '{check_node.name}' points outside the sandbox."
                        )
                check_node = check_node.parent

            target_path = unresolved_candidate.resolve()

        # 5. Strict containment check (Canonical Path Traversal Defense)
        try:
            target_path.relative_to(self._sandbox_root)
        except ValueError:
            raise PathSecurityError(
                f"Path traversal detected: Target '{untrusted_path}' resolves outside the allowed workspace."
            )

        # 6. Symlink escape check on resolved target
        self._verify_symlinks(target_path)

        # 7. Existence verification if requested
        if must_exist and not target_path.exists():
            raise FileNotFoundError(f"Path does not exist: '{untrusted_path}'")

        return target_path

    def _verify_symlinks(self, path: Path) -> None:
        """Inspect the target and all its ancestors for unauthorized symlink escapes.

        Args:
            path: Resolved target path inside the sandbox.

        Raises:
            PathSecurityError: If an unauthorized or escaping symlink is encountered.
        """
        curr = path
        # Walk up from the path to the sandbox root
        while curr != self._sandbox_root and curr.parent != curr:
            if curr.is_symlink():
                if not self._allow_symlinks:
                    raise PathSecurityError(
                        f"Symlinks are disallowed: Component '{curr.name}' is a symbolic link."
                    )
                # If symlinks are allowed, the link target itself must reside inside the sandbox
                try:
                    resolved_target = curr.resolve()
                    resolved_target.relative_to(self._sandbox_root)
                except ValueError:
                    raise PathSecurityError(
                        f"Symlink escape detected: '{curr.name}' points outside the sandbox."
                    )
            curr = curr.parent

    def get_relative_path(self, canonical_path: Path) -> str:
        """Convert a canonical path into a clean, forward-slash relative path from sandbox root."""
        rel = canonical_path.relative_to(self._sandbox_root)
        rel_str = str(rel).replace("\\", "/")
        return "" if rel_str == "." else rel_str
