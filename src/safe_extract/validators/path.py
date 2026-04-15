"""Path safety validation — prevents path traversal and symlink abuse."""

from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath


class PathTraversalError(ValueError):
    pass


class SymlinkError(ValueError):
    pass


def validate_entry_path(entry_name: str, target_dir: Path) -> Path:
    """
    Resolve the final destination path and ensure it stays within target_dir.
    Raises PathTraversalError if the entry uses absolute paths, drive letters,
    UNC paths, or relative traversal to escape the target directory.
    """
    _check_absolute(entry_name)

    dest = (target_dir / entry_name).resolve()
    target_resolved = target_dir.resolve()

    if not dest.is_relative_to(target_resolved):
        raise PathTraversalError(
            f"Path traversal detected: '{entry_name}' resolves outside target directory"
        )

    return dest


def _check_absolute(name: str) -> None:
    """Reject any entry name that uses an absolute or suspicious path."""
    p = name.replace("\\", "/")

    # Unix absolute path: /etc/passwd
    if p.startswith("/"):
        raise PathTraversalError(f"Absolute path in archive entry: '{name}'")

    # Windows drive letter: C:/..., D:\...
    if len(p) >= 2 and p[1] == ":":
        raise PathTraversalError(f"Absolute Windows path in archive entry: '{name}'")

    # UNC path: //server/share
    if p.startswith("//") or p.startswith("\\\\"):
        raise PathTraversalError(f"UNC path in archive entry: '{name}'")


def check_symlink(is_symlink: bool, is_hardlink: bool, policy_allow: bool) -> None:
    """Raise SymlinkError if symlinks/hardlinks are not allowed by policy."""
    if not policy_allow and (is_symlink or is_hardlink):
        kind = "symlink" if is_symlink else "hardlink"
        raise SymlinkError(f"Archive contains a {kind} which is blocked by policy")
