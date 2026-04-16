"""Content validation — extension policy, RTLO detection, double extensions."""

from __future__ import annotations

import unicodedata
from pathlib import Path

from zipguard.policy import ExtractionPolicy

# Unicode bidirectional categories that can be used to spoof filenames
_DANGEROUS_BIDI = frozenset(["R", "AL", "RLE", "RLO", "RLI", "PDF", "PDI"])


class BlockedExtensionError(ValueError):
    pass


class UnsafeFilenameError(ValueError):
    pass


class DoubleExtensionError(ValueError):
    pass


def validate_filename(filename: str, policy: ExtractionPolicy) -> tuple[str, str]:
    """
    Validate filename against policy rules.
    Returns (safe_filename, rename_reason) where rename_reason is empty if not renamed.
    Raises on hard violations.
    """
    name = Path(filename).name  # strip any remaining path components

    if policy.block_rtlo:
        _check_rtlo(name)

    if policy.block_double_extension:
        _check_double_extension(name)

    safe_name, rename_reason = _check_extension(name, policy)

    return safe_name, rename_reason


def _check_rtlo(filename: str) -> None:
    """Detect Right-to-Left Override and other dangerous bidi control characters."""
    for char in filename:
        category = unicodedata.bidirectional(char)
        if category in _DANGEROUS_BIDI:
            raise UnsafeFilenameError(
                f"Unsafe Unicode bidirectional character (category={category}) "
                f"in filename: {filename!r}"
            )
    # Also catch explicit RTLO codepoint U+202E
    if "\u202e" in filename or "\u200f" in filename:
        raise UnsafeFilenameError(f"Right-to-Left Override character in filename: {filename!r}")


def _check_double_extension(filename: str) -> None:
    """
    Detect double extension tricks like 'document.pdf.exe'.
    A file has a double extension if it has 2+ suffixes and the last suffix
    is commonly executable while there are earlier suffixes acting as camouflage.
    """
    suffixes = Path(filename).suffixes
    if len(suffixes) < 2:
        return

    # If any suffix other than the last looks like a document type used for spoofing
    _SPOOF_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}
    _EXEC_EXTENSIONS = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".lnk", ".scr"}

    last = suffixes[-1].lower()
    earlier = {s.lower() for s in suffixes[:-1]}

    if last in _EXEC_EXTENSIONS and earlier & _SPOOF_EXTENSIONS:
        raise DoubleExtensionError(
            f"Double extension spoofing detected: '{filename}' "
            f"(disguised as {earlier & _SPOOF_EXTENSIONS})"
        )


def _check_extension(filename: str, policy: ExtractionPolicy) -> tuple[str, str]:
    """
    Check file extension against block list.
    Returns (safe_name, reason) where reason is empty if not renamed.
    Raises BlockedExtensionError if blocked and rename_blocked=False.
    """
    suffix = Path(filename).suffix.lower()
    blocked = [ext.lower() for ext in policy.block_extensions]

    if suffix in blocked:
        if policy.rename_blocked:
            return filename + ".blocked", f"executable extension blocked by policy ({suffix})"
        raise BlockedExtensionError(
            f"File extension '{suffix}' is blocked by policy: {filename!r}"
        )

    return filename, ""
