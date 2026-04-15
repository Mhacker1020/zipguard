"""Abstract base class for archive format readers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass
class ArchiveEntry:
    """Normalized metadata for a single archive entry."""
    name: str               # Entry path as stored in archive
    file_size: int          # Uncompressed size in bytes
    compressed_size: int    # Compressed size in bytes (0 if unknown)
    is_dir: bool
    is_symlink: bool
    is_hardlink: bool
    link_target: str | None = None  # For symlinks/hardlinks


class BaseArchiveReader(ABC):
    """Common interface for all archive format readers."""

    def __init__(self, path: Path) -> None:
        self.path = path

    @abstractmethod
    def entries(self) -> list[ArchiveEntry]:
        """Return all entries in the archive without extracting."""
        ...

    @abstractmethod
    def extract_entry(self, entry: ArchiveEntry, dest: Path) -> int:
        """
        Extract a single entry to dest using chunked streaming.
        Returns the number of bytes written.
        """
        ...

    @abstractmethod
    def validate_structure(self) -> None:
        """
        Check archive integrity and structure before extraction starts.
        Raises on ambiguous or malformed archives.
        """
        ...
