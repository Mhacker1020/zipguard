"""Abstract base class for archive format readers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass
class ArchiveEntry:
    """Normalized metadata for a single archive entry."""
    name: str               # Entry path as stored in archive
    file_size: int          # Uncompressed size in bytes (may be forged — do not trust blindly)
    compressed_size: int    # Compressed size in bytes (0 if unknown)
    is_dir: bool
    is_symlink: bool
    is_hardlink: bool
    link_target: str | None = None  # For symlinks/hardlinks


# Callback called after each chunk: on_chunk(chunk_size_bytes)
# Raise an exception inside to abort extraction mid-stream.
OnChunkCallback = Callable[[int], None]


class BaseArchiveReader(ABC):
    """
    Common interface for all archive format readers.
    Use as a context manager to keep the archive open for the full extraction:

        with ZipReader(path) as reader:
            reader.validate_structure()
            entries = reader.entries()
            reader.extract_entry(entry, dest, on_chunk=guard)
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    @abstractmethod
    def __enter__(self) -> "BaseArchiveReader":
        ...

    @abstractmethod
    def __exit__(self, *args: object) -> None:
        ...

    @abstractmethod
    def entries(self) -> list[ArchiveEntry]:
        """Return all entries in the archive without extracting."""
        ...

    @abstractmethod
    def extract_entry(
        self,
        entry: ArchiveEntry,
        dest: Path,
        on_chunk: OnChunkCallback | None = None,
    ) -> int:
        """
        Extract a single entry to dest using chunked streaming.
        Calls on_chunk(chunk_size) after writing each chunk — raise inside to abort.
        Returns the number of bytes written.
        """
        ...

    @abstractmethod
    def validate_structure(self) -> None:
        """
        Check archive integrity and structure before extraction starts.
        Raises on ambiguous or malformed archives.
        Must be called while the reader is open (inside with-block).
        """
        ...
