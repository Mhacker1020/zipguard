"""ZIP archive reader with chunked streaming and structure validation."""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Callable

from safe_extract.formats.base import ArchiveEntry, BaseArchiveReader, OnChunkCallback

CHUNK_SIZE = 65536  # 64 KB


class AmbiguousArchiveError(ValueError):
    pass


class EncryptedArchiveError(ValueError):
    pass


class ZipReader(BaseArchiveReader):

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._zf: zipfile.ZipFile | None = None

    def __enter__(self) -> "ZipReader":
        try:
            self._zf = zipfile.ZipFile(self.path, "r")
        except zipfile.BadZipFile as e:
            raise AmbiguousArchiveError(f"Malformed ZIP archive: {e}") from e
        return self

    def __exit__(self, *args: object) -> None:
        if self._zf:
            self._zf.close()
            self._zf = None

    def _require_open(self) -> zipfile.ZipFile:
        if self._zf is None:
            raise RuntimeError("ZipReader must be used as a context manager")
        return self._zf

    def validate_structure(self) -> None:
        """
        Detect duplicate entry names (parsing differentials) and other anomalies.
        Must be called inside a with-block.
        """
        zf = self._require_open()
        names = [e.filename for e in zf.infolist()]

        if len(names) != len(set(names)):
            from collections import Counter
            dupes = [n for n, c in Counter(names).items() if c > 1]
            raise AmbiguousArchiveError(
                f"Ambiguous archive: duplicate entry names detected: {dupes[:5]}"
            )

    def entries(self) -> list[ArchiveEntry]:
        zf = self._require_open()
        result = []
        for info in zf.infolist():
            is_dir = info.filename.endswith("/")
            is_symlink = bool(info.external_attr >> 16 & 0xA000 == 0xA000)
            result.append(ArchiveEntry(
                name=info.filename,
                file_size=info.file_size,
                compressed_size=info.compress_size,
                is_dir=is_dir,
                is_symlink=is_symlink,
                is_hardlink=False,
            ))
        return result

    def extract_entry(
        self,
        entry: ArchiveEntry,
        dest: Path,
        on_chunk: OnChunkCallback | None = None,
    ) -> int:
        """
        Stream-extract a single entry to dest.
        Calls on_chunk(chunk_size) after each 64KB chunk — raise inside to abort.
        Returns bytes written.
        """
        zf = self._require_open()
        dest.parent.mkdir(parents=True, exist_ok=True)

        bytes_written = 0
        try:
            with zf.open(entry.name) as src, open(dest, "wb") as dst:
                while chunk := src.read(CHUNK_SIZE):
                    dst.write(chunk)
                    bytes_written += len(chunk)
                    if on_chunk:
                        on_chunk(len(chunk))
        except RuntimeError as e:
            if "encrypted" in str(e).lower() or "password" in str(e).lower():
                raise EncryptedArchiveError(
                    f"Entry '{entry.name}' is encrypted — provide a password to extract"
                ) from e
            raise

        return bytes_written
