"""ZIP archive reader with chunked streaming and structure validation."""

from __future__ import annotations

import zipfile
from pathlib import Path

from safe_extract.formats.base import ArchiveEntry, BaseArchiveReader

CHUNK_SIZE = 65536  # 64 KB


class AmbiguousArchiveError(ValueError):
    pass


class ZipReader(BaseArchiveReader):

    def validate_structure(self) -> None:
        """
        Detect duplicate entry names and other structural anomalies.
        Duplicate names cause parsing differentials — different tools
        extract different files for the same name.
        """
        try:
            with zipfile.ZipFile(self.path) as zf:
                names = [e.filename for e in zf.infolist()]
        except zipfile.BadZipFile as e:
            raise AmbiguousArchiveError(f"Malformed ZIP archive: {e}") from e

        if len(names) != len(set(names)):
            from collections import Counter
            dupes = [n for n, c in Counter(names).items() if c > 1]
            raise AmbiguousArchiveError(
                f"Ambiguous archive: duplicate entry names detected: {dupes[:5]}"
            )

    def entries(self) -> list[ArchiveEntry]:
        with zipfile.ZipFile(self.path) as zf:
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
                    is_hardlink=False,  # ZIP doesn't support hardlinks natively
                ))
        return result

    def extract_entry(self, entry: ArchiveEntry, dest: Path) -> int:
        """Stream-extract a single entry to dest. Returns bytes written."""
        dest.parent.mkdir(parents=True, exist_ok=True)

        bytes_written = 0
        with zipfile.ZipFile(self.path) as zf:
            with zf.open(entry.name) as src, open(dest, "wb") as dst:
                while chunk := src.read(CHUNK_SIZE):
                    dst.write(chunk)
                    bytes_written += len(chunk)

        return bytes_written
