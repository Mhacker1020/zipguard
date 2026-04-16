"""ZIP archive reader with chunked streaming and structure validation."""

from __future__ import annotations

import struct
import tempfile
import zipfile
from pathlib import Path
from typing import Callable

from zipguard.formats.base import ArchiveEntry, BaseArchiveReader, OnChunkCallback

CHUNK_SIZE = 65536  # 64 KB


class AmbiguousArchiveError(ValueError):
    pass


class EncryptedArchiveError(ValueError):
    pass


class ZIP64ConsistencyError(ValueError):
    pass


# ZIP64 extra field signature
_ZIP64_EXTRA_SIG = 0x0001


def _check_zip64_consistency(info: zipfile.ZipInfo) -> None:
    """
    Verify that ZIP64 extra field values match the central directory header.

    Crafted archives can carry inconsistent sizes — a small value in the main
    header (to pass naive checks) and a huge value in the ZIP64 extra field
    (used at decompression time). We parse the extra field and reject any
    mismatch.
    """
    extra = info.extra
    offset = 0
    while offset + 4 <= len(extra):
        sig, size = struct.unpack_from("<HH", extra, offset)
        offset += 4
        if offset + size > len(extra):
            break
        if sig == _ZIP64_EXTRA_SIG:
            data = extra[offset: offset + size]
            pos = 0
            zip64_uncompressed: int | None = None
            zip64_compressed: int | None = None
            # Fields are present only when the main header value is 0xFFFFFFFF
            if info.file_size == 0xFFFFFFFF and pos + 8 <= len(data):
                (zip64_uncompressed,) = struct.unpack_from("<Q", data, pos)
                pos += 8
            if info.compress_size == 0xFFFFFFFF and pos + 8 <= len(data):
                (zip64_compressed,) = struct.unpack_from("<Q", data, pos)
                pos += 8
            # If both headers are non-sentinel but a ZIP64 field exists anyway,
            # the values must agree — otherwise something is crafted.
            if zip64_uncompressed is None and pos + 8 <= len(data):
                (zip64_uncompressed,) = struct.unpack_from("<Q", data, pos)
                pos += 8
                if zip64_uncompressed != info.file_size:
                    raise ZIP64ConsistencyError(
                        f"ZIP64 size mismatch for '{info.filename}': "
                        f"central dir={info.file_size}, ZIP64 extra={zip64_uncompressed}"
                    )
            if zip64_compressed is None and pos + 8 <= len(data):
                (zip64_compressed,) = struct.unpack_from("<Q", data, pos)
                if zip64_compressed != info.compress_size:
                    raise ZIP64ConsistencyError(
                        f"ZIP64 compressed size mismatch for '{info.filename}': "
                        f"central dir={info.compress_size}, ZIP64 extra={zip64_compressed}"
                    )
            return  # found and checked the ZIP64 field
        offset += size


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
        Detect duplicate entry names (parsing differentials), ZIP64 inconsistencies,
        and other structural anomalies. Must be called inside a with-block.
        """
        zf = self._require_open()
        names = [e.filename for e in zf.infolist()]

        if len(names) != len(set(names)):
            from collections import Counter
            dupes = [n for n, c in Counter(names).items() if c > 1]
            raise AmbiguousArchiveError(
                f"Ambiguous archive: duplicate entry names detected: {dupes[:5]}"
            )

        for info in zf.infolist():
            _check_zip64_consistency(info)

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

        # Write to a temp file in the same directory, rename atomically on success.
        # This ensures no partial files are left on disk if extraction is aborted.
        bytes_written = 0
        tmp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=dest.parent, prefix=".zipguard-", delete=False
            ) as tmp:
                tmp_path = Path(tmp.name)
                try:
                    with zf.open(entry.name) as src:
                        while chunk := src.read(CHUNK_SIZE):
                            tmp.write(chunk)
                            bytes_written += len(chunk)
                            if on_chunk:
                                on_chunk(len(chunk))
                except RuntimeError as e:
                    if "encrypted" in str(e).lower() or "password" in str(e).lower():
                        raise EncryptedArchiveError(
                            f"Entry '{entry.name}' is encrypted — provide a password to extract"
                        ) from e
                    raise
            tmp_path.replace(dest)
            tmp_path = None
        finally:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)

        return bytes_written
