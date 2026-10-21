"""Safe reading of a submitted skill or plugin archive (zip), in memory.

The archive is untrusted data from a logged-in user. Nothing is ever written to disk
and nothing is executed; the only output is, per file, its normalised path, its
SHA-256 and its size. Everything that could surprise a later reader of the files is
refused here, not tolerated: absolute or ``..`` paths (zip-slip), backslashes and drive
letters, control characters, two entries that normalise to the same path (also when only
the case differs), symbolic links and every other non-regular file, encrypted entries,
and archives that are too large, too big when unpacked, or hold too many files.
"""

from __future__ import annotations

import hashlib
import io
import stat
import struct
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass

from central_governance_api.admission.errors import (
    AdmissionContentInvalidError,
    AdmissionContentTooLargeError,
)


_CHUNK = 64 * 1024


@dataclass(frozen=True)
class UnpackedFile:
    path: str
    sha256: str
    size: int


def normalise_path(raw: str) -> str:
    """The one path form used in fingerprints, or ``AdmissionContentInvalidError``."""
    if not raw or "\x00" in raw or "\\" in raw:
        raise AdmissionContentInvalidError("an archive path is empty or malformed")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        raise AdmissionContentInvalidError("an archive path holds control characters")
    path = unicodedata.normalize("NFC", raw)
    if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        raise AdmissionContentInvalidError("an archive path is absolute")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise AdmissionContentInvalidError("an archive path escapes or is not clean")
    return path


def unpack_zip(
    data: bytes, *, max_files: int, max_uncompressed_bytes: int
) -> list[UnpackedFile]:
    """The files of ``data`` with their hashes, or an ``AdmissionContent*`` error.

    Anything the zip reader itself raises on a damaged or unusual archive (a bad CRC,
    a truncated stream, a method it cannot read) is the submitter's problem, not a
    server error, so it becomes ``AdmissionContentInvalidError`` too."""
    try:
        return _unpack(
            data, max_files=max_files, max_uncompressed_bytes=max_uncompressed_bytes
        )
    except (
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        NotImplementedError,
        RuntimeError,
        EOFError,
        OverflowError,
        zlib.error,
        struct.error,
    ):
        raise AdmissionContentInvalidError(
            "the archive is damaged or uses an unsupported zip feature"
        ) from None


def _unpack(
    data: bytes, *, max_files: int, max_uncompressed_bytes: int
) -> list[UnpackedFile]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise AdmissionContentInvalidError(
            "the archive is not a valid zip file"
        ) from None
    with archive:
        infos = archive.infolist()
        if len(infos) > max_files:
            raise AdmissionContentTooLargeError()
        if sum(info.file_size for info in infos) > max_uncompressed_bytes:
            raise AdmissionContentTooLargeError()
        # The first entry must start at byte 0. A zip with something in front of it
        # (a second archive, a self-extracting stub) is read by this library from its
        # LAST end-of-directory record, so another unpacker could take a different one.
        if infos and min(info.header_offset for info in infos) != 0:
            raise AdmissionContentInvalidError(
                "the archive has data before its first entry"
            )
        seen: set[str] = set()
        directories: set[str] = set()
        out: list[UnpackedFile] = []
        total = 0
        for info in infos:
            if info.flag_bits & 0x1:
                raise AdmissionContentInvalidError(
                    "the archive holds an encrypted entry"
                )
            # Only an entry that SAYS it is a link, device, FIFO or socket is refused.
            # Archives written by Python's zipfile or by Windows tools carry no type
            # bits (0): an unspecified type is extracted as a regular file.
            kind = stat.S_IFMT(info.external_attr >> 16)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise AdmissionContentInvalidError(
                    "the archive holds a link or another non-regular file"
                )
            # ``orig_filename``, not ``filename``: Python's zipfile cleans the latter
            # (a backslash becomes "/" on Windows, a name is cut at NUL), so another
            # tool unpacking the same archive could see a path this code cannot.
            stored = info.orig_filename
            if info.is_dir():
                directories.add(normalise_path(stored.rstrip("/")).casefold())
                continue
            path = normalise_path(stored)
            folded = path.casefold()
            if folded in seen:
                raise AdmissionContentInvalidError(
                    "two archive paths are the same after normalisation"
                )
            seen.add(folded)
            digest = hashlib.sha256()
            size = 0
            with archive.open(info) as handle:
                while chunk := handle.read(_CHUNK):
                    size += len(chunk)
                    total += len(chunk)
                    if total > max_uncompressed_bytes:
                        raise AdmissionContentTooLargeError()
                    digest.update(chunk)
            out.append(UnpackedFile(path=path, sha256=digest.hexdigest(), size=size))
        if not out:
            raise AdmissionContentInvalidError("the archive holds no files")
        # A name cannot be a file and also the folder of another entry: unpackers
        # resolve that differently (overwrite, skip, fail half way).
        for entry in seen:
            parts = entry.split("/")
            parents = {"/".join(parts[:i]) for i in range(1, len(parts))}
            if parents & seen:
                raise AdmissionContentInvalidError(
                    "an archive path is both a file and a folder"
                )
        if directories & seen:
            raise AdmissionContentInvalidError(
                "an archive path is both a file and a folder"
            )
        return out
