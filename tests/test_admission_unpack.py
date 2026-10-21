"""Reading a submitted archive: what is accepted and what is refused, and why each
refusal exists. Archives are built in memory; nothing touches the disk."""

from __future__ import annotations

import hashlib
import io
import stat
import unicodedata
import zipfile

import pytest

from central_governance_api.admission.errors import (
    AdmissionContentInvalidError,
    AdmissionContentTooLargeError,
)
from central_governance_api.admission.unpack import unpack_zip


LIMITS = {"max_files": 50, "max_uncompressed_bytes": 10_000}


def _zip(entries: dict[str, bytes], *, attrs: dict[str, int] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if attrs and name in attrs:
                info.external_attr = attrs[name] << 16
            archive.writestr(info, data)
    return buffer.getvalue()


def _unpack(data: bytes, **overrides):
    return unpack_zip(data, **{**LIMITS, **overrides})


def test_files_are_listed_with_their_real_hashes_including_hidden_ones():
    out = _unpack(_zip({"SKILL.md": b"hello", ".hidden/x.sh": b"echo"}))
    by_path = {f.path: f for f in out}
    assert set(by_path) == {"SKILL.md", ".hidden/x.sh"}
    assert by_path["SKILL.md"].sha256 == hashlib.sha256(b"hello").hexdigest()
    assert by_path[".hidden/x.sh"].size == 4


def test_directory_entries_are_ignored_and_paths_are_nfc():
    decomposed = unicodedata.normalize("NFD", "é.md")
    out = _unpack(_zip({"docs/": b"", decomposed: b"x"}))
    assert [f.path for f in out] == [unicodedata.normalize("NFC", "é.md")]


@pytest.mark.parametrize(
    "name",
    [
        "../escape.txt",
        "a/../../escape.txt",
        "/etc/passwd",
        "C:/Windows/x",
        "C:evil",
        "a//b.txt",
        "./a.txt",
        "tab\tname",
    ],
)
def test_a_path_that_escapes_or_is_not_clean_is_refused(name):
    # Why: zip-slip and look-alike paths are how an archive writes outside its folder
    # or hides from a path comparison.
    with pytest.raises(AdmissionContentInvalidError):
        _unpack(_zip({name: b"x"}))


@pytest.mark.parametrize("evil", [chr(92), chr(0)], ids=["backslash", "nul"])
def test_a_backslash_or_nul_in_a_stored_name_is_refused(evil):
    # Python's ZipInfo rewrites a backslash to "/" and cuts a name at NUL when it BUILDS
    # an archive, so such a name can only be made by editing the bytes. Another tool
    # reading the same archive would not rewrite it, which is the danger.
    data = _zip({"aXb.txt": b"x"}).replace(b"aXb.txt", ("a" + evil + "b.txt").encode())
    with pytest.raises(AdmissionContentInvalidError):
        _unpack(data)


def test_a_symbolic_link_is_refused():
    # Why: a link inside a skill can point at ~/.claude (SymJack).
    link = stat.S_IFLNK | 0o777
    with pytest.raises(AdmissionContentInvalidError):
        _unpack(_zip({"SKILL.md": b"x", "link": b"/etc"}, attrs={"link": link}))


def test_a_device_or_fifo_entry_is_refused():
    with pytest.raises(AdmissionContentInvalidError):
        _unpack(_zip({"x": b""}, attrs={"x": stat.S_IFIFO | 0o644}))


def test_two_paths_that_are_the_same_after_normalisation_or_case_are_refused():
    # Why: on a case-insensitive or normalising file system they would overwrite each
    # other, so what is checked is not what is installed.
    with pytest.raises(AdmissionContentInvalidError):
        _unpack(_zip({"Skill.md": b"a", "skill.md": b"b"}))
    nfc = unicodedata.normalize("NFC", "é")
    nfd = unicodedata.normalize("NFD", "é")
    with pytest.raises(AdmissionContentInvalidError):
        _unpack(_zip({nfc: b"a", nfd: b"b"}))


def test_an_empty_or_broken_archive_is_refused():
    with pytest.raises(AdmissionContentInvalidError):
        _unpack(_zip({"only_a_dir/": b""}))
    with pytest.raises(AdmissionContentInvalidError):
        _unpack(b"this is not a zip file")


def test_too_many_files_is_refused():
    many = {f"f{i}.txt": b"x" for i in range(6)}
    with pytest.raises(AdmissionContentTooLargeError):
        _unpack(_zip(many), max_files=5)


def test_a_zip_bomb_is_refused_by_what_it_unpacks_to_not_what_it_weighs():
    # Why: 20 KB of zeros compress to a few dozen bytes; the limit must be on the
    # unpacked size, and it is checked both from the headers and while reading.
    bomb = _zip({"zeros.bin": b"\x00" * 20_000})
    assert len(bomb) < 1_000
    with pytest.raises(AdmissionContentTooLargeError):
        _unpack(bomb)


def test_an_encrypted_entry_is_refused():
    data = bytearray(_zip({"a.txt": b"x"}))
    # set the "encrypted" bit (0x1) in both the local and the central directory header
    for marker in (b"PK\x03\x04", b"PK\x01\x02"):
        at = data.find(marker)
        offset = at + (6 if marker == b"PK\x03\x04" else 8)
        data[offset] |= 0x1
    with pytest.raises(AdmissionContentInvalidError):
        _unpack(bytes(data))


def test_a_damaged_entry_is_the_submitters_error_not_a_server_error():
    # Why (review finding): the zip reader raises BadZipFile when an entry is read, not
    # only when the archive is opened. Stored (uncompressed) so a byte can be flipped.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("SKILL.md", b"hello world")
    damaged = buffer.getvalue().replace(b"hello world", b"hellX world")
    with pytest.raises(AdmissionContentInvalidError):
        _unpack(damaged)


def test_an_archive_with_something_in_front_of_it_is_refused():
    # Why (review finding): two archives joined end to end, or a stub in front. This
    # library reads the LAST directory, so what central fingerprints could differ from
    # what another unpacker extracts.
    first = _zip({"SKILL.md": b"the first archive"})
    second = _zip({"SKILL.md": b"the second archive"})
    with pytest.raises(AdmissionContentInvalidError):
        _unpack(first + second)
    with pytest.raises(AdmissionContentInvalidError):
        _unpack(b"#!/bin/sh\n" + second)


@pytest.mark.parametrize(
    "entries",
    [
        {"a": b"x", "a/b": b"y"},
        {"a/b/c": b"x", "a/b": b"y"},
        {"Docs": b"x", "docs/readme.md": b"y"},
        {"a/": b"", "a": b"x"},
    ],
    ids=["file+child", "deep", "case-folded", "dir+file"],
)
def test_a_path_that_is_both_a_file_and_a_folder_is_refused(entries):
    # Why (review finding): unpackers differ on what happens (overwrite, skip, stop
    # half way), so the installed content is not the checked content.
    with pytest.raises(AdmissionContentInvalidError):
        _unpack(_zip(entries))
