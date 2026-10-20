"""Content fingerprints for admission items. Pure functions, no I/O.

These must agree, byte for byte, with what a device computes from the same content,
because "approved" means "this exact fingerprint". The device side lives in the
openhands-sdk-governed repository (``governance_mcp_fingerprint.py`` for one MCP tool);
the golden vectors in ``tests/test_admission_fingerprint.py`` were produced by that
implementation and pin the two against each other. The algorithm is therefore
duplicated across the two repositories on purpose and the golden vectors are the
contract between them.

Three kinds of fingerprint:

* one MCP tool: SHA-256 over canonical JSON (keys sorted, no whitespace, ASCII escapes)
  of exactly ``name``, ``description`` and ``input_schema``;
* an MCP server item: SHA-256 over the sorted tool fingerprints, one per line (what is
  approved is that SET of tools, not the server's address);
* a skill or plugin: SHA-256 over a manifest of every file, one ``path<TAB>sha256`` line
  per file sorted by path. Paths are NFC-normalised and use ``/``; hidden files and
  hidden directories count like any other; file modes, timestamps and empty
  directories do not count.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any


PREFIX = "sha256:"


def _require_plain_json(value: Any) -> None:
    """``json.dumps`` quietly turns an integer key into a string and a tuple into a
    list, so those would share a fingerprint with the JSON they imitate."""
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"schema key {key!r} is not a string")
            _require_plain_json(item)
    elif isinstance(value, tuple):
        raise TypeError("schema holds a tuple; JSON has only lists")
    elif isinstance(value, list):
        for item in value:
            _require_plain_json(item)


def mcp_tool_fingerprint(
    name: str, description: str | None, input_schema: dict[str, Any]
) -> str:
    """Fingerprint of one MCP tool. Raises ``TypeError``/``ValueError`` for a schema
    that is not plain JSON (NaN, infinity, a non-string key...)."""
    _require_plain_json(input_schema)
    canonical = json.dumps(
        {"name": name, "description": description, "input_schema": input_schema},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return PREFIX + hashlib.sha256(canonical.encode("ascii")).hexdigest()


def mcp_server_fingerprint(tool_fingerprints: Iterable[str]) -> str:
    """Fingerprint of a set of tools: order-independent, duplicates are an error."""
    ordered = sorted(tool_fingerprints)
    if len(ordered) != len(set(ordered)):
        raise ValueError("duplicate tool fingerprint")
    return PREFIX + hashlib.sha256("\n".join(ordered).encode("ascii")).hexdigest()


def manifest_fingerprint(files: Iterable[tuple[str, str]]) -> str:
    """Fingerprint of a directory given as ``(normalised path, sha256 hex)`` pairs."""
    pairs = sorted(files)
    paths = [path for path, _ in pairs]
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate path")
    text = "".join(f"{path}\t{digest}\n" for path, digest in pairs)
    return PREFIX + hashlib.sha256(text.encode("utf-8")).hexdigest()
