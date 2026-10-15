"""A fingerprint for an MCP tool: what a confirmation of that tool must be tied to.

An MCP server describes its own tools (name, description, input schema) and can change
that description at any time. A tool that was confirmed (by a person, or by a check)
should stop counting as confirmed the moment any of the three changes, or "confirm
once" turns into "whatever the server says next is confirmed too". This module only
computes the fingerprint. Nothing in the agent-server uses it yet: there is no
registry of confirmed MCP tools, and every MCP tool is still refused in team mode
(item 1.5, see ``governance/e2e/e2e_mcp_refusal.py``). It is the first piece of
that design, kept small so its behaviour can be pinned down before anything relies
on it.

The fingerprint is a SHA-256 over a canonical JSON (keys sorted, no whitespace, ASCII
escapes) of exactly the three fields. Things that are deliberately part of it:

* the order of list items inside the schema (a server that reorders ``required``
  changes the fingerprint: a spurious re-confirmation is preferred to a missed change);
* ``description`` being absent (``None``) versus empty (``""``).

Things that are deliberately not: the server's address, its name for itself, the
order of the keys of any object.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


FINGERPRINT_PREFIX = "sha256:"


def mcp_tool_fingerprint(
    name: str, description: str | None, input_schema: dict[str, Any]
) -> str:
    """The fingerprint of one MCP tool. Raises ``TypeError``/``ValueError`` for a
    schema that is not plain JSON (a value JSON cannot hold, or NaN/infinity):
    such a tool cannot be fingerprinted and must not be treated as confirmed."""
    canonical = json.dumps(
        {"name": name, "description": description, "input_schema": input_schema},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return FINGERPRINT_PREFIX + hashlib.sha256(canonical.encode("ascii")).hexdigest()
