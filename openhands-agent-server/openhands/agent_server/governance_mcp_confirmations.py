"""A registry of confirmed MCP tools: "confirmed" is tied to the tool's fingerprint.

Item 1.5 / O3. A confirmation says "this exact tool, as this server described it, may
be used". It stays true only while the description the server gives today has the same
fingerprint (``governance_mcp_fingerprint``) as the one that was confirmed. When the
server changes the name text, the description or the input schema, the tool is
unconfirmed again and must be confirmed again; nothing here ever updates a stored
fingerprint on its own.

Nothing in the agent-server's approval path consults this registry yet: every MCP tool
is still refused in team mode, and confirming a tool here does not lift that. Two
things have to exist first: an approval screen that shows what an MCP call does (today
the approver sees only the tool name and the argument sizes), and a way to know which
server a tool really came from.

``server_id`` is whatever the operator configured for the server (a name or a URL).
It is part of the key so that the same tool name on another server is not confirmed,
but it is NOT proof of where a tool came from: whoever controls what answers at that
address controls the description too, and a changed description is exactly what the
fingerprint catches.

Fail closed: a tool whose schema cannot be fingerprinted is never confirmed, a missing
file means nothing is confirmed, and a file that cannot be read raises instead of being
read as "nothing confirmed" (that would hide a damaged registry).
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from openhands.agent_server.governance_mcp_fingerprint import mcp_tool_fingerprint


class McpConfirmations:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path
        self._records: dict[str, dict[str, str]] = {}
        if path is not None and path.exists():
            self._records = self._load(path)

    @staticmethod
    def _key(server_id: str, tool_name: str) -> str:
        # a JSON array cannot be confused by a separator inside either part
        return json.dumps([server_id, tool_name], ensure_ascii=True)

    @staticmethod
    def _load(path: Path) -> dict[str, dict[str, str]]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(
                f"confirmation registry {path} is unreadable: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise ValueError(f"confirmation registry {path} is not a JSON object")
        for key, record in data.items():
            if not (
                isinstance(record, dict)
                and isinstance(record.get("fingerprint"), str)
                and isinstance(record.get("confirmed_by"), str)
            ):
                raise ValueError(f"confirmation registry {path}: bad record for {key}")
        return data

    def _save(self, records: dict[str, dict[str, str]]) -> None:
        """Write ``records`` to disk. The caller updates ``self._records`` only after
        this returns, so a failed write changes nothing in memory either."""
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(records, handle, sort_keys=True, indent=2)
            os.replace(tmp, self._path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def confirm(
        self,
        server_id: str,
        tool_name: str,
        description: str | None,
        input_schema: dict[str, Any],
        confirmed_by: str,
    ) -> str:
        """Record the confirmation of the tool as described right now and return its
        fingerprint. Raises for a schema that cannot be fingerprinted."""
        if not confirmed_by.strip():
            raise ValueError("a confirmation needs the name of who confirmed it")
        fingerprint = mcp_tool_fingerprint(tool_name, description, input_schema)
        updated = dict(self._records)
        updated[self._key(server_id, tool_name)] = {
            "fingerprint": fingerprint,
            "confirmed_by": confirmed_by,
            "confirmed_at": datetime.now(UTC).isoformat(),
        }
        self._save(updated)
        self._records = updated
        return fingerprint

    def is_confirmed(
        self,
        server_id: str,
        tool_name: str,
        description: str | None,
        input_schema: dict[str, Any],
    ) -> bool:
        """True only if this server's tool was confirmed AND describes itself today
        exactly as it did then."""
        record = self._records.get(self._key(server_id, tool_name))
        if record is None:
            return False
        try:
            current = mcp_tool_fingerprint(tool_name, description, input_schema)
        except (TypeError, ValueError):
            return False
        return current == record["fingerprint"]

    def revoke(self, server_id: str, tool_name: str) -> bool:
        """Remove a confirmation; True if there was one."""
        key = self._key(server_id, tool_name)
        if key not in self._records:
            return False
        updated = {k: v for k, v in self._records.items() if k != key}
        self._save(updated)
        self._records = updated
        return True
