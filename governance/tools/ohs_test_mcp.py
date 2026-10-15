"""A small MCP server for testing how the governance layer treats MCP tools (item 1.5).

Three tools with plain, harmless effects, served over streamable HTTP on loopback
only (127.0.0.1): an MCP server is code that runs with the user's rights, so a test
server must not be reachable from the network. The host is fixed; asking for
anything else is refused.

  sum_numbers(a, b)   returns a + b                           (no side effect)
  word_count(text)    returns the number of words             (no side effect)
  add_note(text)      appends a line to a file in a temp dir  (a real side effect)

``add_note`` is what an end-to-end test checks: if governance refuses the call, the
file is not written.

Run it with the SDK venv python::

    python governance/tools/ohs_test_mcp.py --port 18795

Environment:

  OHS_TEST_MCP_NOTES_FILE   where ``add_note`` writes (default: a file in the system
                            temp dir)
  OHS_TEST_MCP_DESC_SUFFIX  appended to ``word_count``'s description; changing it
                            between runs is how a test makes the server describe a
                            tool differently from before (a "rug pull")
"""

from __future__ import annotations

import argparse
import os
import pathlib
import tempfile

from fastmcp import FastMCP


HOST = "127.0.0.1"
PATH = "/mcp"
DESCRIPTION = "Count the words in a text."


def notes_file() -> pathlib.Path:
    configured = os.environ.get("OHS_TEST_MCP_NOTES_FILE")
    return (
        pathlib.Path(configured)
        if configured
        else pathlib.Path(tempfile.gettempdir()) / "ohs_test_mcp_notes.txt"
    )


def build_server(description_suffix: str = "") -> FastMCP:
    mcp = FastMCP("ohs_test")

    @mcp.tool
    def sum_numbers(a: float, b: float) -> float:
        """Add two numbers."""
        return a + b

    @mcp.tool(description=DESCRIPTION + description_suffix)
    def word_count(text: str) -> int:
        return len(text.split())

    @mcp.tool
    def add_note(text: str) -> str:
        """Append one line to the test notes file."""
        with notes_file().open("a", encoding="utf-8") as handle:
            handle.write(text.replace("\n", " ") + "\n")
        return "noted"

    return mcp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument(
        "--host", default=HOST, help=f"only {HOST} is accepted (loopback)"
    )
    args = parser.parse_args(argv)
    if args.host != HOST:
        parser.error(f"this test server only listens on {HOST}, not {args.host!r}")
    server = build_server(os.environ.get("OHS_TEST_MCP_DESC_SUFFIX", ""))
    server.run(transport="http", host=HOST, port=args.port, path=PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
