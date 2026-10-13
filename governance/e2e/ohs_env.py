"""Where things are, for the governance end-to-end scripts in this directory.

The scripts used to name one developer's folders. They now find them from where this
checkout is, and every location can be overridden:

  OHS_CENTRAL_DIR     the central-governance-api checkout
                      (default: the sibling directory `central-governance-api` of
                      this repository)
  OHS_CENTRAL_PYTHON  its Python (default: <central>/.venv/{Scripts/python.exe|bin/python})
  OHS_PG_BIN          the directory of the PostgreSQL programs (psql, createdb, dropdb,
                      ...); default "C:/Program Files/PostgreSQL/17/bin" on Windows,
                      else they are found on PATH

SPY, the Python that runs the agent-server, is the interpreter running the script, so
run these with the Python that can import `openhands.agent_server`.
"""

import os
import pathlib
import sys


REPO = pathlib.Path(__file__).resolve().parents[2]  # governance/<this dir>/this file
SDK = REPO.as_posix()
SPY = sys.executable
_VENV_PYTHON = "Scripts/python.exe" if os.name == "nt" else "bin/python"
CENTRAL = (
    os.environ.get("OHS_CENTRAL_DIR")
    or (REPO.parent / "central-governance-api").as_posix()
)
CPY = os.environ.get("OHS_CENTRAL_PYTHON") or f"{CENTRAL}/.venv/{_VENV_PYTHON}"
PG_BIN = os.environ.get("OHS_PG_BIN") or (
    "C:/Program Files/PostgreSQL/17/bin" if os.name == "nt" else ""
)


def pg_tool(name: str) -> str:
    """Path of a PostgreSQL program: in OHS_PG_BIN if set, else found on PATH."""
    exe = name + (".exe" if os.name == "nt" else "")
    return f"{PG_BIN}/{exe}" if PG_BIN else exe
