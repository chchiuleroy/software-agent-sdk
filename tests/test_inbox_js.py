"""Runs the Node unit tests of the inbox script (tests/js/*.test.mjs).

Files are globbed because Node 22 does not accept a directory for --test.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


_JS_DIR = Path(__file__).resolve().parent / "js"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_inbox_script_unit_tests_pass():
    result = subprocess.run(
        ["node", "--test", *map(str, sorted(_JS_DIR.glob("*.test.mjs")))],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
