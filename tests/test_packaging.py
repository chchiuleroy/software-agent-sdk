"""Regression test for a real bug found 2026-09-16: this project's own
``pyproject.toml`` ``[project.scripts]`` entry silently pointed at a
``uv init`` placeholder (``def main(): print("Hello from
central-governance-api!")``) for the entire time between step 1's
scaffolding and the first real deployment. Nobody caught it because every
test in this suite exercises the app via ``main.create_app()`` directly
(``httpx.ASGITransport``) — none of them ever went through this package's
actual installed console-script entry point, the one thing
``uv run central-governance-api`` itself uses.

This resolves the SAME distribution metadata that command resolves, so it
fails the same way a real invocation would if the entry point is ever
repointed at something hollow again — a placeholder, a typo, a moved
module — without anyone needing to remember to test it by hand.
"""

from __future__ import annotations

import importlib.metadata

from central_governance_api.main import main as real_main


def test_console_script_entry_point_resolves_to_real_main():
    (entry_point,) = importlib.metadata.entry_points(
        group="console_scripts", name="central-governance-api"
    )
    loaded = entry_point.load()
    assert loaded is real_main
