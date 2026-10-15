"""Draw the stratified sample that a labeller marks (mapping.md, "估計設計").

    python sample.py --actions out/actions.jsonl --out out/labels

Writes, into the output directory:

- ``label_batch_N.json``   what the labeller sees: an opaque id, the tool, the cwd
                           class and the de-identified features. NOT the analyzer's
                           answer, the stratum or any weight.
- ``label_repeat.json``    a few of the same items under new ids, for a
                           self-consistency check.
- ``label_key.json``       id -> index, stratum, the stratum's population and sample
                           size, the analyzer's answer. Kept apart; never shown.

The allocation below was fixed after the population counts and before any label.
Sampling inside a stratum is simple random, equal probability (so N_h/n_h is the
right weight), reproducible from SEED.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any


SEED = 20261015
BATCH_SIZE = 75
REPEAT = 20

# (asked?, OpenHands tool, cwd class) -> sample size. A stratum with fewer calls than
# this is taken whole (and only described, not given an interval). Strata not listed
# are not sampled.
ALLOCATION: dict[tuple[bool, str, str], int] = {
    (True, "terminal", "project"): 50,
    (True, "terminal", "broad"): 40,
    (True, "file_editor", "project"): 40,
    (True, "file_editor", "broad"): 10,
    (True, "grep", "project"): 25,
    (True, "grep", "broad"): 10,
    (True, "glob", "project"): 10,
    (True, "glob", "broad"): 10,
    (True, "task_tracker", "project"): 15,
    (True, "task_tracker", "broad"): 15,
    (True, "mcp_tool", "project"): 25,
    (True, "mcp_tool", "broad"): 25,
    # not asked by the analyzer: how often would a person have wanted to be asked?
    (False, "file_editor", "project"): 20,
    (False, "file_editor", "broad"): 20,
    (False, "grep", "project"): 10,
    (False, "grep", "broad"): 10,
    (False, "glob", "project"): 5,
    (False, "glob", "broad"): 5,
}


def stratum_of(row: dict[str, Any]) -> tuple[bool, str, str] | None:
    if row.get("category") not in ("mapped", "mcp") or row.get("confirm") is None:
        return None
    return (bool(row["confirm"]), row["mapped"], row["cwd_class"])


def draw(rows: list[dict[str, Any]], seed: int = SEED) -> list[dict[str, Any]]:
    """The sampled rows, each with its stratum and that stratum's N and n."""
    by_stratum: dict[tuple[bool, str, str], list[dict[str, Any]]] = {}
    for row in rows:
        key = stratum_of(row)
        if key is not None and key in ALLOCATION:
            by_stratum.setdefault(key, []).append(row)
    rng = random.Random(seed)
    chosen: list[dict[str, Any]] = []
    for key in sorted(by_stratum, key=str):
        members = sorted(by_stratum[key], key=lambda r: r["i"])
        rng.shuffle(members)
        n = min(ALLOCATION[key], len(members))
        for row in members[:n]:
            chosen.append({**row, "_stratum": key, "_N": len(members), "_n": n})
    return chosen


def visible(row: dict[str, Any], label_id: str) -> dict[str, Any]:
    """What the labeller may see of a row (and nothing else)."""
    return {
        "id": label_id,
        "tool": row["cc_tool"],
        "cwd_class": row["cwd_class"],
        "features": row.get("shape", {}),
    }


def build(rows: list[dict[str, Any]], seed: int = SEED) -> dict[str, Any]:
    """The batches the labeller sees, the repeat set, and the key kept apart."""
    chosen = draw(rows, seed)
    rng = random.Random(seed + 1)
    rng.shuffle(chosen)  # no order that follows the strata
    ids = [f"L{n:04d}" for n in range(1, len(chosen) + 1)]
    rng.shuffle(ids)  # and ids that do not follow the order either
    key: dict[str, Any] = {}
    shown: list[dict[str, Any]] = []
    for row, label_id in zip(chosen, ids, strict=True):
        shown.append(visible(row, label_id))
        asked, tool, cwd = row["_stratum"]
        key[label_id] = {
            "i": row["i"],
            "sess": row["sess"],
            "asked": asked,
            "tool": tool,
            "cwd_class": cwd,
            "N": row["_N"],
            "n": row["_n"],
            "risk": row["risk"],
        }
    batches = [shown[k : k + BATCH_SIZE] for k in range(0, len(shown), BATCH_SIZE)]
    repeat_source = rng.sample(shown, min(REPEAT, len(shown)))
    repeat: list[dict[str, Any]] = []
    for item in repeat_source:
        new_id = f"R{len(repeat) + 1:04d}"
        repeat.append({**item, "id": new_id})
        key[new_id] = {"repeat_of": item["id"]}
    rng.shuffle(repeat)
    return {"batches": batches, "repeat": repeat, "key": key}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--actions", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    rows = [
        json.loads(line)
        for line in Path(args.actions).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    built = build(rows)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for n, batch in enumerate(built["batches"], 1):
        (out / f"label_batch_{n}.json").write_text(
            json.dumps(batch, indent=1), encoding="utf-8"
        )
    (out / "label_repeat.json").write_text(
        json.dumps(built["repeat"], indent=1), encoding="utf-8"
    )
    (out / "label_key.json").write_text(
        json.dumps(built["key"], indent=1), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "sampled": sum(len(b) for b in built["batches"]),
                "batches": len(built["batches"]),
                "repeat": len(built["repeat"]),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
