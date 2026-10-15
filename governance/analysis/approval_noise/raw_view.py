"""Label a sample of Bash calls from their RAW command, and compare with the
de-identified view (Roy agreed on 2026-10-15; the first report left Bash mostly
undecidable because the features hide what a script does).

The raw text stays on this machine except for what is sent to the labeller, and what is
sent is scrubbed first (home directory -> "~", secret-looking text removed, long
commands cut). Nothing here is committed: ``replay.py --raw-bash`` writes the raw
commands next to ``actions.jsonl`` in a directory that is git-ignored, and the prompts
this module builds go to the scratch directory.

    python raw_view.py draw   --actions out/actions.jsonl --raw out/raw_bash.jsonl --out out/raw_study
    python raw_view.py report --actions out/actions.jsonl --study out/raw_study

``draw`` writes, per item, the two views the labeller sees (``raw_batch.json`` with the
scrubbed command, ``feature_batch.json`` with only the de-identified features), and a
``key.json`` that is never shown. ``report`` reads the two answer files and prints the
estimate under each view for the SAME items.
"""

from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path
from typing import Any


SEED = 20261015
ALLOCATION = {"project": 50, "broad": 40}
MAX_COMMAND_CHARS = 1500

# Text that looks like a credential. Deliberately broad: an over-scrubbed command only
# costs the labeller some context, a leaked secret cannot be taken back.
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)",
            re.S,
        ),
        "<private-key>",
    ),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"), "<jwt>"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<aws-key>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "<github-token>"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "<github-token>"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "<api-key>"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "<slack-token>"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 <redacted>"),
    (re.compile(r"(?i)(authorization:\s*)\S+(\s+\S+)?"), r"\1<redacted>"),
    (re.compile(r"(?i)(x-api-key:\s*)\S+"), r"\1<redacted>"),
    (
        re.compile(
            r"(?i)\b([A-Za-z0-9_]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)[A-Za-z0-9_]*)"
            r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
        ),
        r"\1\2<redacted>",
    ),
    (
        re.compile(
            r"(?i)(--(?:password|passwd|token|secret|api-key|key)[ =])(\"[^\"]*\"|'[^']*'|\S+)"
        ),
        r"\1<redacted>",
    ),
    (re.compile(r"(?i)(\s-p)(\"[^\"]+\"|'[^']+'|\S{4,})(?=\s|$)"), r"\1<redacted>"),
    (re.compile(r"(://[^/\s:@]+:)[^@\s/]+(@)"), r"\1<redacted>\2"),
    (re.compile(r"\b[A-Fa-f0-9]{40,}\b"), "<hex>"),
    # a long token that mixes upper case, lower case and digits (base64 and the like);
    # a path or an identifier is long too but has no such mix, and keeping paths
    # readable is what the study is for
    (
        re.compile(
            r"(?<![A-Za-z0-9+_/.-])(?=[A-Za-z0-9+_-]*[0-9])(?=[A-Za-z0-9+_-]*[A-Z])"
            r"(?=[A-Za-z0-9+_-]*[a-z])[A-Za-z0-9+_-]{40,}={0,2}(?![A-Za-z0-9+_/.-])"
        ),
        "<blob>",
    ),
]


def scrub(text: str, home: str | None = None) -> str:
    """The text with the home directory shortened and credential-looking parts removed,
    cut to ``MAX_COMMAND_CHARS`` (what was cut is said so)."""
    out = str(text)
    if home:
        for variant in {home, home.replace("\\", "/"), home.replace("/", "\\")}:
            if variant:
                out = re.sub(re.escape(variant) + r"(?![A-Za-z0-9_.-])", "~", out)
        # the same directory written by another tool: /c/Users/name (Git Bash),
        # /mnt/c/Users/name (WSL), a lower-case drive, a forward or back slash
        name = re.split(r"[/\\]", home.rstrip("/\\"))[-1]
        if name:
            out = re.sub(
                r"(?i)(?:[A-Za-z]:|/mnt/[a-z]|/[a-z])?[/\\]+Users[/\\]+"
                + re.escape(name)
                + r"(?![A-Za-z0-9_.-])",
                "~",
                out,
            )
    for pattern, replacement in _SECRET_PATTERNS:
        out = pattern.sub(replacement, out)
    if len(out) > MAX_COMMAND_CHARS:
        out = (
            out[:MAX_COMMAND_CHARS]
            + f"  [... cut: {len(out) - MAX_COMMAND_CHARS} more characters]"
        )
    return out


def asked_bash(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """The population: Bash calls the analyzer asks about, by cwd class."""
    population: dict[str, list[dict[str, Any]]] = {"project": [], "broad": []}
    for row in rows:
        if (
            row.get("mapped") == "terminal"
            and row.get("confirm") is True
            and row.get("cwd_class") in population
        ):
            population[row["cwd_class"]].append(row)
    return population


def draw(
    rows: list[dict[str, Any]],
    raw: dict[int, dict[str, Any]],
    seed: int = SEED,
    home: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Simple random sample inside each cwd class (equal probability, so N_h/n_h is
    the weight). Returns the items the labeller sees (each carries both views) and
    the key (id -> index, class, population size, sample size)."""
    rng = random.Random(seed)
    population = asked_bash(rows)
    items: list[dict[str, Any]] = []
    key: dict[str, dict[str, Any]] = {}
    counter = 0
    for cwd_class, size in ALLOCATION.items():
        pool = sorted(population[cwd_class], key=lambda r: r["i"])
        chosen = rng.sample(pool, min(size, len(pool)))
        for row in chosen:
            counter += 1
            label_id = f"B{counter:03d}"
            command = raw.get(row["i"])
            if command is None:
                raise SystemExit(
                    f"no raw command for action {row['i']}: rerun replay.py --raw-bash"
                )
            items.append(
                {
                    "id": label_id,
                    "cwd_class": cwd_class,
                    "features": row["shape"],
                    "command": scrub(command["command"], home),
                    "cwd": scrub(command["cwd"] or "", home),
                }
            )
            key[label_id] = {
                "i": row["i"],
                "sess": row["sess"],
                "cwd_class": cwd_class,
                "N": len(pool),
                "n": len(chosen),
            }
    rng.shuffle(items)
    return items, key


def raw_view(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": i["id"],
            "cwd_class": i["cwd_class"],
            "cwd": i["cwd"],
            "command": i["command"],
        }
        for i in items
    ]


def feature_view(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": i["id"],
            "tool": "Bash",
            "cwd_class": i["cwd_class"],
            "features": i["features"],
        }
        for i in items
    ]


LABELS = ("NECESSARY", "NOT_NECESSARY", "CANNOT_TELL")


def estimate(key: dict[str, dict[str, Any]], labels: dict[str, str]) -> dict[str, Any]:
    """Weighted shares among the asked Bash calls (weights N_h / n_h per cwd class):
    lower bound = NOT_NECESSARY only, upper = NOT_NECESSARY + CANNOT_TELL."""
    totals = {"NECESSARY": 0.0, "NOT_NECESSARY": 0.0, "CANNOT_TELL": 0.0}
    population = 0.0
    for cwd_class in ALLOCATION:
        ids = [k for k, v in key.items() if v["cwd_class"] == cwd_class and k in labels]
        if not ids:
            continue
        info = key[ids[0]]
        weight = info["N"] / len(ids)
        population += info["N"]
        for label_id in ids:
            totals[labels[label_id]] += weight
    if population == 0:
        return {"n": 0}
    return {
        "n": sum(1 for k in key if k in labels),
        "necessary": totals["NECESSARY"] / population,
        "not_necessary": totals["NOT_NECESSARY"] / population,
        "cannot_tell": totals["CANNOT_TELL"] / population,
        "a_low": totals["NOT_NECESSARY"] / population,
        "a_high": (totals["NOT_NECESSARY"] + totals["CANNOT_TELL"]) / population,
    }


def agreement(a: dict[str, str], b: dict[str, str]) -> dict[str, Any]:
    """How the same items were labelled in two views."""
    common = sorted(set(a) & set(b))
    table: dict[str, int] = {}
    for label_id in common:
        pair = f"{a[label_id]} -> {b[label_id]}"
        table[pair] = table.get(pair, 0) + 1
    return {"items": len(common), "pairs": dict(sorted(table.items()))}


def parse_labels(text: str, expected: set[str]) -> dict[str, str]:
    """The labeller's JSON array: only valid, expected, once-answered ids count."""
    match = re.search(r"\[.*\]", text, re.S)
    if not match:
        return {}
    try:
        data = json.loads(match.group(0))
    except ValueError:
        return {}
    labels: dict[str, str] = {}
    seen: set[str] = set()
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        label_id, label = item.get("id"), item.get("label")
        if label_id in seen:
            labels.pop(label_id, None)
            continue
        seen.add(label_id)
        if label_id in expected and label in LABELS:
            labels[label_id] = label
    return labels


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("draw")
    d.add_argument("--actions", required=True)
    d.add_argument("--raw", required=True)
    d.add_argument("--out", required=True)
    r = sub.add_parser("report")
    r.add_argument("--study", required=True)
    args = parser.parse_args(argv)

    if args.cmd == "draw":
        rows = [
            json.loads(line)
            for line in Path(args.actions).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        raw = {}
        for line in Path(args.raw).read_text(encoding="utf-8").splitlines():
            if line.strip():
                item = json.loads(line)
                raw[item["i"]] = item
        items, key = draw(rows, raw, home=str(Path.home()))
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "raw_batch.json").write_text(
            json.dumps(raw_view(items), ensure_ascii=False, indent=1), encoding="utf-8"
        )
        (out / "feature_batch.json").write_text(
            json.dumps(feature_view(items), ensure_ascii=False, indent=1),
            encoding="utf-8",
        )
        (out / "key.json").write_text(json.dumps(key, indent=1), encoding="utf-8")
        print(f"drew {len(items)} items")
        return 0

    study = Path(args.study)
    key = json.loads((study / "key.json").read_text(encoding="utf-8"))
    expected = set(key)
    views = {
        name: parse_labels(
            (study / f"{name}_out.txt").read_text(encoding="utf-8"), expected
        )
        for name in ("raw", "feature")
    }
    print(
        json.dumps(
            {name: estimate(key, labels) for name, labels in views.items()}, indent=1
        )
    )
    print(json.dumps(agreement(views["feature"], views["raw"]), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
