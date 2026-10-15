"""Turn the labels into the estimates promised in mapping.md ("估計設計").

    python report.py --actions out/actions.jsonl --summary out/summary.json \\
        --labels out/labels --out out/report.md

``out/labels`` holds ``label_key.json`` and the labeller's answers
(``label_batch_N_out.txt`` and ``label_repeat_out.txt``).

The estimates:

- ``P(asked)``: share of the analysed calls the analyzer asks about (a count over the
  whole population, no sampling error).
- ``A``: among the asked calls, the share a labeller marks NOT_NECESSARY, weighted
  by each stratum's N_h/n_h. CANNOT_TELL gives an interval: its lower end counts every
  CANNOT_TELL as necessary, its upper end as not necessary.
- ``N = P(asked) * A``: how often a person is asked about something they need not be.
- the other side: among calls NOT asked, the share marked NECESSARY.
- self-consistency of the labeller on the repeated items.

Intervals are a session-cluster bootstrap, an approximation (see mapping.md).
"""

from __future__ import annotations

import argparse
import json
import random
import re
from collections import Counter
from pathlib import Path
from typing import Any


LABELS = ("NECESSARY", "NOT_NECESSARY", "CANNOT_TELL")
BOOTSTRAP = 1000
SEED = 20261016


def parse_labels(text: str, expected: set[str]) -> tuple[dict[str, str], list[str]]:
    """The labels in the labeller's answer, and what was wrong with it. A repeated id,
    an unknown id, an invalid label or a missing id is a problem, never guessed."""
    problems: list[str] = []
    match = re.search(r"```json\s*(.*?)```", text, re.S)
    body = match.group(1) if match else text
    try:
        data = json.loads(body)
    except ValueError:
        return {}, ["the answer is not valid JSON"]
    if not isinstance(data, list):
        return {}, ["the answer is not a JSON array"]
    labels: dict[str, str] = {}
    for item in data:
        if not isinstance(item, dict):
            problems.append("an entry is not an object")
            continue
        label_id, label = item.get("id"), item.get("label")
        if label_id not in expected:
            problems.append(f"unknown id {label_id!r}")
        elif label_id in labels:
            problems.append(f"{label_id} answered twice")
        elif label not in LABELS:
            problems.append(f"{label_id}: invalid label {label!r}")
        else:
            labels[label_id] = label
    for missing in sorted(expected - set(labels)):
        problems.append(f"{missing}: no valid label")
    return labels, problems


def population_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Counts over the whole replay (no sampling)."""
    analysed = [r for r in rows if r.get("category") in ("mapped", "mcp")]
    asked = [r for r in analysed if r.get("confirm") is True]
    return {
        "calls": len(rows),
        "analysed": len(analysed),
        "asked": len(asked),
        "not_asked": sum(1 for r in analysed if r.get("confirm") is False),
        "not_judged": sum(1 for r in analysed if r.get("confirm") is None),
    }


def _strata(
    key: dict[str, Any], labels: dict[str, str], asked: bool
) -> dict[tuple[str, str], dict[str, Any]]:
    """Per (tool, cwd_class) stratum: N, n and the label counts and session members."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for label_id, info in key.items():
        if "N" not in info or info["asked"] is not asked or label_id not in labels:
            continue
        stratum = out.setdefault(
            (info["tool"], info["cwd_class"]),
            {"N": info["N"], "units": []},
        )
        stratum["units"].append((info["sess"], labels[label_id]))
    return out


def _share(
    strata: dict[Any, dict[str, Any]], numerator: set[str], sessions: Counter | None
) -> float | None:
    """Weighted share of units whose label is in ``numerator``; with ``sessions`` the
    units are those of the resampled sessions (with multiplicity)."""
    total = weighted = 0.0
    for stratum in strata.values():
        hit = n = 0.0
        for sess, label in stratum["units"]:
            weight = 1.0 if sessions is None else float(sessions.get(sess, 0))
            n += weight
            if label in numerator:
                hit += weight
        if n == 0:
            continue  # this stratum has no unit in the resample: leave it out
        weighted += stratum["N"] * (hit / n)
        total += stratum["N"]
    return weighted / total if total else None


def _interval(
    strata: dict[Any, dict[str, Any]], numerator: set[str], seed: int
) -> tuple[float | None, tuple[float, float] | None]:
    point = _share(strata, numerator, None)
    sessions = sorted({s for st in strata.values() for s, _ in st["units"]})
    if point is None or len(sessions) < 2:
        return point, None
    rng = random.Random(seed)
    draws: list[float] = []
    for _ in range(BOOTSTRAP):
        picked = Counter(rng.choice(sessions) for _ in sessions)
        value = _share(strata, numerator, picked)
        if value is not None:
            draws.append(value)
    draws.sort()
    if not draws:
        return point, None
    return point, (draws[int(0.025 * len(draws))], draws[int(0.975 * len(draws)) - 1])


def estimate(
    key: dict[str, Any],
    labels: dict[str, str],
    counts: dict[str, int],
    seed: int = SEED,
) -> dict[str, Any]:
    asked = _strata(key, labels, True)
    not_asked = _strata(key, labels, False)
    p_asked = counts["asked"] / counts["analysed"] if counts["analysed"] else None
    a_low, a_low_ci = _interval(asked, {"NOT_NECESSARY"}, seed)
    a_high, a_high_ci = _interval(asked, {"NOT_NECESSARY", "CANNOT_TELL"}, seed)
    cannot = _share(asked, {"CANNOT_TELL"}, None)
    missed, missed_ci = _interval(not_asked, {"NECESSARY"}, seed)
    result: dict[str, Any] = {
        "p_asked": p_asked,
        "a_low": a_low,
        "a_low_ci": a_low_ci,
        "a_high": a_high,
        "a_high_ci": a_high_ci,
        "cannot_tell_share_of_asked": cannot,
        "missed_necessary": missed,
        "missed_necessary_ci": missed_ci,
    }
    if p_asked is not None:
        result["noise_low"] = None if a_low is None else p_asked * a_low
        result["noise_high"] = None if a_high is None else p_asked * a_high
    return result


def by_stratum(key: dict[str, Any], labels: dict[str, str]) -> list[dict[str, Any]]:
    table: dict[tuple[bool, str, str], dict[str, Any]] = {}
    for label_id, info in key.items():
        if "N" not in info or label_id not in labels:
            continue
        row = table.setdefault(
            (info["asked"], info["tool"], info["cwd_class"]),
            {"N": info["N"], "n": info["n"], "labels": Counter()},
        )
        row["labels"][labels[label_id]] += 1
    return [
        {"asked": k[0], "tool": k[1], "cwd_class": k[2], **v}
        for k, v in sorted(table.items(), key=str)
    ]


def self_consistency(key: dict[str, Any], labels: dict[str, str]) -> dict[str, Any]:
    pairs = [
        (labels.get(info["repeat_of"]), labels.get(label_id))
        for label_id, info in key.items()
        if "repeat_of" in info
    ]
    pairs = [(a, b) for a, b in pairs if a is not None and b is not None]
    same = sum(1 for a, b in pairs if a == b)
    return {
        "pairs": len(pairs),
        "same": same,
        "rate": same / len(pairs) if pairs else None,
    }


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.1f}%"


def _ci(interval: tuple[float, float] | None) -> str:
    return (
        ""
        if interval is None
        else f" (95%: {_pct(interval[0])} to {_pct(interval[1])})"
    )


def render(
    summary: dict[str, int],
    counts: dict[str, int],
    est: dict[str, Any],
    strata: list[dict[str, Any]],
    consistency: dict[str, Any],
    problems: list[str],
) -> str:
    lines = ["# 核准噪音量測報告（自動產生）", ""]
    lines += ["## 覆蓋率", ""]
    lines += [
        f"- 最近 {summary.get('window_days')} 天的工具呼叫共 {counts['calls']} 筆（已去重）；"
        f"可對應且送進分析器 {counts['analysed']} 筆；"
        f"無對應 {summary.get('no_mapping', 0)} 筆；格式不全 {summary.get('malformed', 0)} 筆；"
        f"相對路徑無法解析 {summary.get('unresolved', 0)} 筆；"
        f"沒有 cwd 而不能判斷的檔案類 {counts['not_judged']} 筆。",
        f"- 讀取的檔案數 {summary.get('files')}、行數 {summary.get('lines')}，解析失敗 {summary.get('parse_failures', 0)} 行。",
        "- **結論只限定於可對應的呼叫**，不外推到整個工作負載。",
        "",
        "## 全母體（沒有抽樣誤差）",
        "",
        f"- 分析器要求核准：{counts['asked']} / {counts['analysed']} ＝ **{_pct(est['p_asked'])}**",
        "",
        "## 標記後的估計（分層加權；區間是以對話為單位的群聚 bootstrap，屬近似）",
        "",
        f"- 可避免核准比例 A（在被問到的呼叫中標記為不必要）：下界 **{_pct(est['a_low'])}**{_ci(est['a_low_ci'])}"
        f"，上界 **{_pct(est['a_high'])}**{_ci(est['a_high_ci'])}",
        f"  （下界把 CANNOT_TELL 當必要，上界當不必要；CANNOT_TELL 約占被問到呼叫的 {_pct(est['cannot_tell_share_of_asked'])}）",
        f"- 噪音率 N ＝ P(asked) × A：**{_pct(est.get('noise_low'))} 到 {_pct(est.get('noise_high'))}**（占全部可對應呼叫）",
        f"- 沒被問到、但標記者認為必要：{_pct(est['missed_necessary'])}{_ci(est['missed_necessary_ci'])}（樣本小，只作描述）",
        f"- 標記者自我一致性：{consistency['same']} / {consistency['pairs']} ＝ {_pct(consistency['rate'])}（同一位標記者重複標記，不是人與人的一致性）",
        "",
        "## 各層",
        "",
        "| 被問到 | 工具 | cwd | N | n | NECESSARY | NOT_NECESSARY | CANNOT_TELL |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in strata:
        c = row["labels"]
        lines.append(
            f"| {'是' if row['asked'] else '否'} | {row['tool']} | {row['cwd_class']} | {row['N']} | {row['n']} "
            f"| {c['NECESSARY']} | {c['NOT_NECESSARY']} | {c['CANNOT_TELL']} |"
        )
    if problems:
        lines += ["", "## 標記回覆的問題（未猜測、未計入）", ""] + [
            f"- {p}" for p in problems
        ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--actions", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument(
        "--labels", required=True, help="directory with label_key.json and the answers"
    )
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    rows = [
        json.loads(line)
        for line in Path(args.actions).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    summary = json.loads(Path(args.summary).read_text(encoding="utf-8"))
    directory = Path(args.labels)
    key = json.loads((directory / "label_key.json").read_text(encoding="utf-8"))

    labels: dict[str, str] = {}
    problems: list[str] = []
    for out_file in sorted(directory.glob("*_out.txt")):
        stem = out_file.name.removesuffix("_out.txt")
        shown = json.loads((directory / f"{stem}.json").read_text(encoding="utf-8"))
        expected = {item["id"] for item in shown}
        got, issues = parse_labels(out_file.read_text(encoding="utf-8"), expected)
        labels.update(got)
        problems += [f"{stem}: {p}" for p in issues]

    counts = population_counts(rows)
    est = estimate(key, labels, counts)
    text = render(
        summary,
        counts,
        est,
        by_stratum(key, labels),
        self_consistency(key, labels),
        problems,
    )
    Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
