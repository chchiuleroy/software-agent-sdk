"""The estimates of the approval-noise report (governance/analysis/approval_noise/
report.py), checked against numbers worked out by hand."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


_PATH = (
    Path(__file__).resolve().parents[2]
    / "governance"
    / "analysis"
    / "approval_noise"
    / "report.py"
)
_spec = importlib.util.spec_from_file_location("approval_noise_report", _PATH)
assert _spec and _spec.loader
report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(report)


def build(strata):
    """key and labels from [(asked, tool, cwd, N, [labels...])];
    sessions are blocks of 8."""
    key: dict = {}
    labels: dict = {}
    n_id = 0
    for asked, tool, cwd, big_n, given in strata:
        for position, label in enumerate(given):
            n_id += 1
            label_id = f"L{n_id:04d}"
            key[label_id] = {
                "i": n_id,
                "sess": f"s{position // 8}",
                "asked": asked,
                "tool": tool,
                "cwd_class": cwd,
                "N": big_n,
                "n": len(given),
                "risk": "HIGH" if asked else "LOW",
            }
            labels[label_id] = label
    return key, labels


N, U, C = "NECESSARY", "NOT_NECESSARY", "CANNOT_TELL"
COUNTS = {
    "calls": 3100,
    "analysed": 3000,
    "asked": 1500,
    "not_asked": 1500,
    "not_judged": 0,
}


def test_the_estimates_match_a_hand_computation():
    """Asked: terminal N=1000 n=10 (6 not-necessary, 3 necessary, 1 cannot-tell) and
    file_editor N=500 n=5 (all not-necessary). A_low = (1000*.6 + 500*1)/1500, A_high
    counts the cannot-tell too. P(asked) = 1500/3000."""
    key, labels = build(
        [
            (True, "terminal", "project", 1000, [U] * 6 + [N] * 3 + [C]),
            (True, "file_editor", "project", 500, [U] * 5),
        ]
    )
    est = report.estimate(key, labels, COUNTS)
    assert est["p_asked"] == pytest.approx(0.5)
    assert est["a_low"] == pytest.approx(1100 / 1500)
    assert est["a_high"] == pytest.approx(1200 / 1500)
    assert est["cannot_tell_share_of_asked"] == pytest.approx(100 / 1500)
    assert est["noise_low"] == pytest.approx(0.5 * 1100 / 1500)
    assert est["noise_high"] == pytest.approx(0.5 * 1200 / 1500)


def test_a_small_stratum_does_not_count_as_much_as_a_big_one_with_the_same_sample():
    """Sample sizes are equal but populations are not: the weight is N_h / n_h."""
    key, labels = build(
        [
            (True, "terminal", "project", 9000, [N] * 10),
            (True, "glob", "project", 10, [U] * 10),
        ]
    )
    est = report.estimate(key, labels, COUNTS)
    assert est["a_low"] == pytest.approx(10 / 9010)


def test_what_was_not_asked_is_a_separate_estimate_about_missed_necessary():
    key, labels = build(
        [
            (True, "terminal", "project", 100, [U] * 4),
            (False, "file_editor", "project", 400, [N] * 1 + [U] * 3),
            (False, "grep", "project", 100, [U] * 4),
        ]
    )
    est = report.estimate(key, labels, COUNTS)
    assert est["missed_necessary"] == pytest.approx((400 * 0.25 + 100 * 0) / 500)
    assert est["a_low"] == pytest.approx(1.0)  # not-asked labels never enter A


def test_the_interval_brackets_the_point_and_is_reproducible():
    key, labels = build([(True, "terminal", "project", 1000, [U] * 20 + [N] * 20)])
    a = report.estimate(key, labels, COUNTS, seed=7)
    b = report.estimate(key, labels, COUNTS, seed=7)
    assert a == b
    low, high = a["a_low_ci"]
    assert low <= a["a_low"] <= high and low < high


def test_with_one_session_there_is_no_interval_rather_than_a_made_up_one():
    key, labels = build([(True, "terminal", "project", 100, [U])])
    assert report.estimate(key, labels, COUNTS)["a_low_ci"] is None


def test_the_labellers_answer_is_checked_strictly():
    expected = {"L1", "L2", "L3"}
    answer = [
        {"id": "L1", "label": "NECESSARY"},
        {"id": "L2", "label": "MAYBE"},
        {"id": "L1", "label": "NOT_NECESSARY"},
        {"id": "X", "label": "NECESSARY"},
    ]
    text = "noise ```json\n" + json.dumps(answer) + "\n```"
    labels, problems = report.parse_labels(text, expected)
    assert labels == {"L1": "NECESSARY"}
    joined = " ".join(problems)
    for needle in (
        "invalid label",
        "answered twice",
        "unknown id",
        "L3: no valid label",
        "L2: no valid label",
    ):
        assert needle in joined, needle


def test_an_answer_that_is_not_json_yields_nothing_and_says_so():
    assert report.parse_labels("sorry", {"L1"}) == (
        {},
        ["the answer is not valid JSON"],
    )
    assert report.parse_labels('{"id":"L1"}', {"L1"}) == (
        {},
        ["the answer is not a JSON array"],
    )


def test_self_consistency_counts_only_pairs_where_both_were_labelled():
    key = {
        "L1": {"N": 1},
        "L2": {"N": 1},
        "R1": {"repeat_of": "L1"},
        "R2": {"repeat_of": "L2"},
        "R3": {"repeat_of": "L2"},
    }
    labels = {"L1": N, "L2": U, "R1": N, "R2": C}  # R3 was not labelled
    assert report.self_consistency(key, labels) == {"pairs": 2, "same": 1, "rate": 0.5}


def test_population_counts_separate_asked_not_asked_and_not_judged():
    rows = [
        {"category": "mapped", "confirm": True},
        {"category": "mapped", "confirm": False},
        {"category": "mcp", "confirm": True},
        {"category": "mapped", "confirm": None},
        {"category": "no_mapping"},
    ]
    assert report.population_counts(rows) == {
        "calls": 5,
        "analysed": 4,
        "asked": 2,
        "not_asked": 1,
        "not_judged": 1,
    }


def test_the_rendered_report_states_its_limits_and_the_coverage():
    key, labels = build([(True, "terminal", "project", 100, [U, N, C, U])])
    est = report.estimate(key, labels, COUNTS)
    text = report.render(
        {"window_days": 30, "no_mapping": 7, "files": 9, "lines": 99},
        COUNTS,
        est,
        report.by_stratum(key, labels),
        {"pairs": 0, "same": 0, "rate": None},
        ["batch 1: L9: no valid label"],
    )
    for needle in (
        "覆蓋率",
        "只限定於可對應",
        "下界",
        "上界",
        "同一位標記者",
        "L9: no valid label",
    ):
        assert needle in text, needle
    json.dumps(est)  # serialisable
