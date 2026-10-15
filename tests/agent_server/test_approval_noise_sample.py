"""The sampler for the approval-noise labelling (governance/analysis/approval_noise/
sample.py): reproducible, equal-probability within a stratum, and the labeller never
sees the analyzer's answer or the stratum."""

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
    / "sample.py"
)
_spec = importlib.util.spec_from_file_location("approval_noise_sample", _PATH)
assert _spec and _spec.loader
sample = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sample)


def row(
    i, *, tool="terminal", cwd="project", confirm=True, risk="HIGH", category="mapped"
):
    return {
        "i": i,
        "sess": f"s{i % 7}",
        "cc_tool": "Bash" if tool == "terminal" else "Read",
        "category": category,
        "mapped": tool,
        "cwd_class": cwd,
        "shape": {"ops": ["read"], "secret": f"feature-{i}"},
        "risk": risk,
        "confirm": confirm,
    }


def population():
    rows = [row(i) for i in range(500)]  # terminal, project, asked
    rows += [row(1000 + i, cwd="broad") for i in range(60)]
    rows += [
        row(2000 + i, tool="file_editor", confirm=False, risk="LOW") for i in range(100)
    ]
    rows += [
        row(3000 + i, tool="glob") for i in range(4)
    ]  # smaller than its allocation
    rows += [row(4000, category="no_mapping", tool=None, confirm=None, risk=None)]
    rows += [row(4001, tool="task_tracker", cwd="weird")]  # a stratum nobody sampled
    return rows


def test_each_stratum_gets_its_allocation_and_a_small_one_is_taken_whole():
    chosen = sample.draw(population())
    count = {}
    for r in chosen:
        count[r["_stratum"]] = count.get(r["_stratum"], 0) + 1
    assert count[(True, "terminal", "project")] == 50
    assert count[(True, "terminal", "broad")] == 40
    assert count[(False, "file_editor", "project")] == 20
    assert count[(True, "glob", "project")] == 4  # fewer than its 10: all of them
    # the weight is the stratum's population over its sample, for every row in it
    assert {
        (r["_N"], r["_n"])
        for r in chosen
        if r["_stratum"] == (True, "terminal", "project")
    } == {(500, 50)}


def test_calls_that_were_not_analysed_or_are_in_no_sampled_stratum_are_left_out():
    chosen = sample.draw(population())
    assert all(r["category"] in ("mapped", "mcp") for r in chosen)
    assert 4000 not in {r["i"] for r in chosen} and 4001 not in {r["i"] for r in chosen}


def test_the_same_seed_gives_the_same_sample_and_another_seed_a_different_one():
    a = [r["i"] for r in sample.draw(population())]
    assert a == [r["i"] for r in sample.draw(population())]
    assert a != [r["i"] for r in sample.draw(population(), seed=1)]


def test_the_choice_does_not_depend_on_the_order_of_the_input():
    forward = sorted(r["i"] for r in sample.draw(population()))
    backward = sorted(r["i"] for r in sample.draw(list(reversed(population()))))
    assert forward == backward


def test_every_call_in_a_stratum_is_equally_likely_to_be_chosen():
    """Over many seeds each of 500 calls is picked about 50/500 = 10% of the time."""
    hits = dict.fromkeys(range(500), 0)
    rows = [row(i) for i in range(500)]
    for seed in range(400):
        for r in sample.draw(rows, seed=seed):
            hits[r["i"]] += 1
    rates = [h / 400 for h in hits.values()]
    # each rate is Binomial(400, 0.1)/400, sd about 0.015: five sd either side
    assert 0.025 < min(rates) and max(rates) < 0.175
    assert abs(sum(rates) / len(rates) - 0.10) < 0.002


def test_the_labeller_sees_no_verdict_stratum_weight_or_position():
    built = sample.build(population())
    shown = [item for batch in built["batches"] for item in batch] + built["repeat"]
    assert shown
    for item in shown:
        assert set(item) == {"id", "tool", "cwd_class", "features"}
    text = json.dumps(shown)
    for forbidden in (
        "risk",
        "confirm",
        "HIGH",
        "LOW",
        "UNKNOWN",
        "stratum",
        '"N"',
        "asked",
    ):
        assert forbidden not in text, forbidden


def test_ids_do_not_follow_the_order_or_the_strata():
    built = sample.build(population())
    first = [item["id"] for item in built["batches"][0]]
    assert first != sorted(first)
    strata_in_order = [built["key"][i]["asked"] for i in first]
    assert len(set(strata_in_order)) > 1  # asked and not-asked are mixed


def test_the_key_holds_what_the_estimate_needs():
    built = sample.build(population())
    one = built["key"][built["batches"][0][0]["id"]]
    assert set(one) == {"i", "sess", "asked", "tool", "cwd_class", "N", "n", "risk"}
    assert isinstance(one["asked"], bool)


def test_the_repeat_set_is_the_same_items_under_new_ids():
    built = sample.build(population())
    originals = {item["id"]: item for batch in built["batches"] for item in batch}
    assert len(built["repeat"]) == sample.REPEAT
    for item in built["repeat"]:
        source = originals[built["key"][item["id"]]["repeat_of"]]
        assert item["id"] != source["id"] and item["id"].startswith("R")
        assert (item["tool"], item["cwd_class"], item["features"]) == (
            source["tool"],
            source["cwd_class"],
            source["features"],
        )


def test_batches_are_bounded_and_cover_everything_once():
    built = sample.build(population())
    sizes = [len(b) for b in built["batches"]]
    assert max(sizes) <= sample.BATCH_SIZE
    ids = [item["id"] for batch in built["batches"] for item in batch]
    assert len(ids) == len(set(ids)) == sum(sizes)


@pytest.mark.parametrize("key", list(sample.ALLOCATION))
def test_the_allocation_names_real_strata(key):
    asked, tool, cwd = key
    assert isinstance(asked, bool)
    assert tool in {
        "terminal",
        "file_editor",
        "grep",
        "glob",
        "task_tracker",
        "mcp_tool",
    }
    assert cwd in {"project", "broad"}
