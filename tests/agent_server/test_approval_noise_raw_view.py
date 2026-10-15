"""The raw-command labelling study (governance/analysis/approval_noise/raw_view.py):
what is scrubbed before anything is sent, who is sampled, and the weights."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


_PATH = (
    Path(__file__).resolve().parents[2]
    / "governance"
    / "analysis"
    / "approval_noise"
    / "raw_view.py"
)
_spec = importlib.util.spec_from_file_location("approval_noise_raw_view", _PATH)
assert _spec and _spec.loader
raw_view = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(raw_view)

HOME = "C:/Users/someone"


@pytest.mark.parametrize(
    "command, secret",
    [
        (
            "curl -H 'Authorization: Bearer abcDEF123456789xyz' https://x.test",
            "abcDEF123456789xyz",
        ),
        (
            "curl -H 'x-api-key: k_live_1234567890abcdef' https://x.test",
            "k_live_1234567890abcdef",
        ),
        ("export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdef"),
        ("aws s3 ls --profile x && echo AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"),
        ("API_KEY=sk-abcdefghijklmnopqrstuv python run.py", "sk-abcdefghijklmnop"),
        ("PGPASSWORD=hunter2hunter2 psql -h db -U app", "hunter2hunter2"),
        ("mysql -u root -pS3cretPass db", "S3cretPass"),
        ("mysql --password=S3cretPass db", "S3cretPass"),
        ("git clone https://user:p4ssw0rd@github.com/x/y.git", "p4ssw0rd"),
        (
            "echo eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk",
            "eyJhbGciOiJIUzI1NiJ9",
        ),
        ("echo " + "a1" * 25, "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"),
        ("echo " + "Zm9vYmFy" * 8, "Zm9vYmFyZm9vYmFy"),
        (
            "cat <<EOF\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA"
            "\n-----END RSA PRIVATE KEY-----\nEOF",
            "MIIEowIBAAKCAQEA",
        ),
        ("xoxb-1234567890-abcdefghij", "xoxb-1234567890-abcdefghij"),
    ],
)
def test_a_credential_never_survives_the_scrub(command, secret):
    cleaned = raw_view.scrub(command, HOME)
    assert secret not in cleaned, cleaned


@pytest.mark.parametrize(
    "command",
    [
        "ls -la src/tests",
        "git commit -m 'fix token handling in the parser'",
        "python -m pytest tests/test_x.py -q",
        "grep -rn password docs/",
        "cd project && npm run build",
    ],
)
def test_an_ordinary_command_is_left_alone(command):
    assert raw_view.scrub(command, HOME) == command


def test_the_home_directory_is_shortened_in_every_spelling():
    text = "cat C:/Users/someone/.ssh/config C:\\Users\\someone\\x"
    cleaned = raw_view.scrub(text, "C:\\Users\\someone")
    assert "someone" not in cleaned
    assert cleaned.count("~") == 2


def test_a_long_command_is_cut_and_says_so():
    cleaned = raw_view.scrub("echo " + "word " * 1000, HOME)
    assert len(cleaned) < raw_view.MAX_COMMAND_CHARS + 80
    assert "cut: " in cleaned


def _row(i, cwd="project", confirm=True, mapped="terminal"):
    return {
        "i": i,
        "sess": "s",
        "mapped": mapped,
        "confirm": confirm,
        "cwd_class": cwd,
        "shape": {"ops": ["read"]},
    }


def _population():
    rows = [_row(n) for n in range(100)] + [_row(100 + n, "broad") for n in range(60)]
    rows += [_row(900, confirm=False), _row(901, mapped="file_editor")]
    raw = {
        row["i"]: {"i": row["i"], "command": f"echo {row['i']}", "cwd": f"{HOME}/p"}
        for row in rows
    }
    return rows, raw


def test_the_sample_takes_only_asked_bash_calls_in_the_planned_sizes():
    rows, raw = _population()
    items, key = raw_view.draw(rows, raw, home=HOME)
    assert len(items) == 90
    assert sum(1 for v in key.values() if v["cwd_class"] == "project") == 50
    assert sum(1 for v in key.values() if v["cwd_class"] == "broad") == 40
    assert {v["i"] for v in key.values()}.isdisjoint({900, 901})
    assert all(v["N"] in (100, 60) for v in key.values())


def test_the_same_seed_draws_the_same_items_and_another_does_not():
    rows, raw = _population()
    a = raw_view.draw(rows, raw, seed=1, home=HOME)[1]
    b = raw_view.draw(rows, raw, seed=1, home=HOME)[1]
    c = raw_view.draw(rows, raw, seed=2, home=HOME)[1]
    assert a == b
    assert a != c


def test_what_is_sent_is_scrubbed_and_the_two_views_differ():
    rows, raw = _population()
    raw[rows[0]["i"]]["command"] = (
        "curl -H 'Authorization: Bearer abcDEF123456789xyz' " + HOME
    )
    items, _ = raw_view.draw(rows, raw, home=HOME)
    sent = " ".join(i["command"] + i["cwd"] for i in raw_view.raw_view(items))
    assert "abcDEF123456789xyz" not in sent and "someone" not in sent
    for view in raw_view.feature_view(items):
        assert set(view) == {"id", "tool", "cwd_class", "features"}, (
            "no command in the feature view"
        )
    for view in raw_view.raw_view(items):
        assert set(view) == {"id", "cwd_class", "cwd", "command"}, (
            "no features in the raw view"
        )


def test_a_missing_raw_command_stops_the_draw():
    rows, raw = _population()
    del raw[rows[0]["i"]]
    # the first row may or may not be drawn; remove every project command to be sure
    for row in rows:
        if row["cwd_class"] == "project":
            raw.pop(row["i"], None)
    with pytest.raises(SystemExit):
        raw_view.draw(rows, raw, home=HOME)


def test_the_estimate_weights_each_cwd_class_by_its_population():
    """project: N=100, n=2 (one not-necessary, one cannot-tell); broad: N=300, n=1
    (necessary). Shares are over 400 calls."""
    key = {
        "B1": {"cwd_class": "project", "N": 100, "n": 2},
        "B2": {"cwd_class": "project", "N": 100, "n": 2},
        "B3": {"cwd_class": "broad", "N": 300, "n": 1},
    }
    labels = {"B1": "NOT_NECESSARY", "B2": "CANNOT_TELL", "B3": "NECESSARY"}
    est = raw_view.estimate(key, labels)
    assert est["necessary"] == pytest.approx(300 / 400)
    assert est["not_necessary"] == pytest.approx(50 / 400)
    assert est["cannot_tell"] == pytest.approx(50 / 400)
    assert est["a_low"] == pytest.approx(50 / 400)
    assert est["a_high"] == pytest.approx(100 / 400)


def test_only_the_items_both_views_labelled_are_compared():
    feature = {"B1": "CANNOT_TELL", "B2": "NECESSARY", "B3": "NOT_NECESSARY"}
    raw = {"B1": "NOT_NECESSARY", "B2": "NECESSARY"}
    result = raw_view.agreement(feature, raw)
    assert result == {
        "items": 2,
        "pairs": {"CANNOT_TELL -> NOT_NECESSARY": 1, "NECESSARY -> NECESSARY": 1},
    }


def test_the_labellers_answer_is_read_strictly():
    text = (
        '[{"id":"B1","label":"NECESSARY"},{"id":"B2","label":"MAYBE"},'
        '{"id":"B3","label":"NECESSARY"},{"id":"B3","label":"NOT_NECESSARY"},'
        '{"id":"X","label":"NECESSARY"}]'
    )
    assert raw_view.parse_labels(text, {"B1", "B2", "B3"}) == {"B1": "NECESSARY"}
    assert raw_view.parse_labels("no json", {"B1"}) == {}


def test_replay_writes_each_asked_bash_command_under_the_index_of_actions_jsonl(
    tmp_path,
):
    """The raw file is for the labelling study. The analyzer asks about every Bash
    call, so every command is written, keyed by the index it has in actions.jsonl
    (here the first index is 5, to show the key is the caller's and not a counter)."""
    import io
    import json

    replay_path = _PATH.parent / "replay.py"
    spec = importlib.util.spec_from_file_location("replay_for_raw", replay_path)
    replay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(replay)

    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    ts = (now - timedelta(days=1)).isoformat()
    lines = []
    for n, command in enumerate(["ls", "rm -rf /elsewhere/x"]):
        lines.append(
            json.dumps(
                {
                    "timestamp": ts,
                    "cwd": str(tmp_path),
                    "sessionId": "s",
                    "message": {
                        "content": [
                            {
                                "type": "tool_use",
                                "id": f"t{n}",
                                "name": "Bash",
                                "input": {"command": command},
                            }
                        ]
                    },
                }
            )
        )
    file = tmp_path / "s.jsonl"
    file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    counters = {
        k: 0
        for k in (
            "lines", "parse_failures", "tool_uses", "duplicates",
            "outside_window_or_no_time", "no_mapping", "malformed", "unresolved",
            "mcp", "no_cwd",
        )
    }  # fmt: skip
    sink = io.StringIO()
    out = replay.process_file(
        file, replay.Replayer(), set(), now - timedelta(days=30), counters, 5, sink
    )
    written = [json.loads(line) for line in sink.getvalue().splitlines()]
    asked = {r["i"] for r in out if r.get("confirm") is True}
    assert {w["i"] for w in written} == asked == {5, 6}
    assert [w["command"] for w in sorted(written, key=lambda w: w["i"])] == [
        "ls",
        "rm -rf /elsewhere/x",
    ]
    assert all(w["command"] and w["cwd"] == str(tmp_path) for w in written)


@pytest.mark.parametrize(
    "command",
    [
        "cat ~/openhands-governance/openhands-sdk-governed/governance/"
        "needs_attention/design.md",
        "ls /very/long/directory-name-with-hyphens/and_underscores/and-more-and-more/x",
        "python some_really_long_function_name_without_digits_or_capitals_at_all.py",
        "echo ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ",
    ],
)
def test_a_long_path_or_identifier_is_not_mistaken_for_a_secret(command):
    """Paths decide whether a command stays inside the workspace; scrubbing them
    would blind the labeller to the very thing it is asked about."""
    assert raw_view.scrub(command, HOME) == command


@pytest.mark.parametrize(
    "text",
    [
        "cat /c/Users/someone/x",
        "cat /mnt/c/Users/someone/x",
        "cat c:/users/Someone/x",
        "cat C:" + chr(92) + "Users" + chr(92) + "someone" + chr(92) + "x",
        "cat //c/Users/someone/x",
    ],
)
def test_the_home_directory_is_shortened_however_another_tool_writes_it(text):
    cleaned = raw_view.scrub(text, "C:/Users/someone")
    assert "someone" not in cleaned.lower(), cleaned
    assert "~" in cleaned


def test_a_longer_user_name_is_not_cut_in_half():
    cleaned = raw_view.scrub("cat C:/Users/someone2/x", "C:/Users/someone")
    assert cleaned == "cat C:/Users/someone2/x"
