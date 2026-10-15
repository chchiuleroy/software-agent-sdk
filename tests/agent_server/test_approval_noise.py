"""The approval-noise replay (governance/analysis/approval_noise/replay.py).

What matters here is that nothing identifying leaves the process (the output is a
set of booleans, counts and words from a fixed vocabulary) and that the features a
labeller relies on are right. The analyzer itself is the real one; its own table is
pinned in test_builtin_tool_risk.py, so these only check what this script feeds it.
"""

from __future__ import annotations

import importlib.util
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


_PATH = (
    Path(__file__).resolve().parents[2]
    / "governance"
    / "analysis"
    / "approval_noise"
    / "replay.py"
)
_spec = importlib.util.spec_from_file_location("approval_noise_replay", _PATH)
assert _spec and _spec.loader
replay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replay)

CWD = os.path.normpath("C:/work/proj")
HOME = os.path.normpath(os.path.expanduser("~"))


def features(command: str, cwd: str | None = CWD) -> dict:
    return replay.bash_features(command, cwd)


# ------------------------- nothing identifying is written -------------------------

SECRETS = ("hunter2", "secret_project", "tok_abc123", "corp.example.com", "my_script")


@pytest.mark.parametrize(
    "command",
    [
        "python my_script_hunter2.py --token=tok_abc123",
        'curl -s -H "Authorization: tok_abc123" https://api.corp.example.com/v1',
        "cd C:/Users/roy/secret_project && git commit -m 'hunter2'",
        "python -c \"print('hunter2'); rm -rf secret_project | tok_abc123\"",
        "cat > notes.txt <<EOF\nhunter2 secret_project\nrm -rf /\nEOF",
        "FOO=hunter2 BAR=tok_abc123 pytest tests/test_secret_project.py",
        "scp secret_project/x user@corp.example.com:/tmp/",
    ],
)
def test_no_part_of_a_command_reaches_the_output(command):
    written = json.dumps(features(command))
    for secret in SECRETS:
        assert secret not in written, (secret, written)


def test_only_words_from_the_fixed_vocabulary_are_written_as_heads():
    commands = [
        "weirdtool --x",
        "./run_hunter2.sh",
        "git frobnicate",
        "docker secretsub",
        "C:/Users/roy/bin/secret_project.exe a",
    ]
    for command in commands:
        for head in features(command)["heads"]:
            base = head.split()[0]
            assert head == "other" or base in replay._COMMANDS, head
            if " " in head:
                assert (
                    head.split()[1] == "other"
                    or head.split()[1] in replay._SUBCOMMANDS[base]
                )


def test_a_heredoc_body_is_content_not_commands():
    f = features("cat > a.txt <<EOF\nrm -rf /\ncurl -d x https://h\nEOF")
    assert "delete" not in f["ops"] and not f["sends_data"]
    assert f["redirect"] is True


def test_quotes_hide_separators_from_the_scanner():
    f = features('python -c "a | b; rm -rf x && curl https://h"')
    assert f["heads"] == ["python"] and f["pipes"] == 0 and f["chained"] is False
    assert "delete" not in f["ops"]


# ----------------------------- the features themselves -----------------------------


def test_a_delete_is_a_delete_with_its_flag_and_where_it_points():
    f = features("rm -rf C:/elsewhere/x")
    assert "delete" in f["ops"] and f["flags"] == ["-rf"]
    assert f["paths_outside_cwd"] == 1 and f["paths_inside_cwd"] == 0
    g = features("rm build/x.txt")
    assert (
        g["paths_inside_cwd"] == 1 and g["paths_outside_cwd"] == 0 and g["flags"] == []
    )


def test_pushing_and_posting_send_data_but_fetching_does_not():
    assert features("git push origin main")["sends_data"] is True
    assert features("curl -d a=b https://h")["sends_data"] is True
    assert features("curl -X POST https://h")["sends_data"] is True
    assert features("curl -s https://h")["sends_data"] is False
    assert features("git status")["sends_data"] is False


def test_downloading_straight_into_an_interpreter_is_flagged():
    f = features("curl -s https://h | bash")
    assert f["pipe_to_shell"] is True and "exec_script" in f["ops"]
    assert features("curl -s https://h | jq .")["pipe_to_shell"] is False


@pytest.mark.parametrize(
    ("command", "op"),
    [
        ("pytest -q", "runner"),
        ("npm test", "runner"),
        ("pip install x", "install"),
        ("npm i", "install"),
        ("git status", "vcs_read"),
        ("git commit -m x", "vcs_write"),
        ("git pull", "vcs_remote"),
        ("scp a b:/c", "network_send"),
        ("ssh host ls", "remote_exec"),
        ("python x.py", "exec_script"),
        ("ls -la", "read"),
        ("mkdir d", "write"),
    ],
)
def test_the_class_of_what_a_command_does(command, op):
    assert op in features(command)["ops"], features(command)["ops"]


def test_a_redirect_is_a_write_and_knows_where_it_goes():
    inside = features("echo x > out.txt")
    assert "write" in inside["ops"] and inside["redirect_outside_cwd"] is False
    outside = features("echo x > C:/elsewhere/out.txt")
    assert outside["redirect_outside_cwd"] is True
    assert features("ls > /dev/null")["redirect_outside_cwd"] is False


def test_a_path_that_looks_like_a_secret_is_flagged_wherever_it_is():
    assert features("cat ~/.ssh/id_rsa")["secret_path"] is True
    assert features("cat config/.env.local")["secret_path"] is True
    assert features("cat README.md")["secret_path"] is False


def test_a_relative_path_is_read_against_the_commands_own_cwd():
    assert features("cat sub/a.txt")["paths_inside_cwd"] == 1
    assert features("cat ../other/a.txt")["paths_outside_cwd"] == 1
    # no cwd to read it against: counted as unresolved, never guessed
    assert features("cat sub/a.txt", cwd=None)["paths_unresolved"] == 1


# ------------------------------- mapping and paths -------------------------------


def test_a_relative_file_path_becomes_absolute_against_its_own_cwd():
    tool, fields, category = replay.map_call("Read", {"file_path": "a/b.py"}, CWD)
    assert (tool, category) == ("file_editor", "mapped")
    assert os.path.isabs(fields["path"]) and fields["path"] == os.path.join(
        CWD, "a/b.py"
    )
    assert fields["command"] == "view"


def test_a_relative_path_with_no_cwd_is_unresolved_not_analysed():
    assert replay.map_call("Read", {"file_path": "a.py"}, None) == (
        None,
        {},
        "unresolved",
    )
    assert replay.map_call("Grep", {"path": "src"}, None) == (None, {}, "unresolved")
    # an absolute path needs no cwd
    assert replay.map_call("Read", {"file_path": "C:/x/a.py"}, None)[2] == "mapped"


@pytest.mark.parametrize(
    ("name", "tool_input", "tool", "command"),
    [
        ("Read", {"file_path": "C:/x/a"}, "file_editor", "view"),
        ("Edit", {"file_path": "C:/x/a"}, "file_editor", "str_replace"),
        ("Write", {"file_path": "C:/x/a"}, "file_editor", "create"),
        (
            "NotebookEdit",
            {"notebook_path": "C:/x/a.ipynb"},
            "file_editor",
            "str_replace",
        ),
        ("TaskList", {}, "task_tracker", "view"),
        ("TaskGet", {}, "task_tracker", "view"),
        ("TaskCreate", {}, "task_tracker", "plan"),
        ("TodoWrite", {}, "task_tracker", "plan"),
    ],
)
def test_each_tool_maps_to_its_counterpart_and_command(name, tool_input, tool, command):
    got_tool, fields, category = replay.map_call(name, tool_input, CWD)
    assert (got_tool, category) == (tool, "mapped")
    assert fields["command"] == command


def test_what_has_no_counterpart_is_said_so_not_forced():
    for name in ("WebSearch", "WebFetch", "Skill", "ToolSearch", "Agent", "Nope"):
        assert replay.map_call(name, {}, CWD) == (None, {}, "no_mapping")
    assert replay.map_call("mcp__srv__tool", {}, CWD)[2] == "mcp"
    assert replay.map_call("Read", {}, CWD)[2] == "malformed"
    assert replay.map_call("Bash", {"command": 3}, CWD)[2] == "malformed"


def test_cwd_class_tells_a_session_started_at_home_from_one_in_a_project():
    assert replay.cwd_class(HOME) == "broad"
    assert replay.cwd_class(os.path.dirname(HOME)) == "broad"
    assert replay.cwd_class(os.path.join(HOME, "projects", "a")) == "project"
    assert replay.cwd_class(None) == "unknown"
    assert replay.cwd_class("relative/dir") == "unknown"


def test_inside_is_a_real_containment_check():
    assert replay.inside("C:/work/proj/a", "C:/work/proj")
    assert replay.inside("C:/work/proj", "C:/work/proj")
    assert not replay.inside(
        "C:/work/project2/a", "C:/work/proj"
    )  # a prefix, not a parent
    assert not replay.inside("C:/work/proj/../x", "C:/work/proj")
    assert not replay.inside("D:/work/proj/a", "C:/work/proj")


# --------------------------- the real analyzer, end to end ---------------------------


@pytest.fixture(scope="module")
def replayer():
    return replay.Replayer()


def test_what_the_real_analyzer_says_about_each_kind_of_call(replayer):
    ws = CWD
    inside_path = os.path.join(ws, "a.py")
    outside_path = os.path.normpath("C:/elsewhere/a.py")
    assert replayer.verdict(
        "file_editor", {"command": "view", "path": inside_path}, ws
    ) == ("LOW", False)
    assert replayer.verdict(
        "file_editor", {"command": "view", "path": outside_path}, ws
    ) == ("HIGH", True)
    assert replayer.verdict("grep", {"pattern": "x", "path": None}, ws) == (
        "UNKNOWN",
        True,
    )
    assert replayer.verdict("terminal", {"command": "ls"}, "C:/") == ("HIGH", True)
    assert replayer.verdict("task_tracker", {"command": "view"}, "C:/") == (
        "HIGH",
        True,
    )
    assert replayer.verdict("mcp_tool", {}, "C:/") == ("UNKNOWN", True)


def _transcript(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _use(call_id, name, tool_input, *, ts, cwd=CWD, session="s1"):
    return {
        "timestamp": ts,
        "cwd": cwd,
        "sessionId": session,
        "message": {
            "content": [
                {"type": "tool_use", "id": call_id, "name": name, "input": tool_input}
            ]
        },
    }


def test_a_transcript_is_replayed_and_nothing_identifying_is_written(
    tmp_path, replayer
):
    now = datetime.now(UTC)
    recent = (now - timedelta(days=2)).isoformat()
    old = (now - timedelta(days=90)).isoformat()
    inside_file = os.path.join(CWD, "secret_project", "hunter2.py")
    rows = [
        _use("t1", "Read", {"file_path": inside_file}, ts=recent),
        _use(
            "t2", "Bash", {"command": "rm -rf C:/elsewhere/secret_project"}, ts=recent
        ),
        _use(
            "t2", "Bash", {"command": "rm -rf C:/elsewhere/secret_project"}, ts=recent
        ),  # duplicate id
        _use("t3", "Read", {"file_path": inside_file}, ts=old),  # outside the window
        _use("t4", "WebSearch", {"query": "hunter2 secret_project"}, ts=recent),
        _use("t5", "mcp__srv__tool", {"x": "tok_abc123"}, ts=recent),
        _use("t6", "Read", {"file_path": "relative.py"}, ts=recent, cwd=None),
    ]
    file = tmp_path / "s1.jsonl"
    _transcript(file, rows)
    counters = {
        k: 0
        for k in (
            "lines",
            "parse_failures",
            "tool_uses",
            "duplicates",
            "outside_window_or_no_time",
            "no_mapping",
            "malformed",
            "unresolved",
            "mcp",
            "no_cwd",
        )
    }

    out = replay.process_file(
        file, replayer, set(), now - timedelta(days=30), counters, 0
    )

    written = json.dumps(out)
    for secret in (
        "hunter2",
        "secret_project",
        "tok_abc123",
        "elsewhere",
        "relative.py",
    ):
        assert secret not in written, secret
    assert counters["duplicates"] == 1 and counters["outside_window_or_no_time"] == 1
    assert (
        counters["no_mapping"] == 1
        and counters["mcp"] == 1
        and counters["unresolved"] == 1
    )
    by_id = {r["cc_tool"] + str(i): r for i, r in enumerate(out)}
    read = out[0]
    assert (read["mapped"], read["risk"], read["confirm"]) == (
        "file_editor",
        "LOW",
        False,
    )
    assert read["shape"]["workspace_relation"] == "inside"
    bash = out[1]
    assert (bash["mapped"], bash["risk"], bash["confirm"]) == ("terminal", "HIGH", True)
    assert "delete" in bash["shape"]["ops"] and bash["shape"]["paths_outside_cwd"] == 1
    assert by_id  # the rows exist and carry only the documented keys
    allowed = {
        "i",
        "day",
        "sess",
        "cc_tool",
        "category",
        "mapped",
        "cwd_class",
        "shape",
        "risk",
        "confirm",
    }
    assert all(set(r) <= allowed for r in out)


# ----------------- second review: names, opaque commands, operands -----------------


def test_a_tool_name_is_written_only_from_a_fixed_list():
    assert replay.public_tool_name("Bash") == "Bash"
    assert replay.public_tool_name("mcp__claude-in-chrome__javascript_tool") == (
        "mcp__claude-in-chrome__javascript_tool"
    )
    # an organisation's own server or tool name is someone's choice of words
    assert replay.public_tool_name("mcp__acme_secret__tok_abc123") == "mcp__other"
    assert replay.public_tool_name("mcp__claude-in-chrome__a b") == "mcp__other"
    assert replay.public_tool_name("AcmeInternalTool") == "other_tool"
    assert replay.public_tool_name(None) == "other_tool"


def test_a_secret_tool_name_never_reaches_the_rows(tmp_path, replayer):
    now = datetime.now(UTC)
    ts = (now - timedelta(days=1)).isoformat()
    file = tmp_path / "s.jsonl"
    _transcript(
        file,
        [
            _use("a1", "mcp__acme_secret__tok_abc123", {}, ts=ts),
            _use("a2", "AcmeInternalTool_hunter2", {}, ts=ts),
        ],
    )
    counters = dict.fromkeys(
        (
            "lines", "parse_failures", "tool_uses", "duplicates",
            "outside_window_or_no_time", "no_mapping", "malformed", "unresolved",
            "mcp", "no_cwd",
        ),
        0,
    )  # fmt: skip
    out = replay.process_file(
        file, replayer, set(), now - timedelta(days=30), counters, 0
    )
    written = json.dumps(out)
    assert "acme_secret" not in written and "hunter2" not in written
    assert {r["cc_tool"] for r in out} == {"mcp__other", "other_tool"}


def test_commands_after_a_heredoc_are_still_read_and_the_body_is_not():
    f = features("cat > a.txt <<EOF\ncurl -d x https://h\nEOF\nrm -rf C:/elsewhere/x")
    assert "delete" in f["ops"] and f["flags"] == ["-rf"]
    assert f["paths_outside_cwd"] == 1
    assert f["sends_data"] is False  # the heredoc body is not commands


@pytest.mark.parametrize(
    "command",
    [
        "echo `whoami`",
        "echo $(whoami)",
        'bash -c "rm -rf x"',
        "sh -c ls",
        "cmd /c dir",
        'powershell -Command "Get-ChildItem"',
        'python -c "print(1)"',
        "node -e 1",
        "ls | xargs rm",
        "find . -name x -exec rm {} ;",
        "eval ls",
    ],
)
def test_a_command_with_hidden_parts_says_so(command):
    assert features(command)["opaque"] is True


def test_a_plain_command_is_not_opaque():
    for command in ("ls -la", "git status", "pytest -q tests", "cat a.txt | wc -l"):
        assert features(command)["opaque"] is False


def test_a_bare_file_name_is_a_path_operand():
    assert features("rm file.txt")["paths_inside_cwd"] == 1
    assert features("python script.py")["paths_inside_cwd"] == 1
    assert features("cat README.md")["paths_inside_cwd"] == 1
    assert features("rm C:/elsewhere/a.txt")["paths_outside_cwd"] == 1
    assert features("rm ../a.txt")["paths_outside_cwd"] == 1
    # not a file command: its words are not operands
    f = features("echo hello world")
    assert f["paths_inside_cwd"] == f["paths_outside_cwd"] == f["paths_unresolved"] == 0
    # an option's value is not a path
    assert features("grep -n pattern a.txt")["paths_outside_cwd"] == 0


def test_a_redirect_to_something_unresolved_says_so():
    f = features("echo x > $OUT")
    assert f["redirect"] is True and f["redirect_unresolved"] is True
    assert f["redirect_outside_cwd"] is False
    g = features("echo x > out.txt")
    assert g["redirect_unresolved"] is False and g["redirect_outside_cwd"] is False
    assert features("echo x > C:/else/o.txt")["redirect_outside_cwd"] is True
    assert features("echo x > out.txt", cwd=None)["redirect_unresolved"] is True


@pytest.mark.parametrize(
    "command",
    [
        "curl --data=a=b https://h",
        "curl --form=f=@x https://h",
        "curl --request=POST https://h",
        "curl -XPOST https://h",
        "curl --upload-file=x https://h",
        "git -C repo push origin main",
        "git -c user.name=x push",
    ],
)
def test_the_ways_data_leaves_the_machine(command):
    assert features(command)["sends_data"] is True


def test_git_options_do_not_hide_the_subcommand():
    assert features("git -C somewhere status")["heads"] == ["git status"]
    assert features("git -c a=b log")["heads"] == ["git log"]


def test_a_wrapper_does_not_hide_the_command():
    f = features("env FOO=1 rm -rf C:/x")
    assert f["heads"] == ["rm"] and "delete" in f["ops"]
    assert "delete" in features("sudo rm x")["ops"]
    assert "runner" in features("time pytest -q")["ops"]


def test_a_known_word_with_no_class_never_leaves_ops_empty():
    assert "other" in features("export FOO=1")["ops"]
    for command in (
        "psql -c x",
        "kubectl delete pod p",
        "aws s3 rm s3://b/k",
        "terraform apply",
    ):
        assert "remote_state" in features(command)["ops"], command


def test_a_tilde_path_is_expanded_before_the_analyzer_sees_it(replayer):
    tool, fields, category = replay.map_call(
        "Read", {"file_path": "~/.ssh/config"}, CWD
    )
    assert category == "mapped"
    assert fields["path"].startswith(HOME)
    shape = replay.file_features(replayer, tool, fields, CWD)
    assert shape["workspace_relation"] == "outside" and shape["secret_path"] is True


def test_cwd_class_is_the_home_directory_or_above_not_anything_shallow():
    assert replay.cwd_class(HOME) == "broad"
    assert replay.cwd_class(os.path.dirname(HOME)) == "broad"
    assert replay.cwd_class(os.path.splitdrive(HOME)[0] + os.sep) == "broad"
    # shallow but not above home: a project
    assert replay.cwd_class(os.path.normpath("C:/work/proj")) == "project"
    assert replay.cwd_class(os.path.normpath("D:/proj")) == "project"


def test_an_mcp_call_reaches_the_analyzer_under_its_own_name(replayer):
    seen = []
    original = replayer._event

    def spy(tool, fields, tool_name=None):
        seen.append(tool_name)
        return original(tool, fields, tool_name)

    replayer._event = spy
    try:
        assert replayer.verdict("mcp_tool", {}, "C:/", "mcp__srv__tool") == (
            "UNKNOWN",
            True,
        )
    finally:
        replayer._event = original
    assert seen == ["mcp__srv__tool"]


@pytest.mark.skipif(os.name != "nt", reason="uses an NTFS directory junction")
def test_the_workspace_relation_follows_links_like_the_analyzer_does(
    tmp_path, replayer
):
    """A path that is lexically inside the workspace but leads outside through a link
    is outside for the analyzer, so it must be outside for the labeller too."""
    import subprocess

    workspace = tmp_path / "ws"
    elsewhere = tmp_path / "elsewhere"
    workspace.mkdir()
    elsewhere.mkdir()
    link = workspace / "link"
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(elsewhere)],
        capture_output=True,
    )
    if made.returncode != 0:
        pytest.skip("cannot create a junction here")
    path = str(link / "a.txt")
    shape = replay.file_features(
        replayer, "file_editor", {"command": "view", "path": path}, str(workspace)
    )
    assert shape["workspace_relation"] == "outside"
    assert replayer.verdict(
        "file_editor", {"command": "view", "path": path}, str(workspace)
    ) == ("HIGH", True)


def test_an_mcp_call_is_replayed_under_its_real_name_but_written_under_a_safe_one(
    tmp_path, replayer
):
    now = datetime.now(UTC)
    file = tmp_path / "s.jsonl"
    _transcript(
        file,
        [
            _use(
                "m1",
                "mcp__acme_secret__tok",
                {},
                ts=(now - timedelta(days=1)).isoformat(),
            )
        ],
    )
    counters = dict.fromkeys(
        (
            "lines", "parse_failures", "tool_uses", "duplicates",
            "outside_window_or_no_time", "no_mapping", "malformed", "unresolved",
            "mcp", "no_cwd",
        ),
        0,
    )  # fmt: skip
    asked: list = []
    original = replayer.verdict

    def spy(tool, fields, workspace, tool_name=None):
        asked.append(tool_name)
        return original(tool, fields, workspace, tool_name)

    replayer.verdict = spy
    try:
        out = replay.process_file(
            file, replayer, set(), now - timedelta(days=30), counters, 0
        )
    finally:
        replayer.verdict = original
    assert asked == ["mcp__acme_secret__tok"]
    assert out[0]["cc_tool"] == "mcp__other" and "acme" not in json.dumps(out)
