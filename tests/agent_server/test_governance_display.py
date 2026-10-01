"""Tests for the central-approval display projection.

The invariants that matter, each tested on its own below:
- no known secret survives in ANY tool's output (``SECRET_CORPUS``);
- output size is bounded whatever the input size;
- redaction happens before clipping;
- unknown tools show argument names, never values;
- the LLM's summary is labelled untrusted and the SDK's raw-argument fallback
  summary is never shown.
"""

import json

import pytest

from openhands.agent_server.governance_display import (
    MAX_COMMAND_PREVIEW_CHARS,
    MAX_PREVIEW_LINES,
    POLICY_REVISION,
    PROJECTION_VERSION,
    build_display,
)
from openhands.agent_server.governance_redaction import REDACTION_VERSION
from openhands.sdk.event import ActionEvent
from openhands.sdk.llm import MessageToolCall, TextContent
from openhands.sdk.tool import Action
from openhands.tools.apply_patch.definition import ApplyPatchAction
from openhands.tools.browser_use.definition import BrowserNavigateAction
from openhands.tools.file_editor.definition import FileEditorAction
from openhands.tools.terminal.definition import TerminalAction


class _McpLikeAction(Action):
    query: str
    api_token: str


def _event(tool_name: str, action: Action, summary: str | None = None) -> ActionEvent:
    return ActionEvent(
        source="agent",
        thought=[TextContent(text="x")],
        action=action,
        tool_name=tool_name,
        tool_call_id="call_1",
        tool_call=MessageToolCall(
            id="call_1", name=tool_name, arguments="{}", origin="completion"
        ),
        llm_response_id="response_1",
        summary=summary,
    )


def _shown(projection) -> str:
    return projection.summary + json.dumps(projection.payload)


def _terminal(command: str, summary: str | None = None) -> ActionEvent:
    return _event("terminal", TerminalAction(command=command), summary)


# Built by concatenation so no GitHub-token-shaped literal sits in the source
# (public repo: secret scanners flag the format even when the value is fake).
_FAKE_GH = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"

# Add a line here whenever a new secret shape is found in the wild — see the
# how-to-extend steps in governance_redaction.py. Each entry: the secret
# literal that must never appear, and an action carrying it.
SECRET_CORPUS = [
    (
        "sk-FAKE-0000-not-a-real-key",
        _terminal("curl -H 'Authorization: Bearer sk-FAKE-0000-not-a-real-key' x"),
    ),
    (
        "hunter2pass",
        _terminal("git clone https://deploy:hunter2pass@git.example.com/r"),
    ),
    ("s3cretpw", _terminal("mysql -u root --password=s3cretpw db")),
    ("cjkpass42", _terminal("echo 你好 密碼=cjkpass42")),
    ("wJalrXUtnFEMI", _terminal("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI aws s3 ls")),
    (
        _FAKE_GH,
        _event(
            "file_editor",
            FileEditorAction(
                command="create",
                path="/w/.env",
                file_text=f"GH={_FAKE_GH}\n",
            ),
        ),
    ),
    (
        "oldsecretvalue1",
        _event(
            "file_editor",
            FileEditorAction(
                command="str_replace",
                path="/w/c.ini",
                old_str="password=oldsecretvalue1",
                new_str="password=newsecretvalue2",
            ),
        ),
    ),
    (
        "newsecretvalue2",
        _event(
            "file_editor",
            FileEditorAction(
                command="insert",
                path="/w/c.ini",
                insert_line=1,
                new_str="password=newsecretvalue2",
            ),
        ),
    ),
    (
        "patchsecret99",
        _event(
            "apply_patch",
            ApplyPatchAction(
                patch="*** Begin Patch\n*** Update File: a.py\n"
                "+API_KEY = 'patchsecret99'\n*** End Patch"
            ),
        ),
    ),
    (
        "urlpass77",
        _event(
            "browser_navigate",
            BrowserNavigateAction(url="https://bob:urlpass77@site.example/a?x=1"),
        ),
    ),
    (
        "sessionvalue55",
        _event(
            "browser_navigate",
            BrowserNavigateAction(url="https://site.example/a?sid=sessionvalue55"),
        ),
    ),
    (
        "mcpsecret11",
        _event("mcp_tool", _McpLikeAction(query="hi", api_token="mcpsecret11")),
    ),
]


@pytest.mark.parametrize(
    ("secret", "action"),
    SECRET_CORPUS,
    ids=[f"{a.tool_name}-{i}" for i, (_, a) in enumerate(SECRET_CORPUS)],
)
def test_no_corpus_secret_survives_in_any_tool_projection(secret, action):
    assert secret not in _shown(build_display(action))


def test_agent_claim_is_also_redacted():
    projection = build_display(
        _terminal("ls", summary="calling the API with token=claimsecret33")
    )

    assert "claimsecret33" not in _shown(projection)


# --- terminal ---------------------------------------------------------------


def test_terminal_shows_a_bounded_preview_not_the_whole_command():
    command = "echo " + "A" * 5000
    projection = build_display(_terminal(command))

    assert len(projection.payload["command_preview"]) <= MAX_COMMAND_PREVIEW_CHARS
    assert projection.payload["command_length"] == len(command)
    assert projection.payload["truncated"] is True
    assert command not in _shown(projection)


def test_terminal_program_skips_env_assignments_and_directories():
    projection = build_display(_terminal("FOO=bar BAZ=1 /usr/bin/curl -s x"))

    assert projection.payload["program"] == "curl"
    assert "FOO=bar" not in projection.payload["program"]


def test_terminal_multiline_command_is_collapsed_onto_one_line():
    projection = build_display(_terminal("echo a\necho b"))

    assert "\n" not in projection.payload["command_preview"]
    assert projection.payload["command_preview"] == "echo a\\necho b"


def test_secret_straddling_the_preview_limit_does_not_leak_a_prefix():
    # Why: a bare token shape (no "token=" label) needs its full length to be
    # recognised (a GitHub token is "ghp_" + 20 or more characters). If the
    # text were clipped first, only a ~10-character prefix would remain,
    # too short for the pattern, and that prefix would be shown. Redaction
    # must run on the whole text before clipping.
    token = "ghp_" + "A" * 36
    command = "x" * (MAX_COMMAND_PREVIEW_CHARS - 14) + " " + token
    # The test only means something if the limit really cuts the token.
    assert len(command) > MAX_COMMAND_PREVIEW_CHARS
    assert command[
        MAX_COMMAND_PREVIEW_CHARS - 13 : MAX_COMMAND_PREVIEW_CHARS
    ].startswith("ghp_")

    projection = build_display(_terminal(command))

    assert "ghp_" not in _shown(projection)
    assert "AAAA" not in _shown(projection)


def test_redaction_input_is_capped_so_huge_text_cannot_stall_the_patterns():
    # A performance guard: nothing past the cap is ever shown, so there is no
    # reason to run backtracking patterns over megabytes of it.
    from openhands.agent_server.governance_display import _MAX_INPUT_CHARS, _Redactions

    assert len(_Redactions().text("a" * (_MAX_INPUT_CHARS * 2))) == _MAX_INPUT_CHARS


# --- file_editor ------------------------------------------------------------


def test_file_create_shows_path_sizes_and_a_plus_prefixed_preview():
    action = _event(
        "file_editor",
        FileEditorAction(
            command="create", path="/w/a.txt", file_text="line one\nline two\n"
        ),
    )
    payload = build_display(action).payload

    assert payload["kind"] == "file_edit"
    assert payload["path"] == "/w/a.txt"
    assert payload["file_text_bytes"] == len("line one\nline two\n")
    assert payload["file_text_lines"] == 2
    assert payload["diff_preview"] == ["+line one", "+line two"]
    assert payload["diff_truncated"] is False


def test_file_str_replace_shows_a_diff_and_both_sizes():
    action = _event(
        "file_editor",
        FileEditorAction(
            command="str_replace", path="/w/a.txt", old_str="alpha", new_str="beta"
        ),
    )
    payload = build_display(action).payload

    assert payload["old_str_bytes"] == 5
    assert payload["new_str_bytes"] == 4
    assert "-alpha" in payload["diff_preview"]
    assert "+beta" in payload["diff_preview"]


def test_file_insert_shows_line_number_and_new_text():
    action = _event(
        "file_editor",
        FileEditorAction(command="insert", path="/w/a.txt", insert_line=3, new_str="x"),
    )
    payload = build_display(action).payload

    assert payload["insert_line"] == 3
    assert payload["diff_preview"] == ["+x"]


def test_file_view_carries_no_content_fields():
    action = _event("file_editor", FileEditorAction(command="view", path="/w/a.txt"))
    payload = build_display(action).payload

    assert payload["command"] == "view"
    assert "diff_preview" not in payload


def test_file_preview_is_capped_in_lines():
    content = "\n".join(f"row {i}" for i in range(500))
    action = _event(
        "file_editor",
        FileEditorAction(command="create", path="/w/big.txt", file_text=content),
    )
    payload = build_display(action).payload

    assert len(payload["diff_preview"]) == MAX_PREVIEW_LINES
    assert payload["diff_truncated"] is True
    assert payload["file_text_lines"] == 500


# --- apply_patch ------------------------------------------------------------

PATCH = (
    "*** Begin Patch\n"
    "*** Add File: new.py\n+print('hi')\n"
    "*** Update File: src/app.py\n@@\n-old\n+new\n"
    "*** Delete File: gone.py\n"
    "*** End Patch"
)


def test_patch_lists_files_and_counts_changed_lines():
    payload = build_display(
        _event("apply_patch", ApplyPatchAction(patch=PATCH))
    ).payload

    assert payload["kind"] == "patch"
    assert payload["files"] == [
        {"op": "add", "path": "new.py"},
        {"op": "update", "path": "src/app.py"},
        {"op": "delete", "path": "gone.py"},
    ]
    assert payload["file_count"] == 3
    assert payload["added_lines"] == 2
    assert payload["removed_lines"] == 1
    assert payload["patch_bytes"] == len(PATCH.encode())


# --- browser ----------------------------------------------------------------


def test_browser_url_drops_credentials_query_values_and_fragment():
    action = _event(
        "browser_navigate",
        BrowserNavigateAction(url="https://u:p@site.example:8443/a/b?x=1&y=2#frag"),
    )
    payload = build_display(action).payload

    assert payload["url"] == "https://site.example:8443/a/b"
    assert payload["query_keys"] == ["x", "y"]


# --- unknown tools ----------------------------------------------------------


def test_unknown_tool_shows_argument_names_and_never_values():
    action = _event("mcp_tool", _McpLikeAction(query="private question", api_token="t"))
    projection = build_display(action)

    assert projection.payload["kind"] == "generic"
    assert projection.payload["arg_names"] == ["api_token", "query"]
    assert "private question" not in _shown(projection)
    assert projection.summary == "mcp_tool (2 argument(s))"


# --- the agent's own claim --------------------------------------------------


def test_llm_summary_is_kept_but_labelled_untrusted():
    projection = build_display(_terminal("ls", summary="listing files"))

    assert projection.payload["agent_claim"] == {
        "text": "listing files",
        "trusted": False,
    }


def test_sdk_fallback_summary_is_not_shown_as_the_agents_claim():
    # The SDK auto-generates "{tool}: {every raw argument}" when the LLM left
    # summary empty; that is the raw payload, not a claim.
    fallback = 'terminal: {"command": "cat ~/.ssh/id_rsa"}'
    projection = build_display(_terminal("cat ~/.ssh/id_rsa", summary=fallback))

    assert "agent_claim" not in projection.payload
    assert "id_rsa" not in projection.payload.get("agent_claim", {}).get("text", "")


def test_missing_summary_means_no_claim():
    assert "agent_claim" not in build_display(_terminal("ls")).payload


# --- envelope properties ----------------------------------------------------


def test_payload_records_projection_and_redaction_versions():
    payload = build_display(_terminal("ls")).payload

    assert payload["projection_version"] == PROJECTION_VERSION
    assert payload["redaction_version"] == REDACTION_VERSION
    assert payload["tool_name"] == "terminal"
    assert POLICY_REVISION.startswith("agent-server-display-")


def test_payload_names_the_rules_that_fired():
    payload = build_display(_terminal("curl --password=pw1 x")).payload

    assert payload["redactions"] == ["cli_secret_flag"]
    assert build_display(_terminal("ls")).payload["redactions"] == []


def test_projection_is_deterministic_and_json_serialisable():
    action = _terminal("curl -H 'Authorization: Bearer abc123def456' x", "claim")

    first, second = build_display(action), build_display(action)

    assert first == second
    assert json.dumps(first.payload, sort_keys=True) == json.dumps(
        second.payload, sort_keys=True
    )


def _huge_actions() -> list[ActionEvent]:
    big = "Z" * 400_000
    many_lines = "\n".join(["w " * 300] * 5000)
    return [
        _terminal(big, summary=big),
        _event(
            "file_editor", FileEditorAction(command="create", path="/p", file_text=big)
        ),
        _event(
            "file_editor",
            FileEditorAction(command="create", path="/p", file_text=many_lines),
        ),
        _event(
            "file_editor",
            FileEditorAction(
                command="str_replace",
                path="/p",
                old_str=many_lines,
                new_str=many_lines + "x",
            ),
        ),
        _event(
            "apply_patch",
            ApplyPatchAction(
                patch="\n".join(f"*** Add File: f{i}.py\n+x" for i in range(3000))
            ),
        ),
        _event(
            "browser_navigate",
            BrowserNavigateAction(url="https://h.example/" + "p" * 50_000),
        ),
        _event("mcp_tool", _McpLikeAction(query=big, api_token=big)),
    ]


@pytest.mark.parametrize("action", _huge_actions(), ids=lambda a: a.tool_name)
def test_output_size_is_bounded_whatever_the_input_size(action):
    projection = build_display(action)

    assert len(_shown(projection)) < 12_000
