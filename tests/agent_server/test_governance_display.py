"""Tests for the central-approval display projection.

The invariants that matter, each tested on its own below:
- no known secret survives in ANY tool's output (``SECRET_CORPUS``);
- output size is bounded whatever the input size;
- redaction happens before clipping;
- tools with no projection show argument names, never values, and are
  marked unprojected (the device refuses them);
- the LLM's summary is labelled untrusted and the SDK's raw-argument fallback
  summary is never shown.
"""

import json

import pytest

from openhands.agent_server import governance_display as gd
from openhands.agent_server.governance_display import (
    MAX_ARG_CHARS,
    MAX_COMMAND_PREVIEW_CHARS,
    MAX_PREVIEW_LINE_CHARS,
    MAX_PREVIEW_LINES,
    MAX_QUERY_KEYS,
    MAX_URL_CHARS,
    POLICY_REVISION,
    PROJECTION_VERSION,
    build_display,
    truncation_reason,
    unprojected_reason,
)
from openhands.agent_server.governance_redaction import REDACTION_VERSION
from openhands.sdk.event import ActionEvent
from openhands.sdk.llm import MessageToolCall, TextContent
from openhands.sdk.tool import Action
from openhands.sdk.tool.builtins.invoke_skill import InvokeSkillAction
from openhands.sdk.tool.builtins.switch_llm import SwitchLLMAction
from openhands.sdk.tool.builtins.vision_inspect import VisionInspectAction
from openhands.tools.apply_patch.definition import ApplyPatchAction
from openhands.tools.ask_oracle.definition import AskOracleAction
from openhands.tools.browser_use.definition import (
    BrowserClickAction,
    BrowserCloseTabAction,
    BrowserGetContentAction,
    BrowserGetStateAction,
    BrowserGetStorageAction,
    BrowserGoBackAction,
    BrowserListTabsAction,
    BrowserNavigateAction,
    BrowserScrollAction,
    BrowserSetStorageAction,
    BrowserStartRecordingAction,
    BrowserStopRecordingAction,
    BrowserSwitchTabAction,
    BrowserTypeAction,
)
from openhands.tools.delegate.definition import DelegateAction
from openhands.tools.file_editor.definition import FileEditorAction
from openhands.tools.gemini.edit.definition import EditAction
from openhands.tools.gemini.list_directory.definition import ListDirectoryAction
from openhands.tools.gemini.read_file.definition import ReadFileAction
from openhands.tools.gemini.write_file.definition import WriteFileAction
from openhands.tools.glob.definition import GlobAction
from openhands.tools.grep.definition import GrepAction
from openhands.tools.task.definition import TaskAction
from openhands.tools.task_tracker.definition import TaskItem, TaskTrackerAction
from openhands.tools.terminal.definition import TerminalAction
from openhands.tools.tom_consult.definition import (
    ConsultTomAction,
    SleeptimeComputeAction,
)
from openhands.tools.workflow.definition import WorkflowAction


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

# The tools projected after the first four: a secret in their free text must
# not survive either.
SECRET_CORPUS += [
    (
        _FAKE_GH,
        _event(
            "write_file", WriteFileAction(file_path="/w/.env", content=f"T={_FAKE_GH}")
        ),
    ),
    (
        _FAKE_GH,
        _event(
            "ask_oracle", AskOracleAction(question="why", context=f"tok {_FAKE_GH}")
        ),
    ),
    (
        _FAKE_GH,
        _event(
            "workflow",
            WorkflowAction(name="w", script=f"TOKEN = '{_FAKE_GH}'"),
        ),
    ),
    (
        _FAKE_GH,
        _event("grep", GrepAction(pattern=_FAKE_GH)),
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


@pytest.mark.parametrize(
    ("raw", "shown", "keys", "secret"),
    [
        # Found by the independent review: without a scheme the raw URL used
        # to be shown as-is, query values and userinfo included.
        (
            "/callback?sid=sessionvalue55&x=1",
            "/callback",
            ["sid", "x"],
            "sessionvalue55",
        ),
        (
            "//user:urlpass77@site.example/a?x=1",
            "//site.example/a",
            ["x"],
            "urlpass77",
        ),
        (
            "site.example/a?sid=sessionvalue55",
            "site.example/a",
            ["sid"],
            "sessionvalue55",
        ),
        # Opaque schemes carry their content in the "path": show only its size.
        ("data:text/plain;base64,c2Vjcg==", "data:[26 chars]", [], "c2Vjcg"),
        ("javascript:alert('tok123')", "javascript:[15 chars]", [], "tok123"),
        ("mailto:boss@example.com?subject=pw9", "mailto:[28 chars]", [], "pw9"),
        ("https://[::1]:8443/a?x=1", "https://[::1]:8443/a", ["x"], None),
    ],
    ids=[
        "relative",
        "scheme-relative",
        "bare-host",
        "data",
        "javascript",
        "mailto",
        "ipv6",
    ],
)
def test_browser_url_never_shows_more_than_host_port_and_path(raw, shown, keys, secret):
    projection = build_display(
        _event("browser_navigate", BrowserNavigateAction(url=raw))
    )

    assert projection.payload["url"] == shown
    assert projection.payload["query_keys"] == keys
    if secret:
        assert secret not in _shown(projection)


def test_unparseable_url_shows_nothing_derived_from_it():
    # An out-of-range port makes urlsplit(...).port raise ValueError.
    projection = build_display(
        _event(
            "browser_navigate",
            BrowserNavigateAction(url="https://site.example:99999999/a?tok=zz9"),
        )
    )

    assert projection.payload["url"] == ""
    assert "zz9" not in _shown(projection)


# --- unknown tools ----------------------------------------------------------


def test_unknown_tool_shows_argument_names_and_never_values():
    action = _event("mcp_tool", _McpLikeAction(query="private question", api_token="t"))
    projection = build_display(action)

    assert projection.payload["kind"] == "generic"
    assert projection.payload["arg_names"] == ["api_token", "query"]
    assert "private question" not in _shown(projection)
    assert projection.summary == "mcp_tool (2 argument(s))"


# --- built-in tools without a bespoke projector ------------------------------
# What leaves the device for each is decided by ``_TOOL_ARGS`` (deny by
# default). These tests pin the decisions that matter, and the ways the table
# can silently stop covering a tool.


class _ThirdPartyCommand(Action):
    command: str


def test_browser_type_shows_the_length_of_the_text_never_the_text():
    # The typed text may be a password; no redaction pattern recognises one.
    secret = "correct horse battery staple 9"
    projection = build_display(
        _event("browser_type", BrowserTypeAction(index=3, text=secret))
    )

    assert projection.payload["kind"] == "tool_args"
    assert projection.payload["arg_index"] == 3
    assert projection.payload["text_length"] == len(secret)
    assert "horse" not in _shown(projection)
    # Withheld by design is not a cut: such an action is still approvable.
    assert projection.is_truncated is False
    assert projection.is_unprojected is False


def test_browser_set_storage_shows_names_and_counts_never_values():
    state = {
        "cookies": [
            {"name": "session", "value": "cookie-value-zz1", "domain": "a.example"},
            {"name": "csrf", "value": "cookie-value-zz2", "domain": "b.example"},
        ],
        "origins": [
            {
                "origin": "https://a.example",
                "localStorage": [{"name": "jwt", "value": "local-value-zz3"}],
            }
        ],
    }
    projection = build_display(
        _event("browser_set_storage", BrowserSetStorageAction(storage_state=state))
    )

    assert projection.payload["cookie_count"] == 2
    assert projection.payload["cookie_names"] == ["session@a.example", "csrf@b.example"]
    assert projection.payload["origins"] == ["https://a.example"]
    assert projection.payload["storage_item_count"] == 1
    assert "zz1" not in _shown(projection)
    assert "zz3" not in _shown(projection)
    assert projection.is_truncated is False


@pytest.mark.parametrize(
    "state",
    [
        {"cookies": "not-a-list"},
        {"cookies": [], "origins": [], "extra": {"token": "zz"}},
        {"cookies": [{"name": f"c{i}", "domain": "d"} for i in range(60)]},
    ],
    ids=["wrong-shape", "unknown-key", "too-many-cookies"],
)
def test_browser_set_storage_that_cannot_be_shown_in_full_is_flagged(state):
    # Content the projection did not show counts as a cut, so the action is
    # refused instead of approved blind.
    projection = build_display(
        _event("browser_set_storage", BrowserSetStorageAction(storage_state=state))
    )

    assert projection.is_truncated is True


def test_gemini_write_file_is_shown_like_a_file_edit():
    projection = build_display(
        _event("write_file", WriteFileAction(file_path="/w/a.py", content="x = 1\n"))
    )

    assert projection.payload["kind"] == "file_edit"
    assert projection.payload["path"] == "/w/a.py"
    assert projection.payload["diff_preview"] == ["+x = 1"]
    assert projection.summary == "write_file create /w/a.py"
    assert projection.is_truncated is False


def test_gemini_write_file_over_the_preview_limit_is_flagged():
    content = "\n".join(f"line {i}" for i in range(MAX_PREVIEW_LINES + 5))
    projection = build_display(
        _event("write_file", WriteFileAction(file_path="/w/a.py", content=content))
    )

    assert projection.is_truncated is True


def test_gemini_edit_is_a_replacement_unless_old_string_is_empty():
    replace = build_display(
        _event(
            "edit",
            EditAction(file_path="/w/a.py", old_string="a = 1", new_string="a = 2"),
        )
    )
    create = build_display(
        _event(
            "edit", EditAction(file_path="/w/b.py", old_string="", new_string="b = 1")
        )
    )

    assert replace.payload["command"] == "str_replace"
    assert "-a = 1" in replace.payload["diff_preview"]
    assert "+a = 2" in replace.payload["diff_preview"]
    assert replace.payload["expected_replacements"] == 1
    assert create.payload["command"] == "create"
    assert create.payload["diff_preview"] == ["+b = 1"]


def test_gemini_edit_redacts_secrets_in_the_old_and_new_text():
    projection = build_display(
        _event(
            "edit",
            EditAction(
                file_path="/w/.env",
                old_string="GH=x",
                new_string=f"GH={_FAKE_GH}",
            ),
        )
    )

    assert _FAKE_GH not in _shown(projection)


def test_grep_shows_pattern_and_path():
    projection = build_display(
        _event("grep", GrepAction(pattern="TODO", path="/etc", include="*.conf"))
    )

    assert projection.payload["arg_pattern"] == "TODO"
    assert projection.payload["arg_path"] == "/etc"
    assert projection.payload["arg_include"] == "*.conf"
    assert projection.is_truncated is False


def test_a_shown_argument_longer_than_the_limit_is_flagged():
    projection = build_display(
        _event("grep", GrepAction(pattern="x" * (MAX_ARG_CHARS + 1)))
    )

    assert projection.is_truncated is True
    assert len(projection.payload["arg_pattern"]) == MAX_ARG_CHARS


def test_workflow_script_is_previewed_and_a_long_one_is_flagged():
    short = build_display(
        _event("workflow", WorkflowAction(name="w", script="async def main(wf): pass"))
    )
    long_script = "\n".join(f"step_{i}()" for i in range(MAX_PREVIEW_LINES + 1))
    long = build_display(
        _event("workflow", WorkflowAction(name="w", script=long_script))
    )

    assert short.payload["arg_script"] == ["async def main(wf): pass"]
    assert short.is_truncated is False
    assert long.is_truncated is True


def test_subagent_prompt_is_redacted_before_it_is_shown():
    projection = build_display(
        _event(
            "task",
            TaskAction(
                description="d",
                prompt=f"use token {_FAKE_GH} to push",
                subagent_type="default",
            ),
        )
    )

    assert _FAKE_GH not in _shown(projection)
    assert projection.payload["redactions"]


def test_task_tracker_shows_how_many_tasks_not_their_text():
    projection = build_display(
        _event(
            "task_tracker",
            TaskTrackerAction(
                command="plan", task_list=[TaskItem(title="private plan", notes="n")]
            ),
        )
    )

    assert projection.payload["task_list_count"] == 1
    assert "private plan" not in _shown(projection)


def test_a_tool_with_no_projection_is_unprojected():
    projection = build_display(
        _event("mcp_tool", _McpLikeAction(query="private question", api_token="t"))
    )

    assert projection.is_unprojected is True
    assert projection.is_truncated is False


@pytest.mark.parametrize(
    "tool_name",
    ["terminal", "file_editor", "browser_type", "read_file", "workflow", "task"],
)
def test_a_third_party_tool_cannot_borrow_a_built_in_name(tool_name):
    # A projection is chosen by name, but the name is the tool author's. An MCP
    # tool called "browser_type" would otherwise get "text: length only".
    projection = build_display(_event(tool_name, _ThirdPartyCommand(command="x")))

    assert projection.payload["kind"] == "generic"
    assert projection.is_unprojected is True


def test_a_built_in_with_a_new_unlisted_argument_is_unprojected(monkeypatch):
    # If a built-in grows a field the table does not name, showing the rest
    # would hide part of the action: the whole action is treated as unprojected.
    narrowed = {k: v for k, v in gd._TOOL_ARGS["grep"].items() if k != "include"}
    monkeypatch.setitem(gd._TOOL_ARGS, "grep", narrowed)

    projection = build_display(_event("grep", GrepAction(pattern="x")))

    assert projection.is_unprojected is True


_TOOL_ACTION_CLASSES = {
    "read_file": ReadFileAction,
    "list_directory": ListDirectoryAction,
    "grep": GrepAction,
    "glob": GlobAction,
    "browser_type": BrowserTypeAction,
    "browser_click": BrowserClickAction,
    "browser_scroll": BrowserScrollAction,
    "browser_switch_tab": BrowserSwitchTabAction,
    "browser_close_tab": BrowserCloseTabAction,
    "browser_get_state": BrowserGetStateAction,
    "browser_get_content": BrowserGetContentAction,
    "browser_go_back": BrowserGoBackAction,
    "browser_list_tabs": BrowserListTabsAction,
    "browser_get_storage": BrowserGetStorageAction,
    "browser_start_recording": BrowserStartRecordingAction,
    "browser_stop_recording": BrowserStopRecordingAction,
    "workflow": WorkflowAction,
    "task": TaskAction,
    "delegate": DelegateAction,
    "ask_oracle": AskOracleAction,
    "tom_consult": ConsultTomAction,
    "sleeptime_compute": SleeptimeComputeAction,
    "task_tracker": TaskTrackerAction,
    "invoke_skill": InvokeSkillAction,
    "switch_llm": SwitchLLMAction,
    "vision_inspect": VisionInspectAction,
}


def test_the_argument_table_names_every_field_of_every_listed_tool():
    # Drift detector: a field added to a built-in later must be added to
    # _TOOL_ARGS on purpose (it decides what an approver sees of it), not
    # silently turn that tool into "refused".
    assert set(_TOOL_ACTION_CLASSES) == set(gd._TOOL_ARGS)
    for tool_name, cls in _TOOL_ACTION_CLASSES.items():
        fields = set(cls.model_fields) - gd._FRAMEWORK_ARG_KEYS
        assert fields == set(gd._TOOL_ARGS[tool_name]), tool_name


def test_policy_revision_moved_with_what_the_approver_sees():
    # New projections change what an approver sees, so the digest envelope's
    # revision must not still say v1.
    assert POLICY_REVISION != "agent-server-display-v1"


def test_unprojected_reason_never_echoes_the_action():
    # A third-party tool's own name is attacker-controlled; the agent-facing
    # reason is fixed text.
    reason = unprojected_reason()

    assert "approval preview" in reason
    assert "terminal or file_editor" in reason


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


@pytest.mark.parametrize(
    "fallback",
    [
        'terminal: {"command": "cat ~/.ssh/id_rsa"}',
        'terminal:{"command": "cat ~/.ssh/id_rsa"}',
        'terminal: ["cat ~/.ssh/id_rsa"]',
    ],
    ids=["sdk-shape", "no-space", "list"],
)
def test_any_tool_name_prefixed_summary_is_treated_as_the_fallback(fallback):
    # The SDK's real fallback is "{tool.name}: {json.dumps(dict)}", but a
    # summary that merely starts with "<tool>:" is dropped too: it is
    # untrusted anyway, so being conservative costs nothing.
    projection = build_display(_terminal("cat ~/.ssh/id_rsa", summary=fallback))

    assert "agent_claim" not in projection.payload
    assert "id_rsa" not in projection.payload["command_preview"].replace(
        "cat ~/.ssh/id_rsa", ""
    )


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


# --- truncation: does the approver see the whole action? ----------------------


def _create_file(content: str) -> ActionEvent:
    return _event(
        "file_editor",
        FileEditorAction(command="create", path="/w/f.txt", file_text=content),
    )


def _navigate(url: str) -> ActionEvent:
    return _event("browser_navigate", BrowserNavigateAction(url=url))


def _patch_adding(n_lines: int) -> ActionEvent:
    body = "\n".join(f"+{i}" for i in range(n_lines))
    return _event(
        "apply_patch",
        ApplyPatchAction(
            patch=f"*** Begin Patch\n*** Add File: a.py\n{body}\n*** End Patch"
        ),
    )


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        (_terminal("e" * MAX_COMMAND_PREVIEW_CHARS), False),
        (_terminal("e" * (MAX_COMMAND_PREVIEW_CHARS + 1)), True),
        (_create_file("\n".join("r" for _ in range(MAX_PREVIEW_LINES))), False),
        (_create_file("\n".join("r" for _ in range(MAX_PREVIEW_LINES + 1))), True),
        (_create_file("c" * (MAX_PREVIEW_LINE_CHARS + 1)), True),
        (_event("apply_patch", ApplyPatchAction(patch=PATCH)), False),
        (_patch_adding(MAX_PREVIEW_LINES + 5), True),
        (_navigate("https://example.com/a"), False),
        (_navigate("https://example.com/" + "p" * MAX_URL_CHARS), True),
        (_event("some_mcp_tool", _McpLikeAction(query="q", api_token="t")), False),
        (_event("file_editor", FileEditorAction(command="view", path="/w/f")), False),
    ],
    ids=[
        "terminal-at-limit",
        "terminal-over-limit",
        "file-at-line-limit",
        "file-over-line-limit",
        "file-over-line-width",
        "patch-small",
        "patch-over-line-limit",
        "url-short",
        "url-over-limit",
        "unknown-tool",
        "file-view",
    ],
)
def test_projection_reports_whether_the_approver_sees_less_than_the_action(
    action, expected
):
    assert build_display(action).is_truncated is expected


def test_truncation_flag_is_not_part_of_the_digested_payload():
    # The payload is what central digests and shows: adding anything to it
    # would change the wire contract. The flag is derived from it instead.
    payload = build_display(_terminal("e" * 5000)).payload

    assert "is_truncated" not in payload
    assert payload["truncated"] is True


@pytest.mark.parametrize(
    ("action", "limit_text"),
    [
        (_terminal("e" * 5000), str(MAX_COMMAND_PREVIEW_CHARS)),
        (_create_file("r\n" * 500), str(MAX_PREVIEW_LINES)),
        (_patch_adding(100), str(MAX_PREVIEW_LINES)),
        (_navigate("https://example.com/" + "p" * 1000), str(MAX_URL_CHARS)),
    ],
    ids=["terminal", "file", "patch", "url"],
)
def test_truncation_reason_names_the_limit_and_tells_the_agent_what_to_do(
    action, limit_text
):
    reason = truncation_reason(build_display(action))

    assert limit_text in reason
    assert "smaller steps" in reason


def test_truncation_reason_never_repeats_the_action_content():
    secret = "ZZ-not-a-real-secret-ZZ"
    reason = truncation_reason(build_display(_terminal(f"echo {secret} " + "e" * 500)))

    assert secret not in reason


# --- limits that cut the INPUT before the preview limits apply ----------------


def _replace(old: str, new: str) -> ActionEvent:
    return _event(
        "file_editor",
        FileEditorAction(
            command="str_replace", path="/w/f.txt", old_str=old, new_str=new
        ),
    )


def test_str_replace_differing_only_past_the_input_line_cap_is_truncated():
    # The diff is computed on the first _MAX_INPUT_LINES lines of each side.
    # Identical heads give an empty diff, so a change after that point would
    # look like "nothing to show" while the flag stayed False.
    shared = [f"line {i}" for i in range(600)]
    old = "\n".join(shared)
    new = "\n".join(shared[:550] + ["CHANGED"] + shared[551:])

    projection = build_display(_replace(old, new))

    assert projection.payload["diff_preview"] == []
    assert projection.payload["diff_truncated"] is True
    assert projection.is_truncated


def test_str_replace_differing_only_past_the_char_cap_is_truncated():
    old = "a" * 150_000
    new = "a" * 149_999 + "b"

    projection = build_display(_replace(old, new))

    assert projection.is_truncated


def test_str_replace_within_both_caps_is_not_truncated():
    projection = build_display(_replace("old line", "new line"))

    assert not projection.is_truncated


@pytest.mark.parametrize(
    ("n_keys", "expected"),
    [(MAX_QUERY_KEYS, False), (MAX_QUERY_KEYS + 1, True)],
    ids=["keys-at-limit", "keys-over-limit"],
)
def test_browser_url_with_more_query_keys_than_shown_is_truncated(n_keys, expected):
    query = "&".join(f"k{i}=v" for i in range(n_keys))
    projection = build_display(_navigate(f"https://example.com/p?{query}"))

    assert len(projection.payload["query_keys"]) == min(n_keys, MAX_QUERY_KEYS)
    assert projection.is_truncated is expected


# --- cuts the preview limits never see (found in a second review) --------------

_INPUT_CAP = gd._MAX_INPUT_CHARS


def test_query_keys_past_the_input_cap_are_truncated():
    # The URL is cut to the input cap before it is parsed, so a parameter name
    # after a long value is not in query_keys at all.
    url = "https://example.test/cb?k=" + "p" * (_INPUT_CAP + 10) + "&dangerous=v"
    projection = build_display(_navigate(url))

    assert "dangerous" not in projection.payload["query_keys"]
    assert projection.is_truncated


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(document.cookie)",
        "data:text/html,<script>x</script>",
        "file:///etc/passwd",
        "mailto:someone@example.test",
    ],
)
def test_url_whose_content_is_shown_only_as_a_length_is_truncated(url):
    # For schemes without a host the content lives in the "path", and the
    # projection shows only how long it is. That is the whole action, not a
    # credential or a query value, so the approver is not seeing it.
    projection = build_display(_navigate(url))

    assert projection.payload["url"].endswith("chars]")
    assert projection.is_truncated


@pytest.mark.parametrize("url", ["/cb?x=1", "site.example/a?x=1", "https://h.test/p"])
def test_url_shown_as_host_and_path_is_not_truncated(url):
    assert not build_display(_navigate(url)).is_truncated


def test_file_path_past_the_input_cap_is_truncated():
    action = _event(
        "file_editor",
        FileEditorAction(command="create", path="/w/" + "d" * _INPUT_CAP, file_text=""),
    )

    assert build_display(action).is_truncated


def test_input_cut_is_recorded_in_the_payload_only_when_it_happens():
    normal = build_display(_terminal("ls")).payload
    cut = build_display(_terminal("e" * (_INPUT_CAP + 1))).payload

    assert "input_truncated" not in normal
    assert cut["input_truncated"] is True


def test_an_overlong_agent_claim_is_not_an_action_truncation():
    # The claim is the agent's own untrusted text, not the action.
    projection = build_display(_terminal("ls", summary="x" * (_INPUT_CAP + 1)))

    assert not projection.is_truncated
