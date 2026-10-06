"""RoyPathPayloadSecurityAnalyzer routes by tool identity, not field name.

The risk it returns decides whether an action needs approval at all (LOW =
no approval). These tests pin the reasons, not just the outputs:

- a tool is trusted with "a path inside the workspace is fine" only if it is a
  built-in (its Action class comes from ``openhands.tools``). A third-party tool
  (an MCP server's, a plugin's) can call a field ``path`` or even call itself
  ``file_editor``; that must never turn into "no approval";
- the gemini file tools call their argument ``file_path`` / ``dir_path`` and
  resolve a relative path against the workspace, so the analyzer must too.
"""

import os
import subprocess
import sys

import pytest
from litellm import ChatCompletionMessageToolCall
from litellm.types.utils import Function

from openhands.sdk.event import ActionEvent
from openhands.sdk.llm import MessageToolCall, TextContent
from openhands.sdk.security.confirmation_policy import ConfirmRisky
from openhands.sdk.security.risk import SecurityRisk
from openhands.sdk.security.roy_governance import RoyPathPayloadSecurityAnalyzer
from openhands.sdk.tool.schema import Action
from openhands.tools.file_editor.definition import FileEditorAction
from openhands.tools.gemini.edit.definition import EditAction
from openhands.tools.gemini.list_directory.definition import ListDirectoryAction
from openhands.tools.gemini.read_file.definition import ReadFileAction
from openhands.tools.gemini.write_file.definition import WriteFileAction
from openhands.tools.glob.definition import GlobAction
from openhands.tools.grep.definition import GrepAction
from openhands.tools.terminal.definition import TerminalAction


class _ThirdPartyPathAction(Action):
    """What an MCP tool or plugin looks like to the analyzer: not from
    openhands.tools, but with a field called ``path``."""

    path: str


class _ThirdPartyCommandAction(Action):
    command: str


def _event(tool_name: str, action: Action) -> ActionEvent:
    call = ChatCompletionMessageToolCall(
        id="call_1",
        type="function",
        function=Function(name=tool_name, arguments="{}"),
    )
    return ActionEvent(
        source="agent",
        thought=[TextContent(text="t")],
        action=action,
        tool_name=tool_name,
        tool_call_id="call_1",
        tool_call=MessageToolCall.from_chat_tool_call(call),
        llm_response_id="r1",
    )


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "ws"
    root.mkdir()
    # The server's cwd is NOT the workspace, so a relative path judged against
    # cwd instead of the workspace would be classified wrongly.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    return root


@pytest.fixture
def analyzer(workspace):
    return RoyPathPayloadSecurityAnalyzer(workspace_root=str(workspace))


def _risk(analyzer, tool_name: str, action: Action) -> SecurityRisk:
    return analyzer.security_risk(_event(tool_name, action))


# --- built-in tools: path decides ---------------------------------------------


def test_file_editor_inside_workspace_is_low(analyzer, workspace):
    action = FileEditorAction(command="view", path=str(workspace / "a.txt"))
    assert _risk(analyzer, "file_editor", action) == SecurityRisk.LOW


def test_file_editor_outside_workspace_is_high(analyzer, workspace):
    action = FileEditorAction(command="view", path=str(workspace.parent / "x.txt"))
    assert _risk(analyzer, "file_editor", action) == SecurityRisk.HIGH


@pytest.mark.parametrize(
    ("tool_name", "make"),
    [
        ("write_file", lambda p: WriteFileAction(file_path=p, content="x")),
        (
            "edit",
            lambda p: EditAction(file_path=p, old_string="a", new_string="b"),
        ),
        ("read_file", lambda p: ReadFileAction(file_path=p)),
        ("list_directory", lambda p: ListDirectoryAction(dir_path=p)),
    ],
)
def test_gemini_tools_are_judged_by_their_own_path_field(
    analyzer, workspace, tool_name, make
):
    # Before: ``file_path`` / ``dir_path`` were not recognised, so these were
    # always UNKNOWN — gated, while file_editor in the same place was free.
    assert _risk(analyzer, tool_name, make(str(workspace / "a.txt"))) == (
        SecurityRisk.LOW
    )
    outside = str(workspace.parent / "a.txt")
    assert _risk(analyzer, tool_name, make(outside)) == SecurityRisk.HIGH


def test_gemini_relative_path_is_resolved_against_the_workspace(analyzer):
    # The tool joins a relative path onto the workspace root, so "sub/a.txt" is
    # inside it and "../x" is not — whatever the server's cwd is.
    inside = WriteFileAction(file_path="sub/a.txt", content="x")
    escaping = WriteFileAction(file_path="../x.txt", content="x")
    assert _risk(analyzer, "write_file", inside) == SecurityRisk.LOW
    assert _risk(analyzer, "write_file", escaping) == SecurityRisk.HIGH


def test_symlink_out_of_the_workspace_is_high(analyzer, workspace):
    outside = workspace.parent / "secret_dir"
    outside.mkdir()
    link = workspace / "link"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        # Windows without the symlink privilege: a directory junction is also
        # a link realpath() follows, and needs no privilege.
        made = (
            sys.platform == "win32"
            and subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
                capture_output=True,
            ).returncode
            == 0
        )
        if not made:
            pytest.skip("cannot create a symlink or junction here")
    action = WriteFileAction(file_path="link/a.txt", content="x")
    assert _risk(analyzer, "write_file", action) == SecurityRisk.HIGH


def test_grep_and_glob_with_a_path_follow_it(analyzer, workspace):
    inside, outside = str(workspace), str(workspace.parent)
    assert _risk(analyzer, "grep", GrepAction(pattern="x", path=inside)) == (
        SecurityRisk.LOW
    )
    assert _risk(analyzer, "grep", GrepAction(pattern="x", path=outside)) == (
        SecurityRisk.HIGH
    )
    assert _risk(analyzer, "glob", GlobAction(pattern="*", path=inside)) == (
        SecurityRisk.LOW
    )
    assert _risk(analyzer, "glob", GlobAction(pattern="*", path=outside)) == (
        SecurityRisk.HIGH
    )


def test_grep_and_glob_without_a_path_stay_gated(analyzer):
    # glob can take its directory from the pattern ("/etc/**"), so "no path"
    # does not prove "inside the workspace".
    assert _risk(analyzer, "grep", GrepAction(pattern="x")) == SecurityRisk.UNKNOWN
    assert _risk(analyzer, "glob", GlobAction(pattern="/etc/**")) == (
        SecurityRisk.UNKNOWN
    )


@pytest.mark.parametrize(
    "pattern",
    ["../outside/*", "sub/../../outside/*", "/etc/**", "~/x/*", "C:/x/*", r"..\x"],
)
def test_glob_pattern_that_can_leave_the_path_is_gated(analyzer, workspace, pattern):
    # glob evaluates ``pattern`` as written (the Python fallback backend), so a
    # path inside the workspace says nothing about where an absolute or ``..``
    # pattern reaches. (Found by review; the old field-name routing had it too.)
    action = GlobAction(pattern=pattern, path=str(workspace))
    risk = _risk(analyzer, "glob", action)
    assert risk != SecurityRisk.LOW
    assert ConfirmRisky().should_confirm(risk) is True


@pytest.mark.parametrize("pattern", ["**/*.py", "src/*.py", "*.md", "a..b/*"])
def test_glob_pattern_below_the_path_stays_free(analyzer, workspace, pattern):
    action = GlobAction(pattern=pattern, path=str(workspace))
    assert _risk(analyzer, "glob", action) == SecurityRisk.LOW


def test_terminal_is_high(analyzer):
    action = TerminalAction(command="ls")
    assert _risk(analyzer, "terminal", action) == SecurityRisk.HIGH


# --- third-party tools: never LOW because of a field name ---------------------


def test_third_party_tool_with_path_inside_workspace_is_not_free(analyzer, workspace):
    # The gap this change closes: any tool with a ``path`` field inside the
    # workspace used to be LOW, i.e. no approval, whatever it does with it.
    action = _ThirdPartyPathAction(path=str(workspace / "a.txt"))
    risk = _risk(analyzer, "mcp_delete_everything", action)
    assert risk == SecurityRisk.UNKNOWN
    assert ConfirmRisky().should_confirm(risk) is True


def test_third_party_tool_with_path_outside_workspace_is_gated(analyzer, workspace):
    action = _ThirdPartyPathAction(path=str(workspace.parent / "a.txt"))
    risk = _risk(analyzer, "mcp_tool", action)
    assert ConfirmRisky().should_confirm(risk) is True


def test_third_party_tool_cannot_borrow_a_built_in_name(analyzer, workspace):
    # Same name as the built-in, same field, inside the workspace — but the
    # Action class is not from openhands.tools, so it is not trusted.
    action = _ThirdPartyPathAction(path=str(workspace / "a.txt"))
    risk = _risk(analyzer, "file_editor", action)
    assert risk == SecurityRisk.UNKNOWN


def test_third_party_command_field_is_still_high(analyzer):
    # Stricter, so it needs no tool identity.
    action = _ThirdPartyCommandAction(command="anything")
    assert _risk(analyzer, "whatever", action) == SecurityRisk.HIGH


def test_built_in_action_under_another_tool_name_is_not_trusted(analyzer, workspace):
    # The name is the key into the trusted table; an unlisted name with a
    # built-in class is simply an unknown tool.
    action = ReadFileAction(file_path=str(workspace / "a.txt"))
    assert _risk(analyzer, "not_a_listed_tool", action) == SecurityRisk.UNKNOWN
