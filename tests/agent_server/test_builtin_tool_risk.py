"""The risk RoyPathPayloadSecurityAnalyzer gives every built-in tool, pinned.

Under the governed default policy (``ConfirmRisky``: threshold HIGH,
``confirm_unknown=True``) UNKNOWN and HIGH need an approval, LOW does not, and so
does MEDIUM: a MEDIUM answer would run without asking anyone. Whether a tool needs
approval is therefore decided entirely by this table, and a new built-in tool must
not land in UNKNOWN (= "asks") or, worse, somewhere quieter, without anyone having
looked at it.

The table says what the analyzer does today. It is not a second set of rules: the
analyzer is the only place the decision is made, and these tests fail when the two
drift. It is deliberately a record, not a wish: loosening a row (e.g. making a
browser read-only tool LOW) is a separate decision, made per tool and by hand.

It lives in tests/agent_server because it reads both the SDK analyzer and the
agent-server's display tables (agent-server depends on the SDK, not the reverse).
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pkgutil
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

import pytest
from litellm import ChatCompletionMessageToolCall
from litellm.types.utils import Function

import openhands.tools
from openhands.agent_server.governance_display import _PROJECTORS, _TOOL_ARGS
from openhands.sdk.event import ActionEvent
from openhands.sdk.llm import MessageToolCall, TextContent
from openhands.sdk.security.confirmation_policy import ConfirmRisky
from openhands.sdk.security.risk import SecurityRisk
from openhands.sdk.security.roy_governance import (
    _PATH_TOOLS,
    RoyPathPayloadSecurityAnalyzer,
)
from openhands.sdk.tool import ToolDefinition
from openhands.sdk.tool.builtins.finish import FinishAction
from openhands.sdk.tool.builtins.invoke_skill import InvokeSkillAction
from openhands.sdk.tool.builtins.switch_llm import SwitchLLMAction
from openhands.sdk.tool.builtins.think import ThinkAction
from openhands.sdk.tool.builtins.vision_inspect import (
    VISION_INSPECT_TOOL_NAME,
    VisionInspectAction,
)
from openhands.sdk.tool.schema import Action
from openhands.tools.apply_patch.definition import ApplyPatchAction
from openhands.tools.ask_oracle.definition import AskOracleAction
from openhands.tools.browser_use.definition import (
    BrowserAction,
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
from openhands.tools.planning_file_editor.definition import PlanningFileEditorAction
from openhands.tools.task.definition import TaskAction
from openhands.tools.task_tracker.definition import TaskTrackerAction
from openhands.tools.terminal.definition import TerminalAction
from openhands.tools.tom_consult.definition import (
    ConsultTomAction,
    SleeptimeComputeAction,
)
from openhands.tools.workflow.definition import WorkflowAction


LOW, HIGH, UNKNOWN = SecurityRisk.LOW, SecurityRisk.HIGH, SecurityRisk.UNKNOWN


class _Row(NamedTuple):
    action_cls: type[Action]
    # Arguments of one representative call; ``ws`` is a file inside the workspace.
    args: Callable[[Path], dict[str, Any]]
    expected: SecurityRisk
    reason: str


def _no_args(_ws: Path) -> dict[str, Any]:
    return {}


_PATH = "built-in path tool: LOW while the path stays inside the workspace"
_UNLISTED = "no rule names it: UNKNOWN, so it asks"
_BROWSER = _UNLISTED + " (a page can be acted on or read; not judged tool by tool)"

# tool name (what ActionEvent.tool_name carries) -> one row
_TABLE: dict[str, _Row] = {
    "file_editor": _Row(
        FileEditorAction, lambda ws: {"command": "view", "path": str(ws)}, LOW, _PATH
    ),
    "planning_file_editor": _Row(
        PlanningFileEditorAction,
        lambda ws: {"command": "view", "path": str(ws)},
        LOW,
        _PATH,
    ),
    "read_file": _Row(ReadFileAction, lambda ws: {"file_path": str(ws)}, LOW, _PATH),
    "write_file": _Row(
        WriteFileAction,
        lambda ws: {"file_path": str(ws / "a.txt"), "content": "x"},
        LOW,
        _PATH,
    ),
    "edit": _Row(
        EditAction,
        lambda ws: {
            "file_path": str(ws / "a.txt"),
            "old_string": "a",
            "new_string": "b",
        },
        LOW,
        _PATH,
    ),
    "list_directory": _Row(
        ListDirectoryAction, lambda ws: {"dir_path": str(ws)}, LOW, _PATH
    ),
    "grep": _Row(GrepAction, lambda ws: {"pattern": "x", "path": str(ws)}, LOW, _PATH),
    "glob": _Row(
        GlobAction, lambda ws: {"pattern": "*.py", "path": str(ws)}, LOW, _PATH
    ),
    "terminal": _Row(
        TerminalAction,
        lambda _ws: {"command": "ls"},
        HIGH,
        "has a command field: HIGH, any tool identity",
    ),
    "delegate": _Row(
        DelegateAction,
        lambda _ws: {"command": "spawn"},
        HIGH,
        "has a command field (spawn/delegate): HIGH by that rule, same outcome as "
        "UNKNOWN (asks). This checkout registers no tool under this name (only "
        "the Action class, an executor and a display entry remain); the row records "
        "what the analyzer would answer",
    ),
    "task_tracker": _Row(
        TaskTrackerAction,
        _no_args,
        LOW,
        "built-in task tracker: only edits the agent's own task list (relaxed "
        "2026-10-20, Roy agreed); before that its `command` field made it HIGH",
    ),
    "apply_patch": _Row(
        ApplyPatchAction,
        lambda _ws: {"patch": "*** Begin Patch\n*** End Patch"},
        UNKNOWN,
        _UNLISTED + " (writes files, but not through a path field)",
    ),
    "ask_oracle": _Row(
        AskOracleAction,
        lambda _ws: {"question": "q"},
        UNKNOWN,
        _UNLISTED + " (sends the question and context to another model)",
    ),
    "browser_click": _Row(
        BrowserClickAction, lambda _ws: {"index": 1}, UNKNOWN, _BROWSER
    ),
    "browser_close_tab": _Row(
        BrowserCloseTabAction, lambda _ws: {"tab_id": "1"}, UNKNOWN, _BROWSER
    ),
    "browser_get_content": _Row(BrowserGetContentAction, _no_args, UNKNOWN, _BROWSER),
    "browser_get_state": _Row(BrowserGetStateAction, _no_args, UNKNOWN, _BROWSER),
    "browser_get_storage": _Row(BrowserGetStorageAction, _no_args, UNKNOWN, _BROWSER),
    "browser_go_back": _Row(BrowserGoBackAction, _no_args, UNKNOWN, _BROWSER),
    "browser_list_tabs": _Row(BrowserListTabsAction, _no_args, UNKNOWN, _BROWSER),
    "browser_navigate": _Row(
        BrowserNavigateAction,
        lambda _ws: {"url": "https://example.com"},
        UNKNOWN,
        _BROWSER,
    ),
    "browser_scroll": _Row(BrowserScrollAction, _no_args, UNKNOWN, _BROWSER),
    "browser_set_storage": _Row(
        BrowserSetStorageAction,
        lambda _ws: {"storage_state": {}},
        UNKNOWN,
        _BROWSER,
    ),
    "browser_start_recording": _Row(
        BrowserStartRecordingAction, _no_args, UNKNOWN, _BROWSER
    ),
    "browser_stop_recording": _Row(
        BrowserStopRecordingAction, _no_args, UNKNOWN, _BROWSER
    ),
    "browser_switch_tab": _Row(
        BrowserSwitchTabAction, lambda _ws: {"tab_id": "1"}, UNKNOWN, _BROWSER
    ),
    "browser_type": _Row(
        BrowserTypeAction,
        lambda _ws: {"index": 1, "text": "x"},
        UNKNOWN,
        _BROWSER + "; the typed text may be a password",
    ),
    "tom_consult": _Row(
        ConsultTomAction,
        lambda _ws: {"reason": "r"},
        UNKNOWN,
        _UNLISTED + " (sends context to another model)",
    ),
    "sleeptime_compute": _Row(SleeptimeComputeAction, _no_args, UNKNOWN, _UNLISTED),
    "invoke_skill": _Row(
        InvokeSkillAction,
        lambda _ws: {"name": "s"},
        UNKNOWN,
        _UNLISTED + " (loads text that then steers the agent; rendering a skill "
        "can also run its inline commands)",
    ),
    "switch_llm": _Row(
        SwitchLLMAction,
        lambda _ws: {"profile_name": "p", "reason": "r"},
        UNKNOWN,
        _UNLISTED + " (changes which model profile answers next; a profile can "
        "point at another provider)",
    ),
    "task": _Row(
        TaskAction,
        lambda _ws: {"prompt": "p"},
        UNKNOWN,
        _UNLISTED + " (starts a sub-agent)",
    ),
    VISION_INSPECT_TOOL_NAME: _Row(
        VisionInspectAction,
        lambda _ws: {"image_index": 0, "question": "q"},
        UNKNOWN,
        _UNLISTED + " (sends an image to another model)",
    ),
    "workflow": _Row(
        WorkflowAction,
        lambda _ws: {"name": "w", "script": "s"},
        UNKNOWN,
        _UNLISTED + " (runs a script)",
    ),
    # The SDK never asks for a single Finish or Think action (agent.py,
    # _requires_user_confirmation) whatever the analyzer says; the row only records
    # what the analyzer answers.
    "finish": _Row(
        FinishAction,
        lambda _ws: {"message": "m"},
        UNKNOWN,
        _UNLISTED + "; the SDK skips confirmation for a lone Finish anyway",
    ),
    "think": _Row(
        ThinkAction,
        lambda _ws: {"thought": "t"},
        UNKNOWN,
        _UNLISTED + "; the SDK skips confirmation for a lone Think anyway",
    ),
}


class _Variant(NamedTuple):
    tool_name: str
    action: Callable[[Path], Action]
    expected: SecurityRisk
    reason: str


# Other shapes of the same tools that the analyzer answers differently from the
# representative call above. Each one is a decision someone made on purpose.
_VARIANTS: dict[str, _Variant] = {
    "grep without a path": _Variant(
        "grep",
        lambda _ws: GrepAction(pattern="x"),
        LOW,
        "no path: the tool searches its own working directory, which is the "
        "workspace the analyzer is locked to (relaxed 2026-10-20, Roy agreed)",
    ),
    "glob without a path": _Variant(
        "glob",
        lambda _ws: GlobAction(pattern="*.py"),
        LOW,
        "no path: searches the working directory; the pattern stays below it "
        "(relaxed 2026-10-20, Roy agreed)",
    ),
    "glob without a path, pattern that climbs out": _Variant(
        "glob",
        lambda _ws: GlobAction(pattern="../*"),
        UNKNOWN,
        "the pattern can name a directory itself, path or no path",
    ),
    "glob without a path, absolute pattern": _Variant(
        "glob",
        lambda _ws: GlobAction(pattern="/etc/*"),
        UNKNOWN,
        "an absolute pattern is evaluated as written, path or no path",
    ),
    "glob pattern that climbs out": _Variant(
        "glob",
        lambda ws: GlobAction(pattern="../*", path=str(ws)),
        UNKNOWN,
        "a path inside the workspace proves nothing when the pattern leaves it",
    ),
    "glob absolute pattern": _Variant(
        "glob",
        lambda ws: GlobAction(pattern="/etc/*", path=str(ws)),
        UNKNOWN,
        "an absolute pattern is evaluated as written",
    ),
    "glob home-relative pattern": _Variant(
        "glob",
        lambda ws: GlobAction(pattern="~/*", path=str(ws)),
        UNKNOWN,
        "a home-relative pattern leaves the workspace",
    ),
    "glob drive-qualified pattern": _Variant(
        "glob",
        lambda ws: GlobAction(pattern="C:/*", path=str(ws)),
        UNKNOWN,
        "a drive-qualified pattern leaves the workspace",
    ),
    "list_directory without a directory": _Variant(
        "list_directory",
        lambda _ws: ListDirectoryAction(),
        LOW,
        "defaults to the workspace root, which is inside the workspace",
    ),
    "file_editor create inside the workspace": _Variant(
        "file_editor",
        lambda ws: FileEditorAction(
            command="create", path=str(ws / "b.txt"), file_text="x"
        ),
        LOW,
        "the path rule applies whatever the command is",
    ),
}

# A base class of the browser actions, not a tool a model can call.
_NOT_A_TOOL = {BrowserAction}


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


_BUILTIN_PREFIXES = ("openhands.tools.", "openhands.sdk.tool.builtins.")


def _defined_in_a_built_in_module(cls: type) -> bool:
    """True for a class that really is a module-level class of a built-in package.

    ``__module__`` is only a string: another test makes a class that claims a built-in
    module (and a function-local class has the module of the function). Such a class
    lingers in ``__subclasses__()`` until it is garbage collected, so a test run in
    the same process would see it or not depending on timing. The class must also be
    the one that module holds under that name, as ``is_builtin_action`` requires.
    """
    if not cls.__module__.startswith(_BUILTIN_PREFIXES):
        return False
    module = sys.modules.get(cls.__module__)
    return getattr(module, cls.__qualname__, None) is cls


def _builtin_action_classes() -> set[type[Action]]:
    """Every Action class the built-in packages define.

    Only the ``definition`` modules are imported: that is where the tools declare
    their Action classes, and some sibling modules (a POSIX-only terminal backend)
    cannot be imported everywhere.
    """
    for module in pkgutil.walk_packages(openhands.tools.__path__, "openhands.tools."):
        if module.name.endswith(".definition"):
            importlib.import_module(module.name)

    def subclasses(cls: type) -> set[type]:
        found: set[type] = set()
        for sub in cls.__subclasses__():
            found.add(sub)
            found |= subclasses(sub)
        return found

    return {cls for cls in subclasses(Action) if _defined_in_a_built_in_module(cls)}


@pytest.fixture
def workspace(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    (root / "a.txt").write_text("x")
    # Not the workspace, so a path judged against the cwd would be misjudged.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    return root


@pytest.fixture
def analyzer(workspace) -> RoyPathPayloadSecurityAnalyzer:
    return RoyPathPayloadSecurityAnalyzer(workspace_root=str(workspace))


def _in_workspace(workspace: Path) -> Path:
    return workspace / "a.txt"


# --- the table covers every built-in tool --------------------------------------


def test_every_built_in_action_class_has_exactly_one_row():
    """A new built-in tool must be looked at before it ships: without a row here
    it would silently fall to UNKNOWN (or to HIGH if it happens to have a field
    called ``command``) and nobody would have decided that."""
    in_table = [row.action_cls for row in _TABLE.values()]
    assert len(in_table) == len(set(in_table)), "two rows describe the same class"
    built_in = _builtin_action_classes() - _NOT_A_TOOL
    missing = sorted(cls.__qualname__ for cls in built_in - set(in_table))
    unknown = sorted(cls.__qualname__ for cls in set(in_table) - built_in)
    assert not missing, f"built-in Action class(es) with no row in _TABLE: {missing}"
    assert not unknown, f"row(s) for class(es) that are not built-in Actions: {unknown}"


def test_a_class_that_only_claims_a_built_in_module_is_not_a_built_in_action():
    """``__module__`` is a string anyone can set (another test does). Such a class
    must not make the completeness test depend on whether it has been garbage
    collected yet, so discovery counts only classes the module really holds."""

    class _Forged(Action):
        __module__ = "openhands.tools.imaginary.definition"

    forged = _Forged  # alive for the whole test, not left to the collector
    assert forged not in _builtin_action_classes()


def test_the_display_tables_and_the_risk_table_name_the_same_tools():
    """The agent-server only shows (and so can only approve) the tools its display
    tables list; the risk table is keyed by the same tool names. A name in one and
    not the other is either a tool nobody classified or a stale row."""
    display = set(_PATH_TOOLS) | set(_PROJECTORS) | set(_TOOL_ARGS)
    # finish and think are never shown for approval (the SDK does not ask for them).
    assert display | {"finish", "think"} == set(_TABLE)


def test_the_table_is_keyed_by_the_names_tools_really_register():
    """ActionEvent.tool_name is the name a tool registers under, which is not
    always what its Action class suggests (SwitchLLMAction -> switch_llm, the vision
    tool -> inspect_image_with_vision). A row under another name would never be
    consulted and its tool would be classified by the default instead."""
    _builtin_action_classes()  # imports the definition modules

    def tools(cls: type) -> set[type]:
        found: set[type] = set()
        for sub in cls.__subclasses__():
            found.add(sub)
            found |= tools(sub)
        return found

    registered = {
        cls.name
        for cls in tools(ToolDefinition)
        if _defined_in_a_built_in_module(cls)
        and isinstance(getattr(cls, "name", None), str)
        and not cls.name.endswith("_tool_set")
    }
    # delegate: an Action class and executor remain but no tool registers the name.
    assert registered == set(_TABLE) - {"delegate"}


# --- the table is what the analyzer does ---------------------------------------


@pytest.mark.parametrize("name", sorted(_TABLE))
def test_the_row_matches_what_the_analyzer_answers(analyzer, workspace, name):
    """The table records behaviour. If a rule changes, the rows that move must be
    edited on purpose, in the same change."""
    row = _TABLE[name]
    action = row.action_cls(**row.args(_in_workspace(workspace)))
    assert analyzer.security_risk(_event(name, action)) == row.expected, row.reason


@pytest.mark.parametrize("label", sorted(_VARIANTS))
def test_other_call_shapes_of_a_tool_are_pinned_too(analyzer, workspace, label):
    """One representative row cannot show that a path-less grep, or a glob pattern
    that climbs out, asks: those are separate answers and each is pinned."""
    variant = _VARIANTS[label]
    action = variant.action(_in_workspace(workspace))
    risk = analyzer.security_risk(_event(variant.tool_name, action))
    assert risk == variant.expected, variant.reason


def test_a_path_tool_asks_once_its_path_leaves_the_workspace(
    analyzer, workspace, tmp_path
):
    """LOW in the table means "inside the workspace", nothing wider (for the rows
    that are path tools; ``task_tracker`` is LOW for a different reason)."""
    outside = tmp_path / "outside.txt"
    outside.write_text("x")
    for name, row in _TABLE.items():
        if row.expected is not LOW or row.reason != _PATH:
            continue
        args = {
            key: str(outside) if key in {"path", "file_path", "dir_path"} else value
            for key, value in row.args(_in_workspace(workspace)).items()
        }
        risk = analyzer.security_risk(_event(name, row.action_cls(**args)))
        assert risk is HIGH, f"{name}: {risk}"


# --- MEDIUM is never an answer -------------------------------------------------


def test_the_governed_policy_does_not_ask_for_medium():
    """The fact the ban below rests on. If the SDK ever changes it, this fails and
    the ban (and the table) should be reconsidered together."""
    policy = ConfirmRisky()
    assert {risk.name: policy.should_confirm(risk) for risk in SecurityRisk} == {
        "UNKNOWN": True,
        "LOW": False,
        "MEDIUM": False,
        "HIGH": True,
    }


def test_the_analyzer_never_answers_medium(analyzer, workspace, tmp_path):
    """MEDIUM runs without asking anyone under the governed policy, so a tool
    judged "somewhat risky" must be HIGH or UNKNOWN, never MEDIUM."""
    answers = set()
    for name, row in _TABLE.items():
        action = row.action_cls(**row.args(_in_workspace(workspace)))
        answers.add(analyzer.security_risk(_event(name, action)))
    # Hostile and odd inputs, not only the representative ones.
    answers.add(analyzer.security_risk(_event("unheard_of", _ThirdParty(path="/x"))))
    answers.add(
        analyzer.security_risk(
            _event("glob", GlobAction(pattern="../*", path=str(workspace)))
        )
    )
    answers.add(
        analyzer.security_risk(
            _event("read_file", ReadFileAction(file_path=str(tmp_path / "out")))
        )
    )
    assert answers <= {LOW, HIGH, UNKNOWN}, answers
    # And a look at what security_risk() itself returns, because a branch the cases
    # above do not reach could still answer MEDIUM. Only its return statements are
    # read (not comments or unrelated constants); an alias or a helper that returns
    # it would slip past, so this is a tripwire, not a proof.
    source = textwrap.dedent(
        inspect.getsource(RoyPathPayloadSecurityAnalyzer.security_risk)
    )
    returned = [
        ast.unparse(node.value)
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Return) and node.value is not None
    ]
    assert returned, "found no return statements: the check needs updating"
    assert not [value for value in returned if value.endswith("MEDIUM")], returned


# --- a name is not an identity -------------------------------------------------


class _ThirdParty(Action):
    """What an MCP tool or plugin looks like: not from a built-in package, but with
    the field names the built-in path tools use."""

    path: str = ""
    file_path: str = ""
    dir_path: str = ""


@pytest.mark.parametrize("name", sorted(_TABLE))
def test_a_third_party_tool_cannot_borrow_a_built_in_tool_name(
    analyzer, workspace, name
):
    """The table is looked up by name, and a name is whatever the tool's author
    says. Calling itself ``read_file`` and pointing inside the workspace must not
    earn the built-in's LOW."""
    inside = str(_in_workspace(workspace))
    action = _ThirdParty(path=inside, file_path=inside, dir_path=str(workspace))
    assert analyzer.security_risk(_event(name, action)) is UNKNOWN


class _ThirdPartyWithCommand(Action):
    """A third-party tool that calls itself ``task_tracker`` and has the ``command``
    field the built-in has."""

    command: str = "view"


def test_a_third_party_task_tracker_is_not_relaxed(analyzer):
    """Only the built-in class earns LOW. A look-alike keeps the `command` rule."""
    risk = analyzer.security_risk(_event("task_tracker", _ThirdPartyWithCommand()))
    assert risk is HIGH


def test_only_grep_and_glob_are_relaxed_when_they_have_no_path():
    """A tool whose path is required cannot show this in a call, so the set itself
    is pinned: adding a tool here means its path-less form searches the workspace,
    and that has to be read in the tool's code first."""
    from openhands.sdk.security.roy_governance import _SEARCHES_WORKSPACE_WHEN_PATHLESS

    assert _SEARCHES_WORKSPACE_WHEN_PATHLESS == {"grep", "glob"}
