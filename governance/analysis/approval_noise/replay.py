"""Replay Claude Code tool calls through the real RoyPath analyzer and write only
de-identified features (see mapping.md and standard.md in this directory).

Run with the SDK's own Python (the one that can import ``openhands.sdk``):

    python replay.py --projects ~/.claude/projects --days 30 --out out

Nothing here writes a path, a command line, a pattern or any file content. The
analyzer is called in this process on the real strings, and the features a labeller
needs ("is the target outside the workspace", "does it send data out", "is it a
delete") are computed here too, from the full command, and written as booleans,
counts or words from a small fixed vocabulary. The output directory stays on this
machine.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


# Claude Code tools with a counterpart in OpenHands (mapping.md).
_FILE_TOOLS = {
    "Read": ("view", "file_path"),
    "Edit": ("str_replace", "file_path"),
    "Write": ("create", "file_path"),
    "NotebookEdit": ("str_replace", "notebook_path"),
}
_TASK_VIEW = {"TaskList", "TaskGet"}
_TASK_PLAN = {"TaskCreate", "TaskUpdate", "TodoWrite"}

# The only command words that are ever written out. Fixed in advance (not taken from
# the data): a word that is not here is written as "other", so a script name, an
# argument or a fragment of a quoted string can never reach the output.
_COMMANDS = frozenset(
    """
    cd ls dir cat type head tail less more echo printf pwd cp mv rm del rmdir mkdir
    touch find grep rg sed awk sort uniq wc diff tee xargs cut tr which where whoami
    env export set source test true false sleep date time chmod chown ln stat du df
    python python3 py pip pip3 uv pytest ruff pyright mypy black node npm npx pnpm
    yarn tsc vitest eslint prettier cargo rustc go make cmake java javac mvn gradle
    git gh docker kubectl gcloud az aws terraform curl wget ssh scp rsync tar zip
    unzip gzip 7z powershell pwsh cmd bash sh zsh start explorer taskkill tasklist
    netstat sqlite3 psql pg_ctl initdb createdb jq codex claude nlm ffmpeg ffprobe
    yt-dlp whisper-cli apt apt-get brew winget conda poetry
    """.split()
)
# Tools whose second word says what the command does, and the ones worth writing out.
_SUBCOMMANDS = {
    "git": "status diff log add commit push pull fetch checkout branch merge rebase "
    "reset clean stash remote clone tag show restore switch worktree rm mv init config "
    "cherry-pick revert blame grep ls-remote rev-parse".split(),
    "npm": "install i ci run test publish start build uninstall update audit".split(),
    "pnpm": "install add run test publish build".split(),
    "yarn": "install add run test publish build".split(),
    "pip": "install uninstall list show freeze download".split(),
    "pip3": "install uninstall list show freeze download".split(),
    "uv": "run pip sync add remove lock venv".split(),
    "docker": "run build ps compose push pull exec rm rmi stop start logs".split(),
    "gh": "pr issue repo api run workflow release auth".split(),
    "cargo": "build run test install publish check".split(),
    "kubectl": "get apply delete describe logs exec".split(),
    "gcloud": "compute run functions storage auth config".split(),
    "apt": "install remove update upgrade".split(),
    "apt-get": "install remove update upgrade".split(),
    "brew": "install uninstall update upgrade".split(),
    "winget": "install uninstall upgrade".split(),
    "conda": "install create activate env remove".split(),
    "poetry": "install add run publish build".split(),
}  # fmt: skip

# What a head does (standard.md), by fixed vocabulary.
_READ_HEADS = frozenset(
    "cat type head tail less more ls dir find grep rg wc sort uniq diff cut tr stat du "
    "df which where whoami date pwd echo printf env jq tasklist netstat test true "
    "false sleep cd".split()
)
_WRITE_HEADS = frozenset("cp mv mkdir touch tee chmod chown ln sed awk".split())
_DELETE_HEADS = frozenset("rm del rmdir".split())
_RUNNER_BASES = frozenset(
    "pytest ruff pyright mypy black tsc vitest eslint prettier".split()
)
_RUNNER_HEADS = frozenset(["npm test", "npm run", "cargo test", "cargo build", "make"])
_EXEC_BASES = frozenset(
    "python python3 py node bash sh zsh powershell pwsh cmd".split()
)
_VCS_READ = frozenset(
    "git status|git diff|git log|git show|git blame|git grep|git branch|"
    "git rev-parse|git ls-remote".split("|")
)
_VCS_WRITE = frozenset(
    "git add|git commit|git checkout|git reset|git clean|git stash|git merge|"
    "git rebase|git restore|git switch|git cherry-pick|git revert|git tag|git init|"
    "git config|git worktree|git rm|git mv".split("|")
)
_VCS_REMOTE = frozenset(
    ["git push", "git pull", "git fetch", "git clone", "git remote"]
)
_INSTALL = frozenset(
    "pip install|pip3 install|npm install|npm i|npm ci|pnpm install|pnpm add|"
    "yarn install|yarn add|apt install|apt-get install|brew install|winget install|"
    "cargo install|uv add|uv sync|uv pip|conda install|poetry install|poetry add".split(
        "|"
    )
)
# Command wrappers whose next word is the real command.
_WRAPPERS = frozenset("env sudo time nohup call".split())
# Heads whose non-flag arguments are file operands (a bare name like file.txt counts).
_FILE_OPERAND_HEADS = frozenset(
    "rm del rmdir mkdir touch cp mv cat type head tail less more ls dir find grep rg "
    "wc sort uniq diff cut tee chmod chown ln stat du df tar zip unzip gzip 7z sed awk "
    "python python3 py node bash sh zsh powershell pwsh pytest ruff pyright mypy black "
    "tsc vitest eslint prettier jq".split()
)
_REMOTE_STATE_HEADS = frozenset(
    "psql sqlite3 aws az gcloud kubectl terraform docker createdb initdb pg_ctl".split()
)
_SHELL_HEADS = frozenset("bash sh zsh powershell pwsh cmd".split())
_INLINE_CODE_FLAGS = frozenset(["-c", "/c", "-e", "-command", "-encodedcommand"])
# Tool names that may be written out as they are (Claude Code's own tools, and the MCP
# servers named here). Anything else is written as "other_tool" / "mcp__other".
_KNOWN_TOOLS = frozenset(
    """
    Read Edit Write NotebookEdit Grep Glob Bash TaskCreate TaskUpdate TaskList TaskGet
    TaskStop TaskOutput TodoWrite WebSearch WebFetch Skill ToolSearch Agent
    AskUserQuestion ExitPlanMode EnterPlanMode SendMessage Monitor ScheduleWakeup
    CronCreate CronDelete CronList
    """.split()
)
_KNOWN_MCP_SERVERS = frozenset(
    """
    claude-in-chrome computer-use scheduled-tasks pdf-viewer ccd_session ccd_turn
    ccd_directory ccd_host ccd_pr ccd_settings ccd_sidebar ccd_view ccd_window
    ccd_session_mgmt ccd_connectors terminal Claude_Browser visualize mcp-registry
    """.split()
)
_TOOL_PART = re.compile(r"^[A-Za-z0-9_-]{1,50}$")
_FLAG_WHITELIST = frozenset(
    ["-rf", "-fr", "-f", "--force", "--hard", "-X", "-d", "--delete", "--no-verify"]
)
_UPLOAD_FLAGS = frozenset(
    "-d --data --data-raw --data-binary -F --form -T --upload-file --post-data "
    "--post-file".split()
)
_WRITE_METHODS = frozenset(["POST", "PUT", "DELETE", "PATCH"])
_UPLOAD_PREFIXES = (
    "--data=", "--data-raw=", "--data-binary=", "--form=", "--upload-file=",
    "--post-data=", "--post-file=",
)  # fmt: skip
_SECRET_PATH = re.compile(
    r"(^|[\\/])(\.ssh|\.aws|\.gnupg|\.netrc|\.npmrc|\.pypirc|id_rsa|id_ed25519|"
    r"credentials|\.env[^\\/]*)([\\/]|$)",
    re.IGNORECASE,
)
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
MAX_HEADS = 4


def scan_command(command: str) -> tuple[list[str], int, bool, bool, list[str]]:
    """Split a shell command line into its segments, looking only outside quotes.
    Returns (segments, pipes, chained, redirect, redirect_targets). Everything from
    the first heredoc marker on is ignored: a heredoc body is content, not commands."""
    segments: list[str] = []
    current: list[str] = []
    targets: list[str] = []
    quote = ""
    pipes = 0
    chained = False
    redirect = False
    i = 0
    n = len(command)
    while i < n:
        c = command[i]
        if quote:
            current.append(c)
            if c == quote:
                quote = ""
            i += 1
            continue
        if c in "\"'":
            quote = c
            current.append(c)
        elif command.startswith("<<", i):
            # a heredoc body is content: skip it up to its delimiter line, and go on
            # with whatever follows (more commands can).
            m = re.match(r"<<-?\s*['\"]?([A-Za-z0-9_]+)['\"]?", command[i:])
            if m is None:
                break
            end = re.search(
                r"(?m)^\s*" + re.escape(m.group(1)) + r"\s*$", command[i + m.end() :]
            )
            if end is None:
                break
            i += m.end() + end.end()
            continue
        elif command.startswith("&&", i) or command.startswith("||", i):
            chained = True
            segments.append("".join(current))
            current = []
            i += 2
            continue
        elif c in ";\n":
            chained = chained or c == ";"
            segments.append("".join(current))
            current = []
        elif c == "|":
            pipes += 1
            segments.append("".join(current))
            current = []
        elif c == ">":
            redirect = True
            j = i + 1
            while j < n and command[j] in ">&":
                j += 1
            m = re.match(r"\s*([^\s;|&]+)", command[j:])
            if m and not m.group(1).lower().startswith(("&", "/dev/null", "nul")):
                targets.append(m.group(1).strip("\"'"))
            current.append(c)
        else:
            current.append(c)
        i += 1
    segments.append("".join(current))
    return segments, pipes, chained, redirect, targets


def _tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment, posix=False)
    except ValueError:
        return segment.split()


def _word(token: str) -> str:
    word = re.split(r"[\\/]", token)[-1].lower()
    return word[:-4] if word.endswith(".exe") else word


def _strip_wrappers(tokens: list[str]) -> list[str]:
    """Drop `env`/`sudo`/`time`/`nohup` (and the NAME=value words after `env`) so the
    real command is first."""
    while tokens:
        if _ENV_ASSIGNMENT.match(tokens[0]):
            tokens = tokens[1:]
        elif _word(tokens[0]) in _WRAPPERS:
            tokens = tokens[1:]
        else:
            break
    return tokens


def _subcommand(word: str, tokens: list[str]) -> str | None:
    """The first non-option word after the command (git's -C <dir> and -c <k=v> take
    an argument; other options do not)."""
    rest = tokens[1:]
    i = 0
    while i < len(rest):
        t = rest[i]
        if word == "git" and t in ("-C", "-c"):
            i += 2
        elif t.startswith("-"):
            i += 1
        else:
            return t
    return None


def _head(tokens: list[str]) -> str:
    word = _word(tokens[0])
    if word not in _COMMANDS:
        return "other"
    subs = _SUBCOMMANDS.get(word)
    if subs is not None:
        sub = _subcommand(word, tokens)
        if sub is not None:
            return f"{word} {sub.lower()}" if sub.lower() in subs else f"{word} other"
    return word


def _looks_like_path(token: str) -> bool:
    token = token.strip("\"'")
    if not token or token.startswith(("-", "http://", "https://")):
        return False
    return (
        "/" in token
        or "\\" in token
        or token.startswith("~")
        or bool(_DRIVE.match(token))
    )


def _normal(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def _resolve(token: str, cwd: str | None) -> str | None:
    token = os.path.expanduser(token.strip("\"'"))
    if not os.path.isabs(token):
        if cwd is None:
            return None
        token = os.path.join(cwd, token)
    return _normal(token)


def inside(path: str, root: str) -> bool:
    """Whether ``path`` is ``root`` or below it (both are normalised here)."""
    path, root = _normal(path), _normal(root)
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # different drives
        return False


def cwd_class(cwd: str | None) -> str:
    """ "broad" when the session started at the home directory (or higher), where the
    workspace is almost the whole disk and "inside the workspace" says little."""
    if cwd is None or not os.path.isabs(cwd):
        return "unknown"
    norm = _normal(cwd)
    home = _normal(os.path.expanduser("~"))
    # the home directory itself or anything above it (a parent of home, the drive root)
    return "broad" if inside(home, norm) else "project"


def _opaque(command: str, tokens_by_segment: list[list[str]]) -> bool:
    """True when part of what the command runs is not visible in its text: command
    substitution, a nested shell or interpreter given code, `xargs`/`eval`, or
    `find -exec`. Such a command is not understood, and says so."""
    if "`" in command or "$(" in command:
        return True
    for tokens in tokens_by_segment:
        if not tokens:
            continue
        word = _word(tokens[0])
        lowered = {t.lower().strip("\"'") for t in tokens[1:]}
        if word in ("xargs", "eval"):
            return True
        if word == "find" and ("-exec" in lowered or "-execdir" in lowered):
            return True
        if word in _SHELL_HEADS | {"python", "python3", "py", "node"} and (
            lowered & _INLINE_CODE_FLAGS
        ):
            return True
    return False


def bash_features(command: str, cwd: str | None) -> dict[str, Any]:
    """What a Bash command does, without what it says (standard.md, mapping.md)."""
    segments, pipes, chained, redirect, targets = scan_command(command)
    heads: list[str] = []
    ops: set[str] = set()
    flags: set[str] = set()
    n_in = n_out = n_unresolved = 0
    secret = sends = pipe_to_shell = False
    previous_base = ""
    parsed: list[list[str]] = []
    for segment in segments:
        tokens = _strip_wrappers([t for t in _tokens(segment.strip()) if t])
        parsed.append(tokens)
        if not tokens:
            continue
        head = _head(tokens)
        base = head.split()[0]
        heads.append(head)
        flags.update(t for t in tokens if t in _FLAG_WHITELIST)
        seg: set[str] = set()
        if head in _VCS_READ or base in _READ_HEADS:
            seg.add("read")
        if base in _WRITE_HEADS:
            seg.add("write")
        if base in _DELETE_HEADS:
            seg.add("delete")
        if base in _RUNNER_BASES or head in _RUNNER_HEADS:
            seg.add("runner")
        if base in _EXEC_BASES:
            seg.add("exec_script")
        if head in _VCS_READ:
            seg.add("vcs_read")
        if head in _VCS_WRITE:
            seg.add("vcs_write")
        if head in _VCS_REMOTE or base == "gh":
            seg.add("vcs_remote")
        if head in _INSTALL:
            seg.add("install")
        if base in ("curl", "wget"):
            seg.add("network_fetch")
            words = {t.upper().strip("\"'") for t in tokens[1:]}
            lowered = [t.lower() for t in tokens[1:]]
            if (
                any(t in _UPLOAD_FLAGS for t in tokens)
                or any(t.startswith(_UPLOAD_PREFIXES) for t in lowered)
                or words & _WRITE_METHODS
                or any(
                    t[2:].upper() in _WRITE_METHODS
                    for t in tokens
                    if t.startswith("-X")
                )
                or any(
                    t.split("=", 1)[-1].upper() in _WRITE_METHODS
                    for t in lowered
                    if t.startswith("--request=")
                )
            ):
                sends = True
        if base in ("scp", "rsync"):
            seg.add("network_send")
        if base == "ssh":
            seg.add("remote_exec")
        if base in ("taskkill", "start", "explorer"):
            seg.add("process")
        if base in _REMOTE_STATE_HEADS:
            seg.add("remote_state")
        if head == "git push":
            sends = True
        if head == "other":
            seg.add("other")
        if not seg:  # a word that fits no class above: say so (per segment)
            seg.add("other")
        ops |= seg
        if previous_base in ("curl", "wget") and base in _EXEC_BASES:
            pipe_to_shell = True
        previous_base = base
        operands = tokens[1:] if base in _FILE_OPERAND_HEADS else []
        for token in tokens[1:]:
            if _looks_like_path(token) or (
                token in operands and not token.startswith("-") and "=" not in token
            ):
                if _SECRET_PATH.search(token):
                    secret = True
                resolved = _resolve(token, cwd)
                if resolved is None or cwd is None:
                    n_unresolved += 1
                elif inside(resolved, cwd):
                    n_in += 1
                else:
                    n_out += 1
    redirect_out = redirect_unresolved = False
    for target in targets:
        if _SECRET_PATH.search(target):
            secret = True
        if "$" in target or "%" in target or "`" in target:
            redirect_unresolved = True
            continue
        resolved = _resolve(target, cwd)
        if resolved is None or cwd is None:
            redirect_unresolved = True
        elif not inside(resolved, cwd):
            redirect_out = True
    if redirect:
        ops.add("write")
    if pipe_to_shell:
        ops.add("exec_script")
    return {
        "heads": heads[:MAX_HEADS],
        "n_heads": len(heads),
        "ops": sorted(ops),
        "flags": sorted(flags),
        "pipes": pipes,
        "chained": chained,
        "redirect": redirect,
        "redirect_outside_cwd": redirect_out,
        "redirect_unresolved": redirect_unresolved,
        "paths_inside_cwd": n_in,
        "paths_outside_cwd": n_out,
        "paths_unresolved": n_unresolved,
        "secret_path": secret,
        "has_url": bool(re.search(r"https?://", command)),
        "sends_data": sends,
        "pipe_to_shell": pipe_to_shell,
        "opaque": _opaque(command, parsed),
    }


def transcript_files(projects: Path) -> list[Path]:
    """Every session transcript under the projects directory, including the nested
    ones a sub-agent writes (``<project>/<session>/subagents/*.jsonl``). The first
    version read only the top level and so missed those; a reviewer's question about
    coverage found it."""
    return sorted(p for p in projects.rglob("*.jsonl") if p.is_file())


def iter_tool_uses(path: Path, counters: dict[str, int]) -> Iterator[dict[str, Any]]:
    """The tool calls in one transcript, with the record's own time and cwd."""
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            counters["lines"] += 1
            try:
                record = json.loads(line)
            except ValueError:
                counters["parse_failures"] += 1
                continue
            content = (record.get("message") or {}).get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    yield {
                        "id": block.get("id"),
                        "name": block.get("name"),
                        "input": block.get("input") or {},
                        "cwd": record.get("cwd"),
                        "ts": record.get("timestamp"),
                        "session": record.get("sessionId") or path.stem,
                    }


def public_tool_name(name: Any) -> str:
    """The tool name as it may be written out: Claude Code's own tools and MCP servers
    from a fixed list only (a server or tool name is otherwise someone's choice of
    words and may carry a project or organisation name)."""
    if not isinstance(name, str):
        return "other_tool"
    if name in _KNOWN_TOOLS:
        return name
    if name.startswith("mcp__"):
        parts = name.split("__", 2)
        if (
            len(parts) == 3
            and parts[1] in _KNOWN_MCP_SERVERS
            and _TOOL_PART.match(parts[2])
        ):
            return name
        return "mcp__other"
    return "other_tool"


def parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class Replayer:
    """Builds the analyzer's input for a mapped call and asks the real analyzer."""

    def __init__(self) -> None:
        from litellm import ChatCompletionMessageToolCall
        from litellm.types.utils import Function

        from openhands.sdk.event import ActionEvent
        from openhands.sdk.llm import MessageToolCall, TextContent
        from openhands.sdk.security.confirmation_policy import ConfirmRisky
        from openhands.sdk.security.roy_governance import (
            RoyPathPayloadSecurityAnalyzer,
            _pattern_may_leave_path,
        )
        from openhands.sdk.tool.schema import Action
        from openhands.tools.file_editor.definition import FileEditorAction
        from openhands.tools.glob.definition import GlobAction
        from openhands.tools.grep.definition import GrepAction
        from openhands.tools.task_tracker.definition import TaskTrackerAction
        from openhands.tools.terminal.definition import TerminalAction

        class ThirdPartyAction(Action):
            """Stands for an MCP tool: defined outside the built-in packages."""

            note: str = "x"

        self._classes = {
            "file_editor": FileEditorAction,
            "grep": GrepAction,
            "glob": GlobAction,
            "terminal": TerminalAction,
            "task_tracker": TaskTrackerAction,
            "mcp_tool": ThirdPartyAction,
        }
        self._ActionEvent = ActionEvent
        self._call = ChatCompletionMessageToolCall
        self._function = Function
        self._tool_call = MessageToolCall
        self._text = TextContent
        self._analyzer_cls = RoyPathPayloadSecurityAnalyzer
        self._analyzers: dict[str, Any] = {}
        self._policy = ConfirmRisky()
        self.pattern_may_leave_path = _pattern_may_leave_path

    def _event(
        self, tool: str, fields: dict[str, Any], tool_name: str | None = None
    ) -> Any:
        """``tool_name`` is what the analyzer sees as the tool (an MCP tool's own name,
        which the department permission check looks at); built-ins use their own."""
        name = tool_name or tool
        action = self._classes[tool](**fields)
        call = self._call(
            id="c", type="function", function=self._function(name=name, arguments="{}")
        )
        return self._ActionEvent(
            source="agent",
            thought=[self._text(text="t")],
            action=action,
            tool_name=name,
            tool_call_id="c",
            tool_call=self._tool_call.from_chat_tool_call(call),
            llm_response_id="r",
        )

    def in_workspace(self, path: str, workspace: str) -> bool:
        """The analyzer's own containment check (it resolves links), so the feature
        a labeller sees agrees with the verdict."""
        return self._analyzer_for(workspace)._is_in_workspace(
            path, relative_to_workspace=False
        )

    def _analyzer_for(self, workspace: str) -> Any:
        analyzer = self._analyzers.get(workspace)
        if analyzer is None:
            analyzer = self._analyzer_cls(workspace_root=workspace)
            self._analyzers[workspace] = analyzer
        return analyzer

    def verdict(
        self,
        tool: str,
        fields: dict[str, Any],
        workspace: str,
        tool_name: str | None = None,
    ) -> tuple[str, bool]:
        risk = self._analyzer_for(workspace).security_risk(
            self._event(tool, fields, tool_name)
        )
        return risk.name, self._policy.should_confirm(risk)


def absolutise(path: Any, cwd: str | None) -> str | None:
    """A path as the OpenHands tools require it (absolute): a relative one is read
    against the cwd of the very record it came from. None if it cannot be."""
    if not isinstance(path, str) or not path:
        return None
    path = os.path.expanduser(path)
    if os.path.isabs(path):
        return path
    return os.path.join(cwd, path) if cwd else None


def map_call(
    name: Any, tool_input: dict[str, Any], cwd: str | None
) -> tuple[str | None, dict[str, Any], str]:
    """(OpenHands tool, its fields, category). category: mapped | mcp | no_mapping |
    malformed | unresolved. Only ``mapped`` and ``mcp`` have a tool."""
    if name in _FILE_TOOLS:
        command, field = _FILE_TOOLS[name]
        raw = tool_input.get(field)
        if not isinstance(raw, str) or not raw:
            return None, {}, "malformed"
        path = absolutise(raw, cwd)
        if path is None:
            return None, {}, "unresolved"
        return "file_editor", {"command": command, "path": path}, "mapped"
    if name in ("Grep", "Glob"):
        raw = tool_input.get("path")
        path = None
        if isinstance(raw, str) and raw:
            path = absolutise(raw, cwd)
            if path is None:
                return None, {}, "unresolved"
        if name == "Grep":
            return "grep", {"pattern": "x", "path": path}, "mapped"
        pattern = tool_input.get("pattern")
        if not isinstance(pattern, str):
            return None, {}, "malformed"
        return "glob", {"pattern": pattern, "path": path}, "mapped"
    if name == "Bash":
        command = tool_input.get("command")
        if not isinstance(command, str):
            return None, {}, "malformed"
        return "terminal", {"command": command}, "mapped"
    if name in _TASK_VIEW:
        return "task_tracker", {"command": "view"}, "mapped"
    if name in _TASK_PLAN:
        return "task_tracker", {"command": "plan"}, "mapped"
    if isinstance(name, str) and name.startswith("mcp__"):
        return "mcp_tool", {}, "mcp"
    return None, {}, "no_mapping"


def file_features(
    replayer: Replayer, tool: str, fields: dict[str, Any], cwd: str | None
) -> dict[str, Any]:
    path = fields.get("path")
    features: dict[str, Any] = {"path_given": path is not None}
    if tool == "file_editor":
        features["file_cmd"] = fields["command"]
    if path is not None:
        if cwd is None:
            features["workspace_relation"] = "unknown"
        else:
            features["workspace_relation"] = (
                "inside" if replayer.in_workspace(path, cwd) else "outside"
            )
        features["secret_path"] = bool(_SECRET_PATH.search(path))
    if tool == "glob":
        features["pattern_leaves_path"] = bool(
            replayer.pattern_may_leave_path(fields.get("pattern"))
        )
    return features


def process_file(
    path: Path,
    replayer: Replayer,
    seen_ids: set[str],
    since: datetime,
    counters: dict[str, int],
    first_index: int,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for call in iter_tool_uses(path, counters):
        ts = parse_ts(call["ts"])
        if ts is None or ts < since:
            counters["outside_window_or_no_time"] += 1
            continue
        call_id = call["id"]
        if isinstance(call_id, str):
            if call_id in seen_ids:
                counters["duplicates"] += 1
                continue
            seen_ids.add(call_id)
        counters["tool_uses"] += 1
        raw_cwd = call["cwd"]
        cwd = raw_cwd if isinstance(raw_cwd, str) and os.path.isabs(raw_cwd) else None
        tool, fields, category = map_call(call["name"], call["input"], cwd)
        name = public_tool_name(call["name"])
        record: dict[str, Any] = {
            "i": first_index + len(out),
            "day": ts.strftime("%Y-%m-%d"),
            "sess": hashlib.sha256(str(call["session"]).encode()).hexdigest()[:8],
            # a tool name (including an MCP server and tool name) is configuration,
            # not content
            "cc_tool": name,
            "category": category,
            "mapped": tool,
            "cwd_class": cwd_class(cwd),
        }
        if tool is None:
            counters[category] += 1
            out.append(record)
            continue
        if tool == "mcp_tool":
            counters["mcp"] += 1
        if tool == "terminal":
            record["shape"] = bash_features(fields["command"], cwd)
            root = "C:/"
        elif tool in ("file_editor", "grep", "glob"):
            record["shape"] = file_features(replayer, tool, fields, cwd)
            root = cwd or ""
        else:
            record["shape"] = {}
            root = "C:/"
        if tool in ("file_editor", "grep", "glob") and cwd is None:
            record["risk"], record["confirm"] = None, None
            counters["no_cwd"] += 1
        else:
            record["risk"], record["confirm"] = replayer.verdict(
                tool,
                fields,
                root,
                call["name"]
                if tool == "mcp_tool" and isinstance(call["name"], str)
                else None,
            )
        out.append(record)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--projects", required=True, help="Claude Code projects directory"
    )
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--out", required=True, help="output directory (stay local)")
    parser.add_argument(
        "--limit-files", type=int, default=0, help="0 = all (for timing)"
    )
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    files = transcript_files(Path(args.projects).expanduser())
    if args.limit_files:
        files = files[: args.limit_files]
    since = datetime.now(UTC) - timedelta(days=args.days)
    counters = {
        k: 0
        for k in (
            "lines", "parse_failures", "tool_uses", "duplicates",
            "outside_window_or_no_time", "no_mapping", "malformed", "unresolved",
            "mcp", "no_cwd",
        )
    }  # fmt: skip
    counters["files"] = len(files)
    root = Path(args.projects).expanduser()
    counters["nested_files"] = sum(
        1 for f in files if len(f.relative_to(root).parts) > 2
    )
    replayer = Replayer()
    seen: set[str] = set()
    index = 0
    with (out_dir / "actions.jsonl").open("w", encoding="utf-8") as sink:
        for n, file in enumerate(files, 1):
            rows = process_file(file, replayer, seen, since, counters, index)
            index += len(rows)
            for row in rows:
                sink.write(json.dumps(row, ensure_ascii=True) + "\n")
            if n % 50 == 0:
                sink.flush()
                print(f"{n}/{len(files)} files, {index} actions", file=sys.stderr)
    counters["window_days"] = args.days
    (out_dir / "summary.json").write_text(
        json.dumps(counters, indent=2), encoding="utf-8"
    )
    print(json.dumps(counters))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
