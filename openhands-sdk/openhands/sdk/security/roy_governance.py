"""Roy 的自訂治理層,對應 dsh-plugin-mc-embedded 的 roles/preexecute 模組。

註冊為 SecurityAnalyzerBase 的具體子類,可透過 agent-server 的
POST /{conversation_id}/security_analyzer REST endpoint 選用
(SecurityAnalyzerBase 是 DiscriminatedUnionMixin,靠 class 名稱 discriminate)。
"""

from __future__ import annotations

import os
import re
import sys

from openhands.sdk.event.llm_convertible import ActionEvent
from openhands.sdk.security.analyzer import SecurityAnalyzerBase
from openhands.sdk.security.risk import SecurityRisk
from openhands.sdk.security.roy_tool_permissions import is_permitted


DEFAULT_WORKSPACE_ROOT = os.environ.get(
    "ROY_GOVERNANCE_WORKSPACE_ROOT",
    os.path.join(os.path.expanduser("~"), "openhands-governance", "poc", "test-workspace"),
)

# Built-in tools whose single path argument decides the risk, keyed by the tool's
# name. Value: (name of the path field, whether a relative path is resolved
# against the workspace by the tool itself).
#
# The second flag mirrors each tool's own executor, so the analyzer judges the
# file the tool will really touch: the gemini tools join a relative path onto
# the workspace root, while file_editor / grep / glob resolve it against the
# server process's cwd (file_editor refuses a relative path outright).
#
# A path-less call (grep/glob without ``path``) is not listed as safe: glob
# may take a directory out of its pattern, so it stays UNKNOWN (= approval).
_PATH_TOOLS: dict[str, tuple[str, bool]] = {
    "file_editor": ("path", False),
    "planning_file_editor": ("path", False),
    "grep": ("path", False),
    "glob": ("path", False),
    "read_file": ("file_path", True),
    "write_file": ("file_path", True),
    "edit": ("file_path", True),
    "list_directory": ("dir_path", True),
}

# glob takes a second argument that can name a directory by itself: the Python
# fallback backend evaluates ``pattern`` as written, so ``../outside/*`` or an
# absolute pattern reaches files outside ``path``. A ``path`` inside the
# workspace therefore proves nothing unless the pattern stays inside it too.
_PATTERN_FIELD_BY_TOOL = {"glob": "pattern"}
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


def _pattern_may_leave_path(pattern: object) -> bool:
    """True when ``pattern`` is absolute, home-relative, drive-qualified or
    contains a ``..`` component — anything that is not strictly below the
    directory it is searched in."""
    if not isinstance(pattern, str):
        return True
    normalized = pattern.replace("\\", "/")
    return (
        normalized.startswith(("/", "~"))
        or bool(_DRIVE_PREFIX.match(normalized))
        or ".." in normalized.split("/")
    )


# A tool is "built-in" only if its Action class comes from these packages. The
# tool name alone is not enough: a third-party tool (an MCP server's, a plugin's)
# can be called ``file_editor`` or have a field named ``path``, and treating it
# like the built-in would make a path inside the workspace mean "no approval".
_BUILTIN_ACTION_MODULE_PREFIXES = ("openhands.tools.", "openhands.sdk.tool.builtins.")


def is_builtin_action(act: object) -> bool:
    """True if ``act`` is an instance of an Action class defined by a built-in
    package. ``__module__`` alone is just a string a class can set to anything,
    so the class must also be the one registered under that name in
    ``sys.modules``: an MCP tool's dynamically built class, or one that merely
    claims a built-in module name, is not. (Code that can register a module
    under a built-in name already runs inside this process; this keeps a
    third-party tool from borrowing trust, it is not a sandbox.)"""
    cls = type(act)
    if not cls.__module__.startswith(_BUILTIN_ACTION_MODULE_PREFIXES):
        return False
    module = sys.modules.get(cls.__module__)
    return getattr(module, cls.__qualname__, None) is cls


class RoyPathPayloadSecurityAnalyzer(SecurityAnalyzerBase):
    """對應 dsh-authz-roles 的 pathWithin payload matcher + preexecute 的
    riskTier 判定,合併成單一 security_risk() 決策。

    依「工具身分」而非「欄位名稱」分流:

    - 內建檔案/搜尋工具(``_PATH_TOOLS``)的路徑在工作區內 -> LOW(免核准)
    - 同上,路徑在工作區外 -> HIGH(需核准)
    - 同上,但沒給路徑(grep/glob 不帶 path)-> UNKNOWN(需核准)
    - glob 的 pattern 可跳出 path(絕對路徑、``~``、磁碟機代號、``..``)-> UNKNOWN
    - 任何有 ``command`` 欄位的動作(TerminalAction 等)-> HIGH
      (比照 dsh bash/pwsh 一律問;只會更嚴格,所以不限工具身分)
    - 其餘一律 UNKNOWN(需核准),**包含第三方/MCP 工具**,不論它有沒有叫
      ``path`` 的欄位——工具叫什麼、欄位叫什麼都是對方說了算,不能當作
      「這個動作無害」的依據
    """

    workspace_root: str = DEFAULT_WORKSPACE_ROOT

    def _is_in_workspace(self, path: str, *, relative_to_workspace: bool) -> bool:
        if relative_to_workspace and not os.path.isabs(path):
            path = os.path.join(self.workspace_root, path)
        resolved = os.path.realpath(path)
        root = os.path.realpath(self.workspace_root)
        try:
            return os.path.commonpath([resolved, root]) == root
        except ValueError:
            return False

    def security_risk(self, action: ActionEvent) -> SecurityRisk:
        # Department tool permissions (team mode only; a no-op otherwise): a
        # tool the department may not use always needs confirmation, however
        # harmless the path looks, so it reaches the refusal in
        # EventService._create_governance_approval() instead of running as
        # a low-risk action that never asks anyone.
        if not is_permitted(action.tool_name):
            return SecurityRisk.HIGH

        act = action.action

        spec = _PATH_TOOLS.get(action.tool_name)
        if spec is not None and is_builtin_action(act):
            field, relative_to_workspace = spec
            path = getattr(act, field, None)
            pattern_field = _PATTERN_FIELD_BY_TOOL.get(action.tool_name)
            if pattern_field and _pattern_may_leave_path(
                getattr(act, pattern_field, None)
            ):
                return SecurityRisk.UNKNOWN
            if isinstance(path, str) and path:
                in_workspace = self._is_in_workspace(
                    path, relative_to_workspace=relative_to_workspace
                )
                return SecurityRisk.LOW if in_workspace else SecurityRisk.HIGH
            return SecurityRisk.UNKNOWN

        if getattr(act, "command", None) is not None:
            return SecurityRisk.HIGH

        return SecurityRisk.UNKNOWN
