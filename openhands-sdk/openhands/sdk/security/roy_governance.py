"""Roy 的自訂治理層,對應 dsh-plugin-mc-embedded 的 roles/preexecute 模組。

註冊為 SecurityAnalyzerBase 的具體子類,可透過 agent-server 的
POST /{conversation_id}/security_analyzer REST endpoint 選用
(SecurityAnalyzerBase 是 DiscriminatedUnionMixin,靠 class 名稱 discriminate)。
"""

from __future__ import annotations

import os

from openhands.sdk.event.llm_convertible import ActionEvent
from openhands.sdk.security.analyzer import SecurityAnalyzerBase
from openhands.sdk.security.risk import SecurityRisk


DEFAULT_WORKSPACE_ROOT = os.environ.get(
    "ROY_GOVERNANCE_WORKSPACE_ROOT",
    os.path.join(os.path.expanduser("~"), "openhands-governance", "poc", "test-workspace"),
)


class RoyPathPayloadSecurityAnalyzer(SecurityAnalyzerBase):
    """對應 dsh-authz-roles 的 pathWithin payload matcher + preexecute 的
    riskTier 判定,合併成單一 security_risk() 決策。

    - FileEditorAction.path 在工作區內 -> LOW(免核准)
    - FileEditorAction.path 在工作區外 -> HIGH(需核准)
    - TerminalAction(任何 command)     -> HIGH(比照 dsh bash/pwsh 一律問)
    """

    workspace_root: str = DEFAULT_WORKSPACE_ROOT

    def security_risk(self, action: ActionEvent) -> SecurityRisk:
        act = action.action
        path = getattr(act, "path", None)
        if path is not None:
            resolved = os.path.realpath(path)
            root = os.path.realpath(self.workspace_root)
            try:
                in_workspace = os.path.commonpath([resolved, root]) == root
            except ValueError:
                in_workspace = False
            return SecurityRisk.LOW if in_workspace else SecurityRisk.HIGH

        if getattr(act, "command", None) is not None:
            return SecurityRisk.HIGH

        return SecurityRisk.UNKNOWN
