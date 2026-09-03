"""Roy 的治理層機關鍵欄位鎖定機制,對應 dsh 治理鏈的「machine/org 層」概念
(見 roy_km wiki ``project_openhands_governance_platform.md``「下一步」第 8
項的查證結論)。

借鏡 Codex「project-local config 不能覆寫 machine-local provider/auth/
telemetry」的設計原則:``confirmation_mode``／``security_analyzer`` 這兩個
治理關鍵欄位,一旦透過環境變數在這台機器上鎖定,repo/workspace 層(
``ConversationSettings`` 持久化設定、raw REST API 呼叫端顯式傳入的值、
Agent Canvas GUI)一律不能覆寫。

沿用既有 ``ROY_GOVERNANCE_*`` 環境變數慣例(見 ``roy_governance.py`` 的
``ROY_GOVERNANCE_WORKSPACE_ROOT``、``roy_audit_hooks.py`` 的
``ROY_GOVERNANCE_AUDIT_DIR``),不新增設定檔格式——單機/少數機器部署場景
下,環境變數已經是這個 repo 一貫的「admin 層設定,不進使用者可改的
settings.json」機制,不需要另外設計檔案格式與載入順序。

未設定環境變數代表不鎖;已設定但值無法辨識會丟 ``ValueError``——這是治理
邊界設定,打錯字不該悄悄變成「沒鎖」。

``apply_confirmation_policy_lock()``/``apply_security_analyzer_lock()`` 是
冪等的純函式(輸入候選值,回傳鎖定後應該生效的值),供所有實際會改動這兩
個欄位的地方共用同一份判斷邏輯,而非各自複製一份。

已知邊界:這個鎖保護的是「透過 request model 或
``LocalConversation.set_confirmation_policy()``/``set_security_analyzer()``
變更狀態」這條路徑,不保護同一行程內直接改寫
``LocalConversation.state.confirmation_policy``/``security_analyzer`` 這種
mutable public state 的存取——那需要的是 Python 層的信任邊界,不是這個
函式能解決的問題(同行程程式碼本來就能改環境變數本身)。
"""

from __future__ import annotations

import os

from openhands.sdk.security.analyzer import SecurityAnalyzerBase
from openhands.sdk.security.confirmation_policy import (
    AlwaysConfirm,
    ConfirmationPolicyBase,
    ConfirmRisky,
    NeverConfirm,
)
from openhands.sdk.security.risk import SecurityRisk
from openhands.sdk.security.roy_governance import RoyPathPayloadSecurityAnalyzer


_TRUE_VALUES = frozenset({"true", "1", "yes"})
_FALSE_VALUES = frozenset({"false", "0", "no"})
_SECURITY_ANALYZER_VALUES = frozenset({"llm", "none"})


def locked_confirmation_mode() -> bool | None:
    """回傳 machine 層鎖定的 confirmation_mode,未設定回傳 ``None``(不鎖)。

    設定了但值無法辨識會丟 ``ValueError``——這是治理邊界設定,打錯字不該
    悄悄變成「沒鎖」。
    """
    raw = os.environ.get("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE")
    if raw is None:
        return None
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(
        f"ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE={raw!r} is not a recognized "
        f"boolean value (expected one of {sorted(_TRUE_VALUES | _FALSE_VALUES)})"
    )


def locked_security_analyzer() -> str | None:
    """回傳 machine 層鎖定的 security_analyzer 種類(``"llm"``／``"none"``)。

    對應 ``ConversationSettings.security_analyzer``／
    ``_build_security_analyzer()`` 使用的同一套字串詞彙。未設定回傳
    ``None``(不鎖);設定了但值無法辨識會丟 ``ValueError``,理由同上。
    """
    raw = os.environ.get("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER")
    if raw is None:
        return None
    normalized = raw.strip().lower()
    if normalized in _SECURITY_ANALYZER_VALUES:
        return normalized
    raise ValueError(
        f"ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER={raw!r} is not a recognized "
        f"value (expected one of {sorted(_SECURITY_ANALYZER_VALUES)})"
    )


def apply_confirmation_policy_lock(
    policy: ConfirmationPolicyBase,
) -> ConfirmationPolicyBase:
    """回傳鎖定後「真正應該生效」的 confirmation policy。

    冪等的純函式:沒有鎖定就原樣回傳 ``policy``;有鎖定就依方向修正——
    只在「目前不符合鎖定方向」時才動手改寫,不無條件重建物件:
    - 鎖定要求 confirmation on 時,``AlwaysConfirm`` 視為明確更嚴格、
      語意無歧義,予以保留;其他任何值(含 ``ConfirmRisky
      (confirm_unknown=False)`` 這種類別對但行為偏弱的情況,或
      ``NeverConfirm``)一律正規化成治理標準值 ``ConfirmRisky(HIGH)``——
      不能只看類別名稱是不是 ``NeverConfirm``,因為類別相符不代表行為
      上真的會確認。
    - 鎖定要求 confirmation off 時,無條件正規化成 ``NeverConfirm()``。
    """
    lock_mode = locked_confirmation_mode()
    if lock_mode is True:
        if isinstance(policy, AlwaysConfirm):
            return policy
        return ConfirmRisky(threshold=SecurityRisk.HIGH)
    if lock_mode is False:
        if isinstance(policy, NeverConfirm):
            return policy
        return NeverConfirm()
    return policy


def apply_security_analyzer_lock(
    analyzer: SecurityAnalyzerBase | None,
    *,
    workspace_root: str,
) -> SecurityAnalyzerBase | None:
    """回傳鎖定後「真正應該生效」的 security analyzer。

    冪等的純函式。鎖定為 ``"llm"`` 時一律重建全新的
    ``RoyPathPayloadSecurityAnalyzer``,``workspace_root`` 只接受呼叫端
    傳入的 ``workspace_root`` 參數(通常是這個對話真正的 workspace)——
    不接受候選 analyzer 物件裡可能帶著的、呼叫端自訂的 workspace_root,
    因為那個欄位直接決定哪些路徑算「在工作區內」,保留呼叫端自訂值會讓
    鎖定形同虛設。
    """
    lock_analyzer = locked_security_analyzer()
    if lock_analyzer == "none":
        return None
    if lock_analyzer == "llm":
        if (
            isinstance(analyzer, RoyPathPayloadSecurityAnalyzer)
            and analyzer.workspace_root == workspace_root
        ):
            return analyzer
        return RoyPathPayloadSecurityAnalyzer(workspace_root=workspace_root)
    return analyzer
