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

小o code review(2026-09-03)抓到:第一版把「環境變數已設定但值無法辨識
(例如打錯字)」跟「環境變數根本沒設定」都當成「不鎖」處理,對一般
feature flag 這樣合理,但對宣稱是 machine/org governance boundary 的設定,
部署時打錯字會在完全沒有任何錯誤訊號的情況下悄悄解除保護。改成:未設定
才是「不鎖」;已設定但無法辨識直接丟 ``ValueError``,讓第一個嘗試建立
對話的請求就失敗,而不是靜默放行。
"""

from __future__ import annotations

import os


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
