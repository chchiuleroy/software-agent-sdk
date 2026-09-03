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
"""

from __future__ import annotations

import os


def locked_confirmation_mode() -> bool | None:
    """回傳 machine 層鎖定的 confirmation_mode。

    ``ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE`` 未設定,或設定成無法辨識的
    值(例如打錯字),回傳 ``None``(不鎖,沿用既有 per-conversation 邏輯)
    ——寧可不鎖,也不要讓一個看不懂的值被誤判成某個特定方向的鎖定。
    """
    raw = os.environ.get("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE")
    if raw is None:
        return None
    normalized = raw.strip().lower()
    if normalized in ("true", "1", "yes"):
        return True
    if normalized in ("false", "0", "no"):
        return False
    return None


def locked_security_analyzer() -> str | None:
    """回傳 machine 層鎖定的 security_analyzer 種類(``"llm"``／``"none"``)。

    對應 ``ConversationSettings.security_analyzer``／
    ``_build_security_analyzer()`` 使用的同一套字串詞彙。未設定或值無法
    辨識回傳 ``None``(不鎖)。
    """
    raw = os.environ.get("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER")
    if raw is None:
        return None
    normalized = raw.strip().lower()
    if normalized in ("llm", "none"):
        return normalized
    return None
