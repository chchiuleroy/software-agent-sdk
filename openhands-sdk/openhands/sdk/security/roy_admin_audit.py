"""Roy 的治理管理稽核記錄機制,對應 dsh 稽核鏈的另外兩類資料源(見 roy_km wiki
``project_openhands_governance_platform.md``「下一步」第 9 項稽核 log 分類原則
的前置工作)。

記錄兩類事件:
- ``admin_audit``:誰改了治理設定(``LocalConversation.set_confirmation_
  policy()``/``set_security_analyzer()`` 被呼叫,見 conversation/impl/
  local_conversation.py)。
- ``user_approval``:誰核准/拒絕了哪些待處理動作(agent-server 的
  ``EventService.respond_to_confirmation()``,見 agent_server/
  event_service.py)。

跟 ``roy_audit_hooks.py`` 的 SessionStart 稽核不同:這裡的兩個事件都是
in-process 呼叫(setter 呼叫、REST endpoint 處理函式內部),不透過 SDK hooks
機制的 subprocess 執行——沒有「workspace 內容可能劫持這個寫入路徑」的疑慮
(不像 roy_audit_hook_writer.py 需要 workspace-immune 的絕對路徑呼叫保護),
因此直接同步寫檔,不需要那一套 subprocess 隔離。

寫入沿用 ``roy_audit_hooks`` 同一個稽核根目錄(``default_audit_dir()``),以事件類別
分成不同檔名(``admin_audit.jsonl``/``user_approval.jsonl``),為第 9 項的
三類 JSONL 分類先鋪路——目前還沒有第三類(usage,已有 SessionStart 稽核
涵蓋)以外的簽章鏈,單純是分檔記錄,不做任何加密/簽章保證。

已知限制:目前系統沒有 per-request 呼叫端身份驗證機制(identity-aware
self-approval 仍是待完成的前置工作),``user_approval`` 記錄不到「誰」核准,
只能記錄「哪個對話」在「什麼時候」被核准/拒絕了「哪些動作」。
"""

from __future__ import annotations

import datetime
import json
import logging
import os
from typing import Any


logger = logging.getLogger(__name__)


def _audit_dir() -> str:
    from openhands.sdk.security.roy_audit_hooks import default_audit_dir

    return default_audit_dir()


def _write_record(category: str, record: dict[str, Any]) -> None:
    # Fail open: audit logging must never be the reason a governance
    # action (changing a setting, approving/rejecting an action) fails.
    try:
        audit_dir = _audit_dir()
        os.makedirs(audit_dir, exist_ok=True)
        log_path = os.path.join(audit_dir, f"{category}.jsonl")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        logger.warning("Failed to write %s audit record", category, exc_info=True)


def record_admin_audit_event(*, conversation_id: str, field: str, value: str) -> None:
    """記錄一次治理設定變更:哪個對話的哪個欄位被改成了什麼值。"""
    _write_record(
        "admin_audit",
        {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "conversation_id": conversation_id,
            "field": field,
            "value": value,
        },
    )


def record_user_approval_event(
    *,
    conversation_id: str,
    accepted: bool,
    reason: str | None,
    tool_names: list[str],
) -> None:
    """記錄一次核准/拒絕決策:哪個對話核准或拒絕了哪些待處理動作。"""
    _write_record(
        "user_approval",
        {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "conversation_id": conversation_id,
            "accepted": accepted,
            "reason": reason,
            "tool_names": tool_names,
        },
    )
