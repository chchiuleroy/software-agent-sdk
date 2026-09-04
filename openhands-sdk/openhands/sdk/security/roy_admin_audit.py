"""Roy 的治理管理稽核記錄機制,對應 dsh 稽核鏈的另外兩類資料源(見 roy_km wiki
``project_openhands_governance_platform.md``「下一步」第 9 項稽核 log 分類原則
的前置工作)。

記錄兩類事件:
- ``admin_audit``:誰改了治理設定。寫入點是 ``LocalConversation`` 的
  ``_apply_and_audit_confirmation_policy()``/``_apply_and_audit_security_
  analyzer()``(見 conversation/impl/local_conversation.py),建構子(初次
  套用鎖)與公開的 ``set_confirmation_policy()``/``set_security_analyzer()``
  都會經過這裡——只有「值真的變了」才寫入,resume/init 時用相同值重新套用
  不會產生誤報;讀舊值、比較、賦新值、寫稽核紀錄這四步都在同一個
  ``self._state`` 臨界區內完成,並行呼叫不會讀到 stale 的舊值,寫進 JSONL
  的順序也保證跟 state 實際變化的順序一致。
- ``user_approval``:誰核准/拒絕了哪些待處理動作。寫入點在
  ``LocalConversation.run()``/``arun()``(implicit accept)與
  ``reject_pending_actions()`` 本身(見 conversation/impl/
  local_conversation.py),而不是 agent-server 的
  ``EventService.respond_to_confirmation()``——後者只是 REST 入口,寫在
  SDK 層才能涵蓋繞過 REST、直接呼叫這個 SDK 物件的呼叫端(examples、
  delegate、task manager 等),且快照與實際核准/拒絕的動作在同一個
  ``self._state`` 鎖底下完成,不會有另外抓一份 snapshot 造成的競態。

跟 ``roy_audit_hooks.py`` 的 SessionStart 稽核不同:這裡的寫入函式本身都是
同步、in-process 實作(不透過 SDK hooks 機制的 subprocess 執行)——沒有
「workspace 內容可能劫持這個寫入路徑」的疑慮(不像 roy_audit_hook_writer.py
需要 workspace-immune 的絕對路徑呼叫保護),因此不需要那一套 subprocess
隔離。``run()``/setter 等同步呼叫路徑直接呼叫;``arun()`` 這個跑在 asyncio
event loop 上的 async 路徑則會把同一份同步函式丟給 executor 執行,避免卡住
event loop(見下方已知限制第 3 點)。

寫入沿用 ``roy_audit_hooks`` 同一個稽核根目錄(``default_audit_dir()``),以事件類別
分成不同檔名(``admin_audit.jsonl``/``user_approval.jsonl``),為第 9 項的
三類 JSONL 分類先鋪路——目前還沒有第三類(usage,已有 SessionStart 稽核
涵蓋)以外的簽章鏈,單純是分檔記錄,不做任何加密/簽章保證。

已知限制:
1. ``roy_self_approval.py`` 補上了 requester/approver 兩個身份欄位,但仍
   是 opt-in、非完整的多人身份驗證:requester 是行程層級的
   ``ROY_GOVERNANCE_IDENTITY`` 環境變數(整個 agent-server 行程共用同一個
   值,不是每個對話各自登入),approver 要呼叫端顯式提供才有值(今天的
   Agent Canvas GUI 沒有身份輸入介面,永遠不會帶這個欄位)。兩者任一為
   ``None`` 時,``user_approval`` 記錄不到「誰」核准,只記錄「哪個對話」
   在「什麼時候」被以 accept/reject 路徑核准/拒絕了「哪些動作」——SDK
   直接呼叫跟 REST 使用者操作、真人核准跟程式化/自動 resume,沒有兩個
   身份都明確提供時仍無法區分。真正的多人登入/RBAC 仍是待完成項(見 wiki
   同節第 4 項)。
2. 這套 audit 涵蓋的是 constructor 與兩個公開 setter/兩個核准決策入口本身,
   不是 ``ConversationState`` 的完整 mutation audit:直接改
   ``conversation.state.confirmation_policy``/``security_analyzer``、原地
   修改 policy/analyzer 物件內部的 mutable 欄位、或任何透過 ``_state`` 的
   直接操作,都完全不經過這裡,不會留下任何紀錄;持久化 state 或
   base-state 在載入前被外部竄改,建構子重新套鎖時只能看出「套用鎖後的
   effective 值」有沒有變,無法還原「原始值是誰、何時被改的」。
3. ``arun()`` 那個核准事件不能在取得 ``self._state`` 鎖的當下 await(見
   local_conversation.py 該處註解——同一個鎖被刻意跨 ``await astep()``
   持有,FIFOLock 只有 thread-reentrant 沒有 task-reentrant,鎖內 await
   任何東西都會讓同一個 event-loop 執行緒上的其他 task 趁機靜默重入、弄壞
   歷史紀錄),因此寫入的 future 會被收進 ``pending_audit_futures`` 這個
   區域變數,在鎖釋放之後、``arun()`` 的 ``finally`` 區塊裡用
   ``asyncio.shield(asyncio.gather(...))`` 統一 await。用 ``shield()``
   而非直接 ``gather()`` 是因為第一版只用 ``gather()`` 時,若清理階段本身
   還在 await、又收到第二次 ``cancel()``(``interrupt()`` 連續呼叫兩次以上
   是本檔明確支援的情境,見 ``test_multiple_rapid_interrupts``),取消會
   傳播進尚未真正開始執行(還在 executor 佇列排隊)的寫入,讓它們永遠不會
   執行——這點已用受控探針證實(先用單一 worker 佔滿 executor,提交寫入
   後在它還排隊時取消,結果那次寫入完全沒有執行);至於已經開始在
   executor 執行緒上跑的寫入,即使取消也不受影響,執行緒會繼續跑完,這點
   也已用探針驗證。改用 ``shield()`` 後,第二次 cancel 仍會讓 ``arun()``
   本身的這次 await 被中斷、如常返回(尊重呼叫端明確要求取消的意圖),但
   被 shield 保護的 ``gather()`` 會在背景繼續跑,不論寫入當下是在排隊還是
   已經在執行,都不會因為這次額外的取消而被中止——這個 shield 版本一樣已
   用同款受控探針驗證過,取消兩次後排隊中的寫入依然成功執行。這次 await
   本身被中斷時,``arun()`` 內部會 ``except asyncio.CancelledError`` 接住、
   記一筆 log 就繼續往下走(跟本方法最上層那個 ``except asyncio.
   CancelledError`` 的既有契約一致——``arun()`` 一律不把 cancellation
   往呼叫端傳,而是正常返回),不會因此漏掉後面 ``self._cancel_token``/
   ``self._arun_task`` 的清理;但也因此,cancel 兩次的那次呼叫裡,
   ``for result in results:`` 這段例外記錄迴圈不會執行(因為根本沒有等到
   ``results``),那次呼叫看不到任何非 ``OSError`` 例外的 warning log,即使
   背景寫入之後真的失敗。
   仍不是 fsync 等級的落盤保證:``_write_record()`` 用 ``with open(...)``,
   同步函式返回代表 Python stream 已經 close 且 buffer 已 flush 到作業
   系統,但沒有呼叫 ``fsync``,不保證資料已經寫進儲存媒體本身。真正會讓
   紀錄「完全沒寫進 JSONL」的情況包括:寫入函式本身遇到 ``OSError``
   (fail-open 設計下本來就會吞掉、只留一行 warning log,例如磁碟滿、
   權限不足——這不是本節修法要解決的,是既有 fail-open 取捨的直接後果)、
   `` record_user_approval_event()``/``record_admin_audit_event()`` 拋出
   非 ``OSError`` 的例外、或整個程序在寫入函式真正執行完之前被強制終止
   (如 kill -9、直譯器異常崩潰、作業系統/機器故障)這類程序層級失敗。
4. agent-server 的 ``EventService.run()`` 若在 conversation 停在
   WAITING_FOR_CONFIRMATION、但前一個 ``_run_task`` 的 cleanup tail 還沒
   跑完時收到 accept,會被判定成 "conversation_already_running" 並吞掉當
   作成功回應——這種情況下 SDK 層的 ``run()``/``arun()`` 根本不會被呼叫,
   使用者按下的「接受」既不會真的執行、也不會留下 user_approval 紀錄。這
   不是稽核紀錄本身失真(沒有寫出假紀錄),而是核准決策的 REST 契約缺口,
   需要在 ``EventService`` 那層修,不是這個模組能解的。
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
    tool_call_ids: list[str],
    requester_identity: str | None = None,
    approver_identity: str | None = None,
) -> None:
    """記錄一次核准/拒絕決策:哪個對話核准或拒絕了哪些待處理動作。

    ``tool_call_ids`` alongside ``tool_names`` so a record can be matched back
    to a specific action even when multiple pending actions share the same
    tool name.

    ``requester_identity``/``approver_identity`` 是 ``roy_self_approval.py``
    的欄位,兩者預設皆為 ``None``(未設定 ``ROY_GOVERNANCE_IDENTITY``、或呼叫
    端沒帶 approver 身份時的既有行為)——見本檔模組 docstring 已知限制第 1
    點:只有兩者都非 ``None`` 才代表這筆記錄真的知道「誰」核准了。
    """
    _write_record(
        "user_approval",
        {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "conversation_id": conversation_id,
            "accepted": accepted,
            "reason": reason,
            "tool_names": tool_names,
            "tool_call_ids": tool_call_ids,
            "requester_identity": requester_identity,
            "approver_identity": approver_identity,
        },
    )
