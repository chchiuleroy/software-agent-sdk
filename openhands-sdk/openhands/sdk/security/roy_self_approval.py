"""Roy 的 identity-aware self-approval 防護,對應 dsh 治理插件
``dsh-authz-approval-answerer`` 的 requester≠approver 顯式綁定機制(見 roy_km
wiki ``project_openhands_governance_platform.md``「下一步」第 1 項)。

跟 ``roy_admin_audit.py`` 記錄的「誰核准了什麼」不同,這裡解決的是更前一步
的問題:目前系統完全沒有「誰發起、誰核准」的身份欄位,``user_approval``
稽核記錄不到「誰」,自然也擋不住同一個人自己核准自己發起的高風險動作。

設計刻意做成兩段式、預設不生效,不影響 Roy 目前單機單人使用 GUI 的既有
體驗:

1. **requester identity**:conversation 建構當下讀一次
   ``ROY_GOVERNANCE_IDENTITY`` 環境變數(沿用既有 ``ROY_GOVERNANCE_*``
   慣例,見 ``roy_governance_lock.py``),代表「這個對話是代表誰發起
   的」。未設定則為 ``None``——完全比照 ``roy_governance_lock.py`` 的
   「未設定環境變數代表不鎖」精神,這裡是「未設定代表不追蹤身份」。
2. **approver identity**:核准/拒絕當下由呼叫端顯式提供(REST
   ``ConfirmationResponseRequest.approver_identity``,或直接呼叫 SDK
   時的同名參數)。Agent Canvas 目前的 GUI 完全沒有身份切換介面,永遠不會
   帶這個欄位,所以只要呼叫端沒提供,``approver_identity`` 就是
   ``None``。

``check_not_self_approval()`` 只在 requester／approver **兩者都非
None 且正規化後相等** 時才擋下——這代表:
- 沒設定 ``ROY_GOVERNANCE_IDENTITY`` 的機器(Roy 目前的日常桌面 app):
  requester 恆為 ``None``,這個檢查永遠是 no-op,今天的核准流程完全不受
  影響。
- 設定了 ``ROY_GOVERNANCE_IDENTITY`` 但呼叫端沒帶 ``approver_identity``
  的請求(今天的 GUI 就是這種):approver 為 ``None``,同樣是 no-op、
  fail-open——這不是防護有漏洞,是這個模組跟 ``roy_admin_audit.py`` 共用
  的既有取捨:稽核/防護不能是既有正常操作突然失敗的原因,只有呼叫端主動
  聲明了兩個身份,才有東西可比。
- 只有當呼叫端同時提供了 requester(機器層設定)與 approver(呼叫當下
  顯式提供)、且兩者相同,才會真正擋下——這是目前唯一能測到「自己不能
  核准自己」這條路徑的方式。

已知限制(誠實範圍,不誇大):
1. Agent Canvas GUI 沒有身份輸入介面,無法透過滑鼠點擊「以不同身份核准」
   來驗證跨身份核准成功這條路徑——只能透過直接呼叫同一個正在跑的
   agent-server REST API(帶 ``approver_identity``)驗證,不是純滑鼠
   操作的端對端測試。
2. ``ROY_GOVERNANCE_IDENTITY`` 是行程層級的單一值,不是「這次核准是誰
   點的」這種逐次請求都會變動的身份——同一個 agent-server 行程內的所有
   對話共用同一個 requester identity。這對應「這台機器/這個 agent-server
   代表誰」,不是完整的多人登入系統(SSO/RBAC 仍是待完成項,見 wiki 同節
   第 4 項)。
3. 只擋「接受(accept)」路徑——拒絕自己發起的動作不構成權限提升,不需要
   跟本模組一樣的身份比對。
4. 這是一個 cooperative identity check,不是能抵抗惡意 REST caller 的授權
   邊界——任何呼叫端都能在 ``approver_identity`` 欄位自己宣稱一個跟
   requester 不同的假字串來繞過這個檢查(這條路徑本來就對應「呼叫端可以
   直接省略這個欄位觸發 fail-open」,不是這次新增的攻擊面)。真正的授權
   邊界需要 SSO/RBAC 提供不可偽造的身份來源,見上面第 2 點。
5. (2026-09-04 小o review 抓到,已知未修)``EventService.run()`` 排程
   背景任務前的同步檢查與背景任務真正進入
   ``LocalConversation.run()``/``arun()`` 之間有一個 TOCTOU 窗口:
   conversation state 理論上可能在這兩個時間點之間改變。核心安全性質不受
   影響(``LocalConversation.run()``/``arun()`` 自己的檢查是最終防線,
   self-approval 永遠不會真的被執行),但如果真的撞上這個窗口,
   `EventService` 背景任務的通用 ``except Exception`` backstop 會把這次
   拒絕吞掉、變成一般 ERROR 狀態,REST 呼叫端這一次就看不到乾淨的
   403——需要把「確認等待狀態、核對身份、認領 pending action」重構成
   ``LocalConversation`` 內部單一原子操作才能真正關閉,範圍較大,本輪
   未做。
6. (2026-09-04 小o review 抓到,已知未做)`clients/typescript` 的手寫型別
   與 generated schema 尚未加上 ``approver_identity`` 欄位——目前唯一會
   用到這個欄位的呼叫端是直接打 REST API 或 SDK,Agent Canvas GUI 本身
   沒有身份輸入介面、也還沒有任何 TypeScript 呼叫端需要這個欄位,故暫緩
   同步,待真的有 typed 呼叫端需要時再補。
"""

from __future__ import annotations

import os


class SelfApprovalDeniedError(ValueError):
    """Raised by :func:`check_not_self_approval` when requester == approver.

    A ``ValueError`` subclass (not a fresh exception hierarchy) so any
    existing code that already catches ``ValueError`` around
    ``run()``/``arun()`` — matching this codebase's precedent for
    ``"conversation_already_running"`` — keeps working unchanged. The
    subclass exists so the agent-server can register a *specific* exception
    handler (see ``api.py``) that maps this one case to a clean 403 instead
    of falling through to the generic 500 every other unhandled
    ``ValueError`` gets.
    """


def requester_identity_for_conversation() -> str | None:
    """讀取這個對話的 requester identity,未設定回傳 ``None``(不追蹤)。

    刻意不做格式驗證(不像 ``roy_governance_lock.py`` 的布林/列舉值那樣打
    錯字會丟例外)——這是一個自由格式的身份標籤,任何非空字串都合法。
    """
    raw = os.environ.get("ROY_GOVERNANCE_IDENTITY")
    if raw is None:
        return None
    normalized = raw.strip()
    return normalized or None


def _canonicalize(identity: str) -> str:
    return identity.strip().lower()


def check_not_self_approval(
    requester_identity: str | None, approver_identity: str | None
) -> None:
    """requester 與 approver 都非 None 且正規化後相同時,拋出 ``ValueError``。

    任一方為 ``None`` 都視為「沒有足夠資訊比對」,fail-open 放行——見本檔
    模組 docstring 的三種情境說明。
    """
    if requester_identity is None or approver_identity is None:
        return
    if _canonicalize(requester_identity) == _canonicalize(approver_identity):
        raise SelfApprovalDeniedError(
            "self-approval not allowed: requester and approver are the same "
            f"identity ({requester_identity!r})"
        )
