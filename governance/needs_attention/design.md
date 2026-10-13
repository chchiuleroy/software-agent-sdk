# 1.11 `NEEDS_ATTENTION` 掃描與修復：第二層設計（模組與介面）

> **位置說明（2026-10-13）**：本文件原是工作筆記（`ops_notes/`，不在任何 git repo），現已連同 e2e 腳本與 CLI 搬進本 repo 的 `governance/needs_attention/`，CLI 的單元測試在 `tests/agent_server/test_governance_attention_cli.py`。下面 §5 各步驟的紀錄是**當時**的狀態（例如「未 push」「不在任何 git repo」），保留原文作為歷程；現況以 PR 與程式碼為準。

日期：2026-10-13　狀態：**待 Roy 核可才動工**（plan-gate 第二層）
Roy 已拍板（2026-10-13「照建議」）：只做第 1、2 層（單一對話＋全域掃描）；先做 API＋CLI、不做畫面；2932 行誤判獨立 commit；新增終態 `RESOLVED_MANUALLY`。

## 0. 範圍與限度

- **小o 審查（2026-10-13，契約 v1.1）**：8 個進入點盤點正確；兩項 confirmed（S3 狀態合併、步驟 7 的 handshake 快取）已回原始碼核對成立並併入本文；retry 重送不會重複執行（`RESULT_PENDING` 只重送 report、`CLAIM_INFLIGHT` 由 central 以同一 key 回放同一 attempt）、dismiss 後仍被擋、降版風險描述皆被其查證為正確。**其 `not_checked`：未跑任何測試或 e2e、未涵蓋尚未存在的新模組、未驗證多行程與正式資料庫。**
- **來源**：全部由讀程式碼得來（`event_service.py`、`governance_outbox.py`、`governance_router.py`、central `approvals.py`），**沒有重現任何行為**。「NEEDS_ATTENTION 會讓該對話**之後的不同動作**無法再被治理」是推論；小o 指出原先「永遠」過度絕對：同一動作在沒有既有 settled handshake 的行程中（例如重啟後）仍可用原 approval 進入 claim 流程（`maybe_register_governance_approval` 2343–2368 行：同一動作回傳、不同動作遇非終態回傳「不建第二個」；`archive_and_clear` 只在終態執行）。實作第一步要先用 e2e 重現它。
- **改動只在 agent-server 的本機檔案與新端點，不碰 central、不碰正式 DB。**
- **不做**：central 端跨裝置待處理清單（第 3 層）、畫面、`requester_assertion`／`admin_verified` 入口、多行程協調。

## 1. 進入點盤點（8 個，上一版 overview 漏了第 8 個）

| # | 位置（event_service.py） | 觸發 | 新 reason | 已知狀態 |
|---|---|---|---|---|
| S1 | ~782，relay 的 CLAIM_INFLIGHT | claim 回永久錯誤 | `claim_failed` | 無執行嘗試 |
| S2 | ~857，relay 的 RESULT_PENDING | report-result 永久錯誤（`late_report` 後備之後） | `report_failed` | 動作可能已執行 |
| S3 | ~1124，`_wait_for_decision_loop` | central 回 `accepted`／`rejected` 以外的狀態。**小o 審查（confirmed，high）指出**：`/wait` 回的是「當下狀態」（`approvals.py:976–981`，只要與 `known_status` 不同就回），另一個請求可能已把它推進到 `executing`／`applied`／`failed_*`。故依觀察到的狀態拆成兩個 reason：`cancelled`／`expired` → `approval_cancelled_or_expired`；其餘 → `central_status_unexpected`，**觀察到的狀態字串寫入 `last_error_code`**（如 `status=executing`） | 前者：無執行嘗試；後者：**可能已執行** |
| S4 | ~2652，`maybe_report_governance_result` | 同 S2（行內路徑） | `report_failed` | 動作可能已執行 |
| S5 | ~2723，`_reconcile_governance_after_close` | 關閉時回報 `failure_unknown` 失敗 | `reconcile_failed` | 動作可能已執行；relay 已停 |
| S6 | ~2932，`_claim_and_run_governed` | claim 任何例外（含暫時性） | `claim_failed` | 無執行嘗試 |
| S7 | ~3170，`_report_governance_failure` | 綁定不符後回報 `failure_definite` 失敗 | `binding_report_failed` | 工具**沒有**執行 |
| S8 | ~964，`_send_late_report` | `late_report` 被永久拒絕 | `late_report_refused` | 動作可能已執行；central 已 `failed_unknown` |

## 2. 資料模型（`governance_outbox.py`）

- `OutboxState.RESOLVED_MANUALLY`：新增，加入 `TERMINAL_STATES`。
- `NeedsAttentionReason(StrEnum)`：上表 7 個值（`claim_failed`、`report_failed`、`approval_cancelled_or_expired`、`central_status_unexpected`、`reconcile_failed`、`binding_report_failed`、`late_report_refused`）。`unreadable_outbox` 只在 API 回應出現，不寫入檔案。
- 既有欄位 `needs_attention_reason`、`last_error_code`（目前**全程式碼從未寫入**）開始寫入。
- 新增選填欄位：`resolution_note: str | None`、`resolved_at: str | None`（僅 RESOLVED_MANUALLY／abandon 時寫）。
- 新輔助函式 `mark_needs_attention(record, reason, error_code=None)`，取代 8 處 `record_attempt(r, new_state=NEEDS_ATTENTION)` 內嵌 lambda。
- **降版風險（雙向門的唯一例外）**：`from_json` 用 `OutboxState(raw["state"])` 與 `cls(**raw)`。舊版程式讀到含 `resolved_manually` 狀態或新欄位的檔會丟例外。revert 程式碼前必須先確認磁碟上沒有此類檔案；README 要寫明。

## 3. 動作矩陣（核心安全規則：**可能已執行過的動作，永遠不給 abandon**）

| reason | retry | abandon | dismiss（需 note） |
|---|---|---|---|
| `claim_failed` | ✓（→ `CLAIM_INFLIGHT`，沿用 `claim-{request_id}`） | ✓ | ✓ |
| `approval_cancelled_or_expired` | ✗（central 已終態） | ✓ | ✓ |
| `report_failed` | ✓（→ `RESULT_PENDING`，`pending_report_outcome` 已存） | ✗ | ✓ |
| `reconcile_failed` | ✓（→ `RESULT_PENDING`） | ✗ | ✓ |
| `binding_report_failed` | ✓（先寫 `pending_report_outcome="failure_definite"` 再 → `RESULT_PENDING`） | ✗ | ✓ |
| `late_report_refused` | ✗（永久拒絕，重送只會重複同一錯誤） | ✗ | ✓ |
| `central_status_unexpected`（新，S3 拆出） | ✗ | ✗（central 狀態已推進，動作可能已執行；取消與 pre-claim abort 也會因狀態已推進而失敗） | ✓ |

- **retry** 不自己呼叫 central，只把狀態推回可重試狀態，由既有 relay 迴圈用同一 idempotency key 重送（重送安全性來自既有機制，**未逐條驗證**，列入 e2e）。
- **abandon** ＝ 沿用 `cancel_unclaimed_governance_approval` 的 central 取消／中止邏輯（先 cancel，`illegal_transition` 再退回 abort）＋ 本機 `reject_pending_actions` ＋ 狀態 → `CANCELLED`。best effort 的 central 端失敗只記 log，不擋本機解卡。
- **dismiss** ＝ 狀態 → `RESOLVED_MANUALLY`，`resolution_note` 必填（空字串 422）。**不會**自動 reject 本機待確認動作：若同一動作仍在 `WAITING_FOR_CONFIRMATION`，`run()` 仍被 `check_governed_binding_required` 擋（終態記錄），回應用 `conversation_still_waiting: true` 告知，操作者需另行 reject 或 abandon。

## 4. 介面

新模組 `governance_attention.py`（邏輯）；路由加在既有 `governance_router.py`（該檔 docstring 寫「Read-only」，要同步改）。

- `GET /governance/attention`
  - 掃 `conversations_dir/*/governance_outbox.json`（`conversation_id.hex` 為目錄名，`conversation_service.py` 804、811 行），**不需要對話已載入**。
  - 回傳每筆：`conversation_id`、`reason`、`last_error_code`、`central_approval_id`、`attempt_count`、`last_attempt_at`、`allowed_actions`、`request_id`。
  - **讀不動的檔案不靜默略過**：以 `reason="unreadable_outbox"` 列出（`allowed_actions=[]`）。
  - 無 `NEEDS_ATTENTION` 的回 `[]`。個人模式（`governance_deployment_mode != "team"`）回 `[]`。
- `POST /governance/attention/{conversation_id}/resolve`
  - body：`action`（`retry|abandon|dismiss`）、`expected_request_id`（**必填**，與當前記錄比對，不符 409，避免對過期畫面操作）、`note`。
  - 錯誤：404 沒有記錄；409 狀態已不是 `NEEDS_ATTENTION`／`request_id` 不符；409 動作不被該 reason 允許（回 `allowed_actions`）；422 dismiss 缺 note。
  - 需載入對話才能 `reject_pending_actions`／啟動 relay：走 `ConversationService` 既有的載入函式。
- CLI：`governance/needs_attention/governance_attention_cli.py`，`list`／`resolve <conversation_id> <action> [--note ...]`；session API key 從環境變數讀，不印值。
- **認證限度**：agent-server 只有共用的 `X-Session-API-Key`（`dependencies.py`），沒有操作者身分。`resolution_note` 以外，**稽核上無法記錄「誰」**。central 也不會得知。這是 v1 的明確限度。

## 5. 步驟（每步獨立 commit，可停）

1. **✅ 已完成（2026-10-13）重現卡死**：`governance/needs_attention/e2e_needs_attention.py`，真 agent-server＋真 central＋假 IdP＋臨時 Postgres，14/14（兩次執行；第一版 10/10，補對照組後 14/14）。情境：central 取消待核准 → outbox 變 `needs_attention`（S3）；本機 reject 後送第二個不同動作 → 對話停在 `waiting_for_confirmation`，central 的核准列數**停在 1**，outbox 仍是第一個流程。**對照組**（第一個核准正常 accept、`result_reported` 終態）第二個核准**會**出現（列數 2），所以卡死確由 `NEEDS_ATTENTION` 造成、不是情境本身造不出第二個核准。同時確認 `needs_attention_reason`／`last_error_code` 實際為 null。**限度**：只重現了 S3 這一個進入點（以 central 取消觸發）；其餘 7 個進入點未重現，其卡死是依同一段程式碼推論。`BUG-REPRO-*` 檢查斷言的是今天的壞行為，步驟 2～5 完成後要翻轉成健康預期。原計畫（保留）：先寫失敗的測試，真 agent-server 製造 `claim_failed`（accept 後撤銷裝置→claim 403 `device_not_bound`），確認新動作不被治理。
2. **✅ 已完成（2026-10-13，本機分支 `feat/needs-attention-reasons`，`7772331ac`＋`11e2a2e7b`，未 push）**：資料模型＋ `mark_needs_attention` ＋ 8 處改寫（行為不變，只寫入 reason／error_code）。相關測試 707 通過、1 失敗（`test_restart_resumes_conversations_after_non_graceful_shutdown`，**乾淨 main 上也失敗**，既有）；S4、S5 原本沒有 NEEDS_ATTENTION 測試，已補。突變 11 個（原因／code 沒寫、S3 拆分合回、S4／S5 標錯、S8 保護拿掉、狀態變可重試、白名單繞過／放寬／去長度限制、`_error_code_of` 回傳原值）全被抓到。**小o 審查（契約 v1.1）**：「行為不變」成立（8 處 except 範圍、attempt_count、return 路徑逐一比對）；S3 closure 安全；唯一 confirmed（medium）：`last_error_code` 取自 central 回應 body（`governance_client.py::_classify_response`）、未驗證，可把任意字串寫進 `governance_outbox.json`——已回原始碼核對成立並於第二個 commit 修正：只接受 `[A-Za-z0-9_.:=-]{1,64}`，否則存 `unrecognized`（S3 的 `status=…` 同理）。小o 的 `not_checked`：未能跑 pytest（唯讀沙箱無暫存目錄）——測試由小c 自跑。**限度**：沒跑型別檢查；`event_service.py`／`test_event_service.py` 在 main 上本來就不合 `ruff format`，未整檔重排，只確認新增行未增加差異；e2e 未重跑（`BUG-REPRO-2` 預期翻轉，留待步驟 5）。
3. **✅ 已完成（2026-10-13，本機分支 `feat/needs-attention-reasons`，`5954a6564`＋審查後修正 commit，未 push）**：`governance_attention.py` ＋ `GET /api/governance/attention` ＋ 動作矩陣單元測試。相關測試 761 通過、2 跳過、1 失敗（既有，乾淨 main 上也失敗）；ruff 全目錄通過、pyright 0 錯誤（補跑時發現**步驟 2 引入 1 個 pyright 錯誤**，已用 `TypeGuard[str]` 修）。突變 12 個全被抓到（過程中兩次揭露測試本身的洞：真 symlink 測試因這台無法建 symlink 被跳過→改以 monkeypatch ＋ Windows junction 測試；歸檔競態的第一版測試因 `Path.exists()` 內部也呼叫 `stat()` 而沒測到該視窗→改在 `read_text` 注入）。**Windows junction 不會被 `is_symlink()` 偵測卻會被跟隨**，已用 `is_junction()` 處理。**小o 審查（契約 v1.1）**：動作矩陣與設計一致、無把可能已執行者開放 abandon（確認）；`confirmed` 三項：①歸檔競態被誤報為 `unreadable_outbox`（low，**成立並已修**，掃描遇 `FileNotFoundError` 改為略過）；②symlink／junction 檢查非原子（low，成立；前提是能寫入 conversations 目錄的本機程序＝與 server 同信任層級；**不改機制**，只在 docstring 改明寫「盡力而為，非安全邊界」）；③無界並發掃描（它評 medium；事實成立，但**我評為可接受**：呼叫者持有 session API key，而同一個 `api_router` 還掛著 `bash_router`〔`api.py:440`〕，他本來就能執行任意指令；沒加上限／分頁）。`needs_validation`：硬連結可能跨權限洩漏 outbox metadata——**明列為未解**：前提與②相同（需能寫入該目錄），驗證需建立多帳號 ACL 情境，未做。小o 的 `not_checked`：未跑測試（唯讀沙箱）、未驗證競態實際可利用性、未看下游 Canvas 如何呈現 `reason`／`last_error_code`（若以不安全方式呈現 HTML 才有下游問題）。**已知限度**：2 個真 symlink 測試在此機仍跳過；清單無分頁或上限。
4. **✅ 已實作（2026-10-13，本機分支 `feat/needs-attention-reasons`，`46881e69e`＋審查後修正 `ff5329ec7`＋第二輪修正 `fd9f6abcb`，未 push；兩輪審查皆已處理）**：`POST /api/governance/attention/{id}/resolve`＋ retry／abandon／dismiss ＋新終態 `RESOLVED_MANUALLY`＋ `OutboxRecord.resolution_note`／`resolved_at`。相關測試 838 通過、2 跳過、1 失敗（既有）；ruff／pyright 乾淨。**設計取捨**：①abandon 採**失敗即停**（central 不同意或連不上，整個不做、紀錄與對話不動；與「刪對話時失敗只記 log」刻意不同，因為是操作者主動要求）；②central 不可用回 **424 而非 502/503**——`api.py` 的 HTTPException handler 會把所有 5xx 的 body 換成 "Internal Server Error"，操作者會看不到原因；③retry 不自己呼叫 central，只把狀態推回 relay 會重做的狀態（relay 間隔常數 `GOVERNANCE_OUTBOX_RELAY_INTERVAL_SECONDS` 為 30 秒，故 retry 的實際重送最多晚約 30 秒，**未實測**）；④abandon 只在「待確認動作恰好只有這筆紀錄的動作」時才 reject（`reject_pending_actions` 會 reject 全部待確認動作）。**第一輪小o 審查（契約 v1.1）**：retry 的 idempotency key／outcome 與原本一致、`mutate()` 在 callback 丟例外時不寫檔且釋放鎖、`RESOLVED_MANUALLY` 與 binding guard／archive／cancel／close 行為一致、降版風險描述正確（皆其查證為正確）；兩個 `confirmed`（皆 high）：①abandon 的 central／本機副作用發生在 outbox CAS 之前，並發 retry／dismiss 先提交時 abandon 已撤銷 central 並 reject 動作才失敗——**核對成立**，修正：每個對話一把 `_resolve_lock`＋ central 之後 reject 之前重檢；②`_action_still_pending` 與 reject 分兩次取鎖（TOCTOU）——**核對成立**，修正：`_reject_if_only_sync` 在同一執行緒同一次持有 state lock（`FIFOLock` 以執行緒 id 可重入）內檢查並 reject。小o 另指出既有測試「剛好漏掉」第一項：**自查發現我的測試有三處根本不會失敗**（待確認動作與紀錄綁的不是同一個 id，不論實作如何都不會 reject；並發測試中 retry 在 abandon 開始前就跑完）；突變驗證抓出後已重寫，現 9 個新行為突變全被抓到。小o 的 `not_checked`：未跑測試、未做真實整合、未審 resolve 與刪對話的並發。**第二輪審查（只看修正 commit `ff5329ec7`）**：兩個修正皆成立——`FIFOLock` 同執行緒重入計數對稱、`reject_pending_actions` 內無 `release_all`／await／換執行緒（檢查與 reject 確實在同一臨界區）；`_resolve_lock` 無鎖順序反轉、`GovernanceClient` 逾時為 httpx 預設 30 秒（持鎖等待會延遲同一對話的其他 resolve，不死結）；僅一個新 `confirmed`（medium）：central 之後的第二次讀 outbox 沒套用「讀不動 → `unreadable_outbox`」轉譯，原始例外逸出——**核對成立**，已抽成共用 `_load_outbox_for_resolve` 並補測試（突變被抓到）。其 `not_checked`：未能動態跑 pytest（唯讀沙箱無暫存目錄）、未連真實 central；它指出 state-lock 測試用 mock、未單獨整合真實 `FIFOLock` 與 `LocalConversation`（既有 FIFOLock 專項測試涵蓋重入與 release 對稱，故不算缺陷，但**真實整合要等步驟 5 e2e**）。**已知限度**：①resolve 與刪除對話的並發未處理；②`resolution_note`（操作者自由文字，≤1000 字）明文存進本來就含 action payload 的 outbox 檔，log 不輸出 note；③`claim_failed` 在首次 claim 暫時性錯誤時 central 可能其實已 claim 成功，retry 會讓 relay 以同一 attempt 執行工具（小o 未找到比 handshake 快取更嚴重的新路徑）；④降版風險：舊版讀不了含新狀態／新欄位的 outbox 檔，revert 前須先清掉。
5. **✅ 已完成（2026-10-13）e2e**：`governance/needs_attention/e2e_needs_attention.py` 重寫並一次跑 **46/46**，真 agent-server＋真 central（兩次重啟，綁定先關→開→關）＋假 IdP＋臨時 Postgres。涵蓋：CONTROL 基準；A（central 取消→記錄原因與代碼→清單→abandon→**真實 `FIFOLock`＋`LocalConversation` reject，對話回 idle**→下一個不同動作重新被治理、舊紀錄歸檔、被放棄的動作從未執行；翻轉步驟 1 的 `BUG-REPRO-*`）；D（三種被拒絕的請求不改任何東西、dismiss 後對話仍在等待、手動 reject 後可前進）；B（撤銷裝置造出**真實** `claim_failed`〔central 回 `device_not_bound`〕→ abandon 走**真實 pre-claim abort**，central `accepted → cancelled`）；C（重啟 central 關綁定→ retry →**relay 在 25 秒內重送 claim、工具執行一次、central 終態 `applied`**）。日誌 8 個 traceback 逐一核對皆預期內（2 次重啟造成的等待重試×3 層串聯＋2 次故意造的 claim 失敗）。**e2e 級突變驗證 3 個全被抓到**（abandon 不 reject：39/46；retry 不重新武裝：40/46；不記原因：24/46）。**限度**：①單次執行、假 IdP、假 LLM、單機；②真實並發（兩個執行緒同時操作）仍只有單元層 mock 測試；③`claim_failed` 的「暫時性錯誤但 central 其實已 claim 成功」情形沒有實測（阶段 2 用撤銷裝置造永久失敗）；④relay 延遲只有一次量測（25 秒；間隔常數 30 秒）；⑤**`ops_notes/` 不在任何 git repo 內**（`openhands-governance/` 本身不是 repo），這支 e2e 與本設計文件沒有版本控制——與清單 1.18「e2e 放哪裡」同一個未決題。原計畫（保留）：e2e：每個動作至少一條真實路徑（claim_failed→abandon 後對話可再被治理；approval_cancelled_or_expired→abandon→本機 reject；report_failed→retry 的真實路徑若難製造，退為單元測試並明寫）。
6. **✅ 已完成（2026-10-13）CLI ＋ README**：`governance/needs_attention/governance_attention_cli.py`（只用標準庫；`list [--json]`、`resolve <id> retry|abandon|dismiss [--request-id] [--note] [--yes]`）、`governance/needs_attention/README.md`、`tests/agent_server/test_governance_attention_cli.py`（35 個，對著本機真 HTTP 假伺服器記錄實際送出的請求）。**設計重點**：session key 只從環境變數讀（`OH_SESSION_API_KEYS_0`／`SESSION_API_KEY`，與伺服器同名）、不印出、不經命令列、不以明文 http 送往非本機位址、不跟隨轉址；`resolve` 一定引用操作者看過的 `request_id`（不給 `--request-id` 時先顯示紀錄並詢問，引用它剛顯示的 id；`--yes` 必須搭配 `--request-id`）。**CLI 單元層突變 9 個全被抓到**（拿掉明文 http 檢查、`--yes` 免 id、不再詢問、不檢查允許動作、跟隨轉址、dismiss 不要 note、引用錯的 id、伺服器拒絕卻 exit 0、不送 key）。過程中抓到兩個我自己的測試問題：標頭名查找區分大小寫（`urllib` 送出 `X-session-api-key`）；「不跟隨轉址」測試的 302 沒帶 `Location`，拿掉防護也不會失敗——改成帶 `Location` 後才有效。**真實 e2e 新增 CLI 情境，全套 57/57**（含 `list`、帶 id 的 dismiss、問答式 abandon〔回答 y〕、回答 n 不改任何東西、不允許的動作在詢問前就被拒、真實對話回 idle）。**未送小o 審查**，理由：CLI 與測試在 `ops_notes/`（不在任何 git repo），也無量化結論；**但它處理 session key，若之後要放進 repo，放進去前先送審**。**限度**：e2e 的 CLI 情境本身沒有做突變驗證（CLI 邏輯由單元層突變涵蓋；e2e 這段證明的是與真實伺服器的整合）；CLI 無分頁（清單端點也沒有）。
   - **後續（2026-10-13，搬進本 repo 前）**：已送小o 做安全審查（契約 v1.1），4 個 `confirmed`（皆 low）核對屬實並修正：打錯位置的 key（如 `--session-key`）被 argparse 印到 stderr；`--url` 帶 `user:pw@` 時連線錯誤回顯整個 URL；非數字 port 與 `?`／`#` 的 URL 驗證不足；回應無大小上限、形狀不對會丟 `KeyError`。我的測試在這過程中又暴露三個自己的問題（拒絕憑證的測試拿掉防護照樣通過、截斷檢查順序寫反、一個測試期待的措辭已被刻意改掉），皆由突變驗證抓出後修正。CLI 單元測試現為 **62 個**，新增防護的突變全被抓到；搬進 repo 時 e2e 的本機路徑改為可設定（`OHS_CENTRAL_DIR`、`OHS_CENTRAL_PYTHON`、`OHS_PG_BIN`）。
7. **（獨立 commit，可最後做或不做）S6 誤判**：首次 claim 的暫時性例外改為停留 `CLAIM_INFLIGHT` 交給 relay。**已讀到的後果**：relay 恢復 claim 成功後會 `_ensure_claim_redispatch_task` 自動執行該動作（約 797–815 行），即**呼叫端已被告知 `REJECTED_CLAIM_FAILED` 之後，動作仍可能稍後執行**（核准人已核准，行為上與核准一致，但對呼叫端是意外）。動工前要再讀 `respond_to_confirmation` 呼叫端如何處理 `REJECTED_CLAIM_FAILED`，必要時改回傳新結果。**小o 審查（confirmed，medium）補充了漏掉的一點**：`run_and_wait_for_start` 對相同 `binding_fingerprint` 無條件重用既有 handshake、包括已完成的 future（`event_service.py` 約 2834–2851 行；程式註解寫明這是刻意的，用來防止已消耗的核准變成可重放的執行憑證），relay 成功後不會更新或失效它。所以同一行程內，之後對同一 binding 的重試會**永久重播舊的 `REJECTED_CLAIM_FAILED`**，即使動作已被 relay 執行完畢。不能為此直接放寬重用規則（那是防重放設計）。動工前要決定：relay 恢復成功時以受控方式更新 handshake 結果，或維持現狀並在文件與 API 回應說明「以 outbox 狀態為準」。這一步因此有兩個未決點，**未決前不動工**。

   **步驟 7 實作（2026-10-13，分支 `feat/transient-claim-retry`，Roy 拍板選項 1）**：Roy 的規則：「遇到暫時性錯誤可以告知使用者進行重試；若重試兩次後一樣發生問題，請找 superadmin 釐清」，確認「兩次」＝第一次失敗＋重試一次再失敗；不做系統自動重試、不改 Canvas UI。做法：新原因 `claim_transient`（第一次失敗；動作矩陣 retry／dismiss，**沒有 abandon**——暫時性失敗時 central 可能已 claim、只是回應掉了）與 `claim_retry_failed`（重試後又失敗；只有 dismiss）；新欄位 `claim_failures`（為零時不寫入檔案，維持降版相容）。互動路徑（`_claim_and_run_governed`）只有 `GovernancePermanentError` 仍記 `claim_failed`，其餘例外記 `claim_transient`；relay 的 CLAIM_INFLIGHT 暫時性失敗：`claim_failures` 為 0 時照舊每輪重試（崩潰復原），≥1（操作者已重試過）則停止並記 `claim_retry_failed`。**兩個未決點的處理**：①動作稍後被 relay 執行而呼叫端已被告知 502——維持現狀，API 回應與 README 改為明說「以 outbox 為準」；②handshake 快取對同一 binding 永久重播舊的 `REJECTED_CLAIM_FAILED`——**不放寬**（那是防重放設計），同樣以 outbox 為準。

## 6. 驗證計畫

- 每個進入點一個測試：寫入的 reason／error_code 正確。**突變**：把 `mark_needs_attention` 改成不寫 reason，測試必須失敗。
- 動作矩陣：表中每個 ✗ 都有一個 409 測試；突變：把 `report_failed` 的 abandon 打開，測試必須失敗。
- `expected_request_id` 不符 → 409，且記錄未被改動。
- 掃描：損毀 JSON 出現在清單、不使清單 500。
- e2e：沿用 `e2e_device_binding.py` 的 harness（臨時 Postgres 54329、假 IdP、真 agent-server）。

## 7. 未知與風險

- 卡死推論未重現（步驟 1 處理）。
- retry 後 relay 重送是否真的不會重複執行：只靠既有 idempotency key 與 `execution_attempt_id` 守衛，未逐條驗證。
- 多行程、同一 conversations 目錄被兩個 agent-server 共用：不處理。
- abandon 對「central 已 accepted 但從未 claim」的 central 端狀態：沿用既有 cancel→abort 退路，e2e 只涵蓋一種真實組合。
- 共用金鑰無操作者身分（見 §4）。
