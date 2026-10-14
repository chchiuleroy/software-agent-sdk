# 崩溃恢復與「至多執行一次」（OHS 1.16）

日期：2026-10-14　狀態：**已實作（只有測試與本文件，產品碼零變更）**
plan-gate 兩關 Roy 皆核可：1.16 原本的內容（在 central 或 digest 加 replay 類別欄位）**沒有做**，改成「先查完整恢復路徑、把現有的『至多執行一次』鎖住」。

## 0. 範圍與限度

- **來源**：讀程式碼（`event_service.py`、`governance_outbox.py`、`local_conversation.py`、`roy_action_binding.py`、central 的 `approvals/state_machine.py`）＋四個崩潰模擬測試（`tests/agent_server/test_governance_crash_recovery.py`）。
- **測試是什麼**：真實的 `EventService`＋真實的 `LocalConversation`＋真實的磁碟事件日誌與 outbox，只有 `GovernanceClient`（網路）是假的、工具執行器被包成計數間諜、LLM 不准被呼叫。「崩潰」＝取消第一個實例的背景任務、不關閉、讓它的租約過期，再在同一個目錄起第二個實例。
- **relay**：真實的 relay 迴圈第一次要等 30 秒（`GOVERNANCE_OUTBOX_RELAY_INTERVAL_SECONDS`），測試等不了，所以在每個現場之後用 `_relay_outbox_once()` 手動驅動兩個週期；C0 還把 outbox 退回 `CLAIMED`（模擬進度標記那次寫入遺失）再驅動 relay。**限度**：我沒能做出一個只會讓這些 relay 斷言失敗的突變（工具只會執行「未配對」的動作，所以動作已配對後 relay 重新派發本來就執行不到工具），它們是把「relay 路徑也走過」補進證據，不是新的承重測試；承重的是 C1 的 `await` 突變。
- **沒做的**：沒有真的殺 OS 行程；沒有對真實 central 跑；只在 Windows 實跑；對話狀態 `RUNNING`「在工具執行前落盤」這件事是**讀程式碼**得到的（見第 4 節），測試是直接把狀態設成 `RUNNING` 來造現場，沒有測落盤時點本身。
- 中途更正：Gate 1 時我以為重啟後不重複執行靠的是「派發任務建立在 `AgentErrorEvent` 之前」的先後；實測後不是，真正的防線見第 2 節。

## 1. 結論

現在對**所有**動作都是「至多執行一次」：崩潰時被打斷的動作得到一個不可重試的 `AgentErrorEvent`，不會被重跑；agent 若還要做同一件事，是發出**新的**動作、走**新的**核准。central 一次核准只有一個 `execution_attempt_id`，沒有重新 claim 的路徑。所以沒有任何「重放」，1.16 要保護的東西（「重放類別只能收緊」）目前沒有東西可放寬，**不是缺陷**。觸發條件仍是：有人要開放第一個可重放的 action class。

## 2. 為什麼崩潰後不會執行第二次（三道防線）

| # | 防線 | 在哪裡 |
|---|---|---|
| P1 | 持久化的對話狀態仍是 `RUNNING` 時，`EventService.run()` 直接拒絕（`conversation_already_running`） | `event_service.py` `run()` 開頭 |
| P2 | `start()` 把 `RUNNING` 改成 `ERROR`，並寫入與被打斷動作配對的 `AgentErrorEvent`，**這兩步之間沒有 `await`**；所以沒有任何 `run()` 能看到「狀態不是 RUNNING、但動作還沒配對」的瞬間 | `event_service.py` `start()`（`execution_status = ERROR` 到 `_on_event(error_event)`） |
| P3 | 綁定檢查要求恰好一個符合的待執行動作；動作已有 `AgentErrorEvent` 配對就是 `ActionCountMismatchError`，被拒絕 | `roy_action_binding.check_action_binding`，由 `LocalConversation.run()` 呼叫 |

**不是防線的東西**（容易誤以為是）：
- central 的執行租約（預設 **300 秒**，`approval_execution_lease_seconds`）：重啟在 5 分鐘內時租約仍有效。
- outbox 的 `EXECUTION_STARTED`：只是給 central 看的進度標記，且落盤是盡力而為（見 `_dispatch_claimed_run` 的 `_on_start` 註解）；崩潰時 outbox 可能還停在 `CLAIMED`。
- 派發任務建立在 `start()` 的哪個位置：P1 擋住它在 `RUNNING` 時啟動。

**實測 P2 是承重的**：在 `start()` 的 `ERROR` 賦值與 `AgentErrorEvent` 之間人為插入 `await asyncio.sleep(0.5)`，測試 C1 立刻失敗——工具執行器被呼叫了一次，同時 central 還收到 `failure_unknown`（兩邊互相矛盾）。這是目前最脆弱的一點：它靠「兩步之間沒有 await」這個沒有被任何註解或型別保護的事實。

## 3. 崩潰現場表

| 現場 | 磁碟上的狀態 | 重啟後 | central 看到 | 測試 |
|---|---|---|---|---|
| C0 | 對話 `WAITING_FOR_CONFIRMATION`、outbox `CLAIMED`、動作未配對 | 重新派發執行該動作**一次**（這是第一次執行，不是重放） | 之後正常回報結果 | `test_a_claim_without_a_started_run_is_executed_exactly_once` |
| C1 | 對話 `RUNNING`、outbox `CLAIMED`（進度標記沒落盤）、動作未配對 | 寫 `AgentErrorEvent`；重新派發被拒；**不執行** | `failure_unknown` | `test_an_interrupted_execution_is_not_executed_again[progress-marker-never-landed]` |
| C2 | 同上但 outbox 是 `EXECUTION_STARTED` | 同上（`start()` 不會重新派發 `EXECUTION_STARTED`） | `failure_unknown` | `...[progress-marker-landed]` |
| C3 | 對話 `RUNNING`、動作已有 `ObservationEvent`（做完、回報前崩） | **不執行**；回報真實結果 | `success`（或 `failure_definite`），不是 `unknown` | `test_a_finished_action_is_reported_as_it_happened_not_as_unknown` |

**這四個測試沒有涵蓋**：outbox 停在 `PENDING_CREATE`／`CREATED`／`CLAIM_INFLIGHT`／`RESULT_PENDING`／`RECONCILIATION_PENDING` 的重啟。它們重試的是協定訊息（冪等鍵 `claim-<request_id>`／`report-<execution_attempt_id>`），不是動作本身，既有測試以 mock 涵蓋，這裡沒有用真實對話重做。

## 4. 「執行已開始」的持久證據

是**對話狀態 `RUNNING`**，不是 outbox。`LocalConversation.run()` 在 `check_action_binding` 通過後、`agent.step()` 執行工具之前，於同一個狀態鎖內賦值 `execution_status = RUNNING`；`ConversationState.__setattr__` 在 autosave 開啟時會把它寫盤。因此崩在工具開始之後，磁碟上一定是 `RUNNING`＋未配對的動作（C1／C2）；崩在開始之前，是 `WAITING_FOR_CONFIRMATION`（C0）。**限度**：「賦值就落盤」是讀 `state.py` 得到的，沒有測。

## 5. central 端

`approvals/state_machine.py` 的 `_TRANSITIONS` 裡，`CLAIM` 只有一條：`ACCEPTED + CLAIM → EXECUTING`。`EXECUTING + EXPIRE → FAILED_UNKNOWN`（租約到期沒回報），之後只能用 `late_report`（見清單 1.10）補真相，沒有再次 claim。所以即使裝置想重放，central 也不會發第二個 `execution_attempt_id`。

## 6. 將來開放可重放的 action class，要改什麼

1.16 原本的兩個選項，**仍未決定**：
1. 放進 `execution_binding`，digest 涵蓋「核准的動作允許重放」：代價是改 digest 格式與 wire contract。
2. 只存在 central 的 claim 紀錄、claim 時由 central 釘住，之後註冊表只能收緊不能放寬：代價是 central 需要 action class 對照表。

不論哪個，至少要同時改：central 要能發第二個執行嘗試；裝置恢復時要對該類別**不**寫 `AgentErrorEvent`、改走重新執行；核准要涵蓋「允許重放」這件事；P1、P2、P3 對該類別要有明確的例外並各有測試。規則參考 Pi Durable `docs/spec.md` §7.3（來自 `todo.md` 當時讀原文的紀錄，本次沒有重讀）：儲存的政策與目前宣告**都**是 safe 才重跑；目前宣告 unsafe 可以否決；目前宣告 safe 不能升級已儲存的 unsafe；解析不到視為 unsafe。

## 7. 怎麼重跑

```bash
.venv/Scripts/python.exe -m pytest tests/agent_server/test_governance_crash_recovery.py -p no:cacheprovider -q
```

突變驗證（各改一處、跑完還原，測試要失敗）：在 `start()` 的狀態賦值與 `AgentErrorEvent` 之間加 `await`→C1；不寫 `AgentErrorEvent`→C1、C2；停用 `_ensure_claim_redispatch_task`→C0；把 `_classify_governed_action_outcome` 的成功回報改成 `failure_unknown`→C3。
