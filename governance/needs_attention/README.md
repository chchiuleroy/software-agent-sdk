# 治理 outbox 卡住時怎麼處理（NEEDS_ATTENTION）

給操作者看的短說明。設計與審查歷程見同目錄的 `design.md`。

## 這是什麼問題

team 模式下，agent-server 每個對話有一個治理 outbox 紀錄。某些失敗（claim 被拒、回報被拒、central
把核准取消了…）之後，紀錄會停在 `needs_attention`：relay 不會再重試它，而且**這個對話之後的其他動作
也不會再被送去核准**，直到有人處理。沒有人處理就不會有任何動靜，所以要主動看一眼。

## 兩個指令

```bash
python governance_attention_cli.py list
python governance_attention_cli.py resolve <對話id> retry|abandon|dismiss [--request-id ID] [--note 文字] [--operator 名字] [--outcome 結果]
```

`--outcome`（只用於 dismiss）是你在中央確認到的結果：`confirmed_executed`（動作已執行）、`confirmed_not_executed`（動作沒有執行）、`inconclusive`（無法確定）。**只有 `list` 對該紀錄顯示 `outcomes` 時才能用**（動作可能已執行的原因：`report_failed`、`reconcile_failed`、`central_status_unexpected`、`late_report_refused`，以及原因未知的紀錄；動作不可能執行過的原因沒有可說的）。它會**先**以 `requester_assertion` finding 送到中央（證據含你宣告的名字；finding 只是證據，**不會改變核准的狀態**），中央收下才結束本機紀錄；中央不收（例如核准還沒到終態）就什麼都不改、回 424。同樣內容重送會重放同一筆；不同內容是新的一筆（finding 只追加）。

`--operator` 是你宣告的操作者名字（預設為本機登入名），**不是經過驗證的身分**；見下方「已知限度」。

設定（環境變數，或 `--url`）：

| 變數 | 說明 |
|---|---|
| `OH_AGENT_SERVER_URL` | agent-server 位址，預設 `http://127.0.0.1:8000` |
| `OH_SESSION_API_KEYS_0` | session API key（也讀 `SESSION_API_KEY`）。**只能用環境變數給**：不是命令列選項；不會被印出（打錯地方的內容，例如把 key 當成 `--session-key` 或對話 id 打進去，argparse 與錯誤訊息都不會回顯）；不會用明文 http 送往非本機位址；不跟隨轉址 |

`--url` 只能是 `http(s)://主機[:埠][/前綴]`：**不接受帶帳密（`user:pw@`）、`?query`、`#fragment`**；錯誤訊息只會顯示主機與埠，不會回顯其餘部分。伺服器的回應超過 4 MiB、被截斷、或形狀不符（例如版本不一致）時，會明確報錯而不是丟 traceback。

離開碼：`0` 完成、`1` 被拒絕（你回答 n，或伺服器拒絕）、`2` 用法／設定／連線問題。

## 三個動作，何時用哪個

先看 `list` 顯示的 `reason` 與 `allowed`——**清單只會列出該原因下安全的動作**。

| 動作 | 做什麼 | 什麼時候 |
|---|---|---|
| `retry` | 把紀錄推回 relay 會重做的狀態；**本身不送任何東西**，relay 約 30 秒內重做失敗的那一步（用原本的 idempotency key） | 失敗的原因已排除（例如 central 恢復、裝置重新可用） |
| `abandon` | 在 central 取消核准（已核准則做 pre-claim abort）、把本機待確認動作 reject、紀錄結束為 `cancelled`。**central 不同意就整個不做**，紀錄與對話都不動 | 不要這個動作了。只對「確定沒有執行嘗試」的原因開放 |
| `dismiss` | 紀錄結束為 `resolved_manually`，**沒有其他效果**，一定要寫 `--note` | 你已在別處處理好（或判斷不必處理）。對話可能**仍在等待**這個動作——輸出會警告，要自己 reject |

abandon 只對 `claim_failed`、`approval_cancelled_or_expired` 開放，因為其他原因的動作**可能已經執行過**。

### 暫時性的 claim 錯誤：重試一次，再失敗就找 superadmin

核准後的 claim 若因**可能只是暫時的原因**失敗（網路、5xx，任何不是 central 明確拒絕的錯誤），紀錄會停在：

| `reason` | 意思 | 你該做的 |
|---|---|---|
| `claim_transient` | 第一次失敗。**central 可能其實已 claim，只是回應掉了**，所以**沒有 abandon** | `resolve retry` **一次**（relay 約 30 秒內用同一個 idempotency key 重送，若 central 已 claim 會回同一個執行嘗試） |
| `claim_retry_failed` | 重試後又失敗（暫時性或永久皆算） | **不要再 retry**（清單也不再提供）。找 superadmin 查清楚發生什麼事；查清後可 `dismiss`（需 `--note`） |

central **明確拒絕**（例如 `device_not_bound`）仍是 `claim_failed`：不是暫時性，retry／abandon／dismiss 都可用。`list` 會在這兩個原因下多印一行 `next`。呼叫端（確認動作的 API）收到 502 `governance_claim_failed` 時，**動作有沒有執行以 outbox 為準**，不要以那個回應為準。

## 它不會讓你誤動別人的紀錄

`resolve` 一定引用你看過的 `request_id`：

- 給 `--request-id`：就用你給的。若紀錄在你看過之後變了，伺服器拒絕。
- 不給：CLI 先顯示該紀錄現在的樣子並問你，**引用它剛顯示的那個 id**。
- `--yes`（不問）一定要搭配 `--request-id`；沒有「對沒看過的紀錄盲目動作」的路。

## 已知限度

- **操作者是自我宣告，不是認證**：伺服器只認共用的 session API key，持有者可以寫任何名字。`operator`
  是必填欄位（1～64 字、只能是可見字元），abandon／dismiss 時存進紀錄的 `resolved_by`，三種動作都會寫進
  agent-server 的 log（名字以 repr 引用）。**retry 不留在紀錄裡**：retry 後紀錄回到流程中，沒有地方放，
  只有 log 一行。central 不會得知。
- **降版風險**：處理後的紀錄含新狀態 `resolved_manually` 與新欄位（`resolution_note`、`resolved_at`、
  `resolved_by`）；舊版程式讀不了。要退回舊版前，
  先確認沒有這種 outbox 檔（`list` 對讀不動的檔會顯示 `unreadable_outbox`）。
- 與「刪除對話」同時進行沒有處理。
- `list` 沒有分頁；預期待處理的很少。
- 這個 CLI 與本說明在 `governance/needs_attention/`；CLI 的單元測試在 `tests/agent_server/test_governance_attention_cli.py`。

## 怎麼驗證

```bash
# 單元測試（不需要 Postgres／central）
python -m pytest tests/agent_server/test_governance_attention_cli.py

# 真實端到端：真 agent-server＋真 central＋臨時 Postgres，約 5 分鐘。
# 前置條件與環境變數（OHS_CENTRAL_DIR、OHS_CENTRAL_PYTHON、OHS_PG_BIN）見腳本開頭說明。
python governance/needs_attention/e2e_needs_attention.py
```
