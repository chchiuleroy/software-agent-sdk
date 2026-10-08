# 部門工具權限（P2）— 設計 v1

狀態：2026-10-08 Roy 核可 Gate 1（方向 A：部門綁在 agent-server 的 service account）；Gate 2 的兩個確認問題 Roy 回「請繼續」，小c 採用自己的推薦（見下）。實作中。
範圍：central（本 repo）＋ agent-server／SDK（`openhands-sdk-governed`，另一個 PR）。P1 見 `account-requests-departments-design-v1.md`；P3（模型閘道）另案。

## 1. 已決定

- 部門權限按「工具」分類，allow-list：沒列入的工具一律不允許。
- central 看到的是 agent-server 的 service account，不是真人；所以 superadmin 把 service account 指派到部門（`department_principals`）。真人直接呼叫時，退而用 P1 綁定的 membership 查部門。
- 兩層：裝置端用快取的權限表先擋，central 於建立核准與 claim 時再確認。強制開關 `CGA_ENFORCE_TOOL_PERMISSIONS` 預設關。
- 子代理與主對話同一行程，自動沿用同一份權限。
- 小c 預設、Roy 未明確回覆（回「請繼續」）：快照過期後一律全拒（撤銷即時優先於 central 掛掉時的可用性）；「其他帳號向 superadmin 提出權限變更申請」這次不做。

## 2. central 介面

- 表：`department_tool_permissions`（主鍵 `(department_id, tool_name)`）、`department_principals`（`(issuer, sub)` 唯一）。migration `d5e9a2b7c3f1`。
- superadmin：`GET/PUT /api/v1/admin/departments/{id}/tools`（PUT 整組取代，名稱 `[A-Za-z0-9_.:-]{1,128}`，最多 200 個，無變更不寫稽核）；`GET/POST /api/v1/admin/departments/{id}/principals`、`DELETE .../principals/{assignment_id}`。
- 任何已登入者：`GET /api/v1/me/tool-permissions` → `{department_id, department_name, tools, revision, max_age_seconds}`。
- 強制：建立核准與 claim 都呼叫 `ensure_tool_permitted()`；不符回 403 `tool_not_permitted`。claim 也檢查，使建立後才撤銷的權限立刻生效。
- `tool_permission_max_age_seconds`（預設 600）是判斷值，非量測值。

## 3. 裝置端設計（agent-server／SDK）

低風險動作（例如工作區內的檔案編輯）不會進入「建立核准」，所以只在那裡擋工具擋不到它們。因此：

- SDK 新增行程層級快照模組；分析器 `security_risk()` 對未授權工具回 `HIGH`，強迫它走確認流程；
- `_create_governance_approval()` 在建立核准前，對未授權工具走既有的 `_refuse_unreviewable_action()`；
- 快照過期且更新失敗時，一律視為全拒；預設永遠允許的內建工具（如 `finish`）另列。

## 4. 已知限度

- 名稱是自由文字，打錯只會讓該工具沒被授權，不會報錯；central 不知道有哪些合法工具名。
- 同一工具內的動作差異（terminal 讀檔與刪檔）管不到。
- central 掛掉時，快照過期後連低風險動作也被擋。
- 被入侵的裝置可改本機判斷；central 的建立／claim 檢查是兜底，但只涵蓋會走核准的動作。
- 開關預設關：開啟前必須先把每個 service account 指派到部門，否則全拒。

## 5. 小o 審查後的修正（4 項 confirmed，小c 逐項回原始碼核對屬實）

- **裝置端檢查不依賴確認流程（high）**：分析器回 HIGH 只有在對話的確認政策真的會因 HIGH 而詢問時才有效；`NeverConfirm`、沒有分析器、或沒繼承分析器的子代理都不會走到 `_create_governance_approval()`。因此**權威檢查移到 `Agent._execute_action_event()`**（每個對話、含子代理，工具真正執行的地方）；分析器與 EventService 的檢查保留，只是讓核准人不必被問一個注定被拒的工具。
- **central 重放不得越過撤銷（high）**：建立與 claim 的 idempotent 重放原本在權限檢查之前就回傳先前的成功結果；claim 的重放就是執行租約。現在兩處重放前都先檢查權限。殘留：已收到首次 claim 回應的裝置，在撤銷後到租約到期之前仍可執行（claim 到執行之間的短窗口）。
- **整組取代的併發（medium）**：兩個並行 PUT 會各讀同一個「之前」集合而合併成誰都沒要的聯集；改為先對部門列加 `FOR UPDATE`。
- **啟動失敗洩漏（medium）**：`__aenter__` 中途失敗時不會呼叫 `__aexit__`；改為把取得 hold 放在 `__aenter__` 最後一步。
