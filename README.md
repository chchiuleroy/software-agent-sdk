# central-governance-api

OHS 治理平台的中央治理 API — Phase 1 接路由設計 v11 §3。唯一持有 PostgreSQL
憑證的獨立服務；桌面端 agent-server 一律走 REST + OIDC bearer token，不直連
DB。設計全文見 `roy_km` wiki `project_openhands_governance_platform.md`
「Phase 1 接路由設計」章節。

刻意是獨立的 uv 專案（不是 `openhands-sdk-governed` 的一部分）——這個服務有
自己的資料庫、自己的信任邊界，repo 根目錄的 `AGENTS.md` 也明講這類服務屬於
「不同的 repo/service」，不歸 `openhands-agent-server` 管。

## 目前狀態（v11 §11 第 2 步已完成）

已完成（第 1 步，骨架）：
- FastAPI app 骨架（`src/central_governance_api/main.py`）
- 獨立、async 的 OIDC bearer-token 驗證層（`auth/oidc.py` + `auth/dependencies.py`），
  重用 Phase 0 `oidc_principal.py` 的驗證邏輯與測試風格，補上 v11 第 8-11 輪
  審查要求的修正（negative-kid cache、固定演算法、token 長度上限、azp
  allowlist、log 衛生）
- PostgreSQL schema（`models.py`）+ 手寫 Alembic migration（`alembic/versions/`）
  ——涵蓋 v11 §4/§5 的 `PendingApprovalRecord`／`ApprovalDecision`／
  `ReconciliationFinding`，§2 的 `DeviceRegistration`／denylist，§3 的
  `AdminAuditEvent`／`IdempotencyRecord`

已完成（第 2 步前半，純邏輯——零 DB／HTTP 依賴，`approvals/` 子套件）：
- 狀態機（`approvals/state_machine.py`）：`ApprovalStatus`/`ApprovalEvent` +
  `(狀態,事件)→狀態` 轉移表
- RBAC 授權矩陣（`approvals/authorize.py`）：`authorize_create()` +
  `authorize_on_record()`，角色 × ownership 組合判斷
- 兩份模組皆已委派小o（`codex exec --sandbox read-only`）唯讀審查一輪並依
  結論修正——修正重點：`late_report` finding 從 `RECONCILE_AS_REQUESTER`
  拆成獨立的 `RECONCILE_LATE_REPORT` action（admin 不該能冒充原始執行端）、
  補齊「owner 但無角色」「admin 疊加 operator 角色仍須 ownership」等測試、
  狀態機測試改用精確集合比對（原本只驗證「非空」，抓不到誤加的非法轉移）。
  完整審查記錄見 `roy_km` wiki `concept_delegation_override.md`
- 100 個測試全過（27 骨架 + 73 新增），ruff/pyright 皆 0 issue（此為狀態機／
  RBAC 純邏輯階段的數字；接上 router 後的總數見下方）

已完成（第 2 步後半，`routers/approvals.py`——真實 conditional-update SQL）：
- `POST /api/v1/approvals`（create）／`.../decide`／`.../claim`／
  `.../report-result`（pre-claim abort 與執行結果回報兩種形狀）／
  `.../cancel`／`.../reconciliation-findings`，每個都是「idempotency 檢查
  →載入紀錄→授權→狀態機合法性檢查→單一 conditional UPDATE→旁支寫入→
  記 idempotency→單一 commit」同一套流程，狀態轉移的原子性完全由
  `UPDATE ... WHERE status = <expected> RETURNING id` 的 0-row 結果保證，
  不是靠應用層邏輯
- digest 驗證（`approvals/digest.py`）：僅在 create 時做，伺服器重新計算
  `action_type`/`tool_name`/`policy_revision`/`action_summary`/
  `action_payload`/`digest_salt` 的雜湊，比對呼叫端提交的
  `action_payload_digest`，不符直接 400——這是 v11 round-10 Critical
  （digest 未綁定 approver 實際看到的內容）在本服務可驗證範圍內的落地
  方式，完整推理與已知侷限見該模組 docstring
- idempotency 強制（`approvals/idempotency.py`）：`(principal, endpoint,
  resource_id, idempotency_key)` 四元組，命中即原樣回放，key 重複但內容
  不同回 422
- 例外對應（`main.py`）：`AuthorizationDeniedError→403`／
  `IllegalTransitionError→409`／`ConcurrentModificationError→409`／
  `ExecutionAttemptMismatchError→409`／`RecordNotTerminalError→409`／
  `RecordNotFoundError→404`／`DigestMismatchError→400`／
  `IdempotencyKeyReusedError→422`，統一掛 FastAPI exception handler，比照
  `openhands-sdk-governed` 的 `SelfApprovalDeniedError` 模式
- **這批端點是真的接了 Postgres 驗證過的**（本機臨時起了一顆獨立
  PostgreSQL 17 測試叢集，跟 Keycloak 用的正式服務完全分開，跑完
  `alembic upgrade head` 後對它送真實請求）——過程中抓到 2 個純
  mock/靜態檢查絕對抓不到的真 bug：① `ApprovalDecision.decision` 寫入時
  用了 wire-level 動詞（`accept`/`reject`）而非 DB CHECK constraint 要求
  的過去分詞（`accepted`/`rejected`），撞 `ck_decision_value` 直接
  `IntegrityError`，已修正加映射表 ② 兩個測試案例本身的假設錯誤（一個
  誤判 idempotency scope、一個誤判「連續呼叫同一 session」等同「真正併
  發」），跑了才發現預期值錯了，不是程式碼錯
- 21 個整合測試（`tests/test_approvals_router.py`）+ 既有 100 個純邏輯
  測試，`tests/conftest.py` 新增 `db_session` fixture（SAVEPOINT-based
  隔離，讓 router 自己呼叫的 `session.commit()` 真的執行、但測試結束仍
  乾淨 rollback）；沒有可用測試 DB 時（未設定 `CGA_DATABASE_URL`）這批
  測試會乾淨 `skip` 而非報錯，不影響 README 既有 `uv run pytest tests/`
  流程

**委派小o（`codex exec --sandbox read-only`）唯讀審查一輪，抓到 3 個
High + 3 個 Medium，全部已修正**：
1. **[High]** `idempotency.py` 的 docstring 宣稱「併發的輸家會在 unique
   constraint 衝突後改做 replay 查詢」，但 router 從未真的實作這段
   catch/retry 邏輯，只是文件描述、程式碼沒做——已加
   `_commit_or_replay()` helper，捕捉 `IntegrityError` 後 rollback 並重
   查 replay；此路徑本身仍缺真正跨連線併發測試（見下方誠實範圍）
2. **[High]** `decide` 的 conditional UPDATE 只檢查 `status`，沒檢查
   `expires_at`——期限過了但背景 sweep（第 3 步，尚未實作）還沒跑到時仍
   可被決策——已在 WHERE 子句補 `expires_at > now`，並新增
   `test_decide_after_expiry_is_rejected_not_silently_accepted` 直接
   驗證（用 `db_session` 手動把 `expires_at` 改到過去，不需要真併發）
3. **[High]** `report-result` 的執行結果分支同樣沒檢查
   `executing_lease_expires_at`，可能讓過期未回報的 lease 仍然回報成
   `applied`/`failed_definite`，違反「crash 後無法確認就 fail closed」
   的既定原則——已補 WHERE 條件，新增
   `test_report_result_after_lease_expiry_is_rejected` 驗證
4. **[Medium]** digest 模組的 docstring 補上明確的威脅模型限制聲明：只
   在「requester 裝置與執行端是同一信任域」（現行 Track 1 架構下成立）
   前提下有效，不防「請求者裝置本身被入侵後貌合神離地執行不同 canonical
   payload」——這是既有限制的明確化，不是新程式碼
5. **[Medium]** `ReportResultRequest`（及其他所有 request model）補
   `extra="forbid"`——原本欄位拼錯會被 Pydantic 靜默丟棄，兩個真欄位都
   變成「未設定」，會被誤判成合法的 pre-claim abort；新增
   `test_report_result_rejects_unknown_fields` 驗證
6. **[Medium]** pre-claim abort 與一般 cancel 共用 `cancelled` 這個終態，
   但原本沒有留下任何區分兩者的紀錄——已在兩條路徑各自補
   `AdminAuditEvent`（`event_type` 分別為 `approval_pre_claim_abort`／
   `approval_cancelled`），新增
   `test_cancel_and_pre_claim_abort_leave_distinguishable_audit_rows` 驗證

**誠實範圍（這批測試沒證明的事）**：`ConcurrentModificationError`（conditional
UPDATE 的 0-row 分支）與新加的 `_commit_or_replay()` 併發回退路徑，目前
都只靠程式碼審查與型別檢查保證正確，沒有真正的跨 transaction 併發測
試——SAVEPOINT 隔離這招本身讓同一測試檔案內無法模擬「兩個真正同時進行的
請求」，要驗證這兩條路徑得另外開一支犧牲隔離乾淨度的測試（真實 commit +
第二個獨立連線），這次沒做。

已完成（第 2 步剩餘部分，`routers/devices.py` + `routers/audit.py`）：
- `POST /api/v1/devices/register`：任何已驗證身份皆可自行註冊（裝置清冊
  本身不是安全控制，見 `models.DeviceRegistration` docstring，不需要角色
  門檻），`owner_subject` 一律伺服器端塞入。`device_id` 全域唯一（非
  per-owner），撞到既有 row（不論是否已撤銷，撤銷只是 soft-revoke，行永
  遠佔著這個 `device_id`）回 409 `device_already_registered`
- `POST /api/v1/devices/{registration_id}/revoke`：owner 本人或 `governance.admin`
  皆可撤銷（跟 `approvals` 的 CANCEL 同款 admin bypass 理由：撤銷不需要
  代替誰執行任何動作）。成功後同一交易內寫入 `DeviceDenylistEntry`（防止
  同一 `(owner, device_id)` 之後偷偷用 register 復活）+ `AdminAuditEvent`
  （`event_type="device_revoked"`）
- `GET /api/v1/audit-events`：`governance.admin` 限定，支援
  `event_type`／`approval_request_id` 篩選 + offset/limit 分頁（多取 1
  筆判斷 `next_offset`，不用額外 `COUNT(*)`）
- 兩個小重構（第二輪委派審查前先做，避免新舊兩份重複程式碼各自漂移）：
  `_commit_or_replay()` 從 `routers/approvals.py` 私有函式搬到
  `approvals/idempotency.py` 變成公開的 `commit_or_replay()`（`devices.py`
  需要一模一樣的邏輯）；`_now()` 搬到新檔案 `clock.py`（`now_utc()`），
  兩個 router 共用同一份「用 app clock 不用 DB clock」的取捨說明；
  `approvals/schemas.py` 的 `_RequestModel`（`extra="forbid"` 基底類別）
  搬到新檔案 `schemas_base.py` 變成公開的 `RequestModel`，`devices.py`
  的 request model 也繼承它。三個重構皆先跑過全測試確認無回歸，才繼續往
  下寫新端點
- 13 個新整合測試（`tests/test_devices_router.py` 10 個 + `tests/test_audit_router.py`
  3 個），涵蓋 duplicate device_id／denylist 擋復活／owner vs admin vs
  第三方三種撤銷授權／已撤銷再撤銷的 409／分頁

**134 個測試全過**（100 純邏輯 + 34 真實 DB 整合），ruff/pyright 皆 0 issue。

**委派小o（`codex exec --sandbox read-only`）唯讀審查一輪，抓到 1 個
High + 2 個 Medium + 2 個 Low，全部已修正**：
1. **[High]** register／revoke 在相同 idempotency key 真正併發重送時，
   會誤判成「device_id 已註冊」／「已撤銷」的衝突，而不是回放既有結果
   ——PostgreSQL Read Committed 語意下，後到的請求會等前一個 transaction
   commit 後才重新判斷 WHERE/UNIQUE constraint，此時看到的是「已存在」
   而非「我自己的併發重試」。已在 `approvals/idempotency.py` 新增
   `check_replay_or_raise()`（先查是否為同一 idempotency key 的既有回應
   再決定要不要真的報衝突），register 的 `flush()` except 與 revoke 的
   0-row 分支皆已套用；此路徑本身仍缺真正跨連線併發測試（跟
   `commit_or_replay()` 當初的已知缺口同款限制，SAVEPOINT 隔離測不出真
   併發）
2. **[Medium]** `device_id` 沒有格式限制，空字串／含 `/`／`?`／`#`／空白
   都能寫入且全域永久佔用 namespace，卻可能無法透過 revoke 的路徑參數定
   址——已加 pattern 限制（非空、URL-safe 字元、上限 64 字元），register
   的 schema 與 revoke 的路徑參數皆套用，新增
   `test_register_rejects_malformed_device_id` 參數化測試 7 個案例驗證
3. **[Medium]** 零角色即可註冊裝置的推論只處理了「是否授予能力」，沒處理
   「資源濫用／namespace 搶占」——**這是真實安全面向的產品/政策決定，不
   是機械式修法**，故意不在這輪單方面決定配額或改變 device_id 唯一性範
   圍，已在 `routers/devices.py` module docstring 明確揭露此已知缺口留
   給 Roy 判斷
4. **[Low]** revoke 對「裝置不存在」與「裝置存在但不是你的」原本回不同
   狀態碼（404 vs 403），任何已驗證身份都能藉此枚舉裝置清冊——已改成非
   owner/非 admin 一律回 404（無法區分兩種情況），移除因此變成死代碼的
   `DeviceAuthorizationDeniedError`，新增
   `test_revoke_by_non_owner_non_admin_is_masked_as_404` 直接比對兩種情
   況回應完全相同
5. **[Low]** audit-events 分頁本身「多取 1 筆判斷 next_offset」邏輯沒有
   off-by-one，但 offset-based 分頁在有新事件持續寫入時天生不穩定（不是
   這次的 bug，是這個分頁方式的固有限制，已在 `audit.py` docstring 明講
   取捨、未改用 cursor-based 分頁）；原本的分頁測試只驗證第一頁形狀、從
   沒真的走訪下一頁，已改寫成真正走訪到 `next_offset is None` 為止並驗
   證總數不重複不遺漏

審查過程也**順便修正一個跟這批端點無關的既有缺口**：`Idempotency-Key`
header 在所有 write 端點（含既有的 `approvals` 六端點）原本都沒有跟
`IdempotencyRecord.idempotency_key`（`String(128)`）欄位對齊的長度限
制，過長的 key 只會在 DB 寫入時炸開，不會在請求驗證階段乾淨拒絕——新增
共用的 `http_params.py`（`IdempotencyKeyHeader` annotated 型別），
`approvals.py`／`devices.py` 全部端點統一改用。

**141 個測試全過**（100 純邏輯 + 41 真實 DB 整合），ruff/pyright 皆 0 issue。

尚未開始：`wait`（第 3 步，LISTEN/NOTIFY）。

## `(issuer, sub)` 身份欄位拆分 + devices 配額/範圍修正（已完成，2026-09-15）

兩項先前「待 Roy 拍板」的項目，Roy 拍板後同一輪一起做（兩者都動 schema，同一
次 migration 比較有效率）：

**身份欄位拆分**：`requester_subject`／`decision_actor_subject`／
`verifier_subject`／`actor_subject`／`owner_subject`／`revoked_by_subject`／
`scope_principal` 等欄位，原本都只存 `Principal.subject`（`f"{issuer}#{sub}"`
拼接字串），現在全部拆成 `*_issuer`／`*_sub` 兩欄，安全性比對（self-approval
檢查、ownership 檢查）也全部改成 `(issuer, sub)` tuple 比對，不再比字串。
影響範圍：`models.py` 七張表、`approvals/authorize.py`
（`ApprovalOwnership`）、`approvals/idempotency.py`（所有函式的
`principal_subject` 參數拆成兩個）、`routers/approvals.py`／
`routers/devices.py`／`routers/audit.py` 全部呼叫點。HTTP 回應層級刻意不變
——回應仍回傳單一 `xxx_subject` 字串欄位（router 端用
`f"{issuer}#{sub}"` 組出來），只有 DB 儲存與安全比對層改變，API 呼叫端無感。
因為這個 repo 尚未接上任何真實資料庫，直接改寫既有的 initial migration，不
另開一支 follow-up migration。

**devices 配額與範圍**：Roy 三選一（配額 / 系統產生 ID / per-owner 範圍）拍板
「per-owner 範圍 + 配額」，明確不做系統產生 ID（呼叫端自訂名稱對 admin 稽核
更有用，且目前沒有任何安全邏輯依賴 device_id 的不可預測性）：
- `device_registrations.device_id` 唯一性從全域改成 `(owner_issuer,
  owner_sub, device_id)` 複合唯一——這本身也是修正一個既有內部不一致：
  `DeviceDenylistEntry` 原本就是 per-owner 設計，只有主表是全域，兩者現在一致
- 新增 `config.device_registration_quota`（預設 20，含已撤銷的累計筆數，因為
  撤銷不釋放 row）
- **per-owner 範圍改變帶出一個原本沒設計好的問題**：revoke 端點原本用
  `device_id` 字串當路徑參數，但 per-owner 唯一性下，兩個不同 owner 可以有同
  一個 `device_id`（如都叫 "laptop"），revoke 若還用 `device_id` 定址會有歧
  義——改成用註冊時回傳的伺服器 `id`（UUID）定址，跟 approvals 端點「路徑用
  伺服器 UUID，不用呼叫端自訂的 request_id」同一個既有慣例
- 兩個小重構順手做：`_get_settings` 從 `routers/approvals.py` 私有函式搬到
  `config.py` 變成公開的 `get_settings_dependency()`（`devices.py` 配額檢查
  也需要）

10 個新／修改測試（duplicate device_id 分成 same-owner 409／different-owner
成功兩支、配額測試用自訂低配額的獨立 app instance、revoke 全面改用
registration id）。**144 個測試全過**（100 純邏輯 + 44 真實 DB 整合），
ruff/pyright 皆 0 issue。

**委派小o 唯讀審查這批 identity-split/quota 變更，抓到 0 個 High + 2 個
Medium + 4 個 Low，全部已修正**：
1. **[Medium]** 配額檢查的 `SELECT count(*)` 與後續 INSERT 不是原子操作——
   PostgreSQL 預設 Read Committed 隔離下，不同 `device_id` 的併發註冊請求
   可能都讀到同一個計數、都通過檢查、都成功插入，超額幅度可能遠大於「略
   微超過」。這是真正的資源上限（不是統計近似），已在 `register_device`
   加上以 `(issuer, sub)` 為鍵的 transaction-scoped advisory lock
   （`pg_advisory_xact_lock`，`devices.py` 的 `_quota_lock_key`），讓同一
   principal 的併發註冊序列化而非互相競爭。新增
   `test_register_quota_race_is_prevented_by_advisory_lock`
   ——這支測試特意不用共用的 SAVEPOINT 隔離 `db_session` fixture（單一
   session/連線本來就無法產生真正的併發 commit），改用自己的真實
   engine/session-factory 對同一個測試資料庫發出 12 個真正併發的註冊請
   求，驗證恰好只有配額筆數（5）成功、其餘全部 429，測試結束後自行清除
   寫入的 row（不能依賴 fixture 的 rollback）
2. **[Medium]** README（本檔案）revoke 端點路徑仍寫著舊的 `{device_id}`，
   跟改成 `{registration_id}` 後的實作不一致——已修正
3. **[Low]** 新增的 identity-split 測試全部只用單一 issuer，抓不到「拼接
   字串比對」這個舊 bug 類型的迴歸——`test_authorize.py` 新增
   `test_same_sub_different_issuer_is_not_owner`（同 sub 不同 issuer 不是
   owner）與 `test_concatenated_subject_collision_does_not_confer_ownership`
   （建構一組拼接字串會碰撞、但 tuple 不同的案例，證明新比對方式正確處
   理舊比對方式會出錯的情境）；`test_devices_router.py` 新增
   `test_revoke_same_sub_different_issuer_is_not_owner`（直接寫入一筆不同
   issuer 的 DB row，因為這個部署的 OIDC resolver 只信任單一 issuer，
   HTTP 層面產生不出第二個 issuer 的 principal）
4. **[Low]** 配額測試原本只涵蓋循序 happy path——新增
   `test_register_quota_isolated_per_owner`（不同 owner 配額互不影響）、
   `test_register_quota_still_counts_revoked_devices`（撤銷不釋放配額，
   驗證 config.py docstring 的既有宣稱）
5. **[Low]** `authorize.py`／`devices.py`／`test_devices_router.py` 三處註
   解仍描述舊欄位或舊路由語意（`requester_subject` 拼接字串寫法、revoke
   仍用 `device_id` 定址的過時說明）——已更新成當前實作
6. **[Low]** `config.device_registration_quota` 沒有正值限制，0 或負值會
   讓所有註冊都被判定超額（fail-closed，安全但可能因設定錯誤導致誤觸發
   的服務中斷）——已加 `Field(gt=0)`

新增 6 個測試：`test_authorize.py` 2 個純邏輯 issuer 邊界測試、
`test_devices_router.py` 4 個真實 DB 整合測試（issuer 邊界 1 個、配額隔離
1 個、撤銷仍計入配額 1 個、配額併發競爭 1 個）。**150 個測試全過**（102
純邏輯 + 48 真實 DB 整合），ruff/pyright 皆 0 issue。

**第五輪確認性審查改用 Codex 桌面 App**（`codex exec` CLI 連續兩次背景
執行後無實質輸出，第一次卡在自己嘗試用 `rg` 搜尋自身 memory 檔案但環境無
`rg` 可執行檔，第二次連 hook 都跑完卻無回應——依既有 CLI 卡住降級路徑改
用 computer-use 操作桌面 App），**抓到 advisory lock 修法本身引入的 1 個
新 Medium + 1 個 Low**：
1. **[Medium]** 配額滿載時，兩個帶同一 idempotency key 的併發重試若卡在
   advisory lock 上，後到者取得 lock 後重新計算配額會看到「已滿」，直接
   拋 429，而非回放先到者的成功結果——原本的 `find_replayed_response()`
   只在 lock 之前查一次，取得 lock 之後沒有再查，破壞了 idempotency 機
   制的核心保證。已在 `register_device` 取得 lock 後、算配額前，再呼叫
   一次 `find_replayed_response()`
2. **[Low]** 併發測試沒有保證請求真的在 count 區段重疊

新增的確認測試 `test_register_quota_race_same_idempotency_key_replays_not_429`
第一版用 `asyncio.Barrier` 卡住每個 request「第一次」呼叫
`find_replayed_response()`，實測發現在 pytest-asyncio 下即使還原掉修
法，該測試仍穩定通過（asyncio 排程讓某個 task 在其他 task 發出第一次查
詢前就已跑完整個 lock→count→insert→commit）——同一份邏輯改用普通
`asyncio.run()` 腳本測卻能穩定重現 bug，證明是測試本身的假通過風險。改
把 barrier 卡在真正的 `pg_advisory_xact_lock` 呼叫本身（monkeypatch
`AsyncSession.execute`，偵測 SQL 字串含 `pg_advisory_xact_lock` 才卡），
靠 Postgres 自己的互斥鎖保證同時性。連續驗證 3 次：還原修法前穩定
3/3 fail，還原後穩定 3/3 pass。commit `9b0c45f`，**151 個測試全過**
（102 純邏輯 + 49 真實 DB 整合），ruff/pyright 皆 0 issue。

**第六輪確認審查**（同一 Codex 桌面 App session）確認這批修正**無
Critical/High/Medium**，僅 2 個不阻塞的 Low：測試 docstring 仍描述已淘
汰的第一版作法（barrier 卡 `find_replayed_response`，實際已改卡
`AsyncSession.execute`）；barrier 缺少 timeout，若未來某 request 在抵達
lock 前先失敗，其餘 task 會永遠等不到完整 barrier parties。已修正：更新
docstring 反映目前實作，`gather` 外包 `asyncio.wait_for(timeout=10)`。
commit `6d0efbb`，151 測試全過，ruff/pyright 皆 0 issue。**至此五輪委派
審查全部收斂，v11 §11 第 2 步含兩項待拍板決策全部完工。**

## 開發

```bash
uv sync
cp .env.example .env   # 填入真實 OIDC/DB 設定
uv run pytest tests/
uv run ruff check . && uv run ruff format --check .
uv run pyright
```

## 部署前置條件

寫任何會真正連上正式資料庫的程式碼前，先確認 v11 §3「強制部署條件」
（15 條）已經落實——獨立低權限 service account、PostgreSQL ACL 限制、DB
拒絕桌面端直連等。這個 repo 目前只是骨架，還沒到需要那些條件生效的階段。
