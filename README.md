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

`wait`（第 3 步，LISTEN/NOTIFY）已完成，見下方新章節。

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

## `/wait` + 背景到期 sweep（v11 §11 第 3 步，已完成，2026-09-16）

v11 設計記錄本身對 `/wait` 的完整 wire contract 沒有留下逐字稿（只留下 wiki
的一句話：round-10 修過一個「LISTEN/commit 邊界」的 bug，沒留下修法本身長什
麼樣）——這一步的具體實作細節（channel 設計、race-safety 論證、authorization
矩陣）全部是依 PostgreSQL NOTIFY 本身的官方語意重新推導，不是照抄遺失的原文，
所有模組 docstring 都誠實標明這點。

**`approvals/notify.py`（新檔案）**：
- `notify_status_changed()`：在狀態變更的同一個 DB transaction 內呼叫
  `pg_notify()`——這是唯一需要遵守的正確性規則：Postgres 本身保證 NOTIFY 只
  在該 transaction **真的 COMMIT** 時才送達，ROLLBACK 則完全不送，所以只要
  永遠跟著同一筆 conditional UPDATE 放進同一個 transaction，就不需要額外的
  「LISTEN/commit 邊界」處理——這正是 v10 那個遺失的 bug 修法在做的事，只是
  用 Postgres 自己的保證重新推導出來，不是照抄
- `wait_for_status_change()`：**先註冊 LISTEN，再做「目前是否已經不同」的
  authoritative 讀取**，這個順序本身就是唯一的 race-safety 保證——LISTEN 註
  冊之後才 commit 的任何變更，保證會被送達（不論是這次讀取就看到、還是等待
  中被喚醒），不可能被漏掉。用獨立的 `asyncpg.connect()`，不是從 SQLAlchemy
  連線池借連線——asyncpg 的 `add_listener()` callback API 在 SQLAlchemy async
  engine 沒有對應介面，而且每個 `/wait` call 佔用一個連線到 `timeout_seconds`
  （最長 30 秒）會跟其他 endpoint 共用的連線池搶資源。**已知規模限制**：一個
  `/wait` 呼叫一條專屬連線，適合「內部小規模驗證」（README/config.py 反覆強
  調的目前目標），不適合大量同時等待的部署——真要解決需要一個共享單一 LISTEN
  連線＋in-process fan-out 的設計，這次沒做（YAGNI，多一組 reconnect/liveness
  狀態機這個部署階段還不需要）
- 單一共用 channel（`cga_approval_status_changed`），不是每個 approval id 一
  個 channel——動態 channel 需要處理 id 轉 Postgres identifier 的跳脫問題，
  這個規模下每個 listener 多花一次無關通知的 JSON decode+比對可以忽略

**`GET /api/v1/approvals/{id}/wait`**（`routers/approvals.py`）：
- Query 參數：`known_status`（必填，呼叫端最後觀察到的狀態）、
  `timeout_seconds`（選填，預設 `settings.wait_default_timeout_seconds`=25，
  硬上限 `settings.wait_max_timeout_seconds`=30——超過上限直接夾緊，不拒絕，
  因為長輪詢呼叫端本來就該在逾時後立刻再打一次）
- 兩條免等待的快速路徑：① `record.status != known_status` 時直接回
  `changed=true`（不論這次讀取多舊都成立，某次變更已經發生是不會因為讀取時
  間點而改變的事實）② `known_status` 已經是終態時直接回 `changed=false`（終
  態依 `state_machine.TERMINAL_STATUSES` 定義永不再變，浪費一次完整逾時等待
  沒有意義）
- 不是 Idempotency-Key 保護的 write 端點——GET 本來就對重試安全，而且長輪詢
  呼叫端本來就預期會重複呼叫，強加 idempotency key 只會增加摩擦沒有好處
- **RBAC**（`approvals/authorize.py` 新增 `ApprovalAction.WAIT`）：完全是設計
  推理，v11 遺失記錄從沒討論到 `/wait` 的授權——`governance.admin` 或任何
  `agent.approver`（有資格決定「任何」記錄的角色，理所當然有資格確認是否已
  經被別人搶先決定）或持有 `agent.operator` 的記錄本人（跟 CLAIM/REPORT_RESULT
  同一組角色＋ownership 要求，因為 requester 自己的 agent-server 正是 `/wait`
  設計時設想的主要呼叫端）
- 每個會改變 `status` 的既有端點（decide／claim／report-result／cancel）都補
  上 `notify_status_changed()` 呼叫；create（此時 id 還不存在，不可能有人在
  等）與 reconciliation-findings（從不改變 `status`，見
  `models.ReconciliationFinding` docstring）不需要

**`approvals/sweep.py`（新檔案，背景到期 sweep）**：`state_machine.py` 的
`ApprovalEvent.EXPIRE` 事件從第 2 步就定義好了，但沒有任何東西真的觸發
它——每個 write 端點的 conditional UPDATE 只會「拒絕」過期後的寫入，不會主
動把過期的 row 翻成 `expired`/`failed_unknown`，沒有這支 sweep，一個過期的
`pending` row 會永遠停在 `pending`，`/wait` 呼叫端也永遠等不到「它過期了」的
通知，只能等自己的 timeout。以單一 `asyncio` 背景任務（`main.py` 的
lifespan 啟動/取消）逐一掃描三個 deadline 欄位（`expires_at`／
`execution_deadline`／`executing_lease_expires_at`），沿用跟 write 端點完全
相同的 conditional-UPDATE-with-RETURNING 寫法，每筆過期 row 都呼叫
`notify_status_changed()`，讓正在等的 `/wait` 呼叫立刻醒來而不是空等到自己逾
時。多 process 部署會需要加一個 `pg_advisory_lock` 式的單一領導者機制避免多
個 sweep 互相搶同一批 row——這次沒做（YAGNI，目前部署就是單一 process，而且
就算真的重複觸發，conditional UPDATE 本身也只是浪費一次查詢，不會造成錯誤）。
`config.expiry_sweep_interval_seconds`（預設 10 秒）控制掃描頻率。

**測試**：
- `tests/test_sweep.py`（6 個）：純粹用既有 SAVEPOINT-isolated `db_session`
  fixture 直接呼叫 `sweep_expired_approvals()`，驗證三個 deadline bucket 各
  自轉去正確的終態、`executing` 過期落地在 `failed_unknown`（呼應 v10「crash
  後無法確認就 fail closed」）、沒設 deadline 的 row 不會被誤掃、一次掃描可
  以處理多筆過期 row
- `tests/test_wait_endpoint.py`（8 個）：多數用既有 `client`+`db_session`
  fixture 驗證免等待的快速路徑（已變更／已終態／404／403／approver 也可
  wait／未知 status 值 422）與「真的等到逾時」路徑（1 秒逾時，量測耗時確認
  真的等了約 1 秒而非提早返回）。**唯一需要真正跨連線的測試**
  （`test_wait_wakes_immediately_when_another_connection_decides`）比照
  `test_devices_router.py` 的
  `test_register_quota_race_is_prevented_by_advisory_lock` 先例，另起一顆真
  實 engine/session-factory（不用共用的 SAVEPOINT session，因為 SAVEPOINT
  release 從來不是真正的 Postgres COMMIT，NOTIFY 只在真正 COMMIT 時送達）：
  一個真實 HTTP 請求卡在 `/wait`（20 秒逾時），另一個真實 HTTP 請求 0.5 秒後
  呼叫 `decide`，量測 `/wait` 大約 5 秒內就醒來（遠低於 20 秒逾時，證明是被
  NOTIFY 喚醒而非空等逾時）。實測：快速路徑約 0.1 秒完成、1 秒逾時測試量到約
  1 秒、跨連線喚醒測試量到約 4.9 秒（0.5 秒延遲＋連線/HTTP 開銷，遠低於 20
  秒逾時判斷門檻）。
- **165 個測試全過**（151 舊有 + 14 新增），ruff/pyright 皆 0 issue。

**誠實範圍**：sweep 本身在多 process 部署下的重複觸發只靠「conditional
UPDATE 天然不會重複套用」這個既有機制保證安全，沒有寫多 process 併發測試
（單一 process 部署下這條路徑根本不會發生）；`wait_for_status_change()` 的
逐連線資源用量在大量同時等待的情境下沒有上限，屬於已知規模限制（見
`approvals/notify.py` docstring）；timeout 邊界「commit 剛好卡在 callback
排程之間」這條路徑只靠最後一次 authoritative refresh 的程式邏輯保證正確，
沒有專門構造這個時序的race測試（人為在正確的瞬間製造這個邊界本身就需要對
event loop 排程做不可靠的假設）。

**委派小o（`codex exec --sandbox read-only`）唯讀審查一輪，抓到 1 個
High + 2 個 Medium，全部已修正**：
1. **[High]** 每個 `/wait` 呼叫實際占用兩條 DB 連線，可能耗盡主 pool——
   `wait_for_status_change()` 原本只在意「不用連線池借 LISTEN 連線」，卻沒
   注意到函式簽章本身接收的 `session`（來自 FastAPI 的 `Depends(get_db_session)`）
   在整個等待期間完全沒有 commit/rollback/close，SQLAlchemy 的 autobegin
   交易會一路占用池連線到請求結束——docstring 宣稱「不會跟其他 endpoint 共
   用的連線池搶資源」根本不成立，每個長輪詢實際上同時占用池連線＋專屬
   LISTEN 連線兩條。已修正：新增 `_refresh_and_release()` helper，每次讀取
   `record` 後立刻呼叫 `session.commit()`（在 `expire_on_commit=False` 設定
   下，commit 只結束交易釋放連線，不會讓已載入的屬性過期，故之後仍可安全
   讀取 `record.status`），只在真正讀取的瞬間短暫借用池連線，等待期間完全
   不占用
2. **[Medium]** timeout 路徑沒有做最後一次 authoritative refresh——`remaining
   <= 0` 或 `asyncio.wait_for()` 逾時都直接回傳 `False`，若狀態剛好在逾時邊
   界 commit、但 callback 還沒被 event loop 執行到，回應可能攜帶過時狀態卻
   宣稱 `changed=False`，也是 LISTEN 連線中途斷線時唯一能保正確性的地方
   （斷線後所有 NOTIFY 都會漏接，但只要逾時前有這一次補讀，答案依然正確，
   只是變慢，不會答錯）。已修正：`remaining <= 0` 與 `TimeoutError` 兩個逾時
   出口都改呼叫 `_refresh_and_release()` 再決定回傳值，同一支 helper 順便解
   決上一項連線釋放問題
3. **[Medium]** 跨連線測試不夠嚴謹，不必然證明真的走了 NOTIFY 喚醒路
   徑——原本只用 0.5 秒 `sleep` 賭 `/wait` 呼叫已經完成 LISTEN 註冊，機器夠
   慢時 `decide` 可能搶先在監聽註冊前完成，這種情況下 `wait_for_status_change()`
   自己的「進迴圈前那次 authoritative read」就會直接看到 `accepted` 提早返
   回，測試仍會通過但證明錯了東西（只證明「跨連線變更最終會被觀察到」，不
   是「NOTIFY 真的喚醒了卡住的 waiter」）。修法比照本 repo 既有
   `test_register_quota_race_same_idempotency_key_replays_not_429` 解決同類
   問題的手法：monkeypatch 一個真實呼叫邊界（`AsyncSession.refresh`——
   `wait_for_status_change()` 進迴圈前唯一會呼叫它的地方，`decide` 端點完全
   不會呼叫），讓 `decide` 呼叫端明確等到 waiter 真的通過這個點（`listener_ready`
   事件）才送出請求，測試因此變得更快（不再需要固定 0.5 秒 sleep）也更嚴謹

其中 High 的修法本身也連帶讓兩個既有的「timeout 快速路徑」測試
（`test_wait_times_out_when_nothing_changes`／`test_wait_allows_any_approver_not_just_the_owner`）
從共用的 SAVEPOINT-isolated `db_session` fixture 改用真實 engine——因為現在
會在同一個 session 上呼叫兩次 `commit()`（初次讀取一次＋逾時前補讀一次），
而 SAVEPOINT join 模式下釋放一個 savepoint 後再開新的會炸
`sqlalchemy.exc.MissingGreenlet`（這是該 fixture 隔離手法本身的限制，不是
端點邏輯錯誤——同一段邏輯在真實 engine 下的三個測試皆正常通過已經證明這
點）。新增共用 `real_client` fixture（比照 `test_devices_router.py` 既有的
「自建 engine，連不上就 skip」慣例）避免三個真實連線測試各自重複整段
engine/app/resolver 建置邏輯。

**165 個測試全過**（151 舊有 + 14 新增，含審查後修正版本），ruff/pyright
皆 0 issue。commit `ccaf214`，本機未 push。

## MVP 正式環境驗證 + console-script 進入點 bug 修復（已完成，2026-09-16）

v11 §11 三步驟程式碼完成後，Roy 要求「先建正式資料庫和 DB role 當成 MVP
來用，然後測試呼叫」——第一次真的用 `uv run central-governance-api`（正式
進入點，不是 pytest 的 in-process `httpx.ASGITransport`）對接真實
PostgreSQL 與真實 Keycloak，而不只是本機臨時測試叢集。

**正式基礎設施**：獨立的 `cga` DB role + `central_governance` 資料庫（`ops/create_production_db.sql`，
Roy 用自己保管的 Postgres superuser 密碼執行；此檔含真實產生的密碼，已被
`.gitignore` 排除不進版控）；獨立的 `roy-governance` Keycloak realm + 三個
service-account 測試身份（`cga-test-operator`/`cga-test-approver`/`cga-test-admin`，
各自對應 RBAC 矩陣的一個角色，`ops/create_keycloak_test_identities.bat`）——
Phase 0 dev-mode 驗證用的舊測試 realm 在切換到正式 PostgreSQL 後端時已被清空，
這次是重新建立，不是重用。過程中兩個腳本本身也各修了一個真 bug 才能用：
①`.bat` 檔一開始寫了中文/em-dash 註解，這台機器的預設 codepage 把嵌入的
UTF-8 位元組解讀成批次特殊字元，讓 cmd.exe 的解析器整個爛掉，改寫成純
ASCII 才正常執行 ②`-s config."dotted.key"=value` 這種 kcadm 語法在 Windows
上會回「Cannot parse the JSON」且靜默不建立任何東西，改用 `-f <json檔案>`
才成功建出 protocol mapper（`roles` 攤平 claim + `aud` 注入）。

**發現並修復一個先前完全沒被抓到的真實 bug**：`src/central_governance_api/__init__.py`
從第 1 步骨架起就還是 `uv init` 產生的預設樣板（只印一行字），但
`pyproject.toml` 的 `[project.scripts]` 進入點指的正是這支樣板函式，不是
`main.py` 裡真正啟動 uvicorn 的 `main()`——因為所有既有測試都是透過
`main.create_app()` 走 in-process ASGITransport，從來沒有人真的執行過這個
套件自己的 console-script 進入點，直到今天真的用 `uv run central-governance-api`
啟動才發現完全沒有啟動任何伺服器。委派小o 審查（`codex exec` CLI 背景執行
卡住 30 分鐘完全無輸出，改用 computer-use 操作 Codex 桌面 App，依既有 CLI
卡住降級路徑）確認修法無循環 import 風險，並建議更乾淨的版本——讓
`pyproject.toml` 直接指向 `central_governance_api.main:main`，不透過
`__init__.py` 中介（避免 import 套件本身就要拉進整條 app 組裝依賴鏈）；已
採納，`__init__.py` 恢復為空檔案，新增 `tests/test_packaging.py` 直接解析
`importlib.metadata` 的 `console_scripts` 進入點，驗證它真的指向
`main.main`——這正是這個 bug 當初該被抓到卻沒有的那個測試。

**端對端驗證**：用 `cga-test-operator`/`cga-test-approver` 兩個真實 Keycloak
token（不同身份，因為 self-approval 會被擋）跑完整
create→wait（真的卡住，approver 身份 decide 後約 1.5 秒被 NOTIFY 喚醒，不是
空等 20 秒逾時）→claim→report-result 流程，最終狀態正確落在 `applied`；
`/whoami` 確認 OIDC allowlist 正確過濾掉 Keycloak 預設塞的 3 個系統角色
（`default-roles-*`/`offline_access`/`uma_authorization`）。

**166 個測試全過**（165 + 新增的 packaging 進入點回歸測試），ruff/pyright 皆
0 issue。commit `5b04b41`，本機未 push。

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
拒絕桌面端直連等。2026-09-16 已完成其中「獨立低權限 service account」與
「資料庫/憑證隔離」兩項（見上方「MVP 正式環境驗證」章節）；其餘條件（DB
拒絕桌面端直連的網路層限制、migration 專用帳號與執行期帳號分離等）**尚未
落實**，目前仍是 MVP 等級的隔離，不是完整的 15 條件正式部署。
