# central-governance-api

OHS 治理平台的中央治理 API — Phase 1 接路由設計 v11 §3。唯一持有 PostgreSQL
憑證的獨立服務；桌面端 agent-server 一律走 REST + OIDC bearer token，不直連
DB。設計全文見 `roy_km` wiki `project_openhands_governance_platform.md`
「Phase 1 接路由設計」章節。

刻意是獨立的 uv 專案（不是 `openhands-sdk-governed` 的一部分）——這個服務有
自己的資料庫、自己的信任邊界，repo 根目錄的 `AGENTS.md` 也明講這類服務屬於
「不同的 repo/service」，不歸 `openhands-agent-server` 管。

## 目前狀態（v11 §11 第 2 步進行中）

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
- 17 個新整合測試（`tests/test_approvals_router.py`）+ 既有 100 個純邏輯
  測試，`tests/conftest.py` 新增 `db_session` fixture（SAVEPOINT-based
  隔離，讓 router 自己呼叫的 `session.commit()` 真的執行、但測試結束仍
  乾淨 rollback）；沒有可用測試 DB 時（未設定 `CGA_DATABASE_URL`）這批
  測試會乾淨 `skip` 而非報錯，不影響 README 既有 `uv run pytest tests/`
  流程

**誠實範圍（這批測試沒證明的事）**：`ConcurrentModificationError`（conditional
UPDATE 的 0-row 分支）目前只靠程式碼審查與型別檢查保證正確，沒有真正的
跨 transaction 併發測試——SAVEPOINT 隔離這招本身讓同一測試檔案內無法模擬
「兩個真正同時進行的請求」，要驗證這條路徑得另外開一支犧牲隔離乾淨度的
測試（真實 commit + 第二個獨立連線），這次沒做。

尚未開始（v11 §11 第 2 步剩餘部分，刻意留到下一輪）：
devices-register／devices-revoke／audit-events（讀）／`wait`（第 3 步，
LISTEN/NOTIFY）——相對單純的 CRUD 型端點，跟這輪較難的 state-machine／
digest／idempotency 邏輯刻意分開，避免同一輪錯誤面過大。

**待 Roy 拍板**（審查發現，範圍會動到已 commit 的 schema，不是我能單方面決定的）：
`requester_subject`／`decision_actor_subject`／`verifier_subject`／
`actor_subject`／`owner_subject` 等欄位目前只存 `Principal.subject`
（`f"{issuer}#{sub}"` 拼接字串），但 `auth/oidc.py` 的 `Principal.subject`
docstring 明講安全性比對該用 `(issuer, sub)` tuple。審查結論：目前風險比
原本設想的低（OIDC issuer URL 依規範不含 fragment，且 resolver 目前只信任
單一 issuer），但仍是「資料模型違反身份 API 契約」，值得趁 schema 還新
（尚未接上任何真實資料庫）現在就拆成 `*_issuer`／`*_sub` 兩欄，牽動
`models.py` 六張表與 Alembic migration。

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
