# central-governance-api

OHS 治理平台的中央治理 API — Phase 1 接路由設計 v11 §3。唯一持有 PostgreSQL
憑證的獨立服務；桌面端 agent-server 一律走 REST + OIDC bearer token，不直連
DB。設計全文見 `roy_km` wiki `project_openhands_governance_platform.md`
「Phase 1 接路由設計」章節。

刻意是獨立的 uv 專案（不是 `openhands-sdk-governed` 的一部分）——這個服務有
自己的資料庫、自己的信任邊界，repo 根目錄的 `AGENTS.md` 也明講這類服務屬於
「不同的 repo/service」，不歸 `openhands-agent-server` 管。

## 目前狀態（v11 §11 實作順序第 1 步：骨架）

已完成：
- FastAPI app 骨架（`src/central_governance_api/main.py`）
- 獨立、async 的 OIDC bearer-token 驗證層（`auth/oidc.py` + `auth/dependencies.py`），
  重用 Phase 0 `oidc_principal.py` 的驗證邏輯與測試風格，補上 v11 第 8-11 輪
  審查要求的修正（negative-kid cache、固定演算法、token 長度上限、azp
  allowlist、log 衛生）
- PostgreSQL schema（`models.py`）+ 手寫 Alembic migration（`alembic/versions/`）
  ——涵蓋 v11 §4/§5 的 `PendingApprovalRecord`／`ApprovalDecision`／
  `ReconciliationFinding`，§2 的 `DeviceRegistration`／denylist，§3 的
  `AdminAuditEvent`／`IdempotencyRecord`
- 27 個測試全過，ruff/pyright 皆 0 issue

尚未開始（v11 §11 第 2 步以後）：approval 建立／decide／claim／report-result／
wait／cancel／reconciliation-findings／devices-register／audit-events 這些
端點本身的業務邏輯（conditional update、狀態機、idempotency 強制、digest
比對）完全還沒寫，`models.py` 只是 schema。

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
