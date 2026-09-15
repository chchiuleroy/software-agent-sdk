# Session Context: central-governance-api
**Date**: 2026-09-15
**Topic**: v11 §11 實作順序第 2 步——RBAC 授權矩陣與 conditional-update 邏輯（六個 approval-workflow 端點）

## 目標 & 進度
- ✓ 純邏輯層：`approvals/state_machine.py`（狀態轉移表）+ `approvals/authorize.py`（RBAC 矩陣），零 DB/HTTP 依賴，100 測試全過
- ✓ 純邏輯層委派小o 唯讀審查一輪，抓到 1 high（`late_report` 授權路徑錯併入 `RECONCILE_AS_REQUESTER`）+4 medium+2 low，全修正
- ✓ Router 層：`routers/approvals.py`（create/decide/claim/report-result/cancel/reconciliation-findings 六端點）+ `approvals/{digest,idempotency,errors,schemas}.py`
- ✓ **首次真的接上真實 Postgres 驗證**（本機另起獨立測試叢集，port 5433，跟 Keycloak 正式服務分開），非純 mock
- ✓ Router 層委派小o 第二輪審查，抓到 3 high（idempotency 併發回退只有文件沒實作／decide 與 report-result 的 conditional UPDATE 皆漏期限判斷）+3 medium，全修正
- ✓ 121 測試全過（100 純邏輯 + 21 真實 DB 整合），ruff/pyright 0 issue
- ✓ 三次 git commit：`5c73da8`（第 1 步骨架，上次 session）→ `e2e0a9b`（第 2 步初版）→ `39200a0`（審查修正），皆本機未 push
- ✓ wiki 已同步（`project_openhands_governance_platform.md`／`concept_delegation_override.md`／`index.md`／`log.md`），lint 0 issues，向量索引已重建
- ○ devices-register／devices-revoke／audit-events（讀）／`wait`（第 3 步 LISTEN/NOTIFY）尚未開始
- ○ `(issuer, sub)` tuple 欄位拆分（`requester_subject` 等目前只存拼接字串）——待 Roy 拍板是否現在做

## 關鍵決策
- digest 驗證只在 CREATE 時做一次（伺服器重算 display/binding 欄位雜湊比對），不在 decide 時重驗——因為 CREATE 之後這些欄位永不被本 API 修改，一次驗證即終身有效；明確聲明威脅模型限制（無法綁定 canonical payload，只在 requester 裝置與執行端同信任域的 Track 1 架構下成立）
- claim/report-result **沒有** governance.admin bypass（執行是裝置綁定的，admin 不能代替別人裝置執行）；cancel **保留** admin bypass（不涉及執行，可當 kill switch）
- pre-claim-abort 與 cancel 共用 CANCELLED 終態，改用 `AdminAuditEvent`（`event_type` 區分）留下可分辨的紀錄，不新增 DB 欄位/schema
- 測試策略：pyright/ruff 通不過就是真錯，但「跑得動」≠「邏輯對」——所以另起真實 Postgres 而非只用 mock；`tests/conftest.py` 的 `db_session` fixture 用 SQLAlchemy 2.0 `join_transaction_mode="create_savepoint"`（連線層開真外層 transaction，router 的 `commit()` 只釋放巢狀 SAVEPOINT，測試結束整個 rollback），沒設 `CGA_DATABASE_URL` 時這批測試乾淨 skip 不報錯

## 重要程式碼 / 修改
- `src/central_governance_api/approvals/state_machine.py`：狀態轉移表（新檔案）
- `src/central_governance_api/approvals/authorize.py`：RBAC 矩陣，含 `ApprovalAction.RECONCILE_LATE_REPORT`（新檔案）
- `src/central_governance_api/approvals/digest.py`：digest 驗證（新檔案）
- `src/central_governance_api/approvals/idempotency.py`：idempotency 強制（新檔案）
- `src/central_governance_api/approvals/errors.py`：router 專用例外型別（新檔案）
- `src/central_governance_api/approvals/schemas.py`：Pydantic request/response，`extra="forbid"`（新檔案）
- `src/central_governance_api/routers/approvals.py`：六端點主體，`_commit_or_replay()` helper（新檔案）
- `src/central_governance_api/main.py`：掛上 approvals router + 統一例外→HTTP 對應表
- `src/central_governance_api/config.py`：新增三個 TTL 設定
- `tests/conftest.py`：新增 `db_session` fixture（SAVEPOINT 隔離）
- `tests/test_state_machine.py`／`test_authorize.py`／`test_approvals_router.py`：新增測試檔案

## 錯誤 & 修正
- `ApprovalDecision.decision` 原本寫入 wire-level 動詞（`accept`），撞 DB CHECK constraint（要 `accepted`）——真實 DB 才抓到，已加 `_DECISION_DB_VALUES` 映射
- `decide`／`report-result` 的 conditional UPDATE 原本漏了 `expires_at`／`executing_lease_expires_at` 判斷——委派審查抓到，已補 WHERE 條件並各補一個真 DB 整合測試（用 `db_session` 手動把期限改到過去，不需要真併發）
- `idempotency.py` docstring 宣稱的併發回退機制原本沒真的實作——已加 `_commit_or_replay()`，但這條路徑本身仍缺真正跨連線併發測試（已知限制，SAVEPOINT 隔離測不出真併發）

## 下次繼續
- 先確認 Roy 對「`(issuer, sub)` 要不要拆欄位」的拍板結果
- 若繼續往下：devices-register/devices-revoke/audit-events（讀）—— 較單純的 CRUD 端點
- 記得：本機臨時 Postgres 測試叢集還開著（port 5433，`central_governance_test` db），下次接續時可直接用 `CGA_DATABASE_URL="postgresql+asyncpg://cga:cga@127.0.0.1:5433/central_governance_test"` 前綴跑測試；若該叢集已被關閉需重新 `initdb`+`pg_ctl start`+`alembic upgrade head`
- 正式部署仍需 Roy 建立專用 `central_governance` 資料庫與最小權限 DB role（不能沿用 Keycloak 帳號）
