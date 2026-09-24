# Session Context: central-governance-api / agent-server integration

**Date**: 2026-09-16
**Topic**: agent-server 串接 central-governance-api 的評估 → 計畫（v1→v4，五輪小o 審查）→ Phase A 實作落地（三輪 code review，已 commit）。central-governance-api 本身（v11 §11 三步驟 + MVP + GitHub push）已在更早的 session 完成，不在本次範圍。

## 目標 & 進度
- ✓ agent-server 串接評估文件（v2，含第一輪小o 審查）：抓到 team mode 舊端點繞過風險、approval-action 綁定缺口、背景 task 生命週期、OIDC 機器/真人身份問題
- ✓ 低風險垂直切片計畫 v1→v4，四輪小o 審查：
  - v1→v2：小o 指出「_run_lock 誤判為涵蓋真正執行」是小c 看錯程式碼的實質錯誤
  - v3：小c 先讀完 `ConversationState`/`LocalConversation` 真正的 state lock 機制才動筆，找到正確插入點（`run()`/`arun()` 主迴圈 `approved_actions` 算出來那一行，約 2041 行），小o 認可核心洞見正確，但抓到「中央 API 單一 action schema vs agent-server 可能多個 pending action」的 cardinality 不相容
  - v4：明確縮小範圍（只處理單一 pending action）+ 把 claim 責任從 bridge 移到 agent-server 自己做，小o 認可兩個方向決定，但抓到「process≠同步呼叫鏈」（`EventService.run()` 排程背景 task 就返回，例外傳不到 REST 層）與「單一 action≠不需要 reservation」兩個新 Critical
  - **小o 三輪一致確認 Phase A（入口隔離）可以獨立動工**，Phase B-E 需要依 8 項具體門檻重新設計（未做）
- ✓ **Phase A 實作完成並 commit**（`155bef144`，本機未推送）：team mode 下 `respond_to_confirmation` 的 `accept=True` 路徑加 `X-Governance-Bridge-Token` 檢查，5 個檔案（`config.py`/`dependencies.py`/`event_router.py`/`api.py`/`init_router.py`）+ 2 個測試檔案（74 個新測試）
- ✓ 三輪 code review 抓到並修復 3 個 Important：deferred init 沒合併新欄位、OpenAPI schema 未正確記錄新 header（`APIKeyHeader` 命名衝突，改用 `Header(alias=...)`）、`Config.model_copy(update=...)` 不重跑 validator 讓空白 token 繞過驗證（抽成共用 `reject_blank_secret()`）
- ○ **仍未做**：Phase B-E（durable outbox/relay、agent-server 自己 claim、action-bound atomic commit、獨立 bridge worker）完全還沒開工，v4 計畫需要依審查給的 8 項門檻重新設計才能繼續

## 關鍵決策
- Roy 明確要求「agent-server 串接先評估看看要怎麼做，也請小o review」——全程評估/計畫階段沒有寫任何 code，直到 v4 計畫確認 Phase A 可獨立動工才真正落地實作
- 五輪design 審查 + 三輪 code review，是這個子專案目前為止最密集的委派審查循環——每一輪都有實質發現，不是走過場；小c 在 v2→v3 過程中犯過一次實質理解錯誤（`_run_lock` 誤判），已誠實記錄並修正
- Phase A 的實作範圍嚴格對應審查認可的邊界，沒有搶跑 Phase B-E
- Roy 明確要求 commit，小c 檢查 diff scope 乾淨（只有預期的 7 個檔案）後才 commit，訊息遵循既有 `governance:` 前綴慣例

## 重要程式碼 / 修改
- `openhands-sdk-governed`（git commit `155bef144`）：
  - `openhands-agent-server/openhands/agent_server/config.py`：新增 `governance_deployment_mode`/`governance_bridge_token`，共用 `reject_blank_secret()` 函式
  - `openhands-agent-server/openhands/agent_server/dependencies.py`：`authorize_confirmation_response()`、`governance_bridge_token_header()`
  - `openhands-agent-server/openhands/agent_server/event_router.py`：`respond_to_confirmation` 路由接上檢查
  - `openhands-agent-server/openhands/agent_server/api.py`：`SelfApprovalDeniedError` 的 handler 改成 generic detail（連帶修正既有身份洩漏 bug）
  - `openhands-agent-server/openhands/agent_server/init_router.py`：`InitRequest` 補兩個欄位的 deferred-init 合併邏輯
  - `tests/agent_server/test_api.py`、`tests/agent_server/test_init_router.py`：74 個新測試
- 設計文件（未進版控，session scratchpad）：`agent_server_integration_evaluation.md`（v2）、`agent_server_integration_plan_narrow_slice.md`（v1）、`agent_server_integration_plan_v2.md`、`agent_server_integration_plan_v3.md`、`agent_server_integration_plan_v4.md`

## 錯誤 & 修正
- v2→v3：小o 抓到小c 誤判 `EventService._run_lock` 涵蓋真正執行——實際上那個鎖只包排程 task，不包背景 coroutine；小c 誠實記錄這個錯誤並重新讀完 SDK 原始碼才修正
- v3→v4：`central_governance_api` 的 `CreateApprovalRequest` 是單一 action schema，v3 設計成批次 actions，架構落差非程式碼錯誤，靠縮小範圍（只處理單一 pending action）消滅
- Phase A code review 第一輪：deferred init 無法設定新欄位；OpenAPI schema 因 `APIKeyHeader` 命名衝突未正確記錄新 header
- Phase A code review 第二輪：`Config.model_copy(update=...)` 不重跑 field validator，空白 bridge token 能繞過驗證從 `/api/init` 混進去（小o 實際重現：`blank_init_accepted='   '`）
- 完整 `tests/agent_server/` 套件跑出 20 failed + 6 errors，用 `git stash` 驗證是既有 Windows 環境限制（symlink 權限、POSIX SIGTERM trap、PID 競態），與這次變更無關，非回歸

## 下次繼續
- Phase B-E 需要依小o v4 審查給的 8 項具體門檻重新設計（team mode fail-closed 契約、`_run_lock` 內 ownership reservation、`run_and_wait_for_start` handshake、SDK+EventService 兩層都不能把治理拒絕轉成 ERROR、claim→report/reconciliation 的 durable 狀態機、單一 owner operator principal 契約、retry matrix、不可判定的 crash window 用 `inconclusive`）——這是下一個大工程，尚未開始
- Phase A 的 commit 已推上 GitHub：`chchiuleroy/software-agent-sdk` 的 `governance-layer` 分支（`git push origin main:governance-layer`，fast-forward `7317527d9..155bef144`，推送前掃過無真實 secret，`git ls-remote` 核對 SHA 一致）
- 已知非阻擋殘留：`openhands-agent-server/AGENTS.md` 明定的 live-server 測試慣例（`tests/cross/test_remote_conversation_live_server.py`）這次沒補，小o 評估不構成合併阻擋，未來可以補
