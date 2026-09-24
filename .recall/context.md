# Session Context: central-governance-api / Track 2 Slack design (§5a marathon)

**Date**: 2026-09-24
**Topic**: 完成 Track 2 Slack 設計文件 v1 的 §5a（per-user process 生命週期管理，含 workspace-level Postgres advisory lock + crash-recovery 設計）——歷經 18 輪委派小o 對抗審查後正式收斂為 implementation-ready，並 commit。本次 session 也涵蓋更早的 GitHub push 核對、`agent-canvas-source` 發布、`prepackage-governed-sdk.mjs` 腳本修復等（詳見 todo.md 完整記錄）。

## 目標 & 進度
- ✓ **§5a 送審 rounds 2-18，最終判定 0 Critical/0 High/0 Medium/0 Low，implementation-ready**
- ✓ 核心架構演進：round 6-9「縮短窗口」式 fencing（DB claim 緊鄰外部呼叫、per-host enforcement proxy）皆被判定治標不治本 → round 10-11 改用 Postgres session-level advisory lock（正確 primitive），round 10 先踩到鎖定粒度錯配 Critical，round 11 修正後收斂 → round 12-17 聚焦「crash-recovery completion barrier」（如何證明已送達 Docker daemon 的舊 request 不會延遲落地），三次計時器嘗試（retry/backoff、複用 STOP_STATE_UNKNOWN runbook、quiescence window）皆失敗，round 15 改採誠實策略（transport 證據或真人工調查，查不出來永久 fail-closed）才找對方向 → round 16-17 收斂為三路 outcome mapping（NOT_APPLIED/APPLIED/AMBIGUOUS）+ 單一 normative state-machine table → round 18 修完最後文字同步，0/0/0/0
- ✓ 設計文件已 commit：`35be037`（central-governance-api，Roy 拍板「現在 commit」，涵蓋 rounds 2-18 全部演進+`.recall/context.md`）
- ✓ todo.md、roy_km wiki（project 頁/index/overview/log）已完整同步每一輪的發現與修法
- ○ **Track 2 下一步**：§4a（OAuth token binding/unbind 生命週期）是唯一未設計章節，已明確排除在 ready-to-build 之外——是下一個要做的設計工作

## 關鍵決策
- Roy 三次用 `AskUserQuestion` 拍板架構級轉向：①Track 1 委派身份延伸 vs 更簡單的「每個綁定使用者一個 process」架構（選後者）②round 8 發現地基問題後：設計 enforcement proxy 元件（vs 標記已知限制/繼續打轉，選 proxy）③round 9 proxy 也失敗後：改用 Postgres advisory lock 重設（vs 接受殘留風險，選 advisory lock）
- 每輪委派 `codex exec --sandbox read-only`（背景執行，`run_in_background: true`，絕不用 `&`/`disown`），小c 不預設自己是對的，逐項核對小o 的 finding 後才動筆修下一輪
- 小o 明講「implementation-ready 代表規格已足以開始實作，不等於 acceptance tests 已通過或已達 production-ready」——已知限制清單（key custody、tombstone GC 政策、tuning 數值、crash-injection test 待執行、UID 隔離、非 Linux SO_PEERCRED 替代方案等）合理保留、不阻擋實作

## 重要程式碼 / 修改
- `docs/track2-slack-design-v1.md`（central-governance-api，commit `35be037`）：§5a 從 ROUND 1 REVISION 一路修到 ROUND 18 REVISION — IMPLEMENTATION-READY；§9 現況摘要同步更新
- 核心設計要點（實作前必讀）：
  - Advisory lock key = `workspace_id`（不是 per-user，round 11 修正的粒度錯配教訓）
  - 拿鎖後必須在**新 transaction**（鎖之後才開始）重讀 authoritative state，不能沿用排隊前的 transaction
  - Intent record 拆 `operation_id`（邏輯，跨 retry 不變）vs `intent_attempt_id`（實體 row，DB UNIQUE）；`outcome_classification` vs `gate_state` 兩欄分離
  - `start`/`stop` 的 ambiguous 解除：tier 1（transport 證明從未送達，立即 NOT_APPLIED）或 tier 2（人工調查證明舊 request 已終止且效果已知，效果=已套用還要 fresh inspect 交叉驗證才能判 APPLIED，矛盾就永久 AMBIGUOUS/held）——**絕不用計時器**
  - hung-holder runbook：先證明舊 process 已死亡或完成不可繞過的 egress isolation，才能斷 DB session；`hold_state` 有「有 pending intent」跟「無 pending intent」兩條獨立清除路徑

## 錯誤 & 修正
- round 10：lock key 誤設成 `(workspace_id, user_id)`，跟既有 workspace-level ownership 架構粒度錯配，round 11 修正
- round 12-14：連續三次試圖用計時器（retry barrier、STOP_STATE_UNKNOWN 複用、quiescence window）證明「舊 request 不會再落地」，每次都被小o 抓到「時間經過≠證明」的邏輯漏洞，round 15 才改用誠實 fail-closed 策略解決
- round 16：把「舊 request 已終止」錯誤地一律映射成 NOT_APPLIED，沒區分「沒執行」跟「已執行成功」兩種效果，round 17 改成三路 mapping
- round 17→18：正式 state-machine table 跟 prose 沒同步（殘留 quiescence-window 措辭、漏了 tier 1 的 direct NOT_APPLIED 路徑），round 18 修完文字同步後才真正收斂

## 下次繼續
- 設計 §4a（OAuth token binding/unbind 生命週期）——Track 2 唯一剩餘的未設計章節，內容包含：adapter 拿到 token 後怎麼處理（持有 refresh token 當高價值憑證庫 vs 只留 principal id）、`(workspace_id, slack_user_id)` binding key 生命週期、rebind/unbind/deactivation 規則
- §5a 的已知限制清單（key custody、tombstone GC 具體政策、各項 tuning 數值、crash-injection acceptance test）留給實作階段處理，非本次範圍
- 若要開始實作 §5a，先讀 `docs/track2-slack-design-v1.md` 的完整 §5a 章節（含全部 18 輪修訂痕跡）跟 §9 現況摘要
