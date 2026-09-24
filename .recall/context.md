# Session Context: openhands-governance (central-governance-api)
**Date**: 2026-09-24
**Topic**: 設計 OHS Track 2 §4a（OAuth token-binding/unbind lifecycle）從零到 8 輪委派審查收斂為 IMPLEMENTATION-READY

## 目標 & 進度
- ✓ 查 todo.md 待辦清單，標記 2026-09-09「企業前端整合」條目為 SUPERSEDED（被 Track 2 Slack 設計吸收）
- ✓ §4a（Track 2 設計文件唯一遺留未設計的章節）從零開始設計
- ✓ 委派小o（`codex exec --sandbox read-only`）做 8 輪獨立審查，逐輪修正，最終正式判定 **IMPLEMENTATION-READY**（2026-09-24）
- ✓ `todo.md` 補上完整 8 輪里程碑記錄
- ✓ wiki 三頁同步：`project_openhands_governance_platform.md`（詳細 8 輪歷程新章節）、`index.md`（專案摘要 append）、`log.md`（新 entry）
- ✓ 向量索引已增量重建（`project_openhands_governance_platform.md` 重新 embed，index.md/log.md 屬 meta 頁不進索引）
- ○ **尚未 commit**：`track2-slack-design-v1.md` 的今日全部變更（round 1-8）還在 working tree，Roy 尚未明確答覆要不要現在 commit——下次對話開始時應先問這個，不要假設答案

## 關鍵決策
- §4a 核心設計（最終版，即 track2-slack-design-v1.md §4a.0-4a.9）：
  - **身份模型**：central-governance-api 看到的是 per-binding **service principal**（不是人類本人），人類歸屬只在應用層 binding table 被稽核維護（跟既有 device registration「audit hint 非 security control」定位一致）——這是全程最重要的架構修正，round 1 的原始設計誤以為「每人一把 client-credentials 憑證」能讓 central 認得出人類本人，被小o 讀原始碼推翻（token 的 `(issuer, sub)` 是 client 自己的 service-account，不是 Device Flow 驗證過的人類）
  - **Schema**：`slack_identity_binding`（純 pointer + routing status，無身份欄位）、`slack_binding_attempt`（generation 層級擁有身份欄位，不可變一旦寫入）、`active_human_binding`（human-uniqueness reverse index，PK 本身就是唯一性保證）
  - **關鍵機制**：`DEFERRABLE INITIALLY DEFERRED` constraint trigger（commit 時才驗證 pointer-to-BOUND invariant）、CAS-guarded cutover with `LOST_RACE` 終態、takeover 單一 atomic transaction（human lock 先於雙 workspace lock）、`clock_timestamp()`（非 statement/transaction_timestamp）做 lease expiry fence、`fn_attempt_create` 是唯一允許 INSERT 的路徑且寫死 PENDING
  - **v1 明確拍板、不留白**：rebind 不支援換人類身份（需明確 unbind-then-bind）；不做 `azp` 限制；一人最多一個 active binding；sweep tunables 給了精確起始值（jitter ±20%、concurrency cap 4、mass-suspension alert 5分鐘內>25%且≥2筆）
  - **新增跨界範圍**：emergency deactivation 需要 central-governance-api 本身新增 `revoked_service_principal` денylist table（唯一一項不只是 Track 2 adapter/Keycloak 範圍的修法）

## 重要程式碼 / 修改
- `C:/Users/roy/todo.md`：新增 2026-09-24 §4a 完整 8 輪里程碑記錄（置頂）；2026-09-09 舊條目標記 SUPERSEDED
- `openhands-governance/central-governance-api/docs/track2-slack-design-v1.md`：
  - §4a 整段從 placeholder 改寫成完整規格（8 輪修訂，最終標題 "ROUND 8 CLOSURE — IMPLEMENTATION-READY"）
  - 頂部「Current status」摘要段落同步更新反映 §4a 完工
  - **working tree 有未 commit 的變更**（今天一整天的 round 1-8 全部內容）
- `C:/Users/roy/roy_km/wiki/project_openhands_governance_platform.md`：新增「§4a：8 輪委派審查後判 IMPLEMENTATION-READY」章節，frontmatter `updated: 2026-09-24`
- `C:/Users/roy/roy_km/wiki/index.md`：project_openhands_governance_platform 條目 append §4a 摘要
- `C:/Users/roy/roy_km/wiki/log.md`：新增 2026-09-24 ingest entry

## 錯誤 & 修正
- 無重大工具/流程錯誤本次 session；委派審查本身抓到大量設計錯誤（見上方關鍵決策），這是預期中的正常審查產出，不是工具問題
- 8 輪審查中小o 多次指出小c 自己的措辭「講太滿」（如「unforgeable」「never before」「不可能碰撞」），每次都改成跟 §5a 既有措辭一致的誠實版本——提醒未來寫類似規格文件時，優先參考本文件 §5a 已經校準過的措辭風格，不要重新發明可能過度宣稱的說法

## 下次繼續
1. **優先確認**：Roy 是否要 commit `track2-slack-design-v1.md` 今日的變更（尚未詢問到答案就存了這次 session）——下次對話開始應主動問，不要預設
2. commit 後（若 Roy同意），比照過去節奏「先本機 commit，一段落再 push」，push 前需再次確認
3. Track 2 §0-§8 全部設計完成，下一步理論上是實作（§5a、§4a 都已 implementation-ready）——但 Roy 尚未明確表態下一步要不要開始實作、還是先做其他事，不要自行假設開始寫 code
4. 這是本專案繼 §5a（18輪）後第二個走完完整委派審查收斂流程的章節，8 輪明顯比 18 輪少——如果未來還有類似需要從零設計的章節，可以參考這次的效率（一開始就重用 §5a 已驗證的 lock/durable-intent 機制，不要重新從零摸索 fencing primitive）
