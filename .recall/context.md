# Session Context: openhands-governance (central-governance-api)
**Date**: 2026-09-24
**Topic**: 設計 OHS Track 2 §4a 收斂為 IMPLEMENTATION-READY，commit+push，並新增桌面 app 打包待辦

## 目標 & 進度
- ✓ §4a（Track 2 設計文件唯一遺留未設計的章節）從零開始設計，委派小o 8 輪獨立審查，最終正式判定 **IMPLEMENTATION-READY**
- ✓ `todo.md`／wiki 三頁（`project_openhands_governance_platform.md`／`index.md`／`log.md`）同步完成，向量索引已增量重建
- ✓ **已 commit**（`662c180`，`central-governance-api` repo）**並已 push**（`chchiuleroy/software-agent-sdk` 的 `central-governance-api` 分支，`02ad0df..662c180`）——上一次存檔時還沒問到答案，這次已經問到且完成
- ✓ Roy 追加新待辦，經兩輪澄清後寫入 `todo.md`：把 `central-governance-api`（及 `openhands-governance` 底下其他新功能）比照 `agent-canvas-source` 現有的 `electron-builder`+`extraResources` 機制，一起打包進同一個 Electron 桌面 app 安裝檔（現有版本 `OpenHands-Agent-Canvas-Setup-1.16.0.exe`，位於 `agent-canvas-source\dist-electron`）——**不是**獨立打包成 standalone exe 或 Windows Service，我第一次理解錯了，Roy 用 `dist-electron` 路徑舉例才點出正確方向

## 關鍵決策
- §4a 核心設計要點（完整記錄見 wiki `project_openhands_governance_platform.md`「§4a」章節，不重複）：central-governance-api 看到的是 per-binding **service principal** 非人類本人，人類歸屬只在應用層 binding table 稽核維護；schema 三表（`slack_identity_binding`/`slack_binding_attempt`/`active_human_binding`）；`DEFERRABLE INITIALLY DEFERRED` trigger、CAS-guarded cutover、`clock_timestamp()` lease fence、`fn_attempt_create` 唯一 INSERT 入口
- 新打包待辦的範圍判斷：`central-governance-api` 是常駐 API 服務+PostgreSQL 依賴，跟現有 `extraResources` 只打包唯讀 SDK 程式碼的模式不同，實際方案需要另外設計（已記在 todo「下一步」）

## 重要程式碼 / 修改
- `C:/Users/roy/todo.md`：
  - 新增置頂項目「把 `openhands-governance` 底下的新功能一起打包進 Agent Canvas 桌面 app 的 exe」（未完成，待評估打包方案）
  - §4a 完整 8 輪里程碑記錄（已完成）
  - 2026-09-09 舊條目標記 SUPERSEDED
- `openhands-governance/central-governance-api/docs/track2-slack-design-v1.md`：§4a 完整規格（8 輪修訂，"ROUND 8 CLOSURE — IMPLEMENTATION-READY"）——**已 commit 且已 push**，working tree 乾淨
- wiki 三頁已同步（見上次記錄，內容未變）

## 錯誤 & 修正
- 這次 session 有一次理解錯誤：Roy 說「新的 OHS governance SDK 轉成 exe」時，我第一次猜成「把 central-governance-api 獨立打包成 standalone exe/Windows Service」，其實 Roy 要的是「比照 agent-canvas-source 現有機制、打包進同一個 Electron 安裝檔」——**教訓**：Roy 給模糊需求時主動猜測方向沒錯，但猜錯後他傾向直接指出具體參照路徑（這次是 `dist-electron`）而非重新描述需求，收到路徑/具體範例時要優先當作最精準的澄清訊號，不要停留在文字描述層面重新詮釋
- 8 輪委派審查中小o 多次指出小c 自己的措辭「講太滿」（unforgeable/never before/不可能碰撞），每次都改成跟 §5a 既有措辭一致的誠實版本——未來寫類似規格文件優先參考 §5a 已校準的措辭風格

## 下次繼續
1. **打包待辦評估**（新增，優先度看 Roy 何時想推進）：盤點 `central-governance-api` 的執行方式（`uv run central-governance-api`，常駐服務+PostgreSQL）跟 `agent-canvas-source` 現有 `extraResources` 打包模式（唯讀 SDK 程式碼）的差異，設計實際打包方案（可能需要額外處理常駐服務啟動/資料庫依賴，不能原封不動套用現有機制）
2. Track 2 §0-§8 全部設計完成、§5a／§4a 皆 implementation-ready，下一步理論上是實作——但 Roy 尚未明確表態何時開始，不要自行假設開始寫 code
3. 本專案至今兩個走完完整委派審查收斂流程的章節：§5a（18輪）、§4a（8輪，這次）——§4a 較快是因為一開始就重用 §5a 已驗證的 lock/durable-intent 機制，未來類似情境可參考此效率模式
