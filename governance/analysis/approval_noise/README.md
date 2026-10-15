# approval_noise: 核准噪音量測（1.14 方向 B 的證據，不改分析器）

問題：`RoyPathPayloadSecurityAnalyzer` 讓治理預設政策要求核准的動作，有多少其實不必問？這個目錄**只產生證據**；
要不要放寬任何工具，是之後 Roy 逐個決定的事。

## 檔案

| 檔案 | 作用 |
|---|---|
| `mapping.md` | Claude Code 工具 → OpenHands 工具的對應、cwd 廣度分層、Bash 特徵、估計設計（量測前寫定，經兩輪小o 事前審查修訂） |
| `standard.md` | 「必要核准」標準（量測前寫死） |
| `replay.py` | 把本機 Claude Code 對話裡的工具呼叫丟進**真的分析器**，只輸出去識別的特徵 |
| `sample.py` | 依預先寫定的配置抽樣（可重現、層內等機率），產生標記者看的批次、重複題與分開存放的答案鍵 |
| `report.py` | 由標記結果算出估計（分層加權、群聚 bootstrap 區間、CANNOT_TELL 當區間） |
| `report_2026-10-15.md` | 這次量測的結果與解讀 |

## 重跑

```bash
python replay.py --projects <~/.claude/projects> --days 30 --out out
python sample.py --actions out/actions.jsonl --out out/labels
# 把 out/labels/label_batch_*.json 連同 standard.md 交給標記者，答案存成 out/labels/<批次名>_out.txt
python report.py --actions out/actions.jsonl --summary out/summary.json --labels out/labels --out out/report.md
```

要用 SDK 自己的 Python（能 `import openhands.sdk` 的那個）。`out/` 不進版本控制。

## 隱私

`replay.py` 在本機處理完整指令與路徑，**輸出只有**布林、計數與來自事先寫死詞彙表的字（指令詞、子命令、白名單旗標、工具名）。
`tests/agent_server/test_approval_noise.py` 釘住這條界線（含突變驗證）。標記者只看到這些特徵，看不到分析器的答案。

## 限度

見 `mapping.md` 與 `standard.md` 的「限度」，以及 `report_2026-10-15.md`。最重要的三個：標記者是模型（小o）、
Claude Code 的使用不等於 OpenHands agent 的行為、去識別讓部分 Bash 無法判定（以區間呈現）。
