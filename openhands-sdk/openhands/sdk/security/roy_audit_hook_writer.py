"""Governance 稽核 hook 的實際執行體。

由 ``roy_audit_hooks.build_governance_hook_config()`` 產生的 command hook 呼叫
(``python <這個檔案的絕對路徑> <audit_dir>``——刻意用絕對路徑而非
``python -m openhands.sdk.security.roy_audit_hook_writer``:executor 會用
對話的 workspace 當 cwd 執行這條指令,``-m`` 會把 cwd 加進
``sys.path[0]``,workspace 內若剛好有同名的 ``openhands`` 檔案/套件就會被
優先匯入、取代真正的 SDK,等於治理稽核本身變成可被 workspace 內容劫持的
任意程式碼執行入口;絕對路徑呼叫則讓 ``sys.path[0]`` 指向這個受信任的原始
碼目錄,不受 cwd 影響),讀 stdin 的 HookEvent JSON(見
openhands.sdk.hooks.types.HookEvent),append 一行到
``<audit_dir>/<event_type_snake>.jsonl``。

獨立成可執行模組而非 inline shell 指令,是因為 hook 由 subprocess 執行,
寫檔邏輯需要跨平台(Windows/Linux)一致——直接複用呼叫端的 Python 直譯器
(``sys.executable``,見 roy_audit_hooks.py)最簡單可靠,不必另外處理 shell
語法差異。

稽核紀錄只負責忠實寫檔,不做任何攔截判斷(SessionStart/SessionEnd/
PostToolUse 本來就不支援 block,見 HookManager.run_session_start()),
任何內部錯誤都吞掉並回傳 exit code 0——稽核失敗不該連帶讓對話開不起來。
"""

from __future__ import annotations

import datetime
import json
import os
import re
import sys


def _pascal_to_snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def main(argv: list[str]) -> int:
    audit_dir = (
        argv[1]
        if len(argv) > 1
        else os.path.join(os.path.expanduser("~"), ".openhands", "audit")
    )

    try:
        raw = sys.stdin.read()
        event = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, OSError):
        event = {}

    event_type = str(event.get("event_type") or "unknown")
    record = {
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "event_type": event_type,
        "session_id": event.get("session_id"),
        "working_dir": event.get("working_dir"),
    }

    try:
        os.makedirs(audit_dir, exist_ok=True)
        filename = f"{_pascal_to_snake(event_type)}.jsonl"
        log_path = os.path.join(audit_dir, filename)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
