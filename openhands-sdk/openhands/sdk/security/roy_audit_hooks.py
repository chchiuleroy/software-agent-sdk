"""Roy 的治理稽核 hook,對應 dsh 稽核鏈的地基(見 roy_km wiki
``project_openhands_governance_platform.md``「下一步」第 7 項的查證結論)。

用 OpenHands SDK 原生 hooks 機制(``openhands.sdk.hooks``)掛一個治理強制的
SessionStart 稽核 hook,把 session_id/working_dir/時間戳寫進 JSONL。不論
呼叫端(raw REST API 或 Agent Canvas GUI 走的 ``ConversationConfig``,或
OpenAI 相容端點走的 ``ConversationSettings.create_request()``)有沒有自帶
``hook_config``,都用 ``HookConfig.merge()`` 合併而非覆蓋——對應
``confirmation_policy``/``security_analyzer`` 兩個既有生效點「治理關鍵欄位
不能被呼叫端繞過」的同一套設計原則(見 roy_governance.py)。

安全性質:
1. writer 一律以自己模組的 ``__file__`` 組出絕對路徑呼叫(而非
   ``python -m openhands.sdk.security.roy_audit_hook_writer``)——executor
   用對話 workspace 當 ``cwd`` 執行這條指令,``-m`` 會把 cwd 加進
   ``sys.path[0]``,workspace 根目錄若剛好有同名 ``openhands`` 套件就會
   搶先被匯入。絕對路徑呼叫讓 ``sys.path[0]`` 固定指向這個受信任目錄,不
   受 cwd 影響。
2. 冪等判斷會先移除任何同名(``AUDIT_HOOK_NAME``)既有項目,再放回自己
   產生的那一份——同名假 hook(呼叫端或插件塞入)不會被誤判成「已存在」
   而略過真正的稽核。
3. ``default_audit_dir()`` 用 allowlist(僅接受字母/數字/空白/路徑常見符號)
   而非 blocklist 驗證,避免內插進 ``shell=True`` 執行的指令字串時被
   ``$(...)``、反引號等 POSIX shell 展開語法利用。
4. ``LocalConversation.__init__`` 在 ``self._pending_hook_config = ...``
   賦值時就套用本函式,涵蓋 fresh construction 與 resume(resume 呼叫的是
   同一個建構子,只是 ``hook_config=self.stored.hook_config``)。沒有獨立
   的 runtime REST endpoint 或 public setter 可以在建構後整份替換
   ``hook_config``(跟 ``confirmation_policy``/``security_analyzer`` 需要
   額外處理 setter/resume 兩條路徑不同);``_merge_runtime_plugin_hooks()``
   會在 runtime 動態載入 plugin 時再寫一次 ``_pending_hook_config``,但那是
   在已含治理 hook 的既有值上疊加(``HookConfig.merge()``),不會清掉已經
   合併進去的治理 hook。

已知限制,刻意不修(範圍超出「補一個治理 hook」,見
project_openhands_governance_platform.md「下一步」討論):
5. **Plugin hook 合併發生在本檔之後,可能重複執行**:
   ``LocalConversation._ensure_plugins_loaded()`` 在拿到本檔已合併好的
   ``hook_config`` 之後,用 SDK 既有的 ``HookConfig.merge()``(單純串接,
   不做同名去重)疊加 plugin 自帶的 hooks——若某個 plugin 剛好也定義一個
   叫 ``AUDIT_HOOK_NAME`` 的 SessionStart hook,會產生重複紀錄。這是
   ``HookConfig.merge()`` 本身的既有行為,修正需要動 SDK 核心邏輯,超出
   本檔範圍。
"""

from __future__ import annotations

import logging
import os
import re
import sys

from openhands.sdk.hooks import HookConfig, HookDefinition, HookMatcher, HookType


logger = logging.getLogger(__name__)

_DEFAULT_SAFE_AUDIT_DIR = os.path.join(os.path.expanduser("~"), ".openhands", "audit")

# Allowlist, not blocklist: a real filesystem path never needs `$ ` ` ; | & ( )
# < > " ' \n etc., and those are exactly the characters a POSIX or cmd.exe
# shell treats specially inside a double-quoted string (POSIX still expands
# `$(...)`/backticks/`$VAR` inside double quotes; a bare `"` reject alone
# — the first pass at this fix — missed that). Reject anything outside this
# set instead of trying to enumerate every dangerous character for every
# shell this could run under.
_SAFE_PATH_PATTERN = re.compile(r"^[A-Za-z0-9 ._\-/\\:]+$")


def _validated_audit_dir(candidate: str | None) -> str | None:
    if not candidate:
        return None
    if not _SAFE_PATH_PATTERN.fullmatch(candidate):
        logger.warning(
            "ROY_GOVERNANCE_AUDIT_DIR contains characters outside the safe "
            "path allowlist, which could be abused for shell injection in "
            "the hook command string (shell=True); falling back to the "
            "default audit directory instead of using this value."
        )
        return None
    return candidate


def default_audit_dir() -> str:
    """Re-reads and re-validates ``ROY_GOVERNANCE_AUDIT_DIR`` on every call.

    Deliberately not a module-level constant: a constant would be computed
    once at first import and never notice a later env var change (or a
    test's ``monkeypatch.setenv``) — see ``roy_admin_audit.py`` for the same
    reasoning applied to the admin_audit/user_approval writers.
    """
    return (
        _validated_audit_dir(os.environ.get("ROY_GOVERNANCE_AUDIT_DIR"))
        or _DEFAULT_SAFE_AUDIT_DIR
    )


AUDIT_HOOK_NAME = "roy-governance-session-start-audit"

_WRITER_SCRIPT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "roy_audit_hook_writer.py"
)


def _audit_command() -> str:
    return f'"{sys.executable}" "{_WRITER_SCRIPT_PATH}" "{default_audit_dir()}"'


def _build_audit_hook_config() -> HookConfig:
    return HookConfig(
        session_start=[
            HookMatcher(
                hooks=[
                    HookDefinition(
                        type=HookType.COMMAND,
                        name=AUDIT_HOOK_NAME,
                        command=_audit_command(),
                        timeout=5,
                    )
                ]
            )
        ]
    )


def _without_audit_hook(config: HookConfig) -> HookConfig:
    """Strip any hook named ``AUDIT_HOOK_NAME`` out of ``config``.

    Used so a same-named hook supplied by a caller (accidentally or as a
    deliberate bypass attempt) can never masquerade as the real governance
    audit hook and get skipped-as-already-present.
    """
    filtered_matchers = []
    for matcher in config.session_start:
        remaining = [h for h in matcher.hooks if h.name != AUDIT_HOOK_NAME]
        if remaining:
            filtered_matchers.append(matcher.model_copy(update={"hooks": remaining}))
    return config.model_copy(update={"session_start": filtered_matchers})


def build_governance_hook_config(
    user_hook_config: HookConfig | None = None,
) -> HookConfig:
    """回傳治理強制的稽核 ``HookConfig``,與呼叫端自帶的 hook_config 合併。

    冪等且不可被同名 hook 繞過:任何名為 ``AUDIT_HOOK_NAME`` 的既有項目
    (不論是我們自己先前已合併過的,或是呼叫端/插件塞的同名假 hook)都會先
    被移除,再放回我們自己現算的那一份——確保稽核 hook 的內容永遠是這個
    函式當下產生的版本,不會因為「名稱已存在」就被信任跳過,也不會因為重複
    合併(見 settings/model.py 的 ``create_request()`` 會再建構一次
    ``StartConversationRequest``,觸發 ``ConversationConfig`` 自己的
    validator 二次執行)而疊加出兩筆重複的稽核紀錄。
    """
    audit_config = _build_audit_hook_config()
    if user_hook_config is None:
        return audit_config

    cleaned = _without_audit_hook(user_hook_config)
    merged = HookConfig.merge([audit_config, cleaned])
    # audit_config 一定非空,merge 結果不可能是 None。
    assert merged is not None
    return merged
