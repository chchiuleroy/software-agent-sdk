"""Roy 的治理稽核 hook,對應 dsh 稽核鏈的地基(見 roy_km wiki
``project_openhands_governance_platform.md``「下一步」第 7 項的查證結論)。

用 OpenHands SDK 原生 hooks 機制(``openhands.sdk.hooks``)掛一個治理強制的
SessionStart 稽核 hook,把 session_id/working_dir/時間戳寫進 JSONL。不論
呼叫端(raw REST API 或 Agent Canvas GUI 走的 ``ConversationConfig``,或
OpenAI 相容端點走的 ``ConversationSettings.create_request()``)有沒有自帶
``hook_config``,都用 ``HookConfig.merge()`` 合併而非覆蓋——對應
``confirmation_policy``/``security_analyzer`` 兩個既有生效點「治理關鍵欄位
不能被呼叫端繞過」的同一套設計原則(見 roy_governance.py)。

小o code review(2026-09-03)抓到的三個問題,均已修正:
1. **不信任 workspace 遮蔽 writer 模組**:原本用 ``python -m
   openhands.sdk.security.roy_audit_hook_writer`` 呼叫,但 executor 會用
   對話的 workspace 當 ``cwd`` 執行這條指令,而 Python 的 ``-m`` 會把
   *目前工作目錄* 加進 ``sys.path[0]``——只要 workspace 根目錄剛好有一個叫
   ``openhands`` 的檔案/套件,就會在真正的 SDK 套件之前被匯入,等於任何人
   都能讓「治理稽核」這個本該對 workspace 內容免疫的動作,執行 workspace
   提供的任意 Python 程式碼。改成直接用這個模組自己的 ``__file__`` 組出
   絕對路徑呼叫(``python <絕對路徑>``),讓 ``sys.path[0]`` 指向這個受信任
   的原始碼目錄,不受 cwd 影響。
2. **同名假 hook 可以繞過強制稽核**:原本冪等判斷只看名稱是否存在,若呼叫端
   (或惡意插件)剛好塞一個同名但改成 no-op 指令的假 hook,合併邏輯會誤判
   「已經有了」直接放行,真正的稽核永遠不會被加入。改成先移除任何同名項目
   再放回我們自己產生的那一份,同名假 hook 會被覆蓋而非被信任。
3. **audit_dir 可能逃逸出雙引號造成 shell injection**:``DEFAULT_AUDIT_DIR``
   若含雙引號字元,原本直接內插進雙引號包住的指令字串會提前結束引號、讓
   後續內容被當成 shell 指令的一部分執行。合法的 Windows 路徑本來就不能
   含雙引號,POSIX 路徑理論上可以但極不尋常——直接拒絕含雙引號的值,退回
   安全預設路徑,不嘗試做通用的 shell escaping(cmd.exe 的引號規則太不
   可靠,拒絕比硬轉義更安全)。

同一輪 review 還抓到兩項**已知限制,本次刻意不修**(範圍超出「補一個治理
hook」,屬於既有架構的既有邊界,見 project_openhands_governance_platform.md
「下一步」討論,需要 Roy 決定是否／何時擴大範圍):
4. **`Conversation(...)`/`LocalConversation` 直接建構會繞過本檔的治理**:
   本檔的 ``build_governance_hook_config()`` 只掛在 ``ConversationConfig``
   (見 conversation/request.py 的 ``_apply_roy_governance_audit_hook``
   validator)跟 ``ConversationSettings``(見 settings/model.py 的
   ``_build_hook_config()``)這兩個「REST API / Settings 請求模型」層,對應
   既有 ``confirmation_policy``/``security_analyzer`` 治理生效點的相同範圍
   邊界。但 ``LocalConversation.__init__`` 本身接受 ``hook_config`` 作為
   直接參數且完全不套用任何預設值——任何繞過這兩個請求模型、直接呼叫
   ``Conversation(...)``/``LocalConversation(...)`` 的 SDK 使用者(例如
   ``poc/`` 下的測試腳本、或 task manager 建立 sub-agent 對話的路徑,見
   ``openhands-tools`` 的 ``tests/tools/task/test_task_manager.py``
   ``_pending_hook_config is None`` 案例)完全不會觸發稽核 hook。要補齊
   需要在 ``LocalConversation.__init__`` 本身(或它呼叫的更底層共用點)
   加治理預設值,是比本次「加一個 hook」更大的架構改動。
5. **Plugin hook 合併發生在本檔之後,可能重複執行**:``LocalConversation.
   _ensure_plugins_loaded()``(見 conversation/impl/local_conversation.py)
   在 builder 完成、拿到本檔已合併好的 ``hook_config`` 之後,才用
   ``HookConfig.merge()`` 把 plugin 自帶的 hooks 疊加進去——那次 merge是
   SDK 既有邏輯,單純串接不做同名去重,若某個 plugin 剛好也定義一個叫
   ``AUDIT_HOOK_NAME`` 的 SessionStart hook,會產生兩筆重複的
   ``session_start`` 紀錄。這是 ``HookConfig.merge()`` 本身的既有行為
   (不論疊加的是不是治理 hook 都一樣),不是本檔新增的問題,修正需要動
   SDK 核心的 merge 邏輯本身,超出本次範圍。
"""

from __future__ import annotations

import logging
import os
import sys

from openhands.sdk.hooks import HookConfig, HookDefinition, HookMatcher, HookType


logger = logging.getLogger(__name__)

_DEFAULT_SAFE_AUDIT_DIR = os.path.join(os.path.expanduser("~"), ".openhands", "audit")

_configured_audit_dir = os.environ.get("ROY_GOVERNANCE_AUDIT_DIR")
if _configured_audit_dir and '"' in _configured_audit_dir:
    logger.warning(
        "ROY_GOVERNANCE_AUDIT_DIR contains a double-quote character, which "
        "could break out of the quoted hook command string; falling back to "
        "the default audit directory instead of using this value."
    )
    _configured_audit_dir = None

DEFAULT_AUDIT_DIR = _configured_audit_dir or _DEFAULT_SAFE_AUDIT_DIR

AUDIT_HOOK_NAME = "roy-governance-session-start-audit"

_WRITER_SCRIPT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "roy_audit_hook_writer.py"
)


def _audit_command() -> str:
    return f'"{sys.executable}" "{_WRITER_SCRIPT_PATH}" "{DEFAULT_AUDIT_DIR}"'


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
