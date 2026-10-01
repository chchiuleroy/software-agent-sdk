"""Secret lookups must never block the asyncio event loop.

A ``LookupSecret`` resolves with a synchronous ``httpx.get``. In the
agent-server that URL points back at the *same* single-process server, so a
lookup performed on the event-loop thread can never be served: the loop is
frozen waiting for a response only the loop can produce, and the request dies
with a 30s ``ReadTimeout`` (seen as 22 consecutive 30s stalls in a CI e2e run;
a py-spy dump showed ``MainThread`` inside ``mask_secrets_in_output`` ->
``LookupSecret.get_value`` -> ``httpx.get`` below ``arun``/``astep``).

``test_arun_masks_a_secret_served_by_the_event_loop`` reproduces that without a
network: the source can only complete once the loop gets a chance to run.
"""

import asyncio
import threading
from unittest.mock import MagicMock

import pytest
from litellm.types.utils import ModelResponse

from openhands.sdk.agent import Agent
from openhands.sdk.conversation.impl.local_conversation import LocalConversation
from openhands.sdk.conversation.secret_registry import (
    FAILED_LOOKUP_RETRY_SECONDS,
    SecretRegistry,
)
from openhands.sdk.event import MessageEvent
from openhands.sdk.llm import LLM, LLMResponse, Message, TextContent
from openhands.sdk.llm.utils.metrics import MetricsSnapshot, TokenUsage
from openhands.sdk.secret import SecretSource


SECRET_VALUE = "s3cr3t-value-from-the-server"

# Not model fields (pydantic cannot build a schema for these types).
_LOOP: list[asyncio.AbstractEventLoop] = []
_LOOP_SERVED_TIMEOUT_SECONDS = 3.0


# Module-level on purpose (see the note in test_secrets_manager.py).
class OnLoopRecordingSource(SecretSource):
    """Records whether ``get_value`` ran on a thread that has a running loop."""

    on_loop_calls: int = 0
    off_loop_calls: int = 0

    def get_value(self):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            type(self).off_loop_calls += 1
        else:
            type(self).on_loop_calls += 1
        return SECRET_VALUE


class ServedByTheLoopSource(SecretSource):
    """Completes only after the event loop has run a callback *it* was asked for.

    Stands in for ``LookupSecret`` pointing at the agent-server itself: the
    request is answered by the loop, so a caller that blocks the loop while
    waiting can never get the answer and times out.
    """

    def get_value(self):
        answered = threading.Event()
        # The "server" answers by running a callback on the loop.
        _LOOP[0].call_soon_threadsafe(answered.set)
        if not answered.wait(_LOOP_SERVED_TIMEOUT_SECONDS):
            raise OSError("ReadTimeout: the loop was blocked while we waited")
        return SECRET_VALUE


class _CountingFailingSource(SecretSource):
    attempts: int = 0

    def get_value(self):
        type(self).attempts += 1
        raise OSError("lookup failed")


def _response(text: str) -> LLMResponse:
    return LLMResponse(
        message=Message(role="assistant", content=[TextContent(text=text)]),
        metrics=MetricsSnapshot(
            model_name="test-leaky",
            accumulated_cost=0.0,
            max_budget_per_task=0.0,
            accumulated_token_usage=TokenUsage(model="test-leaky"),
        ),
        raw_response=MagicMock(spec=ModelResponse, id="r1"),
    )


class LeakyLLM(LLM):
    """Answers once with text that contains the secret value."""

    def __init__(self):
        super().__init__(model="test-leaky", usage_id="test-leaky")

    def completion(self, messages, tools=None, **kw):  # type: ignore[override]
        return _response(f"the token is {SECRET_VALUE}")

    async def acompletion(self, messages, tools=None, **kw):  # type: ignore[override]
        return _response(f"the token is {SECRET_VALUE}")


@pytest.mark.asyncio
async def test_resolve_pending_sources_off_the_loop_enables_masking_on_it():
    """The intended sequence: resolve in a worker thread, then mask on the loop."""
    OnLoopRecordingSource.on_loop_calls = 0
    OnLoopRecordingSource.off_loop_calls = 0
    registry = SecretRegistry()
    registry.update_secrets({"TOKEN": OnLoopRecordingSource()})

    assert registry.has_unresolved_sources()
    await asyncio.to_thread(registry.resolve_pending_sources)
    assert not registry.has_unresolved_sources()

    assert registry.mask_secrets_in_output(f"leak: {SECRET_VALUE}") == (
        "leak: <secret-hidden>"
    )
    assert OnLoopRecordingSource.off_loop_calls == 1
    assert OnLoopRecordingSource.on_loop_calls == 0


def test_resolve_pending_sources_keeps_the_failure_back_off():
    """A failing source is not retried on every call (same window as before)."""

    registry = SecretRegistry()
    registry.update_secrets({"FAILING": _CountingFailingSource()})
    _CountingFailingSource.attempts = 0

    for _ in range(5):
        registry.resolve_pending_sources()
    assert _CountingFailingSource.attempts == 1
    # A source in back-off is not "pending": callers must not spin on it.
    assert not registry.has_unresolved_sources()

    registry._failed_lookups["FAILING"] -= FAILED_LOOKUP_RETRY_SECONDS
    assert registry.has_unresolved_sources()
    registry.resolve_pending_sources()
    assert _CountingFailingSource.attempts == 2


@pytest.mark.asyncio
async def test_arun_masks_a_secret_served_by_the_event_loop(tmp_path):
    """End to end: a loop-served lookup must not deadlock arun()."""
    loop = asyncio.get_running_loop()
    _LOOP[:] = [loop]

    conv = LocalConversation(
        agent=Agent(llm=LeakyLLM(), tools=[]),
        workspace=str(tmp_path),
        visualizer=None,
    )
    conv.update_secrets({"TOKEN": ServedByTheLoopSource()})
    conv.send_message("hello")

    started = loop.time()
    await asyncio.wait_for(conv.arun(), timeout=10.0)
    elapsed = loop.time() - started

    # Before the fix the lookup blocked the loop until its own 3s timeout.
    assert elapsed < 2.0, f"arun() took {elapsed:.1f}s: the loop was blocked"

    agent_messages = [
        e
        for e in conv.state.events
        if isinstance(e, MessageEvent) and e.source == "agent"
    ]
    assert len(agent_messages) == 1
    text = "".join(
        part.text
        for part in agent_messages[0].llm_message.content
        if isinstance(part, TextContent)
    )
    assert SECRET_VALUE not in text
    assert "<secret-hidden>" in text
