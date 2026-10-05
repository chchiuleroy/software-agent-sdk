import asyncio
import functools
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext, suppress
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, cast
from uuid import UUID, uuid4

from pydantic import ValidationError

from openhands.agent_server.conversation_lease import (
    DEFAULT_LEASE_TTL_SECONDS,
    ConversationLease,
    ConversationOwnershipLostError,
)
from openhands.agent_server.governance_client import (
    GovernanceClient,
    GovernancePermanentError,
    compute_display_digest,
)
from openhands.agent_server.governance_display import (
    POLICY_REVISION,
    DisplayProjection,
    build_display,
    truncation_reason,
)
from openhands.agent_server.governance_outbox import (
    RETRIABLE_STATES,
    TERMINAL_STATES,
    GovernanceOutbox,
    OutboxRecord,
    OutboxState,
    check_governed_binding_required,
    record_attempt,
)
from openhands.agent_server.models import (
    ConfirmationResponseRequest,
    EventPage,
    EventSortOrder,
    StoredConversation,
)
from openhands.agent_server.pub_sub import PubSub, Subscriber
from openhands.sdk import LLM, AgentBase, Event, Message, TextContent, get_logger
from openhands.sdk.agent import ACPAgent
from openhands.sdk.agent.acp_file_credentials import (
    CODEX_AUTH_SECRET_NAME,
    is_valid_codex_auth,
)
from openhands.sdk.conversation.base import BaseConversation
from openhands.sdk.conversation.events_list_base import EventsListBase
from openhands.sdk.conversation.exceptions import ConversationRunError
from openhands.sdk.conversation.goal import (
    GoalController,
    GoalDone,
    GoalOutcome,
    GoalStatus,
    GoalStatusName,
    GoalStep,
    GoalVerdict,
)
from openhands.sdk.conversation.goal.prompts import RESUME_PROMPT
from openhands.sdk.conversation.impl.local_conversation import (
    ACP_INFLIGHT_PROMPT_USER_MESSAGE_ID,
    ACP_SUPERSEDE_INFLIGHT_PROMPT,
    LocalConversation,
)
from openhands.sdk.conversation.persistence_const import BASE_STATE
from openhands.sdk.conversation.response_utils import get_agent_final_response
from openhands.sdk.conversation.secret_registry import SecretValue
from openhands.sdk.conversation.state import (
    ConversationExecutionStatus,
    ConversationState,
)
from openhands.sdk.credential import (
    CredentialBindingError,
    CredentialNeedsReauthentication,
    HttpVersionedCredentialBinding,
    VersionedCredentialBinding,
)
from openhands.sdk.event import (
    ActionEvent,
    AgentErrorEvent,
    ObservationBaseEvent,
    ObservationEvent,
    StreamingDeltaEvent,
    UserRejectObservation,
)
from openhands.sdk.event.conversation_error import ConversationErrorEvent
from openhands.sdk.event.conversation_state import ConversationStateUpdateEvent
from openhands.sdk.event.error_classification import ErrorClassification, FailureKind
from openhands.sdk.event.llm_completion_log import LLMCompletionLogEvent
from openhands.sdk.git.exceptions import GitCommandError, GitRepositoryError
from openhands.sdk.git.utils import run_git_command, validate_git_repository
from openhands.sdk.llm.streaming import LLMStreamChunk
from openhands.sdk.mcp.utils import MCPToolProvider
from openhands.sdk.security.analyzer import SecurityAnalyzerBase
from openhands.sdk.security.confirmation_policy import ConfirmationPolicyBase
from openhands.sdk.security.roy_action_binding import (
    ActionBinding,
    ActionBindingMismatchError,
    ActionCountMismatchError,
    ExecutionLeaseExpiredError,
    compute_execution_commitment,
)
from openhands.sdk.security.roy_self_approval import check_not_self_approval
from openhands.sdk.utils.async_utils import AsyncCallbackWrapper
from openhands.sdk.utils.cipher import Cipher
from openhands.sdk.utils.files import atomic_write_text
from openhands.sdk.workspace import LocalWorkspace


LEASE_RENEW_INTERVAL_SECONDS = 15.0
# Bounds initial-state push so subscribe_to_events does not stall on a
# subscriber whose __call__ blocks (e.g. WS with a full TCP send buffer).
INITIAL_STATE_PUSH_TIMEOUT_SECONDS = 0.5
# How often the per-conversation outbox relay loop (team mode only) wakes up
# to retry a record stuck in one of governance_outbox.RETRIABLE_STATES. Not
# tied to LEASE_RENEW_INTERVAL_SECONDS — this is a slower, coarser sweep
# (retrying a central-governance-api call has real network cost, unlike a
# local lease renewal) and the two loops serve unrelated purposes.
GOVERNANCE_OUTBOX_RELAY_INTERVAL_SECONDS = 30.0
# Defensive floor between successive /wait long-polls in
# _wait_for_decision_loop when a call returns changed=False. In the normal
# case that call already blocked server-side for up to
# Settings.wait_max_timeout_seconds (~25-30s), so re-issuing it "immediately"
# per that method's own docstring is correct and this floor is a no-op in
# practice. It only bites if the server (or a test double) returns
# changed=False without actually blocking, which would otherwise spin the
# loop with no event-loop yield point — deliberately much smaller than
# GOVERNANCE_OUTBOX_RELAY_INTERVAL_SECONDS so it doesn't stack a second
# ~30s delay on top of a long-poll that already took ~30s.
WAIT_FOR_DECISION_MIN_RETRY_DELAY_SECONDS = 1.0


logger = get_logger(__name__)


class CredentialBindingActivationTooLate(RuntimeError):
    pass


class GovernanceStartOutcome(StrEnum):
    """What ``run_and_wait_for_start()`` resolved to — see that method's
    docstring for the full handshake this enum is the result of."""

    STARTED = "started"
    REJECTED_CLAIM_FAILED = "rejected_claim_failed"
    REJECTED_BINDING_MISMATCH = "rejected_binding_mismatch"
    REJECTED_LEASE_EXPIRED = "rejected_lease_expired"
    REJECTED_ACTION_COUNT_MISMATCH = "rejected_action_count_mismatch"
    REJECTED_CANCELLED = "rejected_cancelled"
    REJECTED_INTERNAL_ERROR = "rejected_internal_error"
    PENDING_UNKNOWN = "pending_unknown"


class GovernanceApprovalRequiredError(RuntimeError):
    """Raised by ``respond_to_confirmation()`` when team mode is active and
    an ``accept=True`` request omits ``central_approval_id``.

    A valid ``X-Governance-Bridge-Token`` (Phase A) only proves the caller
    is allowed to reach this endpoint at all — it says nothing about
    whether *this specific action* was actually approved by
    central-governance-api. Without this check, team mode's bridge-token
    gate is not actually a governance gate: any bridge-token holder could
    omit ``central_approval_id`` and fall through to the plain accept path
    below, executing the pending action without ever having gone through
    claim/binding verification."""


class GovernanceStartRejectedError(RuntimeError):
    """Raised by ``respond_to_confirmation()`` when a team-mode accept's
    claim/binding handshake (``run_and_wait_for_start()``) resolves to
    anything other than ``STARTED`` — including ``PENDING_UNKNOWN`` (the
    handshake timed out rather than being rejected, but is still not a
    success the caller can act on). Carries the ``GovernanceStartOutcome``
    itself so ``api.py``'s handler can map it to a stable status/error_code
    without re-deriving it from a message string."""

    def __init__(self, outcome: GovernanceStartOutcome) -> None:
        self.outcome = outcome
        super().__init__(f"governed confirmation did not start: {outcome.value}")


@dataclass
class _GovernanceHandshake:
    """Tracks one ``run_and_wait_for_start()`` call — in flight or already
    settled — so a genuine duplicate (same binding fingerprint) joins the
    same shared future instead of the caller inferring ``STARTED`` from
    ``central_approval_id`` alone (comparing only the approval id would let
    a duplicate return ``STARTED`` before the background task had even
    attempted the claim) *and* instead of dispatching a brand new claim/run
    attempt once the original has already reached a terminal outcome — see
    ``run_and_wait_for_start()``'s reuse check."""

    binding_fingerprint: str
    future: asyncio.Future
    task: asyncio.Task


def _resolve_handshake_once(
    future: asyncio.Future, outcome: GovernanceStartOutcome | None = None
) -> None:
    """The only function allowed to complete a governance-handshake future
    — guarantees every ``_run_governed()`` exit path (normal return,
    exception, cancellation) resolves it exactly once, so a caller waiting
    on ``run_and_wait_for_start()`` is never left hanging past its own
    timeout for a reason other than a genuine timeout.

    Thread-safe: schedules the actual ``set_result`` onto the future's own
    event loop via ``call_soon_threadsafe`` rather than calling it directly,
    because the caller may be running on a worker thread (``EventService``
    dispatches sync-only agents' ``conversation.run()`` through an
    executor — see ``run()``'s existing dispatch logic below — and
    ``asyncio.Future`` is not thread-safe).
    """
    if future.done():
        return
    loop = future.get_loop()

    def _do_resolve() -> None:
        if not future.done():
            future.set_result(outcome)

    loop.call_soon_threadsafe(_do_resolve)


def _apply_created(record: OutboxRecord, central_approval_id: str) -> OutboxRecord:
    record.central_approval_id = central_approval_id
    record.state = OutboxState.CREATED
    return record


def _apply_claim(
    record: OutboxRecord, execution_attempt_id: str, executing_lease_expires_at: str
) -> OutboxRecord:
    record.execution_attempt_id = execution_attempt_id
    record.executing_lease_expires_at = executing_lease_expires_at
    record.state = OutboxState.CLAIMED
    return record


def _with_pending_report_outcome(record: OutboxRecord, outcome: str) -> OutboxRecord:
    """Sets the outcome about to be reported — see OutboxRecord.
    pending_report_outcome's own docstring for why this must be persisted
    before the report_result() call it precedes, not after."""
    record.pending_report_outcome = outcome
    return record


def _classify_governed_action_outcome(
    action_event_id: str, tool_call_id: str | None, events: Sequence[Event]
) -> str | None:
    """Central's ``report-result`` outcome for a governed action, read from
    this device's own persisted event history — never guessed. Conservative
    by construction: only ever returns ``"success"``
    or ``"failure_definite"`` when a matching ``ObservationEvent`` actually
    exists (its ``is_error`` flag decides which); an ``AgentErrorEvent``
    (the synthetic error ``start()`` writes on crash-recovery, matched by
    ``tool_call_id`` per ``ConversationState.get_unmatched_actions()``'s own
    convention — it carries no ``action_id``) means the process died and
    there is no way to tell whether the tool's side effect happened first,
    so it maps to ``"failure_unknown"``, not ``"failure_definite"``. A
    ``UserRejectObservation`` here would mean this action was rejected
    *after* already passing the binding check and starting to run, which
    should not happen — also reported as ``"failure_unknown"`` rather than
    silently dropped. Returns ``None`` (not yet resolved, try again later)
    when none of these have appeared yet.
    """
    for event in events:
        if isinstance(event, ObservationEvent) and event.action_id == action_event_id:
            return "failure_definite" if event.observation.is_error else "success"
        if (
            isinstance(event, UserRejectObservation)
            and event.action_id == action_event_id
        ):
            return "failure_unknown"
        if (
            isinstance(event, AgentErrorEvent)
            and tool_call_id is not None
            and event.tool_call_id == tool_call_id
        ):
            return "failure_unknown"
    return None


def _without_agent_context_secret(
    agent: AgentBase,
    secret_name: str,
) -> AgentBase:
    context = agent.agent_context
    if context is None or not context.secrets or secret_name not in context.secrets:
        return agent
    secrets = dict(context.secrets)
    secrets.pop(secret_name, None)
    return agent.model_copy(
        update={"agent_context": context.model_copy(update={"secrets": secrets})}
    )


@dataclass
class EventService:
    """
    Event service for a conversation running locally, analogous to a conversation
    in the SDK. Async mostly for forward compatibility
    """

    stored: StoredConversation
    conversations_dir: Path
    # Agent for a NEW conversation. meta.json (``stored``) no longer carries the
    # agent — base_state.json is its single source of truth — so the creating
    # caller passes it here. On resume this is ``None`` and the agent is loaded
    # from base_state.json.
    agent: AgentBase | None = None
    cipher: Cipher | None = None
    mcp_tool_provider: MCPToolProvider | None = None
    credential_bindings: dict[str, VersionedCredentialBinding] = field(
        default_factory=dict
    )
    owner_instance_id: str = field(default_factory=lambda: uuid4().hex)
    lease_ttl_seconds: float = DEFAULT_LEASE_TTL_SECONDS
    # Sourced from the same validated Config the REST layer's bridge-token
    # gate reads (request.app.state.config) — via ConversationService.
    # get_instance(), which snapshots these at the same point it snapshots
    # every other Config-derived field (owner_instance_id, lease_ttl_seconds
    # above, etc.). Deliberately NOT read from process environment: team
    # mode configured via a JSON config file, a programmatic Config(...),
    # or deferred-init must agree with the REST route's own authorization
    # check, which reads the same Config — a mismatch here is a governance
    # bypass, not just a DI tidiness issue.
    governance_deployment_mode: Literal["personal", "team"] = "personal"
    governance_client: GovernanceClient | None = None
    governance_origin_device_id: str = "unset-device-id"
    governance_refuse_truncated_actions: bool = True
    _conversation: LocalConversation | None = field(default=None, init=False)
    _pub_sub: PubSub[Event] = field(
        default_factory=lambda: PubSub[Event](max_subscribers=50), init=False
    )
    _run_task: asyncio.Task | None = field(default=None, init=False)
    # Set when a send_message(run=True) is rejected because a run is still
    # wrapping up; consumed by _run_and_publish to re-run the stranded message.
    _rerun_requested: bool = field(default=False, init=False)
    # Set only for the internal ACP interrupt/restart path triggered by a new
    # send_message(run=True). Explicit user pause/interrupt clears it so user
    # stop intent wins over an earlier automatic restart request.
    _acp_internal_rerun_requested: bool = field(default=False, init=False)
    # Incremented for explicit user pause/interrupt requests. Internal ACP
    # supersede restarts compare this generation after their interrupt drains
    # so a later Stop/Pause cannot be overwritten by an automatic restart.
    _explicit_interrupt_generation: int = field(default=0, init=False)
    _closing: bool = field(default=False, init=False)
    _run_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)
    _callback_wrapper: AsyncCallbackWrapper | None = field(default=None, init=False)
    _lease: ConversationLease | None = field(default=None, init=False)
    _lease_generation: int | None = field(default=None, init=False)
    _lease_task: asyncio.Task | None = field(default=None, init=False)
    _external_lease_renewal: bool = field(default=False, init=False)
    _run_executor: ThreadPoolExecutor | None = field(default=None, init=False)
    # Background task for a /goal loop that is running inside this conversation.
    _goal_loop_task: asyncio.Task | None = field(default=None, init=False)
    _goal_loop_outcome: GoalOutcome | None = field(default=None, init=False)
    # Monotonic clock of the last activity, used for idle eviction.
    _last_active_monotonic: float = field(default_factory=time.monotonic, init=False)
    # Subscribers attached at startup; later ones (e.g. websockets) are external.
    _internal_subscriber_ids: set[UUID] = field(default_factory=set, init=False)
    # Tracks the in-flight run_and_wait_for_start() call, if any — see
    # _GovernanceHandshake's docstring for why comparing central_approval_id
    # alone isn't enough to detect a genuine duplicate.
    _active_governance_handshake: _GovernanceHandshake | None = field(
        default=None, init=False
    )
    _governance_outbox_instance: GovernanceOutbox | None = field(
        default=None, init=False
    )
    # A binding/lease/count rejection discovered after claim schedules
    # _report_governance_failure() via on_governed_reject — tracked here so
    # close() can await it before deciding whether the outbox is still
    # orphaned (_reconcile_governance_after_close()). Without this, close()
    # could race with an in-flight report and the two could send central
    # conflicting outcomes for the same execution_attempt_id.
    _pending_governance_report_tasks: set[asyncio.Task] = field(
        default_factory=set, init=False
    )
    # maybe_register_governance_approval()'s fire-and-forget
    # _create_governance_approval() task — tracked so close() can
    # cancel-and-drain it the same way as _lease_task/_goal_loop_task,
    # instead of letting it keep writing to self.governance_outbox after
    # this service is considered closed.
    _pending_governance_create_tasks: set[asyncio.Task] = field(
        default_factory=set, init=False
    )
    # Set by close() once it commits to being the sole source of truth for
    # reporting an orphaned claim. A synchronous conversation.run() on a
    # worker thread cannot be forcibly stopped by cancelling its wrapper
    # task, so on_governed_reject can still fire after close() has already
    # moved on to _reconcile_governance_after_close() — this flag stops
    # that late callback from registering a second, competing report.
    _governance_report_registration_closed: bool = field(default=False, init=False)
    # Background relay loop (team mode only, see _outbox_relay_loop()) that
    # periodically retries an outbox record stuck in one of
    # governance_outbox.RETRIABLE_STATES — the existing per-run hooks
    # (maybe_register_governance_approval/maybe_report_governance_result)
    # only ever fire from inside this conversation's own run() finally
    # block, so a record stuck after a crash with no new run activity has
    # no other retry path in this MVP slice (see this task's own docstring
    # for the full gap this closes).
    _outbox_relay_task: asyncio.Task | None = field(default=None, init=False)
    # Phase E: long-polls central for the CREATE -> decide transition (see
    # _wait_for_decision_loop()'s own docstring for why this is a separate
    # task from _outbox_relay_task rather than folded into it — different
    # call shape, long-poll vs a fast periodic check). Only ever one
    # in-flight per conversation, mirroring the outbox's own single-
    # pending-action MVP scope.
    _wait_for_decision_task: asyncio.Task | None = field(default=None, init=False)
    # Redispatches an already-CLAIMED record (execution_attempt_id/lease
    # already on disk, no re-claim needed) into self.run() — see
    # _ensure_claim_redispatch_task()'s own docstring for why this is a
    # dedicated slot rather than reusing _active_governance_handshake:
    # that slot deliberately replays an already-settled outcome forever
    # (correct for a REST caller retrying an already-consumed approval),
    # which is exactly wrong for this one (a pre-dispatch local failure
    # here must free up for a genuine retry, not be cached as terminal).
    _claim_redispatch_task: asyncio.Task | None = field(default=None, init=False)

    @property
    def conversation_dir(self):
        return self.conversations_dir / self.stored.id.hex

    @property
    def governance_outbox(self) -> GovernanceOutbox:
        if self._governance_outbox_instance is None:
            self._governance_outbox_instance = GovernanceOutbox(self.conversation_dir)
        return self._governance_outbox_instance

    async def load_meta(self):
        meta_file = self.conversation_dir / "meta.json"
        self.stored = StoredConversation.model_validate_json(
            meta_file.read_text(),
            context={
                "cipher": self.cipher,
            },
        )

    async def save_meta(self):
        with self._write_guard():
            meta_file = self.conversation_dir / "meta.json"
            meta_file.write_text(
                self.stored.model_dump_json(
                    context={
                        "cipher": self.cipher,
                    }
                )
            )

    def _without_stored_secret(self, secret_name: str) -> StoredConversation:
        # meta.json (StoredConversation) no longer carries the agent, so there is
        # no agent_context secret to scrub here — only the stored secrets map.
        # The agent's own secret scrub happens on base_state.json (see
        # _scrub_persisted_credentials).
        secrets = dict(self.stored.secrets)
        secrets.pop(secret_name, None)
        return self.stored.model_copy(update={"secrets": secrets})

    async def _scrub_persisted_credentials(
        self,
        credential_bindings: Mapping[str, VersionedCredentialBinding] | None = None,
    ) -> None:
        bindings = (
            self.credential_bindings
            if credential_bindings is None
            else credential_bindings
        )
        if not bindings:
            return

        required_bindings = {
            name
            for name, binding in bindings.items()
            if isinstance(binding, HttpVersionedCredentialBinding)
        }
        if required_bindings:
            # Scrubbed durable credentials must never become a fallback again.
            self.stored = self.stored.model_copy(
                update={
                    "required_runtime_credential_bindings": (
                        self.stored.required_runtime_credential_bindings
                        | required_bindings
                    )
                }
            )

        context = {"cipher": self.cipher}
        base_state_file = self.conversation_dir / BASE_STATE
        meta_file = self.conversation_dir / "meta.json"
        legacy_auth_file = self.conversation_dir / "acp" / "codex" / "auth.json"
        codex_binding = bindings.get(CODEX_AUTH_SECRET_NAME)
        if codex_binding is not None and legacy_auth_file.exists():
            resolved = await codex_binding.load()
            if not is_valid_codex_auth(resolved.value):
                raise CredentialNeedsReauthentication(
                    "ChatGPT authentication is invalid. Please sign in again."
                )
        for secret_name in bindings:
            self.stored = self._without_stored_secret(secret_name)

        if (
            not base_state_file.exists()
            and not meta_file.exists()
            and not legacy_auth_file.exists()
        ):
            return

        with self._write_guard():
            if base_state_file.exists():
                state = ConversationState.model_validate_json(
                    base_state_file.read_text(),
                    context=context,
                )
                sources = dict(state.secret_registry.secret_sources)
                for secret_name in bindings:
                    sources.pop(secret_name, None)
                    state.agent = _without_agent_context_secret(
                        state.agent,
                        secret_name,
                    )
                state.secret_registry = state.secret_registry.model_copy(
                    update={"secret_sources": sources}
                )
                atomic_write_text(
                    base_state_file,
                    state.model_dump_json(exclude_none=True, context=context),
                )

            if meta_file.exists():
                atomic_write_text(
                    meta_file,
                    self.stored.model_dump_json(context=context),
                )
            if codex_binding is not None:
                legacy_auth_file.unlink(missing_ok=True)

    async def activate_credential_binding(
        self,
        secret_name: str,
        binding: VersionedCredentialBinding,
    ) -> None:
        existing = self.credential_bindings.get(secret_name)
        if isinstance(existing, HttpVersionedCredentialBinding) and isinstance(
            binding, HttpVersionedCredentialBinding
        ):
            if existing.url != binding.url:
                raise CredentialBindingActivationTooLate
            await self._scrub_persisted_credentials(
                {**self.credential_bindings, secret_name: binding}
            )
            existing.reauthorize(binding)
            return
        if existing is not None:
            raise CredentialBindingActivationTooLate

        conversation = self._conversation
        if conversation is None:
            raise CredentialBindingActivationTooLate

        state = conversation._state
        with state:
            if not isinstance(conversation.agent, ACPAgent):
                raise CredentialBindingActivationTooLate
            agent = cast(
                ACPAgent,
                _without_agent_context_secret(conversation.agent, secret_name),
            )
            try:
                agent.activate_file_credential_binding(secret_name, binding)
            except RuntimeError as exc:
                raise CredentialBindingActivationTooLate from exc

            self.credential_bindings[secret_name] = binding
            sources = dict(state.secret_registry.secret_sources)
            sources.pop(secret_name, None)
            state.secret_registry = state.secret_registry.model_copy(
                update={"secret_sources": sources}
            )
            state.agent = agent
            conversation.agent = agent
            self.stored = self._without_stored_secret(secret_name)
        await self._scrub_persisted_credentials()

    async def apply_resume_secrets(
        self,
        secrets: dict[str, SecretValue],
    ) -> None:
        conversation = self._conversation
        if conversation is None:
            raise ValueError("inactive_service")
        secrets = {
            name: value
            for name, value in secrets.items()
            if name not in self.credential_bindings
        }
        if not secrets:
            return

        def _update() -> None:
            state = conversation._state
            with state:
                registry = state.secret_registry.model_copy(
                    update={
                        "secret_sources": dict(state.secret_registry.secret_sources)
                    }
                )
                registry.update_secrets(secrets)
                state.secret_registry = registry
                agent = conversation.agent
                if isinstance(agent, ACPAgent):
                    agent.restart_for_updated_credentials(secrets)

        await asyncio.to_thread(_update)
        self.stored = self.stored.model_copy(
            update={"secrets": {**self.stored.secrets, **secrets}}
        )
        await self.save_meta()

    def _write_guard(self):
        if self._lease is None or self._lease_generation is None:
            return nullcontext()
        return self._lease.guarded_write(self._lease_generation)

    def renew_lease(self) -> None:
        """Renew this service's conversation lease.

        Called by a centralized renewal loop (when ``_external_lease_renewal``
        is True) or by the per-service ``_renew_lease_loop`` background task.
        """
        if self._lease is None or self._lease_generation is None:
            return
        try:
            self._lease.renew(self._lease_generation)
        except ConversationOwnershipLostError:
            logger.warning(
                "Conversation lease lost while renewing: %s",
                self.stored.id,
            )
        except Exception:
            logger.exception(
                "Failed to renew conversation lease for %s",
                self.stored.id,
            )

    async def _renew_lease_loop(self) -> None:
        if self._lease is None or self._lease_generation is None:
            return
        try:
            while True:
                await asyncio.sleep(LEASE_RENEW_INTERVAL_SECONDS)
                self.renew_lease()
        except asyncio.CancelledError:
            raise

    async def _outbox_relay_loop(self) -> None:
        """Background relay for a governance outbox record stuck in one of
        governance_outbox.RETRIABLE_STATES with no run activity to trigger
        the existing per-run hooks — maybe_register_governance_approval()
        and maybe_report_governance_result() only ever fire from inside
        this conversation's own run() finally block (see run()'s own
        code), so a record stuck after a crash with no subsequent run has
        no other retry path in this MVP slice. Team-mode only; start()
        only creates this task when governance_deployment_mode == "team".
        """
        try:
            while True:
                await asyncio.sleep(GOVERNANCE_OUTBOX_RELAY_INTERVAL_SECONDS)
                try:
                    await self._relay_outbox_once()
                except Exception:
                    # Every call _relay_outbox_once() makes already has its
                    # own try/except that resolves to either "leave state
                    # as-is, retry next cycle" or a NEEDS_ATTENTION
                    # transition — reaching here means a bug in this loop
                    # itself (or the outbox file layer), not a central-
                    # governance-api failure. Log and keep the loop alive
                    # rather than silently stopping all future retries for
                    # the rest of this conversation's lifetime.
                    logger.exception(
                        "outbox relay attempt failed for conversation %s",
                        self.stored.id,
                    )
        except asyncio.CancelledError:
            raise

    async def _relay_outbox_once(self) -> None:
        """One relay attempt: retries whichever central-governance-api
        call an outbox record's current RETRIABLE_STATES state implies is
        still outstanding. A no-op if there is no outbox record, or its
        state is not one of RETRIABLE_STATES — terminal states need no
        retry, and NEEDS_ATTENTION is deliberately excluded from that
        constant (see its own docstring) because a permanent failure must
        never be auto-retried.
        """
        record = self.governance_outbox.load()
        if record is None or record.state not in RETRIABLE_STATES:
            return
        client = self.governance_client
        if client is None:
            return

        if record.state == OutboxState.PENDING_CREATE:
            # _send_create_approval() already implements this exact
            # retry — same idempotency key, same persist-then-classify
            # error handling — reused rather than duplicated here.
            await self._send_create_approval(record)
            return

        if record.state == OutboxState.CLAIM_INFLIGHT:
            assert record.central_approval_id is not None
            try:
                claim_response = await client.claim(
                    record.central_approval_id,
                    idempotency_key=f"claim-{record.request_id}",
                )
            except GovernancePermanentError:
                logger.exception(
                    "outbox relay: claim permanently failed for approval %s",
                    record.central_approval_id,
                )
                await self.governance_outbox.mutate(
                    lambda r: record_attempt(r, new_state=OutboxState.NEEDS_ATTENTION)
                )
                return
            except Exception:
                # Transient (network/5xx) or unclassified — leave state as
                # CLAIM_INFLIGHT so the next relay cycle retries with the
                # same idempotency key rather than giving up.
                logger.warning(
                    "outbox relay: claim retry failed for approval %s, "
                    "will retry again next cycle",
                    record.central_approval_id,
                    exc_info=True,
                )
                await self.governance_outbox.mutate(record_attempt)
                return
            execution_attempt_id = claim_response["execution_attempt_id"]
            lease_expires_at_raw = claim_response["executing_lease_expires_at"]
            updated = await self.governance_outbox.mutate(
                lambda r: _apply_claim(r, execution_attempt_id, lease_expires_at_raw)
            )
            # This relay cycle recovered from a crash that happened
            # *during* the original claim call — nothing else will ever
            # call self.run() for this approval on its own (Phase E's
            # /wait bridge only drives the initial accept, not a claim
            # recovered here), so without this the record would sit at
            # CLAIMED until the central lease simply expires. Dispatch
            # directly with the execution_attempt_id/lease this call just
            # obtained (updated, not the stale `record` loaded at the top
            # of this method) rather than falling through to the CLAIMED
            # branch below on the *next* cycle — no reason to wait another
            # GOVERNANCE_OUTBOX_RELAY_INTERVAL_SECONDS when this call
            # already has everything it needs right now.
            self._ensure_claim_redispatch_task(updated)
            return

        if record.state == OutboxState.CLAIMED:
            # A crash between _apply_claim() and self.run() ever being
            # dispatched for it (inside _claim_and_run_governed()), or a
            # previous redispatch attempt from this exact branch that hit
            # a local, non-central failure (see _dispatch_claimed_run()'s
            # own comment on why that must not be treated as terminal) —
            # either way, retry every cycle until it genuinely resolves
            # (moves to EXECUTION_STARTED, or a terminal/NEEDS_ATTENTION
            # state via report/reconciliation).
            self._ensure_claim_redispatch_task(record)
            return

        if record.state == OutboxState.RESULT_PENDING:
            assert record.central_approval_id is not None
            assert record.execution_attempt_id is not None
            assert record.pending_report_outcome is not None
            try:
                await client.report_result(
                    record.central_approval_id,
                    idempotency_key=f"report-{record.execution_attempt_id}",
                    execution_attempt_id=record.execution_attempt_id,
                    outcome=record.pending_report_outcome,
                )
                await self.governance_outbox.mutate(
                    lambda r: record_attempt(r, new_state=OutboxState.RESULT_REPORTED)
                )
            except GovernancePermanentError:
                logger.exception(
                    "outbox relay: report-result permanently failed for "
                    "approval %s",
                    record.central_approval_id,
                )
                await self.governance_outbox.mutate(
                    lambda r: record_attempt(r, new_state=OutboxState.NEEDS_ATTENTION)
                )
            except Exception:
                logger.warning(
                    "outbox relay: report-result retry failed for approval "
                    "%s, will retry again next cycle",
                    record.central_approval_id,
                    exc_info=True,
                )
                await self.governance_outbox.mutate(record_attempt)
            return

        # RECONCILIATION_PENDING: no code path writes this state yet (the
        # reconciliation-findings flow is not wired up in this MVP slice —
        # see the wiki's "Phase E" gap list), so there is nothing to relay
        # for it. Included in RETRIABLE_STATES for forward-compatibility
        # with that future work, not because this branch is reachable
        # today.

    def _ensure_wait_for_decision_task(self, central_approval_id: str) -> None:
        """Starts _wait_for_decision_loop() if one isn't already running
        for this conversation. Idempotent by design: _send_create_approval
        calls this on every CREATE success, including a relay retry of a
        stuck PENDING_CREATE — this must not spawn a second concurrent
        long-poll for the same approval."""
        if (
            self._wait_for_decision_task is not None
            and not self._wait_for_decision_task.done()
        ):
            return
        self._wait_for_decision_task = asyncio.create_task(
            self._wait_for_decision_loop(central_approval_id)
        )

    def _ensure_claim_redispatch_task(self, record: OutboxRecord) -> None:
        """Redispatches an already-CLAIMED record (``execution_attempt_id``
        / ``executing_lease_expires_at`` already on disk) straight into
        ``self.run()`` via ``_dispatch_claimed_run()`` — deliberately
        without re-claiming: unlike a fresh ``CLAIM_INFLIGHT`` recovery,
        the claim here already genuinely succeeded, so re-claiming would
        just be a redundant central call racing this record's own
        ``execution_attempt_id`` against whatever a second claim response
        returns. Closes the gap where a crash between ``_apply_claim()``
        and ``self.run()`` (inside ``_claim_and_run_governed()``) leaves a
        record with nothing left to ever call ``run()`` for it again —
        ``maybe_report_governance_result()`` only fires from inside this
        conversation's own run() finally block (see its own docstring),
        so a record stuck at ``CLAIMED`` with no run ever having started
        has no other path forward. Called from both ``start()``'s crash-
        recovery and ``_relay_outbox_once()``'s ``CLAIMED``/post-claim-
        success handling — the latter is why this must be safely
        re-callable every relay cycle, not a one-shot attempt.

        Idempotent while genuinely in flight, like
        ``_ensure_wait_for_decision_task()``. Deliberately *not* built on
        ``_active_governance_handshake``'s fingerprint reuse the way
        ``run_and_wait_for_start()`` is: that reuse deliberately replays
        an already-*settled* outcome forever, so a REST caller retrying
        an already-consumed approval can't re-execute it (see that
        method's own docstring) — correct there, wrong here. A pre-
        dispatch failure from this method (e.g. ``conversation_already_
        running`` from an unrelated crash-recovery race, not a genuine
        binding/lease rejection — see ``_dispatch_claimed_run()``'s own
        comment) must free this slot back up once the task is done, so
        the *next* relay cycle gets a real retry instead of replaying a
        cached rejection forever — that distinction is what actually
        closes the delegated review's finding that a redrive with only
        one shot at success is not meaningfully different from never
        redriving at all.
        """
        if (
            self._claim_redispatch_task is not None
            and not self._claim_redispatch_task.done()
        ):
            return
        central_approval_id = record.central_approval_id
        execution_attempt_id = record.execution_attempt_id
        lease_expires_at_raw = record.executing_lease_expires_at
        assert central_approval_id is not None
        assert execution_attempt_id is not None
        assert lease_expires_at_raw is not None
        self._claim_redispatch_task = asyncio.create_task(
            self._dispatch_claimed_run(
                record,
                central_approval_id,
                execution_attempt_id,
                lease_expires_at_raw,
                future=None,
            )
        )

    async def _wait_for_decision_loop(self, central_approval_id: str) -> None:
        """Phase E: long-polls central's ``GET .../wait`` for the CREATE ->
        decide transition (``pending`` -> ``accepted``/``rejected``/other),
        then drives this conversation accordingly. Without this, nothing
        in this MVP slice ever calls run_and_wait_for_start()/
        reject_pending_actions() on the decision's own initiative — only a
        caller that already knows central_approval_id (e.g. a manual
        respond_to_confirmation REST call after someone tells it the
        approval id out of band) could drive it before this existed.

        A separate task from _outbox_relay_loop, not a branch inside it:
        that loop is a fast periodic sweep across every RETRIABLE_STATES
        record (see its own docstring); this is a single long-poll HTTP
        call that blocks server-side for up to
        Settings.wait_max_timeout_seconds, started once per CREATE (see
        _send_create_approval's own call site) and re-issued in a loop
        only because a ``changed=False`` timeout is "try again", not a
        terminal answer — folding this into the relay loop's own fixed
        sleep-then-check cadence would mean either blocking that loop's
        other RETRIABLE_STATES work for the duration of each long-poll, or
        reimplementing a second concurrency model inside it.
        """
        client = self.governance_client
        if client is None:
            return
        try:
            while True:
                record = self.governance_outbox.load()
                if record is None or record.state != OutboxState.CREATED:
                    # Outbox moved on for a reason this loop didn't cause
                    # (archived for a new action, or a relay cycle already
                    # advanced it past CREATED) — nothing left to wait for.
                    return
                try:
                    response = await client.wait(
                        central_approval_id, known_status="pending"
                    )
                except Exception:
                    logger.warning(
                        "wait-for-decision: /wait call failed for approval "
                        "%s, retrying",
                        central_approval_id,
                        exc_info=True,
                    )
                    await asyncio.sleep(GOVERNANCE_OUTBOX_RELAY_INTERVAL_SECONDS)
                    continue
                if not response.get("changed"):
                    # Server-side timeout with no change — not an error,
                    # the correct response is to just ask again (see
                    # GovernanceClient.wait()'s own docstring). The sleep
                    # here is a small defensive floor, not a backoff: see
                    # WAIT_FOR_DECISION_MIN_RETRY_DELAY_SECONDS's own
                    # comment for why it's deliberately short.
                    await asyncio.sleep(WAIT_FOR_DECISION_MIN_RETRY_DELAY_SECONDS)
                    continue
                status = response.get("status")
                if status == "accepted":
                    await self.run_and_wait_for_start(
                        central_approval_id=central_approval_id
                    )
                elif status == "rejected":
                    await self.reject_pending_actions(
                        "rejected via central governance"
                    )
                else:
                    # cancelled/expired, or a status this MVP slice's
                    # state machine doesn't expect to see land here —
                    # nothing this device can safely automate a response
                    # to; flag for a human rather than guessing.
                    logger.warning(
                        "wait-for-decision: approval %s resolved to "
                        "unexpected status %r; marking needs_attention",
                        central_approval_id,
                        status,
                    )
                    await self.governance_outbox.mutate(
                        lambda r: record_attempt(
                            r, new_state=OutboxState.NEEDS_ATTENTION
                        )
                    )
                return
        except asyncio.CancelledError:
            raise

    def get_conversation(self):
        if not self._conversation:
            raise ValueError("inactive_service")
        return self._conversation

    def _get_event_sync(self, event_id: str) -> Event | None:
        """Private sync function to get a single event.

        Reads directly from the EventLog without acquiring the state lock.
        EventLog reads are safe without the FIFOLock because events are
        append-only and immutable once written.
        """
        if not self._conversation:
            raise ValueError("inactive_service")
        events = self._conversation._state.events
        index = events.get_index(event_id)
        return events[index]

    async def get_event(self, event_id: str) -> Event | None:
        if not self._conversation:
            raise ValueError("inactive_service")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._get_event_sync, event_id)

    def _event_matches_filters(
        self,
        event: Event,
        kind: str | None,
        source: str | None,
        body: str | None,
        timestamp_gte_str: str | None,
        timestamp_lt_str: str | None,
    ) -> bool:
        """Return True if ``event`` matches all of the provided filters."""
        if (
            kind is not None
            and f"{event.__class__.__module__}.{event.__class__.__name__}" != kind
        ):
            return False
        if source is not None and event.source != source:
            return False
        if timestamp_gte_str is not None and event.timestamp < timestamp_gte_str:
            return False
        if timestamp_lt_str is not None and event.timestamp >= timestamp_lt_str:
            return False
        # ``body`` is the most expensive filter (deserializes message content),
        # so evaluate it last.
        if body is not None and not self._event_matches_body(event, body):
            return False
        return True

    def _get_searchable_event(self, events: EventsListBase, index: int) -> Event | None:
        try:
            return events[index]
        except (FileNotFoundError, UnicodeDecodeError, ValidationError) as exc:
            logger.warning(
                "Skipping unreadable event at index %d for conversation %s (%s)",
                index,
                self.stored.id,
                type(exc).__name__,
            )
            return None

    def _search_events_sync(
        self,
        page_id: str | None = None,
        limit: int = 100,
        kind: str | None = None,
        source: str | None = None,
        body: str | None = None,
        sort_order: EventSortOrder = EventSortOrder.TIMESTAMP,
        timestamp__gte: datetime | None = None,
        timestamp__lt: datetime | None = None,
    ) -> EventPage:
        """Private sync function to search events.

        Reads directly from the EventLog without acquiring the state lock.
        EventLog reads are safe without the FIFOLock because events are
        append-only and immutable once written.

        Performance:
            Events are appended in chronological order and never reordered,
            so the on-disk index order matches the timestamp sort order.
            We exploit that by iterating the underlying ``Sequence`` lazily
            by index (forward for TIMESTAMP, backward for TIMESTAMP_DESC),
            stopping as soon as we have ``limit + 1`` filter matches.

            This turns ``search_events`` from O(N) disk reads + O(N log N)
            sort into O(limit + skipped) reads with no sort, which is the
            difference between "loads instantly" and "blocks for seconds"
            for long conversations.
        """
        if not self._conversation:
            raise ValueError("inactive_service")

        events = self._conversation._state.events
        total = len(events)

        # Convert datetime to ISO string for comparison (ISO strings are comparable)
        timestamp_gte_str = timestamp__gte.isoformat() if timestamp__gte else None
        timestamp_lt_str = timestamp__lt.isoformat() if timestamp__lt else None

        reverse = sort_order == EventSortOrder.TIMESTAMP_DESC

        # Resolve page_id to a starting index. Prefer the EventLog's O(1)
        # id-to-index map; fall back to a linear scan for plain sequences
        # (e.g. in tests). An unknown page_id falls back to the natural
        # start of the iteration order, matching prior behavior.
        start_index: int | None = None
        if page_id:
            get_index = getattr(events, "get_index", None)
            if get_index is not None:
                try:
                    start_index = get_index(page_id)
                except KeyError:
                    start_index = None
            else:
                for i in range(total):
                    event = self._get_searchable_event(events, i)
                    if event is not None and event.id == page_id:
                        start_index = i
                        break
        if start_index is None:
            start_index = total - 1 if reverse else 0

        if reverse:
            indices: range = range(start_index, -1, -1)
        else:
            indices = range(start_index, total)

        items: list[Event] = []
        next_page_id: str | None = None
        for i in indices:
            event = self._get_searchable_event(events, i)
            if event is None:
                continue
            if not self._event_matches_filters(
                event, kind, source, body, timestamp_gte_str, timestamp_lt_str
            ):
                continue
            if len(items) >= limit:
                next_page_id = event.id
                break
            items.append(event)

        return EventPage(items=items, next_page_id=next_page_id)

    async def search_events(
        self,
        page_id: str | None = None,
        limit: int = 100,
        kind: str | None = None,
        source: str | None = None,
        body: str | None = None,
        sort_order: EventSortOrder = EventSortOrder.TIMESTAMP,
        timestamp__gte: datetime | None = None,
        timestamp__lt: datetime | None = None,
    ) -> EventPage:
        if not self._conversation:
            raise ValueError("inactive_service")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self._search_events_sync,
            page_id,
            limit,
            kind,
            source,
            body,
            sort_order,
            timestamp__gte,
            timestamp__lt,
        )

    def _count_events_sync(
        self,
        kind: str | None = None,
        source: str | None = None,
        body: str | None = None,
        timestamp__gte: datetime | None = None,
        timestamp__lt: datetime | None = None,
    ) -> int:
        """Private sync function to count events.

        Reads directly from the EventLog without acquiring the state lock.
        EventLog reads are safe without the FIFOLock because events are
        append-only and immutable once written.
        """
        if not self._conversation:
            raise ValueError("inactive_service")

        events = self._conversation._state.events

        # Fast path: with no filters, the count is just the sequence length
        # and we can avoid reading any event payloads from disk.
        if (
            kind is None
            and source is None
            and body is None
            and timestamp__gte is None
            and timestamp__lt is None
        ):
            return len(events)

        # Convert datetime to ISO string for comparison (ISO strings are comparable)
        timestamp_gte_str = timestamp__gte.isoformat() if timestamp__gte else None
        timestamp_lt_str = timestamp__lt.isoformat() if timestamp__lt else None

        count = 0
        for i in range(len(events)):
            event = self._get_searchable_event(events, i)
            if event is None:
                continue
            if self._event_matches_filters(
                event, kind, source, body, timestamp_gte_str, timestamp_lt_str
            ):
                count += 1
        return count

    async def count_events(
        self,
        kind: str | None = None,
        source: str | None = None,
        body: str | None = None,
        timestamp__gte: datetime | None = None,
        timestamp__lt: datetime | None = None,
    ) -> int:
        """Count events matching the given filters."""
        if not self._conversation:
            raise ValueError("inactive_service")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self._count_events_sync,
            kind,
            source,
            body,
            timestamp__gte,
            timestamp__lt,
        )

    def _get_execution_status_sync(self) -> ConversationExecutionStatus:
        if not self._conversation:
            raise ValueError("inactive_service")
        with self._conversation._state as state:
            return state.execution_status

    async def _get_execution_status(self) -> ConversationExecutionStatus:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._get_execution_status_sync)

    def _mark_error_status_sync(self) -> None:
        """Force the conversation into ERROR status (idempotent backstop).

        Called when a run task raised before the conversation could set its own
        ERROR status — e.g. an exception in ``init_state``, which executes
        outside ``run()``/``arun()``'s try-block (via ``_ensure_agent_ready()``).
        Without this, the run's finally would publish a stale non-error status
        (IDLE/RUNNING) and the failure would look like a clean stop. No-op once
        the status is already ERROR. Best-effort: never raises (the caller is an
        error handler).
        """
        if not self._conversation:
            return
        with self._conversation._state as state:
            if state.execution_status != ConversationExecutionStatus.ERROR:
                state.execution_status = ConversationExecutionStatus.ERROR

    def _publish_error_event_sync(self, exc: BaseException) -> None:
        """Emit a ConversationErrorEvent so the UI sees the failure detail.

        For LLM/runtime failures that would otherwise only reach the logs — the
        run-loop backstop and auto-title generation (issue #16686). Best-effort:
        never raises (the caller is an error handler).
        """
        if not self._conversation:
            return
        try:
            error_event = ConversationErrorEvent(
                source="environment",
                code=type(exc).__name__,
                detail=str(exc),
            )
            with self._conversation._state:
                self._conversation._on_event(error_event)
        except Exception:
            logger.exception("Failed to publish backstop ConversationErrorEvent")

    def _create_state_update_event_sync(self) -> ConversationStateUpdateEvent:
        if not self._conversation:
            raise ValueError("inactive_service")
        state = self._conversation._state
        with state:
            return ConversationStateUpdateEvent.from_conversation_state(state)

    async def _create_state_update_event(self) -> ConversationStateUpdateEvent:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._create_state_update_event_sync)

    def _event_matches_body(self, event: Event, body: str) -> bool:
        """Check if event's message content matches body filter (case-insensitive)."""
        # Import here to avoid circular imports
        from openhands.sdk.event.llm_convertible.message import MessageEvent
        from openhands.sdk.llm.message import content_to_str

        # Only check MessageEvent instances for body content
        if not isinstance(event, MessageEvent):
            return False

        # Extract text content from the message
        text_parts = content_to_str(event.llm_message.content)

        # Also check extended content if present
        if event.extended_content:
            extended_text_parts = content_to_str(event.extended_content)
            text_parts.extend(extended_text_parts)

        # Also check reasoning content if present
        if event.reasoning_content:
            text_parts.append(event.reasoning_content)

        # Combine all text content and perform case-insensitive substring match
        full_text = " ".join(text_parts).lower()
        return body.lower() in full_text

    async def batch_get_events(self, event_ids: list[str]) -> list[Event | None]:
        """Given a list of ids, get events (Or none for any which were not found)"""
        results = await asyncio.gather(
            *[self.get_event(event_id) for event_id in event_ids]
        )
        return results

    async def send_message(
        self, message: Message, run: bool = False, _from_goal_loop: bool = False
    ):
        if not self._conversation:
            raise ValueError("inactive_service")
        # A normal user message supersedes any active /goal loop in this
        # conversation. The goal loop's own messages pass _from_goal_loop=True.
        if not _from_goal_loop:
            await self.stop_goal_loop()
        explicit_interrupt_generation = self._explicit_interrupt_generation
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._conversation.send_message, message)
        if run:
            if self._explicit_interrupt_generation != explicit_interrupt_generation:
                return
            (
                did_mark_acp_prompt_superseded,
                active_acp_prompt_has_latest_message,
            ) = await self._mark_running_acp_prompt_superseded()
            interrupted_acp = False
            if did_mark_acp_prompt_superseded:
                self._acp_internal_rerun_requested = True
                interrupted_acp = True
                await self.interrupt(internal_acp_rerun=True)
                if self._explicit_interrupt_generation != explicit_interrupt_generation:
                    return
            try:
                await self.run(
                    acp_internal_rerun_generation=explicit_interrupt_generation
                )
                self._acp_internal_rerun_requested = False
            except ValueError as e:
                if isinstance(e, ActionBindingMismatchError):
                    logger.warning(
                        "send_message(run=True) appended the message but run() "
                        "was refused by the governance gate for conversation "
                        "%s: %s",
                        self.stored.id,
                        e,
                    )
                # run() refused. If a run is still wrapping up (its
                # wait_for_pending tail), the message we just appended won't be
                # picked up by it, so record explicit run intent for
                # _run_and_publish to honor once that task clears. Tracking the
                # request — rather than inferring it later from an IDLE status —
                # is what keeps a deliberate run=False append, or an IDLE reached
                # via another path, from triggering an unwanted run.
                # "inactive_service" is terminal and must not re-arm.
                if (
                    str(e) == "conversation_already_running"
                    and not active_acp_prompt_has_latest_message
                ):
                    self._rerun_requested = True
                    if interrupted_acp:
                        self._acp_internal_rerun_requested = True

    def _mark_running_acp_prompt_superseded_sync(self) -> tuple[bool, bool]:
        """Mark the currently running ACP prompt superseded if needed.

        The tuple is ``(did_mark_superseded, active_prompt_has_latest_message)``.
        If the running ACP prompt has already advanced to the newly appended
        user message, interrupting it would cancel the replacement prompt and
        strand that message behind the persisted cursor.
        """
        if not self._conversation:
            return (False, False)
        if self._run_task is None or self._run_task.done():
            return (False, False)
        if not isinstance(self._conversation.agent, ACPAgent):
            return (False, False)
        with self._conversation._state as state:
            if state.execution_status != ConversationExecutionStatus.RUNNING:
                return (False, False)
            inflight_prompt_user_message_id = state.agent_state.get(
                ACP_INFLIGHT_PROMPT_USER_MESSAGE_ID
            )
            last_user_message_id = state.last_user_message_id
            if inflight_prompt_user_message_id is None or last_user_message_id is None:
                return (False, False)
            active_prompt_has_latest_message = (
                inflight_prompt_user_message_id == last_user_message_id
            )
            if active_prompt_has_latest_message:
                return (False, True)
            state.agent_state = {
                **state.agent_state,
                ACP_SUPERSEDE_INFLIGHT_PROMPT: True,
            }
            return (True, False)

    async def _mark_running_acp_prompt_superseded(self) -> tuple[bool, bool]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._mark_running_acp_prompt_superseded_sync
        )

    async def subscribe_to_events(self, subscriber: Subscriber[Event]) -> UUID:
        subscriber_id = self._pub_sub.subscribe(subscriber)

        # Send current state to the new subscriber immediately.
        # The snapshot is created in a worker thread so waiting on the
        # conversation's synchronous FIFOLock cannot block the server event loop.
        if self._conversation:
            state_update_event = await self._create_state_update_event()
        else:
            state_update_event = ConversationStateUpdateEvent(
                key="execution_status",
                value=ConversationExecutionStatus.IDLE,
            )

        try:
            await asyncio.wait_for(
                subscriber(state_update_event),
                timeout=INITIAL_STATE_PUSH_TIMEOUT_SECONDS,
            )
        except TimeoutError:
            # Subscriber stays registered; only the initial-state push is
            # dropped. Subsequent publishes go through pub_sub and may
            # still block there if the subscriber remains wedged.
            logger.warning(
                f"Initial state push to subscriber {subscriber_id} timed "
                f"out after {INITIAL_STATE_PUSH_TIMEOUT_SECONDS}s."
            )
        # Non-timeout errors propagate to caller (e.g. webhook failures).

        return subscriber_id

    async def unsubscribe_from_events(self, subscriber_id: UUID) -> bool:
        return self._pub_sub.unsubscribe(subscriber_id)

    def _emit_event_from_thread(self, event: Event) -> None:
        """Helper to safely emit events from non-async contexts (e.g., callbacks).

        This schedules event emission in the main event loop, making it safe to call
        from callbacks that may run in different threads. Events are emitted through
        the conversation's normal event flow to ensure they are persisted.
        """
        main_loop = self._main_loop
        conversation = self._conversation
        if main_loop and main_loop.is_running() and conversation:
            # Wrap _on_event with lock acquisition to ensure thread-safe access
            # to conversation state and event log during concurrent operations
            def locked_on_event():
                with conversation._state:
                    conversation._on_event(event)

            # Run the locked callback in an executor to ensure the event is
            # both persisted and sent to WebSocket subscribers
            main_loop.run_in_executor(None, locked_on_event)

    def _setup_llm_log_streaming(self, agent: AgentBase) -> None:
        """Configure LLM log callbacks to stream logs via events."""
        for llm in agent.get_all_llms():
            if not llm.log_completions:
                continue

            # Capture variables for closure
            usage_id = llm.usage_id
            model_name = llm.model

            def log_callback(
                filename: str, log_data: str, uid=usage_id, model=model_name
            ) -> None:
                """Callback to emit LLM completion logs as events."""
                try:
                    event = LLMCompletionLogEvent(
                        filename=filename,
                        log_data=log_data,
                        model_name=model,
                        usage_id=uid,
                    )
                    self._emit_event_from_thread(event)
                except Exception:
                    logger.exception("Failed to emit LLM completion log event")

            llm.telemetry.set_log_completions_callback(log_callback)

    def _setup_acp_activity_heartbeat(self, agent: AgentBase) -> None:
        """Wire ACP activity heartbeat to the idle timer.

        ACP agents delegate to an external subprocess (e.g. gemini-cli,
        claude-agent-acp).  Tool calls run inside that subprocess and never
        hit the agent-server's HTTP endpoints, so update_last_execution_time()
        is never called during conn.prompt().  Without a heartbeat the
        runtime-api sees growing idle_time and kills the pod (~20 min).

        This method checks if the agent is an ACPAgent and, if so, injects a
        callback that resets the idle timer whenever the ACP bridge receives
        a streaming update (throttled to every 30 s by the bridge).
        """
        from openhands.sdk.agent import ACPAgent

        if isinstance(agent, ACPAgent):
            from openhands.agent_server.server_details_router import (
                update_last_execution_time,
            )

            agent._on_activity = update_last_execution_time

    def _setup_stats_streaming(self, agent: AgentBase) -> None:
        """Configure stats update callbacks to stream stats changes via events."""

        def stats_callback() -> None:
            """Callback to emit stats updates.

            Invoked synchronously by ``Telemetry.on_response`` (regular
            Agent path) and ``ACPAgent._record_usage`` (ACP path) — both
            run inside ``LocalConversation.run()``'s ``with self._state:``
            block, so the caller already owns the conversation state lock.

            DO NOT re-acquire the state lock here (``with state:``). It
            looks safe — ``FIFOLock`` documents itself as reentrant — but
            on the ACP code path it deadlocks (silently) before the rest
            of ``step()`` can emit the assistant's FinishAction +
            ObservationEvent, leaving every conversation hung in
            ``running`` status forever. ``_emit_event_from_thread`` below
            already acquires the lock on the executor thread before
            persisting the event; that's the only place serialization
            needs the lock anyway.
            """
            # Publish only the stats field to avoid sending entire state
            if not self._conversation:
                return
            event = ConversationStateUpdateEvent(
                key="stats", value=self._conversation._state.stats
            )
            self._emit_event_from_thread(event)

        for llm in agent.get_all_llms():
            llm.telemetry.set_stats_update_callback(stats_callback)

    @staticmethod
    def _ensure_workspace_is_git_repo(working_dir: Path) -> None:
        """Initialize the workspace as a git repo if it isn't already one.

        The /api/git/changes endpoint expects a real repository to compute
        changes against; without this, agent-created files never appear in
        the Changes tab. We only run `git init` (no commit) — empty repos
        are handled by `get_valid_ref()` via GIT_EMPTY_TREE_HASH, and
        untracked files surface through `git ls-files --others`.
        """
        try:
            validate_git_repository(working_dir)
            return  # already a repo
        except GitRepositoryError:
            logger.debug(
                "Workspace %s is not a git repository; running `git init`",
                working_dir,
            )

        try:
            run_git_command(["git", "init"], working_dir)
        except GitCommandError as e:
            # Don't block conversation startup if git is missing or init
            # fails — the git router is defensive and will return [] anyway.
            logger.warning(
                "Failed to initialize git repository at %s: %s", working_dir, e
            )

    async def start(self):
        # Store the main event loop for cross-thread communication
        self._main_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()

        # self.stored contains an Agent configuration we can instantiate
        self.conversation_dir.mkdir(parents=True, exist_ok=True)
        # lease_ttl_seconds=0 disables leasing for single-instance deployments
        # where shared-storage stale leases would otherwise block pod restarts.
        if self.lease_ttl_seconds > 0:
            self._lease = ConversationLease(
                conversation_dir=self.conversation_dir,
                owner_instance_id=self.owner_instance_id,
                ttl_seconds=self.lease_ttl_seconds,
            )
            lease_claim = self._lease.claim()
            self._lease_generation = lease_claim.generation
        await self._scrub_persisted_credentials()
        workspace = self.stored.workspace
        assert isinstance(workspace, LocalWorkspace)
        working_dir = Path(workspace.working_dir)
        working_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_workspace_is_git_repo(working_dir)
        # base_state.json is the single source of truth for the agent. On resume
        # (base_state exists) pass ``agent=None`` so LocalConversation keeps the
        # persisted agent. On a new conversation the creating caller supplied the
        # agent via ``self.agent``; deep-copy it (expose_secrets) so the running
        # agent is independent of the caller's object.
        base_state_exists = await asyncio.to_thread(
            (self.conversation_dir / BASE_STATE).exists
        )
        if base_state_exists:
            agent: AgentBase | None = None
        else:
            if self.agent is None:
                raise ValueError(
                    "Cannot start a new conversation without an agent: no "
                    "base_state.json to resume and no agent was provided."
                )
            agent_cls = type(self.agent)
            agent = agent_cls.model_validate(
                self.agent.model_dump(context={"expose_secrets": True}),
            )

        # Create LocalConversation with plugins and hook_config.
        # Plugins are loaded lazily on first run()/send_message() call.
        # Hook execution semantics: OpenHands runs hooks sequentially with early-exit
        # on block (PreToolUse), unlike Claude Code's parallel execution model.

        # Create and store callback wrapper to allow flushing pending events
        self._callback_wrapper = AsyncCallbackWrapper(
            self._pub_sub, loop=asyncio.get_running_loop()
        )

        # Token streaming is wired only for agents that can actually emit token
        # callbacks (SDK LLM agents with stream=True, or ACP agents). For a NEW
        # conversation the agent is known here, so decide now. On RESUME the
        # agent is loaded from base_state.json during construction, so defer the
        # decision until after (see the post-construction block below).
        def _agent_can_stream(a: AgentBase) -> bool:
            return isinstance(a, ACPAgent) or any(
                llm.stream for llm in a.get_all_llms()
            )

        streaming_enabled = _agent_can_stream(agent) if agent is not None else True
        streaming_decided = agent is not None

        def _publish_stream_delta(
            content: str | None = None,
            reasoning_content: str | None = None,
        ) -> None:
            # Published directly to _pub_sub (not via _callback_wrapper) so
            # deltas reach subscribers but are NOT persisted to
            # ConversationState.events. See StreamingDeltaEvent docstring.
            if not self._main_loop or not self._main_loop.is_running():
                return
            # Use `is not None` rather than truthiness: some providers
            # emit legitimate empty-string chunks at stream boundaries
            # (e.g. after a tool call) that we still want to forward.
            if content is None and reasoning_content is None:
                return
            event = StreamingDeltaEvent(
                content=content,
                reasoning_content=reasoning_content,
            )
            with suppress(RuntimeError):  # main loop already closed during teardown
                asyncio.run_coroutine_threadsafe(self._pub_sub(event), self._main_loop)

        def _token_streaming_callback(chunk: LLMStreamChunk | str) -> None:
            if isinstance(chunk, str):
                _publish_stream_delta(content=chunk)
                return

            for choice in chunk.choices or ():
                delta = choice.delta
                if delta is None:
                    continue
                content = getattr(delta, "content", None)
                reasoning = getattr(delta, "reasoning_content", None)
                _publish_stream_delta(
                    content=content if isinstance(content, str) else None,
                    reasoning_content=reasoning if isinstance(reasoning, str) else None,
                )

        conversation = LocalConversation(
            agent=agent,
            workspace=workspace,
            plugins=self.stored.plugins,
            persistence_dir=str(self.conversations_dir),
            conversation_id=self.stored.id,
            callbacks=[self._callback_wrapper],
            token_callbacks=([_token_streaming_callback] if streaming_enabled else []),
            max_iteration_per_run=self.stored.max_iterations,
            stuck_detection=self.stored.stuck_detection,
            visualizer=None,
            secrets=self.stored.secrets,
            cipher=self.cipher,
            hook_config=self.stored.hook_config,
            tags=self.stored.tags,
            user_id=self.stored.user_id,
            observability_metadata=self.stored.observability_metadata,
            observability_tags=self.stored.observability_tags,
            observability_span_name=self.stored.observability_span_name,
            mcp_tool_provider=self.mcp_tool_provider,
        )

        conversation.set_confirmation_policy(self.stored.confirmation_policy)
        conversation.set_security_analyzer(self.stored.security_analyzer)
        # On resume the agent was unknown at construction time (loaded from
        # base_state.json), so decide token streaming now and disable it when the
        # resolved agent can't emit token callbacks.
        if not streaming_decided:
            streaming_enabled = _agent_can_stream(conversation.agent)
            logger.debug(
                "Token streaming: %s",
                "enabled" if streaming_enabled else "disabled (no LLM has stream=True)",
            )
            if not streaming_enabled:
                conversation.set_token_callbacks(None)
        self._conversation = conversation
        if isinstance(conversation.agent, ACPAgent):
            for secret_name, binding in self.credential_bindings.items():
                conversation.agent.activate_file_credential_binding(
                    secret_name,
                    binding,
                )
        self._conversation._state.set_write_guard(self._write_guard)
        if not self._external_lease_renewal:
            self._lease_task = asyncio.create_task(self._renew_lease_loop())
        if self.governance_deployment_mode == "team":
            self._outbox_relay_task = asyncio.create_task(self._outbox_relay_loop())
            # Crash-recovery for Phase E: an outbox record already at
            # CREATED means a prior process instance sent create and was
            # waiting on decide when it stopped (crash, or a deploy
            # restart) — resume watching it rather than leaving it to sit
            # until the next relay cycle's PENDING_CREATE-only retry path
            # (which wouldn't touch CREATED at all; see
            # _relay_outbox_once's own state-by-state handling).
            existing_record = self.governance_outbox.load()
            if (
                existing_record is not None
                and existing_record.state == OutboxState.CREATED
                and existing_record.central_approval_id is not None
            ):
                self._ensure_wait_for_decision_task(
                    existing_record.central_approval_id
                )
            elif (
                existing_record is not None
                and existing_record.state == OutboxState.CLAIMED
                and existing_record.central_approval_id is not None
            ):
                # A prior process instance's claim succeeded but
                # self.run() was never reached before it stopped — dispatch
                # immediately (no network call needed, execution_attempt_id
                # /lease are already on disk) rather than waiting up to
                # GOVERNANCE_OUTBOX_RELAY_INTERVAL_SECONDS for the relay's
                # own CLAIMED handling to notice. See
                # _ensure_claim_redispatch_task()'s own docstring for why
                # this record would otherwise sit stuck until the central
                # lease simply expires. A CLAIM_INFLIGHT record (claim
                # itself still uncertain) is deliberately left to the
                # relay's own periodic re-claim-with-classification
                # handling below rather than duplicated here — that retry
                # needs an actual network call either way, so there is no
                # equivalent "immediate and free" case to special-case at
                # startup the way there is for an already-CLAIMED record.
                self._ensure_claim_redispatch_task(existing_record)

        # Register state change callback to automatically publish updates
        self._conversation._state.set_on_state_change(self._conversation._on_event)

        # Setup LLM log streaming for remote execution
        self._setup_llm_log_streaming(self._conversation.agent)

        # Setup stats streaming for remote execution
        self._setup_stats_streaming(self._conversation.agent)

        # Wire ACP activity heartbeat so ACP tool calls (which run inside
        # the subprocess and never hit HTTP endpoints) still reset the
        # agent-server's idle timer and prevent runtime-api from killing
        # the pod during long conn.prompt() calls.
        self._setup_acp_activity_heartbeat(self._conversation.agent)

        # Any conversation loaded from disk with RUNNING status is stale. Active
        # split-brain resumes are prevented earlier by the lease claim itself, so if
        # we made it this far there is no live owner and the interrupted tool call
        # should be surfaced back to the agent.
        state = self._conversation.state
        if state.execution_status == ConversationExecutionStatus.RUNNING:
            state.execution_status = ConversationExecutionStatus.ERROR
            # Crash recovery scans the full log, not the active branch: the
            # process may have died between writing an event file and persisting
            # the advanced HEAD, so the leaf can lag the on-disk events. (Remote
            # branching is unsupported — #3749 — so there are no abandoned
            # branches to exclude here anyway.)
            unmatched_actions = ConversationState.get_unmatched_actions(state.events)
            if unmatched_actions:
                first_action = unmatched_actions[0]
                # Skip if any observation-like event already exists for this
                # tool_call_id, to avoid duplicate observations when an
                # observation matches by tool_call_id but not action_id.
                already_observed = any(
                    isinstance(e, ObservationBaseEvent)
                    and e.tool_call_id == first_action.tool_call_id
                    for e in state.events
                )
                if not already_observed:
                    # The persisted HEAD can lag this action when the process
                    # dies after writing the event file but before autosaving
                    # leaf_event_id. Parent the recovery result to the action
                    # explicitly; otherwise normal tree stamping attaches it to
                    # the stale HEAD, making the action and result siblings and
                    # leaving an orphan tool result on the active branch.
                    error_event = AgentErrorEvent(
                        parent_id=first_action.id,
                        tool_name=first_action.tool_name,
                        tool_call_id=first_action.tool_call_id,
                        error=(
                            "A restart occurred while this tool was in progress. "
                            "This may indicate a fatal memory error or system crash. "
                            "The tool execution was interrupted and did not complete."
                        ),
                        classification=ErrorClassification(
                            kind=FailureKind.INTERNAL, retryable=False
                        ),
                    )
                    self._conversation._on_event(error_event)

        # Crash-recovery counterpart to _run_and_publish()'s finally hook:
        # the synthetic AgentErrorEvent written above (if any) is exactly
        # the kind of evidence _classify_governed_action_outcome() reads —
        # without this call, a governed action whose process died mid-
        # execution would never get reported to central unless a *later*
        # run happened to trigger the finally hook again.
        await self.maybe_report_governance_result()

        # Publish initial state update
        await self._publish_state_update()

    async def run(
        self,
        acp_internal_rerun_generation: int | None = None,
        approver_identity: str | None = None,
        expected_binding: ActionBinding | None = None,
        on_governed_start: Callable[[], None] | None = None,
        on_governed_reject: Callable[[BaseException], None] | None = None,
    ):
        """Run the conversation asynchronously in the background.

        This method starts the conversation run in a background task and returns
        immediately.  When possible, the conversation is driven via its native
        ``arun()`` coroutine so LLM I/O does not tie up a thread-pool worker.
        For conversations that do not expose ``arun()`` (e.g., custom
        subclasses) or whose agent only implements sync ``step()`` (no
        ``astep()`` override), the synchronous ``run()`` is executed
        in the thread pool as before.

        Args:
            approver_identity: Forwarded to the conversation's own
                ``run()``/``arun()`` (see ``roy_self_approval.py``). Checked
                here too, synchronously, before scheduling the background
                task — a block raised from *inside* that task would only
                surface as a generic ERROR status + error event (see the
                task's own backstop ``except Exception`` below), not as an
                exception on this call, so the REST caller would never see
                it as the specific rejection it is. Checking twice is
                intentional: this call protects the REST-facing path (whose
                ``SelfApprovalDeniedError`` a dedicated FastAPI handler in
                ``api.py`` maps to a clean 403), the check inside
                ``run()``/``arun()`` itself protects any caller that drives a
                ``LocalConversation`` directly. There remains a narrow TOCTOU
                window between this check and the background task actually
                reaching ``LocalConversation``'s own check — see
                ``roy_self_approval.py``'s known limitations for why that's
                not fully closed yet (the block itself is never bypassed
                either way; only which of the two call sites ends up raising
                it, and thus whether the REST caller sees the clean 403 or a
                generic ERROR status, is affected).
            expected_binding: Forwarded to the conversation's own
                ``run()``/``arun()`` (see ``roy_action_binding.py``). A
                no-op when ``None`` (personal mode/today's behavior,
                unaffected). Not double-checked here the way
                ``approver_identity`` is — the pending-action snapshot this
                check needs is itself part of the atomic transition inside
                ``run()``/``arun()``'s own state lock, so re-reading it here
                first would not be authoritative anyway (see
                ``run_and_wait_for_start()``, which is the intended caller
                for this parameter).
            on_governed_start: Invoked synchronously, still inside
                ``run()``/``arun()``'s own state lock, the moment a governed
                confirmation's binding check passes and execution status has
                just become ``RUNNING`` — i.e. the earliest point at which
                the caller can be told "this will actually execute". Must
                be cheap and non-throwing (see ``_resolve_handshake_once``,
                the only implementation this parameter is used with).
            on_governed_reject: The mirror image of ``on_governed_start``,
                invoked instead of it if ``expected_binding``'s check fails.
                This is the only way a caller of this method — which itself
                returns as soon as the background task is *scheduled*, not
                when that task actually reaches the binding check — can
                observe the rejection (see ``run_and_wait_for_start()``,
                the intended caller for this parameter).

        Raises:
            ValueError: If the service is inactive, conversation is already
                running, or ``approver_identity`` matches the conversation's
                requester identity while a confirmation is pending.
        """
        if not self._conversation or self._closing:
            raise ValueError("inactive_service")

        # Use lock to make check-and-set atomic, preventing race conditions
        async with self._run_lock:
            if (
                await self._get_execution_status()
                == ConversationExecutionStatus.RUNNING
            ):
                raise ValueError("conversation_already_running")
            if (
                await self._get_execution_status()
                == ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
            ):
                check_not_self_approval(
                    getattr(self._conversation, "_requester_identity", None),
                    approver_identity,
                )
                # Closes the SDK呼叫端繞過 gap: send_message(run=True), the
                # goal loop, and the ACP-rerun path in this method's own
                # finally all call run() without threading through
                # expected_binding, which is a no-op when None by design
                # (see this parameter's own docstring below) — without
                # this check, any of those call sites would silently
                # bypass central governance for a conversation that
                # already has a non-terminal governed action pending. Only
                # engages in team mode: check_governed_binding_required()
                # rejects a missing outbox record, and personal mode never
                # has one, so this gate is what keeps personal-mode
                # confirmations unaffected (and avoids a sync file read on
                # every one of them). See that function's own docstring for
                # what it does and does not check.
                if self.governance_deployment_mode == "team":
                    check_governed_binding_required(
                        self.governance_outbox.load(), expected_binding
                    )
            if self._closing:
                raise ValueError("inactive_service")
            if (
                acp_internal_rerun_generation is not None
                and self._explicit_interrupt_generation != acp_internal_rerun_generation
            ):
                return

            # Check if there's already a running task
            if self._run_task is not None and not self._run_task.done():
                raise ValueError("conversation_already_running")

            # Capture conversation reference for the closure
            conversation = self._conversation

            # Start run in background
            loop = asyncio.get_running_loop()

            async def _run_and_publish():
                try:
                    # Prefer the native async path when available so the event
                    # loop is free during LLM I/O.  Fall back to thread-pool
                    # execution for backward compatibility.
                    #
                    # All guards are required:
                    #  • iscoroutinefunction – filters out non-async objects
                    #    (e.g. MagicMock in tests).
                    #  • conversation override – BaseConversation's default
                    #    ``arun()`` delegates to sync ``run()``, so we require an
                    #    *actual* override to avoid running a sync-only subclass
                    #    on the event loop.
                    #  • agent override – ``LocalConversation`` always overrides
                    #    ``arun()``, but an agent without an ``astep()`` override
                    #    runs sync ``step()`` in a worker thread; route it
                    #    through sync ``run()`` instead.
                    arun = getattr(conversation, "arun", None)
                    has_native_arun = (
                        arun is not None
                        and asyncio.iscoroutinefunction(arun)
                        and type(conversation).arun is not BaseConversation.arun
                        and type(conversation.agent).astep is not AgentBase.astep
                    )
                    # approver_identity/expected_binding/on_governed_start
                    # are LocalConversation-specific extensions
                    # (roy_self_approval.py / roy_action_binding.py), not
                    # part of BaseConversation's abstract signature — only
                    # thread through the ones the caller actually supplied,
                    # so a bare run()/arun() call still dispatches exactly
                    # as before against any conversation-like object that
                    # doesn't know these kwargs exist (e.g. test doubles
                    # exercising this dispatch logic in isolation).
                    passthrough_kwargs: dict[str, object] = {}
                    if approver_identity is not None:
                        passthrough_kwargs["approver_identity"] = approver_identity
                    if expected_binding is not None:
                        passthrough_kwargs["expected_binding"] = expected_binding
                    if on_governed_start is not None:
                        passthrough_kwargs["on_governed_start"] = on_governed_start
                    if on_governed_reject is not None:
                        passthrough_kwargs["on_governed_reject"] = on_governed_reject
                    if has_native_arun:
                        await conversation.arun(**passthrough_kwargs)
                    elif passthrough_kwargs:
                        await loop.run_in_executor(
                            self._run_executor,
                            functools.partial(conversation.run, **passthrough_kwargs),
                        )
                    else:
                        await loop.run_in_executor(self._run_executor, conversation.run)
                except (
                    ActionBindingMismatchError,
                    ExecutionLeaseExpiredError,
                    ActionCountMismatchError,
                ):
                    # Mirrors LocalConversation.run()/arun()'s own equivalent
                    # except clause: raised before execution_status was ever
                    # assigned RUNNING (see roy_action_binding.py's placement
                    # in the state-lock critical section), so there is
                    # nothing here to force back to ERROR either — doing so
                    # would overwrite a perfectly valid
                    # WAITING_FOR_CONFIRMATION. _run_governed() (this
                    # exception's actual caller, via run_and_wait_for_start)
                    # has its own try/except around this same call and is
                    # the one that resolves the governance handshake and
                    # routes to pre-claim-abort/report-result accordingly.
                    raise
                except Exception as exc:
                    logger.exception("Error during conversation run")
                    # Backstop: a run that raised before reaching its own error
                    # handling (e.g. an ACP cold-start failure in init_state,
                    # which runs outside run()/arun()'s try-block) can leave the
                    # status at IDLE/RUNNING. Force ERROR so the finally's
                    # _publish_state_update() surfaces the failure instead of a
                    # misleading non-error state.
                    #
                    # Also surface the detail to the UI (issue #16686). A
                    # ConversationRunError means run()/arun() already emitted its
                    # own event, so skip it there to avoid duplicating the error.
                    if not isinstance(exc, ConversationRunError):
                        await loop.run_in_executor(
                            None, self._publish_error_event_sync, exc
                        )
                    await loop.run_in_executor(None, self._mark_error_status_sync)
                finally:
                    # Wait for all pending events to be published via
                    # AsyncCallbackWrapper before publishing the final state update.
                    # This prevents a race condition where the conversation status
                    # becomes FINISHED before agent events (MessageEvent, ActionEvent,
                    # etc.) are published to WebSocket subscribers.
                    if self._callback_wrapper:
                        await loop.run_in_executor(
                            None, self._callback_wrapper.wait_for_pending, 30.0
                        )

                    # Clear task reference and publish state update
                    self._run_task = None
                    # Phase B hook: team mode + exactly one pending action +
                    # no existing outbox record yet -> register a central
                    # approval. A no-op in every other case (see the
                    # method's own docstring for the full gate). Runs
                    # before publishing state so a listener reacting to
                    # WAITING_FOR_CONFIRMATION can assume registration was
                    # at least attempted.
                    await self.maybe_register_governance_approval()
                    # Phase D-lite hook: if a previously-claimed governed
                    # action's fate can now be read from the event log
                    # (success or a normal tool-level failure), report it
                    # to central. A no-op otherwise — see the method's own
                    # docstring.
                    await self.maybe_report_governance_result()
                    await self._publish_state_update()

                    # Re-arm a run for input stranded while this task was
                    # wrapping up. A send_message(run=True) that arrived during
                    # the wait_for_pending() tail above had its run() rejected as
                    # "conversation_already_running" and suppressed, setting
                    # _rerun_requested. Honor it while the conversation is IDLE
                    # (pending input) or internally ACP-interrupted PAUSED (the
                    # old task finished its interrupt before the replacement run
                    # could start). Explicit user pause/interrupt clears the
                    # internal ACP flag, so user stop intent wins over an older
                    # automatic restart request. If the run loop was still alive
                    # it already absorbed the message and we are FINISHED here,
                    # so the guard avoids a redundant run. A deliberate
                    # run=False append, or an IDLE reached via another path,
                    # never sets the flag.
                    rerun_requested = self._rerun_requested
                    acp_internal_rerun_requested = self._acp_internal_rerun_requested
                    rerun_generation = self._explicit_interrupt_generation
                    self._rerun_requested = False
                    self._acp_internal_rerun_requested = False
                    if rerun_requested:
                        status = await self._get_execution_status()
                        rerun_generation_still_valid = (
                            self._explicit_interrupt_generation == rerun_generation
                        )
                        acp_internal_rerun_still_valid = (
                            acp_internal_rerun_requested
                            and rerun_generation_still_valid
                        )
                        should_restart = rerun_generation_still_valid and (
                            status == ConversationExecutionStatus.IDLE
                            or (
                                acp_internal_rerun_still_valid
                                and status == ConversationExecutionStatus.PAUSED
                                and isinstance(conversation.agent, ACPAgent)
                            )
                        )
                        if should_restart:
                            try:
                                await self.run(
                                    acp_internal_rerun_generation=rerun_generation
                                    if acp_internal_rerun_still_valid
                                    else None
                                )
                            except ValueError as e:
                                if str(e) == "conversation_already_running":
                                    self._rerun_requested = True
                                    self._acp_internal_rerun_requested = (
                                        acp_internal_rerun_requested
                                    )
                                else:
                                    raise

            # Create task but don't await it - runs in background
            self._run_task = asyncio.create_task(_run_and_publish())

    def _snapshot_pending_actions_sync(self) -> list[ActionEvent]:
        """Off-loop helper for ``maybe_register_governance_approval()``.
        Must run via executor, never called directly from the event-loop
        thread: ``ConversationState``'s real lock (``FIFOLock``) is a plain
        ``threading.Lock`` under the hood, so acquiring it synchronously on
        the loop thread would stall the *entire* server process for as
        long as a worker-thread ``conversation.run()`` happens to hold it —
        the finally block's own ``self._run_task = None`` leaves a window
        where a fresh run can start on another thread before this hook
        gets to look."""
        assert self._conversation is not None
        with self._conversation._state as state:
            return ConversationState.get_unmatched_actions(state.active_branch())

    async def maybe_register_governance_approval(self) -> None:
        """Phase B hook: called from ``_run_and_publish()``'s ``finally``
        (see ``run()`` above) after every run, whether it ended normally,
        errored, or is now waiting for confirmation.

        A no-op unless ALL of: team mode is active, execution status is
        currently ``WAITING_FOR_CONFIRMATION``, and there is exactly one
        pending action (see roy_action_binding.py's ``ActionCountMismatch
        Error`` — this MVP slice does not support batch confirmations, so
        it simply never engages rather than guessing). If an outbox record
        already exists for a *different* action and has reached a terminal
        state, it is archived (kept on disk as an audit trail, see
        ``GovernanceOutbox.archive_and_clear()``) so this conversation's
        next confirmation round can be governed too — a conversation is not
        limited to a single governed action over its whole lifetime. If an
        outbox record already exists for the *same* action but is still
        ``PENDING_CREATE`` (the create call was interrupted by a crash, or
        by ``close()`` cancelling the create task before it heard back),
        this hook retries it with the same request_id/idempotency key —
        this hook runs after every single run cycle, including crash-
        recovery, so it doubles as the only retry path a stuck
        PENDING_CREATE has in this MVP slice. Fire-and-forget the actual
        central-governance-api call (network I/O) so this method itself
        returns quickly and never blocks the run's own finally/state-
        publish path.
        """
        if self.governance_deployment_mode != "team" or self._conversation is None:
            return
        if (
            await self._get_execution_status()
            != ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        ):
            return
        loop = asyncio.get_running_loop()
        pending = await loop.run_in_executor(None, self._snapshot_pending_actions_sync)
        if len(pending) != 1:
            logger.info(
                "team mode: %d pending actions (need exactly 1) — governance "
                "hook not engaging for conversation %s",
                len(pending),
                self.stored.id,
            )
            return
        (action,) = pending
        existing = self.governance_outbox.load()
        if existing is not None:
            if existing.action_event_id == action.id:
                if existing.state == OutboxState.PENDING_CREATE:
                    # The create call itself never got a confirmed
                    # response last time (a crash, or close() cancelling
                    # the create task while it was still in flight) —
                    # retry it with the same request_id/idempotency key
                    # rather than leaving this conversation permanently
                    # unable to be governed for this action. Nothing else
                    # in this MVP slice retries a stuck PENDING_CREATE.
                    self._schedule_governance_create_task(
                        self._send_create_approval(existing)
                    )
                # Already created (or in flight past create) for this
                # exact action — not a new confirmation round, nothing
                # more to do.
                return
            if existing.state not in TERMINAL_STATES:
                logger.warning(
                    "team mode: outbox already tracks a different, "
                    "non-terminal governance workflow for conversation %s "
                    "— not creating a second one",
                    self.stored.id,
                )
                return
            await self.governance_outbox.archive_and_clear()
        self._schedule_governance_create_task(self._create_governance_approval(action))

    def _schedule_governance_create_task(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._pending_governance_create_tasks.add(task)
        task.add_done_callback(self._pending_governance_create_tasks.discard)

    async def _create_governance_approval(self, action: ActionEvent) -> None:
        client = self.governance_client
        if client is None:
            logger.error(
                "governance_deployment_mode is 'team' but GovernanceClient "
                "env vars are not fully configured; not creating a central "
                "approval for conversation %s",
                self.stored.id,
            )
            return
        conversation_id = str(self.stored.id)
        digest_salt = uuid4().hex
        # Deliberately NOT action.action.model_dump(...) and NOT
        # action.summary: the first is the raw canonical tool call (may
        # contain shell commands, file contents, URLs, tokens) and
        # roy_action_binding.py's own ActionBinding docstring documents that
        # canonical payloads never leave this device; the second is the LLM's
        # unverified claim or, when empty, the SDK's auto-generated
        # "{tool_name}: {every raw argument}". Central only ever sees this
        # deterministic, bounded, redacted projection (governance_display.py).
        display = build_display(action)
        if self.governance_refuse_truncated_actions and display.is_truncated:
            await self._refuse_truncated_action(action, display)
            return
        action_summary = display.summary
        action_payload = display.payload
        action_payload_digest = compute_display_digest(
            action_type="tool_call",
            tool_name=action.tool_name,
            policy_revision=POLICY_REVISION,
            action_summary=action_summary,
            action_payload=action_payload,
            digest_salt=digest_salt,
        )
        record = OutboxRecord(
            request_id=uuid4().hex,
            conversation_id=conversation_id,
            action_event_id=action.id,
            tool_call_id=action.tool_call_id,
            tool_name=action.tool_name,
            action_type="tool_call",
            policy_revision=POLICY_REVISION,
            action_summary=action_summary,
            action_payload=action_payload,
            digest_salt=digest_salt,
            action_payload_digest=action_payload_digest,
            execution_commitment=compute_execution_commitment(action, conversation_id),
            origin_device_id=self.governance_origin_device_id,
        )
        try:
            await self.governance_outbox.create_record(record)
        except FileExistsError:
            # Lost a race with another call to this same method — the
            # existing record is authoritative, nothing more to do.
            return
        await self._send_create_approval(record)

    async def _refuse_truncated_action(
        self, action: ActionEvent, display: DisplayProjection
    ) -> None:
        """Reject a pending action that no approver could be shown in full.

        An approver sees the bounded projection, so approving an action whose
        projection was cut would approve text nobody read. No outbox record
        exists for it, so run() already refuses it (see
        check_governed_binding_required()); rejecting turns that dead end into
        feedback the agent can act on. reject_pending_actions() rejects
        whatever is pending, and a human may have rejected this action
        meanwhile, so the re-check and the rejection happen under one hold of
        the state lock (see _reject_if_still_pending_sync()).

        If rejecting fails the conversation stays waiting with no approval,
        which run() still refuses: the safe outcome holds, so this only logs.
        """
        logger.warning(
            "team mode: refusing action %s (tool %s) for conversation %s: its "
            "approval preview is truncated",
            action.id,
            action.tool_name,
            self.stored.id,
        )
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                self._reject_if_still_pending_sync,
                action.id,
                truncation_reason(display),
            )
        except Exception:
            logger.exception(
                "team mode: could not reject the truncated action %s for "
                "conversation %s; it stays unapproved",
                action.id,
                self.stored.id,
            )

    def _reject_if_still_pending_sync(self, action_id: str, reason: str) -> bool:
        """Off-loop (see _snapshot_pending_actions_sync() for why): reject the
        pending actions only if the one pending action is still ``action_id``.
        The read and the rejection share one hold of the state lock — it is
        reentrant, so reject_pending_actions() takes it again inside — so no
        other thread can change what is pending between them."""
        assert self._conversation is not None
        with self._conversation._state as state:
            pending = ConversationState.get_unmatched_actions(state.active_branch())
            if [a.id for a in pending] != [action_id]:
                return False
            self._conversation.reject_pending_actions(reason)
            return True

    async def _send_create_approval(self, record: OutboxRecord) -> None:
        """POSTs ``record``'s own already-persisted fields to central via
        ``create_approval()``, keyed by the record's own ``request_id`` —
        stable whether this is the record's first attempt (see
        ``_create_governance_approval``) or a retry of one still stuck in
        ``PENDING_CREATE`` (see ``maybe_register_governance_approval``),
        so central's idempotency check treats both the same."""
        client = self.governance_client
        if client is None:
            return
        try:
            response = await client.create_approval(
                {
                    "request_id": record.request_id,
                    "origin_device_id": record.origin_device_id,
                    "conversation_id": record.conversation_id,
                    "action_event_id": record.action_event_id,
                    "tool_call_id": record.tool_call_id,
                    "action_type": record.action_type,
                    "tool_name": record.tool_name,
                    "policy_revision": record.policy_revision,
                    "action_summary": record.action_summary,
                    "action_payload": record.action_payload,
                    "digest_salt": record.digest_salt,
                    "action_payload_digest": record.action_payload_digest,
                },
                idempotency_key=f"create-{record.request_id}",
            )
        except Exception:
            logger.exception(
                "central-governance-api create failed for conversation %s; "
                "leaving outbox in pending_create for a future run to retry",
                record.conversation_id,
            )
            return
        await self.governance_outbox.mutate(lambda r: _apply_created(r, response["id"]))
        # Phase E: start waiting for the decide event now that there is a
        # central_approval_id to wait on — covers both this method's first-
        # attempt caller (_create_governance_approval) and its relay-retry
        # caller (maybe_register_governance_approval's stuck-PENDING_CREATE
        # path / _relay_outbox_once), so either path arriving at CREATED
        # ends up watched.
        self._ensure_wait_for_decision_task(response["id"])

    def _snapshot_events_sync(self) -> list[Event]:
        """Off-loop helper for ``maybe_report_governance_result()`` — see
        ``_snapshot_pending_actions_sync()``'s docstring for why this must
        run via executor rather than directly on the event-loop thread."""
        assert self._conversation is not None
        with self._conversation._state as state:
            return list(state.events)

    async def maybe_report_governance_result(self) -> None:
        """Phase D-lite hook: called from ``_run_and_publish()``'s
        ``finally`` alongside ``maybe_register_governance_approval()``.

        Without this, ``report-result`` is only ever called for a
        binding/lease/count rejection discovered *after* claim (see
        ``_report_governance_failure``) — a governed action that actually
        ran to completion (success or a
        normal tool-level failure) never told central anything past
        ``on_governed_start``, leaving the central record stuck at
        executing/leased until expiry. A no-op unless there is a ``CLAIMED``
        outbox record AND its action's fate can already be read
        unambiguously from the event log (see
        ``_classify_governed_action_outcome`` — never guesses ``"success"``
        without a matching observation); otherwise this is simply retried
        on the next ``finally``.
        """
        if self.governance_deployment_mode != "team" or self._conversation is None:
            return
        record = self.governance_outbox.load()
        # CLAIMED: on_governed_start's own EXECUTION_STARTED mutate (see
        # that closure's comment) hasn't landed yet, or never will
        # (accepted best-effort window). EXECUTION_STARTED: the common
        # case once that mutate has landed. Either way this method's job
        # is the same — check whether the event log now has a conclusive
        # outcome for this action.
        if record is None or record.state not in (
            OutboxState.CLAIMED,
            OutboxState.EXECUTION_STARTED,
        ):
            return
        loop = asyncio.get_running_loop()
        events = await loop.run_in_executor(None, self._snapshot_events_sync)
        outcome = _classify_governed_action_outcome(
            record.action_event_id, record.tool_call_id, events
        )
        if outcome is None:
            return
        client = self.governance_client
        if client is None:
            return
        assert record.central_approval_id is not None
        assert record.execution_attempt_id is not None
        # Durably persist the *intent* to report this exact outcome before
        # making the call — mirrors _claim_and_run_governed()'s
        # CLAIM_INFLIGHT step (see this module's own docstring's "every
        # external call is preceded by durably persisting intent"
        # invariant). Without this, a crash between the call succeeding at
        # central and this process recording that fact locally would leave
        # no record of which outcome was actually reported, and a naive
        # retry could re-classify a different outcome from a since-changed
        # event log — this way, _outbox_relay_loop()'s retry always
        # replays the exact same outcome via the same idempotency key.
        await self.governance_outbox.mutate(
            lambda r: record_attempt(
                _with_pending_report_outcome(r, outcome),
                new_state=OutboxState.RESULT_PENDING,
            )
        )
        try:
            await client.report_result(
                record.central_approval_id,
                idempotency_key=f"report-{record.execution_attempt_id}",
                execution_attempt_id=record.execution_attempt_id,
                outcome=outcome,
            )
            await self.governance_outbox.mutate(
                lambda r: record_attempt(r, new_state=OutboxState.RESULT_REPORTED)
            )
        except GovernancePermanentError:
            logger.exception(
                "failed to report governed execution result for approval %s",
                record.central_approval_id,
            )
            await self.governance_outbox.mutate(
                lambda r: record_attempt(r, new_state=OutboxState.NEEDS_ATTENTION)
            )
        except Exception:
            # Transient (network/5xx) or unclassified — leave state as
            # RESULT_PENDING so _outbox_relay_loop() retries with the same
            # idempotency key on its next cycle, rather than giving up
            # after a single attempt the way this method previously did.
            logger.warning(
                "failed to report governed execution result for approval %s, "
                "will retry via outbox relay",
                record.central_approval_id,
                exc_info=True,
            )
            await self.governance_outbox.mutate(record_attempt)

    async def _reconcile_governance_after_close(self) -> None:
        """Called at the end of ``close()``, after both the governance
        handshake task and the run task (if any) have been cancelled and
        drained. If a central claim succeeded (outbox state ``CLAIMED``)
        but this service is shutting down before ``maybe_report_
        governance_result()`` ever found conclusive evidence — the
        handshake was cancelled before ``self.run()`` even started, or a
        governed run was cancelled mid-execution with nothing observed yet
        — the central execution lease would otherwise be orphaned with no
        path to resolution. Best-effort and unconditional: report
        ``"failure_unknown"`` rather than leave central waiting on a
        process that is being torn down right now.
        """
        client = self.governance_client
        if client is None:
            return
        record = self.governance_outbox.load()
        # See maybe_report_governance_result()'s identical check for why
        # both CLAIMED and EXECUTION_STARTED are accepted here.
        if record is None or record.state not in (
            OutboxState.CLAIMED,
            OutboxState.EXECUTION_STARTED,
        ):
            return
        assert record.central_approval_id is not None
        assert record.execution_attempt_id is not None
        # Same persist-intent-first pattern as maybe_report_governance_
        # result() — see that method's comment for why. NEEDS_ATTENTION on
        # any failure here (rather than leaving it RESULT_PENDING for a
        # relay retry, as maybe_report_governance_result() does) is
        # deliberate: the outbox relay loop was already stopped just above
        # in close(), so nothing would ever retry a RESULT_PENDING left
        # behind by a process that is tearing down right now.
        await self.governance_outbox.mutate(
            lambda r: record_attempt(
                _with_pending_report_outcome(r, "failure_unknown"),
                new_state=OutboxState.RESULT_PENDING,
            )
        )
        try:
            await client.report_result(
                record.central_approval_id,
                idempotency_key=f"report-{record.execution_attempt_id}",
                execution_attempt_id=record.execution_attempt_id,
                outcome="failure_unknown",
            )
            await self.governance_outbox.mutate(
                lambda r: record_attempt(r, new_state=OutboxState.RESULT_REPORTED)
            )
        except Exception:
            logger.exception(
                "failed to reconcile orphaned governance claim %s during close",
                record.central_approval_id,
            )
            await self.governance_outbox.mutate(
                lambda r: record_attempt(r, new_state=OutboxState.NEEDS_ATTENTION)
            )

    async def run_and_wait_for_start(
        self, *, central_approval_id: str, timeout_seconds: float = 20.0
    ) -> GovernanceStartOutcome:
        """Team-mode entry point for ``respond_to_confirmation``'s
        ``accept=True`` path: waits until this governed confirmation has
        either genuinely started executing or been rejected, instead of
        returning as soon as a background task is merely scheduled — a
        "schedule and return 200" version wouldn't give the caller a
        meaningful answer under central governance: a claim, a lease, and
        a report/reconciliation obligation may all already exist by the
        time a caller doing nothing but scheduling would have found out
        that the binding check was going to fail.

        ``_run_lock`` here only ever guards *registering* the handshake and
        scheduling ``_claim_and_run_governed`` — never the claim call
        itself (network I/O) — so this cannot block an unrelated
        ``send_message``/``pause`` call on this conversation for the
        duration of a round trip to central-governance-api.
        """
        if self._closing:
            raise ValueError("inactive_service")
        outbox_record = self.governance_outbox.load()
        if outbox_record is None or outbox_record.central_approval_id != (
            central_approval_id
        ):
            raise ValueError(
                f"no governance outbox record matches approval "
                f"{central_approval_id} for conversation {self.stored.id}"
            )
        binding_fingerprint = ActionBinding(
            central_approval_id=central_approval_id,
            action_event_id=outbox_record.action_event_id,
            execution_commitment=outbox_record.execution_commitment,
        ).fingerprint()

        async with self._run_lock:
            # Re-checked under the lock (same pattern as run()'s own two-
            # stage check): close() and this method both touch
            # _active_governance_handshake, and close() only ever snapshots
            # it once, early on — a handshake created here after that
            # snapshot would never be seen by close(), leaving its claim
            # uncaptured by this shutdown's reconciliation.
            if self._closing:
                raise ValueError("inactive_service")
            existing = self._active_governance_handshake
            if existing is not None and existing.binding_fingerprint == (
                binding_fingerprint
            ):
                # Reuse unconditionally, whether the handshake is still in
                # flight or already settled. Awaiting an already-done
                # future just replays its settled outcome synchronously —
                # without this, a retried call for the exact same binding
                # (central replaying create/claim with the same
                # idempotency key after e.g. a PENDING_UNKNOWN timeout, or
                # any other caller retry) would dispatch a brand new
                # _claim_and_run_governed() attempt for an execution that
                # already reached a terminal outcome, turning an already-
                # consumed central approval into a replayable execution
                # credential (it could re-run self.run() against a
                # conversation that has since moved past
                # WAITING_FOR_CONFIRMATION entirely).
                future = existing.future
            elif existing is not None and not existing.future.done():
                raise ValueError(
                    "a different governance execution is already in "
                    "flight for this conversation"
                )
            else:
                if outbox_record.state in TERMINAL_STATES:
                    # Only a *new* handshake is refused here; a retry that
                    # matches the active handshake reuses it above and
                    # replays its settled outcome. With no matching
                    # handshake in memory (fresh process, or a different
                    # approval ran since) the outbox is the only record of
                    # this approval, and a finished one must not enter the
                    # claim flow again: that would overwrite its terminal
                    # state and let a consumed approval drive a new run.
                    raise ActionBindingMismatchError(
                        f"governance approval {central_approval_id} is "
                        f"already finished ({outbox_record.state.name}) and "
                        "cannot start a new execution"
                    )
                future = asyncio.get_running_loop().create_future()
                task = asyncio.create_task(
                    self._claim_and_run_governed(
                        outbox_record, central_approval_id, future
                    )
                )
                self._active_governance_handshake = _GovernanceHandshake(
                    binding_fingerprint=binding_fingerprint,
                    future=future,
                    task=task,
                )

        try:
            return await asyncio.wait_for(
                asyncio.shield(future), timeout=timeout_seconds
            )
        except TimeoutError:
            # Not a rejection — the handshake future is untouched (shield()
            # protects it from this timeout's cancellation) and the
            # underlying claim/run continues; the outbox is the source of
            # truth for whatever eventually happens.
            return GovernanceStartOutcome.PENDING_UNKNOWN

    async def _claim_and_run_governed(
        self,
        outbox_record: OutboxRecord,
        central_approval_id: str,
        future: asyncio.Future,
    ) -> None:
        """Task body scheduled by ``run_and_wait_for_start()``. Guarantees
        ``future`` resolves exactly once (via ``_resolve_handshake_once``)
        regardless of which step fails — claim, or the governed
        ``run()`` itself."""
        try:
            client = self.governance_client
            if client is None:
                logger.error(
                    "governance_deployment_mode is 'team' but GovernanceClient "
                    "env vars are not fully configured; refusing to claim %s",
                    central_approval_id,
                )
                _resolve_handshake_once(
                    future, GovernanceStartOutcome.REJECTED_INTERNAL_ERROR
                )
                return

            try:
                await self.governance_outbox.mutate(
                    lambda r: record_attempt(r, new_state=OutboxState.CLAIM_INFLIGHT)
                )
                claim_response = await client.claim(
                    central_approval_id,
                    idempotency_key=f"claim-{outbox_record.request_id}",
                )
            except Exception:
                logger.exception(
                    "claim failed for governance approval %s", central_approval_id
                )
                await self.governance_outbox.mutate(
                    lambda r: record_attempt(r, new_state=OutboxState.NEEDS_ATTENTION)
                )
                _resolve_handshake_once(
                    future, GovernanceStartOutcome.REJECTED_CLAIM_FAILED
                )
                return

            execution_attempt_id = claim_response["execution_attempt_id"]
            lease_expires_at_raw = claim_response["executing_lease_expires_at"]
            await self.governance_outbox.mutate(
                lambda r: _apply_claim(r, execution_attempt_id, lease_expires_at_raw)
            )

            await self._dispatch_claimed_run(
                outbox_record,
                central_approval_id,
                execution_attempt_id,
                lease_expires_at_raw,
                future,
            )
        except asyncio.CancelledError:
            # Deliberately NOT a bare `finally`: after `await self.run(...)`
            # returns normally (the common case — self.run() only
            # *schedules* the real run as a separate task and returns
            # almost immediately, well before on_governed_start/
            # on_governed_reject have had any chance to fire — see
            # _dispatch_claimed_run()'s own comment on capturing the
            # loop), this try body reaches its end with the handshake
            # future still genuinely unresolved. A bare `finally` here
            # would unconditionally resolve it to REJECTED_CANCELLED at
            # that point, pre-empting the real STARTED/REJECTED_* outcome
            # the callback is about to deliver. Only a genuine
            # cancellation of *this* task — e.g. EventService.close()
            # draining it — should force-resolve the future here; every
            # other exit path above already resolved it itself via
            # _resolve_handshake_once(), which is idempotent.
            _resolve_handshake_once(future, GovernanceStartOutcome.REJECTED_CANCELLED)
            raise

    async def _dispatch_claimed_run(
        self,
        outbox_record: OutboxRecord,
        central_approval_id: str,
        execution_attempt_id: str,
        lease_expires_at_raw: str,
        future: asyncio.Future | None,
    ) -> None:
        """Builds the ``ActionBinding`` for an already-claimed record and
        calls ``self.run()`` to actually start it, wiring
        ``on_governed_start``/``on_governed_reject`` identically
        regardless of caller. Shared by two callers with different
        expectations about the outcome:

        - ``_claim_and_run_governed()`` (``future`` is a real handshake a
          REST caller is awaiting via ``run_and_wait_for_start()``) — a
          pre-dispatch failure here is genuinely terminal for that
          caller's request, so it resolves ``future`` to
          ``REJECTED_INTERNAL_ERROR``.
        - ``_ensure_claim_redispatch_task()`` (``future`` is ``None`` — a
          crash-recovery redispatch of an already-``CLAIMED`` record with
          no caller waiting on a result) — a pre-dispatch failure there
          (e.g. ``conversation_already_running`` from an unrelated
          concurrent recovery path) is a local, transient conflict, not
          central rejecting the action, so it must NOT be treated as
          terminal: this method just logs and returns, leaving the
          outbox at ``CLAIMED`` (still in ``RETRIABLE_STATES``) for the
          next relay cycle to genuinely retry. See that method's own
          docstring for why this differs from
          ``run_and_wait_for_start()``'s own handshake-reuse semantics.

        A binding-check failure discovered *inside* ``self.run()``'s own
        dispatch is unaffected by which caller this is — it is only ever
        observed via ``on_governed_reject`` below, never as an exception
        on the ``self.run()`` call itself, and central is always told
        about it via ``_report_governance_failure()`` regardless of
        whether anyone is waiting on ``future``.
        """

        def _resolve(outcome: GovernanceStartOutcome) -> None:
            if future is not None:
                _resolve_handshake_once(future, outcome)

        binding = ActionBinding(
            central_approval_id=central_approval_id,
            action_event_id=outbox_record.action_event_id,
            execution_commitment=outbox_record.execution_commitment,
            execution_attempt_id=execution_attempt_id,
            executing_lease_expires_at=datetime.fromisoformat(lease_expires_at_raw),
        )

        # `self.run()` only *schedules* the actual conversation run as a
        # background task and returns immediately (see its own docstring) —
        # the binding check this whole handshake exists to gate on happens
        # deep inside that background task, on whichever thread ends up
        # running it (a worker thread for a sync-only agent's conversation.
        # run(), the event-loop thread for arun()). So on_governed_start/
        # on_governed_reject, not this call's own return or exceptions, are
        # the only way to observe that check's outcome — capture the loop
        # here so both callbacks can safely hand work back to it regardless
        # of which thread invokes them.
        loop = asyncio.get_running_loop()

        def _on_start() -> None:
            _resolve(GovernanceStartOutcome.STARTED)

            # Best-effort persistence of EXECUTION_STARTED — NOT a
            # durability guarantee. This callback fires synchronously,
            # still inside the conversation's own state lock (see
            # run()'s docstring for on_governed_start), so it must stay
            # cheap and non-throwing; a real durable write here would
            # mean doing file I/O inside that lock. Scheduling the
            # mutate onto the loop instead leaves a narrow window: a
            # crash between the binding check passing here and this
            # scheduled mutate actually completing leaves the outbox
            # at CLAIMED rather than EXECUTION_STARTED. That is an
            # accepted trade-off (see the wiki's design notes this
            # task closes) — CLAIMED is what crash-recovery already
            # handles via maybe_report_governance_result()'s own event-
            # log classification, so no execution outcome is ever lost
            # or duplicated by this window; only this one intermediate
            # progress marker's visibility to central is at risk, and
            # only in that narrow window. Tracked in
            # _pending_governance_report_tasks (same set close() drains
            # before _reconcile_governance_after_close(), even though
            # this isn't a "report" task — reusing it here still lets
            # close() wait for this mutate rather than possibly racing
            # it) so normal (non-crash) shutdown never loses this
            # marker either.
            def _mark_started_on_loop() -> None:
                task = asyncio.create_task(
                    self.governance_outbox.mutate(
                        lambda r: record_attempt(
                            r, new_state=OutboxState.EXECUTION_STARTED
                        )
                    )
                )
                self._pending_governance_report_tasks.add(task)
                task.add_done_callback(
                    self._pending_governance_report_tasks.discard
                )

            loop.call_soon_threadsafe(_mark_started_on_loop)

        def _on_reject(exc: BaseException) -> None:
            if isinstance(exc, ActionBindingMismatchError):
                outcome = GovernanceStartOutcome.REJECTED_BINDING_MISMATCH
            elif isinstance(exc, ActionCountMismatchError):
                outcome = GovernanceStartOutcome.REJECTED_ACTION_COUNT_MISMATCH
            elif isinstance(exc, ExecutionLeaseExpiredError):
                outcome = GovernanceStartOutcome.REJECTED_LEASE_EXPIRED
            else:
                outcome = GovernanceStartOutcome.REJECTED_INTERNAL_ERROR

            # call_soon_threadsafe (not run_coroutine_threadsafe): this
            # callback may run on a worker thread, so it hands the real
            # work back to the loop thread. Once running there it
            # resolves the future directly and registers the report
            # task back-to-back with no await between them, so close()
            # (itself only ever running on the loop thread) can never
            # observe one without the other.
            def _handle_reject_on_loop() -> None:
                if future is not None and not future.done():
                    future.set_result(outcome)
                # close() has already committed to being the sole
                # reporter for this claim (see
                # _governance_report_registration_closed's field
                # docstring) — registering a report here now would be a
                # second, untracked, competing outcome for central.
                if self._governance_report_registration_closed:
                    return
                task = asyncio.create_task(
                    self._report_governance_failure(
                        central_approval_id, execution_attempt_id
                    )
                )
                self._pending_governance_report_tasks.add(task)
                task.add_done_callback(
                    self._pending_governance_report_tasks.discard
                )

            loop.call_soon_threadsafe(_handle_reject_on_loop)

        try:
            await self.run(
                expected_binding=binding,
                on_governed_start=_on_start,
                on_governed_reject=_on_reject,
            )
        except Exception:
            if future is not None:
                # Only pre-dispatch failures reach here (inactive_service,
                # conversation_already_running, a self-approval block) — a
                # binding-check failure is only ever observed via
                # on_governed_reject above, never as an exception on this
                # call.
                logger.exception(
                    "run() rejected governed start for approval %s",
                    central_approval_id,
                )
                _resolve(GovernanceStartOutcome.REJECTED_INTERNAL_ERROR)
            else:
                # No caller waiting (a crash-recovery redispatch) — see
                # this method's own docstring for why this must not be
                # treated as a terminal outcome for the approval, just
                # this one attempt.
                logger.warning(
                    "claim redispatch failed for approval %s, will retry "
                    "again next relay cycle",
                    central_approval_id,
                    exc_info=True,
                )

    async def _report_governance_failure(
        self, central_approval_id: str, execution_attempt_id: str
    ) -> None:
        """Best-effort report-result(failure_definite) for a binding/lease
        rejection discovered *after* claim already succeeded — a narrow
        window that's unavoidable without a heavier synchronous protocol.
        This does not block the handshake response; failures here leave
        the outbox in NEEDS_ATTENTION for manual/relay follow-up (the
        relay loop itself is not part of this MVP slice).
        """
        client = self.governance_client
        if client is None:
            return
        try:
            await client.report_result(
                central_approval_id,
                idempotency_key=f"report-{execution_attempt_id}",
                execution_attempt_id=execution_attempt_id,
                outcome="failure_definite",
            )
            await self.governance_outbox.mutate(
                lambda r: record_attempt(r, new_state=OutboxState.RESULT_REPORTED)
            )
        except Exception:
            logger.exception(
                "failed to report binding-mismatch failure for approval %s",
                central_approval_id,
            )
            await self.governance_outbox.mutate(
                lambda r: record_attempt(r, new_state=OutboxState.NEEDS_ATTENTION)
            )

    async def start_goal_loop(
        self,
        objective: str,
        *,
        judge_llm: LLM | None = None,
        max_iterations: int = 10,
    ) -> None:
        """Start a ``/goal`` loop inside this conversation.

        Sends the objective, runs the agent, and judges completion after each
        run, re-prompting until the goal is done or ``max_iterations`` is
        reached. All work stays in this conversation's event history and stream,
        exactly like a normal run; this does not create another conversation.

        Args:
            objective: The goal to pursue and audit against.
            judge_llm: LLM that grades completion. Defaults to the agent's LLM.
            max_iterations: Hard cap on audit rounds before giving up.

        Raises:
            ValueError: If the service is inactive, a goal loop is already
                running, no judge LLM is available, or the objective is empty.
        """
        if not self._conversation or self._closing:
            raise ValueError("inactive_service")
        if judge_llm is None:
            judge_llm = getattr(self._conversation.agent, "llm", None)
        if judge_llm is None:
            raise ValueError("no_judge_llm")
        # GoalController validates the objective/max_iterations (raises ValueError).
        controller = GoalController(objective, judge_llm, max_iterations=max_iterations)
        # Under _run_lock, atomically refuse a concurrent goal loop or active
        # conversation run; otherwise /goal could judge an unrelated transcript.
        async with self._run_lock:
            if self._closing:
                raise ValueError("inactive_service")
            if self._goal_loop_task is not None and not self._goal_loop_task.done():
                raise ValueError("goal_already_running")
            # _run_task first: a live run holds the state lock across its step,
            # so reading execution status would block behind it.
            if (self._run_task is not None and not self._run_task.done()) or (
                await self._get_execution_status()
                == ConversationExecutionStatus.RUNNING
            ):
                raise ValueError("conversation_already_running")
            # Re-check after the await above: close() runs without _run_lock, so
            # it may have begun teardown meanwhile (mirrors run()'s post-status
            # _closing re-check) -- avoid spawning a task close() won't cancel.
            if self._closing:
                raise ValueError("inactive_service")
            self._goal_loop_outcome = None
            self._goal_loop_task = asyncio.create_task(self._run_goal_loop(controller))

    async def _run_goal_loop(
        self, controller: GoalController, *, resume: bool = False
    ) -> None:
        """Drive one active ``/goal`` loop inside this conversation.

        Reuses the SDK's transport-agnostic ``GoalController`` for decisions;
        this method owns only I/O: sending messages, awaiting each run, judging
        off the event loop, and publishing goal-status updates.
        """
        conversation = self._conversation
        if conversation is None:
            return
        loop = asyncio.get_running_loop()

        def _snapshot_and_judge() -> GoalStep:
            # Snapshot events under the conversation lock, then judge (an LLM
            # call) with the lock released -- both on this worker thread.
            with conversation._state:
                events = list(conversation._state.events)
            return controller.on_run_finished(events)

        def _user(text: str) -> Message:
            return Message(role="user", content=[TextContent(text=text)])

        async def _emit_status(
            *,
            active: bool,
            status: GoalStatusName,
            verdict: GoalVerdict | None = None,
        ) -> None:
            # Persist + publish a goal-status update so a UI can render a chip.
            # ConversationStateUpdateEvent is not LLM-convertible, so it never
            # enters the agent's or the judge's context.
            event = ConversationStateUpdateEvent(
                key="goal",
                value=GoalStatus(
                    active=active,
                    status=status,
                    iteration=controller.iteration,
                    max_iterations=controller.max_iterations,
                    objective=controller.objective,
                    verdict=verdict,
                ).model_dump(),
            )

            def _persist() -> None:
                with conversation._state:
                    conversation._on_event(event)

            await loop.run_in_executor(None, _persist)

        try:
            await _emit_status(active=True, status="running")
            nudge = RESUME_PROMPT if resume else controller.start()
            await self.send_message(_user(nudge), run=False, _from_goal_loop=True)
            while True:
                try:
                    await self.run()
                except (
                    ActionBindingMismatchError,
                    ActionCountMismatchError,
                    ExecutionLeaseExpiredError,
                ):
                    # Team mode blocked this run() because a governed
                    # action requires central approval that has not been
                    # granted — an expected governance gate (see
                    # check_governed_binding_required(), which this
                    # method's own bindingless self.run() call is exactly
                    # the kind of caller that check exists to stop), not a
                    # goal-loop bug. Halt the same way the PAUSED/ERROR
                    # branch below does, rather than falling through to
                    # this method's outer `except Exception` handler,
                    # which would misleadingly log an expected governance
                    # gate as "Goal loop failed".
                    logger.info(
                        "Goal loop halted: awaiting central governance approval"
                    )
                    await _emit_status(active=False, status="interrupted")
                    return
                except ValueError as e:
                    if str(e) != "conversation_already_running":
                        raise
                run_task = self._run_task
                if run_task is not None:
                    await asyncio.wait({run_task})
                status = await self._get_execution_status()
                if status in (
                    ConversationExecutionStatus.PAUSED,
                    ConversationExecutionStatus.ERROR,
                ):
                    logger.info("Goal loop halted early: status=%s", status)
                    await _emit_status(active=False, status="interrupted")
                    return
                if status == ConversationExecutionStatus.STUCK:
                    # The stuck detector is a heuristic that often fires during
                    # legitimate iteration (re-running a test, retrying an edit).
                    # The goal loop already has an authoritative judge that
                    # audits completion each round, so a STUCK run is not a
                    # reason to halt the whole goal -- proceed to the judge and
                    # let it decide continue-vs-stop (sending a followup nudge
                    # that breaks the agent out of any genuine loop). Only
                    # PAUSED/ERROR (real stop signals) terminate the goal.
                    logger.info("Goal loop continuing past stuck run")
                step = await loop.run_in_executor(None, _snapshot_and_judge)
                if isinstance(step, GoalDone):
                    self._goal_loop_outcome = step.outcome
                    await _emit_status(
                        active=False,
                        status=step.outcome.status,
                        verdict=step.outcome.verdict,
                    )
                    logger.info(
                        "Goal %s after %d round(s)",
                        step.outcome.status,
                        step.outcome.iterations,
                    )
                    return
                # Carry the round's verdict so a UI can show per-round judge
                # feedback (score + what's missing), not just the final one.
                await _emit_status(active=True, status="running", verdict=step.verdict)
                await self.send_message(
                    _user(step.followup), run=False, _from_goal_loop=True
                )
        except asyncio.CancelledError:
            logger.info("Goal loop cancelled")
            # Explicit stop or user interjection: record a resumable
            # interrupted status, except during service teardown.
            if not self._closing:
                with suppress(Exception):
                    await _emit_status(active=False, status="interrupted")
            raise
        except Exception:
            logger.exception("Goal loop failed")
            # An unexpected failure (judge LLM error, controller bug, ...) leaves
            # the loop dead: record an interrupted status (resumable) so the UI
            # doesn't show it running. Skip during close(), like the cancel path.
            if not self._closing:
                with suppress(Exception):
                    await _emit_status(active=False, status="interrupted")
        finally:
            self._goal_loop_task = None

    async def stop_goal_loop(self) -> bool:
        """Cancel the active ``/goal`` loop inside this conversation.

        Returns True if a loop was active. Unlike ``interrupt()``, this targets
        the background goal loop itself and records an ``interrupted`` status so
        :meth:`resume_goal_loop` can continue it later.
        """
        task = self._goal_loop_task
        if task is None or task.done():
            return False
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        return True

    def _last_goal_loop_status(self) -> dict | None:
        """Return the most recent goal-status payload, or None if there is none."""
        conversation = self._conversation
        if conversation is None:
            return None
        with conversation._state:
            for event in reversed(list(conversation._state.events)):
                if (
                    isinstance(event, ConversationStateUpdateEvent)
                    and event.key == "goal"
                ):
                    return event.value if isinstance(event.value, dict) else None
        return None

    async def resume_goal_loop(
        self, *, judge_llm: LLM | None = None, max_iterations: int | None = None
    ) -> None:
        """Resume the last interrupted ``/goal`` loop in this conversation.

        Reconstructs the loop from the last persisted goal-status event and
        continues from the iteration it had reached. This works within a session
        and across a server restart because goal-status events are persisted.

        Raises:
            ValueError: If the service is inactive, a goal loop is already
                running, no judge LLM is available, or there is no resumable goal
                loop because none was started or it already completed/capped.
        """
        if not self._conversation or self._closing:
            raise ValueError("inactive_service")
        loop = asyncio.get_running_loop()
        last = await loop.run_in_executor(None, self._last_goal_loop_status)
        if last is None or last.get("status") in ("complete", "capped"):
            raise ValueError("no_resumable_goal")
        if judge_llm is None:
            judge_llm = getattr(self._conversation.agent, "llm", None)
        if judge_llm is None:
            raise ValueError("no_judge_llm")
        controller = GoalController(
            last["objective"],
            judge_llm,
            max_iterations=max_iterations or int(last["max_iterations"]),
        )
        controller.iteration = int(last["iteration"])
        # Same busy guard as start_goal_loop: refuse a goal loop or active run.
        async with self._run_lock:
            if self._closing:
                raise ValueError("inactive_service")
            if self._goal_loop_task is not None and not self._goal_loop_task.done():
                raise ValueError("goal_already_running")
            if (self._run_task is not None and not self._run_task.done()) or (
                await self._get_execution_status()
                == ConversationExecutionStatus.RUNNING
            ):
                raise ValueError("conversation_already_running")
            if self._closing:  # see start_goal_loop: close() may have begun teardown
                raise ValueError("inactive_service")
            self._goal_loop_outcome = None
            self._goal_loop_task = asyncio.create_task(
                self._run_goal_loop(controller, resume=True)
            )

    async def respond_to_confirmation(self, request: ConfirmationResponseRequest):
        """Accept or reject pending actions.

        The user_approval audit record is written by the SDK layer itself
        (``LocalConversation.run()``/``arun()``/``reject_pending_actions()``),
        not here — that's the only way the record can also cover callers that
        drive a ``LocalConversation`` directly instead of going through this
        REST-facing method, and it lets the SDK capture the pending-action
        snapshot atomically under its own state lock instead of this method
        taking a separate, unsynchronized snapshot beforehand.

        Raises:
            GovernanceApprovalRequiredError: If team mode is active and
                ``request.central_approval_id`` is missing — accept is
                refused rather than silently falling through to the plain
                (ungoverned) path below.
            GovernanceStartRejectedError: If ``request.central_approval_id``
                is set and the claim/binding handshake did not result in
                the run actually starting — see ``run_and_wait_for_start()``.
        """
        if request.accept:
            if self.governance_deployment_mode == "team":
                if request.central_approval_id is None:
                    raise GovernanceApprovalRequiredError(
                        "team mode requires central_approval_id on accept"
                    )
                outcome = await self.run_and_wait_for_start(
                    central_approval_id=request.central_approval_id
                )
                # PENDING_UNKNOWN (the handshake timed out, not rejected —
                # see run_and_wait_for_start()'s own docstring) is not
                # STARTED either: the caller must not treat it as a plain
                # success, since claim/binding may still be unresolved.
                # GovernanceStartRejectedError carries the exact outcome so
                # api.py's handler can map it to its own distinct,
                # non-terminal response rather than folding it into STARTED.
                if outcome != GovernanceStartOutcome.STARTED:
                    raise GovernanceStartRejectedError(outcome)
                return
            try:
                await self.run(approver_identity=request.approver_identity)
            except ValueError as e:
                # Treat "already running" as a no-op success
                if str(e) == "conversation_already_running":
                    logger.debug(
                        "Confirmation accepted but conversation already running"
                    )
                else:
                    raise
        else:
            await self.reject_pending_actions(
                request.reason, approver_identity=request.approver_identity
            )

    async def reject_pending_actions(
        self, reason: str, approver_identity: str | None = None
    ):
        """Reject all pending actions and publish updated state."""
        if not self._conversation:
            raise ValueError("inactive_service")
        loop = asyncio.get_running_loop()
        # See the equivalent comment in run(): only thread approver_identity
        # through when supplied, so a plain reject_pending_actions(reason)
        # call still dispatches exactly as before against any
        # conversation-like object that predates this kwarg.
        if approver_identity is not None:
            await loop.run_in_executor(
                None,
                functools.partial(
                    self._conversation.reject_pending_actions,
                    reason,
                    approver_identity=approver_identity,
                ),
            )
        else:
            await loop.run_in_executor(
                None, self._conversation.reject_pending_actions, reason
            )

    async def pause(self):
        if self._conversation:
            self._explicit_interrupt_generation += 1
            self._rerun_requested = False
            self._acp_internal_rerun_requested = False
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._conversation.pause)
            # Publish state update after pause to ensure stats are updated
            await self._publish_state_update()

    async def interrupt(self, *, internal_acp_rerun: bool = False):
        """Immediately cancel an in-flight async LLM call.

        Delegates to :meth:`LocalConversation.interrupt` which cancels the
        ``arun()`` task.  If no async run is in progress the call falls
        back to :meth:`pause`.
        """
        if self._conversation:
            if not internal_acp_rerun:
                self._explicit_interrupt_generation += 1
                self._rerun_requested = False
                self._acp_internal_rerun_requested = False
            self._conversation.interrupt()
            # Wait for the run task to finish so we can publish the final
            # state update (PAUSED + InterruptEvent) cleanly. The shield keeps
            # the 5s timeout from force-cancelling a cleanup that still needs
            # to drain its ACP prompt/cancel handshake.
            if self._run_task is not None and not self._run_task.done():
                with suppress(Exception):
                    await asyncio.wait_for(asyncio.shield(self._run_task), timeout=5.0)
                # Only clear _run_task if it actually finished; if
                # wait_for timed out the task may still be running and
                # clearing prematurely would allow a second run() to
                # start while the first is still in progress.
                if self._run_task is not None and self._run_task.done():
                    self._run_task = None
            await self._publish_state_update()

    async def update_secrets(self, secrets: dict[str, SecretValue]):
        """Update secrets in the conversation."""
        if not self._conversation:
            raise ValueError("inactive_service")
        if CODEX_AUTH_SECRET_NAME in self.credential_bindings:
            secrets = dict(secrets)
            secrets.pop(CODEX_AUTH_SECRET_NAME, None)
        conversation = self._conversation

        def _update_and_resolve() -> None:
            conversation.update_secrets(secrets)
            # arun() only resolves lookups at the start of each iteration, so a
            # secret added while a step is already in flight would otherwise be
            # resolved by the loop-thread output masking at the end of that
            # step, where a LookupSecret pointing back at this server deadlocks
            # until its timeout. Resolve here, in the worker thread.
            #
            # Deliberately NOT under the state lock: arun() holds it across the
            # LLM await, so taking it here would queue this request behind the
            # whole step, and resolving while holding it would bring the
            # self-deadlock back. The registry is re-read after the update, so
            # this resolves the one output masking will read. A concurrent
            # registry replacement (activate_credential_binding,
            # apply_resume_secrets: copy + assign under the lock) can still drop
            # an update that lands between its copy and its assignment; that
            # race predates this change and is unchanged by it.
            conversation.state.secret_registry.resolve_pending_sources()

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _update_and_resolve)

    async def set_confirmation_policy(self, policy: ConfirmationPolicyBase):
        """Set the confirmation policy for the conversation."""
        if not self._conversation:
            raise ValueError("inactive_service")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, self._conversation.set_confirmation_policy, policy
        )

    async def set_security_analyzer(
        self, security_analyzer: SecurityAnalyzerBase | None
    ):
        """Set the security analyzer for the conversation."""
        if not self._conversation:
            raise ValueError("inactive_service")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, self._conversation.set_security_analyzer, security_analyzer
        )

    async def load_plugin(self, plugin_ref: str) -> None:
        """Load a marketplace plugin into the active conversation."""
        if self._conversation is None:
            raise ValueError("inactive_service")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._conversation.load_plugin, plugin_ref)

    async def switch_acp_model(self, model: str) -> None:
        """Switch the model on an ACP conversation.

        For a conversation that has already started, runs the (blocking)
        protocol-level ``session/set_model`` round-trip in a worker thread; for
        one not yet run, the SDK defers the switch (persist-only). Either way the
        switched model is persisted as the authoritative value in
        ``base_state.json``: ``LocalConversation.switch_acp_model`` sets
        ``state.agent`` to an agent copy carrying the new ``acp_model``, which the
        autosave path writes to base_state. On resume the agent is rebuilt from
        base_state (the single source of truth), so no ``meta.json`` mirror is
        needed.
        """
        if self._conversation is None:
            # Match the inactive-service convention of the other event-service
            # methods (the conversation router maps it to 400). The SDK no
            # longer raises for a created-but-not-yet-run conversation, so a
            # pre-first-run switch is a normal 200 deferral, not an error.
            raise ValueError("inactive_service")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._conversation.switch_acp_model, model)

    async def close(self):
        self._closing = True
        self._explicit_interrupt_generation += 1
        self._rerun_requested = False
        self._acp_internal_rerun_requested = False

        # Cancel any in-progress /goal loop first so it cannot start a new run
        # while we drain the current one below.
        if self._goal_loop_task is not None and not self._goal_loop_task.done():
            self._goal_loop_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._goal_loop_task
        self._goal_loop_task = None

        # maybe_register_governance_approval()'s fire-and-forget approval-
        # creation tasks are independent of the claim/run handshake below —
        # cancel-and-drain them the same way so none of them keeps writing
        # to self.governance_outbox after this service is closed.
        if self._pending_governance_create_tasks:
            create_tasks = list(self._pending_governance_create_tasks)
            for task in create_tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*create_tasks, return_exceptions=True)

        # Phase E's wait-for-decision task must be stopped *before* the
        # _active_governance_handshake snapshot just below — otherwise it
        # could observe an "accepted" decision and call
        # run_and_wait_for_start() (creating a brand-new handshake) after
        # that snapshot has already been taken, leaving this shutdown's
        # reconciliation blind to it entirely. If it already got as far as
        # awaiting run_and_wait_for_start() before this cancel reaches it,
        # that inner call's own _run_lock-guarded _closing check (see its
        # own docstring) rejects it instead — so cancelling this outer
        # loop-driving task can never race a handshake it already started.
        if self._wait_for_decision_task is not None:
            self._wait_for_decision_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._wait_for_decision_task
            self._wait_for_decision_task = None

        # Same treatment for an in-flight governance claim/run handshake
        # (run_and_wait_for_start()'s background task) — without this, a
        # caller still waiting on that handshake would only ever time out
        # once its own deadline expires. Cancel-and-drain here only reaches
        # the task itself: _claim_and_run_governed() *dispatches* self.run()
        # and then returns — the real on_governed_start/on_governed_reject
        # callback lives inside the separately-scheduled run task, so by
        # the time we get here the handshake task is very often already
        # done while the future it was working toward is still unresolved.
        # Not cleared yet — the future is only force-resolved once, below,
        # after the run task and any pending report task have both had a
        # real chance to deliver the actual outcome first.
        #
        # Snapshotting under _run_lock (the same lock
        # run_and_wait_for_start() holds while creating a handshake and
        # re-checks _closing under) serializes the two: either this
        # snapshot runs first and sees no handshake (and the concurrent
        # run_and_wait_for_start() call then sees _closing=True, set
        # above, once it gets the lock, and is rejected before creating
        # one), or run_and_wait_for_start() creates the handshake first
        # and this snapshot — waiting its turn for the same lock — is
        # guaranteed to see it. Without sharing the lock, a handshake
        # created between _closing being set and this snapshot running
        # would be invisible to this shutdown's reconciliation.
        async with self._run_lock:
            pending_handshake = self._active_governance_handshake
        if pending_handshake is not None and not pending_handshake.task.done():
            pending_handshake.task.cancel()
            with suppress(asyncio.CancelledError):
                await pending_handshake.task

        if self._lease_task is not None:
            self._lease_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._lease_task
            self._lease_task = None

        # Stop the outbox relay loop before _reconcile_governance_after_
        # close() runs below — otherwise a relay cycle could fire
        # concurrently with reconcile's own report_result() call for the
        # same record, sending central two racing outcomes for one
        # execution_attempt_id.
        if self._outbox_relay_task is not None:
            self._outbox_relay_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._outbox_relay_task
            self._outbox_relay_task = None

        # Stopped only after the relay loop above — otherwise a relay
        # cycle could still call _ensure_claim_redispatch_task() and spawn
        # a brand-new one right after this drain. Like the handshake task
        # (dispatches self.run() and returns almost immediately), this is
        # not where the real execution outcome is observed — just where a
        # crash-recovery redispatch attempt itself is drained so it can't
        # keep mutating self.governance_outbox after this service is
        # considered closed.
        if self._claim_redispatch_task is not None:
            self._claim_redispatch_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._claim_redispatch_task
            self._claim_redispatch_task = None

        # Drain in-flight run before teardown so MCP close doesn't race
        # with a tool call mid-step.
        if self._run_task is not None and not self._run_task.done():
            if self._conversation is not None:
                loop = asyncio.get_running_loop()
                try:
                    await loop.run_in_executor(None, self._conversation.pause)
                except Exception:
                    logger.warning(
                        "Failed to pause conversation during close", exc_info=True
                    )
            # Cancel the run task so arun()'s CancelledError handler can
            # transition to PAUSED cleanly.  For the legacy thread-pool
            # path the underlying thread keeps running but the wrapper
            # task still settles, unblocking the wait below.
            self._run_task.cancel()
            try:
                await asyncio.wait_for(self._run_task, timeout=10.0)
            except asyncio.CancelledError:
                pass  # Expected after cancel()
            except Exception as exc:
                logger.warning("Run task did not exit cleanly during close: %s", exc)
            self._run_task = None

        # If on_governed_reject fired as part of the run task's own
        # execution just drained above, its call_soon_threadsafe-scheduled
        # closure (_handle_reject_on_loop) is guaranteed to have been
        # *scheduled* onto this loop's ready queue by now — but not
        # necessarily to have *run* yet: draining self._run_task only
        # guarantees the run task's own coroutine has settled, not that
        # every callback it scheduled along the way has already executed.
        # Yield once so the loop processes its ready queue — including
        # that closure — before the snapshot below, rather than depending
        # on an unstated ordering guarantee between two independently-
        # scheduled callbacks.
        await asyncio.sleep(0)

        # From here on, close() is committed to being the sole reporter for
        # any orphaned claim via _reconcile_governance_after_close() below.
        # A synchronous conversation.run() still executing on its own
        # worker thread (see the comment above the run-task drain — that
        # thread cannot be forcibly stopped by cancelling its wrapper task)
        # can still call on_governed_reject after this point; the flag
        # stops that late callback from registering a second, untracked
        # report that could conflict with the one close() is about to send.
        self._governance_report_registration_closed = True

        # Wait for any in-flight on_governed_reject-triggered report (see
        # _pending_governance_report_tasks's docstring) to finish *before*
        # deciding below whether the outbox is still orphaned — otherwise
        # close() could race that report and the two could send central
        # conflicting outcomes for the same execution_attempt_id. Each task
        # already handles its own errors internally (see
        # _report_governance_failure), so nothing further to do with the
        # gathered results here.
        if self._pending_governance_report_tasks:
            await asyncio.gather(
                *self._pending_governance_report_tasks, return_exceptions=True
            )

        # The run task and any pending report task have now both had a
        # real chance to deliver the actual STARTED/REJECTED_* outcome via
        # on_governed_start/on_governed_reject. Force-resolve only if that
        # genuinely never happened — idempotent, so this is a no-op
        # whenever the real callback already fired (the common case).
        # Without this, a handshake whose task completed early (the usual
        # case — self.run() only dispatches and returns) but whose real
        # callback never got a chance to run before shutdown would leave
        # any waiter to find out only via its own timeout, contradicting
        # this method's own promise to unblock it immediately.
        if pending_handshake is not None:
            _resolve_handshake_once(
                pending_handshake.future, GovernanceStartOutcome.REJECTED_CANCELLED
            )
        self._active_governance_handshake = None

        # After the handshake, the run task, and any pending report task
        # (if any) have all been cancelled/drained/awaited above, check
        # whether a central claim succeeded but never reached a conclusive
        # result — either because the handshake was cancelled before
        # self.run() ever started, or because a governed run was cancelled
        # mid-execution with no observation yet. Without this, that claim's
        # execution lease is orphaned: the conversation may still be
        # WAITING_FOR_CONFIRMATION (not RUNNING), so a future restart's
        # crash-recovery path would never notice anything wrong and never
        # report it either.
        await self._reconcile_governance_after_close()

        await self._pub_sub.close()
        if self._conversation:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._conversation.close)
            self._conversation = None
        self.credential_bindings = {}

        if self._lease is not None and self._lease_generation is not None:
            self._lease.release(self._lease_generation)
        self._lease_generation = None
        self._lease = None

    async def generate_title(
        self, llm: "LLM | None" = None, max_length: int = 50
    ) -> str:
        """Generate a title for the conversation.

        Resolves the provided LLM via the conversation's registry if a usage_id is
        present, registering it if needed. Then delegates to LocalConversation in an
        executor to avoid blocking the event loop.
        """
        if not self._conversation:
            raise ValueError("inactive_service")

        resolved_llm = llm
        if llm is not None:
            usage_id = llm.usage_id
            try:
                resolved_llm = self._conversation.llm_registry.get(usage_id)
            except KeyError:
                self._conversation.llm_registry.add(llm)
                resolved_llm = llm

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._conversation.generate_title, resolved_llm, max_length
        )

    async def ask_agent(self, question: str) -> str:
        """Ask the agent a simple question without affecting conversation state.

        Delegates to LocalConversation in an executor to avoid blocking the event loop.
        """
        if not self._conversation:
            raise ValueError("inactive_service")

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._conversation.ask_agent, question)

    async def condense(self) -> None:
        """Force condensation of the conversation history.

        Delegates to LocalConversation in an executor to avoid blocking the event loop.
        """
        if not self._conversation:
            raise ValueError("inactive_service")

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._conversation.condense)

    async def navigate_to(self, event_id: str | None) -> None:
        """Move the conversation HEAD to an existing event (in-place re-root).

        Delegates to LocalConversation in an executor to avoid blocking the event loop.

        Raises:
            ValueError: If ``event_id`` is not ``None`` and not in the conversation.
        """
        if not self._conversation:
            raise ValueError("inactive_service")

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._conversation.navigate_to, event_id
        )

    def _get_agent_final_response_sync(self) -> str:
        """Extract the agent's final response from the conversation events.

        Reads directly from the EventLog without acquiring the state lock.
        EventLog reads are safe without the FIFOLock because events are
        append-only and immutable once written.
        """
        if not self._conversation:
            raise ValueError("inactive_service")
        return get_agent_final_response(self._conversation._state.events)

    async def get_agent_final_response(self) -> str:
        """Extract the agent's final response from the conversation events.

        Returns the text from the last FinishAction or agent MessageEvent,
        or empty string if no final response is found.
        """
        if not self._conversation:
            raise ValueError("inactive_service")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._get_agent_final_response_sync)

    async def get_state(self) -> ConversationState:
        if not self._conversation:
            raise ValueError("inactive_service")
        return self._conversation._state

    async def _publish_state_update(self):
        """Publish a ConversationStateUpdateEvent with the current state."""
        if not self._conversation:
            return

        state_update_event = await self._create_state_update_event()
        # Note: _pub_sub iterates through subscribers sequentially. If any subscriber
        # is slow, it will delay subsequent subscribers. For high-throughput scenarios,
        # consider using asyncio.gather() for concurrent notification in the future.
        await self._pub_sub(state_update_event)

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        save_error: BaseException | None = None
        try:
            await self.save_meta()
        except ConversationOwnershipLostError:
            logger.info(
                "Skipping meta save after ownership loss for conversation %s",
                self.stored.id,
            )
        except BaseException as exc:
            save_error = exc
        close_error: BaseException | None = None
        try:
            await self.close()
        except BaseException as exc:
            close_error = exc
        if isinstance(close_error, CredentialBindingError):
            raise close_error
        if save_error is not None:
            if close_error is not None:
                logger.warning(
                    "Event service close also failed after meta save failure",
                    exc_info=(
                        type(close_error),
                        close_error,
                        close_error.__traceback__,
                    ),
                )
            raise save_error
        if close_error is not None:
            raise close_error

    def is_open(self) -> bool:
        return bool(self._conversation)

    def touch(self) -> None:
        """Record activity so idle-eviction defers this conversation."""
        self._last_active_monotonic = time.monotonic()

    def idle_seconds(self) -> float:
        """Seconds since the last recorded activity."""
        return time.monotonic() - self._last_active_monotonic

    def mark_subscription_baseline(self) -> None:
        """Snapshot the current (internal) subscribers; later ones are external."""
        self._internal_subscriber_ids = self._pub_sub.subscriber_ids()

    def has_external_subscribers(self) -> bool:
        """True if a non-internal subscriber (e.g. a websocket) is attached."""
        return bool(self._pub_sub.subscriber_ids() - self._internal_subscriber_ids)

    def is_idle_evictable(self) -> bool:
        """Safe to evict only with no in-flight work and no external subscriber."""
        run_active = self._run_task is not None and not self._run_task.done()
        goal_active = (
            self._goal_loop_task is not None and not self._goal_loop_task.done()
        )
        governance_active = (
            self._active_governance_handshake is not None
            and not self._active_governance_handshake.task.done()
        ) or (
            self._claim_redispatch_task is not None
            and not self._claim_redispatch_task.done()
        )
        governance_background_work_active = bool(
            self._pending_governance_create_tasks
            or self._pending_governance_report_tasks
        )
        if (
            self._closing
            or run_active
            or goal_active
            or governance_active
            or governance_background_work_active
            or self._rerun_requested
            or self._acp_internal_rerun_requested
            or self.has_external_subscribers()
        ):
            return False
        return True
