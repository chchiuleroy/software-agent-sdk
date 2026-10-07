import asyncio
import contextlib
import json
import shutil
import threading
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
import pytest_asyncio

from openhands.agent_server.conversation_lease import LEASE_FILE_NAME
from openhands.agent_server.conversation_service import ConversationService
from openhands.agent_server.event_service import (
    EventService,
    GovernanceApprovalRequiredError,
    GovernanceStartOutcome,
    GovernanceStartRejectedError,
    _GovernanceHandshake,
    _with_execution_attested,
    _with_execution_started,
    _with_pending_report_outcome,
)
from openhands.agent_server.governance_client import (
    GovernancePermanentError,
    compute_display_digest,
)
from openhands.agent_server.governance_display import POLICY_REVISION, build_display
from openhands.agent_server.governance_outbox import OutboxRecord, OutboxState
from openhands.agent_server.models import (
    ConfirmationResponseRequest,
    EventPage,
    EventSortOrder,
    StoredConversation,
)
from openhands.agent_server.pub_sub import Subscriber
from openhands.sdk import LLM, Agent, AgentBase, Conversation, Message
from openhands.sdk.agent import ACPAgent
from openhands.sdk.conversation.event_store import EventLog
from openhands.sdk.conversation.exceptions import ConversationRunError
from openhands.sdk.conversation.fifo_lock import FIFOLock
from openhands.sdk.conversation.impl.local_conversation import (
    ACP_INFLIGHT_PROMPT_USER_MESSAGE_ID,
    ACP_SUPERSEDE_INFLIGHT_PROMPT,
    LocalConversation,
)
from openhands.sdk.conversation.secret_registry import SecretRegistry
from openhands.sdk.conversation.state import (
    ConversationExecutionStatus,
    ConversationState,
)
from openhands.sdk.credential import CredentialSyncError
from openhands.sdk.event import AgentErrorEvent, Event
from openhands.sdk.event.conversation_error import ConversationErrorEvent
from openhands.sdk.event.conversation_state import ConversationStateUpdateEvent
from openhands.sdk.event.llm_convertible import (
    ActionEvent,
    MessageEvent,
    ObservationEvent,
)
from openhands.sdk.io.local import LocalFileStore
from openhands.sdk.io.memory import InMemoryFileStore
from openhands.sdk.llm import MessageToolCall, TextContent
from openhands.sdk.mcp.config import coerce_mcp_config
from openhands.sdk.secret import SecretSource
from openhands.sdk.security.confirmation_policy import NeverConfirm
from openhands.sdk.security.roy_action_binding import (
    ActionBinding,
    ActionBindingMismatchError,
    compute_execution_commitment,
)
from openhands.sdk.subagent.schema import AgentDefinition
from openhands.sdk.tool import Action
from openhands.sdk.utils.cipher import Cipher
from openhands.sdk.workspace import LocalWorkspace
from openhands.tools.browser_use.definition import BrowserTypeAction
from openhands.tools.terminal import TerminalAction, TerminalObservation
from tests.agent_server.stress.scripts import (
    SlowTestLLM,
    start_conversation_with_test_llm,
    text_message,
)


# Agent for a new conversation. meta.json (StoredConversation) no longer carries
# the agent — base_state.json is its single source of truth — so tests pass it to
# EventService separately.
def _sample_agent() -> Agent:
    return Agent(llm=LLM(model="gpt-4o", usage_id="test-llm"), tools=[])


@pytest.fixture
def sample_agent():
    return _sample_agent()


@pytest.fixture
def sample_stored_conversation():
    """Create a sample StoredConversation for testing."""
    return StoredConversation(
        id=uuid4(),
        workspace=LocalWorkspace(working_dir="workspace/project"),
        confirmation_policy=NeverConfirm(),
        initial_message=None,
        metrics=None,
        created_at=datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC),
        updated_at=datetime(2025, 1, 1, 12, 30, 0, tzinfo=UTC),
    )


@pytest.fixture
def event_service(sample_stored_conversation, sample_agent):
    """Create an EventService instance for testing."""
    service = EventService(
        stored=sample_stored_conversation,
        agent=sample_agent,
        conversations_dir=Path("test_conversation_dir"),
    )
    return service


@pytest.fixture
def mock_conversation_with_events():
    """Create a mock conversation with sample events."""
    conversation = MagicMock(spec=Conversation)
    state = MagicMock(spec=ConversationState)

    # Create sample events with different timestamps and kinds
    events = [
        MessageEvent(
            id=f"event{index}", source="user", llm_message=Message(role="user")
        )
        for index in range(1, 6)
    ]

    state.events = events
    state.__enter__ = MagicMock(return_value=state)
    state.__exit__ = MagicMock(return_value=None)
    conversation._state = state

    return conversation


@pytest.fixture
def mock_conversation_with_timestamped_events():
    """Create a mock conversation with events having specific timestamps for testing."""
    conversation = MagicMock(spec=Conversation)
    state = MagicMock(spec=ConversationState)

    # Create events with specific ISO format timestamps
    # These timestamps are in chronological order
    timestamps = [
        "2025-01-01T10:00:00.000000",
        "2025-01-01T11:00:00.000000",
        "2025-01-01T12:00:00.000000",
        "2025-01-01T13:00:00.000000",
        "2025-01-01T14:00:00.000000",
    ]

    events = []
    for index, timestamp in enumerate(timestamps, 1):
        event = MessageEvent(
            id=f"event{index}",
            source="user",
            llm_message=Message(role="user"),
            timestamp=timestamp,
        )
        events.append(event)

    state.events = events
    state.__enter__ = MagicMock(return_value=state)
    state.__exit__ = MagicMock(return_value=None)
    conversation._state = state

    return conversation


def _message_event(event_id: str, text: str, timestamp: str) -> MessageEvent:
    return MessageEvent(
        id=event_id,
        source="user",
        llm_message=Message(role="user", content=[TextContent(text=text)]),
        timestamp=timestamp,
    )


def _event_log_with_unreadable_middle(
    fs, unreadable_payload: str | bytes
) -> tuple[EventLog, MessageEvent, MessageEvent, str]:
    event0 = _message_event(
        "00000000-0000-0000-0000-000000000001",
        "first",
        "2026-06-16T09:00:00",
    )
    unreadable_event_id = "00000000-0000-0000-0000-000000000002"
    event2 = _message_event(
        "00000000-0000-0000-0000-000000000003",
        "third",
        "2026-06-16T09:00:02",
    )
    unreadable_path = f"events/event-00001-{unreadable_event_id}.json"
    fs.write(
        f"events/event-00000-{event0.id}.json",
        event0.model_dump_json(exclude_none=True),
    )
    fs.write(unreadable_path, unreadable_payload)
    fs.write(
        f"events/event-00002-{event2.id}.json",
        event2.model_dump_json(exclude_none=True),
    )
    return EventLog(fs), event0, event2, unreadable_path


def _attach_event_log(event_service, event_log: EventLog) -> None:
    conversation = MagicMock(spec=Conversation)
    state = MagicMock(spec=ConversationState)
    state.events = event_log
    conversation._state = state
    event_service._conversation = conversation


class TestEventServiceSearchEvents:
    """Test cases for EventService.search_events method."""

    @pytest.mark.asyncio
    async def test_search_events_inactive_service(self, event_service):
        """Test that search_events raises ValueError when conversation is not active."""
        event_service._conversation = None

        with pytest.raises(ValueError, match="inactive_service"):
            await event_service.search_events()

    @pytest.mark.asyncio
    async def test_search_events_empty_result(self, event_service):
        """Test search_events with no events."""
        # Mock conversation with empty events
        conversation = MagicMock(spec=Conversation)
        state = MagicMock(spec=ConversationState)
        state.events = []
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation._state = state

        event_service._conversation = conversation

        result = await event_service.search_events()

        assert isinstance(result, EventPage)
        assert result.items == []
        assert result.next_page_id is None

    @pytest.mark.asyncio
    async def test_search_events_basic(
        self, event_service, mock_conversation_with_events
    ):
        """Test basic search_events functionality."""
        event_service._conversation = mock_conversation_with_events

        result = await event_service.search_events()

        assert len(result.items) == 5
        assert result.next_page_id is None
        # Default sort is TIMESTAMP (ascending), so first event should be earliest
        assert result.items[0].timestamp < result.items[-1].timestamp

    @pytest.mark.asyncio
    async def test_search_events_kind_filter(
        self, event_service, mock_conversation_with_events
    ):
        """Test filtering events by kind."""
        event_service._conversation = mock_conversation_with_events

        # Test filtering by ActionEvent
        result = await event_service.search_events(kind="ActionEvent")
        assert len(result.items) == 0

        # Test filtering by MessageEvent
        result = await event_service.search_events(
            kind="openhands.sdk.event.llm_convertible.message.MessageEvent"
        )
        assert len(result.items) == 5
        for event in result.items:
            assert event.__class__.__name__ == "MessageEvent"

        # Test filtering by non-existent kind
        result = await event_service.search_events(kind="NonExistentEvent")
        assert len(result.items) == 0

    @pytest.mark.asyncio
    async def test_search_events_sorting(
        self, event_service, mock_conversation_with_events
    ):
        """Test sorting events by timestamp."""
        event_service._conversation = mock_conversation_with_events

        # Test TIMESTAMP (ascending) - default
        result = await event_service.search_events(sort_order=EventSortOrder.TIMESTAMP)
        assert len(result.items) == 5
        for i in range(len(result.items) - 1):
            assert result.items[i].timestamp <= result.items[i + 1].timestamp

        # Test TIMESTAMP_DESC (descending)
        result = await event_service.search_events(
            sort_order=EventSortOrder.TIMESTAMP_DESC
        )
        assert len(result.items) == 5
        for i in range(len(result.items) - 1):
            assert result.items[i].timestamp >= result.items[i + 1].timestamp

    @pytest.mark.asyncio
    async def test_search_events_pagination(
        self, event_service, mock_conversation_with_events
    ):
        """Test pagination functionality."""
        event_service._conversation = mock_conversation_with_events

        # Test first page with limit 2
        result = await event_service.search_events(limit=2)
        assert len(result.items) == 2
        assert result.next_page_id is not None

        # Test second page using next_page_id
        result = await event_service.search_events(page_id=result.next_page_id, limit=2)
        assert len(result.items) == 2
        assert result.next_page_id is not None

        # Test third page
        result = await event_service.search_events(page_id=result.next_page_id, limit=2)
        assert len(result.items) == 1  # Only one item left
        assert result.next_page_id is None

    @pytest.mark.asyncio
    async def test_search_events_combined_filter_and_sort(
        self, event_service, mock_conversation_with_events
    ):
        """Test combining kind filtering with sorting."""
        event_service._conversation = mock_conversation_with_events

        # Filter by ActionEvent and sort by TIMESTAMP_DESC
        result = await event_service.search_events(
            kind="openhands.sdk.event.llm_convertible.message.MessageEvent",
            sort_order=EventSortOrder.TIMESTAMP_DESC,
        )

        assert len(result.items) == 5
        for event in result.items:
            assert event.__class__.__name__ == "MessageEvent"
        # Should be sorted by timestamp descending (newest first)
        assert result.items[0].timestamp > result.items[1].timestamp

    @pytest.mark.asyncio
    async def test_search_events_pagination_with_filter(
        self, event_service, mock_conversation_with_events
    ):
        """Test pagination with filtering."""
        event_service._conversation = mock_conversation_with_events

        # Filter by MessageEvent with limit 1
        result = await event_service.search_events(
            kind="openhands.sdk.event.llm_convertible.message.MessageEvent", limit=1
        )
        assert len(result.items) == 1
        assert result.items[0].__class__.__name__ == "MessageEvent"
        assert result.next_page_id is not None

        # Get second page
        result = await event_service.search_events(
            kind="openhands.sdk.event.llm_convertible.message.MessageEvent",
            page_id=result.next_page_id,
            limit=4,
        )
        assert len(result.items) == 4
        assert result.items[0].__class__.__name__ == "MessageEvent"
        assert result.next_page_id is None  # No more MessageEvents

    @pytest.mark.asyncio
    async def test_search_events_invalid_page_id(
        self, event_service, mock_conversation_with_events
    ):
        """Test search_events with invalid page_id."""
        event_service._conversation = mock_conversation_with_events

        # Use a non-existent page_id
        invalid_page_id = "invalid_event_id"
        result = await event_service.search_events(page_id=invalid_page_id)

        # Should return all items since page_id doesn't match any event
        assert len(result.items) == 5
        assert result.next_page_id is None

    @pytest.mark.asyncio
    async def test_search_events_large_limit(
        self, event_service, mock_conversation_with_events
    ):
        """Test search_events with limit larger than available events."""
        event_service._conversation = mock_conversation_with_events

        result = await event_service.search_events(limit=100)

        assert len(result.items) == 5  # All available events
        assert result.next_page_id is None

    @pytest.mark.parametrize("unreadable_payload", ["", "{not-json", "{}"])
    @pytest.mark.asyncio
    async def test_search_events_skips_unreadable_event_files(
        self, event_service, unreadable_payload
    ):
        fs = InMemoryFileStore()
        event_log, event0, event2, _ = _event_log_with_unreadable_middle(
            fs, unreadable_payload
        )
        _attach_event_log(event_service, event_log)

        result = await event_service.search_events(limit=10)

        assert [event.id for event in result.items] == [event0.id, event2.id]
        assert result.next_page_id is None

    @pytest.mark.asyncio
    async def test_search_events_skips_missing_event_files(self, event_service):
        fs = InMemoryFileStore()
        event_log, event0, event2, unreadable_path = _event_log_with_unreadable_middle(
            fs, "will be deleted"
        )
        fs.delete(unreadable_path)
        _attach_event_log(event_service, event_log)

        result = await event_service.search_events(limit=10)

        assert [event.id for event in result.items] == [event0.id, event2.id]
        assert result.next_page_id is None

    @pytest.mark.asyncio
    async def test_search_events_skips_non_utf8_event_files(
        self, event_service, tmp_path
    ):
        fs = LocalFileStore(str(tmp_path))
        event_log, event0, event2, _ = _event_log_with_unreadable_middle(fs, b"\xff")
        _attach_event_log(event_service, event_log)

        result = await event_service.search_events(limit=10)

        assert [event.id for event in result.items] == [event0.id, event2.id]
        assert result.next_page_id is None

    @pytest.mark.asyncio
    async def test_search_events_zero_limit(
        self, event_service, mock_conversation_with_events
    ):
        """Test search_events with zero limit."""
        event_service._conversation = mock_conversation_with_events

        result = await event_service.search_events(limit=0)

        assert len(result.items) == 0
        # Should still have next_page_id if there are events available
        assert result.next_page_id is not None

    @pytest.mark.asyncio
    async def test_search_events_does_not_scan_whole_log(self, event_service):
        """Loading the most recent N events must be O(limit), not O(total).

        Regression test for a previous implementation that read every event
        from the EventLog before returning a single page, making long
        conversations effectively unusable.
        """

        class _CountingEvents:
            """Sequence wrapper that counts ``__getitem__`` accesses."""

            def __init__(self, items: list[Event]):
                self._items = items
                self.getitem_calls = 0
                # ``get_index`` is what EventLog exposes; mirroring it lets us
                # verify the O(1) page_id lookup path is exercised.
                self._id_to_idx = {e.id: i for i, e in enumerate(items)}

            def __len__(self) -> int:
                return len(self._items)

            def __getitem__(self, idx: int) -> Event:
                self.getitem_calls += 1
                return self._items[idx]

            def __iter__(self):  # pragma: no cover - must NOT be used in fast path
                raise AssertionError(
                    "search_events fell back to full iteration; expected "
                    "index-based access only"
                )

            def get_index(self, event_id: str) -> int:
                return self._id_to_idx[event_id]

        total = 1000
        events = [
            MessageEvent(
                id=f"event{i:05d}",
                source="user",
                llm_message=Message(role="user"),
            )
            for i in range(total)
        ]
        wrapper = _CountingEvents(cast(list[Event], events))

        conversation = MagicMock(spec=Conversation)
        state = MagicMock(spec=ConversationState)
        state.events = wrapper
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation._state = state
        event_service._conversation = conversation

        # First page: 50 most recent events out of 1000.
        result = await event_service.search_events(
            limit=50, sort_order=EventSortOrder.TIMESTAMP_DESC
        )
        assert len(result.items) == 50
        assert result.items[0].id == events[-1].id
        assert result.items[-1].id == events[-50].id
        assert result.next_page_id == events[-51].id
        # Must read at most limit + 1 events (one extra for next_page_id).
        assert wrapper.getitem_calls <= 51, (
            f"Expected <=51 getitem calls, got {wrapper.getitem_calls}"
        )

        # Second page via page_id: also O(limit) and uses get_index (no scan).
        wrapper.getitem_calls = 0
        next_page = await event_service.search_events(
            page_id=result.next_page_id,
            limit=50,
            sort_order=EventSortOrder.TIMESTAMP_DESC,
        )
        assert len(next_page.items) == 50
        assert next_page.items[0].id == events[-51].id
        assert wrapper.getitem_calls <= 51

    @pytest.mark.asyncio
    async def test_search_events_exact_pagination_boundary(self, event_service):
        """Test pagination when the number of events exactly matches the limit."""
        # Create exactly 3 events
        conversation = MagicMock(spec=Conversation)
        state = MagicMock(spec=ConversationState)

        events = [
            MessageEvent(
                id=f"event{index}", source="user", llm_message=Message(role="user")
            )
            for index in range(1, 4)
        ]

        state.events = events
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation._state = state

        event_service._conversation = conversation

        # Request exactly 3 events (same as available)
        result = await event_service.search_events(limit=3)

        assert len(result.items) == 3
        assert result.next_page_id is None  # No more events available

    @pytest.mark.asyncio
    async def test_search_events_timestamp_gte_filter(
        self, event_service, mock_conversation_with_timestamped_events
    ):
        """Test filtering events with timestamp__gte (greater than or equal)."""
        event_service._conversation = mock_conversation_with_timestamped_events

        # Filter events >= 12:00:00 (should return events 3, 4, 5)
        filter_time = datetime(2025, 1, 1, 12, 0, 0)
        result = await event_service.search_events(timestamp__gte=filter_time)

        assert len(result.items) == 3
        assert result.items[0].id == "event3"
        assert result.items[1].id == "event4"
        assert result.items[2].id == "event5"
        # All returned events should have timestamp >= filter value
        filter_iso = filter_time.isoformat()
        for event in result.items:
            assert event.timestamp >= filter_iso

    @pytest.mark.asyncio
    async def test_search_events_timestamp_lt_filter(
        self, event_service, mock_conversation_with_timestamped_events
    ):
        """Test filtering events with timestamp__lt (less than)."""
        event_service._conversation = mock_conversation_with_timestamped_events

        # Filter events < 13:00:00 (should return events 1, 2, 3)
        filter_time = datetime(2025, 1, 1, 13, 0, 0)
        result = await event_service.search_events(timestamp__lt=filter_time)

        assert len(result.items) == 3
        assert result.items[0].id == "event1"
        assert result.items[1].id == "event2"
        assert result.items[2].id == "event3"
        # All returned events should have timestamp < filter value
        filter_iso = filter_time.isoformat()
        for event in result.items:
            assert event.timestamp < filter_iso

    @pytest.mark.asyncio
    async def test_search_events_timestamp_range_filter(
        self, event_service, mock_conversation_with_timestamped_events
    ):
        """Test filtering events with both timestamp__gte and timestamp__lt."""
        event_service._conversation = mock_conversation_with_timestamped_events

        # Filter events between 11:00:00 and 13:00:00 (should return events 2, 3)
        gte_time = datetime(2025, 1, 1, 11, 0, 0)
        lt_time = datetime(2025, 1, 1, 13, 0, 0)
        result = await event_service.search_events(
            timestamp__gte=gte_time, timestamp__lt=lt_time
        )

        assert len(result.items) == 2
        assert result.items[0].id == "event2"
        assert result.items[1].id == "event3"
        # All returned events should be within the range
        gte_iso = gte_time.isoformat()
        lt_iso = lt_time.isoformat()
        for event in result.items:
            assert event.timestamp >= gte_iso
            assert event.timestamp < lt_iso

    @pytest.mark.asyncio
    async def test_search_events_timestamp_filter_with_timezone_aware(
        self, event_service, mock_conversation_with_timestamped_events
    ):
        """Test filtering events with timezone-aware datetime requires normalization.

        Event timestamps are naive (server local time), so callers must normalize
        timezone-aware datetimes to naive before filtering. This is done by the
        REST/WebSocket API layer via normalize_datetime_to_server_timezone().
        """
        event_service._conversation = mock_conversation_with_timestamped_events

        # Filter events >= 12:00:00 (naive, as if normalized by API layer)
        # The API layer would convert a tz-aware datetime to naive server time
        filter_time = datetime(2025, 1, 1, 12, 0, 0)  # naive datetime
        result = await event_service.search_events(timestamp__gte=filter_time)

        assert len(result.items) == 3
        assert result.items[0].id == "event3"
        assert result.items[1].id == "event4"
        assert result.items[2].id == "event5"

    @pytest.mark.asyncio
    async def test_search_events_timestamp_filter_no_matches(
        self, event_service, mock_conversation_with_timestamped_events
    ):
        """Test filtering events with timestamps that don't match any events."""
        event_service._conversation = mock_conversation_with_timestamped_events

        # Filter events >= 15:00:00 (should return no events)
        filter_time = datetime(2025, 1, 1, 15, 0, 0)
        result = await event_service.search_events(timestamp__gte=filter_time)

        assert len(result.items) == 0
        assert result.next_page_id is None

    @pytest.mark.asyncio
    async def test_search_events_timestamp_filter_all_events(
        self, event_service, mock_conversation_with_timestamped_events
    ):
        """Test filtering events with timestamps that include all events."""
        event_service._conversation = mock_conversation_with_timestamped_events

        # Filter events >= 09:00:00 (should return all events)
        filter_time = datetime(2025, 1, 1, 9, 0, 0)
        result = await event_service.search_events(timestamp__gte=filter_time)

        assert len(result.items) == 5
        assert result.items[0].id == "event1"
        assert result.items[4].id == "event5"


class TestEventServiceCountEvents:
    """Test cases for EventService.count_events method."""

    @pytest.mark.asyncio
    async def test_count_events_inactive_service(self, event_service):
        """Test that count_events raises ValueError when service is inactive."""
        event_service._conversation = None

        with pytest.raises(ValueError, match="inactive_service"):
            await event_service.count_events()

    @pytest.mark.asyncio
    async def test_count_events_empty_result(self, event_service):
        """Test count_events with no events."""
        conversation = MagicMock(spec=Conversation)
        state = MagicMock(spec=ConversationState)
        state.events = []
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation._state = state

        event_service._conversation = conversation

        result = await event_service.count_events()
        assert result == 0

    @pytest.mark.asyncio
    async def test_count_events_basic(
        self, event_service, mock_conversation_with_events
    ):
        """Test basic count_events functionality."""
        event_service._conversation = mock_conversation_with_events

        result = await event_service.count_events()
        assert result == 5  # Total events in mock_conversation_with_events

    @pytest.mark.asyncio
    async def test_count_events_kind_filter(
        self, event_service, mock_conversation_with_events
    ):
        """Test counting events with kind filter."""
        event_service._conversation = mock_conversation_with_events

        # Count all events
        result = await event_service.count_events()
        assert result == 5

        # Count ActionEvent events (should be 5)
        result = await event_service.count_events(
            kind="openhands.sdk.event.llm_convertible.message.MessageEvent"
        )
        assert result == 5

        # Count non-existent event type (should be 0)
        result = await event_service.count_events(kind="NonExistentEvent")
        assert result == 0

    @pytest.mark.asyncio
    async def test_count_events_skips_unreadable_event_files_when_filtering(
        self, event_service
    ):
        fs = InMemoryFileStore()
        event_log, _, _, _ = _event_log_with_unreadable_middle(fs, "")
        _attach_event_log(event_service, event_log)

        assert await event_service.count_events() == 3
        assert await event_service.count_events(source="user") == 2

    @pytest.mark.asyncio
    async def test_count_events_timestamp_gte_filter(
        self, event_service, mock_conversation_with_timestamped_events
    ):
        """Test counting events with timestamp__gte filter."""
        event_service._conversation = mock_conversation_with_timestamped_events

        # Count events >= 12:00:00 (should return 3)
        filter_time = datetime(2025, 1, 1, 12, 0, 0)
        result = await event_service.count_events(timestamp__gte=filter_time)
        assert result == 3

    @pytest.mark.asyncio
    async def test_count_events_timestamp_lt_filter(
        self, event_service, mock_conversation_with_timestamped_events
    ):
        """Test counting events with timestamp__lt filter."""
        event_service._conversation = mock_conversation_with_timestamped_events

        # Count events < 13:00:00 (should return 3)
        filter_time = datetime(2025, 1, 1, 13, 0, 0)
        result = await event_service.count_events(timestamp__lt=filter_time)
        assert result == 3

    @pytest.mark.asyncio
    async def test_count_events_timestamp_range_filter(
        self, event_service, mock_conversation_with_timestamped_events
    ):
        """Test counting events with both timestamp filters."""
        event_service._conversation = mock_conversation_with_timestamped_events

        # Count events between 11:00:00 and 13:00:00 (should return 2)
        gte_time = datetime(2025, 1, 1, 11, 0, 0)
        lt_time = datetime(2025, 1, 1, 13, 0, 0)
        result = await event_service.count_events(
            timestamp__gte=gte_time, timestamp__lt=lt_time
        )
        assert result == 2

    @pytest.mark.asyncio
    async def test_count_events_timestamp_filter_with_timezone_aware(
        self, event_service, mock_conversation_with_timestamped_events
    ):
        """Test counting events with timezone-aware datetime requires normalization.

        Event timestamps are naive (server local time), so callers must normalize
        timezone-aware datetimes to naive before filtering. This is done by the
        REST/WebSocket API layer via normalize_datetime_to_server_timezone().
        """
        event_service._conversation = mock_conversation_with_timestamped_events

        # Count events >= 12:00:00 (naive, as if normalized by API layer)
        filter_time = datetime(2025, 1, 1, 12, 0, 0)  # naive datetime
        result = await event_service.count_events(timestamp__gte=filter_time)
        assert result == 3

    @pytest.mark.asyncio
    async def test_count_events_timestamp_filter_no_matches(
        self, event_service, mock_conversation_with_timestamped_events
    ):
        """Test counting events with timestamps that don't match any events."""
        event_service._conversation = mock_conversation_with_timestamped_events

        # Count events >= 15:00:00 (should return 0)
        filter_time = datetime(2025, 1, 1, 15, 0, 0)
        result = await event_service.count_events(timestamp__gte=filter_time)
        assert result == 0

    @pytest.mark.asyncio
    async def test_count_events_timestamp_filter_all_events(
        self, event_service, mock_conversation_with_timestamped_events
    ):
        """Test counting events with timestamps that include all events."""
        event_service._conversation = mock_conversation_with_timestamped_events

        # Count events >= 09:00:00 (should return 5)
        filter_time = datetime(2025, 1, 1, 9, 0, 0)
        result = await event_service.count_events(timestamp__gte=filter_time)
        assert result == 5


class TestEventServiceSendMessage:
    """Test cases for EventService.send_message method."""

    async def _mock_executor(self, *args):
        """Helper to create a mock coroutine for run_in_executor."""
        return None

    @pytest.mark.asyncio
    async def test_send_message_inactive_service(self, event_service):
        """Test that send_message raises ValueError when service is inactive."""
        event_service._conversation = None
        message = Message(role="user", content=[])

        with pytest.raises(ValueError, match="inactive_service"):
            await event_service.send_message(message)

    @pytest.mark.asyncio
    async def test_send_message_with_run_false_default(self, event_service):
        """Test send_message with default run=True."""
        # Mock conversation and its methods
        conversation = MagicMock()
        state = MagicMock()
        state.execution_status = ConversationExecutionStatus.IDLE
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation.state = state
        conversation._state = state
        conversation.send_message = MagicMock()
        conversation.run = MagicMock()

        event_service._conversation = conversation
        message = Message(role="user", content=[])

        # Mock the event loop and executor
        with patch("asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()
            mock_get_loop.return_value = mock_loop
            mock_loop.run_in_executor.side_effect = lambda *args: self._mock_executor()

            # Call send_message with default run=True
            await event_service.send_message(message)

            # Verify send_message was called via executor
            mock_loop.run_in_executor.assert_any_call(
                None, conversation.send_message, message
            )
            # Verify run was called via executor since run=True and agent is not running
            assert (
                None,
                conversation.run,
            ) not in mock_loop.run_in_executor.call_args_list

    @pytest.mark.asyncio
    async def test_send_message_with_run_false(self, event_service):
        """Test send_message with run=False."""
        # Mock conversation and its methods
        conversation = MagicMock()
        conversation.send_message = MagicMock()
        conversation.run = MagicMock()

        event_service._conversation = conversation
        message = Message(role="user", content=[])

        # Mock the event loop and executor
        with patch("asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()
            mock_get_loop.return_value = mock_loop
            mock_loop.run_in_executor.side_effect = lambda *args: self._mock_executor()

            # Call send_message with run=False
            await event_service.send_message(message, run=False)

            # Verify send_message was called via executor
            mock_loop.run_in_executor.assert_called_once_with(
                None, conversation.send_message, message
            )
            # Verify run was NOT called since run=False
            assert mock_loop.run_in_executor.call_count == 1  # Only send_message call

    @pytest.mark.asyncio
    async def test_send_message_with_run_true_agent_already_running(
        self, event_service
    ):
        """Test send_message with run=True but agent already running."""
        # Mock conversation and its methods
        conversation = MagicMock()
        state = MagicMock()
        state.execution_status = ConversationExecutionStatus.RUNNING
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation.state = state
        conversation._state = state
        conversation.send_message = MagicMock()
        conversation.run = MagicMock()

        event_service._conversation = conversation
        # Simulate conversation already running to test the ValueError path
        event_service._run_task = asyncio.create_task(asyncio.sleep(10))
        message = Message(role="user", content=[])

        # Call send_message with run=True — should silently skip run
        await event_service.send_message(message, run=True)

        conversation.send_message.assert_called_once_with(message)
        # run() delegates to self.run() which checks status under lock
        # and raises ValueError (caught by send_message) — so
        # conversation.run is never invoked.
        conversation.run.assert_not_called()

        # Clean up the simulated running task
        event_service._run_task.cancel()
        with suppress(asyncio.CancelledError):
            await event_service._run_task

    @pytest.mark.asyncio
    async def test_send_message_with_run_true_agent_idle(self, event_service):
        """Test send_message with run=True and agent idle triggers run."""
        # Mock conversation and its methods
        conversation = MagicMock()
        state = MagicMock()
        state.execution_status = ConversationExecutionStatus.IDLE
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation.state = state
        conversation._state = state
        conversation.send_message = MagicMock()
        conversation.run = MagicMock()

        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()
        message = Message(role="user", content=[])

        # Call send_message with run=True
        await event_service.send_message(message, run=True)

        # Verify send_message was called
        conversation.send_message.assert_called_once_with(message)

        # send_message delegates to self.run() which creates a background task
        assert event_service._run_task is not None
        await event_service._run_task

        # Verify run was called since agent was idle
        conversation.run.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_message_with_run_true_interrupts_running_acp_turn(
        self, event_service, tmp_path
    ):
        """A new user message should interrupt an in-flight ACP prompt."""
        agent = ACPAgent(acp_command=["echo", "test"])
        conversation = LocalConversation(
            agent=agent,
            workspace=str(tmp_path),
            max_iteration_per_run=4,
            stuck_detection=False,
        )
        conversation.send_message("initial request")
        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()

        first_step_started = asyncio.Event()
        first_step_cancelled = asyncio.Event()
        second_step_seen = asyncio.Event()
        prompts_seen: list[str] = []

        def user_text(event: MessageEvent | None) -> str:
            assert event is not None
            content = event.llm_message.content[0]
            assert isinstance(content, TextContent)
            return content.text

        async def blocking_astep(
            self,  # noqa: ARG001
            conv: LocalConversation,  # noqa: ARG001
            on_event,  # noqa: ARG001
            on_token=None,  # noqa: ARG001
            prompt_message: MessageEvent | None = None,
        ) -> None:
            prompts_seen.append(user_text(prompt_message))
            if len(prompts_seen) == 1:
                first_step_started.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    first_step_cancelled.set()
                    raise

            second_step_seen.set()
            conv.state.execution_status = ConversationExecutionStatus.FINISHED

        with (
            patch.object(ACPAgent, "init_state", autospec=True),
            patch.object(ACPAgent, "astep", new=blocking_astep),
        ):
            try:
                await event_service.run()
                await asyncio.wait_for(first_step_started.wait(), timeout=1.0)

                await event_service.send_message(
                    Message(role="user", content=[TextContent(text="intervening")]),
                    run=True,
                )

                await asyncio.wait_for(first_step_cancelled.wait(), timeout=1.0)
                await asyncio.wait_for(second_step_seen.wait(), timeout=1.0)
            finally:
                if (
                    event_service._run_task is not None
                    and not event_service._run_task.done()
                ):
                    conversation.interrupt()
                    with suppress(asyncio.CancelledError, TimeoutError):
                        await asyncio.wait_for(event_service._run_task, timeout=1.0)

        assert prompts_seen == ["initial request", "intervening"]

    @pytest.mark.asyncio
    async def test_send_message_with_run_true_does_not_interrupt_current_acp_prompt(
        self, event_service, tmp_path
    ):
        """Do not cancel the ACP prompt if it already advanced to the new message."""
        agent = ACPAgent(acp_command=["echo", "test"])
        conversation = LocalConversation(
            agent=agent,
            workspace=str(tmp_path),
            max_iteration_per_run=4,
            stuck_detection=False,
        )
        conversation.send_message("initial request")
        conversation.state.execution_status = ConversationExecutionStatus.RUNNING
        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()

        release_run = asyncio.Event()
        event_service._run_task = asyncio.create_task(release_run.wait())
        original_send_message = conversation.send_message

        def send_and_mark_active_prompt(message):
            original_send_message(message)
            conversation.state.execution_status = ConversationExecutionStatus.RUNNING
            conversation.state.agent_state = {
                **conversation.state.agent_state,
                ACP_INFLIGHT_PROMPT_USER_MESSAGE_ID: (
                    conversation.state.last_user_message_id
                ),
            }

        conversation.send_message = send_and_mark_active_prompt  # type: ignore[method-assign]
        conversation.interrupt = MagicMock()  # type: ignore[method-assign]

        try:
            await event_service.send_message(
                Message(role="user", content=[TextContent(text="intervening")]),
                run=True,
            )
        finally:
            release_run.set()
            await event_service._run_task
            event_service._run_task = None

        conversation.interrupt.assert_not_called()
        assert event_service._rerun_requested is False

    @pytest.mark.asyncio
    async def test_acp_supersede_mark_rechecks_current_prompt(
        self, event_service, tmp_path
    ):
        """Do not attach the supersede marker to a replacement ACP prompt."""
        agent = ACPAgent(acp_command=["echo", "test"])
        conversation = LocalConversation(
            agent=agent,
            workspace=str(tmp_path),
            max_iteration_per_run=4,
            stuck_detection=False,
        )
        conversation.send_message("initial request")
        conversation.send_message("replacement request")
        latest_user_message_id = conversation.state.last_user_message_id
        assert latest_user_message_id is not None
        conversation.state.execution_status = ConversationExecutionStatus.RUNNING
        conversation.state.agent_state = {
            **conversation.state.agent_state,
            ACP_INFLIGHT_PROMPT_USER_MESSAGE_ID: latest_user_message_id,
        }
        event_service._conversation = conversation
        release_run = asyncio.Event()
        event_service._run_task = asyncio.create_task(release_run.wait())

        try:
            (
                marked,
                active_prompt_has_latest,
            ) = await event_service._mark_running_acp_prompt_superseded()
        finally:
            release_run.set()
            await event_service._run_task
            event_service._run_task = None

        assert marked is False
        assert active_prompt_has_latest is True
        assert ACP_SUPERSEDE_INFLIGHT_PROMPT not in conversation.state.agent_state

    @pytest.mark.asyncio
    async def test_explicit_interrupt_clears_internal_acp_rerun_request(
        self, event_service
    ):
        """A later explicit stop should win over an earlier internal ACP rerun."""
        conversation = MagicMock()
        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()
        event_service._rerun_requested = True
        event_service._acp_internal_rerun_requested = True

        await event_service.interrupt()

        conversation.interrupt.assert_called_once()
        assert event_service._rerun_requested is False
        assert event_service._acp_internal_rerun_requested is False

    @pytest.mark.asyncio
    async def test_internal_acp_rerun_does_not_override_explicit_interrupt(
        self, event_service
    ):
        """Explicit Stop/Pause should win while an internal ACP interrupt drains."""
        conversation = MagicMock()
        conversation.send_message = MagicMock()
        event_service._conversation = conversation
        event_service._mark_running_acp_prompt_superseded = AsyncMock(
            return_value=(True, False)
        )
        event_service.run = AsyncMock()

        async def interrupt_and_simulate_user_stop(internal_acp_rerun=False):
            assert internal_acp_rerun is True
            event_service._explicit_interrupt_generation += 1
            event_service._rerun_requested = False
            event_service._acp_internal_rerun_requested = False

        event_service.interrupt = interrupt_and_simulate_user_stop

        await event_service.send_message(Message(role="user", content=[]), run=True)

        event_service.run.assert_not_awaited()
        assert event_service._rerun_requested is False
        assert event_service._acp_internal_rerun_requested is False

    @pytest.mark.asyncio
    async def test_internal_acp_send_message_restart_rechecks_generation_in_run(
        self, event_service, tmp_path
    ):
        """A late explicit Stop/Pause should prevent direct ACP restart."""
        agent = ACPAgent(acp_command=["echo", "test"])
        conversation = LocalConversation(
            agent=agent,
            workspace=str(tmp_path),
            max_iteration_per_run=3,
            stuck_detection=False,
        )
        mock_arun = AsyncMock()
        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()
        event_service._mark_running_acp_prompt_superseded = AsyncMock(
            return_value=(True, False)
        )
        event_service.interrupt = AsyncMock()

        async def status_with_late_explicit_interrupt():
            event_service._explicit_interrupt_generation += 1
            event_service._rerun_requested = False
            event_service._acp_internal_rerun_requested = False
            return ConversationExecutionStatus.PAUSED

        event_service._get_execution_status = status_with_late_explicit_interrupt

        with patch.object(conversation, "arun", mock_arun):
            await event_service.send_message(Message(role="user", content=[]), run=True)

        event_service.interrupt.assert_awaited_once_with(internal_acp_rerun=True)
        mock_arun.assert_not_awaited()
        assert event_service._run_task is None
        assert event_service._rerun_requested is False
        assert event_service._acp_internal_rerun_requested is False

    @pytest.mark.asyncio
    async def test_internal_acp_rerun_rechecks_explicit_interrupt_before_restart(
        self, event_service, tmp_path
    ):
        """Explicit Stop/Pause should win during final restart status checks."""
        agent = ACPAgent(acp_command=["echo", "test"])
        conversation = LocalConversation(
            agent=agent,
            workspace=str(tmp_path),
            max_iteration_per_run=3,
            stuck_detection=False,
        )
        mock_arun = AsyncMock()
        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()
        event_service._rerun_requested = True
        event_service._acp_internal_rerun_requested = True

        status_calls = 0

        async def status_with_late_explicit_interrupt():
            nonlocal status_calls
            status_calls += 1
            if status_calls == 1:
                return ConversationExecutionStatus.IDLE
            event_service._explicit_interrupt_generation += 1
            event_service._rerun_requested = False
            event_service._acp_internal_rerun_requested = False
            return ConversationExecutionStatus.PAUSED

        event_service._get_execution_status = status_with_late_explicit_interrupt

        with patch.object(conversation, "arun", mock_arun):
            await event_service.run()
            assert event_service._run_task is not None
            await asyncio.wait_for(event_service._run_task, timeout=1.0)

        mock_arun.assert_awaited_once()
        assert status_calls == 2
        assert event_service._rerun_requested is False
        assert event_service._acp_internal_rerun_requested is False

    @pytest.mark.asyncio
    async def test_send_message_with_run_true_logs_exception(self, event_service):
        """Test that exceptions from conversation.run() are caught and logged."""
        # Mock conversation and its methods
        conversation = MagicMock()
        state = MagicMock()
        state.execution_status = ConversationExecutionStatus.IDLE
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation.state = state
        conversation._state = state
        conversation.send_message = MagicMock()
        conversation.run = MagicMock(side_effect=RuntimeError("Test error"))

        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()
        message = Message(role="user", content=[])

        # Patch the logger to verify exception logging
        with patch("openhands.agent_server.event_service.logger") as mock_logger:
            # Call send_message with run=True
            await event_service.send_message(message, run=True)

            # Wait for the background task to complete
            assert event_service._run_task is not None
            await event_service._run_task

            # Verify the exception was logged via logger.exception()
            # (logged by run()'s _run_and_publish handler)
            mock_logger.exception.assert_called_once_with(
                "Error during conversation run"
            )

        # Verify send_message was still called
        conversation.send_message.assert_called_once_with(message)

        # Verify run was called (and raised the exception)
        conversation.run.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_exception_forces_error_status(self, event_service):
        """A run that raises before setting its own ERROR status (e.g. an ACP
        cold-start failure in init_state, which runs outside run()/arun()'s
        try-block) must be flipped to ERROR so the finally's state publish
        surfaces the failure instead of a stale IDLE/RUNNING status (issue
        #1024)."""
        conversation = MagicMock()
        state = MagicMock()
        # Status never advanced past IDLE because the failure happened in
        # _ensure_agent_ready() before the run loop set RUNNING.
        state.execution_status = ConversationExecutionStatus.IDLE
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation.state = state
        conversation._state = state
        conversation.send_message = MagicMock()
        conversation.run = MagicMock(side_effect=RuntimeError("init failed"))

        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()

        await event_service.send_message(Message(role="user", content=[]), run=True)
        assert event_service._run_task is not None
        await event_service._run_task

        assert state.execution_status == ConversationExecutionStatus.ERROR
        # The final state update is still published after the flip.
        event_service._publish_state_update.assert_awaited()

    @pytest.mark.asyncio
    async def test_run_exception_preserves_existing_error_status(self, event_service):
        """When the run already set ERROR (the regular Agent path), the backstop
        is a no-op — it must not clobber a status the run already owns."""
        conversation = MagicMock()
        state = MagicMock()
        state.execution_status = ConversationExecutionStatus.ERROR
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation.state = state
        conversation._state = state
        conversation.send_message = MagicMock()
        conversation.run = MagicMock(side_effect=RuntimeError("boom"))

        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()

        await event_service.send_message(Message(role="user", content=[]), run=True)
        assert event_service._run_task is not None
        await event_service._run_task

        assert state.execution_status == ConversationExecutionStatus.ERROR

    @pytest.mark.asyncio
    async def test_run_exception_emits_conversation_error_event(self, event_service):
        """A failure that escapes run()/arun()'s own emission must be surfaced
        by the backstop as a ConversationErrorEvent (issue #16686)."""
        conversation = MagicMock()
        state = MagicMock()
        state.execution_status = ConversationExecutionStatus.IDLE
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation.state = state
        conversation._state = state
        conversation.send_message = MagicMock()
        conversation._on_event = MagicMock()
        conversation.run = MagicMock(side_effect=RuntimeError("model does not exist"))

        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()

        await event_service.send_message(Message(role="user", content=[]), run=True)
        assert event_service._run_task is not None
        await event_service._run_task

        # A single ConversationErrorEvent was emitted through _on_event, carrying
        # the exception type and message so the UI can render the detail.
        error_events = [
            call.args[0]
            for call in conversation._on_event.call_args_list
            if isinstance(call.args[0], ConversationErrorEvent)
        ]
        assert len(error_events) == 1
        assert error_events[0].code == "RuntimeError"
        assert error_events[0].detail == "model does not exist"
        assert error_events[0].source == "environment"
        assert state.execution_status == ConversationExecutionStatus.ERROR

    @pytest.mark.asyncio
    async def test_run_conversation_run_error_does_not_double_emit(self, event_service):
        """A ConversationRunError is already surfaced by run()/arun(), so the
        backstop must not emit a duplicate ConversationErrorEvent."""
        conversation = MagicMock()
        state = MagicMock()
        state.execution_status = ConversationExecutionStatus.ERROR
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation.state = state
        conversation._state = state
        conversation.send_message = MagicMock()
        conversation._on_event = MagicMock()
        conversation.run = MagicMock(
            side_effect=ConversationRunError(
                conversation_id=uuid4(),
                original_exception=RuntimeError("already surfaced"),
            )
        )

        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()

        await event_service.send_message(Message(role="user", content=[]), run=True)
        assert event_service._run_task is not None
        await event_service._run_task

        error_events = [
            call.args[0]
            for call in conversation._on_event.call_args_list
            if isinstance(call.args[0], ConversationErrorEvent)
        ]
        assert error_events == []

    @pytest.mark.asyncio
    async def test_send_message_with_different_message_types(self, event_service):
        """Test send_message with different message types."""
        # Mock conversation
        conversation = MagicMock()
        conversation.send_message = MagicMock()
        conversation.run = MagicMock()

        event_service._conversation = conversation

        # Mock the event loop and executor
        with patch("asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()
            mock_get_loop.return_value = mock_loop
            # Create a side effect that returns a new coroutine each time
            mock_loop.run_in_executor.side_effect = lambda *args: self._mock_executor()

            # Test with user message (run=False to avoid state checking)
            user_message = Message(role="user", content=[])
            await event_service.send_message(user_message, run=False)
            mock_loop.run_in_executor.assert_any_call(
                None, conversation.send_message, user_message
            )

            # Test with assistant message
            assistant_message = Message(role="assistant", content=[])
            await event_service.send_message(assistant_message, run=False)
            mock_loop.run_in_executor.assert_any_call(
                None, conversation.send_message, assistant_message
            )

            # Test with system message
            system_message = Message(role="system", content=[])
            await event_service.send_message(system_message, run=False)
            mock_loop.run_in_executor.assert_any_call(
                None, conversation.send_message, system_message
            )

    @pytest.mark.asyncio
    async def test_load_plugin_delegates_to_conversation(self, event_service):
        """Runtime plugin loads are delegated through the executor."""
        conversation = MagicMock()
        conversation.load_plugin = MagicMock()
        event_service._conversation = conversation

        with patch("asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()
            mock_get_loop.return_value = mock_loop
            mock_loop.run_in_executor.side_effect = lambda *args: self._mock_executor()

            await event_service.load_plugin("plugin@team")

        mock_loop.run_in_executor.assert_called_once_with(
            None, conversation.load_plugin, "plugin@team"
        )

    @pytest.mark.asyncio
    async def test_load_plugin_inactive_service(self, event_service):
        """Runtime plugin loads require an active conversation."""
        event_service._conversation = None

        with pytest.raises(ValueError, match="inactive_service"):
            await event_service.load_plugin("plugin@team")


class TestEventServiceRespondToConfirmation:
    """Test cases for confirmation responses and rejection handling."""

    @pytest.mark.asyncio
    async def test_respond_to_confirmation_accept_calls_run(self, event_service):
        """Accepting confirmation should trigger run and not rejection."""
        event_service._conversation = MagicMock()
        event_service.run = AsyncMock()
        event_service.reject_pending_actions = AsyncMock()

        request = ConfirmationResponseRequest(accept=True, reason="ignored")

        await event_service.respond_to_confirmation(request)

        # approver_identity is threaded through even when the request didn't
        # set one (None) — see roy_self_approval.py.
        event_service.run.assert_awaited_once_with(approver_identity=None)
        event_service.reject_pending_actions.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_respond_to_confirmation_rejects_actions(self, event_service):
        """Rejecting confirmation should call reject_pending_actions with reason."""
        event_service._conversation = MagicMock()
        event_service.run = AsyncMock()
        event_service.reject_pending_actions = AsyncMock()

        reason = "User rejected actions"
        request = ConfirmationResponseRequest(accept=False, reason=reason)

        await event_service.respond_to_confirmation(request)

        event_service.reject_pending_actions.assert_awaited_once_with(
            reason, approver_identity=None
        )
        event_service.run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_respond_to_confirmation_requires_central_approval_id_in_team_mode(
        self, event_service
    ):
        """Team mode + accept=True without central_approval_id must be
        refused, not silently fall through to the plain (ungoverned) accept
        path — a valid X-Governance-Bridge-Token only proves the caller may
        reach this endpoint, not that this specific action was actually
        approved by central-governance-api."""
        event_service.governance_deployment_mode = "team"
        event_service._conversation = MagicMock()
        event_service.run = AsyncMock()
        event_service.run_and_wait_for_start = AsyncMock()

        request = ConfirmationResponseRequest(accept=True, central_approval_id=None)

        with pytest.raises(GovernanceApprovalRequiredError):
            await event_service.respond_to_confirmation(request)

        event_service.run.assert_not_awaited()
        event_service.run_and_wait_for_start.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_respond_to_confirmation_uses_handshake_in_team_mode(
        self, event_service
    ):
        """The mirror-image case: team mode + a real central_approval_id
        must route through run_and_wait_for_start(), not the plain path."""
        event_service.governance_deployment_mode = "team"
        event_service._conversation = MagicMock()
        event_service.run = AsyncMock()
        event_service.run_and_wait_for_start = AsyncMock(
            return_value=GovernanceStartOutcome.STARTED
        )

        request = ConfirmationResponseRequest(
            accept=True, central_approval_id="approval-1"
        )
        await event_service.respond_to_confirmation(request)

        event_service.run_and_wait_for_start.assert_awaited_once_with(
            central_approval_id="approval-1"
        )
        event_service.run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_respond_to_confirmation_team_mode_ignores_client_approver_identity(
        self, event_service
    ):
        """Identity model B (2026-10-02): under team mode the *only* approver
        identity that counts is the one central-governance-api verified from
        the approver's OIDC token when they decided the request (recorded as
        its ``decision_actor``). A caller-supplied ``approver_identity`` is
        self-reported, so it is not an authorization boundary.

        What this pins, and no more: on the team-mode accept path
        ``respond_to_confirmation`` itself (a) hands only ``central_approval_id``
        to the handshake, (b) never calls the plain ``run(...)`` (the path that
        forwards ``approver_identity``), (c) never calls
        ``check_not_self_approval`` with the client-supplied value, and (d) never
        puts the value into the recorded calls of the three objects observed
        here (the handshake, the plain ``run`` and the conversation). The
        handshake is mocked, so what happens *inside* it (including the
        ``run()`` it ends up calling with ``approver_identity=None``) is
        covered by the handshake tests, not by this one."""
        claimed = "someone-claimed-by-the-client"
        event_service.governance_deployment_mode = "team"
        event_service._conversation = MagicMock()
        event_service.run = AsyncMock()
        event_service.run_and_wait_for_start = AsyncMock(
            return_value=GovernanceStartOutcome.STARTED
        )

        request = ConfirmationResponseRequest(
            accept=True,
            central_approval_id="approval-1",
            approver_identity=claimed,
        )
        with patch(
            "openhands.agent_server.event_service.check_not_self_approval"
        ) as self_approval_check:
            await event_service.respond_to_confirmation(request)

        event_service.run_and_wait_for_start.assert_awaited_once_with(
            central_approval_id="approval-1"
        )
        # The plain path is the only one that forwards approver_identity; it
        # must not run at all in team mode.
        event_service.run.assert_not_awaited()
        # The local self-approval check must not be fed the client's claim by
        # this method (a regression that consumes the field *before* calling
        # the handshake would still satisfy the two assertions above).
        self_approval_check.assert_not_called()
        for collaborator in (
            event_service.run,
            event_service.run_and_wait_for_start,
            event_service._conversation,
        ):
            assert claimed not in repr(collaborator.mock_calls)

    @pytest.mark.asyncio
    async def test_respond_to_confirmation_raises_on_pending_unknown_outcome(
        self, event_service
    ):
        """PENDING_UNKNOWN (the handshake timed out, not a rejection — see
        run_and_wait_for_start()'s own docstring) must not be folded into
        the STARTED success path: the caller cannot yet tell whether
        claim/binding actually succeeded, so it needs its own distinct,
        non-success outcome rather than a false-positive 200."""
        event_service.governance_deployment_mode = "team"
        event_service._conversation = MagicMock()
        event_service.run = AsyncMock()
        event_service.run_and_wait_for_start = AsyncMock(
            return_value=GovernanceStartOutcome.PENDING_UNKNOWN
        )

        request = ConfirmationResponseRequest(
            accept=True, central_approval_id="approval-1"
        )
        with pytest.raises(GovernanceStartRejectedError) as exc_info:
            await event_service.respond_to_confirmation(request)

        assert exc_info.value.outcome == GovernanceStartOutcome.PENDING_UNKNOWN
        event_service.run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_run_blocks_self_approval_before_scheduling_background_task(
        self, event_service
    ):
        """A blocked self-approval must raise synchronously from run() itself
        — not from inside the background task it schedules. Anything raised
        from *inside* that task is caught by its own backstop (see
        test_run_exception_forces_error_status) and turned into a generic
        ERROR status + error event instead of propagating to the REST
        caller, which would silently swallow this specific rejection. This
        is why EventService.run() checks eagerly rather than relying on the
        equivalent check already inside LocalConversation.run()/arun()."""
        conversation = MagicMock()
        state = MagicMock()
        state.execution_status = ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation.state = state
        conversation._state = state
        conversation._requester_identity = "roy"
        conversation.run = MagicMock()
        conversation.arun = AsyncMock()

        event_service._conversation = conversation

        with pytest.raises(ValueError, match="self-approval not allowed"):
            await event_service.run(approver_identity="roy")

        assert event_service._run_task is None
        conversation.run.assert_not_called()
        conversation.arun.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_run_allows_different_approver_identity_via_event_service(
        self, event_service
    ):
        conversation = MagicMock()
        state = MagicMock()
        state.execution_status = ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation.state = state
        conversation._state = state
        conversation._requester_identity = "roy"
        conversation.run = MagicMock()

        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()

        await event_service.run(approver_identity="test-approver")
        assert event_service._run_task is not None
        await event_service._run_task

        conversation.run.assert_called_once_with(approver_identity="test-approver")

    @pytest.mark.asyncio
    async def test_respond_to_confirmation_propagates_self_approval_block(
        self, event_service
    ):
        """The REST-facing entry point must not swallow a blocked
        self-approval the way it swallows "conversation_already_running" —
        the caller needs to see this was refused, not silently no-op'd."""
        event_service._conversation = MagicMock()
        event_service.run = AsyncMock(
            side_effect=ValueError(
                "self-approval not allowed: requester and approver are the "
                "same identity ('roy')"
            )
        )

        request = ConfirmationResponseRequest(accept=True, approver_identity="roy")

        with pytest.raises(ValueError, match="self-approval not allowed"):
            await event_service.respond_to_confirmation(request)

    # The user_approval audit record itself is no longer written here — see
    # LocalConversation.run()/arun()/reject_pending_actions() and
    # tests/sdk/security/test_roy_user_approval_audit.py.

    @pytest.mark.asyncio
    async def test_reject_pending_actions_inactive_service(self, event_service):
        """Rejecting pending actions should fail when service is inactive."""
        event_service._conversation = None

        with pytest.raises(ValueError, match="inactive_service"):
            await event_service.reject_pending_actions("any reason")

    @pytest.mark.asyncio
    async def test_reject_pending_actions_invokes_conversation(self, event_service):
        """Rejecting pending actions should delegate to conversation via executor."""
        conversation = MagicMock()
        conversation.reject_pending_actions = MagicMock()
        event_service._conversation = conversation

        async def _mock_executor(*_args, **_kwargs):
            return None

        with patch("asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()
            mock_get_loop.return_value = mock_loop
            mock_loop.run_in_executor.return_value = _mock_executor()

            await event_service.reject_pending_actions("custom reason")

            # No approver_identity supplied — dispatched exactly as before
            # (bare method reference, no functools.partial wrapping) so any
            # conversation-like object that predates this kwarg still works.
            mock_loop.run_in_executor.assert_called_once_with(
                None, conversation.reject_pending_actions, "custom reason"
            )

    @pytest.mark.asyncio
    async def test_reject_pending_actions_forwards_approver_identity(
        self, event_service
    ):
        """approver_identity passed to EventService.reject_pending_actions()
        must reach LocalConversation.reject_pending_actions() — this is what
        lets the audit record capture who rejected, and is recorded (never
        blocked, unlike accept — see roy_self_approval.py) even when it
        matches the requester identity."""
        conversation = MagicMock()
        conversation.reject_pending_actions = MagicMock()
        event_service._conversation = conversation

        async def _mock_executor(*_args, **_kwargs):
            return None

        with patch("asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()
            mock_get_loop.return_value = mock_loop
            mock_loop.run_in_executor.return_value = _mock_executor()

            await event_service.reject_pending_actions(
                "custom reason", approver_identity="roy"
            )

            _executor_arg, dispatched = mock_loop.run_in_executor.call_args.args
            assert dispatched.keywords == {"approver_identity": "roy"}


class TestEventServiceIsOpen:
    """Test cases for EventService.is_open method."""

    def test_is_open_when_conversation_is_none(self, event_service):
        """Test is_open returns False when _conversation is None."""
        event_service._conversation = None
        assert not event_service.is_open()

    def test_is_open_when_conversation_exists(self, event_service):
        """Test is_open returns True when _conversation exists."""
        conversation = MagicMock(spec=Conversation)
        event_service._conversation = conversation
        assert event_service.is_open()

    def test_is_open_when_conversation_is_falsy(self, event_service):
        """Test is_open returns False when _conversation is falsy."""
        # Test with various falsy values
        falsy_values = [None, False, 0, "", [], {}]

        for falsy_value in falsy_values:
            event_service._conversation = falsy_value
            assert not event_service.is_open(), f"Expected False for {falsy_value}"

    def test_is_open_when_conversation_is_truthy(self, event_service):
        """Test is_open returns True when _conversation is truthy."""
        # Test with various truthy values
        truthy_values = [
            MagicMock(spec=Conversation),
            "some_string",
            1,
            [1, 2, 3],
            {"key": "value"},
            True,
        ]

        for truthy_value in truthy_values:
            event_service._conversation = truthy_value
            assert event_service.is_open(), f"Expected True for {truthy_value}"


class TestEventServiceBodyFiltering:
    """Test cases for EventService body filtering functionality."""

    def test_event_matches_body_with_message_event(self, event_service):
        """Test _event_matches_body with MessageEvent containing text content."""
        from openhands.sdk.llm.message import TextContent

        # Create a MessageEvent with text content
        message = Message(role="user", content=[TextContent(text="Hello world")])
        event = MessageEvent(id="test", source="user", llm_message=message)

        # Test case-insensitive matching
        assert event_service._event_matches_body(event, "hello")
        assert event_service._event_matches_body(event, "WORLD")
        assert event_service._event_matches_body(event, "Hello world")
        assert event_service._event_matches_body(event, "llo wor")

        # Test non-matching
        assert not event_service._event_matches_body(event, "goodbye")
        assert not event_service._event_matches_body(event, "xyz")

    def test_event_matches_body_with_non_message_event(self, event_service):
        """Test _event_matches_body with non-MessageEvent (should return False)."""
        from openhands.sdk.event.user_action import PauseEvent

        # Create a non-MessageEvent
        event = PauseEvent(id="test")

        # Should always return False for non-MessageEvent
        assert not event_service._event_matches_body(event, "any text")
        assert not event_service._event_matches_body(event, "")

    def test_event_matches_body_with_empty_content(self, event_service):
        """Test _event_matches_body with MessageEvent containing empty content."""
        # Create a MessageEvent with empty content
        message = Message(role="user", content=[])
        event = MessageEvent(id="test", source="user", llm_message=message)

        # Should not match any non-empty text
        assert not event_service._event_matches_body(event, "any text")
        # Empty string should match empty content (empty string contains empty string)
        assert event_service._event_matches_body(event, "")

    @pytest.mark.asyncio
    async def test_search_events_with_body_filter_integration(self, event_service):
        """Test search_events with body filter using real MessageEvents."""
        from openhands.sdk.llm.message import TextContent

        # Create a conversation with MessageEvents containing different text
        conversation = MagicMock(spec=Conversation)
        state = MagicMock(spec=ConversationState)

        events = [
            MessageEvent(
                id="event1",
                source="user",
                llm_message=Message(
                    role="user", content=[TextContent(text="Hello world")]
                ),
            ),
            MessageEvent(
                id="event2",
                source="agent",
                llm_message=Message(
                    role="assistant", content=[TextContent(text="How can I help?")]
                ),
            ),
            MessageEvent(
                id="event3",
                source="user",
                llm_message=Message(
                    role="user", content=[TextContent(text="Create a Python script")]
                ),
            ),
        ]

        state.events = events
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation._state = state

        event_service._conversation = conversation

        # Test filtering by "hello" (should match event1)
        result = await event_service.search_events(body="hello")
        assert len(result.items) == 1
        assert result.items[0].id == "event1"

        # Test filtering by "python" (should match event3)
        result = await event_service.search_events(body="python")
        assert len(result.items) == 1
        assert result.items[0].id == "event3"

        # Test filtering by "help" (should match event2)
        result = await event_service.search_events(body="help")
        assert len(result.items) == 1
        assert result.items[0].id == "event2"

        # Test filtering by non-matching text
        result = await event_service.search_events(body="nonexistent")
        assert len(result.items) == 0

    @pytest.mark.asyncio
    async def test_count_events_with_body_filter_integration(self, event_service):
        """Test count_events with body filter using real MessageEvents."""
        from openhands.sdk.llm.message import TextContent

        # Create a conversation with MessageEvents containing different text
        conversation = MagicMock(spec=Conversation)
        state = MagicMock(spec=ConversationState)

        events = [
            MessageEvent(
                id="event1",
                source="user",
                llm_message=Message(
                    role="user", content=[TextContent(text="Hello world")]
                ),
            ),
            MessageEvent(
                id="event2",
                source="agent",
                llm_message=Message(
                    role="assistant", content=[TextContent(text="Hello there")]
                ),
            ),
            MessageEvent(
                id="event3",
                source="user",
                llm_message=Message(
                    role="user", content=[TextContent(text="Create a Python script")]
                ),
            ),
        ]

        state.events = events
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation._state = state

        event_service._conversation = conversation

        # Test counting by "hello" (should match 2 events)
        result = await event_service.count_events(body="hello")
        assert result == 2

        # Test counting by "python" (should match 1 event)
        result = await event_service.count_events(body="python")
        assert result == 1

        # Test counting by non-matching text
        result = await event_service.count_events(body="nonexistent")
        assert result == 0


class TestEventServiceRun:
    """Test cases for EventService.run method."""

    @pytest.mark.asyncio
    async def test_run_inactive_service(self, event_service):
        """Test that run raises ValueError when conversation is not active."""
        event_service._conversation = None

        with pytest.raises(ValueError, match="inactive_service"):
            await event_service.run()

    @pytest.mark.asyncio
    async def test_run_already_running_by_status(self, event_service):
        """Test that run raises ValueError when conversation is already running."""
        conversation = MagicMock(spec=Conversation)
        state = MagicMock(spec=ConversationState)
        state.execution_status = ConversationExecutionStatus.RUNNING
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation._state = state

        event_service._conversation = conversation

        with pytest.raises(ValueError, match="conversation_already_running"):
            await event_service.run()

    @pytest.mark.asyncio
    async def test_run_already_running_by_task(self, event_service):
        """Test that run raises ValueError when there's an active run task."""
        conversation = MagicMock(spec=Conversation)
        state = MagicMock(spec=ConversationState)
        state.execution_status = ConversationExecutionStatus.IDLE
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation._state = state

        event_service._conversation = conversation

        # Create a mock task that is not done
        mock_task = MagicMock()
        mock_task.done.return_value = False
        event_service._run_task = mock_task

        with pytest.raises(ValueError, match="conversation_already_running"):
            await event_service.run()

    @pytest.mark.asyncio
    async def test_run_starts_background_task(self, event_service):
        """Test that run starts a background task and returns immediately."""
        conversation = MagicMock(spec=Conversation)
        state = MagicMock(spec=ConversationState)
        state.execution_status = ConversationExecutionStatus.IDLE
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation._state = state
        conversation.run = MagicMock()

        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()

        # Call run - should return immediately
        await event_service.run()

        # Verify a task was created
        assert event_service._run_task is not None

        # Wait for the background task to complete
        await event_service._run_task

        # Verify conversation.run was called
        conversation.run.assert_called_once()

        # Verify state update was published after run completed
        event_service._publish_state_update.assert_called()

    @pytest.mark.asyncio
    async def test_run_publishes_state_update_on_completion(self, event_service):
        """Test that run publishes state update after completion."""
        conversation = MagicMock(spec=Conversation)
        state = MagicMock(spec=ConversationState)
        state.execution_status = ConversationExecutionStatus.IDLE
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation._state = state
        conversation.run = MagicMock()

        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()

        await event_service.run()
        await event_service._run_task  # Wait for completion

        # State update should be published after run completes
        event_service._publish_state_update.assert_called()

    @pytest.mark.asyncio
    async def test_run_publishes_state_update_on_error(self, event_service):
        """Test that run publishes state update even if run raises an error."""
        conversation = MagicMock(spec=Conversation)
        state = MagicMock(spec=ConversationState)
        state.execution_status = ConversationExecutionStatus.IDLE
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation._state = state
        conversation.run = MagicMock(side_effect=RuntimeError("Test error"))

        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()

        await event_service.run()

        # Wait for the background task to complete (it will raise but be caught)
        try:
            await event_service._run_task
        except RuntimeError:
            pass  # Expected

        # State update should still be published (in finally block)
        event_service._publish_state_update.assert_called()


class TestEventServiceSaveMeta:
    """Test cases for EventService.save_meta method."""

    @pytest.mark.asyncio
    async def test_save_meta_preserves_updated_at(self, event_service, tmp_path):
        """Test that save_meta does not modify updated_at.

        On server restart every conversation's save_meta is called.  Before the
        fix, save_meta stamped updated_at = utc_now(), so all conversations
        appeared to have been updated at restart time.
        """
        original_updated_at = datetime(2025, 1, 1, 12, 30, 0, tzinfo=UTC)
        event_service.stored.updated_at = original_updated_at
        event_service.conversations_dir = tmp_path
        conv_dir = tmp_path / event_service.stored.id.hex
        conv_dir.mkdir(parents=True, exist_ok=True)

        await event_service.save_meta()

        # In-memory value must be unchanged
        assert event_service.stored.updated_at == original_updated_at

        # Persisted value must also match
        meta_file = conv_dir / "meta.json"
        loaded = StoredConversation.model_validate_json(meta_file.read_text())
        assert loaded.updated_at == original_updated_at

    @pytest.mark.asyncio
    async def test_save_meta_round_trips_agent_definition_mcp_secrets(
        self, sample_stored_conversation, tmp_path
    ):
        cipher = Cipher("stored-conversation-mcp-secret")
        sample_stored_conversation.agent_definitions = [
            AgentDefinition(
                name="web-researcher",
                mcp_config=coerce_mcp_config(
                    {
                        "tavily": {
                            "command": "npx",
                            "args": ["-y", "tavily-mcp@0.2.1"],
                            "env": {"TAVILY_API_KEY": "${TAVILY_API_KEY}"},
                        }
                    }
                ),
            )
        ]
        service = EventService(
            stored=sample_stored_conversation,
            conversations_dir=tmp_path,
            cipher=cipher,
        )
        service.conversation_dir.mkdir(parents=True)

        await service.save_meta()

        payload = (service.conversation_dir / "meta.json").read_text()
        assert "${TAVILY_API_KEY}" not in payload
        loaded = StoredConversation.model_validate_json(
            payload,
            context={"cipher": cipher},
        )
        assert loaded.agent_definitions[0].mcp_config is not None
        env = loaded.agent_definitions[0].mcp_config["tavily"].env
        assert env is not None
        assert env["TAVILY_API_KEY"].get_secret_value() == "${TAVILY_API_KEY}"

    @pytest.mark.asyncio
    async def test_switch_acp_model_persists_via_conversation(self, tmp_path):
        """switch_acp_model delegates to the SDK conversation, which persists the
        new model to base_state.json (the single source of truth).

        meta.json no longer carries the agent, so the event service must NOT
        mirror the switch there. The SDK ``LocalConversation.switch_acp_model``
        sets ``state.agent`` to an agent carrying the new ``acp_model``, which the
        autosave path writes to base_state.json; on resume the agent is rebuilt
        from base_state.
        """
        stored = StoredConversation(
            id=uuid4(),
            workspace=LocalWorkspace(working_dir=str(tmp_path)),
            confirmation_policy=NeverConfirm(),
            initial_message=None,
            metrics=None,
        )
        service = EventService(stored=stored, conversations_dir=tmp_path)
        conv_dir = tmp_path / stored.id.hex
        conv_dir.mkdir(parents=True, exist_ok=True)

        # Write a meta.json up front so the assertion below proves the switch
        # does not overwrite an *existing* meta.json with an agent mirror, rather
        # than trivially passing because meta.json was never created.
        await service.save_meta()
        meta_file = conv_dir / "meta.json"
        assert meta_file.exists()
        assert "agent" not in json.loads(meta_file.read_text())

        # Stand in for a live conversation; the protocol-level switch and the
        # base_state persistence are covered by the SDK's own tests — here we
        # only assert delegation and that meta.json is not written with an agent.
        service._conversation = MagicMock()

        await service.switch_acp_model("new-model")

        # Live switch is delegated to the SDK conversation (which persists to
        # base_state.json).
        service._conversation.switch_acp_model.assert_called_once_with("new-model")
        # StoredConversation no longer carries the agent at all.
        assert not hasattr(service.stored, "agent")
        # meta.json still exists and was never given an agent mirror.
        assert meta_file.exists()
        assert "agent" not in json.loads(meta_file.read_text())

    @pytest.mark.asyncio
    async def test_switch_acp_model_inactive_service_raises_value_error(self, tmp_path):
        """An inactive service (no live conversation) raises the shared
        ``inactive_service`` ValueError — consistent with the other
        event-service methods — which the router maps to 400. It is no longer a
        RuntimeError: the SDK now defers (rather than rejects) a switch before
        the first run(), so the only failure mode here is a closed/never-started
        service.
        """

        stored = StoredConversation(
            id=uuid4(),
            workspace=LocalWorkspace(working_dir=str(tmp_path)),
            confirmation_policy=NeverConfirm(),
            initial_message=None,
            metrics=None,
        )
        service = EventService(stored=stored, conversations_dir=tmp_path)
        # _conversation defaults to None (service not started).
        assert service._conversation is None

        with pytest.raises(ValueError, match="inactive_service"):
            await service.switch_acp_model("new-model")


class TestEventServiceStartWithRunningStatus:
    """Test cases for EventService.start handling of RUNNING execution status."""

    @pytest.mark.asyncio
    async def test_start_sets_error_status_when_running_from_disk(
        self, event_service, tmp_path
    ):
        """Test that start() sets ERROR status and adds AgentErrorEvent.

        When a conversation is loaded from disk with RUNNING status, it indicates
        the process crashed or was terminated unexpectedly. The EventService should:
        1. Set execution_status to ERROR
        2. Add an AgentErrorEvent for the first unmatched action to inform the agent
        """
        from openhands.sdk.event import AgentErrorEvent
        from openhands.sdk.event.llm_convertible import ActionEvent
        from openhands.sdk.llm import MessageToolCall, TextContent
        from openhands.tools.terminal import TerminalAction

        # Setup paths
        event_service.conversations_dir = tmp_path
        conv_dir = tmp_path / event_service.stored.id.hex
        conv_dir.mkdir(parents=True, exist_ok=True)

        # Update workspace to use a valid temp directory
        event_service.stored.workspace = LocalWorkspace(working_dir=str(tmp_path))

        with patch(
            "openhands.agent_server.event_service.LocalConversation"
        ) as MockConversation:
            mock_conv = MagicMock()
            mock_state = MagicMock()
            mock_agent = MagicMock()

            # Create an unmatched action event (action without observation)
            unmatched_action = ActionEvent(
                source="agent",
                thought=[TextContent(text="I need to run ls command")],
                action=TerminalAction(command="ls"),
                tool_name="terminal",
                tool_call_id="call_1",
                tool_call=MessageToolCall(
                    id="call_1",
                    name="terminal",
                    arguments='{"command": "ls"}',
                    origin="completion",
                ),
                llm_response_id="response_1",
            )

            # Set up mock state with RUNNING status and the unmatched action
            mock_state.execution_status = ConversationExecutionStatus.RUNNING
            mock_state.events = [unmatched_action]
            mock_state.stats = MagicMock()

            # Setup mock agent
            mock_agent.get_all_llms.return_value = []

            mock_conv._state = mock_state
            mock_conv.state = mock_state
            mock_conv.agent = mock_agent
            mock_conv._on_event = MagicMock()
            MockConversation.return_value = mock_conv

            # Call start
            await event_service.start()

            # Verify execution_status was changed to ERROR
            assert mock_state.execution_status == ConversationExecutionStatus.ERROR

            # Verify AgentErrorEvent was added via _on_event
            mock_conv._on_event.assert_called()
            call_args = mock_conv._on_event.call_args_list

            # Find the AgentErrorEvent call
            error_event_calls = [
                call for call in call_args if isinstance(call[0][0], AgentErrorEvent)
            ]
            assert len(error_event_calls) == 1

            error_event = error_event_calls[0][0][0]
            assert error_event.tool_name == "terminal"
            assert error_event.tool_call_id == "call_1"
            assert "restart occurred" in error_event.error
            assert "fatal memory error" in error_event.error

    @pytest.mark.asyncio
    async def test_start_crash_recovery_triggers_governance_result_reporting(
        self, event_service, tmp_path
    ):
        """The synthetic AgentErrorEvent this crash-recovery path writes is
        exactly the evidence maybe_report_governance_result()'s classifier
        needs — start() must actually call it, not just publish state.
        Without this wiring, a governed action whose process died
        mid-execution with no follow-up run would leave central waiting
        forever."""
        from openhands.sdk.event.llm_convertible import ActionEvent
        from openhands.sdk.llm import MessageToolCall, TextContent
        from openhands.tools.terminal import TerminalAction

        event_service.conversations_dir = tmp_path
        conv_dir = tmp_path / event_service.stored.id.hex
        conv_dir.mkdir(parents=True, exist_ok=True)
        event_service.stored.workspace = LocalWorkspace(working_dir=str(tmp_path))
        event_service.governance_deployment_mode = "team"
        event_service.maybe_report_governance_result = AsyncMock()

        with patch(
            "openhands.agent_server.event_service.LocalConversation"
        ) as MockConversation:
            mock_conv = MagicMock()
            mock_state = MagicMock()
            mock_agent = MagicMock()

            unmatched_action = ActionEvent(
                source="agent",
                thought=[TextContent(text="running a command")],
                action=TerminalAction(command="ls"),
                tool_name="terminal",
                tool_call_id="call_1",
                tool_call=MessageToolCall(
                    id="call_1",
                    name="terminal",
                    arguments='{"command": "ls"}',
                    origin="completion",
                ),
                llm_response_id="response_1",
            )
            mock_state.execution_status = ConversationExecutionStatus.RUNNING
            mock_state.events = [unmatched_action]
            mock_state.stats = MagicMock()
            mock_agent.get_all_llms.return_value = []
            mock_conv._state = mock_state
            mock_conv.state = mock_state
            mock_conv.agent = mock_agent
            mock_conv._on_event = MagicMock()
            MockConversation.return_value = mock_conv

            await event_service.start()

        event_service.maybe_report_governance_result.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_start_does_not_add_error_event_when_no_unmatched_actions(
        self, event_service, tmp_path
    ):
        """Test that start() doesn't add AgentErrorEvent without unmatched actions.

        Even if execution_status is RUNNING, if there are no unmatched actions,
        no AgentErrorEvent should be added.
        """
        from openhands.sdk.event import AgentErrorEvent

        # Setup paths
        event_service.conversations_dir = tmp_path
        conv_dir = tmp_path / event_service.stored.id.hex
        conv_dir.mkdir(parents=True, exist_ok=True)

        # Update workspace to use a valid temp directory
        event_service.stored.workspace = LocalWorkspace(working_dir=str(tmp_path))

        with patch(
            "openhands.agent_server.event_service.LocalConversation"
        ) as MockConversation:
            mock_conv = MagicMock()
            mock_state = MagicMock()
            mock_agent = MagicMock()

            # Set up mock state with RUNNING status but no events (no unmatched actions)
            mock_state.execution_status = ConversationExecutionStatus.RUNNING
            mock_state.events = []
            mock_state.stats = MagicMock()

            # Setup mock agent
            mock_agent.get_all_llms.return_value = []

            mock_conv._state = mock_state
            mock_conv.state = mock_state
            mock_conv.agent = mock_agent
            mock_conv._on_event = MagicMock()
            MockConversation.return_value = mock_conv

            # Call start
            await event_service.start()

            # Verify execution_status was changed to ERROR
            assert mock_state.execution_status == ConversationExecutionStatus.ERROR

            # Verify _on_event was NOT called with AgentErrorEvent
            error_event_calls = [
                call
                for call in mock_conv._on_event.call_args_list
                if isinstance(call[0][0], AgentErrorEvent)
            ]
            assert len(error_event_calls) == 0

    @pytest.mark.asyncio
    async def test_start_does_nothing_when_status_not_running(
        self, event_service, tmp_path
    ):
        """Test that start() doesn't modify execution_status when it's not RUNNING."""
        from openhands.sdk.event import AgentErrorEvent

        # Setup paths
        event_service.conversations_dir = tmp_path
        conv_dir = tmp_path / event_service.stored.id.hex
        conv_dir.mkdir(parents=True, exist_ok=True)

        # Update workspace to use a valid temp directory
        event_service.stored.workspace = LocalWorkspace(working_dir=str(tmp_path))

        with patch(
            "openhands.agent_server.event_service.LocalConversation"
        ) as MockConversation:
            mock_conv = MagicMock()
            mock_state = MagicMock()
            mock_agent = MagicMock()

            # Set up mock state with IDLE status
            mock_state.execution_status = ConversationExecutionStatus.IDLE
            mock_state.events = []
            mock_state.stats = MagicMock()

            # Setup mock agent
            mock_agent.get_all_llms.return_value = []

            mock_conv._state = mock_state
            mock_conv.state = mock_state
            mock_conv.agent = mock_agent
            mock_conv._on_event = MagicMock()
            MockConversation.return_value = mock_conv

            # Call start
            await event_service.start()

            # Verify execution_status remains IDLE
            assert mock_state.execution_status == ConversationExecutionStatus.IDLE

            # Verify _on_event was NOT called with AgentErrorEvent
            error_event_calls = [
                call
                for call in mock_conv._on_event.call_args_list
                if isinstance(call[0][0], AgentErrorEvent)
            ]
            assert len(error_event_calls) == 0

    @pytest.mark.asyncio
    async def test_start_skips_error_event_when_observation_already_exists(
        self, event_service, tmp_path
    ):
        """Don't synthesize AgentErrorEvent if the loaded state already carries an
        ObservationBaseEvent for the unmatched action's tool_call_id.

        Reproduces the gap get_unmatched_actions misses: an ObservationEvent that
        matches by tool_call_id but not by action_id (e.g. action_id rewritten on
        replay) — without this guard we'd emit a duplicate observation-like event.
        """
        event_service.conversations_dir = tmp_path
        conv_dir = tmp_path / event_service.stored.id.hex
        conv_dir.mkdir(parents=True, exist_ok=True)
        event_service.stored.workspace = LocalWorkspace(working_dir=str(tmp_path))

        with patch(
            "openhands.agent_server.event_service.LocalConversation"
        ) as MockConversation:
            mock_conv = MagicMock()
            mock_state = MagicMock()
            mock_agent = MagicMock()

            unmatched_action = ActionEvent(
                source="agent",
                thought=[TextContent(text="run ls")],
                action=TerminalAction(command="ls"),
                tool_name="terminal",
                tool_call_id="call_1",
                tool_call=MessageToolCall(
                    id="call_1",
                    name="terminal",
                    arguments='{"command": "ls"}',
                    origin="completion",
                ),
                llm_response_id="response_1",
            )
            # Observation matches by tool_call_id but with a different action_id,
            # so get_unmatched_actions still reports the action as unmatched.
            stale_observation = ObservationEvent(
                observation=TerminalObservation.from_text(
                    "done", command="ls", exit_code=0
                ),
                action_id="some_other_action_id",
                tool_name="terminal",
                tool_call_id="call_1",
            )

            mock_state.execution_status = ConversationExecutionStatus.RUNNING
            mock_state.events = [unmatched_action, stale_observation]
            mock_state.stats = MagicMock()

            mock_agent.get_all_llms.return_value = []
            mock_conv._state = mock_state
            mock_conv.state = mock_state
            mock_conv.agent = mock_agent
            mock_conv._on_event = MagicMock()
            MockConversation.return_value = mock_conv

            await event_service.start()

            assert mock_state.execution_status == ConversationExecutionStatus.ERROR
            error_event_calls = [
                call
                for call in mock_conv._on_event.call_args_list
                if isinstance(call[0][0], AgentErrorEvent)
            ]
            assert len(error_event_calls) == 0

    @pytest.mark.skipif(not shutil.which("git"), reason="git executable not found")
    @pytest.mark.asyncio
    async def test_start_initializes_workspace_as_git_repo(
        self, event_service, tmp_path
    ):
        """A fresh workspace dir should be `git init`-ed during start().

        Without this, /api/git/changes 500s on non-repo workspaces and
        agent-created files never appear in the Changes tab.
        """
        # Arrange
        event_service.conversations_dir = tmp_path
        conv_dir = tmp_path / event_service.stored.id.hex
        conv_dir.mkdir(parents=True, exist_ok=True)
        workspace_dir = tmp_path / "fresh_workspace"
        event_service.stored.workspace = LocalWorkspace(working_dir=str(workspace_dir))

        with patch(
            "openhands.agent_server.event_service.LocalConversation"
        ) as MockConversation:
            mock_conv = MagicMock()
            mock_state = MagicMock()
            mock_agent = MagicMock()
            mock_state.execution_status = ConversationExecutionStatus.IDLE
            mock_state.events = []
            mock_state.stats = MagicMock()
            mock_agent.get_all_llms.return_value = []
            mock_conv._state = mock_state
            mock_conv.state = mock_state
            mock_conv.agent = mock_agent
            mock_conv._on_event = MagicMock()
            MockConversation.return_value = mock_conv

            # Act
            await event_service.start()

        # Assert
        assert (workspace_dir / ".git").exists()

    @pytest.mark.skipif(not shutil.which("git"), reason="git executable not found")
    @pytest.mark.asyncio
    async def test_start_is_idempotent_for_already_initialized_repo(
        self, event_service, tmp_path
    ):
        """Resuming a conversation on an existing repo must not re-init it.

        Guards against accidental double-init that could clobber refs/HEAD
        on a workspace the user already has commits in.
        """
        # Arrange — pre-initialize the workspace dir as a git repo and
        # capture the .git directory's identity so we can detect re-init.
        event_service.conversations_dir = tmp_path
        conv_dir = tmp_path / event_service.stored.id.hex
        conv_dir.mkdir(parents=True, exist_ok=True)
        workspace_dir = tmp_path / "existing_repo"
        workspace_dir.mkdir(parents=True, exist_ok=True)
        from openhands.sdk.git.utils import run_git_command

        run_git_command(["git", "init"], workspace_dir)
        marker = workspace_dir / ".git" / "_idempotency_marker"
        marker.write_text("preexisting")

        event_service.stored.workspace = LocalWorkspace(working_dir=str(workspace_dir))

        with patch(
            "openhands.agent_server.event_service.LocalConversation"
        ) as MockConversation:
            mock_conv = MagicMock()
            mock_state = MagicMock()
            mock_agent = MagicMock()
            mock_state.execution_status = ConversationExecutionStatus.IDLE
            mock_state.events = []
            mock_state.stats = MagicMock()
            mock_agent.get_all_llms.return_value = []
            mock_conv._state = mock_state
            mock_conv.state = mock_state
            mock_conv.agent = mock_agent
            mock_conv._on_event = MagicMock()
            MockConversation.return_value = mock_conv

            # Act
            await event_service.start()

        # Assert — repo still present and our marker survived (no re-init).
        assert (workspace_dir / ".git").exists()
        assert marker.exists()
        assert marker.read_text() == "preexisting"


class TestEventServiceConcurrentSubscriptions:
    """Test cases for concurrent subscription handling without deadlocks.

    These tests verify that the fix for moving async operations outside the
    FIFOLock context prevents deadlocks when multiple subscribers are active
    or when subscribers are slow.
    """

    @pytest.fixture
    def mock_conversation_with_real_lock(self):
        """Create a mock conversation with a real FIFOLock for testing concurrency."""
        conversation = MagicMock(spec=Conversation)
        state = MagicMock(spec=ConversationState)

        # Use a real FIFOLock to test actual locking behavior
        real_lock = FIFOLock()
        state._lock = real_lock
        state.__enter__ = lambda self: (real_lock.acquire(), self)[1]
        state.__exit__ = lambda self, *args: real_lock.release()

        # Set up minimal state attributes needed for ConversationStateUpdateEvent
        state.events = []
        state.execution_status = ConversationExecutionStatus.IDLE
        state.model_dump = MagicMock(
            return_value={
                "execution_status": "idle",
                "events": [],
            }
        )

        conversation._state = state
        return conversation

    @pytest.mark.asyncio
    async def test_concurrent_subscriptions_no_deadlock(
        self, event_service, mock_conversation_with_real_lock
    ):
        """Test that multiple concurrent subscriptions don't cause deadlocks.

        This test creates multiple subscribers that are subscribed concurrently
        and verifies that all subscriptions complete without hanging.
        """
        event_service._conversation = mock_conversation_with_real_lock
        received_events: list[list[Event]] = [[] for _ in range(3)]

        class TestSubscriber(Subscriber[Event]):
            def __init__(self, index: int):
                self.index = index

            async def __call__(self, event: Event):
                received_events[self.index].append(event)

        # Subscribe multiple subscribers concurrently
        subscribers = [TestSubscriber(i) for i in range(3)]

        # Use asyncio.wait_for to detect deadlocks with a timeout
        async def subscribe_all():
            tasks = [event_service.subscribe_to_events(sub) for sub in subscribers]
            return await asyncio.gather(*tasks)

        # This should complete within 2 seconds if there's no deadlock
        subscriber_ids = await asyncio.wait_for(subscribe_all(), timeout=2.0)

        # Verify all subscriptions succeeded
        assert len(subscriber_ids) == 3
        for sub_id in subscriber_ids:
            assert sub_id is not None

        # Verify all subscribers received the initial state event
        for i, events in enumerate(received_events):
            assert len(events) == 1, f"Subscriber {i} should have received 1 event"
            assert isinstance(events[0], ConversationStateUpdateEvent)

    @pytest.mark.asyncio
    async def test_subscription_receives_state_when_conversation_not_open(
        self, event_service
    ):
        """Inactive services still need an initial state event for WS readiness."""
        received_events: list[Event] = []

        class TestSubscriber(Subscriber[Event]):
            async def __call__(self, event: Event):
                received_events.append(event)

        await event_service.subscribe_to_events(TestSubscriber())

        assert len(received_events) == 1
        event = received_events[0]
        assert isinstance(event, ConversationStateUpdateEvent)
        assert event.key == "execution_status"
        assert event.value == ConversationExecutionStatus.IDLE

    @pytest.mark.asyncio
    async def test_slow_subscriber_does_not_block_lock(
        self, event_service, mock_conversation_with_real_lock
    ):
        """Test that a slow subscriber doesn't hold the lock during I/O.

        This test verifies that the lock is released before the async send
        operation, allowing other operations to proceed even if a subscriber
        is slow.
        """
        event_service._conversation = mock_conversation_with_real_lock
        state = mock_conversation_with_real_lock._state
        lock_held_during_sleep = False

        class SlowSubscriber(Subscriber[Event]):
            async def __call__(self, event: Event):
                nonlocal lock_held_during_sleep
                # Check if lock is held during the async operation
                # If the fix is correct, the lock should NOT be held here
                lock_held_during_sleep = state._lock.locked()
                await asyncio.sleep(0.1)  # Simulate slow I/O

        slow_subscriber = SlowSubscriber()

        # Subscribe with the slow subscriber
        await asyncio.wait_for(
            event_service.subscribe_to_events(slow_subscriber),
            timeout=2.0,
        )

        # The lock should NOT be held during the async sleep
        # (it's released before the await subscriber() call)
        assert not lock_held_during_sleep, (
            "Lock should not be held during async subscriber call"
        )

    @pytest.mark.asyncio
    async def test_subscription_snapshot_wait_does_not_block_event_loop(
        self, event_service, mock_conversation_with_real_lock
    ):
        """Creating the initial state snapshot must not stall the async loop.

        A reconnecting WebSocket subscriber takes an initial state snapshot before
        the subscription starts streaming events. If snapshot creation waits on the
        conversation's synchronous FIFOLock, it must do so in a worker thread; if
        it blocks in the async task, the whole server loop stops answering liveness
        probes.
        """
        event_service._conversation = mock_conversation_with_real_lock

        original_snapshot = event_service._create_state_update_event_sync
        release_snapshot = threading.Event()
        timings: dict[str, float] = {}

        def blocking_snapshot() -> ConversationStateUpdateEvent:
            timings["snapshot_start"] = time.monotonic()
            release_snapshot.wait(timeout=1.0)
            timings["snapshot_end"] = time.monotonic()
            return original_snapshot()

        event_service._create_state_update_event_sync = blocking_snapshot

        def release_after_delay() -> None:
            time.sleep(0.2)
            release_snapshot.set()

        threading.Thread(target=release_after_delay, daemon=True).start()

        class TestSubscriber(Subscriber[Event]):
            async def __call__(self, event: Event):
                return None

        async def heartbeat() -> None:
            await asyncio.sleep(0.05)
            timings["heartbeat"] = time.monotonic()

        await asyncio.wait_for(
            asyncio.gather(
                event_service.subscribe_to_events(TestSubscriber()),
                heartbeat(),
            ),
            timeout=1.0,
        )

        assert "snapshot_end" in timings
        assert "heartbeat" in timings
        assert timings["heartbeat"] < timings["snapshot_end"], (
            "subscribe_to_events blocked the async loop while waiting for the "
            "state snapshot lock"
        )

    @pytest.mark.asyncio
    async def test_subscription_during_state_update(
        self, event_service, mock_conversation_with_real_lock
    ):
        """Test that subscriptions and state updates can interleave without deadlock.

        This test simulates a scenario where a subscription happens while
        a state update is being published, verifying no deadlock occurs.
        """
        event_service._conversation = mock_conversation_with_real_lock
        events_received: list[Event] = []

        class CollectorSubscriber(Subscriber[Event]):
            async def __call__(self, event: Event):
                events_received.append(event)
                # Simulate some async work
                await asyncio.sleep(0.01)

        # First, subscribe a collector
        collector = CollectorSubscriber()
        await event_service.subscribe_to_events(collector)

        # Now trigger a state update while potentially another subscription happens
        async def subscribe_new():
            new_subscriber = CollectorSubscriber()
            return await event_service.subscribe_to_events(new_subscriber)

        async def publish_update():
            await event_service._publish_state_update()

        # Run both concurrently - this should not deadlock
        results = await asyncio.wait_for(
            asyncio.gather(subscribe_new(), publish_update(), return_exceptions=True),
            timeout=2.0,
        )

        # Verify no exceptions occurred
        for result in results:
            if isinstance(result, Exception):
                pytest.fail(f"Unexpected exception: {result}")

    @pytest.mark.asyncio
    async def test_multiple_state_updates_with_slow_subscribers(
        self, event_service, mock_conversation_with_real_lock
    ):
        """Test multiple rapid state updates with slow subscribers don't deadlock.

        This test verifies that even with slow subscribers, multiple state
        updates can be processed without the lock causing contention issues.
        """
        event_service._conversation = mock_conversation_with_real_lock
        events_received: list[Event] = []

        class SlowCollectorSubscriber(Subscriber[Event]):
            async def __call__(self, event: Event):
                events_received.append(event)
                await asyncio.sleep(0.05)  # Simulate slow processing

        # Subscribe a slow collector
        slow_collector = SlowCollectorSubscriber()
        await event_service.subscribe_to_events(slow_collector)

        # Clear the initial state event
        events_received.clear()

        # Trigger multiple state updates rapidly
        async def rapid_updates():
            for _ in range(5):
                await event_service._publish_state_update()

        # This should complete without deadlock
        await asyncio.wait_for(rapid_updates(), timeout=5.0)

        # Verify all updates were received
        assert len(events_received) == 5, (
            f"Expected 5 events, got {len(events_received)}"
        )


class TestSearchEventsBlockedByRunLoop:
    """Reproduce: search_events blocks for the entire duration of agent.step().

    The run loop in LocalConversation.run() holds the FIFOLock on
    ConversationState for each iteration (including the LLM call and tool
    execution).  EventService._search_events_sync() acquires the *same* lock
    to iterate events, so it blocks until the step finishes.

    See HANG_REPRO.md for the full write-up.
    """

    @pytest.mark.asyncio
    async def test_search_events_not_blocked_by_state_lock(
        self, sample_stored_conversation
    ):
        """search_events must return promptly even while the run loop holds the lock.

        This simulates the real scenario: LocalConversation.run() holds
        ``_state`` (FIFOLock) for the entire agent step, while
        ``_search_events_sync`` tries to acquire the same lock in a
        thread-pool executor.

        The expected (fixed) behaviour is that the read path does NOT
        contend on the write lock, so search_events returns in well
        under a second regardless of how long the step takes.
        """
        service = EventService(
            stored=sample_stored_conversation,
            conversations_dir=Path("test_conversation_dir"),
        )

        conversation = MagicMock(spec=Conversation)
        state = MagicMock(spec=ConversationState)

        real_lock = FIFOLock()
        state._lock = real_lock
        state.__enter__ = lambda self: (real_lock.acquire(), self)[1]
        state.__exit__ = lambda self, *args: real_lock.release()
        state.events = [
            MessageEvent(id=f"evt-{i}", source="user", llm_message=Message(role="user"))
            for i in range(3)
        ]
        state.execution_status = ConversationExecutionStatus.RUNNING
        conversation._state = state
        service._conversation = conversation

        hold_seconds = 2.0
        lock_acquired = threading.Event()

        def hold_lock_like_run_loop():
            """Simulate LocalConversation.run() holding the lock during step."""
            with state:
                lock_acquired.set()
                time.sleep(hold_seconds)

        # Start the "run loop" thread that holds the lock
        run_thread = threading.Thread(target=hold_lock_like_run_loop, daemon=True)
        run_thread.start()
        lock_acquired.wait(timeout=5.0)

        # search_events should return quickly even though the lock is held
        t0 = time.monotonic()
        result = await service.search_events()
        elapsed = time.monotonic() - t0

        run_thread.join(timeout=5.0)

        # search_events returned correct data
        assert len(result.items) == 3

        # The critical assertion: search_events must NOT be blocked by the
        # run-loop's lock.  If it takes anywhere near hold_seconds, the read
        # path is still contending on the write lock (the bug in HANG_REPRO.md).
        max_acceptable = 0.5
        assert elapsed < max_acceptable, (
            f"search_events took {elapsed:.3f}s, but should return in "
            f"<{max_acceptable}s even while the run loop holds the state lock "
            f"for {hold_seconds}s.  The read path is blocked by the write lock "
            f"(see HANG_REPRO.md)."
        )


class _SyncOnlyAgent(AgentBase):
    """Agent that only implements sync step() (no astep override).

    Defined at module level (not inside a test) because ``AgentBase`` is a
    discriminated-union member and local classes cannot be registered.
    """

    def step(self, conversation, on_event, on_token=None):
        pass


class TestEventServiceClose:
    """Tests for EventService.close() awaiting conversation teardown."""

    @pytest.mark.asyncio
    async def test_close_awaits_conversation_close(self, event_service):
        """close() must await conversation.close(), not fire-and-forget."""
        conversation = MagicMock(spec=Conversation)
        event_service._conversation = conversation

        closed = asyncio.Event()

        def slow_close():
            # Simulate non-trivial teardown work
            time.sleep(0.05)
            closed.set()

        conversation.close = slow_close

        await event_service.close()

        assert closed.is_set(), (
            "EventService.close() returned before conversation.close() finished"
        )

    @pytest.mark.asyncio
    async def test_close_clears_conversation_reference(self, event_service):
        """close() must set _conversation to None after closing."""
        conversation = MagicMock()
        event_service._conversation = conversation

        await event_service.close()

        assert event_service._conversation is None

    @pytest.mark.asyncio
    async def test_close_is_idempotent(self, event_service):
        """Calling close() twice must not raise."""
        conversation = MagicMock()
        event_service._conversation = conversation

        await event_service.close()
        await event_service.close()  # second call — _conversation is already None

        conversation.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_exit_closes_after_meta_save_failure(self, event_service):
        event_service.save_meta = AsyncMock(side_effect=OSError("save failed"))
        event_service.close = AsyncMock()

        with pytest.raises(OSError, match="save failed"):
            await event_service.__aexit__(None, None, None)

        event_service.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_exit_prioritizes_credential_close_failure(self, event_service):
        event_service.save_meta = AsyncMock(side_effect=OSError("save failed"))
        event_service.close = AsyncMock(
            side_effect=CredentialSyncError("broker unavailable")
        )

        with pytest.raises(CredentialSyncError, match="broker unavailable"):
            await event_service.__aexit__(None, None, None)

    @pytest.mark.asyncio
    async def test_close_pauses_before_closing_conversation(self, event_service):
        """close() must pause an in-flight run before calling conversation.close().
        If close() ran first, the still-active run loop would race with executor
        teardown — closing MCP clients while a tool call is in flight."""
        conversation = MagicMock(spec=Conversation)
        call_order: list[str] = []

        def record_pause():
            call_order.append("pause")

        def record_close():
            call_order.append("close")

        conversation.pause = record_pause
        conversation.close = record_close
        event_service._conversation = conversation

        # Task is in-flight when close() inspects it, finishes during the await.
        async def fake_run():
            await asyncio.sleep(0.05)

        event_service._run_task = asyncio.create_task(fake_run())

        await event_service.close()

        assert call_order == ["pause", "close"], (
            f"Expected pause before close, got {call_order}"
        )
        assert event_service._run_task is None

    @pytest.mark.asyncio
    async def test_close_skips_pause_when_no_run_task(self, event_service):
        """close() must not call pause() when no run task is in flight."""
        conversation = MagicMock(spec=Conversation)
        conversation.pause = MagicMock()
        conversation.close = MagicMock()
        event_service._conversation = conversation
        event_service._run_task = None

        await event_service.close()

        conversation.pause.assert_not_called()
        conversation.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_proceeds_on_run_task_timeout(self, event_service, caplog):
        """If the run task does not finish within the timeout, close() logs
        and still proceeds. Server shutdown must not block on a hanging
        agent.step(): cancel-on-timeout only cancels the asyncio wrapper, not
        the underlying worker thread, so we accept that case as best-effort.
        Pause must still be attempted so the common case (step finishes
        promptly) stays clean."""
        conversation = MagicMock(spec=Conversation)
        conversation.pause = MagicMock()
        conversation.close = MagicMock()
        event_service._conversation = conversation

        async def hanging_run():
            await asyncio.sleep(60)

        hanging_task = asyncio.create_task(hanging_run())
        event_service._run_task = hanging_task

        try:
            with (
                caplog.at_level("WARNING"),
                patch(
                    "openhands.agent_server.event_service.asyncio.wait_for",
                    AsyncMock(side_effect=asyncio.TimeoutError),
                ),
            ):
                await event_service.close()
        finally:
            hanging_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, BaseException):
                await hanging_task

        conversation.pause.assert_called_once()
        assert "did not exit cleanly" in caplog.text
        assert event_service._run_task is None
        conversation.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_uses_executor_for_sync_only_conversation(self, event_service):
        """EventService.run() must use the thread-pool executor when the
        conversation only inherits the default BaseConversation.arun()
        (which delegates to sync run()).  This prevents sync-only
        subclasses from accidentally blocking the event loop."""
        from openhands.sdk.conversation.base import BaseConversation

        run_thread_id: int | None = None
        mock = MagicMock()

        # Concrete subclass that never overrides arun(); all abstract
        # methods are filled by a MagicMock delegate so we only test
        # the dispatch logic.
        class SyncOnlyConversation(BaseConversation):
            """Minimal subclass that only implements sync run()."""

            @property
            def id(self):
                return mock.id

            @property
            def state(self):
                return mock.state

            @property
            def conversation_stats(self):
                return mock.conversation_stats

            def send_message(self, message, sender=None):
                pass

            def run(self):
                nonlocal run_thread_id
                run_thread_id = threading.current_thread().ident

            def pause(self):
                pass

            def close(self):
                pass

            def set_confirmation_policy(self, policy):
                pass

            def set_security_analyzer(self, analyzer):
                pass

            def update_secrets(self, secrets):
                pass

            def reject_pending_actions(self, reason=""):
                pass

            def interrupt(self):
                pass

            def generate_title(self, llm=None, max_length=50):
                return ""

            def ask_agent(self, question):
                return ""

            def condense(self):
                pass

            def execute_tool(self, tool_name, action):
                return mock.execute_tool(tool_name, action)

            def fork(self, **kwargs):
                return mock.fork(**kwargs)

            def navigate_to(self, event_id):
                return mock.navigate_to(event_id)

        conv = SyncOnlyConversation()
        event_service._conversation = conv  # type: ignore[assignment]

        # Sanity: this conversation does NOT override arun()
        assert type(conv).arun is BaseConversation.arun

        # Bypass guards that access internal _state (not part of the
        # abstract interface) so we only test the dispatch logic.
        with (
            patch.object(
                type(event_service),
                "_get_execution_status",
                new_callable=AsyncMock,
                return_value=ConversationExecutionStatus.PAUSED,
            ),
            patch.object(
                type(event_service),
                "_publish_state_update",
                new_callable=AsyncMock,
            ),
        ):
            await event_service.run()
            # Give the background task a moment to execute
            await asyncio.sleep(0.3)

        event_loop_thread = threading.current_thread().ident
        assert run_thread_id is not None, "run() was never called"
        assert run_thread_id != event_loop_thread, (
            "run() executed on the event loop thread — expected thread-pool"
        )

    async def test_run_uses_executor_for_sync_only_agent(self, event_service):
        """EventService.run() must use the thread-pool executor when the
        agent only implements sync step() (no astep() override), even if the
        conversation overrides arun().  ``LocalConversation`` always overrides
        arun(), so the conversation-level guard alone would route sync-only
        custom agents through the native async path, running their sync
        step() in a worker thread while arun() holds the state lock on the
        event-loop thread (B5)."""
        from openhands.sdk.conversation.base import BaseConversation

        run_called = False
        arun_called = False
        agent = _SyncOnlyAgent(llm=LLM(model="gpt-4o", usage_id="sync-only"))

        # Stand-in conversation that overrides arun() (like LocalConversation)
        # but wraps a sync-only agent.  Only the dispatch-relevant members are
        # implemented.
        class AsyncConvSyncAgent:
            def __init__(self):
                self.agent = agent

            async def arun(self):
                nonlocal arun_called
                arun_called = True

            def run(self):
                nonlocal run_called
                run_called = True

        conv = AsyncConvSyncAgent()
        event_service._conversation = conv  # type: ignore[assignment]

        # Sanity: conversation overrides arun() but the agent inherits the
        # default astep(), so the native async path must NOT be taken.
        assert type(conv).arun is not BaseConversation.arun
        assert type(conv.agent).astep is AgentBase.astep

        with (
            patch.object(
                type(event_service),
                "_get_execution_status",
                new_callable=AsyncMock,
                return_value=ConversationExecutionStatus.PAUSED,
            ),
            patch.object(
                type(event_service),
                "_publish_state_update",
                new_callable=AsyncMock,
            ),
        ):
            await event_service.run()
            # Give the background task a moment to execute
            await asyncio.sleep(0.3)

        assert run_called, "sync run() was never called"
        assert not arun_called, (
            "arun() was used for a sync-only agent — expected sync run()"
        )


@pytest_asyncio.fixture
async def real_conversation_service(tmp_path):
    persist = tmp_path / "persist"
    persist.mkdir()
    service = ConversationService(conversations_dir=persist)
    async with service:
        yield service


class _WedgedSubscriber:
    """Models a WS client whose TCP send buffer is full."""

    def __init__(self) -> None:
        self.unblock = asyncio.Event()

    async def __call__(self, event):
        await self.unblock.wait()

    async def close(self) -> None:
        self.unblock.set()  # let PubSub.close() finish


@pytest.mark.timeout(15)
async def test_subscribe_to_events_does_not_deadlock_on_wedged_subscriber(
    real_conversation_service, tmp_path
):
    (tmp_path / "ws").mkdir()
    info = await start_conversation_with_test_llm(
        real_conversation_service,
        parent_llm=SlowTestLLM.from_messages([text_message("ok")], latency_s=0.0),
        workspace_dir=str(tmp_path / "ws"),
        usage_id="wedged-sub",
        initial_text=None,
    )
    es = await real_conversation_service.get_event_service(info.id)
    assert es is not None

    wedged = _WedgedSubscriber()
    try:
        await asyncio.wait_for(es.subscribe_to_events(wedged), timeout=1.0)
    except TimeoutError:
        pytest.fail("subscribe_to_events blocked > 1 s on a wedged subscriber.")
    finally:
        wedged.unblock.set()


@pytest.mark.timeout(45)
async def test_close_blocks_until_executor_thread_finishes(
    real_conversation_service, tmp_path, monkeypatch
):
    # close() cancels the _run_task then waits for it to settle.  With the
    # native arun() path the task handles CancelledError and transitions to
    # PAUSED quickly.  We verify close() returns promptly (the cancellation
    # machinery works) and that the task is properly cleaned up.
    (tmp_path / "ws").mkdir()
    parent_llm = SlowTestLLM.from_messages(
        [text_message("done")],
        latency_s=12.0,  # > the 10 s wait_for in close()
    )
    info = await start_conversation_with_test_llm(
        real_conversation_service,
        parent_llm=parent_llm,
        workspace_dir=str(tmp_path / "ws"),
        usage_id="close-race",
        initial_text=None,
    )
    es = await real_conversation_service.get_event_service(info.id)
    assert es is not None

    await es.send_message(
        Message(role="user", content=[TextContent(text="long step")]),
        run=False,
    )
    await es.run()
    await asyncio.sleep(0.5)

    def _broken():
        raise RuntimeError("pause/close unavailable")

    conv = es.get_conversation()
    monkeypatch.setattr(conv, "pause", _broken)
    monkeypatch.setattr(conv, "close", _broken)

    close_start = time.monotonic()
    with contextlib.suppress(Exception):
        await es.close()
    close_elapsed = time.monotonic() - close_start

    # close() should return well before the 12 s LLM latency because
    # it cancels the arun() task, which handles CancelledError and
    # transitions to PAUSED.  Allow a generous margin for CI but ensure
    # it did not block the full 12 s.
    assert close_elapsed < 11.0, (
        f"close() took {close_elapsed:.1f}s — expected fast cancellation"
    )

    monkeypatch.undo()


class TestStatsCallbackNoDeadlock:
    """Regression: stats_callback must not re-acquire the state lock.

    ``Telemetry._stats_update_callback`` is invoked synchronously from
    inside the LLM completion / ACP turn pipeline while another thread
    (``LocalConversation.run()``) holds the conversation state's
    ``FIFOLock`` via ``with self._state:``.

    Empirically the deadlock is **cross-thread**: the FIFOLock's
    same-thread reentry works fine (verified in
    ``test_same_thread_reentry_works_on_fifolock``), but when the
    callback fires on a different thread than the lock owner, the
    extra ``with state:`` inside the callback waits forever.  That is
    what hung every short-text ACP conversation before this fix.

    These tests pin the contract: the callback returns promptly and
    the stats event is queued for emission regardless of which thread
    owns the lock.
    """

    def _make_service_with_callback(self):
        stored = StoredConversation(
            id=uuid4(),
            workspace=LocalWorkspace(working_dir="workspace/project"),
            confirmation_policy=NeverConfirm(),
            initial_message=None,
            metrics=None,
            created_at=datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC),
            updated_at=datetime(2025, 1, 1, 12, 30, 0, tzinfo=UTC),
        )
        service = EventService(
            stored=stored,
            agent=Agent(llm=LLM(model="gpt-4o", usage_id="test-stats"), tools=[]),
            conversations_dir=Path("test_conversation_dir"),
        )
        # A real FIFOLock on a Mock-ish state so the callback contends on
        # the actual production lock primitive, but we don't have to spin
        # up the LocalConversation event loop / persistence stack to
        # exercise the deadlock.
        state = MagicMock()
        state._lock = FIFOLock()
        state.__enter__ = MagicMock(side_effect=lambda: state._lock.acquire())
        state.__exit__ = MagicMock(side_effect=lambda *a: state._lock.release())
        state.stats = MagicMock(name="stats")

        conversation = MagicMock()
        conversation._state = state
        service._conversation = conversation
        # Stub the executor-thread emission path so the test stays
        # synchronous + deterministic.  The under-test behaviour is just
        # ``stats_callback returns promptly``; the locked_on_event side of
        # _emit_event_from_thread is covered elsewhere.
        service._emit_event_from_thread = MagicMock(name="_emit_event_from_thread")

        callbacks: list = []
        service._setup_stats_streaming(
            MagicMock(
                get_all_llms=lambda: [
                    MagicMock(
                        telemetry=MagicMock(set_stats_update_callback=callbacks.append)
                    )
                ]
            )
        )
        assert len(callbacks) == 1, "stats_callback must be registered exactly once"
        return service, state, callbacks[0]

    def test_same_thread_reentry_works_on_fifolock(self):
        """Sanity: FIFOLock's reentrancy contract holds for same-thread re-acquire.

        Documents why the fix is **not** about masking a broken reentrant
        lock — even with the buggy ``with state:`` re-entry, the same
        thread can re-acquire FIFOLock without deadlock.  This isolates
        the deadlock as a cross-thread phenomenon (see the next test).
        """
        lock = FIFOLock()
        finished = threading.Event()

        def run():
            with lock:
                with lock:  # same-thread re-entry
                    pass
            finished.set()

        threading.Thread(target=run, daemon=True).start()
        assert finished.wait(timeout=2.0), "FIFOLock should support same-thread reentry"

    @pytest.mark.timeout(10)
    def test_returns_promptly_when_another_thread_holds_state_lock(self):
        """The deadlock case: another thread owns the lock when the callback fires.

        Mirrors production: ``LocalConversation.run()`` on thread A holds
        ``state``'s FIFOLock via ``with self._state:``; the stats callback
        fires on a different thread (executor / portal / bridge) and would
        re-acquire the lock with ``with state:`` — blocking forever because
        FIFOLock's reentrancy gates on ``threading.get_ident()`` and thread
        B's ident is not the owner.

        Pre-fix this test hangs forever and the pytest timeout cap fires.
        Post-fix the callback no longer re-acquires the lock and returns
        immediately, with the stats event handed to ``_emit_event_from_thread``
        for serialization once thread A eventually releases the lock.
        """
        service, state, stats_callback = self._make_service_with_callback()
        lock_acquired = threading.Event()
        callback_completed = threading.Event()
        release_lock = threading.Event()

        def thread_a_holds_lock():
            with state:
                lock_acquired.set()
                # Hold the lock until the callback thread has done its work
                # (or until the test times out, whichever comes first).
                release_lock.wait(timeout=5.0)

        def thread_b_invokes_callback():
            assert lock_acquired.wait(timeout=2.0), "thread A never took the lock"
            stats_callback()
            callback_completed.set()

        a = threading.Thread(target=thread_a_holds_lock, daemon=True)
        b = threading.Thread(target=thread_b_invokes_callback, daemon=True)
        a.start()
        b.start()
        try:
            assert callback_completed.wait(timeout=2.0), (
                "stats_callback hung — thread A still holds the FIFOLock "
                "and the callback's `with state:` is blocking on it. "
                "Restore the fix that removes the redundant lock acquire."
            )
            emit_mock = cast(MagicMock, service._emit_event_from_thread)
            emit_mock.assert_called_once()
        finally:
            release_lock.set()
            a.join(timeout=2.0)
            b.join(timeout=2.0)

    def test_returns_promptly_with_no_lock_contention(self):
        """Baseline: callback returns and emit is scheduled when nothing is held."""
        service, _state, stats_callback = self._make_service_with_callback()
        finished = threading.Event()

        def run():
            stats_callback()
            finished.set()

        threading.Thread(target=run, daemon=True).start()
        assert finished.wait(timeout=2.0), (
            "stats_callback did not return within 2s with no lock contention"
        )
        emit_mock = cast(MagicMock, service._emit_event_from_thread)
        emit_mock.assert_called_once()


@pytest.mark.timeout(30)
async def test_message_in_run_cleanup_tail_is_not_stranded(
    real_conversation_service, tmp_path, monkeypatch
):
    """A message that lands while a *finished* run is still in its
    ``wait_for_pending()`` cleanup tail must still be processed.

    Regression test for a stranded-message race: ``send_message(run=True)``
    suppresses run()'s ``conversation_already_running`` while ``_run_task`` is
    wrapping up, and without the re-arm in ``_run_and_publish`` nothing re-runs
    once the tail clears — so the message sits unprocessed until the next send.

    Not the in-flight case: ``LocalConversation.run`` deliberately keeps looping
    on FINISHED so a message arriving *during* a step is absorbed. The unguarded
    gap is strictly the post-run executor tail owned by ``_run_and_publish``.
    """
    (tmp_path / "ws").mkdir()
    # One scripted reply per user message; each is plain text (no tool calls)
    # so the agent finishes the turn immediately. ``_call_count`` tells us how
    # many turns actually ran.
    parent_llm = SlowTestLLM.from_messages(
        [text_message("reply one"), text_message("reply two")],
        latency_s=0.0,
    )
    info = await start_conversation_with_test_llm(
        real_conversation_service,
        parent_llm=parent_llm,
        workspace_dir=str(tmp_path / "ws"),
        usage_id="tail-strand",
        initial_text=None,
    )
    es = await real_conversation_service.get_event_service(info.id)
    assert es is not None and es._callback_wrapper is not None

    # Park every run in its wait_for_pending() tail until released. It runs in
    # a thread-pool worker, so block on a threading.Event there and signal
    # entry back to the test.
    entered_tail = threading.Event()
    release_tail = threading.Event()

    def _blocking_wait(timeout: float) -> None:
        entered_tail.set()
        release_tail.wait(timeout)

    monkeypatch.setattr(es._callback_wrapper, "wait_for_pending", _blocking_wait)

    # Turn 1: the agent answers "first", finishes (FINISHED), then the run
    # task parks in our blocking wait_for_pending().
    await es.send_message(
        Message(role="user", content=[TextContent(text="first")]), run=True
    )
    assert await asyncio.to_thread(entered_tail.wait, 10.0), (
        "first run never reached its wait_for_pending tail"
    )
    first_run_task = es._run_task
    assert first_run_task is not None
    assert parent_llm._call_count == 1
    assert await es._get_execution_status() == ConversationExecutionStatus.FINISHED

    # Turn 2 arrives DURING the tail: send_message appends it and resets the
    # terminal status to IDLE, then run() is rejected (task not done) and
    # suppressed. Nothing runs yet.
    await es.send_message(
        Message(role="user", content=[TextContent(text="second")]), run=True
    )
    assert parent_llm._call_count == 1, "second turn ran before the tail cleared?!"
    assert es._run_task is first_run_task, "a second run started concurrently"

    # Release the tail; the first run task finishes and clears _run_task.
    release_tail.set()
    await first_run_task

    # The second message must now get processed. Without the _run_and_publish
    # re-arm it is stranded (call_count stays 1, status stuck IDLE).
    deadline = time.monotonic() + 5.0
    while parent_llm._call_count < 2 and time.monotonic() < deadline:
        await asyncio.sleep(0.05)

    assert parent_llm._call_count == 2, (
        "second message was stranded — the agent never ran for it after the "
        f"first run's cleanup tail cleared (call_count={parent_llm._call_count}, "
        f"status={await es._get_execution_status()})"
    )


@pytest.mark.timeout(30)
async def test_run_false_message_in_cleanup_tail_is_not_run(
    real_conversation_service, tmp_path, monkeypatch
):
    """A run=False append landing in the cleanup tail must NOT be auto-run.

    Guards the explicit-intent contract behind the re-arm: send_message(
    run=False) appends without running, and _run_and_publish must not
    resurrect it just because send_message reset the terminal status to IDLE.
    """
    (tmp_path / "ws").mkdir()
    # Two scripted replies, but only the first turn should ever run.
    parent_llm = SlowTestLLM.from_messages(
        [text_message("reply one"), text_message("must not run")],
        latency_s=0.0,
    )
    info = await start_conversation_with_test_llm(
        real_conversation_service,
        parent_llm=parent_llm,
        workspace_dir=str(tmp_path / "ws"),
        usage_id="tail-run-false",
        initial_text=None,
    )
    es = await real_conversation_service.get_event_service(info.id)
    assert es is not None and es._callback_wrapper is not None

    entered_tail = threading.Event()
    release_tail = threading.Event()

    def _blocking_wait(timeout: float) -> None:
        entered_tail.set()
        release_tail.wait(timeout)

    monkeypatch.setattr(es._callback_wrapper, "wait_for_pending", _blocking_wait)

    # Turn 1 runs and parks in the wait_for_pending tail.
    await es.send_message(
        Message(role="user", content=[TextContent(text="first")]), run=True
    )
    assert await asyncio.to_thread(entered_tail.wait, 10.0), (
        "first run never reached its wait_for_pending tail"
    )
    first_run_task = es._run_task
    assert first_run_task is not None
    assert parent_llm._call_count == 1

    # Append a message with run=False during the tail: the caller explicitly
    # does NOT want a run. It resets the terminal status to IDLE but must not
    # set the re-run flag.
    await es.send_message(
        Message(role="user", content=[TextContent(text="just append")]), run=False
    )
    assert es._rerun_requested is False

    # Release the tail and let the run task settle; nothing should re-run.
    release_tail.set()
    await first_run_task
    await asyncio.sleep(0.3)  # give any erroneous re-arm a chance to fire

    assert parent_llm._call_count == 1, (
        "run=False append in the cleanup tail was unexpectedly run "
        f"(call_count={parent_llm._call_count})"
    )
    assert es._run_task is None


def test_emit_event_from_thread_uses_captured_loop(event_service: EventService) -> None:
    """_emit_event_from_thread must use the captured main_loop, not self._main_loop.

    Before this fix, the method captured _main_loop into a local variable for
    the if-check but then called self._main_loop.run_in_executor(...) in the
    body. A concurrent close() setting self._main_loop = None between the
    check and the call would cause AttributeError. The fix uses main_loop.
    """
    captured_calls: list = []

    mock_loop = MagicMock()
    mock_loop.is_running.return_value = True

    def record_and_null(*args, **kwargs):
        # Simulate concurrent close() nulling self._main_loop mid-call
        object.__setattr__(event_service, "_main_loop", None)
        captured_calls.append(args)

    mock_loop.run_in_executor.side_effect = record_and_null

    event_service._main_loop = mock_loop  # type: ignore[assignment]
    event_service._conversation = MagicMock()  # type: ignore[assignment]

    event = MagicMock()

    # Should not raise AttributeError even though self._main_loop is cleared
    event_service._emit_event_from_thread(event)
    assert len(captured_calls) == 1, "run_in_executor should have been called once"


def test_llm_log_callback_swallows_emit_failures(
    event_service: EventService, caplog
) -> None:
    callbacks = []
    llm = MagicMock(log_completions=True, usage_id="test-usage", model="gpt-4o")
    llm.telemetry.set_log_completions_callback.side_effect = callbacks.append

    object.__setattr__(
        event_service,
        "_emit_event_from_thread",
        MagicMock(side_effect=RuntimeError("emit failed")),
    )

    with caplog.at_level("ERROR"):
        event_service._setup_llm_log_streaming(MagicMock(get_all_llms=lambda: [llm]))
        callbacks[0]("completion.json", "{}")

    emit_mock = cast(MagicMock, event_service._emit_event_from_thread)
    emit_mock.assert_called_once()
    assert "Failed to emit LLM completion log event" in caplog.text


def _make_stored(tmp_path: Path) -> StoredConversation:
    return StoredConversation(
        id=uuid4(),
        workspace=LocalWorkspace(working_dir=str(tmp_path)),
        confirmation_policy=NeverConfirm(),
        initial_message=None,
        metrics=None,
    )


def _make_mock_conv() -> MagicMock:
    mock_conv = MagicMock()
    mock_state = MagicMock()
    mock_state.execution_status = ConversationExecutionStatus.IDLE
    mock_state.events = []
    mock_state.stats = MagicMock()
    mock_conv.agent.get_all_llms.return_value = []
    mock_conv._state = mock_state
    mock_conv.state = mock_state
    mock_conv._on_event = MagicMock()
    return mock_conv


@pytest.mark.asyncio
async def test_event_service_skips_lease_when_ttl_is_zero(tmp_path: Path) -> None:
    stored = _make_stored(tmp_path)
    service = EventService(
        stored=stored,
        agent=_sample_agent(),
        conversations_dir=tmp_path,
        lease_ttl_seconds=0,
    )
    with patch(
        "openhands.agent_server.event_service.LocalConversation",
        return_value=_make_mock_conv(),
    ):
        await service.start()

    assert service._lease is None
    assert not (tmp_path / stored.id.hex / LEASE_FILE_NAME).exists()


@pytest.mark.asyncio
async def test_event_service_creates_lease_with_custom_ttl(tmp_path: Path) -> None:
    stored = _make_stored(tmp_path)
    service = EventService(
        stored=stored,
        agent=_sample_agent(),
        conversations_dir=tmp_path,
        lease_ttl_seconds=10.0,
    )
    with patch(
        "openhands.agent_server.event_service.LocalConversation",
        return_value=_make_mock_conv(),
    ):
        await service.start()

    assert service._lease is not None
    assert service._lease._ttl_seconds == 10.0
    assert (tmp_path / stored.id.hex / LEASE_FILE_NAME).exists()


def _governance_pending_action(
    call_id: str = "call_1", *, command: str = "ls", summary: str | None = None
) -> ActionEvent:
    return ActionEvent(
        source="agent",
        thought=[TextContent(text="running a command")],
        action=TerminalAction(command=command),
        tool_name="terminal",
        tool_call_id=call_id,
        tool_call=MessageToolCall(
            id=call_id,
            name="terminal",
            arguments=json.dumps({"command": command}),
            origin="completion",
        ),
        llm_response_id="response_1",
        summary=summary,
    )


class _NoPreviewAction(Action):
    """What an MCP tool's action looks like to governance: not from a built-in
    package, so no projection exists for it."""

    query: str


def _governance_pending_other_action(
    tool_name: str, action: Action, call_id: str = "call_1"
) -> ActionEvent:
    return ActionEvent(
        source="agent",
        thought=[TextContent(text="calling a tool")],
        action=action,
        tool_name=tool_name,
        tool_call_id=call_id,
        tool_call=MessageToolCall(
            id=call_id, name=tool_name, arguments="{}", origin="completion"
        ),
        llm_response_id="response_1",
    )


class TestEventServiceGovernanceOrchestration:
    """Team-mode central-governance-api orchestration: the Phase B
    create-approval hook (``maybe_register_governance_approval`` /
    ``_create_governance_approval``) and the claim/run handshake
    (``run_and_wait_for_start`` / ``_claim_and_run_governed`` /
    ``_report_governance_failure``).
    """

    @pytest.fixture
    def governed_service(self, event_service, tmp_path):
        """team mode active, matching what ConversationService.get_instance()
        would snapshot from a validated Config onto every EventService it
        constructs (see event_service.py's governance_deployment_mode/
        governance_client/governance_origin_device_id fields) — these are
        plain instance attributes, not process environment variables, so
        tests set them directly rather than monkeypatching env vars or
        patching a module-level lookup function. governance_client stays
        unset here — tests that need one set
        `governed_service.governance_client = fake_client` directly.
        """
        event_service.conversations_dir = tmp_path
        event_service.conversation_dir.mkdir(parents=True, exist_ok=True)
        event_service.governance_deployment_mode = "team"
        event_service.governance_origin_device_id = "device-1"
        return event_service

    def _mock_conversation(self, pending_actions):
        conversation = MagicMock()
        state = MagicMock()
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        state.active_branch = MagicMock(return_value=list(pending_actions))
        conversation._state = state
        return conversation

    # ---------------- maybe_register_governance_approval ----------------

    @pytest.mark.asyncio
    async def test_maybe_register_noop_when_team_mode_inactive(self, event_service):
        event_service._conversation = self._mock_conversation(
            [_governance_pending_action()]
        )
        event_service._get_execution_status = AsyncMock(
            return_value=ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )
        await event_service.maybe_register_governance_approval()
        assert event_service.governance_outbox.load() is None

    @pytest.mark.asyncio
    async def test_maybe_register_noop_when_not_waiting_for_confirmation(
        self, governed_service
    ):
        governed_service._conversation = self._mock_conversation(
            [_governance_pending_action()]
        )
        governed_service._get_execution_status = AsyncMock(
            return_value=ConversationExecutionStatus.RUNNING
        )
        await governed_service.maybe_register_governance_approval()
        assert governed_service.governance_outbox.load() is None

    @pytest.mark.asyncio
    async def test_maybe_register_noop_when_outbox_already_exists(
        self, governed_service
    ):
        governed_service._conversation = self._mock_conversation(
            [_governance_pending_action()]
        )
        governed_service._get_execution_status = AsyncMock(
            return_value=ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )
        governed_service._create_governance_approval = AsyncMock()
        with patch(
            "openhands.agent_server.event_service.GovernanceOutbox.load",
            return_value=MagicMock(),
        ):
            await governed_service.maybe_register_governance_approval()
        governed_service._create_governance_approval.assert_not_called()

    @pytest.mark.asyncio
    async def test_maybe_register_retries_a_stuck_pending_create_for_the_same_action(
        self, governed_service
    ):
        """A create call interrupted mid-flight (crash, or close()
        cancelling the create task) leaves the outbox in PENDING_CREATE
        with no relay to ever move it forward on its own — this hook is
        the only retry path a stuck PENDING_CREATE has in this MVP slice,
        and it runs after every single run cycle including crash-recovery,
        so it must retry rather than treat "record already exists for this
        action" as unconditionally done."""
        action = _governance_pending_action()
        governed_service._conversation = self._mock_conversation([action])
        governed_service._get_execution_status = AsyncMock(
            return_value=ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )
        stuck_record = OutboxRecord(
            request_id="req-stuck",
            conversation_id=str(governed_service.stored.id),
            action_event_id=action.id,
            tool_call_id=action.tool_call_id,
            tool_name=action.tool_name,
            action_type="tool_call",
            policy_revision="agent-server-mvp-v1",
            action_summary="running a command",
            action_payload={},
            digest_salt="salt",
            action_payload_digest="digest",
            execution_commitment=compute_execution_commitment(
                action, str(governed_service.stored.id)
            ),
            origin_device_id="device-1",
            state=OutboxState.PENDING_CREATE,
        )
        await governed_service.governance_outbox.create_record(stuck_record)
        governed_service._create_governance_approval = AsyncMock()
        governed_service._send_create_approval = AsyncMock()

        await governed_service.maybe_register_governance_approval()
        await asyncio.sleep(0)

        governed_service._send_create_approval.assert_called_once()
        (called_record,) = governed_service._send_create_approval.call_args.args
        assert called_record.request_id == "req-stuck"
        governed_service._create_governance_approval.assert_not_called()

    @pytest.mark.asyncio
    async def test_maybe_register_noop_when_pending_count_not_one(
        self, governed_service
    ):
        governed_service._conversation = self._mock_conversation([])
        governed_service._get_execution_status = AsyncMock(
            return_value=ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )
        governed_service._create_governance_approval = AsyncMock()
        await governed_service.maybe_register_governance_approval()
        governed_service._create_governance_approval.assert_not_called()

    @pytest.mark.asyncio
    async def test_maybe_register_schedules_create_for_single_pending_action(
        self, governed_service
    ):
        action = _governance_pending_action()
        governed_service._conversation = self._mock_conversation([action])
        governed_service._get_execution_status = AsyncMock(
            return_value=ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )
        governed_service._create_governance_approval = AsyncMock()

        await governed_service.maybe_register_governance_approval()
        # _create_governance_approval is scheduled via asyncio.create_task —
        # give the loop a tick to actually run it.
        await asyncio.sleep(0)

        governed_service._create_governance_approval.assert_called_once_with(action)

    @pytest.mark.asyncio
    async def test_maybe_register_tracks_create_task_until_it_completes(
        self, governed_service
    ):
        """The fire-and-forget task must be visible to close()/idle
        eviction while in flight, and drop out again once it settles —
        otherwise close() has no way to cancel-and-drain it and a long-
        idle conversation with a stuck create call could never be evicted.
        """
        action = _governance_pending_action()
        governed_service._conversation = self._mock_conversation([action])
        governed_service._get_execution_status = AsyncMock(
            return_value=ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )
        release = asyncio.Event()

        async def _slow_create(_action):
            await release.wait()

        governed_service._create_governance_approval = AsyncMock(
            side_effect=_slow_create
        )

        await governed_service.maybe_register_governance_approval()
        await asyncio.sleep(0)

        assert len(governed_service._pending_governance_create_tasks) == 1

        release.set()
        (task,) = governed_service._pending_governance_create_tasks
        await task

        assert governed_service._pending_governance_create_tasks == set()

    @pytest.mark.asyncio
    async def test_maybe_register_archives_terminal_record_for_a_new_action(
        self, governed_service
    ):
        """A conversation must be governable more than once over its
        lifetime — after the first governed action reaches a terminal
        state, the next WAITING_FOR_CONFIRMATION round (a *different*
        action) must get its own approval, not be silently skipped
        forever."""
        old_action = _governance_pending_action(call_id="call_1")
        await governed_service.governance_outbox.create_record(
            OutboxRecord(
                request_id="req-old",
                conversation_id=str(governed_service.stored.id),
                action_event_id=old_action.id,
                tool_call_id=old_action.tool_call_id,
                tool_name=old_action.tool_name,
                action_type="tool_call",
                policy_revision="agent-server-mvp-v1",
                action_summary="old action",
                action_payload={},
                digest_salt="salt",
                action_payload_digest="digest",
                execution_commitment="commitment",
                origin_device_id="device-1",
                state=OutboxState.RESULT_REPORTED,
                central_approval_id="approval-old",
            )
        )

        new_action = _governance_pending_action(call_id="call_2")
        governed_service._conversation = self._mock_conversation([new_action])
        governed_service._get_execution_status = AsyncMock(
            return_value=ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )
        governed_service._create_governance_approval = AsyncMock()

        await governed_service.maybe_register_governance_approval()
        await asyncio.sleep(0)

        governed_service._create_governance_approval.assert_called_once_with(new_action)
        # The old, terminal record was archived (moved aside), not deleted.
        archived = list(
            governed_service.conversation_dir.glob(".governance_outbox.req-old.*.json")
        )
        assert len(archived) == 1

    @pytest.mark.asyncio
    async def test_maybe_register_does_not_duplicate_for_the_same_action(
        self, governed_service
    ):
        """Idempotent: if the outbox already tracks this exact action
        (whatever its state), don't create a second one for it."""
        action = _governance_pending_action()
        await governed_service.governance_outbox.create_record(
            OutboxRecord(
                request_id="req-1",
                conversation_id=str(governed_service.stored.id),
                action_event_id=action.id,
                tool_call_id=action.tool_call_id,
                tool_name=action.tool_name,
                action_type="tool_call",
                policy_revision="agent-server-mvp-v1",
                action_summary="an action",
                action_payload={},
                digest_salt="salt",
                action_payload_digest="digest",
                execution_commitment="commitment",
                origin_device_id="device-1",
                state=OutboxState.CREATED,
                central_approval_id="approval-1",
            )
        )

        governed_service._conversation = self._mock_conversation([action])
        governed_service._get_execution_status = AsyncMock(
            return_value=ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )
        governed_service._create_governance_approval = AsyncMock()

        await governed_service.maybe_register_governance_approval()
        await asyncio.sleep(0)

        governed_service._create_governance_approval.assert_not_called()

    @pytest.mark.asyncio
    async def test_maybe_register_fails_closed_for_a_different_nonterminal_action(
        self, governed_service
    ):
        """If the outbox tracks a *different*, still-active workflow, this
        is an unexpected state (the MVP only ever governs one action at a
        time) — fail closed rather than guessing or overwriting it."""
        active_action = _governance_pending_action(call_id="call_1")
        await governed_service.governance_outbox.create_record(
            OutboxRecord(
                request_id="req-active",
                conversation_id=str(governed_service.stored.id),
                action_event_id=active_action.id,
                tool_call_id=active_action.tool_call_id,
                tool_name=active_action.tool_name,
                action_type="tool_call",
                policy_revision="agent-server-mvp-v1",
                action_summary="active action",
                action_payload={},
                digest_salt="salt",
                action_payload_digest="digest",
                execution_commitment="commitment",
                origin_device_id="device-1",
                state=OutboxState.CLAIMED,
                central_approval_id="approval-active",
            )
        )

        other_action = _governance_pending_action(call_id="call_2")
        governed_service._conversation = self._mock_conversation([other_action])
        governed_service._get_execution_status = AsyncMock(
            return_value=ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )
        governed_service._create_governance_approval = AsyncMock()

        await governed_service.maybe_register_governance_approval()
        await asyncio.sleep(0)

        governed_service._create_governance_approval.assert_not_called()
        # The still-active record is untouched, not archived.
        record = governed_service.governance_outbox.load()
        assert record is not None
        assert record.request_id == "req-active"

    # ---------------- _create_governance_approval ----------------

    @pytest.mark.asyncio
    async def test_create_governance_approval_noop_without_client_config(
        self, event_service, tmp_path
    ):
        """Team mode with incomplete GovernanceClient env config must not
        silently pretend to succeed — it should leave no outbox record
        behind for a relay to find later."""
        event_service.conversations_dir = tmp_path
        await event_service._create_governance_approval(_governance_pending_action())
        assert event_service.governance_outbox.load() is None

    async def _drain_wait_for_decision_task(self, governed_service) -> None:
        """CREATE succeeding always starts _wait_for_decision_task (see
        _send_create_approval's own call site) — tests that only care
        about the create call itself, not Phase E's follow-on long-poll,
        cancel-and-drain it the same way close() does, rather than leaving
        an orphaned task (whose own client.wait() call would hit an
        un-mocked MagicMock attribute and swallow a TypeError into a 30s
        sleep-then-retry) alive past the test."""
        task = governed_service._wait_for_decision_task
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    @pytest.mark.asyncio
    async def test_create_governance_approval_success_updates_outbox(
        self, governed_service
    ):
        fake_client = MagicMock()
        fake_client.create_approval = AsyncMock(return_value={"id": "approval-123"})
        governed_service.governance_client = fake_client
        await governed_service._create_governance_approval(_governance_pending_action())

        record = governed_service.governance_outbox.load()
        assert record is not None
        assert record.state == OutboxState.CREATED
        assert record.central_approval_id == "approval-123"
        fake_client.create_approval.assert_awaited_once()
        _, kwargs = fake_client.create_approval.call_args
        assert kwargs["idempotency_key"] == f"create-{record.request_id}"
        await self._drain_wait_for_decision_task(governed_service)

    @pytest.mark.asyncio
    async def test_create_governance_approval_never_sends_raw_canonical_payload(
        self, governed_service
    ):
        """The canonical tool-call payload (may contain shell commands,
        file contents, secrets) must never leave this device — central
        receives exactly the bounded, redacted projection from
        governance_display, never the whole command. execution_commitment is
        exempt: it's a local-only SHA-256, never transmitted in cleartext
        form."""
        command = "echo " + "A" * 1000
        action = _governance_pending_action(command=command)
        fake_client = MagicMock()
        fake_client.create_approval = AsyncMock(return_value={"id": "approval-123"})
        governed_service.governance_client = fake_client
        # This command is long on purpose, to see what central receives when a
        # truncated action *is* sent. By default such an action is refused and
        # never sent (see test_truncated_action_is_refused_instead_of_...).
        governed_service.governance_refuse_truncated_actions = False
        await governed_service._create_governance_approval(action)

        (body,), kwargs = fake_client.create_approval.call_args
        projection = build_display(action)
        assert body["action_summary"] == projection.summary
        assert body["action_payload"] == projection.payload
        assert body["policy_revision"] == POLICY_REVISION
        assert command not in json.dumps(body)
        assert body["action_payload"]["truncated"] is True
        # Central re-verifies this digest from the fields it receives; they
        # must reproduce it exactly — including the execution commitment,
        # which the digest now covers.
        assert body["action_payload_digest"] == compute_display_digest(
            action_type=body["action_type"],
            tool_name=body["tool_name"],
            policy_revision=body["policy_revision"],
            action_summary=body["action_summary"],
            action_payload=body["action_payload"],
            digest_salt=body["digest_salt"],
            execution_commitment=body["execution_commitment"],
        )
        # The commitment is an HMAC under a per-record key that stays here:
        # central must be able to hold the value but never the key.
        record = governed_service.governance_outbox.load()
        assert record.commitment_key
        assert record.commitment_key not in json.dumps(body)
        assert body["execution_commitment"] == record.execution_commitment
        await self._drain_wait_for_decision_task(governed_service)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "summary",
        [
            # What the SDK auto-generates when the LLM leaves `summary` empty:
            # the tool name plus ALL raw arguments.
            "terminal: {\"command\": \"curl -H 'Authorization: Bearer sk-FAKE-1' x\"}",
            # What an LLM (or an injected prompt) may claim instead.
            "running unit tests to verify the fix",
            None,
        ],
        ids=["sdk-fallback-with-raw-args", "llm-claim", "no-summary"],
    )
    async def test_create_governance_approval_summary_never_carries_raw_args(
        self, governed_service, summary
    ):
        """Why: ActionEvent.summary is either the SDK's auto-generated
        "{tool}: {every raw argument}" or an unverified LLM claim. Sending
        it as the summary leaked commands/file contents/tokens to central (and
        let a prompt-injected LLM mislabel a dangerous command). The summary
        central shows is now built from the action itself; the LLM's text only
        survives as a redacted claim explicitly marked untrusted, and the SDK
        fallback is dropped."""
        action = _governance_pending_action(
            command="curl -H 'Authorization: Bearer sk-FAKE-1' x", summary=summary
        )
        fake_client = MagicMock()
        fake_client.create_approval = AsyncMock(return_value={"id": "approval-123"})
        governed_service.governance_client = fake_client
        await governed_service._create_governance_approval(action)

        (body,), _ = fake_client.create_approval.call_args
        assert "sk-FAKE-1" not in json.dumps(body)
        # Derived from the real command, not from the LLM's words.
        assert body["action_summary"].startswith("terminal: curl")
        assert "unit tests" not in body["action_summary"]
        claim = body["action_payload"].get("agent_claim")
        if summary == "running unit tests to verify the fix":
            assert claim == {"text": summary, "trusted": False}
        else:
            assert claim is None
        await self._drain_wait_for_decision_task(governed_service)

    @pytest.mark.asyncio
    async def test_create_governance_approval_leaves_pending_on_api_failure(
        self, governed_service
    ):
        fake_client = MagicMock()
        fake_client.create_approval = AsyncMock(side_effect=RuntimeError("boom"))
        governed_service.governance_client = fake_client
        await governed_service._create_governance_approval(_governance_pending_action())

        record = governed_service.governance_outbox.load()
        assert record is not None
        assert record.state == OutboxState.PENDING_CREATE
        assert record.central_approval_id is None

    # ---------------- run_and_wait_for_start ----------------

    @pytest.mark.asyncio
    async def test_run_and_wait_for_start_raises_without_matching_outbox(
        self, event_service, tmp_path
    ):
        event_service.conversations_dir = tmp_path
        with pytest.raises(ValueError, match="no governance outbox"):
            await event_service.run_and_wait_for_start(central_approval_id="approval-1")

    @pytest.mark.asyncio
    async def test_run_and_wait_for_start_refuses_a_new_handshake_while_closing(
        self, governed_service
    ):
        """A handshake created after close() has started would never be
        captured by close()'s own (already-run) handshake snapshot step —
        its claim would go completely unreconciled by this shutdown.
        Mirrors run()'s own _closing check."""
        action = _governance_pending_action()
        record = OutboxRecord(
            request_id="req-1",
            conversation_id=str(governed_service.stored.id),
            action_event_id=action.id,
            tool_call_id=action.tool_call_id,
            tool_name=action.tool_name,
            action_type="tool_call",
            policy_revision="agent-server-mvp-v1",
            action_summary="running a command",
            action_payload={},
            digest_salt="salt",
            action_payload_digest="digest",
            execution_commitment=compute_execution_commitment(
                action, str(governed_service.stored.id)
            ),
            origin_device_id="device-1",
            state=OutboxState.CREATED,
            central_approval_id="approval-1",
        )
        await governed_service.governance_outbox.create_record(record)
        governed_service._closing = True

        with pytest.raises(ValueError, match="inactive_service"):
            await governed_service.run_and_wait_for_start(
                central_approval_id="approval-1"
            )

        assert governed_service._active_governance_handshake is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "terminal_state",
        [
            OutboxState.RESULT_REPORTED,
            OutboxState.RECONCILIATION_REPORTED,
            OutboxState.CANCELLED,
        ],
    )
    async def test_run_and_wait_for_start_refuses_to_restart_a_finished_approval(
        self, governed_service, terminal_state
    ):
        """No handshake is in memory (fresh process, or a different one is
        active), so only the outbox says anything about this approval. A
        finished approval must not enter the claim flow again: doing so would
        overwrite the terminal audit state and let a consumed approval drive
        a new execution."""
        await self._create_outbox_record(governed_service, state=terminal_state)
        fake_client = MagicMock()
        fake_client.claim = AsyncMock()
        governed_service.governance_client = fake_client
        governed_service.run = AsyncMock()

        with pytest.raises(ActionBindingMismatchError, match="already finished"):
            await governed_service.run_and_wait_for_start(
                central_approval_id="approval-1", timeout_seconds=5.0
            )

        fake_client.claim.assert_not_awaited()
        governed_service.run.assert_not_awaited()
        assert governed_service._active_governance_handshake is None
        record = governed_service.governance_outbox.load()
        assert record is not None and record.state == terminal_state

    @pytest.mark.asyncio
    async def test_run_and_wait_for_start_returns_started_on_success(
        self, governed_service
    ):
        action = _governance_pending_action()
        record = OutboxRecord(
            request_id="req-1",
            conversation_id=str(governed_service.stored.id),
            action_event_id=action.id,
            tool_call_id=action.tool_call_id,
            tool_name=action.tool_name,
            action_type="tool_call",
            policy_revision="agent-server-mvp-v1",
            action_summary="running a command",
            action_payload={},
            digest_salt="salt",
            action_payload_digest="digest",
            execution_commitment=compute_execution_commitment(
                action, str(governed_service.stored.id)
            ),
            origin_device_id="device-1",
            state=OutboxState.CREATED,
            central_approval_id="approval-1",
        )
        await governed_service.governance_outbox.create_record(record)

        fake_client = MagicMock()
        fake_client.claim = AsyncMock(
            return_value={
                "execution_attempt_id": "attempt-1",
                "executing_lease_expires_at": "2099-01-01T00:00:00+00:00",
            }
        )

        async def _fake_run(*, expected_binding, on_governed_start, **_kwargs):
            # Matches real EventService.run() timing: it only *schedules*
            # the actual run and returns almost immediately, well before
            # on_governed_start/on_governed_reject fire. Calling the
            # callback synchronously here instead would mask a
            # premature-resolution bug: a bare `finally` in
            # _claim_and_run_governed()'s cancellation handling would
            # resolve the handshake to REJECTED_CANCELLED as soon as this
            # coroutine returned, before the deferred callback ever got a
            # chance to run.
            asyncio.get_running_loop().call_soon(on_governed_start)

        governed_service.run = AsyncMock(side_effect=_fake_run)

        governed_service.governance_client = fake_client
        outcome = await governed_service.run_and_wait_for_start(
            central_approval_id="approval-1", timeout_seconds=5.0
        )

        assert outcome == GovernanceStartOutcome.STARTED
        # on_governed_start's own EXECUTION_STARTED mutate is scheduled via
        # call_soon_threadsafe -> create_task (see that closure's own
        # comment for why this is best-effort, not synchronous with the
        # binding check) — give the loop a couple of turns and drain the
        # tracked fire-and-forget task before asserting on-disk state,
        # rather than relying on incidental ordering.
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        if governed_service._pending_governance_report_tasks:
            await asyncio.gather(*governed_service._pending_governance_report_tasks)
        updated = governed_service.governance_outbox.load()
        assert updated is not None
        assert updated.state == OutboxState.EXECUTION_STARTED
        assert updated.execution_attempt_id == "attempt-1"

        # A retried call for the exact same binding (e.g. central replaying
        # create/claim with the same idempotency key, or any other caller
        # retry) must replay the already-settled STARTED outcome, not
        # dispatch a second claim/run attempt — an already-consumed
        # approval must not become a replayable execution credential.
        second_outcome = await governed_service.run_and_wait_for_start(
            central_approval_id="approval-1", timeout_seconds=5.0
        )
        assert second_outcome == GovernanceStartOutcome.STARTED
        fake_client.claim.assert_awaited_once()
        governed_service.run.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_run_and_wait_for_start_rejects_mismatched_approval_id(
        self, governed_service
    ):
        action = _governance_pending_action()
        record = OutboxRecord(
            request_id="req-1",
            conversation_id=str(governed_service.stored.id),
            action_event_id=action.id,
            tool_call_id=action.tool_call_id,
            tool_name=action.tool_name,
            action_type="tool_call",
            policy_revision="agent-server-mvp-v1",
            action_summary="running a command",
            action_payload={},
            digest_salt="salt",
            action_payload_digest="digest",
            execution_commitment=compute_execution_commitment(
                action, str(governed_service.stored.id)
            ),
            origin_device_id="device-1",
            state=OutboxState.CREATED,
            central_approval_id="approval-1",
        )
        await governed_service.governance_outbox.create_record(record)

        with pytest.raises(ValueError, match="no governance outbox record matches"):
            await governed_service.run_and_wait_for_start(
                central_approval_id="some-other-approval"
            )

    @pytest.mark.asyncio
    async def test_run_and_wait_for_start_times_out_to_pending_unknown(
        self, governed_service
    ):
        action = _governance_pending_action()
        record = OutboxRecord(
            request_id="req-1",
            conversation_id=str(governed_service.stored.id),
            action_event_id=action.id,
            tool_call_id=action.tool_call_id,
            tool_name=action.tool_name,
            action_type="tool_call",
            policy_revision="agent-server-mvp-v1",
            action_summary="running a command",
            action_payload={},
            digest_salt="salt",
            action_payload_digest="digest",
            execution_commitment=compute_execution_commitment(
                action, str(governed_service.stored.id)
            ),
            origin_device_id="device-1",
            state=OutboxState.CREATED,
            central_approval_id="approval-1",
        )
        await governed_service.governance_outbox.create_record(record)

        never_resolves: asyncio.Future = asyncio.get_running_loop().create_future()

        async def _hang_forever(*_args, **_kwargs):
            await never_resolves

        governed_service._claim_and_run_governed = AsyncMock(side_effect=_hang_forever)

        outcome = await governed_service.run_and_wait_for_start(
            central_approval_id="approval-1", timeout_seconds=0.05
        )
        assert outcome == GovernanceStartOutcome.PENDING_UNKNOWN
        never_resolves.cancel()

    # ---------------- _claim_and_run_governed ----------------

    @pytest.mark.asyncio
    async def test_claim_and_run_governed_reports_claim_failure(self, governed_service):
        action = _governance_pending_action()
        record = OutboxRecord(
            request_id="req-1",
            conversation_id=str(governed_service.stored.id),
            action_event_id=action.id,
            tool_call_id=action.tool_call_id,
            tool_name=action.tool_name,
            action_type="tool_call",
            policy_revision="agent-server-mvp-v1",
            action_summary="running a command",
            action_payload={},
            digest_salt="salt",
            action_payload_digest="digest",
            execution_commitment=compute_execution_commitment(
                action, str(governed_service.stored.id)
            ),
            origin_device_id="device-1",
            state=OutboxState.CREATED,
            central_approval_id="approval-1",
        )
        await governed_service.governance_outbox.create_record(record)

        fake_client = MagicMock()
        fake_client.claim = AsyncMock(side_effect=RuntimeError("network down"))
        future: asyncio.Future = asyncio.get_running_loop().create_future()

        governed_service.governance_client = fake_client
        await governed_service._claim_and_run_governed(record, "approval-1", future)
        # _resolve_handshake_once schedules via call_soon_threadsafe —
        # pump the loop once so it actually runs before we check it.
        await asyncio.sleep(0)

        assert future.result() == GovernanceStartOutcome.REJECTED_CLAIM_FAILED
        updated = governed_service.governance_outbox.load()
        assert updated is not None
        assert updated.state == OutboxState.NEEDS_ATTENTION

    @pytest.mark.asyncio
    async def test_claim_and_run_governed_reports_binding_mismatch_to_central(
        self, governed_service
    ):
        """A binding mismatch discovered *after* claim already succeeded must
        still resolve the handshake and best-effort report the failure back
        to central — see _report_governance_failure's docstring for why this
        window can't be fully closed in this MVP slice."""
        action = _governance_pending_action()
        record = OutboxRecord(
            request_id="req-1",
            conversation_id=str(governed_service.stored.id),
            action_event_id=action.id,
            tool_call_id=action.tool_call_id,
            tool_name=action.tool_name,
            action_type="tool_call",
            policy_revision="agent-server-mvp-v1",
            action_summary="running a command",
            action_payload={},
            digest_salt="salt",
            action_payload_digest="digest",
            execution_commitment=compute_execution_commitment(
                action, str(governed_service.stored.id)
            ),
            origin_device_id="device-1",
            state=OutboxState.CREATED,
            central_approval_id="approval-1",
        )
        await governed_service.governance_outbox.create_record(record)

        fake_client = MagicMock()
        fake_client.claim = AsyncMock(
            return_value={
                "execution_attempt_id": "attempt-1",
                "executing_lease_expires_at": "2099-01-01T00:00:00+00:00",
            }
        )
        fake_client.report_result = AsyncMock(return_value={})
        future: asyncio.Future = asyncio.get_running_loop().create_future()

        async def _fake_run(*, on_governed_reject, **_kwargs):
            on_governed_reject(ActionBindingMismatchError("replaced"))

        governed_service.run = AsyncMock(side_effect=_fake_run)

        governed_service.governance_client = fake_client
        await governed_service._claim_and_run_governed(record, "approval-1", future)
        # on_governed_reject schedules the report via
        # run_coroutine_threadsafe — pump the loop so it actually runs.
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        assert future.result() == GovernanceStartOutcome.REJECTED_BINDING_MISMATCH
        fake_client.report_result.assert_awaited_once()
        _, kwargs = fake_client.report_result.call_args
        assert kwargs["outcome"] == "failure_definite"
        assert kwargs["execution_attempt_id"] == "attempt-1"

    # ---------------- _report_governance_failure ----------------

    @pytest.mark.asyncio
    async def test_report_governance_failure_marks_result_reported_on_success(
        self, governed_service
    ):
        action = _governance_pending_action()
        record = OutboxRecord(
            request_id="req-1",
            conversation_id=str(governed_service.stored.id),
            action_event_id=action.id,
            tool_call_id=action.tool_call_id,
            tool_name=action.tool_name,
            action_type="tool_call",
            policy_revision="agent-server-mvp-v1",
            action_summary="running a command",
            action_payload={},
            digest_salt="salt",
            action_payload_digest="digest",
            execution_commitment=compute_execution_commitment(
                action, str(governed_service.stored.id)
            ),
            origin_device_id="device-1",
            state=OutboxState.CLAIMED,
            central_approval_id="approval-1",
            execution_attempt_id="attempt-1",
        )
        await governed_service.governance_outbox.create_record(record)

        fake_client = MagicMock()
        fake_client.report_result = AsyncMock(return_value={})
        governed_service.governance_client = fake_client
        await governed_service._report_governance_failure("approval-1", "attempt-1")

        updated = governed_service.governance_outbox.load()
        assert updated is not None
        assert updated.state == OutboxState.RESULT_REPORTED

    @pytest.mark.asyncio
    async def test_report_governance_failure_marks_needs_attention_on_error(
        self, governed_service
    ):
        action = _governance_pending_action()
        record = OutboxRecord(
            request_id="req-1",
            conversation_id=str(governed_service.stored.id),
            action_event_id=action.id,
            tool_call_id=action.tool_call_id,
            tool_name=action.tool_name,
            action_type="tool_call",
            policy_revision="agent-server-mvp-v1",
            action_summary="running a command",
            action_payload={},
            digest_salt="salt",
            action_payload_digest="digest",
            execution_commitment=compute_execution_commitment(
                action, str(governed_service.stored.id)
            ),
            origin_device_id="device-1",
            state=OutboxState.CLAIMED,
            central_approval_id="approval-1",
            execution_attempt_id="attempt-1",
        )
        await governed_service.governance_outbox.create_record(record)

        fake_client = MagicMock()
        fake_client.report_result = AsyncMock(side_effect=RuntimeError("boom"))
        governed_service.governance_client = fake_client
        await governed_service._report_governance_failure("approval-1", "attempt-1")

        updated = governed_service.governance_outbox.load()
        assert updated is not None
        assert updated.state == OutboxState.NEEDS_ATTENTION

    # ---------------- maybe_report_governance_result ----------------

    def _claimed_record(self, governed_service, action) -> OutboxRecord:
        return OutboxRecord(
            request_id="req-1",
            conversation_id=str(governed_service.stored.id),
            action_event_id=action.id,
            tool_call_id=action.tool_call_id,
            tool_name=action.tool_name,
            action_type="tool_call",
            policy_revision="agent-server-mvp-v1",
            action_summary="running a command",
            action_payload={},
            digest_salt="salt",
            action_payload_digest="digest",
            execution_commitment=compute_execution_commitment(
                action, str(governed_service.stored.id)
            ),
            origin_device_id="device-1",
            state=OutboxState.CLAIMED,
            central_approval_id="approval-1",
            execution_attempt_id="attempt-1",
        )

    # ---------- execution commitment: registered, presented, attested ----------

    def _keyed(self, governed_service, action, record: OutboxRecord) -> OutboxRecord:
        """``record`` as a device creates it now: its commitment is an HMAC
        under a per-record key that is stored with it."""
        record.commitment_key = "k" * 64
        record.execution_commitment = compute_execution_commitment(
            action, str(governed_service.stored.id), record.commitment_key
        )
        return record

    async def _claim_with_fake_central(self, governed_service, record):
        await governed_service.governance_outbox.create_record(record)
        fake_client = MagicMock()
        fake_client.claim = AsyncMock(
            return_value={
                "execution_attempt_id": "attempt-1",
                "executing_lease_expires_at": "2099-01-01T00:00:00+00:00",
            }
        )

        seen_bindings: list = []

        async def _fake_run(*, expected_binding, on_governed_start, **_kwargs):
            seen_bindings.append(expected_binding)
            asyncio.get_running_loop().call_soon(on_governed_start)

        governed_service.run = AsyncMock(side_effect=_fake_run)
        governed_service.governance_client = fake_client
        outcome = await governed_service.run_and_wait_for_start(
            central_approval_id="approval-1", timeout_seconds=5.0
        )
        assert outcome == GovernanceStartOutcome.STARTED
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        if governed_service._pending_governance_report_tasks:
            await asyncio.gather(*governed_service._pending_governance_report_tasks)
        return fake_client, seen_bindings

    @pytest.mark.asyncio
    async def test_claim_presents_the_registered_commitment_and_marks_attested(
        self, governed_service
    ):
        """Central only hands out the lease if the commitment presented at
        claim equals the one registered before the human decided, and the
        local binding check must use the same key to recompute it. Once that
        check has passed and execution has started, the record is marked so a
        later report may attest it."""
        action = _governance_pending_action()
        record = self._keyed(
            governed_service,
            action,
            self._claimed_record(governed_service, action),
        )
        record.state = OutboxState.CREATED
        record.execution_attempt_id = None

        client, seen = await self._claim_with_fake_central(governed_service, record)

        _, kwargs = client.claim.call_args
        assert kwargs["execution_commitment"] == record.execution_commitment
        assert seen[0].commitment_key == record.commitment_key
        updated = governed_service.governance_outbox.load()
        assert updated.execution_attested is True

    @pytest.mark.asyncio
    async def test_claim_of_a_record_with_no_key_presents_nothing(
        self, governed_service
    ):
        """A record created before commitments were registered has nothing at
        central to compare with; sending one would be a mismatch."""
        action = _governance_pending_action()
        record = self._claimed_record(governed_service, action)
        record.state = OutboxState.CREATED
        record.execution_attempt_id = None

        client, _ = await self._claim_with_fake_central(governed_service, record)

        _, kwargs = client.claim.call_args
        assert kwargs["execution_commitment"] is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("keyed", "attested", "expect_attestation"),
        [
            (True, True, True),
            # The marker is lost if the process dies before it is written;
            # that must read as "not attested", never as a pass.
            (True, False, False),
            # No key means central holds no commitment for this record.
            (False, True, False),
        ],
        ids=["attested", "marker-lost", "legacy-record"],
    )
    async def test_report_attests_only_what_was_verified_before_execution(
        self, governed_service, keyed, attested, expect_attestation
    ):
        action = _governance_pending_action()
        record = self._claimed_record(governed_service, action)
        if keyed:
            self._keyed(governed_service, action, record)
        record.execution_attested = attested
        await governed_service.governance_outbox.create_record(record)
        observation = ObservationEvent(
            tool_name=action.tool_name,
            tool_call_id=action.tool_call_id,
            observation=TerminalObservation(command="ls", is_error=False),
            action_id=action.id,
        )
        governed_service._conversation = self._mock_conversation([])
        governed_service._conversation._state.events = [action, observation]
        fake_client = MagicMock()
        fake_client.report_result = AsyncMock(return_value={})
        governed_service.governance_client = fake_client

        await governed_service.maybe_report_governance_result()

        _, kwargs = fake_client.report_result.call_args
        expected = record.execution_commitment if expect_attestation else None
        assert kwargs["executed_commitment"] == expected

    @pytest.mark.asyncio
    async def test_report_uses_the_marker_that_landed_after_the_snapshot_was_read(
        self, governed_service
    ):
        """The EXECUTION_STARTED marker is written by a separately scheduled
        task, so it can land after the report path has loaded the record but
        before it sends. Reading the attestation from that stale snapshot
        would tell central "not attested" for an execution whose check had
        passed (found by review)."""
        action = _governance_pending_action()
        record = self._keyed(
            governed_service, action, self._claimed_record(governed_service, action)
        )
        assert record.execution_attested is False
        await governed_service.governance_outbox.create_record(record)
        observation = ObservationEvent(
            tool_name=action.tool_name,
            tool_call_id=action.tool_call_id,
            observation=TerminalObservation(command="ls", is_error=False),
            action_id=action.id,
        )
        governed_service._conversation = self._mock_conversation([])
        governed_service._conversation._state.events = [action, observation]
        fake_client = MagicMock()
        fake_client.report_result = AsyncMock(return_value={})
        governed_service.governance_client = fake_client

        real_mutate = governed_service.governance_outbox.mutate
        marker_pending = True

        async def _mutate_after_marker_lands(fn):
            # The marker lands first, then the report path's own mutate runs.
            nonlocal marker_pending
            if marker_pending:
                marker_pending = False
                await real_mutate(_with_execution_attested)
            return await real_mutate(fn)

        governed_service.governance_outbox.mutate = _mutate_after_marker_lands

        await governed_service.maybe_report_governance_result()

        _, kwargs = fake_client.report_result.call_args
        assert kwargs["executed_commitment"] == record.execution_commitment

    @pytest.mark.asyncio
    async def test_close_reconcile_does_not_attest_an_execution_that_never_started(
        self, governed_service
    ):
        action = _governance_pending_action()
        record = self._keyed(
            governed_service, action, self._claimed_record(governed_service, action)
        )
        await governed_service.governance_outbox.create_record(record)
        fake_client = MagicMock()
        fake_client.report_result = AsyncMock(return_value={})
        governed_service.governance_client = fake_client
        governed_service._conversation = None

        await governed_service.close()

        _, kwargs = fake_client.report_result.call_args
        assert kwargs["outcome"] == "failure_unknown"
        assert kwargs["executed_commitment"] is None

    @pytest.mark.asyncio
    async def test_maybe_report_result_reports_success(self, governed_service):
        action = _governance_pending_action()
        await governed_service.governance_outbox.create_record(
            self._claimed_record(governed_service, action)
        )
        observation = ObservationEvent(
            tool_name=action.tool_name,
            tool_call_id=action.tool_call_id,
            observation=TerminalObservation(command="ls", is_error=False),
            action_id=action.id,
        )
        governed_service._conversation = self._mock_conversation([])
        governed_service._conversation._state.events = [action, observation]

        fake_client = MagicMock()
        fake_client.report_result = AsyncMock(return_value={})
        governed_service.governance_client = fake_client
        await governed_service.maybe_report_governance_result()

        fake_client.report_result.assert_awaited_once()
        _, kwargs = fake_client.report_result.call_args
        assert kwargs["outcome"] == "success"
        assert kwargs["execution_attempt_id"] == "attempt-1"
        updated = governed_service.governance_outbox.load()
        assert updated is not None
        assert updated.state == OutboxState.RESULT_REPORTED

    @pytest.mark.asyncio
    async def test_maybe_report_result_reports_failure_definite(self, governed_service):
        action = _governance_pending_action()
        await governed_service.governance_outbox.create_record(
            self._claimed_record(governed_service, action)
        )
        observation = ObservationEvent(
            tool_name=action.tool_name,
            tool_call_id=action.tool_call_id,
            observation=TerminalObservation(command="ls", is_error=True),
            action_id=action.id,
        )
        governed_service._conversation = self._mock_conversation([])
        governed_service._conversation._state.events = [action, observation]

        fake_client = MagicMock()
        fake_client.report_result = AsyncMock(return_value={})
        governed_service.governance_client = fake_client
        await governed_service.maybe_report_governance_result()

        _, kwargs = fake_client.report_result.call_args
        assert kwargs["outcome"] == "failure_definite"

    @pytest.mark.asyncio
    async def test_maybe_report_result_reports_failure_unknown_on_crash_recovery(
        self, governed_service
    ):
        """A synthetic AgentErrorEvent (crash-recovery, matched by
        tool_call_id — it carries no action_id) means the process died
        before we know whether the tool's side effect happened — must never
        be reported as a definite outcome."""
        action = _governance_pending_action()
        await governed_service.governance_outbox.create_record(
            self._claimed_record(governed_service, action)
        )
        crash_error = AgentErrorEvent(
            tool_name=action.tool_name,
            tool_call_id=action.tool_call_id,
            error="restart occurred mid-execution",
        )
        governed_service._conversation = self._mock_conversation([])
        governed_service._conversation._state.events = [action, crash_error]

        fake_client = MagicMock()
        fake_client.report_result = AsyncMock(return_value={})
        governed_service.governance_client = fake_client
        await governed_service.maybe_report_governance_result()

        _, kwargs = fake_client.report_result.call_args
        assert kwargs["outcome"] == "failure_unknown"

    @pytest.mark.asyncio
    async def test_maybe_report_result_noop_when_not_yet_resolved(
        self, governed_service
    ):
        """No matching observation yet (the action is still pending or
        running) — must not guess an outcome; just retry on the next
        finally."""
        action = _governance_pending_action()
        await governed_service.governance_outbox.create_record(
            self._claimed_record(governed_service, action)
        )
        governed_service._conversation = self._mock_conversation([])
        governed_service._conversation._state.events = [action]

        fake_client = MagicMock()
        fake_client.report_result = AsyncMock(return_value={})
        governed_service.governance_client = fake_client
        await governed_service.maybe_report_governance_result()

        fake_client.report_result.assert_not_awaited()
        updated = governed_service.governance_outbox.load()
        assert updated is not None
        assert updated.state == OutboxState.CLAIMED

    @pytest.mark.asyncio
    async def test_maybe_report_result_noop_when_outbox_not_claimed(
        self, governed_service
    ):
        """Only a CLAIMED record represents a governed action actually in
        flight — any other state (still pending create, already reported,
        etc.) is not this hook's concern."""
        action = _governance_pending_action()
        record = self._claimed_record(governed_service, action)
        record.state = OutboxState.CREATED
        await governed_service.governance_outbox.create_record(record)

        fake_client = MagicMock()
        fake_client.report_result = AsyncMock(return_value={})
        governed_service.governance_client = fake_client
        await governed_service.maybe_report_governance_result()

        fake_client.report_result.assert_not_awaited()

    # ---------------- cancellation / lifecycle ----------------

    @pytest.mark.asyncio
    async def test_claim_and_run_governed_cancellation_resolves_handshake(
        self, governed_service
    ):
        """Cancelling the background handshake task (e.g. EventService.
        close() draining in-flight work) must still resolve the future —
        otherwise a waiter would hang until its own timeout instead of
        observing the cancellation immediately."""
        action = _governance_pending_action()
        record = self._claimed_record(governed_service, action)
        record.state = OutboxState.CREATED
        await governed_service.governance_outbox.create_record(record)

        fake_client = MagicMock()
        never_returns: asyncio.Future = asyncio.get_running_loop().create_future()

        async def _hang_forever(*_args, **_kwargs):
            await never_returns

        fake_client.claim = AsyncMock(side_effect=_hang_forever)
        future: asyncio.Future = asyncio.get_running_loop().create_future()

        governed_service.governance_client = fake_client
        task = asyncio.create_task(
            governed_service._claim_and_run_governed(record, "approval-1", future)
        )
        await asyncio.sleep(0)  # let it reach the hanging claim() call
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

        assert future.result() == GovernanceStartOutcome.REJECTED_CANCELLED
        never_returns.cancel()

    @pytest.mark.asyncio
    async def test_is_idle_evictable_false_while_governance_handshake_active(
        self, governed_service
    ):
        future: asyncio.Future = asyncio.get_running_loop().create_future()

        async def _hang_forever():
            await future

        task = asyncio.create_task(_hang_forever())
        governed_service._active_governance_handshake = _GovernanceHandshake(
            binding_fingerprint="fp", future=future, task=task
        )

        assert governed_service.is_idle_evictable() is False

        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    @pytest.mark.asyncio
    async def test_is_idle_evictable_false_while_governance_background_work_pending(
        self, governed_service
    ):
        """Not just the handshake — a fire-and-forget create/report task
        must also hold off idle eviction, or an evict-then-close() sweep
        would silently cancel work that was never flagged as in-flight."""
        release = asyncio.Event()

        async def _hang_until_released():
            await release.wait()

        create_task = asyncio.create_task(_hang_until_released())
        governed_service._pending_governance_create_tasks.add(create_task)

        assert governed_service.is_idle_evictable() is False

        release.set()
        await create_task
        # Production code discards via a done-callback (see
        # maybe_register_governance_approval()) — do it explicitly here
        # since this test adds the task to the set directly.
        governed_service._pending_governance_create_tasks.discard(create_task)
        assert governed_service.is_idle_evictable() is True

        release = asyncio.Event()
        report_task = asyncio.create_task(_hang_until_released())
        governed_service._pending_governance_report_tasks.add(report_task)

        assert governed_service.is_idle_evictable() is False

        release.set()
        await report_task
        governed_service._pending_governance_report_tasks.discard(report_task)
        assert governed_service.is_idle_evictable() is True

    @pytest.mark.asyncio
    async def test_close_cancels_pending_create_task(self, governed_service):
        """maybe_register_governance_approval()'s fire-and-forget create
        task is independent of the claim/run handshake, but must be
        cancelled-and-drained the same way — otherwise it can keep writing
        to self.governance_outbox after close() considers the service torn
        down."""
        future: asyncio.Future = asyncio.get_running_loop().create_future()

        async def _hang_forever():
            await future

        task = asyncio.create_task(_hang_forever())
        governed_service._pending_governance_create_tasks.add(task)
        task.add_done_callback(
            governed_service._pending_governance_create_tasks.discard
        )
        governed_service._conversation = None  # keep close() minimal

        await governed_service.close()

        assert task.cancelled()
        assert governed_service._pending_governance_create_tasks == set()

    @pytest.mark.asyncio
    async def test_close_cancels_in_flight_governance_handshake(self, governed_service):
        future: asyncio.Future = asyncio.get_running_loop().create_future()

        async def _hang_forever():
            await future

        task = asyncio.create_task(_hang_forever())
        governed_service._active_governance_handshake = _GovernanceHandshake(
            binding_fingerprint="fp", future=future, task=task
        )
        governed_service._conversation = None  # keep close() minimal

        await governed_service.close()

        assert task.cancelled() or task.done()
        assert governed_service._active_governance_handshake is None

    @pytest.mark.asyncio
    async def test_close_reconciles_an_orphaned_claimed_record(self, governed_service):
        """If a central claim succeeded (outbox CLAIMED) but this service
        is shutting down before any conclusive result was ever reported —
        whether the handshake was cancelled before self.run() started, or
        a governed run was cancelled mid-execution — close() must
        proactively report failure_unknown rather than leave central
        holding an execution lease with no path to resolution."""
        action = _governance_pending_action()
        record = self._claimed_record(governed_service, action)
        await governed_service.governance_outbox.create_record(record)

        fake_client = MagicMock()
        fake_client.report_result = AsyncMock(return_value={})
        governed_service.governance_client = fake_client
        governed_service._conversation = None  # keep close() minimal

        await governed_service.close()

        fake_client.report_result.assert_awaited_once()
        _, kwargs = fake_client.report_result.call_args
        assert kwargs["outcome"] == "failure_unknown"
        assert kwargs["execution_attempt_id"] == "attempt-1"
        updated = governed_service.governance_outbox.load()
        assert updated is not None
        assert updated.state == OutboxState.RESULT_REPORTED

    @pytest.mark.asyncio
    async def test_close_does_not_reconcile_a_non_claimed_record(
        self, governed_service
    ):
        """Only a CLAIMED record represents an orphaned central execution
        lease — any other state (still pending create, already reported,
        etc.) is not this hook's concern."""
        action = _governance_pending_action()
        record = self._claimed_record(governed_service, action)
        record.state = OutboxState.CREATED
        await governed_service.governance_outbox.create_record(record)

        fake_client = MagicMock()
        fake_client.report_result = AsyncMock(return_value={})
        governed_service.governance_client = fake_client
        governed_service._conversation = None

        await governed_service.close()

        fake_client.report_result.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_close_waits_for_pending_reject_report_before_reconciling(
        self, governed_service
    ):
        """A binding-mismatch rejection discovered after claim schedules
        _report_governance_failure() via on_governed_reject. close() must
        wait for that report to actually finish before deciding whether
        the outbox still needs a failure_unknown reconciliation —
        otherwise the two could send central conflicting outcomes for the
        same execution_attempt_id.

        close() is started immediately after on_governed_reject fires,
        without pumping the loop first — exercising the exact window where
        the call_soon_threadsafe-scheduled closure has been *scheduled*
        but not yet *executed*. The atomic closure that resolves the
        handshake and registers the report task together (no await between
        the two steps) guarantees close() can only ever observe "both
        happened" or "neither" — never one without the other — so this
        must still end up waiting for and draining the report correctly
        even started this early.
        """
        action = _governance_pending_action()
        record = self._claimed_record(governed_service, action)
        await governed_service.governance_outbox.create_record(record)

        release_report = asyncio.Event()

        async def _slow_report_result(*_args, **_kwargs):
            await release_report.wait()
            return {}

        fake_client = MagicMock()
        fake_client.claim = AsyncMock(
            return_value={
                "execution_attempt_id": "attempt-1",
                "executing_lease_expires_at": "2099-01-01T00:00:00+00:00",
            }
        )
        fake_client.report_result = AsyncMock(side_effect=_slow_report_result)
        governed_service.governance_client = fake_client

        async def _fake_run(*, on_governed_reject, **_kwargs):
            on_governed_reject(ActionBindingMismatchError("replaced"))

        governed_service.run = AsyncMock(side_effect=_fake_run)
        governed_service._conversation = None  # keep close() minimal

        future: asyncio.Future = asyncio.get_running_loop().create_future()
        await governed_service._claim_and_run_governed(record, "approval-1", future)

        close_task = asyncio.create_task(governed_service.close())
        await asyncio.sleep(0)
        assert not close_task.done()  # still waiting on the pending report

        release_report.set()
        await close_task

        # Exactly one report, not a second conflicting one from
        # _reconcile_governance_after_close() racing the first.
        fake_client.report_result.assert_awaited_once()
        _, kwargs = fake_client.report_result.call_args
        assert kwargs["outcome"] == "failure_definite"
        updated = governed_service.governance_outbox.load()
        assert updated is not None
        assert updated.state == OutboxState.RESULT_REPORTED

    @pytest.mark.asyncio
    async def test_close_sees_a_task_registered_via_call_soon_threadsafe(
        self, governed_service
    ):
        """Deterministic, mechanism-level regression: the test above relies
        on on_governed_reject's own closure having already been scheduled
        before close() is started, so a natural ready-queue ordering could
        coincidentally make it pass even without the fix. This test removes
        that ambiguity by driving the exact primitive directly: schedule a
        task-registering closure via call_soon_threadsafe with *zero*
        intervening awaits, then start close() immediately — the narrowest
        possible version of the window close() must not fall through."""
        governed_service._conversation = None  # keep close() minimal
        release_task = asyncio.Event()

        async def _slow_task() -> None:
            await release_task.wait()

        def _register_late_task() -> None:
            task = asyncio.create_task(_slow_task())
            governed_service._pending_governance_report_tasks.add(task)
            task.add_done_callback(
                governed_service._pending_governance_report_tasks.discard
            )

        asyncio.get_running_loop().call_soon_threadsafe(_register_late_task)
        # No await between the scheduling call above and starting close()
        # below — the closure has not run yet at this point.
        close_task = asyncio.create_task(governed_service.close())
        await asyncio.sleep(0)
        assert not close_task.done(), (
            "close() must have observed the task this closure registers, "
            "not decided there was nothing pending before the closure ever "
            "ran"
        )

        release_task.set()
        await close_task

    @pytest.mark.asyncio
    async def test_late_reject_after_registration_closed_does_not_register_a_report(
        self, governed_service
    ):
        """The other side of the window above: once close() has committed
        to being the sole reporter (_governance_report_registration_closed
        set), a late on_governed_reject — e.g. from a synchronous
        conversation.run() still executing on its own worker thread, which
        close() cannot forcibly stop (see close()'s run-task-drain
        comment) — must not register a second, untracked report that could
        conflict with close()'s own reconciliation outcome."""
        action = _governance_pending_action()
        record = self._claimed_record(governed_service, action)
        await governed_service.governance_outbox.create_record(record)

        fake_client = MagicMock()
        fake_client.claim = AsyncMock(
            return_value={
                "execution_attempt_id": "attempt-1",
                "executing_lease_expires_at": "2099-01-01T00:00:00+00:00",
            }
        )
        fake_client.report_result = AsyncMock(return_value={})
        governed_service.governance_client = fake_client

        captured_on_reject = None

        async def _fake_run(*, on_governed_reject, **_kwargs):
            nonlocal captured_on_reject
            captured_on_reject = on_governed_reject

        governed_service.run = AsyncMock(side_effect=_fake_run)

        future: asyncio.Future = asyncio.get_running_loop().create_future()
        await governed_service._claim_and_run_governed(record, "approval-1", future)
        assert captured_on_reject is not None

        # Simulate close() having already reached the point where it
        # commits to _reconcile_governance_after_close() being authoritative.
        governed_service._governance_report_registration_closed = True

        captured_on_reject(ActionBindingMismatchError("replaced"))
        await asyncio.sleep(0)

        assert governed_service._pending_governance_report_tasks == set()
        fake_client.report_result.assert_not_awaited()
        # The handshake future is still resolved -- only the *report*
        # registration is suppressed, not the outcome itself.
        assert future.result() == GovernanceStartOutcome.REJECTED_BINDING_MISMATCH

    @pytest.mark.asyncio
    async def test_late_reject_after_a_real_close_call_does_not_register_a_report(
        self, governed_service
    ):
        """Strengthens the test above by actually running close() to
        completion first, instead of only setting the flag by hand —
        proving the suppression genuinely survives a real close() call
        (which also exercises its own failure_unknown reconciliation
        report for the orphaned CLAIMED record), not just this test's own
        assumption about the flag's effect."""
        action = _governance_pending_action()
        record = self._claimed_record(governed_service, action)
        await governed_service.governance_outbox.create_record(record)

        fake_client = MagicMock()
        fake_client.claim = AsyncMock(
            return_value={
                "execution_attempt_id": "attempt-1",
                "executing_lease_expires_at": "2099-01-01T00:00:00+00:00",
            }
        )
        fake_client.report_result = AsyncMock(return_value={})
        governed_service.governance_client = fake_client

        captured_on_reject = None

        async def _fake_run(*, on_governed_reject, **_kwargs):
            nonlocal captured_on_reject
            captured_on_reject = on_governed_reject

        governed_service.run = AsyncMock(side_effect=_fake_run)
        governed_service._conversation = None  # keep close() minimal

        future: asyncio.Future = asyncio.get_running_loop().create_future()
        await governed_service._claim_and_run_governed(record, "approval-1", future)
        assert captured_on_reject is not None

        await governed_service.close()  # the real thing, run to completion

        # close()'s own reconciliation already reported the orphaned claim.
        fake_client.report_result.assert_awaited_once()
        _, kwargs = fake_client.report_result.call_args
        assert kwargs["outcome"] == "failure_unknown"
        fake_client.report_result.reset_mock()

        # Simulates the executor-thread race close()'s own run-task-drain
        # comment describes: conversation.run() was still executing on its
        # own worker thread and only calls back into on_governed_reject
        # after close() has already returned.
        captured_on_reject(ActionBindingMismatchError("replaced"))
        await asyncio.sleep(0)

        assert governed_service._pending_governance_report_tasks == set()

    # ---------------- check_governed_binding_required (via run()) ----------------
    # Reached from run()'s own WAITING_FOR_CONFIRMATION branch — closes the
    # gap send_message(run=True), the goal loop, and the ACP-rerun path in
    # run()'s own finally all shared: calling run() without expected_binding
    # is a no-op bypass of central governance for a conversation that
    # already has one pending (see that function's own docstring for the
    # full rationale).

    def _governed_conversation(self, requester_identity: str | None = None):
        conversation = MagicMock()
        state = MagicMock()
        state.execution_status = ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation.state = state
        conversation._state = state
        conversation._requester_identity = requester_identity
        conversation.run = MagicMock()
        conversation.arun = AsyncMock()
        return conversation

    async def _create_outbox_record(
        self,
        governed_service,
        *,
        state: OutboxState,
        central_approval_id: str | None = "approval-1",
    ) -> OutboxRecord:
        action = _governance_pending_action()
        record = OutboxRecord(
            request_id="req-1",
            conversation_id=str(governed_service.stored.id),
            action_event_id=action.id,
            tool_call_id=action.tool_call_id,
            tool_name=action.tool_name,
            action_type="tool_call",
            policy_revision="agent-server-mvp-v1",
            action_summary="running a command",
            action_payload={},
            digest_salt="salt",
            action_payload_digest="digest",
            execution_commitment=compute_execution_commitment(
                action, str(governed_service.stored.id)
            ),
            origin_device_id="device-1",
            state=state,
            central_approval_id=central_approval_id,
        )
        await governed_service.governance_outbox.create_record(record)
        return record

    @pytest.mark.asyncio
    async def test_run_blocks_bindingless_call_when_governed_action_pending_create(
        self, governed_service
    ):
        """PENDING_CREATE (no central_approval_id minted yet — create
        failed, is still in flight, or is being retried) must fail
        *closed*, not be treated as "nothing to compare against yet".
        Nobody can hold a genuine binding for an approval that doesn't
        exist, so every run() call is blocked in this window too — see
        check_governed_binding_required()'s own docstring for why an
        earlier version of this guard got this wrong."""
        await self._create_outbox_record(
            governed_service,
            state=OutboxState.PENDING_CREATE,
            central_approval_id=None,
        )
        governed_service._conversation = self._governed_conversation()

        with pytest.raises(ActionBindingMismatchError):
            await governed_service.run()

        assert governed_service._run_task is None
        governed_service._conversation.run.assert_not_called()
        governed_service._conversation.arun.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_run_blocks_bindingless_call_when_governed_action_claimed(
        self, governed_service
    ):
        await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIMED
        )
        governed_service._conversation = self._governed_conversation()

        with pytest.raises(ActionBindingMismatchError):
            await governed_service.run()

        assert governed_service._run_task is None
        governed_service._conversation.run.assert_not_called()
        governed_service._conversation.arun.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_run_blocks_bindingless_call_when_governed_action_started(
        self, governed_service
    ):
        """Same guard, EXECUTION_STARTED state — covers the window between
        on_governed_start's own mutate landing and report-result, not just
        the pre-start CLAIMED window covered by the test above."""
        await self._create_outbox_record(
            governed_service, state=OutboxState.EXECUTION_STARTED
        )
        governed_service._conversation = self._governed_conversation()

        with pytest.raises(ActionBindingMismatchError):
            await governed_service.run()

        assert governed_service._run_task is None

    # ---------------- no-outbox boundary ----------------
    # check_governed_binding_required() refuses a run() when there is no
    # outbox record at all. These tests cover how a team-mode conversation
    # can wait for confirmation with no outbox record, and that a
    # bindingless run() is refused then.
    # Invariant: in team mode a bindingless run() of a conversation that is
    # waiting for confirmation is refused whether or not an outbox record
    # exists yet.

    def _waiting_conversation_with_pending(self, *pending_actions):
        conversation = self._governed_conversation()
        conversation._state.active_branch = MagicMock(
            return_value=list(pending_actions)
        )
        conversation.send_message = MagicMock()
        return conversation

    @pytest.mark.asyncio
    async def test_hook_declines_two_pending_actions_so_no_outbox_record_exists(
        self, governed_service
    ):
        """Reachability, not the invariant: with other than one pending
        action maybe_register_governance_approval() never engages (batch
        confirmations are unsupported), so a team-mode conversation stays
        WAITING_FOR_CONFIRMATION with no outbox record and no create task."""
        governed_service._conversation = self._waiting_conversation_with_pending(
            _governance_pending_action("call_1"),
            _governance_pending_action("call_2", command="pwd"),
        )

        await governed_service.maybe_register_governance_approval()

        assert governed_service.governance_outbox.load() is None
        assert governed_service._pending_governance_create_tasks == set()

    @pytest.mark.asyncio
    async def test_run_blocks_bindingless_call_with_no_outbox_record(
        self, governed_service
    ):
        assert governed_service.governance_outbox.load() is None
        governed_service._conversation = self._governed_conversation()

        with pytest.raises(ActionBindingMismatchError, match="no governed approval"):
            await governed_service.run()

        assert governed_service._run_task is None
        governed_service._conversation.run.assert_not_called()
        governed_service._conversation.arun.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_send_message_run_blocked_with_no_outbox_record(
        self, governed_service, caplog
    ):
        """Same invariant through send_message(run=True), which reaches
        run() without an expected binding. send_message() swallows the
        ValueError run() raises, so the observable contract is that no run
        was started, and the refusal is logged so the caller's silent
        success is diagnosable."""
        governed_service._conversation = self._governed_conversation()
        governed_service._conversation.send_message = MagicMock()
        caplog.set_level("WARNING")

        await governed_service.send_message(
            Message(role="user", content=[TextContent(text="go on")]), run=True
        )

        assert governed_service._run_task is None
        governed_service._conversation.run.assert_not_called()
        governed_service._conversation.arun.assert_not_awaited()
        assert "refused by the governance gate" in caplog.text

    @pytest.mark.asyncio
    async def test_run_blocks_bindingless_call_in_window_before_create_persists(
        self, governed_service
    ):
        """One pending action: the hook schedules the create task and
        returns, but the PENDING_CREATE record is written only once that
        task runs. Hold the task back to model that window; a bindingless
        run() inside it must still be refused."""
        governed_service._conversation = self._waiting_conversation_with_pending(
            _governance_pending_action()
        )
        scheduled = []
        governed_service._schedule_governance_create_task = MagicMock(
            side_effect=lambda coro: (scheduled.append(coro), coro.close())
        )

        await governed_service.maybe_register_governance_approval()
        assert len(scheduled) == 1  # hook engaged, record not written yet
        assert governed_service.governance_outbox.load() is None

        with pytest.raises(ActionBindingMismatchError):
            await governed_service.run()

        governed_service._conversation.run.assert_not_called()
        governed_service._conversation.arun.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_run_blocks_bindingless_call_after_hook_declines_two_pending(
        self, governed_service
    ):
        """End to end for the batch case: the hook declines, no record ever
        exists, and a bindingless run() must still be refused rather than
        executing the pending actions."""
        governed_service._conversation = self._waiting_conversation_with_pending(
            _governance_pending_action("call_1"),
            _governance_pending_action("call_2", command="pwd"),
        )
        await governed_service.maybe_register_governance_approval()
        assert governed_service.governance_outbox.load() is None

        with pytest.raises(ActionBindingMismatchError):
            await governed_service.run()

        governed_service._conversation.run.assert_not_called()
        governed_service._conversation.arun.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_run_blocks_bindingless_call_for_batch_round_after_terminal_record(
        self, governed_service
    ):
        """A terminal record only means the governed action it tracked is
        finished. A later confirmation round with several pending actions is
        never registered (the hook needs exactly one), so the old terminal
        record stays on disk and covers none of them; a bindingless run()
        must still be refused."""
        await self._create_outbox_record(
            governed_service, state=OutboxState.RESULT_REPORTED
        )
        governed_service._conversation = self._waiting_conversation_with_pending(
            _governance_pending_action("call_2"),
            _governance_pending_action("call_3", command="pwd"),
        )
        await governed_service.maybe_register_governance_approval()
        record = governed_service.governance_outbox.load()
        assert record is not None and record.state == OutboxState.RESULT_REPORTED

        with pytest.raises(ActionBindingMismatchError, match="already finished"):
            await governed_service.run()

        governed_service._conversation.run.assert_not_called()
        governed_service._conversation.arun.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_run_allows_matching_expected_binding(self, governed_service):
        record = await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIMED
        )
        governed_service._conversation = self._governed_conversation()
        governed_service._publish_state_update = AsyncMock()
        assert record.central_approval_id is not None
        binding = ActionBinding(
            central_approval_id=record.central_approval_id,
            action_event_id=record.action_event_id,
            execution_commitment=record.execution_commitment,
        )

        await governed_service.run(expected_binding=binding)

        assert governed_service._run_task is not None

    @pytest.mark.asyncio
    async def test_run_rejects_binding_for_a_different_action(self, governed_service):
        """A binding for a different action_event_id than the one currently
        tracked in the outbox must not be accepted — same failure mode as a
        stale/replayed binding, not just a wholly-missing one."""
        record = await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIMED
        )
        governed_service._conversation = self._governed_conversation()
        assert record.central_approval_id is not None
        stale_binding = ActionBinding(
            central_approval_id=record.central_approval_id,
            action_event_id="some-other-action-id",
            execution_commitment=record.execution_commitment,
        )

        with pytest.raises(ActionBindingMismatchError):
            await governed_service.run(expected_binding=stale_binding)

        assert governed_service._run_task is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "terminal_state",
        [
            OutboxState.RESULT_REPORTED,
            OutboxState.RECONCILIATION_REPORTED,
            OutboxState.CANCELLED,
        ],
    )
    async def test_run_blocks_bindingless_call_when_outbox_terminal(
        self, governed_service, terminal_state
    ):
        """A terminal record only describes a governed action that is
        finished, cancelled or reconciled. The conversation is waiting for
        confirmation of other pending actions that the record does not
        cover, so a bindingless run() is refused until a new approval
        exists."""
        await self._create_outbox_record(governed_service, state=terminal_state)
        governed_service._conversation = self._governed_conversation()

        with pytest.raises(ActionBindingMismatchError, match="already finished"):
            await governed_service.run()

        assert governed_service._run_task is None
        governed_service._conversation.run.assert_not_called()
        governed_service._conversation.arun.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_run_blocks_matching_binding_when_outbox_terminal(
        self, governed_service
    ):
        """A settled approval cannot start a run again, even when the caller
        presents the binding of that very record."""
        record = await self._create_outbox_record(
            governed_service, state=OutboxState.RESULT_REPORTED
        )
        governed_service._conversation = self._governed_conversation()
        assert record.central_approval_id is not None
        binding = ActionBinding(
            central_approval_id=record.central_approval_id,
            action_event_id=record.action_event_id,
            execution_commitment=record.execution_commitment,
        )

        with pytest.raises(ActionBindingMismatchError, match="already finished"):
            await governed_service.run(expected_binding=binding)

        assert governed_service._run_task is None
        governed_service._conversation.run.assert_not_called()
        governed_service._conversation.arun.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_run_allows_bindingless_call_in_personal_mode(self, event_service):
        """The guard is gated on governance_deployment_mode == "team" itself
        (not just on the outbox being empty, which is always true in
        personal mode anyway) — see run()'s own comment for why: avoids an
        unnecessary sync file read on every personal-mode confirmation."""
        assert event_service.governance_deployment_mode == "personal"
        conversation = MagicMock()
        state = MagicMock()
        state.execution_status = ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        state.__enter__ = MagicMock(return_value=state)
        state.__exit__ = MagicMock(return_value=None)
        conversation.state = state
        conversation._state = state
        conversation._requester_identity = None
        conversation.run = MagicMock()
        event_service._conversation = conversation
        event_service._publish_state_update = AsyncMock()

        await event_service.run()

        assert event_service._run_task is not None

    # ---------------- outbox relay loop ----------------
    # _relay_outbox_once() / _outbox_relay_loop() — the only retry path for
    # a record stuck in RETRIABLE_STATES with no run activity to trigger
    # the existing per-run hooks (maybe_register_governance_approval /
    # maybe_report_governance_result only ever fire from inside this
    # conversation's own run() finally block).

    @pytest.mark.asyncio
    async def test_relay_noop_without_outbox_record(self, governed_service):
        governed_service.governance_client = MagicMock()
        await governed_service._relay_outbox_once()  # must not raise

    @pytest.mark.asyncio
    async def test_relay_noop_when_state_not_retriable(self, governed_service):
        """NEEDS_ATTENTION is deliberately excluded from RETRIABLE_STATES —
        a permanent failure must never be auto-retried."""
        await self._create_outbox_record(
            governed_service, state=OutboxState.NEEDS_ATTENTION
        )
        fake_client = MagicMock()
        fake_client.claim = AsyncMock()
        fake_client.report_result = AsyncMock()
        governed_service.governance_client = fake_client

        await governed_service._relay_outbox_once()

        fake_client.claim.assert_not_awaited()
        fake_client.report_result.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_relay_noop_without_client_configured(self, governed_service):
        await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIM_INFLIGHT
        )
        governed_service.governance_client = None
        await governed_service._relay_outbox_once()  # must not raise
        updated = governed_service.governance_outbox.load()
        assert updated.state == OutboxState.CLAIM_INFLIGHT  # unchanged

    @pytest.mark.asyncio
    async def test_relay_retries_pending_create(self, governed_service):
        """PENDING_CREATE relays through the exact same _send_create_
        approval() path maybe_register_governance_approval() already uses
        for this — reused rather than duplicated, so this test only needs
        to confirm the dispatch, not re-verify that method's own request
        shape (covered by test_create_governance_approval_success_updates_
        outbox)."""
        record = await self._create_outbox_record(
            governed_service,
            state=OutboxState.PENDING_CREATE,
            central_approval_id=None,
        )
        fake_client = MagicMock()
        fake_client.create_approval = AsyncMock(return_value={"id": "approval-new"})
        governed_service.governance_client = fake_client

        await governed_service._relay_outbox_once()

        fake_client.create_approval.assert_awaited_once()
        _, kwargs = fake_client.create_approval.call_args
        assert kwargs["idempotency_key"] == f"create-{record.request_id}"
        updated = governed_service.governance_outbox.load()
        assert updated.state == OutboxState.CREATED
        assert updated.central_approval_id == "approval-new"
        await self._drain_wait_for_decision_task(governed_service)

    @pytest.mark.asyncio
    async def test_relay_retries_claim_inflight_success(self, governed_service):
        await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIM_INFLIGHT
        )
        fake_client = MagicMock()
        fake_client.claim = AsyncMock(
            return_value={
                "execution_attempt_id": "attempt-relay",
                "executing_lease_expires_at": "2099-01-01T00:00:00+00:00",
            }
        )
        governed_service.governance_client = fake_client
        # _ensure_claim_redispatch_task()'s own behavior (driving
        # self.run() forward) is covered by its own dedicated tests below —
        # stubbed here so this test stays focused on the relay's re-claim
        # step, and so it doesn't need a real conversation to avoid an
        # orphaned background task past the end of this test.
        governed_service._ensure_claim_redispatch_task = MagicMock()

        await governed_service._relay_outbox_once()

        fake_client.claim.assert_awaited_once()
        _, kwargs = fake_client.claim.call_args
        assert kwargs["idempotency_key"] == "claim-req-1"
        updated = governed_service.governance_outbox.load()
        assert updated.state == OutboxState.CLAIMED
        assert updated.execution_attempt_id == "attempt-relay"
        # Dispatched with the record this exact call just obtained
        # (fresh execution_attempt_id), not a stale re-load.
        governed_service._ensure_claim_redispatch_task.assert_called_once()
        (dispatched_record,), _ = (
            governed_service._ensure_claim_redispatch_task.call_args
        )
        assert dispatched_record.execution_attempt_id == "attempt-relay"

    @pytest.mark.asyncio
    async def test_relay_claim_inflight_permanent_error_marks_needs_attention(
        self, governed_service
    ):
        await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIM_INFLIGHT
        )
        fake_client = MagicMock()
        fake_client.claim = AsyncMock(
            side_effect=GovernancePermanentError(
                "not found", error_code="not_found", status_code=404
            )
        )
        governed_service.governance_client = fake_client

        await governed_service._relay_outbox_once()

        updated = governed_service.governance_outbox.load()
        assert updated.state == OutboxState.NEEDS_ATTENTION

    @pytest.mark.asyncio
    async def test_relay_claim_inflight_transient_error_keeps_retrying(
        self, governed_service
    ):
        """A transient (network/5xx) failure must leave the record
        retriable — the whole point of this loop over the pre-existing
        single-attempt call sites is that a crash/network blip does not
        permanently strand the workflow after just one failed attempt."""
        await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIM_INFLIGHT
        )
        fake_client = MagicMock()
        fake_client.claim = AsyncMock(side_effect=ConnectionError("boom"))
        governed_service.governance_client = fake_client

        await governed_service._relay_outbox_once()

        updated = governed_service.governance_outbox.load()
        assert updated.state == OutboxState.CLAIM_INFLIGHT
        assert updated.attempt_count == 1

    # ---------------- _dispatch_claimed_run / _ensure_claim_redispatch_task
    # Closes the High finding from delegated review (round 2): a crash
    # between _apply_claim() and self.run() inside _claim_and_run_governed()
    # otherwise leaves a CLAIMED record with nothing left to ever call
    # run() for it again — central sees it as executing while nothing
    # local ever happens, until the lease simply expires. Unlike the
    # round-1 fix (routing through run_and_wait_for_start(), which
    # duplicated the claim call and cached a pre-dispatch failure forever
    # via _active_governance_handshake's reuse-even-when-settled
    # semantics), this dispatches directly from an already-claimed record
    # and stays genuinely retriable on failure — see CLAIMED's own
    # inclusion in RETRIABLE_STATES.

    @pytest.mark.asyncio
    async def test_dispatch_claimed_run_calls_run_with_binding(
        self, governed_service
    ):
        record = await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIMED
        )
        governed_service._conversation = self._governed_conversation()
        governed_service._publish_state_update = AsyncMock()

        await governed_service._dispatch_claimed_run(
            record,
            "approval-1",
            "attempt-1",
            "2099-01-01T00:00:00+00:00",
            future=None,
        )

        assert governed_service._run_task is not None

    @pytest.mark.asyncio
    async def test_dispatch_claimed_run_logs_and_swallows_failure_without_future(
        self, governed_service
    ):
        """No caller waiting on a result (the crash-recovery redispatch
        case, future=None) — a pre-dispatch failure (e.g. run() rejecting
        because the conversation is already running via the unrelated
        generic crash-recovery path) must not propagate out as an
        unhandled task exception, and must not be cached as terminal the
        way a real REST caller's handshake would be."""
        record = await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIMED
        )
        governed_service._closing = True  # makes self.run() raise cheaply

        await governed_service._dispatch_claimed_run(
            record,
            "approval-1",
            "attempt-1",
            "2099-01-01T00:00:00+00:00",
            future=None,
        )  # must not raise

        # Deliberately not asserted against the record's on-disk state:
        # this call never touches the outbox itself (only self.run()'s own
        # binding check would, and it never reaches that here) — the
        # "still retriable" behavior this test cares about is simply that
        # the call above returned without raising or mutating anything.

    @pytest.mark.asyncio
    async def test_dispatch_claimed_run_resolves_future_on_pre_dispatch_failure(
        self, governed_service
    ):
        """The future-bearing caller (_claim_and_run_governed(), via a
        real REST caller's run_and_wait_for_start()) still gets a
        terminal answer for *its own* request — only the no-future
        crash-recovery path treats this as retriable."""
        record = await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIMED
        )
        governed_service._closing = True
        future = asyncio.get_event_loop().create_future()

        await governed_service._dispatch_claimed_run(
            record, "approval-1", "attempt-1", "2099-01-01T00:00:00+00:00", future
        )
        # _resolve_handshake_once() schedules the actual set_result via
        # call_soon_threadsafe (thread-safety, see its own docstring) —
        # yield once so that scheduled callback actually runs.
        await asyncio.sleep(0)

        assert future.done()
        assert future.result() == GovernanceStartOutcome.REJECTED_INTERNAL_ERROR

    @pytest.mark.asyncio
    async def test_ensure_claim_redispatch_task_is_idempotent(self, governed_service):
        """_relay_outbox_once()'s periodic CLAIMED sweep and start()'s
        crash-recovery can both observe the same stuck record — must not
        spawn a second concurrent dispatch attempt for it."""
        record = await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIMED
        )
        record.execution_attempt_id = "attempt-1"
        record.executing_lease_expires_at = "2099-01-01T00:00:00+00:00"

        async def _never_returns(*args, **kwargs):
            await asyncio.sleep(1000)

        governed_service._dispatch_claimed_run = MagicMock(
            side_effect=lambda *a, **kw: _never_returns()
        )

        governed_service._ensure_claim_redispatch_task(record)
        first_task = cast(
            "asyncio.Task[None]", governed_service._claim_redispatch_task
        )
        governed_service._ensure_claim_redispatch_task(record)

        assert governed_service._claim_redispatch_task is first_task
        governed_service._dispatch_claimed_run.assert_called_once()
        first_task.cancel()
        with suppress(asyncio.CancelledError):
            await first_task

    @pytest.mark.asyncio
    async def test_ensure_claim_redispatch_task_retries_after_a_settled_failure(
        self, governed_service
    ):
        """The core fix over the round-1 design: once a redispatch attempt
        has *settled* (whether it succeeded or failed), the slot frees up
        so the next call is a genuine new attempt — not a replay of a
        cached rejection. This is what actually closes the delegated
        review's finding that a redrive with only one shot at success is
        not meaningfully different from never redriving at all."""
        record = await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIMED
        )
        record.execution_attempt_id = "attempt-1"
        record.executing_lease_expires_at = "2099-01-01T00:00:00+00:00"
        governed_service._dispatch_claimed_run = AsyncMock(return_value=None)

        governed_service._ensure_claim_redispatch_task(record)
        await governed_service._claim_redispatch_task
        governed_service._ensure_claim_redispatch_task(record)
        await governed_service._claim_redispatch_task

        assert governed_service._dispatch_claimed_run.await_count == 2

    @pytest.mark.asyncio
    async def test_relay_claimed_calls_ensure_claim_redispatch_task(
        self, governed_service
    ):
        record = await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIMED
        )
        governed_service.governance_client = MagicMock()
        governed_service._ensure_claim_redispatch_task = MagicMock()

        await governed_service._relay_outbox_once()

        governed_service._ensure_claim_redispatch_task.assert_called_once_with(record)

    @pytest.mark.asyncio
    async def test_relay_claim_inflight_success_ends_up_dispatching_run(
        self, governed_service
    ):
        """End-to-end across the seam the delegated review's third round
        flagged as untested: a CLAIM_INFLIGHT record recovered by the relay
        really does walk client.claim() -> _apply_claim() -> ActionBinding
        -> self.run() -> a scheduled _run_task, with nothing mocked out in
        between (only the fixture's own governance_client boundary and
        conversation construction are stubbed, same as every other test in
        this file that exercises a real run())."""
        await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIM_INFLIGHT
        )
        fake_client = MagicMock()
        fake_client.claim = AsyncMock(
            return_value={
                "execution_attempt_id": "attempt-e2e",
                "executing_lease_expires_at": "2099-01-01T00:00:00+00:00",
            }
        )
        governed_service.governance_client = fake_client
        governed_service._conversation = self._governed_conversation()
        governed_service._publish_state_update = AsyncMock()

        await governed_service._relay_outbox_once()
        assert governed_service._claim_redispatch_task is not None
        await governed_service._claim_redispatch_task

        assert governed_service._run_task is not None
        updated = governed_service.governance_outbox.load()
        assert updated.execution_attempt_id == "attempt-e2e"

    @pytest.mark.asyncio
    async def test_start_resumes_claimed_action_after_crash(self, governed_service):
        """A record already at CLAIMED when start() runs means a prior
        process instance's claim succeeded but self.run() was never
        reached before it stopped — dispatch immediately (no network call
        needed) rather than waiting up to
        GOVERNANCE_OUTBOX_RELAY_INTERVAL_SECONDS for the next relay
        cycle to notice (mirrors the existing CREATED/wait-for-decision
        crash-recovery just above)."""
        await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIMED
        )
        governed_service._external_lease_renewal = True
        conversation = self._governed_conversation()
        conversation._state.set_write_guard = MagicMock()
        conversation._state.set_on_state_change = MagicMock()
        governed_service._conversation = conversation
        governed_service._setup_llm_log_streaming = MagicMock()
        governed_service._setup_stats_streaming = MagicMock()
        governed_service._setup_acp_activity_heartbeat = MagicMock()
        governed_service.governance_client = MagicMock()
        governed_service._ensure_claim_redispatch_task = MagicMock()

        try:
            await governed_service.start()
        except Exception:
            pass
        finally:
            governed_service._ensure_claim_redispatch_task.assert_called_once()
            if governed_service._outbox_relay_task is not None:
                governed_service._outbox_relay_task.cancel()
                with suppress(asyncio.CancelledError):
                    await governed_service._outbox_relay_task

    @pytest.mark.asyncio
    async def test_start_does_not_immediately_redispatch_claim_inflight(
        self, governed_service
    ):
        """CLAIM_INFLIGHT (the claim call itself is still uncertain) is
        deliberately left to the relay's own periodic re-claim-with-
        classification handling rather than special-cased at startup —
        that retry needs an actual network call either way, so there is
        no "immediate and free" case to special-case here the way there
        is for an already-CLAIMED record (see start()'s own comment)."""
        await self._create_outbox_record(
            governed_service, state=OutboxState.CLAIM_INFLIGHT
        )
        governed_service._external_lease_renewal = True
        conversation = self._governed_conversation()
        conversation._state.set_write_guard = MagicMock()
        conversation._state.set_on_state_change = MagicMock()
        governed_service._conversation = conversation
        governed_service._setup_llm_log_streaming = MagicMock()
        governed_service._setup_stats_streaming = MagicMock()
        governed_service._setup_acp_activity_heartbeat = MagicMock()
        governed_service.governance_client = MagicMock()
        governed_service._ensure_claim_redispatch_task = MagicMock()

        try:
            await governed_service.start()
        except Exception:
            pass
        finally:
            governed_service._ensure_claim_redispatch_task.assert_not_called()
            if governed_service._outbox_relay_task is not None:
                governed_service._outbox_relay_task.cancel()
                with suppress(asyncio.CancelledError):
                    await governed_service._outbox_relay_task

    # ---------------- refusing actions an approver cannot see in full ----------------

    async def _register_pending(self, governed_service, action, *, conversation=None):
        """Run the real register hook for one pending ``action`` with a fake
        central client; returns (client, conversation). The conversation is a
        mock, so what is asserted is whether the hook asks it to reject."""
        client = MagicMock()
        client.create_approval = AsyncMock(return_value={"id": "approval-1"})
        governed_service.governance_client = client
        conversation = conversation or self._mock_conversation([action])
        governed_service._conversation = conversation
        governed_service._get_execution_status = AsyncMock(
            return_value=ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )
        await governed_service.maybe_register_governance_approval()
        for task in list(governed_service._pending_governance_create_tasks):
            await task
        return client, conversation

    @pytest.mark.asyncio
    async def test_truncated_action_is_refused_instead_of_sent_for_approval(
        self, governed_service
    ):
        """An approver sees a clipped preview of a long command, so nothing
        stops them approving a tail they never saw. The device refuses such an
        action itself: no central approval is created and the pending action is
        rejected with a reason the agent can act on."""
        secret = "ZZ-not-a-real-secret-ZZ"
        action = _governance_pending_action(command=f"echo {secret} " + "x" * 500)

        client, conversation = await self._register_pending(governed_service, action)

        client.create_approval.assert_not_awaited()
        assert governed_service.governance_outbox.load() is None
        conversation.reject_pending_actions.assert_called_once()
        (reason,) = conversation.reject_pending_actions.call_args.args
        assert "cannot be reviewed in full" in reason
        assert "smaller steps" in reason
        assert secret not in reason

    @pytest.mark.asyncio
    async def test_truncated_action_goes_to_central_when_the_refusal_is_turned_off(
        self, governed_service
    ):
        governed_service.governance_refuse_truncated_actions = False
        action = _governance_pending_action(command="x" * 500)

        client, conversation = await self._register_pending(governed_service, action)

        client.create_approval.assert_awaited_once()
        conversation.reject_pending_actions.assert_not_called()
        await self._drain_wait_for_decision_task(governed_service)

    @pytest.mark.asyncio
    async def test_action_shown_in_full_still_goes_to_central(self, governed_service):
        action = _governance_pending_action(command="ls")

        client, conversation = await self._register_pending(governed_service, action)

        client.create_approval.assert_awaited_once()
        conversation.reject_pending_actions.assert_not_called()
        await self._drain_wait_for_decision_task(governed_service)

    @pytest.mark.asyncio
    async def test_tool_without_a_preview_is_refused_instead_of_sent_for_approval(
        self, governed_service
    ):
        """An approver of an MCP tool's action would see only argument names:
        approval means nothing. The device refuses it itself, with a reason
        the agent can act on that does not echo anything from the action."""
        secret = "ZZ-private-query-ZZ"
        action = _governance_pending_other_action(
            "mcp_search", _NoPreviewAction(query=secret)
        )

        client, conversation = await self._register_pending(governed_service, action)

        client.create_approval.assert_not_awaited()
        assert governed_service.governance_outbox.load() is None
        conversation.reject_pending_actions.assert_called_once()
        (reason,) = conversation.reject_pending_actions.call_args.args
        assert "no approval preview" in reason
        assert "built-in tool" in reason
        assert secret not in reason
        assert "mcp_search" not in reason

    @pytest.mark.asyncio
    async def test_tool_without_a_preview_goes_to_central_when_the_refusal_is_off(
        self, governed_service
    ):
        governed_service.governance_refuse_unprojected_actions = False
        action = _governance_pending_other_action(
            "mcp_search", _NoPreviewAction(query="q")
        )

        client, conversation = await self._register_pending(governed_service, action)

        client.create_approval.assert_awaited_once()
        conversation.reject_pending_actions.assert_not_called()
        await self._drain_wait_for_decision_task(governed_service)

    @pytest.mark.asyncio
    async def test_built_in_tool_with_a_preview_still_goes_to_central(
        self, governed_service
    ):
        # browser_type shows its text length only — withheld by design, not a
        # reason to refuse.
        action = _governance_pending_other_action(
            "browser_type", BrowserTypeAction(index=1, text="hello")
        )

        client, conversation = await self._register_pending(governed_service, action)

        client.create_approval.assert_awaited_once()
        (body,), _ = client.create_approval.call_args
        assert body["action_payload"]["kind"] == "tool_args"
        assert body["action_payload"]["text_length"] == 5
        assert "hello" not in json.dumps(body)
        conversation.reject_pending_actions.assert_not_called()
        await self._drain_wait_for_decision_task(governed_service)

    @pytest.mark.asyncio
    async def test_refusal_does_not_reject_when_the_pending_action_has_changed(
        self, governed_service
    ):
        """Between the hook's check and the refusal a human may already have
        rejected the action, and a newer one may be pending.
        reject_pending_actions() rejects whatever is pending, so the refusal
        re-reads the pending action and does nothing unless it is still the one
        it refused."""
        action = _governance_pending_action(command="x" * 500)
        conversation = self._mock_conversation([action])
        conversation._state.active_branch = MagicMock(side_effect=[[action], []])

        client, _ = await self._register_pending(
            governed_service, action, conversation=conversation
        )

        client.create_approval.assert_not_awaited()
        conversation.reject_pending_actions.assert_not_called()

    @pytest.mark.asyncio
    async def test_refusal_checks_and_rejects_under_one_hold_of_the_state_lock(
        self, governed_service
    ):
        """The re-read and the rejection must happen while the conversation
        state lock is held, or a newer pending action could appear between
        them and be rejected with the wrong reason. The lock is reentrant, so
        reject_pending_actions() can take it again inside the same hold."""
        action = _governance_pending_action(command="x" * 500)
        conversation = self._mock_conversation([action])
        calls: list[str] = []
        state = conversation._state
        state.__enter__ = MagicMock(side_effect=lambda: calls.append("lock") or state)
        state.__exit__ = MagicMock(side_effect=lambda *a: calls.append("unlock"))
        state.active_branch = MagicMock(
            side_effect=lambda: calls.append("read") or [action]
        )
        conversation.reject_pending_actions = MagicMock(
            side_effect=lambda reason: calls.append("reject")
        )

        await self._register_pending(
            governed_service, action, conversation=conversation
        )

        # first hold: the register hook's own read; second hold: the refusal
        assert calls == ["lock", "read", "unlock", "lock", "read", "reject", "unlock"]

    @pytest.mark.asyncio
    async def test_refusal_that_cannot_reject_leaves_the_conversation_unapproved(
        self, governed_service
    ):
        """If rejecting fails the conversation stays waiting with no approval:
        run() still refuses it, so the safe outcome holds and the hook does not
        raise out of its fire-and-forget task."""
        action = _governance_pending_action(command="x" * 500)
        conversation = self._mock_conversation([action])
        conversation.reject_pending_actions = MagicMock(
            side_effect=RuntimeError("inactive_service")
        )

        client, _ = await self._register_pending(
            governed_service, action, conversation=conversation
        )  # must not raise

        client.create_approval.assert_not_awaited()
        assert governed_service.governance_outbox.load() is None

    async def _start_restored(self, governed_service, pending, status, client):
        """start() on a service whose persisted conversation is in ``status``
        with ``pending`` actions, as after a process restart. Only the two
        reads that describe the persisted conversation are stubbed; start()'s
        own wiring and the real register hook run."""
        governed_service._external_lease_renewal = True
        governed_service.governance_client = client
        with (
            patch.object(
                governed_service,
                "_get_execution_status",
                AsyncMock(return_value=status),
            ),
            patch.object(
                governed_service,
                "_snapshot_pending_actions_sync",
                return_value=list(pending),
            ),
        ):
            await governed_service.start()
            # let the fire-and-forget create task run to completion
            for task in list(governed_service._pending_governance_create_tasks):
                await task

    async def _stop_restored(self, governed_service) -> None:
        await self._drain_wait_for_decision_task(governed_service)
        await governed_service.close()

    @pytest.mark.asyncio
    async def test_start_registers_approval_for_conversation_restored_while_waiting(
        self, governed_service
    ):
        """After a restart a conversation persisted as WAITING_FOR_CONFIRMATION
        with one pending action and no outbox record had nothing that would
        ever register it: the register hook only runs from the end of a run,
        and no run can start (run() refuses a bindingless call, and nothing
        holds a binding for an approval that does not exist). It could only be
        rejected. start() must run the same hook once, as it already does for
        the report hook, so the pending action gets a central approval."""
        action = _governance_pending_action()
        client = MagicMock()
        client.create_approval = AsyncMock(return_value={"id": "approval-restart"})
        try:
            await self._start_restored(
                governed_service,
                [action],
                ConversationExecutionStatus.WAITING_FOR_CONFIRMATION,
                client,
            )

            client.create_approval.assert_awaited_once()
            payload = client.create_approval.call_args.args[0]
            assert payload["action_event_id"] == action.id
            record = governed_service.governance_outbox.load()
            assert record is not None
            assert record.action_event_id == action.id
            assert record.state == OutboxState.CREATED
            assert record.central_approval_id == "approval-restart"
        finally:
            await self._stop_restored(governed_service)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("status", "n_pending"),
        [
            (ConversationExecutionStatus.IDLE, 1),
            (ConversationExecutionStatus.WAITING_FOR_CONFIRMATION, 0),
            (ConversationExecutionStatus.WAITING_FOR_CONFIRMATION, 2),
        ],
        ids=["not-waiting", "waiting-no-action", "waiting-several-actions"],
    )
    async def test_start_does_not_register_unless_exactly_one_action_is_waiting(
        self, governed_service, status, n_pending
    ):
        """The restart path must keep the hook's own preconditions: nothing is
        created for a conversation that is not waiting, or whose pending
        actions are not exactly one (batch confirmations are out of scope)."""
        pending = [_governance_pending_action(f"call_{i}") for i in range(n_pending)]
        client = MagicMock()
        client.create_approval = AsyncMock(return_value={"id": "unexpected"})
        try:
            await self._start_restored(governed_service, pending, status, client)

            client.create_approval.assert_not_awaited()
            assert governed_service.governance_outbox.load() is None
        finally:
            await self._stop_restored(governed_service)

    @pytest.mark.asyncio
    async def test_real_restart_of_waiting_conversation_registers_its_approval(
        self, governed_service, tmp_path
    ):
        """No stubs on the persisted conversation: a service is started, left
        waiting for confirmation with one unmatched action and closed; a new
        service on the same directory then restarts it and must register the
        approval from what was actually persisted."""
        action = _governance_pending_action()
        governed_service._external_lease_renewal = True
        await governed_service.start()
        conversation = governed_service.get_conversation()
        with conversation._state as state:
            conversation._on_event(action)
            state.execution_status = (
                ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
            )
        await governed_service.close()

        restarted = EventService(
            stored=governed_service.stored,
            agent=governed_service.agent,
            conversations_dir=governed_service.conversations_dir,
        )
        restarted.governance_deployment_mode = "team"
        restarted.governance_origin_device_id = "device-1"
        restarted._external_lease_renewal = True
        client = MagicMock()
        client.create_approval = AsyncMock(return_value={"id": "approval-real"})
        restarted.governance_client = client
        try:
            await restarted.start()
            for task in list(restarted._pending_governance_create_tasks):
                await task

            client.create_approval.assert_awaited_once()
            record = restarted.governance_outbox.load()
            assert record is not None
            assert record.action_event_id == action.id
            assert record.state == OutboxState.CREATED
        finally:
            await self._drain_wait_for_decision_task(restarted)
            await restarted.close()

    @pytest.mark.asyncio
    async def test_real_restart_with_a_truncated_action_is_refused_not_registered(
        self, governed_service
    ):
        """Restart-time registration and the refusal of truncated actions meet
        here: a conversation persisted as waiting on an action whose preview
        would be cut must not get a central approval when it is restored, and
        the action must be rejected so the conversation is not left waiting."""
        action = _governance_pending_action(command="x" * 500)
        governed_service._external_lease_renewal = True
        await governed_service.start()
        conversation = governed_service.get_conversation()
        with conversation._state as state:
            conversation._on_event(action)
            state.execution_status = (
                ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
            )
        await governed_service.close()

        restarted = EventService(
            stored=governed_service.stored,
            agent=governed_service.agent,
            conversations_dir=governed_service.conversations_dir,
        )
        restarted.governance_deployment_mode = "team"
        restarted.governance_origin_device_id = "device-1"
        restarted._external_lease_renewal = True
        client = MagicMock()
        client.create_approval = AsyncMock()
        restarted.governance_client = client
        try:
            await restarted.start()
            for task in list(restarted._pending_governance_create_tasks):
                await task

            client.create_approval.assert_not_awaited()
            assert restarted.governance_outbox.load() is None
            assert restarted._snapshot_pending_actions_sync() == []
            status = restarted.get_conversation().state.execution_status
            assert status != ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        finally:
            await restarted.close()

    @pytest.mark.asyncio
    async def test_relay_retries_result_pending_success(self, governed_service):
        await self._create_outbox_record(
            governed_service, state=OutboxState.RESULT_PENDING
        )

        def _set_pending_report_fields(r: OutboxRecord) -> OutboxRecord:
            r.execution_attempt_id = "attempt-1"
            return _with_pending_report_outcome(r, "success")

        await governed_service.governance_outbox.mutate(_set_pending_report_fields)
        fake_client = MagicMock()
        fake_client.report_result = AsyncMock(return_value={})
        governed_service.governance_client = fake_client

        await governed_service._relay_outbox_once()

        fake_client.report_result.assert_awaited_once()
        _, kwargs = fake_client.report_result.call_args
        assert kwargs["outcome"] == "success"
        assert kwargs["idempotency_key"] == "report-attempt-1"
        updated = governed_service.governance_outbox.load()
        assert updated.state == OutboxState.RESULT_REPORTED

    @pytest.mark.asyncio
    async def test_relay_resend_attests_a_marker_that_landed_after_the_load(
        self, governed_service
    ):
        """The relay loads the record once, but the start marker is its own
        task and can land before the resend goes out; the attestation must
        come from the current record (found by review)."""
        action = _governance_pending_action()
        record = self._keyed(
            governed_service, action, self._claimed_record(governed_service, action)
        )
        record.state = OutboxState.RESULT_PENDING
        record.pending_report_outcome = "success"
        await governed_service.governance_outbox.create_record(record)
        fake_client = MagicMock()
        fake_client.report_result = AsyncMock(return_value={})
        governed_service.governance_client = fake_client

        real_mutate = governed_service.governance_outbox.mutate
        marker_pending = True

        async def _mutate_after_marker_lands(fn):
            nonlocal marker_pending
            if marker_pending:
                marker_pending = False
                await real_mutate(_with_execution_started)
            return await real_mutate(fn)

        governed_service.governance_outbox.mutate = _mutate_after_marker_lands

        await governed_service._relay_outbox_once()

        _, kwargs = fake_client.report_result.call_args
        assert kwargs["executed_commitment"] == record.execution_commitment
        assert (
            governed_service.governance_outbox.load().state
            == OutboxState.RESULT_REPORTED
        )

    @pytest.mark.parametrize(
        ("state", "expected"),
        [
            (OutboxState.CLAIMED, OutboxState.EXECUTION_STARTED),
            # The marker can arrive late. It must not pull a record that is
            # already reporting (or reported) back to EXECUTION_STARTED, which
            # the relay does not retry from.
            (OutboxState.RESULT_PENDING, OutboxState.RESULT_PENDING),
            (OutboxState.RESULT_REPORTED, OutboxState.RESULT_REPORTED),
            (OutboxState.NEEDS_ATTENTION, OutboxState.NEEDS_ATTENTION),
        ],
    )
    def test_start_marker_only_advances_a_claimed_record(
        self, governed_service, state, expected
    ):
        action = _governance_pending_action()
        record = self._claimed_record(governed_service, action)
        record.state = state

        updated = _with_execution_started(record)

        assert updated.state == expected
        # The attestation is recorded whatever the state: the check passed.
        assert updated.execution_attested is True

    @pytest.mark.asyncio
    async def test_relay_result_pending_permanent_error_marks_needs_attention(
        self, governed_service
    ):
        await self._create_outbox_record(
            governed_service, state=OutboxState.RESULT_PENDING
        )

        def _set_pending_report_fields(r: OutboxRecord) -> OutboxRecord:
            r.execution_attempt_id = "attempt-1"
            return _with_pending_report_outcome(r, "failure_unknown")

        await governed_service.governance_outbox.mutate(_set_pending_report_fields)
        fake_client = MagicMock()
        fake_client.report_result = AsyncMock(
            side_effect=GovernancePermanentError(
                "bad body", error_code="validation_error", status_code=422
            )
        )
        governed_service.governance_client = fake_client

        await governed_service._relay_outbox_once()

        updated = governed_service.governance_outbox.load()
        assert updated.state == OutboxState.NEEDS_ATTENTION

    @pytest.mark.asyncio
    async def test_start_creates_outbox_relay_task_in_team_mode(
        self, governed_service
    ):
        assert governed_service.governance_deployment_mode == "team"
        assert governed_service._outbox_relay_task is None
        governed_service._external_lease_renewal = True  # skip lease task setup

        conversation = self._governed_conversation()
        conversation._state.set_write_guard = MagicMock()
        conversation._state.set_on_state_change = MagicMock()
        governed_service._conversation = conversation
        # start() does a lot of setup unrelated to this test; only the
        # outbox-relay-task creation at the point it happens is asserted.
        governed_service._setup_llm_log_streaming = MagicMock()
        governed_service._setup_stats_streaming = MagicMock()
        governed_service._setup_acp_activity_heartbeat = MagicMock()

        try:
            await governed_service.start()
        except Exception:
            pass  # start() does much more than this test cares about
        finally:
            assert governed_service._outbox_relay_task is not None
            governed_service._outbox_relay_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await governed_service._outbox_relay_task

    @pytest.mark.asyncio
    async def test_close_cancels_outbox_relay_task(self, governed_service):
        governed_service._conversation = None  # keep close() minimal
        relay_started = asyncio.Event()

        async def _fake_relay_loop():
            try:
                relay_started.set()
                await asyncio.sleep(1000)
            except asyncio.CancelledError:
                raise

        governed_service._outbox_relay_task = asyncio.create_task(_fake_relay_loop())
        await relay_started.wait()

        await governed_service.close()

        assert governed_service._outbox_relay_task is None

    # ---------------- Phase E: wait-for-decision loop ----------------
    # _wait_for_decision_loop() / _ensure_wait_for_decision_task() — the
    # only thing in this MVP slice that ever calls run_and_wait_for_start()
    # / reject_pending_actions() on the central decide event's own
    # initiative, closing the gap where only a caller that already knew
    # central_approval_id out of band could drive a governed conversation
    # forward after CREATE.

    @pytest.mark.asyncio
    async def test_wait_for_decision_calls_run_and_wait_for_start_on_accept(
        self, governed_service
    ):
        await self._create_outbox_record(
            governed_service, state=OutboxState.CREATED
        )
        fake_client = MagicMock()
        fake_client.wait = AsyncMock(
            return_value={"id": "approval-1", "status": "accepted", "changed": True}
        )
        governed_service.governance_client = fake_client
        governed_service.run_and_wait_for_start = AsyncMock(
            return_value=GovernanceStartOutcome.STARTED
        )

        await governed_service._wait_for_decision_loop("approval-1")

        fake_client.wait.assert_awaited_once()
        _, kwargs = fake_client.wait.call_args
        assert kwargs["known_status"] == "pending"
        governed_service.run_and_wait_for_start.assert_awaited_once_with(
            central_approval_id="approval-1"
        )

    @pytest.mark.asyncio
    async def test_wait_for_decision_calls_reject_pending_actions_on_reject(
        self, governed_service
    ):
        await self._create_outbox_record(
            governed_service, state=OutboxState.CREATED
        )
        fake_client = MagicMock()
        fake_client.wait = AsyncMock(
            return_value={"id": "approval-1", "status": "rejected", "changed": True}
        )
        governed_service.governance_client = fake_client
        governed_service.reject_pending_actions = AsyncMock()

        await governed_service._wait_for_decision_loop("approval-1")

        governed_service.reject_pending_actions.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_wait_for_decision_marks_needs_attention_on_unexpected_status(
        self, governed_service
    ):
        """cancelled/expired, or any status this MVP slice's own event
        handling doesn't expect to observe here — nothing this device can
        safely automate a response to."""
        await self._create_outbox_record(
            governed_service, state=OutboxState.CREATED
        )
        fake_client = MagicMock()
        fake_client.wait = AsyncMock(
            return_value={"id": "approval-1", "status": "cancelled", "changed": True}
        )
        governed_service.governance_client = fake_client

        await governed_service._wait_for_decision_loop("approval-1")

        updated = governed_service.governance_outbox.load()
        assert updated.state == OutboxState.NEEDS_ATTENTION

    @pytest.mark.asyncio
    async def test_wait_for_decision_retries_on_unchanged_timeout(
        self, governed_service
    ):
        """changed=False is a server-side long-poll timeout with no
        decision yet — the correct response is to call /wait again
        immediately, not treat it as an error or give up."""
        await self._create_outbox_record(
            governed_service, state=OutboxState.CREATED
        )
        fake_client = MagicMock()
        fake_client.wait = AsyncMock(
            side_effect=[
                {"id": "approval-1", "status": "pending", "changed": False},
                {"id": "approval-1", "status": "accepted", "changed": True},
            ]
        )
        governed_service.governance_client = fake_client
        governed_service.run_and_wait_for_start = AsyncMock(
            return_value=GovernanceStartOutcome.STARTED
        )

        await governed_service._wait_for_decision_loop("approval-1")

        assert fake_client.wait.await_count == 2
        governed_service.run_and_wait_for_start.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_wait_for_decision_stops_when_outbox_moved_on(
        self, governed_service
    ):
        """The outbox advancing past CREATED for a reason this loop didn't
        cause (archived for a new action, or a relay cycle got there
        first) means there is nothing left for this loop to wait for —
        it must not call /wait against a record that no longer matches
        what it started watching."""
        governed_service.governance_client = MagicMock()
        # No outbox record at all — simulates archive_and_clear() having
        # already run for this conversation's next confirmation round.
        await governed_service._wait_for_decision_loop("approval-1")
        governed_service.governance_client.wait.assert_not_called()

    @pytest.mark.asyncio
    async def test_wait_for_decision_noop_without_client_configured(
        self, governed_service
    ):
        await self._create_outbox_record(
            governed_service, state=OutboxState.CREATED
        )
        governed_service.governance_client = None
        await governed_service._wait_for_decision_loop("approval-1")  # must not raise

    @pytest.mark.asyncio
    async def test_ensure_wait_for_decision_task_is_idempotent(
        self, governed_service
    ):
        """_send_create_approval calls this on every CREATE success,
        including a relay retry of a stuck PENDING_CREATE for the same
        action — must not spawn a second concurrent long-poll for the same
        approval."""
        governed_service._wait_for_decision_task = None

        async def _never_returns():
            await asyncio.sleep(1000)

        governed_service._wait_for_decision_loop = MagicMock(
            side_effect=lambda _id: _never_returns()
        )

        governed_service._ensure_wait_for_decision_task("approval-1")
        # cast: pyright's narrowing of this attribute to None (from the
        # explicit assignment above) goes stale across the mutating call
        # it doesn't do interprocedural analysis on — it really is a Task
        # here, per _ensure_wait_for_decision_task's own contract.
        first_task = cast(
            "asyncio.Task[None]", governed_service._wait_for_decision_task
        )
        governed_service._ensure_wait_for_decision_task("approval-1")

        assert governed_service._wait_for_decision_task is first_task
        first_task.cancel()
        with suppress(asyncio.CancelledError):
            await first_task

    @pytest.mark.asyncio
    async def test_start_resumes_wait_for_decision_after_crash(
        self, governed_service
    ):
        """A record already at CREATED when start() runs means a prior
        process instance sent create and was waiting on decide when it
        stopped — resume watching it rather than leaving it to sit until
        some other trigger notices (the relay loop's own state-by-state
        handling doesn't touch CREATED at all; see _relay_outbox_once)."""
        await self._create_outbox_record(
            governed_service, state=OutboxState.CREATED
        )
        governed_service._external_lease_renewal = True  # skip lease task setup
        conversation = self._governed_conversation()
        conversation._state.set_write_guard = MagicMock()
        conversation._state.set_on_state_change = MagicMock()
        governed_service._conversation = conversation
        governed_service._setup_llm_log_streaming = MagicMock()
        governed_service._setup_stats_streaming = MagicMock()
        governed_service._setup_acp_activity_heartbeat = MagicMock()
        governed_service.governance_client = MagicMock()
        governed_service.governance_client.wait = AsyncMock(
            return_value={"id": "approval-1", "status": "pending", "changed": False}
        )

        try:
            await governed_service.start()
        except Exception:
            pass  # start() does much more than this test cares about
        finally:
            assert governed_service._wait_for_decision_task is not None
            governed_service._wait_for_decision_task.cancel()
            with suppress(asyncio.CancelledError):
                await governed_service._wait_for_decision_task
            if governed_service._outbox_relay_task is not None:
                governed_service._outbox_relay_task.cancel()
                with suppress(asyncio.CancelledError):
                    await governed_service._outbox_relay_task

    @pytest.mark.asyncio
    async def test_close_cancels_wait_for_decision_task(self, governed_service):
        governed_service._conversation = None  # keep close() minimal
        wait_started = asyncio.Event()

        async def _fake_wait_loop():
            try:
                wait_started.set()
                await asyncio.sleep(1000)
            except asyncio.CancelledError:
                raise

        governed_service._wait_for_decision_task = asyncio.create_task(
            _fake_wait_loop()
        )
        await wait_started.wait()

        await governed_service.close()

        assert governed_service._wait_for_decision_task is None


# Module-level on purpose: a function-local SecretSource subclass auto-registers
# globally (see tests/sdk/conversation/test_secrets_manager.py).
_UPDATE_SECRETS_LOOP: list[asyncio.AbstractEventLoop] = []
_UPDATE_SECRETS_VALUE = "value-served-by-the-loop"


class LoopAnsweredSource(SecretSource):
    """Completes only if the event loop is free to answer, like a LookupSecret
    whose URL points back at this very server."""

    def get_value(self):
        answered = threading.Event()
        _UPDATE_SECRETS_LOOP[0].call_soon_threadsafe(answered.set)
        if not answered.wait(3.0):
            raise OSError("ReadTimeout: the loop was blocked while we waited")
        return _UPDATE_SECRETS_VALUE


@pytest.mark.asyncio
async def test_update_secrets_resolves_new_sources_before_a_loop_thread_mask(
    event_service,
):
    """A secret added while arun() is mid-step must not be first resolved by the
    loop-thread masking at the end of that step: arun() only pre-resolves at the
    start of each iteration, so the update itself has to do it, off the loop."""
    registry = SecretRegistry()
    conversation = MagicMock()
    conversation.state.secret_registry = registry
    conversation.update_secrets.side_effect = registry.update_secrets
    event_service._conversation = conversation
    _UPDATE_SECRETS_LOOP[:] = [asyncio.get_running_loop()]

    await asyncio.wait_for(
        event_service.update_secrets({"TOKEN": LoopAnsweredSource()}), timeout=10
    )

    assert not registry.has_unresolved_sources()
    # What the end-of-step masking on the loop thread will now find: nothing to do.
    assert registry.mask_secrets_in_output(f"leak: {_UPDATE_SECRETS_VALUE}") == (
        "leak: <secret-hidden>"
    )

