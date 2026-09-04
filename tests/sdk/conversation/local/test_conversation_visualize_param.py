"""Tests for the Conversation class visualize parameter."""

from unittest.mock import Mock, patch

import pytest
from pydantic import SecretStr

from openhands.sdk.agent import Agent
from openhands.sdk.conversation import Conversation
from openhands.sdk.conversation.visualizer import (
    DefaultConversationVisualizer,
)
from openhands.sdk.event.llm_convertible import MessageEvent
from openhands.sdk.llm import LLM, Message, TextContent


def create_test_event(content: str = "Test event content") -> MessageEvent:
    """Create a test MessageEvent for testing."""
    return MessageEvent(
        llm_message=Message(role="user", content=[TextContent(text=content)]),
        source="user",
    )


def assert_stamped_event_matches(actual: MessageEvent, expected: MessageEvent) -> None:
    """Compare an event a callback actually received against the one passed
    to on_event(), tolerating only the one field the callback chain is
    expected to change.

    The composed callback tree-stamps parent_id onto events before
    callbacks see them (pointing at the governance SessionStart audit
    hook's own event, since it's no longer the first event once that hook
    has fired) — so the object a callback receives is a stamped copy, not
    the original. Normalizing just that field keeps this able to catch any
    other unintended mutation (content, source, timestamp, ...).
    """
    assert actual.model_copy(update={"parent_id": expected.parent_id}) == expected


@pytest.fixture
def mock_agent():
    """Create a real agent for testing."""
    llm = LLM(model="gpt-4o-mini", api_key=SecretStr("test-key"), usage_id="test-llm")
    agent = Agent(llm=llm, tools=[])
    return agent


def test_conversation_with_default_visualizer(mock_agent):
    """Test Conversation with default visualizer (omitted parameter)."""
    with patch.object(Agent, "init_state") as mock_init_state:
        conversation = Conversation(agent=mock_agent)

        # Should have a visualizer
        assert conversation._visualizer is not None
        assert isinstance(conversation._visualizer, DefaultConversationVisualizer)

        # Agent initialization is lazy; trigger it explicitly
        conversation._ensure_agent_ready()

        # Agent should be initialized with callbacks that include visualizer
        mock_init_state.assert_called_once()
        args, kwargs = mock_init_state.call_args
        assert "on_event" in kwargs

        # The on_event callback should be composed of multiple callbacks
        on_event = kwargs["on_event"]
        assert callable(on_event)


def test_conversation_with_visualize_false(mock_agent):
    """Test Conversation with visualizer=None."""
    with patch.object(Agent, "init_state") as mock_init_state:
        conversation = Conversation(agent=mock_agent, visualizer=None)

        # Should not have a visualizer
        assert conversation._visualizer is None

        # Agent initialization is lazy; trigger it explicitly
        conversation._ensure_agent_ready()

        # Agent should still be initialized with callbacks (just not visualizer)
        mock_init_state.assert_called_once()
        args, kwargs = mock_init_state.call_args
        assert "on_event" in kwargs

        # The on_event callback should still exist (for state persistence)
        on_event = kwargs["on_event"]
        assert callable(on_event)


def test_conversation_default_visualize_is_true(mock_agent):
    """Test that visualizer defaults to default visualizer."""
    with patch.object(Agent, "init_state"):
        conversation = Conversation(agent=mock_agent)

        # Should have a visualizer by default
        assert conversation._visualizer is not None
        assert isinstance(conversation._visualizer, DefaultConversationVisualizer)


def test_conversation_with_custom_callbacks_and_default_visualizer(mock_agent):
    """Test Conversation with custom callbacks and default visualizer."""
    custom_callback = Mock()
    callbacks = [custom_callback]

    with patch.object(Agent, "init_state") as mock_init_state:
        conversation = Conversation(agent=mock_agent, callbacks=callbacks)

        # Should have a visualizer
        assert conversation._visualizer is not None

        # Agent initialization is lazy; trigger it explicitly
        conversation._ensure_agent_ready()

        # Test that callbacks are composed correctly by triggering an event
        mock_init_state.assert_called_once()
        args, kwargs = mock_init_state.call_args
        on_event = kwargs["on_event"]

        # _ensure_agent_ready() already ran the governance SessionStart audit
        # hook through this same callback chain once (see roy_audit_hooks.py)
        # — reset so the assertions below observe only the event triggered
        # explicitly next.
        custom_callback.reset_mock()

        # Create a test event
        test_event = create_test_event("Test event content")
        on_event(test_event)

        # Custom callback should have been called. Not
        # assert_called_once_with(test_event) — see assert_stamped_event_
        # matches()'s docstring for why the object that actually reaches
        # custom_callback is a stamped copy, not test_event itself.
        custom_callback.assert_called_once()
        assert_stamped_event_matches(custom_callback.call_args.args[0], test_event)

        # Event should be in conversation state
        stored_event = next(
            e for e in conversation.state.events if e.id == test_event.id
        )
        assert_stamped_event_matches(stored_event, test_event)


def test_conversation_with_custom_callbacks_and_visualize_false(mock_agent):
    """Test Conversation with custom callbacks and visualize=False."""
    custom_callback = Mock()
    callbacks = [custom_callback]

    with patch.object(Agent, "init_state") as mock_init_state:
        conversation = Conversation(
            agent=mock_agent, callbacks=callbacks, visualizer=None
        )

        # Should not have a visualizer
        assert conversation._visualizer is None

        # Agent initialization is lazy; trigger it explicitly
        conversation._ensure_agent_ready()

        # Test that callbacks are composed correctly
        mock_init_state.assert_called_once()
        args, kwargs = mock_init_state.call_args
        on_event = kwargs["on_event"]

        # _ensure_agent_ready() already ran the governance SessionStart audit
        # hook through this same callback chain once — reset so the
        # assertions below observe only the event triggered explicitly next.
        custom_callback.reset_mock()

        # Create a test event and trigger it
        test_event = create_test_event("Test event content")
        on_event(test_event)

        # Custom callback should have been called. Not
        # assert_called_once_with(test_event) — see assert_stamped_event_
        # matches()'s docstring for why.
        custom_callback.assert_called_once()
        assert_stamped_event_matches(custom_callback.call_args.args[0], test_event)

        # Event should be in conversation state
        stored_event = next(
            e for e in conversation.state.events if e.id == test_event.id
        )
        assert_stamped_event_matches(stored_event, test_event)


def test_conversation_callback_order(mock_agent):
    """Test that callbacks are executed in the correct order."""
    call_order = []

    def callback1(event):
        call_order.append("callback1")

    def callback2(event):
        call_order.append("callback2")

    # Create a custom visualizer that tracks when it's called
    with patch.object(Agent, "init_state") as mock_init_state:
        # Create a mock visualizer instance
        mock_visualizer = Mock(spec=DefaultConversationVisualizer)
        mock_visualizer.on_event = Mock(
            side_effect=lambda e: call_order.append("visualizer")
        )

        conversation = Conversation(
            agent=mock_agent,
            callbacks=[callback1, callback2],
            visualizer=mock_visualizer,
        )

        # Agent initialization is lazy; trigger it explicitly
        conversation._ensure_agent_ready()

        # Get the composed callback
        mock_init_state.assert_called_once()
        args, kwargs = mock_init_state.call_args
        on_event = kwargs["on_event"]

        # _ensure_agent_ready() already ran the governance SessionStart audit
        # hook through this same callback chain once — clear so the
        # assertion below observes only the event triggered explicitly next.
        call_order.clear()

        # Trigger an event
        test_event = create_test_event("Test event content")
        on_event(test_event)

        # Check order: visualizer, callback1, callback2, then state persistence
        assert call_order == ["visualizer", "callback1", "callback2"]

        # Event should be in state (state persistence happens last)
        assert test_event in conversation.state.events


def test_conversation_no_callbacks_with_default_visualizer(mock_agent):
    """Test Conversation with no custom callbacks but default visualizer."""
    with patch.object(Agent, "init_state") as mock_init_state:
        conversation = Conversation(agent=mock_agent, callbacks=None)

        # Should have a visualizer
        assert conversation._visualizer is not None

        # Agent initialization is lazy; trigger it explicitly
        conversation._ensure_agent_ready()

        # Should still work with just visualizer and state persistence
        mock_init_state.assert_called_once()
        args, kwargs = mock_init_state.call_args
        on_event = kwargs["on_event"]

        # Should be able to handle events
        test_event = create_test_event("Test event content")
        on_event(test_event)

        # Event should be in state
        assert test_event in conversation.state.events


def test_conversation_no_callbacks_with_visualize_false(mock_agent):
    """Test Conversation with no custom callbacks and visualize=False."""
    with patch.object(Agent, "init_state") as mock_init_state:
        conversation = Conversation(agent=mock_agent, callbacks=None, visualizer=None)

        # Should not have a visualizer
        assert conversation._visualizer is None

        # Agent initialization is lazy; trigger it explicitly
        conversation._ensure_agent_ready()

        # Should still work with just state persistence
        mock_init_state.assert_called_once()
        args, kwargs = mock_init_state.call_args
        on_event = kwargs["on_event"]

        # Should be able to handle events
        test_event = create_test_event("Test event content")
        on_event(test_event)

        # Event should be in state
        assert test_event in conversation.state.events


def test_conversation_with_custom_visualizer_instance(mock_agent):
    """Test Conversation with a custom DefaultConversationVisualizer instance."""
    # Create a custom visualizer
    custom_visualizer = DefaultConversationVisualizer(
        highlight_regex={"Test:": "bold red"},
        skip_user_messages=True,
    )

    with patch.object(Agent, "init_state") as mock_init_state:
        conversation = Conversation(agent=mock_agent, visualizer=custom_visualizer)

        # Should use the custom visualizer
        assert conversation._visualizer is custom_visualizer
        assert isinstance(conversation._visualizer, DefaultConversationVisualizer)

        # Agent initialization is lazy; trigger it explicitly
        conversation._ensure_agent_ready()

        # Agent should be initialized with callbacks that include the custom visualizer
        mock_init_state.assert_called_once()
        args, kwargs = mock_init_state.call_args
        assert "on_event" in kwargs

        # The on_event callback should be composed of multiple callbacks
        on_event = kwargs["on_event"]
        assert callable(on_event)


def test_conversation_with_custom_visualizer_and_callbacks(mock_agent):
    """Test Conversation with custom visualizer and custom callbacks."""
    custom_callback = Mock()
    callbacks = [custom_callback]

    # Create a custom visualizer with mocked on_event to track calls
    custom_visualizer = Mock(spec=DefaultConversationVisualizer)
    custom_visualizer.on_event = Mock()

    with patch.object(Agent, "init_state") as mock_init_state:
        conversation = Conversation(
            agent=mock_agent, callbacks=callbacks, visualizer=custom_visualizer
        )

        # Should use the custom visualizer
        assert conversation._visualizer is custom_visualizer

        # Agent initialization is lazy; trigger it explicitly
        conversation._ensure_agent_ready()

        # Test that callbacks are composed correctly
        mock_init_state.assert_called_once()
        args, kwargs = mock_init_state.call_args
        on_event = kwargs["on_event"]

        # _ensure_agent_ready() already ran the governance SessionStart audit
        # hook through this same callback chain once — reset so the
        # assertions below observe only the event triggered explicitly next.
        custom_visualizer.on_event.reset_mock()
        custom_callback.reset_mock()

        # Create a test event and trigger it
        test_event = create_test_event("Test event content")
        on_event(test_event)

        # Both custom visualizer and custom callback should have been
        # called. Not assert_called_once_with(test_event) — see
        # assert_stamped_event_matches()'s docstring for why.
        custom_visualizer.on_event.assert_called_once()
        assert_stamped_event_matches(
            custom_visualizer.on_event.call_args.args[0], test_event
        )
        custom_callback.assert_called_once()
        assert_stamped_event_matches(custom_callback.call_args.args[0], test_event)

        # Event should be in conversation state
        stored_event = next(
            e for e in conversation.state.events if e.id == test_event.id
        )
        assert_stamped_event_matches(stored_event, test_event)


def test_conversation_with_visualize_none(mock_agent):
    """Test Conversation with visualize=None (no visualization)."""
    with patch.object(Agent, "init_state") as mock_init_state:
        conversation = Conversation(agent=mock_agent, visualizer=None)

        # Should not have a visualizer
        assert conversation._visualizer is None

        # Agent initialization is lazy; trigger it explicitly
        conversation._ensure_agent_ready()

        # Agent should still be initialized with callbacks (just not visualizer)
        mock_init_state.assert_called_once()
        args, kwargs = mock_init_state.call_args
        assert "on_event" in kwargs

        # The on_event callback should still exist (for state persistence)
        on_event = kwargs["on_event"]
        assert callable(on_event)


def test_conversation_with_visualizer_class(mock_agent):
    """Test Conversation with a visualizer class (not instance)."""
    with patch.object(Agent, "init_state") as mock_init_state:
        # Pass the class itself, not an instance
        conversation = Conversation(
            agent=mock_agent,
            visualizer=DefaultConversationVisualizer,
        )

        # Should have instantiated the visualizer
        assert conversation._visualizer is not None
        assert isinstance(conversation._visualizer, DefaultConversationVisualizer)

        # Agent initialization is lazy; trigger it explicitly
        conversation._ensure_agent_ready()

        # Agent should be initialized with callbacks that include visualizer
        mock_init_state.assert_called_once()
        args, kwargs = mock_init_state.call_args
        assert "on_event" in kwargs

        # The on_event callback should be composed of multiple callbacks
        on_event = kwargs["on_event"]
        assert callable(on_event)
