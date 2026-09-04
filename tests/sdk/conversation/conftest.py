"""Shared test fixtures for conversation tests."""

from unittest.mock import Mock

from openhands.sdk.event import HookExecutionEvent
from openhands.sdk.security.roy_audit_hooks import _WRITER_SCRIPT_PATH


def non_governance_audit_events(events):
    """Filter out the governance-mandated SessionStart audit hook's
    HookExecutionEvent (see roy_audit_hooks.py, which fires that hook on
    every conversation) from a conversation's event list.

    Deliberately narrower than "every HookExecutionEvent": matches on the
    writer script path embedded in this specific hook's command, so a
    test's own PreToolUse/Stop/custom-SessionStart hook still shows up and
    can be asserted on normally — only this one infrastructure event, which
    predates most tests' own scenarios, gets filtered out. Not airtight: a
    test that deliberately crafts a hook command containing this same path
    as a substring (e.g. to test path-argument handling) would also get
    filtered — not a concern for anything in this test suite today.
    """
    return [
        e
        for e in events
        if not (
            isinstance(e, HookExecutionEvent) and _WRITER_SCRIPT_PATH in e.hook_command
        )
    ]


def create_mock_http_client(conversation_id: str | None = None):
    """Create a comprehensive mock HTTP client for RemoteConversation.

    This helper creates a mock httpx.Client that properly handles both
    POST and GET requests with appropriate mock responses.

    Args:
        conversation_id: Optional specific conversation ID to use for mocking.
                        If not provided, a fixed test ID will be used.
    """
    # Use a fixed conversation ID for testing if not provided
    if conversation_id is None:
        conversation_id = "12345678-1234-5678-9abc-123456789abc"

    mock_client = Mock()

    # Mock POST response for conversation creation
    mock_post_response = Mock()
    mock_post_response.raise_for_status.return_value = None
    mock_post_response.json.return_value = {"id": conversation_id}

    # Mock GET response for events sync
    mock_get_response = Mock()
    mock_get_response.raise_for_status.return_value = None
    mock_get_response.json.return_value = {"items": []}

    # Configure the request method to return appropriate responses
    def mock_request(method, url, **kwargs):
        if method == "POST":
            return mock_post_response
        elif method == "GET":
            return mock_get_response
        else:
            # Default response
            response = Mock()
            response.raise_for_status.return_value = None
            response.json.return_value = {}
            return response

    mock_client.request = Mock(side_effect=mock_request)
    mock_client.post = Mock(return_value=mock_post_response)
    mock_client.get = Mock(return_value=mock_get_response)

    return mock_client
