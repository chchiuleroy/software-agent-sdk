"""Tests for the agent server API functionality."""

import asyncio
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from openhands.agent_server.api import (
    _default_server_tmux_tmpdir,
    _ensure_server_tmux_tmpdir,
    _get_root_path,
    api_lifespan,
    create_app,
)
from openhands.agent_server.config import Config


@pytest.fixture(autouse=True)
def clear_web_url_env(monkeypatch):
    monkeypatch.delenv("OH_WEB_URL", raising=False)
    monkeypatch.delenv("RUNTIME_URL", raising=False)
    monkeypatch.delenv("TMUX_TMPDIR", raising=False)


def test_default_server_tmux_tmpdir_uses_current_pid(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "openhands.agent_server.api.tempfile.gettempdir", lambda: str(tmp_path)
    )

    assert _default_server_tmux_tmpdir() == (
        tmp_path / f"openhands-agent-server-{os.getpid()}"
    )


def test_ensure_server_tmux_tmpdir_defaults_per_process_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "openhands.agent_server.api.tempfile.gettempdir", lambda: str(tmp_path)
    )

    tmux_tmpdir, was_defaulted = _ensure_server_tmux_tmpdir()

    assert was_defaulted is True
    assert tmux_tmpdir == tmp_path / f"openhands-agent-server-{os.getpid()}"
    assert tmux_tmpdir.is_dir()
    assert os.environ["TMUX_TMPDIR"] == str(tmux_tmpdir)


def test_ensure_server_tmux_tmpdir_respects_existing_env(tmp_path, monkeypatch):
    existing = tmp_path / "custom-tmux"
    monkeypatch.setenv("TMUX_TMPDIR", str(existing))

    tmux_tmpdir, was_defaulted = _ensure_server_tmux_tmpdir()

    assert was_defaulted is False
    assert tmux_tmpdir == existing
    assert not existing.exists()


class TestStaticFilesServing:
    """Test static files serving functionality."""

    def test_static_files_not_mounted_when_path_none(self):
        """Test that static files are not mounted when static_files_path is None."""
        config = Config(static_files_path=None)
        app = create_app(config)
        client = TestClient(app)

        # Try to access static files endpoint - should return 404
        response = client.get("/static/test.txt")
        assert response.status_code == 404

    def test_static_files_not_mounted_when_directory_missing(self):
        """Test that static files are not mounted when directory doesn't exist."""
        config = Config(static_files_path=Path("/nonexistent/directory"))
        app = create_app(config)
        client = TestClient(app)

        # Try to access static files endpoint - should return 404
        response = client.get("/static/test.txt")
        assert response.status_code == 404

    def test_static_files_mounted_when_directory_exists(self):
        """Test that static files are mounted when directory exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            static_dir = Path(temp_dir)

            # Create a test file
            test_file = static_dir / "test.txt"
            test_file.write_text("Hello, static world!")

            config = Config(static_files_path=static_dir)
            app = create_app(config)
            client = TestClient(app)

            # Access the static file
            response = client.get("/static/test.txt")
            assert response.status_code == 200
            assert response.text == "Hello, static world!"
            assert response.headers["content-type"] == "text/plain; charset=utf-8"

    def test_static_files_serve_html(self):
        """Test that static files can serve HTML files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            static_dir = Path(temp_dir)

            # Create an HTML test file
            html_file = static_dir / "index.html"
            html_content = "<html><body><h1>Static HTML</h1></body></html>"
            html_file.write_text(html_content)

            config = Config(static_files_path=static_dir)
            app = create_app(config)
            client = TestClient(app)

            # Access the HTML file
            response = client.get("/static/index.html")
            assert response.status_code == 200
            assert response.text == html_content
            assert "text/html" in response.headers["content-type"]

    def test_static_files_serve_subdirectory(self):
        """Test that static files can serve files from subdirectories."""
        with tempfile.TemporaryDirectory() as temp_dir:
            static_dir = Path(temp_dir)

            # Create a subdirectory with a file
            sub_dir = static_dir / "assets"
            sub_dir.mkdir()
            css_file = sub_dir / "style.css"
            css_content = "body { color: blue; }"
            css_file.write_text(css_content)

            config = Config(static_files_path=static_dir)
            app = create_app(config)
            client = TestClient(app)

            # Access the CSS file in subdirectory
            response = client.get("/static/assets/style.css")
            assert response.status_code == 200
            assert response.text == css_content
            assert "text/css" in response.headers["content-type"]

    def test_static_files_404_for_missing_file(self):
        """Test that missing static files return 404."""
        with tempfile.TemporaryDirectory() as temp_dir:
            static_dir = Path(temp_dir)

            config = Config(static_files_path=static_dir)
            app = create_app(config)
            client = TestClient(app)

            # Try to access non-existent file
            response = client.get("/static/nonexistent.txt")
            assert response.status_code == 404

    def test_static_files_security_no_directory_traversal(self):
        """Test that directory traversal attacks are prevented."""
        with tempfile.TemporaryDirectory() as temp_dir:
            static_dir = Path(temp_dir)

            # Create a file outside the static directory
            parent_dir = Path(temp_dir).parent
            secret_file = parent_dir / "secret.txt"
            secret_file.write_text("Secret content")

            config = Config(static_files_path=static_dir)
            app = create_app(config)
            client = TestClient(app)

            # Try directory traversal attack
            response = client.get("/static/../secret.txt")
            assert response.status_code == 404

        # Clean up the secret file
        if secret_file.exists():
            secret_file.unlink()


class TestRootRedirect:
    """Test root endpoint redirect functionality."""

    def test_root_redirect_to_index_html_when_exists(self):
        """Test that root endpoint redirects to /static/index.html when it exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            static_dir = Path(temp_dir)

            # Create an index.html file
            index_file = static_dir / "index.html"
            index_file.write_text("<html><body><h1>Welcome</h1></body></html>")

            config = Config(static_files_path=static_dir)
            app = create_app(config)
            client = TestClient(app)

            # Test root redirect
            response = client.get("/", follow_redirects=False)
            assert response.status_code == 302
            assert response.headers["location"] == "/static/index.html"

    def test_root_redirect_to_static_dir_when_no_index(self):
        """Test that root endpoint redirects to /static/ when no index.html exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            static_dir = Path(temp_dir)

            # Create a different file (not index.html)
            other_file = static_dir / "other.html"
            other_file.write_text("<html><body><h1>Other</h1></body></html>")

            config = Config(static_files_path=static_dir)
            app = create_app(config)
            client = TestClient(app)

            # Test root redirect
            response = client.get("/", follow_redirects=False)
            assert response.status_code == 302
            assert response.headers["location"] == "/static/"

    def test_root_redirect_follows_to_index_html(self):
        """Test that following the root redirect serves index.html when it exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            static_dir = Path(temp_dir)

            # Create an index.html file
            index_file = static_dir / "index.html"
            index_content = "<html><body><h1>Welcome to Static Site</h1></body></html>"
            index_file.write_text(index_content)

            config = Config(static_files_path=static_dir)
            app = create_app(config)
            client = TestClient(app)

            # Test root redirect with follow_redirects=True
            response = client.get("/", follow_redirects=True)
            assert response.status_code == 200
            assert response.text == index_content
            assert "text/html" in response.headers["content-type"]

    def test_no_root_redirect_when_static_files_not_configured(self):
        """Test that root endpoint doesn't redirect when static files are not configured."""  # noqa: E501
        config = Config(static_files_path=None)
        app = create_app(config)
        client = TestClient(app)

        # Root should return 404 (no handler defined)
        response = client.get("/")
        assert response.status_code == 200

    def test_no_root_redirect_when_static_directory_missing(self):
        """Test that root endpoint doesn't redirect when static directory doesn't exist."""  # noqa: E501
        config = Config(static_files_path=Path("/nonexistent/directory"))
        app = create_app(config)
        client = TestClient(app)

        # Root should return 404 (no handler defined)
        response = client.get("/")
        assert response.status_code == 200


class TestServiceParallelization:
    """Test that services are started and stopped in parallel."""

    async def test_services_start_in_parallel(self):
        """Test that VSCode and Tool Preload services start concurrently."""
        # Create mock services that take some time to start
        mock_vscode_service = AsyncMock()
        mock_tool_preload_service = AsyncMock()
        mock_conversation_service = AsyncMock()

        active_starts = 0
        max_concurrent_starts = 0
        start_lock = asyncio.Lock()

        async def slow_start():
            nonlocal active_starts, max_concurrent_starts
            async with start_lock:
                active_starts += 1
                max_concurrent_starts = max(max_concurrent_starts, active_starts)

            await asyncio.sleep(0.1)

            async with start_lock:
                active_starts -= 1

            return True

        mock_vscode_service.start = AsyncMock(side_effect=slow_start)
        mock_tool_preload_service.start = AsyncMock(side_effect=slow_start)

        # Mock the service getters
        with (
            patch(
                "openhands.agent_server.api.get_default_conversation_service",
                return_value=mock_conversation_service,
            ),
            patch(
                "openhands.agent_server.api.get_vscode_service",
                return_value=mock_vscode_service,
            ),
            patch(
                "openhands.agent_server.api.get_tool_preload_service",
                return_value=mock_tool_preload_service,
            ),
        ):
            # Create a mock FastAPI app
            mock_app = AsyncMock()
            mock_app.state = SimpleNamespace(config=Config())

            async with api_lifespan(mock_app):
                pass

            assert max_concurrent_starts == 2

            # Verify all services were started
            mock_vscode_service.start.assert_called_once()
            mock_tool_preload_service.start.assert_called_once()

    async def test_services_stop_in_parallel(self):
        """Test that VSCode and Tool Preload services stop concurrently."""
        # Create mock services that take some time to stop
        mock_vscode_service = AsyncMock()
        mock_tool_preload_service = AsyncMock()
        mock_conversation_service = AsyncMock()

        # Make each service take 0.1 seconds to stop
        async def slow_stop():
            await asyncio.sleep(0.1)

        mock_vscode_service.start = AsyncMock(return_value=True)
        mock_tool_preload_service.start = AsyncMock(return_value=True)
        mock_vscode_service.stop = AsyncMock(side_effect=slow_stop)
        mock_tool_preload_service.stop = AsyncMock(side_effect=slow_stop)

        # Mock the service getters
        with (
            patch(
                "openhands.agent_server.api.get_default_conversation_service",
                return_value=mock_conversation_service,
            ),
            patch(
                "openhands.agent_server.api.get_vscode_service",
                return_value=mock_vscode_service,
            ),
            patch(
                "openhands.agent_server.api.get_tool_preload_service",
                return_value=mock_tool_preload_service,
            ),
        ):
            # Create a mock FastAPI app
            mock_app = AsyncMock()
            mock_app.state = SimpleNamespace(config=Config())

            async with api_lifespan(mock_app):
                # Exit the context to trigger shutdown
                pass

            # Verify all services were stopped
            mock_vscode_service.stop.assert_called_once()
            mock_tool_preload_service.stop.assert_called_once()

    async def test_services_handle_none_values(self):
        """Test that the lifespan handles None service values correctly."""
        mock_conversation_service = AsyncMock()

        # Mock all services as None (disabled)
        with (
            patch(
                "openhands.agent_server.api.get_default_conversation_service",
                return_value=mock_conversation_service,
            ),
            patch("openhands.agent_server.api.get_vscode_service", return_value=None),
            patch(
                "openhands.agent_server.api.get_tool_preload_service", return_value=None
            ),
        ):
            # Create a mock FastAPI app
            mock_app = AsyncMock()
            mock_app.state = SimpleNamespace(config=Config())

            # This should not raise any exceptions
            async with api_lifespan(mock_app):
                pass

            # Verify conversation service was set up
            assert mock_app.state.conversation_service == mock_conversation_service

    async def test_lifespan_defaults_and_restores_tmux_tmpdir(
        self, tmp_path, monkeypatch
    ):
        """Test that lifespan defaults TMUX_TMPDIR per server instance."""
        monkeypatch.setattr(
            "openhands.agent_server.api.tempfile.gettempdir", lambda: str(tmp_path)
        )
        mock_conversation_service = AsyncMock()

        with (
            patch(
                "openhands.agent_server.api.get_default_conversation_service",
                return_value=mock_conversation_service,
            ),
            patch("openhands.agent_server.api.get_vscode_service", return_value=None),
            patch(
                "openhands.agent_server.api.get_tool_preload_service", return_value=None
            ),
        ):
            mock_app = AsyncMock()
            mock_app.state = SimpleNamespace(config=Config())
            expected_tmux_tmpdir = tmp_path / f"openhands-agent-server-{os.getpid()}"

            async with api_lifespan(mock_app):
                assert os.environ["TMUX_TMPDIR"] == str(expected_tmux_tmpdir)

            assert "TMUX_TMPDIR" not in os.environ


class TestRootPath:
    """Tests for _get_root_path function and root_path configuration."""

    def test_get_root_path_returns_slash_when_web_url_is_none(self):
        """Test that _get_root_path returns '' when web_url is not configured."""
        config = Config(web_url=None)
        assert _get_root_path(config) == ""

    def test_get_root_path_extracts_path_from_url(self):
        """Test that _get_root_path extracts the path component from web_url."""
        config = Config(web_url="https://example.com/runtime/123")
        assert _get_root_path(config) == "/runtime/123"

    def test_get_root_path_returns_slash_for_root_url(self):
        """Test that _get_root_path returns '/' for a URL without path."""
        config = Config(web_url="https://example.com")
        assert _get_root_path(config) == ""

    def test_get_root_path_with_trailing_slash(self):
        """Test that _get_root_path preserves trailing slash."""
        config = Config(web_url="https://example.com/api/")
        assert _get_root_path(config) == "/api"

    def test_get_root_path_with_complex_path(self):
        """Test _get_root_path with a complex nested path."""
        config = Config(
            web_url="https://work-1-abc123.prod-runtime.all-hands.dev/runtime/456/api"
        )
        assert _get_root_path(config) == "/runtime/456/api"

    def test_fastapi_instance_uses_root_path(self):
        """Test that FastAPI instance is created with correct root_path."""
        config = Config(web_url="https://example.com/mypath")
        app = create_app(config)
        assert app.root_path == "/mypath"

    def test_fastapi_instance_uses_default_root_path_when_no_web_url(self):
        """Test that FastAPI instance uses '/' root_path when web_url is None."""
        config = Config(web_url=None)
        app = create_app(config)
        assert app.root_path == ""


class TestConfigWebUrl:
    """Tests for web_url configuration field."""

    def test_web_url_default_is_none_when_env_not_set(self):
        """Test that web_url defaults to None when no env vars are set."""
        with patch.dict("os.environ", {}, clear=True):
            config = Config()
            assert config.web_url is None

    def test_web_url_reads_from_oh_web_url_env(self):
        """Test that web_url reads from the canonical OH_WEB_URL env var."""
        with patch.dict("os.environ", {"OH_WEB_URL": "https://test.example.com/path"}):
            config = Config()
            assert config.web_url == "https://test.example.com/path"

    def test_web_url_ignores_legacy_runtime_url_env(self):
        """Test that deprecated RUNTIME_URL no longer configures web_url."""
        with patch.dict("os.environ", {"RUNTIME_URL": "https://test.example.com/path"}):
            config = Config()

        assert config.web_url is None

    def test_web_url_reads_oh_web_url_when_runtime_url_is_also_set(self):
        """Test that OH_WEB_URL remains authoritative."""
        with patch.dict(
            "os.environ",
            {
                "OH_WEB_URL": "https://preferred.example.com/path",
                "RUNTIME_URL": "https://legacy.example.com/path",
            },
        ):
            config = Config()

        assert config.web_url == "https://preferred.example.com/path"

    def test_web_url_can_be_set_explicitly(self):
        """Test that web_url can be set explicitly, overriding env vars."""
        with patch.dict(
            "os.environ",
            {
                "OH_WEB_URL": "https://env.example.com/oh",
                "RUNTIME_URL": "https://env.example.com/runtime",
            },
        ):
            config = Config(web_url="https://explicit.example.com/custom")
            assert config.web_url == "https://explicit.example.com/custom"


@pytest.mark.parametrize(
    "web_url,expected_root_path",
    [
        (None, ""),
        ("https://example.com", ""),
        ("https://example.com/", ""),
        ("https://example.com/api", "/api"),
        ("https://example.com/api/v1", "/api/v1"),
        ("http://localhost:8000/test", "/test"),
        ("https://work-1-xyz.prod-runtime.all-hands.dev/runtime/abc", "/runtime/abc"),
    ],
)
def test_get_root_path_parametrized(web_url, expected_root_path):
    """Parametrized test for _get_root_path with various URL patterns."""
    config = Config(web_url=web_url)
    assert _get_root_path(config) == expected_root_path


class TestHttpExceptionLogging:
    """5xx HTTPExceptions are intentionally-raised flow control.

    They should be logged as a single ERROR line without a full stack
    trace; only genuinely unhandled exceptions should get a traceback.
    Otherwise routine upstream blips look indistinguishable from a process
    crash in the logs.
    """

    def _build_app_with_failing_route(self, status_code: int):
        from fastapi import HTTPException as FastAPIHTTPException

        config = Config(static_files_path=None)
        app = create_app(config)

        @app.get(f"/__test__/raise_{status_code}")
        def _raise():
            raise FastAPIHTTPException(
                status_code=status_code, detail="boom from upstream"
            )

        return app

    def test_5xx_http_exception_logged_without_traceback_by_default(self, caplog):
        import logging

        app = self._build_app_with_failing_route(502)
        client = TestClient(app)

        with caplog.at_level(logging.ERROR, logger="openhands.agent_server.api"):
            response = client.get("/__test__/raise_502")

        assert response.status_code == 502
        # Client still sees the same sanitized 5xx envelope.
        assert response.json()["detail"] == "Internal Server Error"

        api_error_records = [
            r
            for r in caplog.records
            if r.name == "openhands.agent_server.api" and r.levelno == logging.ERROR
        ]
        assert len(api_error_records) == 1, (
            "Expected exactly one ERROR log line for a 5xx HTTPException, "
            f"got: {[r.getMessage() for r in api_error_records]}"
        )
        record = api_error_records[0]
        # The whole point of the fix: no stack trace attached for an
        # intentionally-raised HTTPException.
        assert record.exc_info is None, (
            "5xx HTTPException should not log a traceback by default; "
            f"got exc_info={record.exc_info!r}"
        )
        # Message must still carry status, method, path, and detail so
        # the log is useful for monitoring.
        message = record.getMessage()
        assert "502" in message
        assert "GET" in message
        assert "/__test__/raise_502" in message
        assert "boom from upstream" in message

    def test_5xx_http_exception_includes_traceback_when_debug_enabled(
        self, caplog, monkeypatch
    ):
        import logging

        # DEBUG is read at module import time in api.py, so monkeypatch
        # the bound name on the module rather than mutating the env.
        monkeypatch.setattr("openhands.agent_server.api.DEBUG", True)

        app = self._build_app_with_failing_route(503)
        client = TestClient(app)

        with caplog.at_level(logging.ERROR, logger="openhands.agent_server.api"):
            response = client.get("/__test__/raise_503")

        assert response.status_code == 503
        api_error_records = [
            r
            for r in caplog.records
            if r.name == "openhands.agent_server.api" and r.levelno == logging.ERROR
        ]
        assert len(api_error_records) == 1
        # In DEBUG mode the traceback is preserved as an opt-in debugging aid.
        assert api_error_records[0].exc_info is not None

    def test_4xx_http_exception_logged_at_info_without_traceback(self, caplog):
        import logging

        app = self._build_app_with_failing_route(404)
        client = TestClient(app)

        with caplog.at_level(logging.INFO, logger="openhands.agent_server.api"):
            response = client.get("/__test__/raise_404")

        assert response.status_code == 404
        # 4xx path returns the raw detail (not the sanitized 5xx envelope).
        assert response.json() == {"detail": "boom from upstream"}

        api_records = [
            r for r in caplog.records if r.name == "openhands.agent_server.api"
        ]
        # No ERROR-level noise for a routine 4xx.
        assert not any(r.levelno >= logging.ERROR for r in api_records)
        info_records = [r for r in api_records if r.levelno == logging.INFO]
        assert info_records, "Expected an INFO log line for a 4xx HTTPException"
        assert all(r.exc_info is None for r in info_records)


class TestSelfApprovalDeniedHandler:
    """A blocked self-approval (roy_self_approval.SelfApprovalDeniedError)
    must reach an HTTP caller as a clean 403, not the generic 500 every
    other unhandled ValueError falls through to — see the review finding
    this closes: event_router.respond_to_confirmation() lets the exception
    propagate, and without a dedicated handler api.py's catch-all
    Exception handler would treat it as an opaque server fault.

    Exercised through a real ASGI request (TestClient), not by calling the
    handler function directly, so this also proves FastAPI actually
    dispatches SelfApprovalDeniedError to this handler ahead of the
    generic one.
    """

    def test_self_approval_denied_maps_to_403(self):
        from openhands.sdk.security.roy_self_approval import (
            SelfApprovalDeniedError,
        )

        config = Config(static_files_path=None)
        app = create_app(config)

        @app.get("/__test__/raise_self_approval_denied")
        def _raise():
            raise SelfApprovalDeniedError(
                "self-approval not allowed: requester and approver are the "
                "same identity ('roy')"
            )

        client = TestClient(app)
        response = client.get("/__test__/raise_self_approval_denied")

        assert response.status_code == 403
        body = response.json()
        assert body["error_code"] == "self_approval_denied"
        assert "self-approval not allowed" in body["detail"]
        # The requester identity ('roy') must not leak into the response
        # body — it is only safe to have it in the server-side log.
        assert "roy" not in body["detail"]


class TestGovernanceBridgeTokenGate:
    """``POST .../respond_to_confirmation``'s ``accept=True`` path, gated by
    ``X-Governance-Bridge-Token`` when ``governance_deployment_mode ==
    "team"`` — see ``dependencies.authorize_confirmation_response``.

    Exercised through real ASGI requests (TestClient) against the actual
    mounted route, not by calling the dependency function directly, so this
    proves the gate is really wired into ``event_router.py`` and reads
    ``app.state.config`` at request time. ``get_event_service`` is
    overridden with a stub so these tests isolate the authorization gate
    itself from the (unrelated, heavier) machinery of driving a real
    conversation into WAITING_FOR_CONFIRMATION.
    """

    @staticmethod
    def _client_and_stub(config: Config) -> tuple[TestClient, AsyncMock]:
        from openhands.agent_server.dependencies import get_event_service

        app = create_app(config)
        stub_event_service = AsyncMock()
        app.dependency_overrides[get_event_service] = lambda: stub_event_service
        return TestClient(app), stub_event_service

    @staticmethod
    def _respond(
        client: TestClient,
        *,
        accept: bool,
        token: str | None = None,
    ):
        conversation_id = "11111111-1111-1111-1111-111111111111"
        headers = {"X-Governance-Bridge-Token": token} if token is not None else {}
        return client.post(
            f"/api/conversations/{conversation_id}/events/respond_to_confirmation",
            json={"accept": accept, "reason": "test"},
            headers=headers,
        )

    def test_personal_mode_accept_ignores_missing_token(self):
        """Default deployment mode: today's behavior, completely unchanged."""
        config = Config(static_files_path=None)
        assert config.governance_deployment_mode == "personal"
        client, stub = self._client_and_stub(config)

        response = self._respond(client, accept=True)

        assert response.status_code == 200
        stub.respond_to_confirmation.assert_awaited_once()

    def test_team_mode_accept_with_correct_token_passes(self):
        config = Config(
            static_files_path=None,
            governance_deployment_mode="team",
            governance_bridge_token="s3cr3t",
        )
        client, stub = self._client_and_stub(config)

        response = self._respond(client, accept=True, token="s3cr3t")

        assert response.status_code == 200
        stub.respond_to_confirmation.assert_awaited_once()

    def test_team_mode_accept_with_wrong_token_is_403(self):
        config = Config(
            static_files_path=None,
            governance_deployment_mode="team",
            governance_bridge_token="s3cr3t",
        )
        client, stub = self._client_and_stub(config)

        response = self._respond(client, accept=True, token="wrong")

        assert response.status_code == 403
        stub.respond_to_confirmation.assert_not_awaited()

    def test_team_mode_accept_with_missing_token_is_403(self):
        config = Config(
            static_files_path=None,
            governance_deployment_mode="team",
            governance_bridge_token="s3cr3t",
        )
        client, stub = self._client_and_stub(config)

        response = self._respond(client, accept=True)

        assert response.status_code == 403
        stub.respond_to_confirmation.assert_not_awaited()

    def test_team_mode_accept_fails_closed_when_token_unconfigured(self):
        """An unconfigured bridge token must never be treated as 'no check
        needed' — every accept=True caller is refused, even one that
        supplies no token at all (which would otherwise trivially "match"
        an absent expected value if compared naively)."""
        config = Config(
            static_files_path=None,
            governance_deployment_mode="team",
            governance_bridge_token=None,
        )
        client, stub = self._client_and_stub(config)

        response = self._respond(client, accept=True)

        assert response.status_code == 403
        stub.respond_to_confirmation.assert_not_awaited()

    def test_team_mode_reject_is_never_gated(self):
        """accept=False cannot grant elevated privilege, so it is never
        gated — even with no token, an unconfigured bridge token, and team
        mode active all at once."""
        config = Config(
            static_files_path=None,
            governance_deployment_mode="team",
            governance_bridge_token=None,
        )
        client, stub = self._client_and_stub(config)

        response = self._respond(client, accept=False)

        assert response.status_code == 200
        stub.respond_to_confirmation.assert_awaited_once()

    def test_governance_bridge_token_masked_in_repr(self):
        """``governance_bridge_token`` is ``SecretStr`` (matching the
        existing ``secret_key`` field's precedent) specifically so that
        logging or otherwise stringifying a ``Config`` instance — e.g. an
        unrelated error message that happens to include ``repr(config)`` —
        can never leak the raw token. Pins that this field actually uses
        that type, not just that a plain string happens not to appear
        somewhere incidental."""
        config = Config(
            static_files_path=None,
            governance_deployment_mode="team",
            governance_bridge_token="s3cr3t",
        )

        assert "s3cr3t" not in repr(config)
        assert "s3cr3t" not in str(config.governance_bridge_token)
        # The actual Pydantic serialization boundary — the path any future
        # debug/admin endpoint that dumps Config would go through — not
        # just repr()/str(), which nothing in this codebase necessarily
        # calls on a live Config today.
        assert "s3cr3t" not in config.model_dump_json()

    def test_governance_bridge_token_rejects_blank_value(self):
        """A blank token is almost certainly a misconfigured env var
        (``OH_GOVERNANCE_BRIDGE_TOKEN=""``), not an intentional secret —
        must fail at Config construction, not silently become an
        unmatchable-by-design fail-closed token nobody can diagnose."""
        with pytest.raises(ValidationError):
            Config(governance_bridge_token="   ")

    def test_session_api_key_still_required_alongside_bridge_token(self):
        """The bridge token is an *additional* requirement layered on top
        of session-key auth (check_session_api_key, applied to the whole
        /api router), not a replacement for it — a caller must satisfy
        both, not either."""
        config = Config(
            static_files_path=None,
            session_api_keys=["session-key"],
            governance_deployment_mode="team",
            governance_bridge_token="bridge-secret",
        )
        client, stub = self._client_and_stub(config)
        conversation_id = "11111111-1111-1111-1111-111111111111"
        url = f"/api/conversations/{conversation_id}/events/respond_to_confirmation"

        # Correct bridge token but no session key → still rejected by the
        # unrelated, pre-existing session-key gate.
        response = client.post(
            url,
            json={"accept": True},
            headers={"X-Governance-Bridge-Token": "bridge-secret"},
        )
        assert response.status_code == 401
        stub.respond_to_confirmation.assert_not_awaited()

        # Both satisfied → passes through.
        response = client.post(
            url,
            json={"accept": True},
            headers={
                "X-Session-API-Key": "session-key",
                "X-Governance-Bridge-Token": "bridge-secret",
            },
        )
        assert response.status_code == 200
        stub.respond_to_confirmation.assert_awaited_once()

    def test_governance_bridge_token_header_documented_in_openapi(self):
        """The header must be a real, documented parameter on this route —
        not silently collapsed into the unrelated X-Session-API-Key
        security scheme (both were, at one point, undistinguished
        APIKeyHeader instances with no scheme_name, which FastAPI merges
        into a single OpenAPI security scheme)."""
        config = Config(static_files_path=None, governance_deployment_mode="team")
        app = create_app(config)
        client = TestClient(app)

        schema = client.get("/openapi.json").json()

        confirm_op = schema["paths"][
            "/api/conversations/{conversation_id}/events/respond_to_confirmation"
        ]["post"]
        header_params = [
            p for p in confirm_op.get("parameters", []) if p.get("in") == "header"
        ]
        assert any(p["name"] == "X-Governance-Bridge-Token" for p in header_params), (
            header_params
        )
