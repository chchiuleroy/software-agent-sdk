"""SmtpMailer against a tiny in-process SMTP sink (no real relay, no mocks of
smtplib), so the real wire exchange and the failure mapping are exercised."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from central_governance_api.config import Settings
from central_governance_api.mailer import MailerError, SmtpMailer, build_mailer

from .conftest import AUDIENCE, ISSUER, JWKS_URL


class _SmtpSink:
    def __init__(self) -> None:
        self.messages: list[str] = []
        self.recipients: list[str] = []

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writer.write(b"220 sink ready\r\n")
        while True:
            line = (await reader.readline()).decode(errors="replace").strip()
            if not line:
                break
            verb = line.split(" ", 1)[0].upper()
            if verb in {"EHLO", "HELO"}:
                writer.write(b"250 sink\r\n")
            elif verb in {"MAIL", "RSET", "NOOP"}:
                writer.write(b"250 OK\r\n")
            elif verb == "RCPT":
                self.recipients.append(line)
                writer.write(b"250 OK\r\n")
            elif verb == "DATA":
                writer.write(b"354 go ahead\r\n")
                await writer.drain()
                body = await reader.readuntil(b"\r\n.\r\n")
                self.messages.append(body.decode(errors="replace"))
                writer.write(b"250 queued\r\n")
            elif verb == "QUIT":
                writer.write(b"221 bye\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"502 not implemented\r\n")
            await writer.drain()
        writer.close()


@pytest.fixture
async def sink() -> AsyncIterator[tuple[_SmtpSink, int]]:
    state = _SmtpSink()
    server = await asyncio.start_server(state.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield state, port
    finally:
        server.close()
        await server.wait_closed()


def _mailer(port: int) -> SmtpMailer:
    return SmtpMailer(
        host="127.0.0.1",
        port=port,
        username=None,
        password=None,
        from_addr="ohs@corp.example",
        starttls=False,
    )


async def test_message_reaches_the_relay_with_recipient_and_body(sink):
    state, port = sink
    await _mailer(port).send(
        to="alice@corp.example", subject="OHS 帳號申請驗證碼", body="code ABCD2345"
    )
    assert any("alice@corp.example" in r for r in state.recipients)
    assert "code ABCD2345" in state.messages[0]
    assert "alice@corp.example" in state.messages[0]


async def test_unreachable_relay_becomes_a_mailer_error_without_details():
    # Why: the exception text can echo relay/recipient details; only the
    # class name may travel. Port 9 on loopback refuses connections.
    with pytest.raises(MailerError) as info:
        await _mailer(9).send(to="a@corp.example", subject="s", body="b")
    assert "127.0.0.1" not in str(info.value)
    assert "a@corp.example" not in str(info.value)


def _settings(**overrides) -> Settings:
    return Settings(
        oidc_issuer=ISSUER,
        oidc_jwks_url=JWKS_URL,
        oidc_audience=AUDIENCE,
        **overrides,
    )  # pyright: ignore[reportCallIssue]


def test_build_mailer_is_none_without_smtp_settings():
    # Why: no relay configured must read as "cannot verify", not as "send
    # to a default host".
    assert build_mailer(_settings()) is None
    assert build_mailer(_settings(smtp_host="relay.example")) is None
    assert (
        build_mailer(_settings(smtp_host="relay.example", smtp_from="o@corp.example"))
        is not None
    )
