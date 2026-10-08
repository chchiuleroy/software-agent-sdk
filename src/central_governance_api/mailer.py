"""Outbound e-mail for the account-request verification code.

Standard library only (``smtplib`` run in a worker thread) — one short
message per application does not justify a new dependency. ``Mailer`` is a
``Protocol`` so tests inject a fake; ``build_mailer`` returns ``None`` when
SMTP is not configured, which the submit route turns into a 503 rather than
accepting an application it cannot verify.
"""

from __future__ import annotations

import asyncio
import smtplib
from email.message import EmailMessage
from typing import Protocol

from central_governance_api.config import Settings


class MailerError(Exception):
    """The message could not be handed to the SMTP relay."""


class Mailer(Protocol):
    async def send(self, *, to: str, subject: str, body: str) -> None: ...


class SmtpMailer:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str | None,
        password: str | None,
        from_addr: str,
        starttls: bool,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._from_addr = from_addr
        self._starttls = starttls

    def _send_blocking(self, message: EmailMessage) -> None:
        with smtplib.SMTP(self._host, self._port, timeout=15) as smtp:
            if self._starttls:
                smtp.starttls()
            if self._username and self._password:
                smtp.login(self._username, self._password)
            smtp.send_message(message)

    async def send(self, *, to: str, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = self._from_addr
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body)
        try:
            await asyncio.to_thread(self._send_blocking, message)
        except (smtplib.SMTPException, OSError) as exc:
            # Class name only: the exception text can echo the recipient or
            # relay details, which do not belong in logs or responses.
            raise MailerError(type(exc).__name__) from None


def build_mailer(settings: Settings) -> Mailer | None:
    if not settings.smtp_host or not settings.smtp_from:
        return None
    password = settings.smtp_password
    return SmtpMailer(
        host=settings.smtp_host,
        port=settings.smtp_port,
        username=settings.smtp_username,
        password=password.get_secret_value() if password else None,
        from_addr=settings.smtp_from,
        starttls=settings.smtp_starttls,
    )
