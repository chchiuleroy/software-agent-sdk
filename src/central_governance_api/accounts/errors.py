"""Error types for the account-request flow. Registered as exception
handlers in ``main.py`` (same pattern as ``approvals/errors.py``).

Messages are fixed strings: this flow is reachable without authentication,
so nothing here may echo caller input or reveal whether an e-mail address
already has an application or an account.
"""

from __future__ import annotations


class EmailDomainNotAllowedError(Exception):
    """The e-mail's domain is not on ``account_email_domains``. Maps to 422.
    The domain list is not a secret, so this one is specific."""

    def __init__(self) -> None:
        super().__init__("e-mail domain is not allowed for account requests")


class AccountRequestRateLimitedError(Exception):
    """Too many applications for this e-mail or overall. Maps to 429."""

    def __init__(self) -> None:
        super().__init__("too many account requests; try again later")


class InvalidVerificationCodeError(Exception):
    """Wrong, expired, locked-out or unknown: deliberately one error so the
    response says nothing about which. Maps to 400."""

    def __init__(self) -> None:
        super().__init__("verification code is invalid or expired")


class MailUnavailableError(Exception):
    """SMTP is not configured or the relay refused the message. Maps to 503."""

    def __init__(self) -> None:
        super().__init__("verification e-mail could not be sent")
