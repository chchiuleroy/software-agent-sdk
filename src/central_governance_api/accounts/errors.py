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


class DepartmentNotFoundError(Exception):
    """No department with this id. Maps to 404."""

    def __init__(self) -> None:
        super().__init__("no such department")


class DepartmentExistsError(Exception):
    """A department with this name already exists. Maps to 409."""

    def __init__(self) -> None:
        super().__init__("a department with this name already exists")


class DepartmentDisabledError(Exception):
    """Disabled departments cannot receive new members, and cannot be
    disabled twice. Maps to 409."""

    def __init__(self) -> None:
        super().__init__("department is disabled")


class AccountRequestNotFoundError(Exception):
    """No account request with this id. Maps to 404."""

    def __init__(self) -> None:
        super().__init__("no such account request")


class AccountRequestNotPendingError(Exception):
    """The request is not awaiting review (already decided, expired, or not
    yet verified). Maps to 409. Also the answer to a replayed decision: the
    conditional state change makes a repeat harmless rather than idempotent."""

    def __init__(self) -> None:
        super().__init__("account request is not awaiting review")


class SelfApprovalNotAllowedError(Exception):
    """A superadmin may not decide an application made with their own
    e-mail address. Maps to 403."""

    def __init__(self) -> None:
        super().__init__("cannot decide an account request for your own e-mail")


class PrincipalAlreadyAssignedError(Exception):
    """This service-account identity already belongs to a department. Maps
    to 409."""

    def __init__(self) -> None:
        super().__init__("principal is already assigned to a department")


class PrincipalAssignmentNotFoundError(Exception):
    """No such department assignment. Maps to 404."""

    def __init__(self) -> None:
        super().__init__("no such department assignment")


class ToolNotPermittedError(Exception):
    """The caller's department is not permitted to use this tool. Maps to
    403. The message names no tool and no department."""

    def __init__(self) -> None:
        super().__init__("this tool is not permitted for the caller's department")
