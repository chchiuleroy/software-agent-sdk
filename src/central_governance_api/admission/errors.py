"""Error types of the admission registry. Registered as exception handlers in
``main.py`` (same pattern as ``accounts/errors.py``). Messages are fixed strings."""

from __future__ import annotations


class AdmissionItemNotFoundError(Exception):
    """No such admission item (also for one outside the caller's reach). 404."""

    def __init__(self) -> None:
        super().__init__("no such admission item")


class AdmissionInvalidTransitionError(Exception):
    """The item is not in a state this action applies to. 409."""

    def __init__(self) -> None:
        super().__init__("the item is not in a state this action applies to")


class AdmissionContentInvalidError(Exception):
    """The submitted content is not acceptable (bad archive, unsafe path, symlink,
    malformed tool descriptor...). 422. The detail names the rule, never echoes
    the content."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)


class AdmissionContentTooLargeError(Exception):
    """The submitted content exceeds the configured size or file-count limit. 413."""

    def __init__(self) -> None:
        super().__init__("the submitted content is too large")


class AdmissionRateLimitedError(Exception):
    """Too many submissions or too many items waiting by this submitter. 429."""

    def __init__(self) -> None:
        super().__init__("too many admission submissions; try again later")


class AdmissionNoDepartmentError(Exception):
    """The caller belongs to no department, so there is nothing to scope the
    submission to. 409."""

    def __init__(self) -> None:
        super().__init__("the caller belongs to no department")


class AdmissionContentChangedError(Exception):
    """The stored content no longer hashes to the item's fingerprint. 409. The
    approval is refused: what would be approved is not what was checked."""

    def __init__(self) -> None:
        super().__init__("the stored content does not match the item's fingerprint")


class AdmissionDepartmentNotAllowedError(Exception):
    """Only a superadmin may submit for a department other than their own. 403."""

    def __init__(self) -> None:
        super().__init__("only a superadmin may submit for another department")
