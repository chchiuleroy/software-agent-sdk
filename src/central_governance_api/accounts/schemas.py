"""Request/response bodies for the account-request flow."""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints, field_validator

from central_governance_api.schemas_base import RequestModel


# Deliberately plain: no e-mail-validator dependency. Proof of ownership is
# the emailed code, not the syntax; this only keeps obvious garbage out.
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")


def normalize_email(raw: str) -> str:
    return raw.strip().lower()


class CreateAccountRequest(RequestModel):
    email: Annotated[str, StringConstraints(max_length=320)]
    display_name: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    requested_department: Annotated[
        str, StringConstraints(min_length=1, max_length=128)
    ]
    reason: Annotated[str, StringConstraints(max_length=1000)] = ""

    @field_validator("email")
    @classmethod
    def _email_shape(cls, v: str) -> str:
        v = normalize_email(v)
        if not _EMAIL_RE.match(v):
            raise ValueError("not a valid e-mail address")
        return v


class VerifyAccountRequest(RequestModel):
    email: Annotated[str, StringConstraints(max_length=320)]
    code: Annotated[str, StringConstraints(min_length=1, max_length=32)]

    @field_validator("email")
    @classmethod
    def _email_normalized(cls, v: str) -> str:
        return normalize_email(v)


class AccountRequestAccepted(BaseModel):
    status: str = Field(default="verification_sent")


class AccountRequestVerified(BaseModel):
    status: str = Field(default="pending_review")
