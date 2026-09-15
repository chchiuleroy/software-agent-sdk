"""Shared Pydantic base for every request body in this service.

Started as a private class inside ``approvals/schemas.py``; promoted here
once ``routers/devices.py`` needed the identical ``extra="forbid"``
behavior — this belongs at the service level, not owned by one feature's
schema module.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class RequestModel(BaseModel):
    """Base for every request body across this service. ``extra="forbid"``
    (code-review Medium, originally found in ``approvals/schemas.py``):
    Pydantic's default silently *drops* unknown fields rather than
    rejecting them — for ``ReportResultRequest`` specifically, a client
    that typos both ``execution_attempt_id`` and ``outcome`` would have
    both real fields end up unset, which that model's own pairing
    validator reads as a legitimate pre-claim abort instead of the
    malformed request it actually is. Applying this to every request
    model service-wide so the same silent-typo failure mode can't recur
    in a router that doesn't happen to remember this one lesson.
    """

    model_config = ConfigDict(extra="forbid")
