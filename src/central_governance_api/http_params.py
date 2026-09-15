"""Shared FastAPI parameter annotations used across more than one router.

``IdempotencyKeyHeader``: every write endpoint in this service takes an
``Idempotency-Key`` header (see ``approvals/idempotency.py``'s module
docstring — "every write endpoint needs this, not just claim"), and every
one of them stores it in ``IdempotencyRecord.idempotency_key``, a
``String(128)`` column (models.py). Code review caught that none of the
``Header(alias="Idempotency-Key")`` declarations across ``routers/
approvals.py``/``routers/devices.py`` actually enforced that bound — an
over-length key would only fail later, as an unhandled DB error, instead
of a clean 422 at the request-validation boundary where FastAPI would
catch it automatically if the constraint were declared. One shared
``Annotated`` alias instead of repeating ``max_length=128`` at every call
site, so the DB column and the HTTP-layer constraint can't drift apart
silently in a router that forgets to copy it.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Header


IdempotencyKeyHeader = Annotated[
    str, Header(alias="Idempotency-Key", min_length=1, max_length=128)
]
