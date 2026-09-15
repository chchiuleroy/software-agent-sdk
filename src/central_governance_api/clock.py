"""The one clock every deadline/timestamp computation in this service uses.

App-process timestamps (``datetime.now(UTC)``), not Postgres's own
``now()`` — a reasoned simplification, not something v11 specifies. Fine
while this API process and its Postgres are co-located (true today: both
run on the same machine); a deployment that splits this service across
multiple app-server processes/hosts would need every deadline comparison
here to move server-side (``func.now()`` in the SQL itself) to avoid
clock-skew-induced early/late expiry. Centralized here — rather than each
router defining its own ``_now()`` — so that migration, when it happens,
is a one-file change instead of a grep-and-fix across every router.
"""

from __future__ import annotations

from datetime import UTC, datetime


def now_utc() -> datetime:
    return datetime.now(UTC)
