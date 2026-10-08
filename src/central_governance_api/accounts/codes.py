"""Verification-code generation and HMAC.

The code is 8 characters from an alphabet without look-alikes (no 0/O,
1/I/L), about 40 bits; with a 5-attempt lock-out and a 15-minute life that
is far out of reach of guessing. Only an HMAC (keyed with a server secret)
is stored, so a database read alone does not reveal a live code.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets


_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 8


def generate_code() -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(CODE_LENGTH))


def normalize_code(raw: str) -> str:
    return raw.strip().upper().replace(" ", "").replace("-", "")


def code_hmac(*, key: str, email: str, code: str) -> str:
    return hmac.new(
        key.encode(), f"{email}:{normalize_code(code)}".encode(), hashlib.sha256
    ).hexdigest()


def codes_match(expected_hmac: str, candidate_hmac: str) -> bool:
    return hmac.compare_digest(expected_hmac, candidate_hmac)
