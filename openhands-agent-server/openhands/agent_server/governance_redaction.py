"""Best-effort secret redaction for the text a central approval displays.

Pattern based, on purpose: it only recognises secrets that *look like*
secrets (a labelled value, a well-known token shape, credentials in a URL).
An unlabeled secret — e.g. the literal password in ``echo hunter2`` — is NOT
caught. That is why callers never send whole commands or files: previews are
short and bounded (see ``governance_display``), and redaction is the second
line of defence, not the first.

Every rule must run in LINEAR time. This executes synchronously, on text an
LLM or a file controls, for every high-risk action, and Python's ``re`` does
not release the GIL: a rule that backtracks quadratically freezes the whole
agent-server (one such rule took over a minute on 32k characters of
``a-a-a-...``). So:

- no unbounded quantifier in FRONT of a literal that can repeat (that is what
  made ``[A-Za-z0-9_.-]*password`` quadratic: every word boundary re-scanned
  the rest of the run) — put the literal first and bound what follows it;
- every scan that can fail carries an upper bound;
- a scan that succeeds ends with a possessive tail (``*+``) so a token longer
  than the bound is still redacted to its end, never half shown.

``test_no_rule_is_superlinear_on_adversarial_input`` enforces this per rule.

How to extend (the rules are data, not code paths):

1. Add one ``RedactionRule`` to ``RULES``, following the linear-time rules
   above. Order matters: specific token shapes first, the generic
   ``key=value`` rules last, so a specific rule gets to name what it found.
2. Add a positive case (must be redacted, rule name asserted) and, if the
   pattern could over-match, a negative case (must stay untouched) to the
   parametrized tests in ``tests/agent_server/test_governance_redaction.py``.
   Add the rule's own opening text to ``_ADVERSARIAL_UNITS`` there.
3. Add a realistic line to ``SECRET_CORPUS`` in
   ``tests/agent_server/test_governance_display.py``; that test asserts no
   corpus secret survives in any tool's projection.
4. Bump ``REDACTION_VERSION``. It is stored in every approval's payload, so an
   approval records which rule set redacted what its approver saw.

Over-redaction is the safe failure here (the approver sees a bit less); an
under-matching pattern is the dangerous one, so patterns lean broad.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# 1: initial. 2: + cjk_key_value_secret. 3: linear-time rewrite (bounded
# scans, possessive tails) + pem_private_key_unterminated.
REDACTION_VERSION = 3

_SECRET_WORDS = (
    r"password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|credential"
)
# What may follow a secret word inside the same label (``token_count``,
# ``password.prod``), bounded and possessive.
_LABEL_TAIL = r"[A-Za-z0-9_.-]{0,64}+"


@dataclass(frozen=True)
class RedactionRule:
    name: str
    pattern: re.Pattern[str]
    replacement: str


def _rule(name: str, pattern: str, replacement: str, flags: int = 0) -> RedactionRule:
    return RedactionRule(name, re.compile(pattern, flags), replacement)


# Replacements are literal templates; "\1" etc. keep the part of the match
# that is NOT secret (the label), so the approver still sees what was hidden.
RULES: tuple[RedactionRule, ...] = (
    _rule(
        "pem_private_key",
        r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----.{0,8192}?"
        r"-----END [A-Z ]{0,30}PRIVATE KEY-----",
        "[REDACTED:pem_private_key]",
        re.DOTALL,
    ),
    # A header with no END marker in reach (a truncated or malformed block):
    # redact the base64-looking body that follows it. The body class has no
    # "-", so the scan stops at the next marker.
    _rule(
        "pem_private_key_unterminated",
        r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----[A-Za-z0-9+/=\s]{0,8192}+",
        "[REDACTED:pem_private_key_unterminated]",
    ),
    _rule(
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{8,512}+\.[A-Za-z0-9_-]{8,8192}+\.[A-Za-z0-9_-]{8,}+",
        "[REDACTED:jwt]",
    ),
    _rule(
        "url_userinfo",
        r"(\b[a-z][a-z0-9+.-]{0,31}://)[^/\s:@'\"]{1,2048}+:[^/\s@'\"]{1,2048}+@",
        r"\1[REDACTED:url_userinfo]@",
        re.IGNORECASE,
    ),
    _rule(
        "github_token",
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}+|github_pat_[A-Za-z0-9_]{20,255}+)"
        r"[A-Za-z0-9_]*+",
        "[REDACTED:github_token]",
    ),
    _rule(
        "slack_token",
        r"\bxox[abprs]-[A-Za-z0-9-]{10,255}+[A-Za-z0-9-]*+",
        "[REDACTED:slack_token]",
    ),
    _rule(
        "aws_access_key_id",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}[0-9A-Z]*+",
        "[REDACTED:aws_access_key_id]",
    ),
    _rule(
        "google_api_key",
        r"\bAIza[0-9A-Za-z_-]{35,255}+[0-9A-Za-z_-]*+",
        "[REDACTED:google_api_key]",
    ),
    _rule(
        "openai_style_key",
        r"\bsk-[A-Za-z0-9_-]{16,512}+[A-Za-z0-9_-]*+",
        "[REDACTED:openai_style_key]",
    ),
    _rule(
        "authorization_header",
        r"(\b(?:proxy-)?authorization\s{0,16}+[:=]\s{0,16}+)"
        r"(?:(?:bearer|basic|token|digest)\s{1,16}+)?[^\s'\",;]++",
        r"\1[REDACTED:authorization_header]",
        re.IGNORECASE,
    ),
    _rule(
        "bearer_token",
        r"\b(bearer\s{1,16}+)[A-Za-z0-9._~+/=-]{8,}+",
        r"\1[REDACTED:bearer_token]",
        re.IGNORECASE,
    ),
    _rule(
        "cli_secret_flag",
        rf"(--?(?:{_SECRET_WORDS}|auth)s?(?:=|\s{{1,16}}+))(\"[^\"]*\"|'[^']*'|\S++)",
        r"\1[REDACTED:cli_secret_flag]",
        re.IGNORECASE,
    ),
    # Generic ``label = value`` / ``"label": "value"``: last of the ASCII
    # rules, so the specific rules above name what they found first. The
    # secret word comes FIRST and the rest of the label is bounded (see the
    # module doc); whatever precedes the word (``AWS_``, ``db_``) is left in
    # place, which is exactly what keeps the label visible to the approver.
    _rule(
        "key_value_secret",
        rf"((?:{_SECRET_WORDS}){_LABEL_TAIL})(\"?\s{{0,16}}+[=:]\s{{0,16}}+)"
        # Not a value an earlier, more specific rule already replaced.
        r"(?!\[REDACTED:)(\"[^\"]*\"|'[^']*'|[^\s'\";,&]++)",
        r"\1\2[REDACTED:key_value_secret]",
        re.IGNORECASE,
    ),
    # Chinese labels (Traditional and Simplified). Accepts ASCII and
    # full-width colons/equals.
    _rule(
        "cjk_key_value_secret",
        r"((?:密碼|密码|口令|密鑰|密钥|金鑰|金钥|憑證|凭证|令牌|權杖|权杖|私鑰|私钥)"
        r"[A-Za-z0-9_]{0,64}+)(\s{0,16}+[=:：＝]\s{0,16}+)"
        r"(?!\[REDACTED:)(\"[^\"]*\"|'[^']*'|「[^」]*」|[^\s'\";,&，。；]++)",
        r"\1\2[REDACTED:cjk_key_value_secret]",
    ),
)


@dataclass(frozen=True)
class Redacted:
    text: str
    # Names of the rules that fired, sorted and de-duplicated.
    applied: tuple[str, ...]


def redact(text: str) -> Redacted:
    applied: set[str] = set()
    for rule in RULES:
        text, count = rule.pattern.subn(rule.replacement, text)
        if count:
            applied.add(rule.name)
    return Redacted(text=text, applied=tuple(sorted(applied)))
