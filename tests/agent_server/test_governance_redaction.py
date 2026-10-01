"""Tests for the pattern-based redaction used by the central-approval display.

Every positive case names the rule that must fire, so a regression in one
pattern cannot hide behind another rule happening to catch the same text.
"""

import pytest

from openhands.agent_server.governance_redaction import (
    REDACTION_VERSION,
    RULES,
    redact,
)


# Built by concatenation so no GitHub-token-shaped literal sits in the source
# (public repo: secret scanners flag the format even when the value is fake).
_FAKE_GH = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
_FAKE_GH_PAT = "github_pat_" + "11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz"

# (input, secret that must not survive, rule that must fire)
POSITIVE_CASES = [
    (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\n"
        "-----END RSA PRIVATE KEY-----",
        "MIIEowIBAAKCAQEA1234",
        "pem_private_key",
    ),
    (
        "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dBjftJeZ4CVPmB92K27uhbUJU1p1r",
        "eyJhbGciOiJIUzI1NiJ9",
        "jwt",
    ),
    (
        "git clone https://deploy:hunter2pass@git.example.com/org/repo.git",
        "hunter2pass",
        "url_userinfo",
    ),
    (
        f"export GH={_FAKE_GH}",
        _FAKE_GH,
        "github_token",
    ),
    (
        _FAKE_GH_PAT,
        _FAKE_GH_PAT,
        "github_token",
    ),
    (
        "SLACK=xoxb-123456789012-abcdefghij",
        "xoxb-123456789012-abcdefghij",
        "slack_token",
    ),
    (
        "aws configure set id AKIAABCDEFGHIJKLMNOP",
        "AKIAABCDEFGHIJKLMNOP",
        "aws_access_key_id",
    ),
    (
        "key AIzaSyA-abcdefghijklmnopqrstuvwxyz012345",
        "AIzaSyA-abcdefghijklmnopqrstuvwxyz012345",
        "google_api_key",
    ),
    (
        "use sk-FAKE-0000-not-a-real-key please",
        "sk-FAKE-0000-not-a-real-key",
        "openai_style_key",
    ),
    (
        "curl -H 'Authorization: Bearer abc123def456' https://x",
        "abc123def456",
        "authorization_header",
    ),
    (
        "curl -H 'authorization: Basic dXNlcjpwYXNz'",
        "dXNlcjpwYXNz",
        "authorization_header",
    ),
    ("auth is bearer abcdefgh12345678 here", "abcdefgh12345678", "bearer_token"),
    ("mysql -u root --password=s3cretpw db", "s3cretpw", "cli_secret_flag"),
    ("tool --api-key 'my key value' run", "my key value", "cli_secret_flag"),
    ("tool -token abcdef123 go", "abcdef123", "cli_secret_flag"),
    (
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG",
        "wJalrXUtnFEMI/K7MDENG",
        "key_value_secret",
    ),
    ('{"api_key": "plainvalue99"}', "plainvalue99", "key_value_secret"),
    (
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B",
        "MIIEvQIBADANBgkqhkiG9w0B",
        "pem_private_key_unterminated",
    ),
    ("echo 你好 密碼=hunter2", "hunter2", "cjk_key_value_secret"),
    ("我的密码：abc12345 請勿外洩", "abc12345", "cjk_key_value_secret"),
    ("金鑰 = 「長長的金鑰值」", "長長的金鑰值", "cjk_key_value_secret"),
    ("DB密碼_prod＝s3cr3t99", "s3cr3t99", "cjk_key_value_secret"),
    ("db_password: 'p@ss w0rd'", "p@ss w0rd", "key_value_secret"),
]


@pytest.mark.parametrize(
    ("text", "secret", "rule"),
    POSITIVE_CASES,
    ids=[f"{rule}-{i}" for i, (_, _, rule) in enumerate(POSITIVE_CASES)],
)
def test_secret_is_redacted_and_the_rule_is_named(text, secret, rule):
    result = redact(text)

    assert secret not in result.text
    assert rule in result.applied


@pytest.mark.parametrize(
    "text",
    [
        "ls -la /tmp",
        "git status --short",
        "grep -rn 'tokenizer' src/",  # a secret word with no value assignment
        "python -m pytest tests/ -k passwords_are_hashed",  # word inside an identifier
        "cat README.md",
        "https://example.com/docs/page?lang=en",
        "echo hello world",
        "請在登入頁輸入密碼後按下確認",  # a Chinese secret word with no value
        "密碼規則：至少八個字元",  # the label is "密碼規則", not "密碼"
        "",
    ],
)
def test_ordinary_text_is_left_untouched(text):
    result = redact(text)

    assert result.text == text
    assert result.applied == ()


def test_label_stays_visible_so_the_approver_sees_what_was_hidden():
    result = redact("DB_PASSWORD=hunter2")

    assert result.text.startswith("DB_PASSWORD=")
    assert "hunter2" not in result.text


def test_redaction_is_idempotent():
    once = redact("curl -H 'Authorization: Bearer abc123def456' --password=pw1 x")

    assert redact(once.text).text == once.text


def test_applied_rule_names_are_sorted_and_unique():
    result = redact("a=1 PASSWORD=x token=y Authorization: Bearer abcdefgh12345")

    assert list(result.applied) == sorted(set(result.applied))


def test_every_rule_has_a_unique_name_and_a_positive_case():
    names = [rule.name for rule in RULES]
    covered = {rule for _, _, rule in POSITIVE_CASES}

    # A rule without a test case can silently stop matching; keep the table
    # and the cases in step (see the how-to-extend steps in the module doc).
    assert len(names) == len(set(names))
    assert set(names) == covered


def test_redaction_version_is_a_positive_int():
    assert isinstance(REDACTION_VERSION, int)
    assert REDACTION_VERSION >= 1


# --- performance: no rule may be super-linear -----------------------------
#
# Redaction runs synchronously, on text an LLM or a file controls, for every
# high-risk action. Python's `re` does not release the GIL, so a rule that
# backtracks quadratically freezes the whole agent-server (a 32k-character
# "a-a-a-..." took over a minute in `key_value_secret` before this was fixed).
# Each family below repeats a string that starts a match for some rule (or
# produces many word boundaries) without ever completing one.

_ADVERSARIAL_UNITS = [
    "a-",
    "a.",
    "a",
    "a_",
    "sk-",
    "eyJ",
    "eyJabcdefgh.",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "AKIA",
    "AIza",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----\nQUJD",
    "Authorization: ",
    "authorization ",
    "Bearer ",
    "password=",
    "password",
    "--password ",
    "-token ",
    "密碼",
    "密碼=",
    "://",
    "x://u:",
    "a:b@",
]
_SLOW_SECONDS = 0.5
_ADVERSARIAL_LENGTH = 12_000


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.name)
def test_no_rule_is_superlinear_on_adversarial_input(rule):
    import time

    slow = []
    for unit in _ADVERSARIAL_UNITS:
        text = unit * (_ADVERSARIAL_LENGTH // len(unit) + 1)
        started = time.perf_counter()
        rule.pattern.subn(rule.replacement, text)
        elapsed = time.perf_counter() - started
        if elapsed > _SLOW_SECONDS:
            slow.append(f"{unit!r}: {elapsed:.1f}s")

    assert not slow, f"{rule.name} is slow on: {slow}"
