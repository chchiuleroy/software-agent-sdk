"""Tests for governance/needs_attention/governance_attention_cli.py.

They run against a real local HTTP server that records what it receives, so what the
CLI actually sends (headers, body, paths) can be asserted."""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest


_CLI_PATH = (
    Path(__file__).resolve().parents[2]
    / "governance"
    / "needs_attention"
    / "governance_attention_cli.py"
)
_spec = importlib.util.spec_from_file_location("governance_attention_cli", _CLI_PATH)
assert _spec is not None and _spec.loader is not None
cli = importlib.util.module_from_spec(_spec)
sys.modules["governance_attention_cli"] = cli
_spec.loader.exec_module(cli)


CID = str(uuid.uuid4())
LIST_PATH = "/api/governance/attention"
RESOLVE_PATH = f"/api/governance/attention/{CID}/resolve"
SECRET = "sk-test-SECRET-123"

ITEM = {
    "conversation_id": CID,
    "reason": "claim_failed",
    "last_error_code": "device_not_bound",
    "central_approval_id": "approval-1",
    "request_id": "req-1",
    "attempt_count": 2,
    "last_attempt_at": "2026-10-13T00:00:00+00:00",
    "allowed_actions": ["retry", "abandon", "dismiss"],
}
OK_RESULT = {
    "conversation_id": CID,
    "action": "dismiss",
    "request_id": "req-1",
    "new_state": "resolved_manually",
    "central_step": "not_applicable",
    "conversation_still_waiting": False,
}


class _Fake:
    def __init__(self):
        self.requests: list[dict] = []
        self.routes: dict[tuple[str, str], tuple[int, object]] = {}
        self.url = ""

    def posts(self):
        return [r for r in self.requests if r["method"] == "POST"]


@pytest.fixture
def server():
    fake = _Fake()

    class Handler(BaseHTTPRequestHandler):
        def _handle(self, method):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b""
            fake.requests.append(
                {
                    "method": method,
                    "path": self.path,
                    "headers": dict(self.headers),
                    "body": json.loads(raw) if raw else None,
                }
            )
            route = fake.routes.get((method, self.path), (404, {"detail": "no route"}))
            status, body = route[0], route[1]
            extra = route[2] if len(route) > 2 else {}
            payload = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            for name, value in extra.items():
                self.send_header(name, value)
            self.send_header("Content-Type", "application/json")
            if "Content-Length" not in extra:  # a test may lie about it on purpose
                self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):  # noqa: N802
            self._handle("GET")

        def do_POST(self):  # noqa: N802
            self._handle("POST")

        def log_message(self, format: str, *args: Any) -> None:  # noqa: ARG002
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    fake.url = f"http://127.0.0.1:{httpd.server_port}"
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield fake
    httpd.shutdown()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (cli.URL_ENV, *cli.KEY_ENVS):
        monkeypatch.delenv(name, raising=False)


def header(request: dict, name: str) -> str | None:
    """A request header by name, ignoring case (HTTP headers are case-insensitive;
    urllib sends this one as X-session-api-key)."""
    wanted = name.lower()
    return next((v for k, v in request["headers"].items() if k.lower() == wanted), None)


def run(capsys, *argv) -> tuple[int, str, str]:
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


# ---------------------------------- list ----------------------------------


def test_list_with_nothing_says_so(server, capsys):
    server.routes[("GET", LIST_PATH)] = (200, [])

    code, out, _ = run(capsys, "list", "--url", server.url)

    assert (code, out.strip()) == (0, "Nothing needs attention.")


def test_list_shows_what_identifies_each_record(server, capsys):
    server.routes[("GET", LIST_PATH)] = (200, [ITEM])

    code, out, _ = run(capsys, "list", "--url", server.url)

    assert code == 0
    for expected in (
        CID,
        "claim_failed",
        "device_not_bound",
        "req-1",
        "retry, abandon, dismiss",
    ):
        assert expected in out


@pytest.mark.parametrize(
    ("reason", "allowed", "advice"),
    [
        ("claim_transient", ["retry", "dismiss"], "run `resolve retry` once"),
        ("claim_retry_failed", ["dismiss"], "ask a superadmin"),
    ],
)
def test_list_tells_the_operator_what_to_do_about_a_temporary_claim_failure(
    server, capsys, reason, allowed, advice
):
    """The rule the operator follows: retry once, and if that fails again, ask a
    superadmin. Without the line they would see only a reason code."""
    server.routes[("GET", LIST_PATH)] = (
        200,
        [{**ITEM, "reason": reason, "allowed_actions": allowed}],
    )

    _, out, _ = run(capsys, "list", "--url", server.url)

    assert advice in out


def test_list_adds_no_advice_line_for_other_reasons(server, capsys):
    server.routes[("GET", LIST_PATH)] = (200, [ITEM])

    _, out, _ = run(capsys, "list", "--url", server.url)

    assert "next" not in out


def test_list_json_is_the_servers_answer_unchanged(server, capsys):
    server.routes[("GET", LIST_PATH)] = (200, [ITEM])

    code, out, _ = run(capsys, "list", "--json", "--url", server.url)

    assert code == 0 and json.loads(out) == [ITEM]


def test_list_explains_an_unreadable_outbox(server, capsys):
    broken = {
        **ITEM,
        "reason": "unreadable_outbox",
        "allowed_actions": [],
        "request_id": None,
        "last_error_code": None,
    }
    server.routes[("GET", LIST_PATH)] = (200, [broken])

    _, out, _ = run(capsys, "list", "--url", server.url)

    assert "could not be read" in out and "none" in out


def test_the_url_comes_from_the_environment_too(server, capsys, monkeypatch):
    monkeypatch.setenv(cli.URL_ENV, server.url)
    server.routes[("GET", LIST_PATH)] = (200, [])

    assert run(capsys, "list")[0] == 0


# ------------------------------ the session key ------------------------------


def test_the_session_key_is_sent_when_set_and_never_printed(
    server, capsys, monkeypatch
):
    monkeypatch.setenv("OH_SESSION_API_KEYS_0", SECRET)
    server.routes[("GET", LIST_PATH)] = (200, [ITEM])

    code, out, err = run(capsys, "list", "--url", server.url)

    assert code == 0
    assert header(server.requests[0], "X-Session-API-Key") == SECRET
    assert SECRET not in out and SECRET not in err


def test_the_older_key_variable_is_read_too(server, capsys, monkeypatch):
    monkeypatch.setenv("SESSION_API_KEY", SECRET)
    server.routes[("GET", LIST_PATH)] = (200, [])

    run(capsys, "list", "--url", server.url)

    assert header(server.requests[0], "X-Session-API-Key") == SECRET


def test_no_key_header_when_none_is_set(server, capsys):
    server.routes[("GET", LIST_PATH)] = (200, [])

    run(capsys, "list", "--url", server.url)

    assert header(server.requests[0], "X-Session-API-Key") is None


def test_the_key_is_not_an_option_and_a_mistyped_one_is_not_echoed(capsys):
    """argparse normally repeats what it did not understand, on stderr. A key typed
    as an option, or in the place of a value, must not be printed back."""
    for argv in (
        ["list", "--session-key", SECRET],
        ["resolve", str(uuid.uuid4()), SECRET],  # in the place of the action
        ["bogus-command", SECRET],
    ):
        with pytest.raises(SystemExit) as exit_info:
            cli.main(argv)
        shown = capsys.readouterr()
        assert exit_info.value.code == 2
        assert SECRET not in shown.out + shown.err, argv


def test_a_missing_argument_is_still_explained(capsys):
    """Only messages that repeat the operator's text are withheld."""
    with pytest.raises(SystemExit):
        cli.main(["resolve"])
    assert "the following arguments are required" in capsys.readouterr().err


def test_the_key_is_never_sent_over_plain_http_to_another_host(capsys, monkeypatch):
    monkeypatch.setenv("OH_SESSION_API_KEYS_0", SECRET)

    code, out, err = run(capsys, "list", "--url", "http://agent.example.com:8000")

    assert code == 2 and "plain http" in err
    assert SECRET not in out + err  # and nothing was connected to (no such host)


def test_a_401_tells_the_operator_which_variable_to_set(server, capsys):
    server.routes[("GET", LIST_PATH)] = (401, {"detail": "Unauthorized"})

    code, _, err = run(capsys, "list", "--url", server.url)

    assert code == 1 and "OH_SESSION_API_KEYS_0" in err


def test_a_redirect_is_not_followed_so_the_key_cannot_follow_it(
    server, capsys, monkeypatch
):
    monkeypatch.setenv("OH_SESSION_API_KEYS_0", SECRET)
    server.routes[("GET", LIST_PATH)] = (
        302,
        {"detail": "moved"},
        {"Location": f"{server.url}/elsewhere"},
    )
    server.routes[("GET", "/elsewhere")] = (200, [])

    code, _, err = run(capsys, "list", "--url", server.url)

    assert code == 1 and "302" in err
    assert [r["path"] for r in server.requests] == [LIST_PATH]  # /elsewhere never asked


def test_an_unreachable_server_is_a_connection_error(capsys):
    code, _, err = run(capsys, "list", "--url", "http://127.0.0.1:9")

    assert code == 2 and "cannot reach" in err


@pytest.mark.parametrize("bad", ["ftp://x", "not a url", "http://"])
def test_a_bad_url_is_refused(capsys, bad):
    code, _, err = run(capsys, "list", "--url", bad)

    assert code == 2 and "not a usable server url" in err


@pytest.mark.parametrize(
    "url",
    [
        "http://user:hunter2@127.0.0.1:9",
        "https://admin:hunter2@agent.example.com",
        "http://:hunter2@127.0.0.1:9",
        "http://hunter2@127.0.0.1:9",  # a user name alone can be a token too
    ],
)
def test_credentials_in_the_url_are_refused_not_merely_not_echoed(capsys, url):
    """Refused outright: a url that is accepted would just fail to connect, with
    nothing in the output to say that credentials do not belong there."""
    code, out, err = run(capsys, "list", "--url", url)

    assert code == 2 and "must not contain credentials" in err
    assert "hunter2" not in out + err


def test_a_bad_scheme_does_not_make_the_message_echo_the_credentials(capsys):
    code, out, err = run(capsys, "list", "--url", "ftp://user:hunter2@x")

    assert code == 2 and "hunter2" not in out + err


@pytest.mark.parametrize(
    ("url", "why"),
    [
        ("http://127.0.0.1:bad", "bad port"),
        ("http://127.0.0.1:99999999", "bad port"),
        ("http://127.0.0.1:9?x=1", "query"),
        ("http://127.0.0.1:9#frag", "query"),
        ("http://127.0.0.1:9/a;b=1", "query"),
    ],
)
def test_an_url_with_a_bad_port_or_extras_is_a_controlled_error(capsys, url, why):
    """These used to escape as an uncaught exception or silently build a wrong path."""
    code, _, err = run(capsys, "list", "--url", url)

    assert code == 2 and why in err and "Traceback" not in err


def test_a_path_prefix_in_the_url_is_kept(server, capsys):
    server.routes[("GET", "/prefix" + LIST_PATH)] = (200, [])

    code, _, _ = run(capsys, "list", "--url", server.url + "/prefix/")

    assert code == 0 and server.requests[0]["path"] == "/prefix" + LIST_PATH


def test_a_connection_error_names_only_the_host_not_the_rest_of_the_url(capsys):
    code, _, err = run(capsys, "list", "--url", "http://127.0.0.1:9/private-prefix")

    assert code == 2 and "127.0.0.1:9" in err and "private-prefix" not in err


# ------------------------- odd answers from the server -------------------------


def test_an_answer_that_is_too_large_is_not_read(server, capsys, monkeypatch):
    monkeypatch.setattr(cli, "MAX_RESPONSE_BYTES", 50)
    server.routes[("GET", LIST_PATH)] = (200, [ITEM] * 5)

    code, _, err = run(capsys, "list", "--url", server.url)

    assert code == 2 and "larger than" in err


@pytest.mark.parametrize(
    "answer",
    [
        b"<html>not json</html>",
        b'"just a string"',
        b"{}",
        b"[{}]",  # a list, but its items are not records
        b'[{"conversation_id": 5}]',
        b"[1, 2]",
    ],
)
def test_a_list_answer_of_the_wrong_shape_is_a_controlled_error(server, capsys, answer):
    server.routes[("GET", LIST_PATH)] = (200, answer)

    code, _, err = run(capsys, "list", "--url", server.url)

    assert code == 1 and "not in the shape" in err and "Traceback" not in err


@pytest.mark.parametrize("answer", [b"{}", b"[]", b"not json", b'{"action": 1}'])
def test_a_resolve_answer_of_the_wrong_shape_is_a_controlled_error(
    server, capsys, answer
):
    server.routes[("POST", RESOLVE_PATH)] = (200, answer)

    code, _, err = run(
        capsys, "resolve", CID, "retry", "--request-id", "r", "--url", server.url
    )

    assert code == 1 and "not in the shape" in err and "Traceback" not in err


def test_an_answer_cut_short_is_reported_as_such(server, capsys):
    """Cut at a point that happens to be valid JSON, so only the length can tell."""
    server.routes[("GET", LIST_PATH)] = (200, b"[]", {"Content-Length": "500"})

    code, _, err = run(capsys, "list", "--url", server.url)

    assert code == 2 and "cut short" in err and "Traceback" not in err


@pytest.mark.parametrize("blank", ["", "   "])
def test_an_empty_request_id_is_refused_before_any_request(server, capsys, blank):
    code, _, err = run(
        capsys, "resolve", CID, "retry", "--request-id", blank, "--url", server.url
    )

    assert code == 2 and "empty" in err and server.requests == []


# --------------------------------- resolve ---------------------------------


def test_resolve_with_a_request_id_sends_exactly_that(server, capsys):
    server.routes[("POST", RESOLVE_PATH)] = (200, OK_RESULT)

    code, out, _ = run(
        capsys,
        "resolve",
        CID,
        "dismiss",
        "--request-id",
        "req-1",
        "--note",
        "  checked at central  ",
        "--operator",
        "  ada  ",
        "--url",
        server.url,
    )

    assert code == 0
    (post,) = server.posts()
    assert post["body"] == {
        "action": "dismiss",
        "expected_request_id": "req-1",
        "note": "checked at central",
        "operator": "ada",
    }
    assert len(server.requests) == 1  # no list fetch: the id was given
    assert "resolved_manually" in out


def test_a_conversation_id_without_hyphens_is_accepted(server, capsys):
    server.routes[("POST", RESOLVE_PATH)] = (200, OK_RESULT)

    code, _, _ = run(
        capsys,
        "resolve",
        CID.replace("-", ""),
        "retry",
        "--request-id",
        "req-1",
        "--url",
        server.url,
    )

    assert code == 0 and server.posts()[0]["path"] == RESOLVE_PATH


def test_a_bad_conversation_id_is_refused_before_any_request_and_not_echoed(
    server, capsys
):
    """Whatever was typed in that position may be a secret typed in the wrong place."""
    code, out, err = run(
        capsys, "resolve", SECRET, "retry", "--request-id", "r", "--url", server.url
    )

    assert code == 2 and "not a UUID" in err and server.requests == []
    assert SECRET not in out + err


def test_dismiss_without_a_note_is_refused_before_any_request(server, capsys):
    for note in ([], ["--note", "   "]):
        code, _, err = run(
            capsys,
            "resolve",
            CID,
            "dismiss",
            "--request-id",
            "r",
            *note,
            "--url",
            server.url,
        )
        assert code == 2 and "needs --note" in err
    assert server.requests == []


def test_yes_without_a_request_id_is_refused(server, capsys):
    """--yes must not become a way to act on a record nobody looked at."""
    code, _, err = run(capsys, "resolve", CID, "abandon", "--yes", "--url", server.url)

    assert code == 2 and "--yes needs --request-id" in err and server.requests == []


def test_yes_with_a_request_id_does_not_ask(server, capsys, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("must not ask"))
    server.routes[("POST", RESOLVE_PATH)] = (200, {**OK_RESULT, "action": "abandon"})

    code, _, _ = run(
        capsys,
        "resolve",
        CID,
        "abandon",
        "--request-id",
        "req-1",
        "--yes",
        "--url",
        server.url,
    )

    assert code == 0


def test_without_a_request_id_it_shows_the_record_then_quotes_the_id_it_showed(
    server, capsys, monkeypatch
):
    server.routes[("GET", LIST_PATH)] = (200, [ITEM])
    server.routes[("POST", RESOLVE_PATH)] = (200, {**OK_RESULT, "action": "retry"})
    monkeypatch.setattr("builtins.input", lambda *_: "y")

    code, out, _ = run(capsys, "resolve", CID, "retry", "--url", server.url)

    assert code == 0
    assert "device_not_bound" in out and "About to retry" in out
    assert server.posts()[0]["body"]["expected_request_id"] == "req-1"


@pytest.mark.parametrize("answer", ["n", "", "no", "yes please no"])
def test_anything_but_yes_declines_and_sends_nothing(
    server, capsys, monkeypatch, answer
):
    server.routes[("GET", LIST_PATH)] = (200, [ITEM])
    monkeypatch.setattr("builtins.input", lambda *_: answer)

    code, _, err = run(capsys, "resolve", CID, "abandon", "--url", server.url)

    assert code == 1 and "not done" in err and server.posts() == []


def test_no_input_at_all_declines(server, capsys, monkeypatch):
    server.routes[("GET", LIST_PATH)] = (200, [ITEM])

    def _eof(*_):
        raise EOFError

    monkeypatch.setattr("builtins.input", _eof)

    code, _, _ = run(capsys, "resolve", CID, "abandon", "--url", server.url)

    assert code == 1 and server.posts() == []


def test_a_conversation_that_needs_nothing_is_reported_and_nothing_is_sent(
    server, capsys
):
    server.routes[("GET", LIST_PATH)] = (200, [])

    code, _, err = run(capsys, "resolve", CID, "retry", "--url", server.url)

    assert code == 1 and "nothing there needs attention" in err and server.posts() == []


def test_an_action_the_record_does_not_allow_is_refused_locally(
    server, capsys, monkeypatch
):
    server.routes[("GET", LIST_PATH)] = (
        200,
        [{**ITEM, "reason": "report_failed", "allowed_actions": ["retry", "dismiss"]}],
    )
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("must not ask"))

    code, _, err = run(capsys, "resolve", CID, "abandon", "--url", server.url)

    assert code == 1 and "not allowed" in err and "retry, dismiss" in err
    assert server.posts() == []


def test_a_refusal_from_the_server_is_shown_with_what_is_allowed(server, capsys):
    server.routes[("POST", RESOLVE_PATH)] = (
        409,
        {
            "detail": {
                "error_code": "action_not_allowed",
                "detail": "abandon is not allowed",
                "allowed_actions": ["retry", "dismiss"],
            }
        },
    )

    code, _, err = run(
        capsys, "resolve", CID, "abandon", "--request-id", "req-1", "--url", server.url
    )

    assert code == 1
    assert "action_not_allowed" in err and "allowed: retry, dismiss" in err


def test_central_failures_are_shown_by_name(server, capsys):
    server.routes[("POST", RESOLVE_PATH)] = (
        424,
        {
            "detail": {
                "error_code": "central_failed",
                "detail": "central refused the cancel (x)",
                "allowed_actions": None,
            }
        },
    )

    code, _, err = run(
        capsys, "resolve", CID, "abandon", "--request-id", "req-1", "--url", server.url
    )

    assert code == 1 and "central_failed" in err


def test_a_conversation_still_waiting_is_called_out(server, capsys):
    server.routes[("POST", RESOLVE_PATH)] = (
        200,
        {**OK_RESULT, "conversation_still_waiting": True},
    )

    _, out, _ = run(
        capsys,
        "resolve",
        CID,
        "dismiss",
        "--request-id",
        "req-1",
        "--note",
        "n",
        "--url",
        server.url,
    )

    assert "STILL waiting" in out


def test_retry_says_nothing_was_sent_yet(server, capsys):
    server.routes[("POST", RESOLVE_PATH)] = (
        200,
        {**OK_RESULT, "action": "retry", "new_state": "claim_inflight"},
    )

    _, out, _ = run(
        capsys, "resolve", CID, "retry", "--request-id", "req-1", "--url", server.url
    )

    assert "nothing was sent yet" in out and "claim_inflight" in out


def test_central_step_is_reported_for_an_abandon(server, capsys):
    server.routes[("POST", RESOLVE_PATH)] = (
        200,
        {
            **OK_RESULT,
            "action": "abandon",
            "new_state": "cancelled",
            "central_step": "aborted",
        },
    )

    _, out, _ = run(
        capsys, "resolve", CID, "abandon", "--request-id", "req-1", "--url", server.url
    )

    assert "central: aborted" in out


def test_the_operator_defaults_to_the_login_name(server, capsys, monkeypatch):
    server.routes[("POST", RESOLVE_PATH)] = (200, {**OK_RESULT, "action": "retry"})
    monkeypatch.setattr(cli.getpass, "getuser", lambda: "login-name")

    for extra in ([], ["--operator", "   "]):  # blank counts as not given
        server.requests.clear()
        code, _, _ = run(
            capsys,
            "resolve",
            CID,
            "retry",
            "--request-id",
            "req-1",
            "--url",
            server.url,
            *extra,
        )
        assert code == 0
        assert server.posts()[0]["body"]["operator"] == "login-name"


def test_no_login_name_and_no_operator_is_refused_before_any_request(
    server, capsys, monkeypatch
):
    def _no_user():
        raise OSError("no user")

    monkeypatch.setattr(cli.getpass, "getuser", _no_user)

    code, _, err = run(
        capsys, "resolve", CID, "retry", "--request-id", "req-1", "--url", server.url
    )

    assert code == 2 and "--operator" in err and server.requests == []


def test_the_prompt_says_who_it_is_acting_as_and_that_it_is_not_verified(
    server, capsys, monkeypatch
):
    server.routes[("GET", LIST_PATH)] = (200, [ITEM])
    server.routes[("POST", RESOLVE_PATH)] = (200, {**OK_RESULT, "action": "retry"})
    monkeypatch.setattr("builtins.input", lambda *_: "y")

    code, out, _ = run(
        capsys, "resolve", CID, "retry", "--operator", "ada", "--url", server.url
    )

    assert code == 0
    assert "Acting as 'ada' (self-declared, not verified)" in out


# ------------------------------ --outcome (dismiss) ------------------------------


def test_outcome_is_sent_with_a_dismiss(server, capsys):
    server.routes[("POST", RESOLVE_PATH)] = (200, OK_RESULT)

    code, _, _ = run(
        capsys,
        "resolve",
        CID,
        "dismiss",
        "--request-id",
        "req-1",
        "--note",
        "checked",
        "--operator",
        "ada",
        "--outcome",
        "confirmed_executed",
        "--url",
        server.url,
    )

    assert code == 0
    assert server.posts()[0]["body"]["outcome"] == "confirmed_executed"


def test_no_outcome_is_sent_unless_asked_for(server, capsys):
    server.routes[("POST", RESOLVE_PATH)] = (200, OK_RESULT)
    run(
        capsys,
        "resolve",
        CID,
        "dismiss",
        "--request-id",
        "req-1",
        "--note",
        "checked",
        "--url",
        server.url,
    )
    assert "outcome" not in server.posts()[0]["body"]


@pytest.mark.parametrize("action", ["retry", "abandon"])
def test_an_outcome_with_another_action_is_refused_before_any_request(
    server, capsys, action
):
    code, _, err = run(
        capsys,
        "resolve",
        CID,
        action,
        "--request-id",
        "req-1",
        "--outcome",
        "inconclusive",
        "--url",
        server.url,
    )
    assert code == 2 and "--outcome only goes with dismiss" in err
    assert server.requests == []


def test_an_unknown_outcome_value_is_refused(server, capsys):
    with pytest.raises(SystemExit) as exit_info:
        run(
            capsys,
            "resolve",
            CID,
            "dismiss",
            "--request-id",
            "req-1",
            "--note",
            "x",
            "--outcome",
            "probably_ran",
            "--url",
            server.url,
        )
    assert exit_info.value.code == 2
    assert server.requests == []


def test_the_prompt_says_central_is_told_first_and_a_refused_outcome_is_not_sent(
    server, capsys, monkeypatch
):
    asserting = {**ITEM, "allowed_outcomes": ["inconclusive"]}
    server.routes[("GET", LIST_PATH)] = (200, [asserting])
    server.routes[("POST", RESOLVE_PATH)] = (200, OK_RESULT)
    monkeypatch.setattr("builtins.input", lambda *_: "y")

    code, out, _ = run(
        capsys,
        "resolve",
        CID,
        "dismiss",
        "--note",
        "x",
        "--outcome",
        "inconclusive",
        "--url",
        server.url,
    )
    assert code == 0 and "It first tells central: inconclusive" in out

    # an outcome the record does not allow is refused before asking anyone
    server.requests.clear()
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("must not ask"))
    code, _, err = run(
        capsys,
        "resolve",
        CID,
        "dismiss",
        "--note",
        "x",
        "--outcome",
        "confirmed_executed",
        "--url",
        server.url,
    )
    assert code == 1 and "cannot be asserted" in err and server.posts() == []


def test_list_shows_which_outcomes_a_record_allows(server, capsys):
    server.routes[("GET", LIST_PATH)] = (
        200,
        [{**ITEM, "allowed_outcomes": ["confirmed_executed", "inconclusive"]}],
    )
    code, out, _ = run(capsys, "list", "--url", server.url)
    assert code == 0
    assert "outcomes      confirmed_executed, inconclusive" in out

    server.routes[("GET", LIST_PATH)] = (200, [ITEM])
    _, out, _ = run(capsys, "list", "--url", server.url)
    assert "outcomes" not in out
