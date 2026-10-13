"""Operator CLI for conversations whose governance outbox is parked in NEEDS_ATTENTION.

  python governance_attention_cli.py list [--json] [--url URL]
  python governance_attention_cli.py resolve <conversation-id> retry|abandon|dismiss
         [--request-id ID] [--note TEXT] [--yes] [--url URL]

It talks to one agent-server's GET /api/governance/attention and
POST /api/governance/attention/{id}/resolve (see design.md in this directory).
Standard library only.

Settings (environment, or --url):
  OH_AGENT_SERVER_URL      default http://127.0.0.1:8000
  OH_SESSION_API_KEYS_0    the session API key, if the server has one
                           (SESSION_API_KEY is read too). Never taken from the
                           command line, never printed, and not sent over plain http
                           to anything but a loopback address.

`resolve` acts on the record you were shown. With --request-id it quotes that id;
without it the CLI shows you the record as it is right now, asks, and quotes the id it
just showed. --yes only skips that question and therefore requires --request-id: there
is no way to act on a record you have not seen.

Exit status: 0 done, 1 refused (by you or by the server), 2 usage, configuration or
connection problem.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any


DEFAULT_URL = "http://127.0.0.1:8000"
URL_ENV = "OH_AGENT_SERVER_URL"
KEY_ENVS = ("OH_SESSION_API_KEYS_0", "SESSION_API_KEY")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
ACTIONS = ("retry", "abandon", "dismiss")
TIMEOUT_SECONDS = 30
# Far above any real answer (a list of a few records). A bigger body is refused unread.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

EFFECT = {
    "retry": "re-arm the step that failed; the relay repeats it within about one "
    "relay cycle (30 seconds)",
    "abandon": "withdraw the approval at central, reject the pending action here "
    "and end the record",
    "dismiss": "end the record with no other effect (the conversation may still be "
    "waiting on the action)",
}


class CliError(Exception):
    """Something the operator has to fix; ``code`` is the exit status."""

    def __init__(self, message: str, code: int = 2) -> None:
        super().__init__(message)
        self.code = code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the session key would go with it."""

    def redirect_request(self, *_args: Any, **_kwargs: Any):
        return None


def session_key() -> str | None:
    for name in KEY_ENVS:
        value = os.environ.get(name)
        if value:
            return value
    return None


def display_url(url: str) -> str:
    """scheme://host[:port] only. Anything else in a URL (credentials, path, query)
    can be a secret, so it is never echoed in a message."""
    parsed = urllib.parse.urlparse(url)
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        port = ""
    return f"{parsed.scheme}://{parsed.hostname or '?'}{port}"


def base_url(url_arg: str | None) -> str:
    url = (url_arg or os.environ.get(URL_ENV) or DEFAULT_URL).rstrip("/")
    expected = "expected http(s)://host:port"
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise CliError(f"not a usable server url ({expected})")
    if parsed.username is not None or parsed.password is not None:
        raise CliError(
            "the server url must not contain credentials; the session API key goes "
            "in OH_SESSION_API_KEYS_0"
        )
    try:
        _ = parsed.port  # raises ValueError for a port that is not a number
    except ValueError:
        raise CliError(f"not a usable server url: bad port ({expected})") from None
    if parsed.query or parsed.fragment or parsed.params:
        raise CliError(
            f"not a usable server url: no ?query, #fragment or ;params ({expected}"
            "[/prefix])"
        )
    return url


def check_transport(url: str, key: str | None) -> None:
    parsed = urllib.parse.urlparse(url)
    if key and parsed.scheme == "http" and parsed.hostname not in LOOPBACK_HOSTS:
        raise CliError(
            "refusing to send the session API key over plain http to "
            f"{parsed.hostname}; use https, or a loopback address"
        )


def _parse(raw: bytes) -> Any:
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except ValueError:
        return text[:200]


def call(method: str, url: str, key: str | None, body: dict | None = None):
    """(status, parsed body). Raises CliError if the server cannot be reached."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if key:
        request.add_header("X-Session-API-Key", key)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            return response.status, _parse(_read_capped(response))
    except urllib.error.HTTPError as exc:
        return exc.code, _parse(_read_capped(exc))
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        raise CliError(
            f"cannot reach {display_url(url)}: {type(exc).__name__}"
        ) from exc


def _read_capped(response) -> bytes:
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) <= MAX_RESPONSE_BYTES:
        # read(n) hands back whatever arrived, without complaint, if the connection
        # ends early; a cut-short answer must not be mistaken for a short complete one.
        # (Not applicable to an over-long answer: only part of that was asked for.)
        declared = response.headers.get("Content-Length")
        if declared is not None and declared.isdigit() and len(raw) < int(declared):
            raise CliError(
                "the server's answer was cut short (the connection ended early)"
            )
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CliError(
            f"the server's answer is larger than {MAX_RESPONSE_BYTES} bytes; "
            "not reading it"
        )
    return raw


_UNEXPECTED_ANSWER = (
    "the server answered, but not in the shape this tool expects "
    "(a different server version?)"
)


def _error_text(status: int, body: Any) -> str:
    if status == 401:
        return (
            "the server wants a session API key (401): set OH_SESSION_API_KEYS_0 "
            "(or SESSION_API_KEY) to the same value the server uses"
        )
    detail = body.get("detail") if isinstance(body, dict) else body
    if isinstance(detail, dict):
        text = f"{detail.get('error_code', status)}: {detail.get('detail', '')}"
        if detail.get("allowed_actions"):
            text += f" (allowed: {', '.join(detail['allowed_actions'])})"
        return text
    return f"HTTP {status}: {detail}"


def fetch_items(url: str, key: str | None) -> list[dict]:
    status, body = call("GET", f"{url}/api/governance/attention", key)
    if status != 200:
        raise CliError(_error_text(status, body), code=1)
    if not isinstance(body, list) or not all(
        isinstance(i, dict) and isinstance(i.get("conversation_id"), str) for i in body
    ):
        raise CliError(_UNEXPECTED_ANSWER, code=1)
    return body


# What to do next, for the reasons where it is not just "pick an action".
_NEXT_STEP = {
    "claim_transient": (
        "the claim failed, maybe only for a moment: run `resolve retry` once"
    ),
    "claim_retry_failed": (
        "the claim was retried and failed again: ask a superadmin to find out "
        "what happened (do not retry again)"
    ),
}


def _describe(item: dict) -> str:
    code = f" ({item['last_error_code']})" if item.get("last_error_code") else ""
    step = _NEXT_STEP.get(item.get("reason"))
    return "\n".join(
        [
            f"  conversation  {item['conversation_id']}",
            f"  reason        {item.get('reason')}{code}",
            f"  attempts      {item.get('attempt_count')}, "
            f"last {item.get('last_attempt_at')}",
            f"  request_id    {item.get('request_id')}",
            f"  allowed       {', '.join(item.get('allowed_actions') or []) or 'none'}",
            *([f"  next          {step}"] if step else []),
        ]
    )


def cmd_list(args: argparse.Namespace) -> int:
    url = base_url(args.url)
    key = session_key()
    check_transport(url, key)
    items = fetch_items(url, key)
    if args.json:
        print(json.dumps(items, indent=2))
    elif not items:
        print("Nothing needs attention.")
    else:
        print(f"{len(items)} conversation(s) need attention:\n")
        print("\n\n".join(_describe(i) for i in items))
        unreadable = [i for i in items if i.get("reason") == "unreadable_outbox"]
        if unreadable:
            print(
                f"\n{len(unreadable)} outbox file(s) could not be read: they are "
                "damaged, too large, a link, or written by a newer version. Nothing "
                "can be done "
                "to them from here."
            )
    return 0


def cmd_resolve(args: argparse.Namespace) -> int:
    action = args.action
    note = (args.note or "").strip() or None
    if action == "dismiss" and note is None:
        raise CliError("dismiss needs --note saying why")
    if args.request_id is not None and not args.request_id.strip():
        raise CliError("--request-id is empty")
    if args.yes and not args.request_id:
        raise CliError(
            "--yes needs --request-id: this does not act on a record you have not seen"
        )
    try:
        conversation_id = str(uuid.UUID(args.conversation_id))
    except ValueError:
        # Not echoed: whatever was typed here may be something else, a key for one.
        raise CliError("the conversation id is not a UUID") from None
    url = base_url(args.url)
    key = session_key()
    check_transport(url, key)

    request_id = args.request_id
    if request_id is None:
        item = next(
            (
                i
                for i in fetch_items(url, key)
                if i["conversation_id"] == conversation_id
            ),
            None,
        )
        if item is None:
            raise CliError(
                f"{conversation_id} is not in the list: nothing there needs attention",
                code=1,
            )
        print(_describe(item))
        if action not in (item.get("allowed_actions") or []):
            raise CliError(
                f"{action} is not allowed for this record "
                f"(allowed: {', '.join(item.get('allowed_actions') or []) or 'none'})",
                code=1,
            )
        print(f"\nAbout to {action}: {EFFECT[action]}.")
        try:
            answer = input("Go ahead? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in ("y", "yes"):
            raise CliError("not done", code=1)
        request_id = item["request_id"]

    body: dict[str, Any] = {"action": action, "expected_request_id": request_id}
    if note is not None:
        body["note"] = note
    status, result = call(
        "POST", f"{url}/api/governance/attention/{conversation_id}/resolve", key, body
    )
    if status != 200:
        raise CliError(_error_text(status, result), code=1)
    if not isinstance(result, dict) or not all(
        isinstance(result.get(k), str) for k in ("action", "new_state")
    ):
        raise CliError(_UNEXPECTED_ANSWER, code=1)

    print(f"{result['action']}: record is now {result['new_state']}")
    if result.get("central_step") not in (None, "not_applicable"):
        print(f"  central: {result['central_step']}")
    if result.get("conversation_still_waiting"):
        print(
            "  the conversation is STILL waiting for confirmation of this action; "
            "reject it (or abandon) before it can move on"
        )
    if action == "retry":
        print(
            "  nothing was sent yet: the relay repeats the step within about 30 seconds"
        )
    return 0


class _QuietParser(argparse.ArgumentParser):
    """argparse echoes what it could not understand ("unrecognized arguments: ...",
    "invalid choice: ..."). A secret typed in the wrong place (say, --session-key
    sk-...) would be printed to the terminal, so only messages that contain none of
    the operator's text are shown as they are."""

    _SAFE_PREFIXES = ("the following arguments are required",)

    def error(self, message: str):
        if not message.startswith(self._SAFE_PREFIXES):
            message = (
                "the command line was not understood (what was typed is not echoed, "
                "in case it contains a secret); see --help. The session API key is "
                "read from the environment, not from an option"
            )
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _QuietParser(
        prog="governance_attention_cli",
        description=(
            "List and resolve governance outbox records parked in NEEDS_ATTENTION."
        ),
    )
    common = _QuietParser(add_help=False)
    common.add_argument(
        "--url", help=f"agent-server base url (default: ${URL_ENV} or {DEFAULT_URL})"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser(
        "list", parents=[common], help="show conversations that need attention"
    )
    p_list.add_argument("--json", action="store_true", help="print the raw JSON")
    p_list.set_defaults(func=cmd_list)

    p_resolve = sub.add_parser(
        "resolve", parents=[common], help="retry, abandon or dismiss one record"
    )
    p_resolve.add_argument("conversation_id")
    p_resolve.add_argument("action", choices=ACTIONS)
    p_resolve.add_argument("--request-id", help="the request_id shown by `list`")
    p_resolve.add_argument("--note", help="why (required for dismiss)")
    p_resolve.add_argument(
        "--yes", action="store_true", help="do not ask; requires --request-id"
    )
    p_resolve.set_defaults(func=cmd_resolve)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.code


if __name__ == "__main__":
    sys.exit(main())
