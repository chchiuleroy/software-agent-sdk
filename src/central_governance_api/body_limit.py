"""A request-body size limit that works while the body is being read.

FastAPI reads and parses a whole JSON body before any dependency or handler runs, so a
check inside the endpoint (``admission_max_archive_bytes`` on the decoded archive) only
helps after a body of any size is already in memory. This limit sits in front, for the
paths it is given:

* a ``Content-Length`` above the limit is refused at once, before a byte is read;
* otherwise (chunked uploads, or a header that understates) the bytes are counted as
  they arrive and the request is stopped as soon as the total passes the limit.

Pure ASGI, no dependency. Only the listed ``(method, path)`` pairs are limited; every
other route is untouched.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any


Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

ERROR_CODE = "admission_content_too_large"
DETAIL = "the submitted content is too large"


class _TooLarge(Exception):
    pass


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, *, limits: dict[tuple[str, str], int]) -> None:
        self.app = app
        self.limits = limits

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.limits.get((scope["method"], scope["path"]))
        if limit is None:
            await self.app(scope, receive, send)
            return

        declared = dict(scope.get("headers", [])).get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > limit
            except ValueError:
                too_big = True
            if too_big:
                await self._refuse(send)
                return

        received = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _TooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _TooLarge:
            if not started:
                await self._refuse(send)

    @staticmethod
    async def _refuse(send: Send) -> None:
        body = json.dumps({"error_code": ERROR_CODE, "detail": DETAIL}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
