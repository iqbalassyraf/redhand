"""
Request body cap for every route (CLAUDE.md section 5.6: bound all resource use).

Pure ASGI so it runs before any handler and never buffers. Two checks:
  1. A declared Content-Length over the limit is answered 413 at once, without calling the application.
  2. The bytes that actually arrive are counted. The header is only an early exit: a chunked body, or a header that lies, is stopped at the
     limit. Once the limit is passed the application is told the client went away (so a handler stops reading) and whatever it then sends is
     dropped in favour of the 413. Reading therefore stops at the limit; it does not run on to the end of an arbitrarily large body.
Bodies that legitimately exceed the default (batched event ingest, trace ingest) are named in `path_limits`; the longest matching path prefix
wins.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

TOO_LARGE_BODY = b'{"detail":"Request body too large."}'


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, *, default_limit: int, path_limits: Mapping[str, int] | None = None) -> None:
        self.app = app
        self._default = default_limit
        # Longest prefix first, so "/v1/telemetry/ingest" beats "/v1".
        self._path_limits = sorted((path_limits or {}).items(), key=lambda item: len(item[0]), reverse=True)

    def _limit_for(self, path: str) -> int:
        for prefix, limit in self._path_limits:
            if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
                return limit
        return self._default

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self._limit_for(str(scope.get("path", "")))
        for name, value in scope.get("headers", []):
            if name == b"content-length" and value.isdigit() and int(value) > limit:
                await self._refuse(send)
                return

        received = 0
        exceeded = False
        started = False

        async def limited_receive() -> Message:
            nonlocal received, exceeded
            if exceeded:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    exceeded = True
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if exceeded:
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            if not exceeded:
                raise
        if exceeded and not started:
            await self._refuse(send)

    @staticmethod
    async def _refuse(send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(TOO_LARGE_BODY)).encode()),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": TOO_LARGE_BODY})
