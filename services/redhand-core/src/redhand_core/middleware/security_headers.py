"""
Response headers on every answer (CLAUDE.md sections 5.3 and 5.5). Pure ASGI, so it also covers answers raised by other middleware (a 413).
  - X-Content-Type-Options: nosniff: a browser never reinterprets a JSON answer as something it can run.
  - Cache-Control: no-store, unless the route chose its own: authenticated answers, tokens and tool results must not sit in a browser or proxy cache.
  - Strict-Transport-Security: browsers stay on https (ignored over plain http, so it is harmless in development).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

FIXED_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"strict-transport-security", b"max-age=63072000; includeSubDomains"),
)
DEFAULT_CACHE_CONTROL = (b"cache-control", b"no-store")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                for name, value in (*FIXED_HEADERS, DEFAULT_CACHE_CONTROL):
                    if name not in present:
                        headers.append((name, value))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, with_headers)
