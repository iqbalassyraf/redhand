"""
What may be logged about an outbound request (CLAUDE.md section 5.2). A webhook URL is a credential: a Slack incoming-webhook URL is the
secret itself and a resume URL can carry a token in its path or query. httpx also copies the whole URL into its own error text, so logging
the exception leaks it too. Log the host, and the error's type and HTTP status, never the URL or the exception message.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

INVALID_ADDRESS = "an invalid address"


def safe_host(url: str) -> str:
    """The host of a URL, with no scheme, credentials, port, path or query. A string that is not a URL becomes a fixed phrase."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return INVALID_ADDRESS
    return host if host else INVALID_ADDRESS


def safe_error(exc: BaseException) -> str:
    """The exception's type, plus the HTTP status when there is one: enough to debug, nothing that came from the URL."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"{type(exc).__name__} (HTTP {exc.response.status_code})"
    return type(exc).__name__
