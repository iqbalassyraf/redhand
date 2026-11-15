"""
Webhook URLs are credentials (a Slack incoming-webhook URL IS the secret; a resume URL can carry a token in its path or query), and httpx puts
the full URL into its own error text. Nothing core logs about an outbound webhook may contain more than the host. These tests put a fake
secret into the URL and read every log line (H1.2, CLAUDE.md section 5.2).
"""

from __future__ import annotations

import logging

import httpx
import pytest

from redhand_core.services.safe_log import safe_error, safe_host

SECRET = "SuperSecretWebhookToken0123456789"
URL = f"https://hooks.example.com/services/T000/B000/{SECRET}?token={SECRET}&x=1"


def test_a_url_is_reduced_to_its_host() -> None:
    assert safe_host(URL) == "hooks.example.com"
    assert safe_host("https://user:pw@internal.example.net:8443/a/b?c=d#e") == "internal.example.net"
    assert safe_host("not a url") == "an invalid address"
    assert safe_host("") == "an invalid address"
    assert SECRET not in safe_host(URL)


def test_an_error_is_reduced_to_its_type_and_status() -> None:
    request = httpx.Request("POST", URL)
    status_error = httpx.HTTPStatusError(f"Client error '404 Not Found' for url '{URL}'", request=request, response=httpx.Response(404, request=request))
    assert safe_error(status_error) == "HTTPStatusError (HTTP 404)"
    assert safe_error(httpx.ConnectError(f"failed to reach {URL}", request=request)) == "ConnectError"
    assert safe_error(httpx.ReadTimeout(f"timed out calling {URL}", request=request)) == "ReadTimeout"
    assert SECRET not in safe_error(status_error)


@pytest.mark.asyncio
async def test_slack_failure_does_not_log_the_webhook_url(caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    from redhand_core.services.notifications import slack

    async def fail(self: httpx.AsyncClient, url: str, **kwargs: object) -> httpx.Response:
        request = httpx.Request("POST", url)
        response = httpx.Response(404, request=request)
        response.raise_for_status()  # raises with the URL in its message
        return response

    monkeypatch.setattr(httpx.AsyncClient, "post", fail)
    caplog.set_level(logging.DEBUG)
    result = await slack.dispatch_slack_hitl_notification(URL, {"id": "intervention-1", "agent_id": "a", "tool_name": "t", "tool_arguments": {}})
    assert result is False
    assert SECRET not in caplog.text and "hooks.example.com" in caplog.text


@pytest.mark.asyncio
async def test_siem_failure_does_not_log_the_webhook_url(caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    from redhand_core.services.siem_exporter import SIEMExporter

    async def fail(self: httpx.AsyncClient, url: str, **kwargs: object) -> httpx.Response:
        raise httpx.ConnectError(f"cannot connect to {url}", request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.AsyncClient, "post", fail)
    caplog.set_level(logging.DEBUG)
    exporter = SIEMExporter(max_retries=1)
    assert await exporter.export_events(siem_webhook_url=URL, security_event_rows=[{"id": "e1", "message": "x"}]) is False
    assert SECRET not in caplog.text


def test_no_log_call_in_core_mentions_a_webhook_url_without_reducing_it() -> None:
    """Static guard for sites a behavioural test does not reach (the resume webhook in routers/hitl.py): inside a logger call, every
    *webhook_url argument must be wrapped in safe_host()."""
    import re
    from pathlib import Path

    source_root = Path(__file__).resolve().parents[1] / "src" / "redhand_core"
    call = re.compile(r"logger\.(?:debug|info|warning|error|exception|critical)\((?:[^()]|\([^()]*\))*\)", re.S)
    offenders: list[str] = []
    for path in source_root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for match in call.finditer(text):
            args = match.group(0)
            cleaned = re.sub(r"safe_host\(\s*\w*webhook_url\s*\)", "", args)
            if re.search(r"\b\w*webhook_url\b", cleaned):
                offenders.append(f"{path.relative_to(source_root)}: {' '.join(args.split())[:120]}")
    assert offenders == [], offenders
