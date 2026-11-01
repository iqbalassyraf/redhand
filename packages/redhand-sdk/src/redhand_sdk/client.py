"""
RedHand SDK - Async HTTPX Telemetry & STS Broker Client
File: packages/redhand-sdk/src/redhand_sdk/client.py
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import httpx

from redhand_sdk.cache import get_default_cache
from redhand_sdk.models import (
    AWSEphemeralTokenMintResponse,
    EphemeralTokenMintResponse,
    TelemetryBatchIngestRequest,
    TelemetryIngestResponse,
    TraceSpanItem,
)

logger = logging.getLogger("redhand.sdk.client")


class RedHandClient:
    """
    Asynchronous HTTPX client bridging `redhand-sdk` to `redhand-core`.
    Handles both immediate flush (for security blocks & HITL pauses) and
    non-blocking background span shipping.
    """

    def __init__(
        self,
        *,
        core_url: str | None = None,
        api_key: str | None = None,
        external_agent_id: str = "default-agent",
        agent_name: str = "RedHand Protected Agent",
        framework: str = "custom",
        environment: str = "development",
        default_resume_webhook_url: str | None = None,
        offline_mode: bool = False,
    ) -> None:
        self.core_url = (
            core_url or os.environ.get("REDHAND_CORE_URL", "http://localhost:8000")
        ).rstrip("/")
        self.api_key = api_key or os.environ.get("REDHAND_API_KEY", "rh_dev_local_key")
        self.external_agent_id = external_agent_id
        self.agent_name = agent_name
        self.framework = framework
        self.environment = environment
        self.default_resume_webhook_url = default_resume_webhook_url
        self.offline_mode = offline_mode

        self._http = httpx.AsyncClient(
            base_url=self.core_url,
            headers={"X-RedHand-API-Key": self.api_key},
            timeout=httpx.Timeout(5.0, connect=2.0),
        )
        self._background_tasks: set[asyncio.Task[Any]] = set()

    async def flush_spans(
        self,
        spans: list[TraceSpanItem],
    ) -> TelemetryIngestResponse | None:
        """Immediately transmits a batch of spans to `/v1/telemetry/ingest`."""
        if not spans or self.offline_mode:
            return None

        batch = TelemetryBatchIngestRequest(
            external_agent_id=self.external_agent_id,
            agent_name=self.agent_name,
            framework=self.framework,
            environment=self.environment,
            spans=spans,
        )

        try:
            resp = await self._http.post(
                "/v1/telemetry/ingest",
                content=batch.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            return TelemetryIngestResponse.model_validate(resp.json())
        except httpx.HTTPError as exc:
            logger.warning("Telemetry flush to redhand-core failed (%s); continuing.", exc)
            return None

    def enqueue_span(self, span: TraceSpanItem) -> None:
        """Schedules a non-blocking telemetry flush on the active event loop."""
        if self.offline_mode:
            return
        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(self.flush_spans([span]))
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
        except RuntimeError:
            pass

    async def mint_ephemeral_gcp_token(
        self,
        *,
        trace_id: str,
        span_id: str,
        tool_name: str,
        target_resource: str,
        permissions: list[str],
        condition_expression: str | None = None,
    ) -> EphemeralTokenMintResponse | None:
        """Requests a single-use GCP STS downscoped token from `redhand-core` with caching."""
        if self.offline_mode:
            return None

        cache = get_default_cache()
        cached = cache.get_token(
            provider="gcp",
            target_resource=target_resource,
            permissions=permissions,
            agent_id=self.external_agent_id,
        )
        if isinstance(cached, EphemeralTokenMintResponse):
            return cached

        payload: dict[str, Any] = {
            "trace_id": trace_id,
            "span_id": span_id,
            "external_agent_id": self.external_agent_id,
            "tool_name": tool_name,
            "target_resource": target_resource,
            "permissions": permissions,
        }
        if condition_expression:
            payload["condition"] = {
                "title": f"redhand_jit_{span_id}",
                "expression": condition_expression,
            }

        resp = await self._http.post("/v1/iam/mint/gcp", json=payload)
        resp.raise_for_status()
        token = EphemeralTokenMintResponse.model_validate(resp.json())
        cache.put_token(
            provider="gcp",
            target_resource=target_resource,
            permissions=permissions,
            agent_id=self.external_agent_id,
            token=token,
        )
        return token

    async def mint_ephemeral_aws_token(
        self,
        *,
        trace_id: str,
        span_id: str,
        tool_name: str,
        role_arn: str,
        target_resource_arn: str,
        actions: list[str],
        duration_seconds: int = 900,
    ) -> AWSEphemeralTokenMintResponse | None:
        """Requests short-lived downscoped AWS credentials from `redhand-core` via STS Session Policy."""
        if self.offline_mode:
            return None

        cache = get_default_cache()
        cached = cache.get_token(
            provider="aws",
            target_resource=target_resource_arn,
            permissions=actions,
            agent_id=self.external_agent_id,
        )
        if isinstance(cached, AWSEphemeralTokenMintResponse):
            return cached

        payload: dict[str, Any] = {
            "trace_id": trace_id,
            "span_id": span_id,
            "external_agent_id": self.external_agent_id,
            "tool_name": tool_name,
            "role_arn": role_arn,
            "target_resource_arn": target_resource_arn,
            "actions": actions,
            "duration_seconds": duration_seconds,
        }

        resp = await self._http.post("/v1/iam/mint/aws", json=payload)
        resp.raise_for_status()
        token = AWSEphemeralTokenMintResponse.model_validate(resp.json())
        cache.put_token(
            provider="aws",
            target_resource=target_resource_arn,
            permissions=actions,
            agent_id=self.external_agent_id,
            token=token,
        )
        return token

    async def aclose(self) -> None:
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        await self._http.aclose()


_default_client: RedHandClient | None = None


def configure_redhand(**kwargs: Any) -> RedHandClient:
    """Configures and returns the global default `RedHandClient` instance."""
    global _default_client
    _default_client = RedHandClient(**kwargs)
    return _default_client


def get_default_client() -> RedHandClient:
    global _default_client
    if _default_client is None:
        _default_client = RedHandClient()
    return _default_client

