"""
RedHand Core - Human-in-the-Loop (HITL) Circuit Breaker Resolution Router
File: services/redhand-core/src/redhand_core/routers/hitl.py

Handles human operator approvals and denials from `redhand-ui`, verifies
cryptographic state integrity (`state_checksum`), updates durable checkpoint
state in Supabase, and asynchronously dispatches the `resume_webhook_url`
to wake up suspended agent runs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, Request, status

from redhand_core.net.outbound import OutboundBlockedError, OutboundError, insecure_webhooks_allowed, post_json, record_blocked
from redhand_core.services.safe_log import safe_host
from pydantic import BaseModel, ConfigDict, Field
from supabase import AsyncClient

from redhand_core.auth.operator import SecurityOperatorDep
from redhand_core.config import Settings, get_settings
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.services.notifications.slack import (
    parse_slack_interactive_payload,
    verify_slack_signature,
)

logger = logging.getLogger("redhand.core.hitl")

router = APIRouter(
    prefix="/v1/hitl",
    tags=["Human-in-the-Loop (HITL) Circuit Breaker"],
)


# =============================================================================
# 1. REQUEST & RESPONSE WIRE CONTRACTS
# =============================================================================


class HITLResolutionAction(str, Enum):
    APPROVE = "approve"
    DENY = "deny"


class HITLResolveRequest(BaseModel):
    """
    Payload sent by a human security operator from `redhand-ui` (or Slack webhook)
    to approve or deny a paused agent tool invocation.
    """

    model_config = ConfigDict(extra="forbid")

    action: HITLResolutionAction = Field(
        ...,
        description="Operator decision: 'approve' to resume execution or 'deny' to abort.",
    )
    reviewer_comment: str | None = Field(
        default=None,
        max_length=2048,
        description="Optional audit rationale for approving or denying the action.",
    )
    modified_tool_arguments: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Optional sanitized/modified tool arguments injected by the human reviewer "
            "prior to resuming execution."
        ),
    )


class HITLResolveResponse(BaseModel):
    """Receipt returned after resolving a pending HITL circuit-breaker intervention."""

    model_config = ConfigDict(extra="forbid")

    intervention_id: UUID
    trace_id: str
    span_id: str
    agent_id: UUID
    status: str = Field(..., examples=["approved", "denied", "partially_approved"])
    state_integrity_verified: bool = True
    resume_webhook_dispatched: bool = False
    resolved_at: datetime
    effective_tool_arguments: dict[str, Any]
    required_approvals: int = 1
    current_signatures: int = 1


# =============================================================================
# 2. INTEGRITY & ASYNC WEBHOOK HELPERS
# =============================================================================


def compute_canonical_state_checksum(state_dict: dict[str, Any]) -> str:
    """
    Recomputes the canonical SHA-256 hex digest of `serialized_agent_state`
    to verify the checkpoint was not tampered with at rest in the database.
    """
    canonical_bytes = json.dumps(state_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


async def trigger_agent_resume_webhook(
    *,
    intervention_id: UUID,
    resume_webhook_url: str,
    wake_payload: dict[str, Any],
    supabase: AsyncClient,
    timeout_seconds: float = 10.0,
) -> None:
    """
    Asynchronously dispatches an HTTP POST request to the suspended agent worker's
    `resume_webhook_url` with the verified serialized state and operator decision.
    Updates the intervention status to `'resumed'` (or `'failed'` on transport error).
    """
    try:
        response = await post_json(
            resume_webhook_url,
            wake_payload,
            allow_insecure=insecure_webhooks_allowed(),
            headers={
                "Content-Type": "application/json",
                "X-RedHand-Intervention-ID": str(intervention_id),
                "X-RedHand-Event": "hitl.approved",
            },
            timeout=timeout_seconds,
        )
        response.raise_for_status()

        await (
            supabase.table("hitl_interventions")
            .update(
                {
                    "status": "resumed",
                    "resumed_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            .eq("id", str(intervention_id))
            .execute()
        )
        logger.info(
            "Successfully woke suspended agent for intervention %s via %s",
            intervention_id,
            safe_host(resume_webhook_url),
        )
    except OutboundError as exc:
        if isinstance(exc, OutboundBlockedError):
            record_blocked("resume")
        logger.error(
            "Failed to invoke the resume webhook on %s for intervention %s: %s",
            safe_host(resume_webhook_url),
            intervention_id,
            exc,
        )
        await (
            supabase.table("hitl_interventions")
            .update({"status": "failed"})
            .eq("id", str(intervention_id))
            .execute()
        )


# =============================================================================
# 3. RESOLUTION ENDPOINT
# =============================================================================


@router.post(
    "/{intervention_id}/resolve",
    response_model=HITLResolveResponse,
    status_code=status.HTTP_200_OK,
    summary="Approve or Deny a Paused HITL Circuit-Breaker Intervention",
)
async def resolve_hitl_intervention(
    intervention_id: Annotated[UUID, Path(description="UUID of the pending HITL intervention.")],
    payload: HITLResolveRequest,
    operator: SecurityOperatorDep,
    background_tasks: BackgroundTasks,
    supabase: Annotated[AsyncClient, Depends(get_supabase_service_client)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HITLResolveResponse:
    """The reviewer is always the authenticated operator; the body cannot name one."""
    return await _resolve_intervention(
        intervention_id=intervention_id,
        payload=payload,
        reviewer_id=str(operator.user_id),
        organization_id=operator.organization_id,
        background_tasks=background_tasks,
        supabase=supabase,
        settings=settings,
    )


async def _resolve_intervention(
    *,
    intervention_id: UUID,
    payload: HITLResolveRequest,
    reviewer_id: str,
    organization_id: UUID,
    background_tasks: BackgroundTasks,
    supabase: Any,
    settings: Settings,
) -> HITLResolveResponse:
    """
    Resolves a paused Human-in-the-Loop intervention:

    1. Fetches the intervention record from `public.hitl_interventions`.
    2. Verifies it is currently in `'pending'` status and has not expired.
    3. Recomputes the SHA-256 checksum of `serialized_agent_state` and compares it
       against `state_checksum` to guarantee tamper-proof rehydration.
    4. Updates the record to `'approved'` or `'denied'` with audit timestamps.
    5. If approved, schedules an asynchronous POST callback to `resume_webhook_url`
       containing the serialized agent state and effective tool arguments.
    """
    # Step 1: Fetch the intervention record
    query_res = await (
        supabase.table("hitl_interventions")
        .select("*")
        .eq("id", str(intervention_id))
        .eq("organization_id", str(organization_id))
        .maybe_single()
        .execute()
    )

    record: dict[str, Any] | None = query_res.data if query_res else None
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"HITL intervention '{intervention_id}' not found.",
        )

    # Step 2: Enforce state machine transitions & expiration window
    current_status = record.get("status")
    if current_status not in ("pending", "partially_approved"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Intervention '{intervention_id}' cannot be resolved because its current "
                f"status is '{current_status}' (expected 'pending' or 'partially_approved')."
            ),
        )

    now_utc = datetime.now(timezone.utc)
    if raw_expires_at := record.get("expires_at"):
        expires_at = datetime.fromisoformat(str(raw_expires_at).replace("Z", "+00:00"))
        if expires_at < now_utc:
            await (
                supabase.table("hitl_interventions")
                .update({"status": "expired"})
                .eq("id", str(intervention_id))
        .eq("organization_id", str(organization_id))
                .execute()
            )
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail=f"Intervention '{intervention_id}' expired at {expires_at.isoformat()}.",
            )

    # Step 3: Cryptographic State Checksum Verification
    serialized_state: dict[str, Any] = record.get("serialized_agent_state") or {}
    expected_checksum: str = record.get("state_checksum") or ""
    actual_checksum = compute_canonical_state_checksum(serialized_state)

    if not expected_checksum or actual_checksum != expected_checksum:
        logger.critical(
            "State checksum mismatch for intervention %s! Expected=%s, Computed=%s",
            intervention_id,
            expected_checksum,
            actual_checksum,
        )
        await (
            supabase.table("hitl_interventions")
            .update({"status": "failed"})
            .eq("id", str(intervention_id))
        .eq("organization_id", str(organization_id))
            .execute()
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Cryptographic state checksum verification failed. "
                "The serialized agent state may have been tampered with at rest."
            ),
        )

    # Step 4: Multi-Signature Four-Eyes Principle Evaluation
    effective_args: dict[str, Any] = (
        payload.modified_tool_arguments
        if payload.modified_tool_arguments is not None
        else (record.get("proposed_tool_arguments") or {})
    )

    required_approvals = int(record.get("required_approvals") or 1)
    existing_approvals = list(record.get("approvals") or [])
    current_reviewer_str = reviewer_id
    now_iso = now_utc.isoformat()

    if payload.action == HITLResolutionAction.APPROVE:
        # Check if this reviewer already signed
        if any(str(appr.get("reviewer_user_id")) == current_reviewer_str for appr in existing_approvals):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Four-Eyes Principle violation: A reviewer cannot sign an approval twice.",
            )

        existing_approvals.append(
            {
                "reviewer_user_id": current_reviewer_str,
                "reviewer_comment": payload.reviewer_comment,
                "approved_at": now_iso,
            }
        )

        current_signatures = len(existing_approvals)
        if current_signatures < required_approvals:
            new_status = "partially_approved"
            is_fully_approved = False
        else:
            new_status = "approved"
            is_fully_approved = True

        update_fields: dict[str, Any] = {
            "status": new_status,
            "approvals": existing_approvals,
            "reviewer_user_id": current_reviewer_str,
            "reviewer_comment": payload.reviewer_comment,
            "approved_at": now_iso if is_fully_approved else None,
        }
    else:
        # Denial: immediate rejection
        new_status = "denied"
        is_fully_approved = False
        current_signatures = len(existing_approvals)
        update_fields = {
            "status": "denied",
            "reviewer_user_id": current_reviewer_str,
            "reviewer_comment": payload.reviewer_comment,
            "denied_at": now_iso,
        }

    if payload.modified_tool_arguments is not None:
        update_fields["modified_tool_arguments"] = payload.modified_tool_arguments

    await (
        supabase.table("hitl_interventions")
        .update(update_fields)
        .eq("id", str(intervention_id))
        .eq("organization_id", str(organization_id))
        .execute()
    )

    # Step 5: If Fully Approved, Dispatch Async Webhook to Wake Suspended Agent Run
    resume_dispatched = False
    resume_webhook_url: str | None = record.get("resume_webhook_url")

    if is_fully_approved and resume_webhook_url:
        wake_payload: dict[str, Any] = {
            "intervention_id": str(intervention_id),
            "organization_id": record.get("organization_id"),
            "agent_id": record.get("agent_id"),
            "trace_id": record.get("trace_id"),
            "span_id": record.get("span_id"),
            "status": "approved",
            "tool_name": record.get("proposed_tool_name"),
            "effective_tool_arguments": effective_args,
            "serialized_agent_state": serialized_state,
            "state_checksum": actual_checksum,
            "approvals": existing_approvals,
            "reviewer_user_id": current_reviewer_str,
            "reviewer_comment": payload.reviewer_comment,
            "resolved_at": now_iso,
        }
        background_tasks.add_task(
            trigger_agent_resume_webhook,
            intervention_id=intervention_id,
            resume_webhook_url=resume_webhook_url,
            wake_payload=wake_payload,
            supabase=supabase,
            timeout_seconds=settings.HITL_WEBHOOK_TIMEOUT_SECONDS,
        )
        resume_dispatched = True

    return HITLResolveResponse(
        intervention_id=intervention_id,
        trace_id=str(record["trace_id"]),
        span_id=str(record["span_id"]),
        agent_id=UUID(str(record["agent_id"])),
        status=new_status,
        state_integrity_verified=True,
        resume_webhook_dispatched=resume_dispatched,
        resolved_at=now_utc,
        effective_tool_arguments=effective_args,
        required_approvals=required_approvals,
        current_signatures=current_signatures,
    )


# =============================================================================
# 4. SLACK INTERACTIVITY WEBHOOK ENDPOINT
# =============================================================================


@router.post(
    "/slack/interactivity",
    status_code=status.HTTP_200_OK,
    summary="Handle Slack Block Kit Interactivity Webhook",
)
async def handle_slack_interactivity(
    request: Request,
    background_tasks: BackgroundTasks,
    supabase: Annotated[AsyncClient, Depends(get_supabase_service_client)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """
    Receives interactive payload from Slack when an operator clicks
    [Approve & Resume] or [Deny Execution] buttons in a Slack channel.
    """
    if settings.SLACK_SIGNING_SECRET is None or not settings.SLACK_ORGANIZATION_ID:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Slack interactivity is not configured.",
        )
    slack_org_id = UUID(settings.SLACK_ORGANIZATION_ID)

    body_bytes = await request.body()
    if not verify_slack_signature(
        signing_secret=settings.SLACK_SIGNING_SECRET.get_secret_value(),
        timestamp_header=request.headers.get("X-Slack-Request-Timestamp"),
        signature_header=request.headers.get("X-Slack-Signature"),
        body=body_bytes,
        now=time.time(),
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Slack request signature.",
        )

    body_str = body_bytes.decode("utf-8")
    parsed = parse_slack_interactive_payload(body_str)
    if not parsed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to parse Slack interactive payload.",
        )

    try:
        intervention_id = UUID(parsed["intervention_id"])
        reviewer_user_id = UUID(parsed["reviewer_user_id"])
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID in Slack interactive payload: {exc}",
        )

    action = (
        HITLResolutionAction.APPROVE
        if parsed["action"] == "approve"
        else HITLResolutionAction.DENY
    )

    resolve_req = HITLResolveRequest(
        action=action,
        reviewer_comment=parsed.get("reviewer_comment"),
    )

    # The Slack app is linked to exactly one organization (SLACK_ORGANIZATION_ID), so a
    # signed Slack click can only resolve that tenant's interventions. The reviewer is
    # the Slack user, derived deterministically from the signed payload.
    res = await _resolve_intervention(
        intervention_id=intervention_id,
        payload=resolve_req,
        reviewer_id=str(reviewer_user_id),
        organization_id=slack_org_id,
        background_tasks=background_tasks,
        supabase=supabase,
        settings=settings,
    )

    return {
        "response_type": "ephemeral",
        "text": (
            f"✅ Intervention `{res.intervention_id}` resolved with status: *{res.status.upper()}* "
            f"({res.current_signatures}/{res.required_approvals} approvals)."
        ),
    }

