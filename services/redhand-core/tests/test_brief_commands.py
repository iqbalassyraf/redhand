"""
The night brief's ingest command (docs/testing/briefs/2026-11-13-night-1.md, Part O step O1, reused by O4, O6 and Part P) must be accepted by core's
ingest model. The first staging run of Part O got HTTP 422 because the command left out the required `sdk_version`; this test fails if the brief's
JSON body ever stops matching what core accepts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from redhand_core.routers.telemetry import TelemetryBatchIngestRequest

BRIEF = Path(__file__).resolve().parents[3] / "docs" / "testing" / "briefs" / "2026-11-13-night-1.md"


def _o1_body() -> dict[str, object]:
    row = next(line for line in BRIEF.read_text(encoding="utf-8").splitlines() if line.startswith("| O1 |"))
    match = re.search(r"-d '(\{.*?\})'", row)
    assert match, "the O1 row no longer has a -d '...' JSON body"
    body: dict[str, object] = json.loads(match.group(1))
    return body


def test_the_brief_ingest_body_is_accepted_by_core() -> None:
    request = TelemetryBatchIngestRequest.model_validate(_o1_body())
    span = request.spans[0]
    assert (span.model_provider, span.model_name, span.prompt_tokens) == ("anthropic", "claude-sonnet-5-5", 1_000_000)


def test_the_brief_body_with_part_p_changes_is_accepted_too() -> None:
    body = _o1_body()
    body["external_agent_id"] = "night-model"
    spans = body["spans"]
    assert isinstance(spans, list)
    spans[0].update({"model_provider": "openai", "model_name": "gpt-mystery"})
    TelemetryBatchIngestRequest.model_validate(body)
