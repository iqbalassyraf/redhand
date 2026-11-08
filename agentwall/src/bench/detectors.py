"""
The detectors the benchmark measures: the checks the gateway actually runs today. A detector looks at one sample and
says whether it flags it. New detectors (Radar in M4) are added to DETECTORS and the numbers move honestly.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..firewall.ast_guardrails import EgressTaintGuardrail
from ..firewall.mcp_vetting import MCPServerAuditor
from ..firewall.injection_model import SECOND_STAGE
from ..firewall.radar import category_of, scan_result
from .corpus import Kind, Sample


@dataclass(frozen=True, slots=True)
class Detector:
    name: str
    kinds: frozenset[Kind]
    flags: Callable[[Sample], bool]


def _egress(sample: Sample) -> bool:
    assert sample.text is not None
    _, found = EgressTaintGuardrail.scan_and_redact(sample.text)
    return bool(found)


def _manifest_auditor(sample: Sample) -> bool:
    assert sample.manifest is not None
    return MCPServerAuditor.audit_manifest(sample.manifest).verdict != "PASS"


def _description_auditor(sample: Sample) -> bool:
    """The auditor has no description-only mode, so the text is wrapped in an otherwise clean manifest whose tool has a
    strict, bounded schema: anything it reports is about the description."""
    assert sample.text is not None
    manifest = {
        "name": "probe", "command": "node", "args": ["server.js"],
        "tools": [{
            "name": "probe_tool", "description": sample.text,
            "inputSchema": {"type": "object", "additionalProperties": False, "required": ["q"],
                            "properties": {"q": {"type": "string", "maxLength": 200}}},
        }],
    }
    return bool(MCPServerAuditor.audit_manifest(manifest).findings)


def _radar(sample: Sample) -> bool:
    """Actionable Radar findings (not low confidence) count only for the category they inform: an XSS rule does not get credit for an injection sample."""
    assert sample.text is not None
    return any(category_of(f) == sample.category for f in scan_result(sample.text).actionable)


def _radar_model(sample: Sample) -> bool:
    """The second-stage model (trained on the development samples: its dev numbers are NOT evidence; held-out and blind rounds are)."""
    assert sample.text is not None
    return any(category_of(f) == sample.category for f in scan_result(sample.text, detectors=SECOND_STAGE).actionable)


DETECTORS: tuple[Detector, ...] = (
    Detector("egress_guardrail", frozenset({"tool_result"}), _egress),
    Detector("radar", frozenset({"tool_result"}), _radar),
    Detector("radar_model", frozenset({"tool_result"}), _radar_model),
    Detector("manifest_auditor", frozenset({"manifest"}), _manifest_auditor),
    Detector("description_auditor", frozenset({"tool_description"}), _description_auditor),
)


def flagged_by(sample: Sample, detectors: tuple[Detector, ...] = DETECTORS) -> list[str]:
    """Names of the detectors that apply to this kind of sample and flag it."""
    return [d.name for d in detectors if sample.kind in d.kinds and d.flags(sample)]
