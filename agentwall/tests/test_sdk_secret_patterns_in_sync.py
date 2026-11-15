"""
The SDK's secret patterns (`redhand scan`, docs/plans/phase4-m5b-secrets-in-files.md) are copied from the gateway's EgressTaintGuardrail
because the SDK must install on its own and cannot import `agentwall`. This test is the only place both are visible, so it keeps them
in step and measures the SDK matcher on the same corpus the gateway guardrail is measured on.
"""

from __future__ import annotations

import re

from agentwall.src.bench.corpus import load_corpus
from agentwall.src.firewall.ast_guardrails import EgressTaintGuardrail
from redhand_sdk.scanner.secrets import DOCUMENTED_EXAMPLES, SECRET_PATTERNS, scan_text

# Patterns that look for a place data is sent to, not for a secret. The SDK deliberately does not report them as secrets.
NOT_SECRETS = {"METADATA_SSRF", "EXFIL_WEBHOOK"}
# The deliberate differences (stated in the SDK module docstring). The gateway's patterns match anywhere, so "risk-assessment-and-mitigation"
# looks like an "sk-" key, which would flag ordinary Markdown and YAML. The SDK patterns add a word-boundary guard in front, and its AWS
# pattern needs a whole 20-character key id (the gateway's has an alternative that matches only four characters: A3T plus one). Reported as
# a follow-up for the gateway; not changed here (out of scope).
BOUNDARY = r"(?<![A-Za-z0-9_-])"
GUARDED = {"ANTHROPIC_KEY", "OPENAI_KEY", "GCP_BEARER"}  # the SDK pattern is BOUNDARY + the gateway pattern, exactly
OWN_PATTERN = {"AWS_KEY"}


def gateway_secret_patterns() -> dict[str, str]:
    return {name: pattern.pattern for name, pattern in EgressTaintGuardrail.PATTERNS if name not in NOT_SECRETS}


def test_every_gateway_secret_kind_is_in_the_sdk_table_and_nothing_extra() -> None:
    assert sorted(name for name, _ in SECRET_PATTERNS) == sorted(gateway_secret_patterns())


def test_the_patterns_are_the_gateways_with_only_the_documented_guard() -> None:
    sdk = {name: pattern.pattern for name, pattern in SECRET_PATTERNS}
    gateway = gateway_secret_patterns()
    for name, gateway_pattern in gateway.items():
        if name in GUARDED:
            assert sdk[name] == BOUNDARY + gateway_pattern, f"{name} drifted from the gateway guardrail"
        elif name in OWN_PATTERN:
            assert sdk[name] != gateway_pattern, f"{name} no longer differs: remove it from OWN_PATTERN"
        else:
            assert sdk[name] == gateway_pattern, f"{name} drifted from the gateway guardrail"


def test_the_sdk_aws_pattern_still_matches_every_full_key_the_gateway_matches() -> None:
    sdk = dict(SECRET_PATTERNS)["AWS_KEY"]
    for prefix in ("AKIA", "A3TA", "A3T0"):
        key = prefix + "QX7RTV3KLMNPWZ4B"
        assert sdk.search(key), key


def _gateway_found(text: str) -> set[str]:
    _, detections = EgressTaintGuardrail.scan_and_redact(text)
    return {m.group(1) for d in detections if (m := re.match(r"Detected secret '([A-Z_]+)'", d)) and m.group(1) not in NOT_SECRETS}


def _gateway_found_without_documented_examples(text: str) -> bool:
    """Whether the gateway finds a secret once the documentation example the SDK skips on purpose is taken out of the text."""
    for example in DOCUMENTED_EXAMPLES:
        text = text.replace(example, "")
    return bool(_gateway_found(text))


def _corpus_texts() -> list[tuple[str, str, str]]:
    return [(s.id, s.label, s.text) for s in load_corpus() if s.category == "secret_leak" and s.text is not None]


def test_the_sdk_matcher_agrees_with_the_gateway_guardrail_on_the_secret_leak_corpus() -> None:
    """Same verdict (found or not) on every sample. The kind label may differ: the SDK reports an Anthropic key as ANTHROPIC_KEY, the gateway,
    whose OpenAI pattern runs first, as OPENAI_KEY. The documented AWS example is skipped by the SDK on purpose and is taken out for the comparison."""
    samples = _corpus_texts()
    assert len(samples) >= 30
    disagreements = [
        sample_id for sample_id, _, text in samples
        if bool(scan_text(text, "sample.txt")) != _gateway_found_without_documented_examples(text)
    ]
    assert disagreements == [], f"the SDK and the gateway disagree on: {disagreements}"


def test_the_counts_on_the_corpus_are_reported() -> None:
    """Not a claim about real prompt files: only what the matcher does on our own labelled samples."""
    samples = _corpus_texts()
    malicious = [text for _, label, text in samples if label == "malicious"]
    benign = [text for _, label, text in samples if label == "benign"]
    sdk_found = sum(1 for t in malicious if scan_text(t, "s.txt"))
    sdk_false = sum(1 for t in benign if scan_text(t, "s.txt"))
    gateway_found = sum(1 for t in malicious if _gateway_found(t))
    print(f"secret_leak corpus: SDK found {sdk_found} of {len(malicious)} malicious, flagged {sdk_false} of {len(benign)} benign; "
          f"the gateway guardrail found {gateway_found} (the one extra is the AWS documentation example the SDK skips on purpose)")
    assert sdk_found == gateway_found - 1
    assert sdk_false == 0
