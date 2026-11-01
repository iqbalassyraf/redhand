"""
RedHand Core - Streaming DLP & Secret Redaction Scrubber
File: services/redhand-core/src/redhand_core/services/dlp_scrubber.py

Scans and redacts sensitive credentials, bearer tokens, private keys, and PII
from `observation_payload`, `thought_content`, and `tool_arguments` in <2ms
prior to database persistence and SIEM export.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


@dataclass(frozen=True, slots=True)
class DLPRule:
    rule_id: str
    label: str
    pattern: re.Pattern[str]
    replacement: str


@dataclass(frozen=True, slots=True)
class DLPDetection:
    rule_id: str
    label: str
    field_path: str
    redacted_preview: str


_DLP_RULES: tuple[DLPRule, ...] = (
    DLPRule(
        rule_id="RH-DLP-GCP-OAUTH",
        label="GCP OAuth2 Access Token",
        pattern=re.compile(r"ya29\.[0-9A-Za-z\-_]{24,}"),
        replacement="[REDACTED_GCP_OAUTH_TOKEN]",
    ),
    DLPRule(
        rule_id="RH-DLP-GCP-APIKEY",
        label="Google Cloud API Key",
        pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        replacement="[REDACTED_GCP_API_KEY]",
    ),
    DLPRule(
        rule_id="RH-DLP-AWS-KEY",
        label="AWS Access Key ID",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        replacement="[REDACTED_AWS_ACCESS_KEY]",
    ),
    DLPRule(
        rule_id="RH-DLP-PRIVATE-KEY",
        label="PEM Private Key",
        pattern=re.compile(
            r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"
            r"[\s\S]*?"
            r"-----END\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"
        ),
        replacement="[REDACTED_PEM_PRIVATE_KEY]",
    ),
    DLPRule(
        rule_id="RH-DLP-JWT",
        label="JSON Web Token (JWT)",
        pattern=re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        ),
        replacement="[REDACTED_JWT_TOKEN]",
    ),
    DLPRule(
        rule_id="RH-DLP-EMAIL",
        label="PII Email Address",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@(?!example\.com)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        replacement="[REDACTED_EMAIL]",
    ),
)


class DLPScrubber:
    """
    Recursively scrubs strings, dicts, and lists for secrets and PII before
    traces are written to Supabase or exported to external SIEMs.
    """

    def scrub_text(
        self,
        text: str | None,
        *,
        field_path: str = "root",
    ) -> tuple[str | None, list[DLPDetection]]:
        if not text:
            return text, []

        detections: list[DLPDetection] = []
        sanitized = text

        for rule in _DLP_RULES:
            if rule.pattern.search(sanitized):
                sanitized = rule.pattern.sub(rule.replacement, sanitized)
                detections.append(
                    DLPDetection(
                        rule_id=rule.rule_id,
                        label=rule.label,
                        field_path=field_path,
                        redacted_preview=sanitized[:180],
                    )
                )

        return sanitized, detections

    def scrub_value(
        self,
        value: Any,
        *,
        field_path: str = "root",
    ) -> tuple[Any, list[DLPDetection]]:
        if value is None:
            return None, []

        if isinstance(value, str):
            return self.scrub_text(value, field_path=field_path)

        if isinstance(value, dict):
            sanitized_dict: dict[str, Any] = {}
            all_detections: list[DLPDetection] = []
            for k, v in value.items():
                clean_v, child_detections = self.scrub_value(
                    v, field_path=f"{field_path}.{k}"
                )
                sanitized_dict[k] = clean_v
                all_detections.extend(child_detections)
            return sanitized_dict, all_detections

        if isinstance(value, list):
            sanitized_list: list[Any] = []
            all_detections = []
            for idx, item in enumerate(value):
                clean_item, child_detections = self.scrub_value(
                    item, field_path=f"{field_path}[{idx}]"
                )
                sanitized_list.append(clean_item)
                all_detections.extend(child_detections)
            return sanitized_list, all_detections

        return value, []


_default_scrubber: DLPScrubber | None = None


def get_dlp_scrubber() -> DLPScrubber:
    global _default_scrubber
    if _default_scrubber is None:
        _default_scrubber = DLPScrubber()
    return _default_scrubber

