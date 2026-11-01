"""
Immutable, tamper-evident audit logger compliant with ISO/IEC 42001 and NIST AI 600-1.
"""

from datetime import datetime, timezone
import hashlib
import json
import threading
from typing import Any, Literal
from pydantic import BaseModel, Field
import structlog

logger = structlog.get_logger(__name__)


class AuditRecord(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trace_id: str
    span_id: str
    agent_id: str
    caller_identity: str
    tool_name: str
    sanitized_arguments: dict[str, Any]
    firewall_decision: Literal["ALLOW", "BLOCK", "REDACT"]
    policy_violation_reasons: list[str] = Field(default_factory=list)
    downstream_status: int | None = None
    execution_latency_ms: float = 0.0
    credential_jti: str | None = None
    prev_record_hash: str = "GENESIS_BLOCK_00000000000000000000000000000000"
    record_hash: str = ""

    def calculate_hash(self) -> str:
        payload = {
            "timestamp": self.timestamp,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "agent_id": self.agent_id,
            "caller_identity": self.caller_identity,
            "tool_name": self.tool_name,
            "sanitized_arguments": self.sanitized_arguments,
            "firewall_decision": self.firewall_decision,
            "policy_violation_reasons": self.policy_violation_reasons,
            "downstream_status": self.downstream_status,
            "execution_latency_ms": self.execution_latency_ms,
            "credential_jti": self.credential_jti,
            "prev_record_hash": self.prev_record_hash,
        }
        canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()


class TamperEvidentAuditLogger:
    """Thread-safe, append-only cryptographic audit logger."""

    def __init__(self, log_file_path: str | None = None) -> None:
        self._lock = threading.Lock()
        self._records: list[AuditRecord] = []
        self._last_hash = "GENESIS_BLOCK_00000000000000000000000000000000"
        self._log_file_path = log_file_path

    def record(
        self,
        *,
        trace_id: str,
        span_id: str,
        agent_id: str,
        caller_identity: str,
        tool_name: str,
        sanitized_arguments: dict[str, Any],
        firewall_decision: Literal["ALLOW", "BLOCK", "REDACT"],
        policy_violation_reasons: list[str] | None = None,
        downstream_status: int | None = None,
        execution_latency_ms: float = 0.0,
        credential_jti: str | None = None,
    ) -> AuditRecord:
        with self._lock:
            record_obj = AuditRecord(
                trace_id=trace_id,
                span_id=span_id,
                agent_id=agent_id,
                caller_identity=caller_identity,
                tool_name=tool_name,
                sanitized_arguments=sanitized_arguments,
                firewall_decision=firewall_decision,
                policy_violation_reasons=policy_violation_reasons or [],
                downstream_status=downstream_status,
                execution_latency_ms=execution_latency_ms,
                credential_jti=credential_jti,
                prev_record_hash=self._last_hash,
            )
            record_obj.record_hash = record_obj.calculate_hash()
            self._last_hash = record_obj.record_hash
            self._records.append(record_obj)

            # Persist to disk if configured
            if self._log_file_path:
                try:
                    with open(self._log_file_path, "a", encoding="utf-8") as f:
                        f.write(record_obj.model_dump_json() + "\n")
                except Exception as exc:
                    logger.error("Failed to append audit record to file", error=str(exc))

            logger.info(
                "Audit record logged",
                trace_id=trace_id,
                agent_id=agent_id,
                tool_name=tool_name,
                decision=firewall_decision,
                hash=record_obj.record_hash[:12],
            )
            return record_obj

    def get_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return [r.model_dump() for r in self._records[-limit:]]

    def verify_chain_integrity(self) -> tuple[bool, str | None]:
        with self._lock:
            expected_prev = "GENESIS_BLOCK_00000000000000000000000000000000"
            for idx, r in enumerate(self._records):
                if r.prev_record_hash != expected_prev:
                    return False, f"Broken link at index {idx}: expected prev {expected_prev}, got {r.prev_record_hash}"
                computed = r.calculate_hash()
                if computed != r.record_hash:
                    return False, f"Tampered hash at index {idx}: expected {computed}, got {r.record_hash}"
                expected_prev = r.record_hash
            return True, None


_audit_logger_instance: TamperEvidentAuditLogger | None = None


def get_audit_logger() -> TamperEvidentAuditLogger:
    global _audit_logger_instance
    if _audit_logger_instance is None:
        _audit_logger_instance = TamperEvidentAuditLogger()
    return _audit_logger_instance

