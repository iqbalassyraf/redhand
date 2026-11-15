"""
Immutable, tamper-evident audit logger compliant with ISO/IEC 42001 and NIST AI 600-1.
"""

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import queue
import threading
from typing import Any, Literal
from pydantic import BaseModel, Field
import structlog

logger = structlog.get_logger(__name__)

GENESIS_HASH = "GENESIS_BLOCK_00000000000000000000000000000000"
# Records kept in memory. A process that serves calls for weeks must not grow without limit (CLAUDE.md section 9); the complete, durable
# record of every decision is the Black Box in redhand-core, and the optional audit file keeps everything this process wrote.
MAX_RECORDS_DEFAULT = 10_000


@dataclass(frozen=True, slots=True)
class AuditStats:
    retained: int  # records held in memory now
    dropped: int  # older records removed from memory (their hash anchors the retained window)
    total: int  # every record this process has made
    file_errors: int  # appends to the audit file that failed


def digest_arguments(arguments: dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON form of the arguments (non-JSON values via str())."""
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditRecord(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trace_id: str
    span_id: str
    agent_id: str
    caller_identity: str
    organization_id: str | None = None
    server: str | None = None
    tool_name: str
    # Raw tool arguments are never stored: they can contain customer data or secrets
    # (CLAUDE.md §10). We keep only the argument names and a digest, which is enough
    # to correlate a record with a payload the customer holds, without retaining it.
    argument_keys: list[str] = Field(default_factory=list)
    arguments_sha256: str = ""
    firewall_decision: Literal["ALLOW", "BLOCK", "REDACT", "ERROR"]
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
            "organization_id": self.organization_id,
            "server": self.server,
            "tool_name": self.tool_name,
            "argument_keys": self.argument_keys,
            "arguments_sha256": self.arguments_sha256,
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
    """
    Thread-safe, append-only cryptographic audit logger. Memory is bounded: when the window is full the oldest record is dropped and its
    hash becomes the anchor the retained window verifies from, so tampering inside the window is still detected. The optional file append
    runs on a writer thread, never on the caller's (the request's) thread.
    """

    def __init__(self, log_file_path: str | None = None, max_records: int = MAX_RECORDS_DEFAULT) -> None:
        if max_records < 1:
            raise ValueError("max_records must be at least 1")
        self._lock = threading.Lock()
        self._records: deque[AuditRecord] = deque(maxlen=max_records)
        self._last_hash = GENESIS_HASH
        self._anchor_hash = GENESIS_HASH  # the hash the oldest retained record must point back to
        self._dropped = 0
        self._total = 0
        self._log_file_path = log_file_path
        self._file_errors = 0
        self._lines: queue.SimpleQueue[str | _Marker | None] = queue.SimpleQueue()
        self._writer: threading.Thread | None = None

    def record(
        self,
        *,
        trace_id: str,
        span_id: str,
        agent_id: str,
        caller_identity: str,
        tool_name: str,
        arguments: dict[str, Any],
        organization_id: str | None = None,
        server: str | None = None,
        firewall_decision: Literal["ALLOW", "BLOCK", "REDACT", "ERROR"],
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
                organization_id=organization_id,
                server=server,
                tool_name=tool_name,
                argument_keys=sorted(str(k) for k in arguments),
                arguments_sha256=digest_arguments(arguments),
                firewall_decision=firewall_decision,
                policy_violation_reasons=policy_violation_reasons or [],
                downstream_status=downstream_status,
                execution_latency_ms=execution_latency_ms,
                credential_jti=credential_jti,
                prev_record_hash=self._last_hash,
            )
            record_obj.record_hash = record_obj.calculate_hash()
            self._last_hash = record_obj.record_hash
            if len(self._records) == self._records.maxlen:
                self._anchor_hash = self._records[0].record_hash  # the record about to fall out anchors the new window
                self._dropped += 1
            self._records.append(record_obj)
            self._total += 1

            if self._log_file_path:
                self._ensure_writer()
                self._lines.put(record_obj.model_dump_json() + "\n")  # a queue put never waits for the disk

            logger.info(
                "Audit record logged",
                trace_id=trace_id,
                agent_id=agent_id,
                tool_name=tool_name,
                decision=firewall_decision,
                hash=record_obj.record_hash[:12],
            )
            return record_obj

    def _ensure_writer(self) -> None:
        if self._writer is None or not self._writer.is_alive():
            self._writer = threading.Thread(target=self._write_loop, name="audit-file-writer", daemon=True)
            self._writer.start()

    def _write_loop(self) -> None:
        while True:
            line = self._lines.get()
            if line is None:
                return
            if isinstance(line, _Marker):
                line.done.set()
                continue
            try:
                self._append_line(line)
            except Exception as exc:  # noqa: BLE001  a full or missing disk must never break recording
                self._file_errors += 1
                logger.error("Failed to append audit record to file", error_type=type(exc).__name__)

    def _append_line(self, line: str) -> None:
        assert self._log_file_path is not None
        with open(self._log_file_path, "a", encoding="utf-8") as f:
            f.write(line)

    def flush(self, timeout: float = 5.0) -> None:
        """Waits until every line queued so far has been written (tests and shutdown)."""
        if self._writer is None:
            return
        done = threading.Event()
        marker = _Marker(done)
        self._lines.put(marker)
        done.wait(timeout)

    def close(self) -> None:
        if self._writer is not None and self._writer.is_alive():
            self._lines.put(None)
            self._writer.join(timeout=5.0)

    def stats(self) -> AuditStats:
        with self._lock:
            return AuditStats(retained=len(self._records), dropped=self._dropped, total=self._total, file_errors=self._file_errors)

    def get_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return [r.model_dump() for r in list(self._records)[-limit:]]

    def verify_chain_integrity(self) -> tuple[bool, str | None]:
        with self._lock:
            expected_prev = self._anchor_hash
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


class _Marker:
    """A queue item that is not a line: when the writer reaches it, everything before it has been written."""

    def __init__(self, done: threading.Event) -> None:
        self.done = done
