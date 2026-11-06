"""
RedHand SDK - <50ms In-Memory Tiered Semantic Firewall
File: packages/redhand-sdk/src/redhand_sdk/firewall/engine.py

Architecture:
- Tier 0 (<1.5ms): Deterministic AST inspection, SSRF/Metadata guards, and
                   compiled regex signatures for Indirect Prompt Injection.
- Tier 1 (<25ms):  In-memory INT8 quantized ONNX DeBERTa-v3 / Prompt-Guard
                   sequence classification with zero network I/O.
"""

from __future__ import annotations

import ast
import json
import logging
import math
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from redhand_sdk.models import (
    FirewallVerdict,
    SecurityEventType,
    SecurityFindingPayload,
    SeverityLevel,
)

logger = logging.getLogger("redhand.sdk.firewall")


# =============================================================================
# 1. RESULT CONTAINER & CONFIGURATION
# =============================================================================


@dataclass(frozen=True, slots=True)
class FirewallEvaluationResult:
    verdict: FirewallVerdict
    latency_ms: float
    finding: SecurityFindingPayload | None = None


@dataclass(frozen=True, slots=True)
class Tier0Rule:
    rule_id: str
    event_type: SecurityEventType
    severity: SeverityLevel
    pattern: re.Pattern[str]
    description: str


# =============================================================================
# 2. TIER 0: DETERMINISTIC SIGNATURES & AST SANDBOX RULES (<1.5ms)
# =============================================================================

_TIER0_RULES: tuple[Tier0Rule, ...] = (
    Tier0Rule(
        rule_id="RH-T0-001",
        event_type=SecurityEventType.PROMPT_INJECTION_INDIRECT,
        severity=SeverityLevel.CRITICAL,
        pattern=re.compile(
            r"(?i)(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|system)\s+"
            r"(?:instructions|prompts|directives|guardrails|constraints|rules|safety)"
        ),
        description="Indirect prompt injection attempting system instruction override.",
    ),
    Tier0Rule(
        rule_id="RH-T0-002",
        event_type=SecurityEventType.PROMPT_INJECTION_INDIRECT,
        severity=SeverityLevel.CRITICAL,
        pattern=re.compile(
            r"(?i)(?:<\s*/?\s*(?:system|instruction|developer|admin_override)\s*>|"
            r"\[?SYSTEM\s*OVERRIDE\]?|###\s*NEW\s+SYSTEM\s+PROMPT)"
        ),
        description="Structural delimiter spoofing / XML tag injection detected in tool payload.",
    ),
    Tier0Rule(
        rule_id="RH-T0-003",
        event_type=SecurityEventType.IAM_SCOPE_VIOLATION,
        severity=SeverityLevel.CRITICAL,
        pattern=re.compile(
            r"(?i)(?:169\.254\.169\.254|metadata\.google\.internal|"
            r"computeMetadata/v1/instance/service-accounts)"
        ),
        description="Cloud instance metadata SSRF / credential harvesting attempt blocked.",
    ),
    Tier0Rule(
        rule_id="RH-T0-004",
        event_type=SecurityEventType.DLP_SECRET_LEAK_PREVENTED,
        severity=SeverityLevel.HIGH,
        pattern=re.compile(
            r"(?:ya29\.[0-9A-Za-z\-_]{30,}|AIza[0-9A-Za-z\-_]{35}|"
            r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----|AKIA[0-9A-Z]{16})"
        ),
        description="Raw cloud credential or private key detected in outbound tool arguments.",
    ),
    Tier0Rule(
        rule_id="RH-T0-005",
        event_type=SecurityEventType.PROMPT_INJECTION_DIRECT,
        severity=SeverityLevel.HIGH,
        pattern=re.compile(
            r"(?i)(?:(?:curl|wget|nc|netcat|bash\s+-i|/dev/tcp/)\s+[^\s]*(?:webhook\.site|"
            r"ngrok\.io|oastify\.com|burpcollaborator\.net|interact\.sh)|"
            r"(?:pastebin\.com|hastebin\.com|webhook\.site)[^\s]*)"
        ),
        description="Command exfiltration tunnel / pastebin exfil payload detected.",
    ),
    Tier0Rule(
        rule_id="RH-T0-006",
        event_type=SecurityEventType.UNREGISTERED_TOOL_INVOCATION,
        severity=SeverityLevel.CRITICAL,
        pattern=re.compile(
            r"(?i)(?:drop\s+table|drop\s+database|truncate\s+table|delete\s+from\s+[a-z0-9_]+\s*;)"
        ),
        description="Destructive raw SQL drop table/database execution attempt blocked.",
    ),
)

_FORBIDDEN_AST_CALLS: frozenset[str] = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "os.system",
        "os.popen",
        "subprocess.Popen",
        "subprocess.run",
        "subprocess.call",
        "pty.spawn",
    }
)

_FORBIDDEN_AST_ATTRS: frozenset[str] = frozenset(
    {
        "__subclasses__",
        "__globals__",
        "__builtins__",
        "__code__",
        "__closure__",
        "__mro__",
    }
)


# =============================================================================
# 3. TIER 1: IN-MEMORY ONNX RUNTIME CLASSIFIER ADAPTER (<25ms)
# =============================================================================


class InMemoryONNXDebertaClassifier:
    """
    Loads an INT8-quantized DeBERTa-v3 Prompt Injection model into local process
    memory via `onnxruntime`.
    """

    def __init__(
        self,
        model_path: str | Path | None = None,
        max_seq_length: int = 256,
        intra_op_threads: int = 4,
    ) -> None:
        self.max_seq_length = max_seq_length
        self._ort_session: Any = None
        self._tokenizer: Any = None

        resolved_path = Path(
            model_path
            or os.environ.get(
                "REDHAND_ONNX_MODEL_PATH",
                Path.home() / ".cache" / "redhand" / "deberta-v3-prompt-injection-int8.onnx",
            )
        )

        if resolved_path.is_file():
            self._load_onnx_session(resolved_path, intra_op_threads)
        else:
            logger.debug(
                "ONNX weights not found at %s; using fast in-memory lexical-logit stub.",
                resolved_path,
            )

    def _load_onnx_session(self, model_path: Path, intra_op_threads: int) -> None:
        """Initializes the local ONNX Runtime InferenceSession with graph optimizations."""
        try:
            import onnxruntime as ort  # type: ignore[import-not-found]
            from tokenizers import Tokenizer  # type: ignore[import-not-found]

            sess_options = ort.SessionOptions()
            sess_options.intra_op_num_threads = intra_op_threads
            sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            sess_options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL

            self._ort_session = ort.InferenceSession(
                str(model_path),
                sess_options=sess_options,
                providers=["CPUExecutionProvider"],
            )

            tokenizer_path = model_path.with_name("tokenizer.json")
            if tokenizer_path.is_file():
                self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
                self._tokenizer.enable_truncation(max_length=self.max_seq_length)
                self._tokenizer.enable_padding(length=self.max_seq_length)
        except Exception as exc:
            logger.warning("Failed to initialize ONNX Runtime session (%s); falling back.", exc)
            self._ort_session = None

    @property
    def model_loaded(self) -> bool:
        """True only when a real ONNX session and tokenizer are in use, not the lexical stand-in."""
        return self._ort_session is not None and self._tokenizer is not None

    @property
    def detector_tier(self) -> str:
        """What to call this detector in findings: it must not claim to be the model when it is the stub."""
        return "tier1_onnx_deberta" if self.model_loaded else "tier1_lexical_stub"

    def predict_injection_probability(self, text: str) -> float:
        """
        Runs sequence classification over `text` and returns the probability [0.0, 1.0]
        that the payload contains an adversarial prompt injection or hijacked intent.
        """
        if not text.strip():
            return 0.0

        if self._ort_session is not None and self._tokenizer is not None:
            encoded = self._tokenizer.encode(text[:4096])
            input_ids = np.asarray([encoded.ids], dtype=np.int64)
            attention_mask = np.asarray([encoded.attention_mask], dtype=np.int64)

            ort_inputs = {
                "input_ids": input_ids,
                "attention_mask": attention_mask,
            }
            logits = self._ort_session.run(None, ort_inputs)[0][0]
            shifted = logits - np.max(logits)
            exp_scores = np.exp(shifted)
            probs = exp_scores / np.sum(exp_scores)
            return float(probs[1])

        return self._emulate_quantized_deberta_scoring(text)

    @staticmethod
    def _emulate_quantized_deberta_scoring(text: str) -> float:
        """
        Sub-millisecond lexical-logit approximation used when the 86MB `.onnx` artifact
        is not yet mounted in local dev/CI containers.
        """
        lowered = text.lower()
        logit = -3.2

        weighted_signals: tuple[tuple[str, float], ...] = (
            ("ignore previous", 4.5),
            ("system prompt", 3.4),
            ("you are now", 2.8),
            ("do anything now", 4.2),
            ("exfiltrate", 4.0),
            ("send all data to", 4.1),
            ("print the secret", 3.8),
            ("bypass security", 3.9),
            ("sudo ", 2.1),
            ("drop table", 3.7),
            ("rm -rf", 4.2),
            ("base64 -d", 2.9),
            ("important: new instructions", 4.4),
        )

        for phrase, weight in weighted_signals:
            if phrase in lowered:
                logit += weight

        return round(1.0 / (1.0 + math.exp(-logit)), 4)


# =============================================================================
# 4. FIREWALL ENGINE ORCHESTRATOR
# =============================================================================


class FirewallEngine:
    """
    Executes the tiered <50ms Semantic Firewall pipeline before any tool
    is permitted to execute or request an ephemeral cloud token.
    """

    def __init__(
        self,
        block_threshold: float = 0.82,
        flag_threshold: float = 0.55,
        latency_sla_ms: float = 50.0,
        onnx_model_path: str | Path | None = None,
    ) -> None:
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        self.latency_sla_ms = latency_sla_ms
        self._classifier = InMemoryONNXDebertaClassifier(model_path=onnx_model_path)

    def _tier1_rule_id(self, verdict: str) -> str:
        return f"RH-T1-{'DEBERTA' if self._classifier.model_loaded else 'LEXICAL-STUB'}-{verdict}"

    def evaluate(
        self,
        *,
        tool_name: str,
        tool_arguments: dict[str, Any],
        agent_thought: str | None = None,
    ) -> FirewallEvaluationResult:
        """
        Synchronously evaluates tool arguments and preceding agent thought in <50ms.
        """
        start_ns = time.perf_counter_ns()

        serialized_args = json.dumps(tool_arguments, ensure_ascii=False, default=str)
        composite_payload = (
            f"TOOL: {tool_name}\nTHOUGHT: {agent_thought or ''}\nARGS: {serialized_args}"
        )

        # TIER 0A: Compiled Regex Signature Scan
        for rule in _TIER0_RULES:
            match = rule.pattern.search(composite_payload)
            if match:
                latency_ms = self._elapsed_ms(start_ns)
                snippet = self._sanitize_snippet(match.group(0))
                return FirewallEvaluationResult(
                    verdict=FirewallVerdict.BLOCKED,
                    latency_ms=latency_ms,
                    finding=SecurityFindingPayload(
                        event_type=rule.event_type,
                        severity=rule.severity,
                        verdict=FirewallVerdict.BLOCKED,
                        detector_tier="tier0_regex_signature",
                        confidence_score=1.0,
                        firewall_latency_ms=latency_ms,
                        trigger_snippet=snippet,
                        matched_rule_id=rule.rule_id,
                        mitigation_action=(
                            f"Blocked '{tool_name}' execution: {rule.description}"
                        ),
                    ),
                )

        # TIER 0B: Deterministic AST Inspection
        ast_violation = self._inspect_ast_arguments(tool_arguments)
        if ast_violation is not None:
            rule_id, snippet, reason = ast_violation
            latency_ms = self._elapsed_ms(start_ns)
            return FirewallEvaluationResult(
                verdict=FirewallVerdict.BLOCKED,
                latency_ms=latency_ms,
                finding=SecurityFindingPayload(
                    event_type=SecurityEventType.PROMPT_INJECTION_INDIRECT,
                    severity=SeverityLevel.CRITICAL,
                    verdict=FirewallVerdict.BLOCKED,
                    detector_tier="tier0_ast_validator",
                    confidence_score=1.0,
                    firewall_latency_ms=latency_ms,
                    trigger_snippet=self._sanitize_snippet(snippet),
                    matched_rule_id=rule_id,
                    mitigation_action=f"Blocked '{tool_name}' via AST analysis: {reason}",
                ),
            )

        # TIER 1: In-Memory ONNX DeBERTa-v3 Classifier Inference
        score = self._classifier.predict_injection_probability(composite_payload)
        latency_ms = self._elapsed_ms(start_ns)

        if latency_ms > self.latency_sla_ms:
            logger.warning(
                "Semantic Firewall exceeded %.1fms SLA (took %.2fms on tool '%s')",
                self.latency_sla_ms,
                latency_ms,
                tool_name,
            )

        if score >= self.block_threshold:
            return FirewallEvaluationResult(
                verdict=FirewallVerdict.BLOCKED,
                latency_ms=latency_ms,
                finding=SecurityFindingPayload(
                    event_type=SecurityEventType.PROMPT_INJECTION_INDIRECT,
                    severity=SeverityLevel.CRITICAL if score >= 0.92 else SeverityLevel.HIGH,
                    verdict=FirewallVerdict.BLOCKED,
                    detector_tier=self._classifier.detector_tier,
                    confidence_score=round(score, 4),
                    firewall_latency_ms=latency_ms,
                    trigger_snippet=self._sanitize_snippet(serialized_args[:256]),
                    matched_rule_id=self._tier1_rule_id("INJECTION"),
                    mitigation_action=(
                        f"Semantic classifier blocked '{tool_name}' due to high probability "
                        f"({score:.1%}) of indirect prompt injection or intent hijacking."
                    ),
                ),
            )

        if score >= self.flag_threshold:
            return FirewallEvaluationResult(
                verdict=FirewallVerdict.FLAGGED,
                latency_ms=latency_ms,
                finding=SecurityFindingPayload(
                    event_type=SecurityEventType.PROMPT_INJECTION_INDIRECT,
                    severity=SeverityLevel.MEDIUM,
                    verdict=FirewallVerdict.FLAGGED,
                    detector_tier=self._classifier.detector_tier,
                    confidence_score=round(score, 4),
                    firewall_latency_ms=latency_ms,
                    trigger_snippet=self._sanitize_snippet(serialized_args[:256]),
                    matched_rule_id=self._tier1_rule_id("SUSPICIOUS"),
                    mitigation_action=(
                        f"Tool '{tool_name}' permitted with elevated telemetry flag "
                        f"(classifier score={score:.1%})."
                    ),
                ),
            )

        return FirewallEvaluationResult(
            verdict=FirewallVerdict.ALLOW,
            latency_ms=latency_ms,
            finding=None,
        )

    def _inspect_ast_arguments(
        self,
        tool_arguments: dict[str, Any],
    ) -> tuple[str, str, str] | None:
        for arg_name, arg_val in tool_arguments.items():
            if not isinstance(arg_val, str) or len(arg_val) < 4:
                continue

            if not any(
                tok in arg_val
                for tok in ("__", "import", "eval(", "exec(", "os.", "subprocess")
            ):
                continue

            try:
                tree = ast.parse(arg_val.strip())
            except SyntaxError:
                for dunder in _FORBIDDEN_AST_ATTRS:
                    if dunder in arg_val:
                        return (
                            "RH-T0-AST-DUNDER",
                            f"{arg_name}={arg_val[:120]}",
                            f"Forbidden Python dunder attribute '{dunder}' in argument '{arg_name}'.",
                        )
                continue

            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    return (
                        "RH-T0-AST-IMPORT",
                        ast.unparse(node),
                        f"Dynamic module import inside tool argument '{arg_name}' is prohibited.",
                    )
                if isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_AST_ATTRS:
                    return (
                        "RH-T0-AST-ATTR",
                        ast.unparse(node),
                        f"Sandbox escape attribute '{node.attr}' detected in '{arg_name}'.",
                    )
                if isinstance(node, ast.Call):
                    call_name = self._resolve_ast_call_name(node.func)
                    if call_name in _FORBIDDEN_AST_CALLS:
                        return (
                            "RH-T0-AST-CALL",
                            ast.unparse(node),
                            f"Forbidden system call '{call_name}' detected in '{arg_name}'.",
                        )
        return None

    @staticmethod
    def _resolve_ast_call_name(func_node: ast.expr) -> str:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            if isinstance(func_node.value, ast.Name):
                return f"{func_node.value.id}.{func_node.attr}"
            return func_node.attr
        return ""

    @staticmethod
    def _elapsed_ms(start_ns: int) -> float:
        return round((time.perf_counter_ns() - start_ns) / 1_000_000.0, 2)

    @staticmethod
    def _sanitize_snippet(raw: str, max_len: int = 256) -> str:
        redacted = re.sub(
            r"(ya29\.[0-9A-Za-z\-_]+|AIza[0-9A-Za-z\-_]+|AKIA[0-9A-Z]{16})",
            "[REDACTED_CREDENTIAL]",
            raw,
        )
        return redacted[:max_len]


_default_firewall_instance: FirewallEngine | None = None


def get_default_firewall() -> FirewallEngine:
    global _default_firewall_instance
    if _default_firewall_instance is None:
        _default_firewall_instance = FirewallEngine()
    return _default_firewall_instance

