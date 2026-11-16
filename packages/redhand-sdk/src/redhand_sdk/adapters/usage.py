"""
RedHand SDK - reading model usage out of an LLM result.

The control plane estimates cost from the token counts reported here, so every function returns what the provider said or "not reported"
(zero tokens, empty model); nothing is guessed, and nothing here ever raises into the caller's agent. Results are duck-typed (LangChain's
`LLMResult` shape) so the SDK does not depend on langchain.

No prompt or completion text is read.
"""

from __future__ import annotations

from typing import Any

MAX_REPORTED_TOKENS = 1_000_000_000  # one call cannot have used more; a larger number is a bad value, not usage
MAX_MODEL_NAME = 128  # the span field's own limit

# Integration package named in the serialized LLM -> provider name the control plane's price table uses. Anything else is left unnamed
# (the price is then "unknown"): a wrong provider would price a model against the wrong cloud's rates.
_PROVIDER_BY_PACKAGE = {
    "langchain_anthropic": "anthropic",
    "langchain_openai": "openai",
}


def _count(value: Any) -> int:
    """A token count, or 0 when the value is not a plain non-negative whole number in a believable range."""
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value if 0 <= value <= MAX_REPORTED_TOKENS else 0


def _pair(source: Any, prompt_key: str, completion_key: str) -> tuple[int, int] | None:
    if not isinstance(source, dict):
        return None
    prompt, completion = _count(source.get(prompt_key)), _count(source.get(completion_key))
    return (prompt, completion) if prompt or completion else None


def extract_usage(response: Any) -> tuple[int, int]:
    """(prompt tokens, completion tokens) the provider reported for one call; (0, 0) when it reported none.

    The result-level numbers win over per-message ones, because providers that give both describe the same call and adding them would
    count it twice."""
    llm_output = getattr(response, "llm_output", None)
    if isinstance(llm_output, dict):
        for key, names in (("token_usage", ("prompt_tokens", "completion_tokens")), ("usage", ("input_tokens", "output_tokens"))):
            found = _pair(llm_output.get(key), *names)
            if found is not None:
                return found
    prompt_total = completion_total = 0
    for generation in _generations(response):
        found = _pair(getattr(getattr(generation, "message", None), "usage_metadata", None), "input_tokens", "output_tokens")
        if found is not None:
            prompt_total += found[0]
            completion_total += found[1]
    return min(prompt_total, MAX_REPORTED_TOKENS), min(completion_total, MAX_REPORTED_TOKENS)


def _generations(response: Any) -> list[Any]:
    rows = getattr(response, "generations", None)
    if not isinstance(rows, list):
        return []
    flat: list[Any] = []
    for row in rows:
        if isinstance(row, list):
            flat.extend(row)
    return flat


def clean_model_name(value: Any) -> str:
    return value if isinstance(value, str) and 0 < len(value) <= MAX_MODEL_NAME else ""


def extract_model(response: Any) -> str:
    """The model name the provider reported for the call, or "" when it named none."""
    llm_output = getattr(response, "llm_output", None)
    if isinstance(llm_output, dict):
        for key in ("model_name", "model"):
            name = clean_model_name(llm_output.get(key))
            if name:
                return name
    for generation in _generations(response):
        meta = getattr(getattr(generation, "message", None), "response_metadata", None)
        if isinstance(meta, dict):
            for key in ("model_name", "model"):
                name = clean_model_name(meta.get(key))
                if name:
                    return name
    return ""


def model_from_invocation(kwargs: dict[str, Any]) -> str:
    """The model named in the parameters a LangChain callback passes when a call starts, or ""."""
    params = kwargs.get("invocation_params")
    if isinstance(params, dict):
        for key in ("model", "model_name"):
            name = clean_model_name(params.get(key))
            if name:
                return name
    return ""


def provider_from_serialized(serialized: Any) -> str:
    """The provider implied by the integration package that built the LLM ("anthropic" for langchain_anthropic), or "" if not known."""
    path = serialized.get("id") if isinstance(serialized, dict) else None
    if isinstance(path, list) and path and isinstance(path[0], str):
        return _PROVIDER_BY_PACKAGE.get(path[0], "")
    return ""
