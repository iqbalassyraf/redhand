"""
RedHand SDK - model usage reporting from the LangChain adapter (Phase 4.5 B4).

The control plane turns reported tokens into an estimated cost, so the adapter must report what the model call said and nothing else:
real token counts when the provider gave them, zero ("not reported") when it did not, and never a model name that nobody supplied.
Fakes are plain objects shaped like LangChain's `LLMResult`; langchain itself is not installed in the test environment.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from redhand_sdk.adapters.langchain import RedHandLangChainHandler
from redhand_sdk.adapters.usage import extract_model, extract_usage
from redhand_sdk.client import RedHandClient
from redhand_sdk.models import StepType, TraceSpanItem


class RecordingClient(RedHandClient):
    """An offline client that keeps the spans it was given instead of sending them."""

    def __init__(self) -> None:
        super().__init__(external_agent_id="usage-test-agent", agent_name="Usage test", framework="pytest", offline_mode=True)
        self.spans: list[TraceSpanItem] = []

    def enqueue_span(self, span: TraceSpanItem) -> None:
        self.spans.append(span)


def result(llm_output: dict[str, Any] | None = None, messages: list[Any] | None = None) -> SimpleNamespace:
    generations = [[SimpleNamespace(message=message)] for message in (messages or [])]
    return SimpleNamespace(llm_output=llm_output, generations=generations)


def message(usage: dict[str, Any] | None = None, meta: dict[str, Any] | None = None) -> SimpleNamespace:
    return SimpleNamespace(usage_metadata=usage, response_metadata=meta or {})


def handler(client: RecordingClient, **kwargs: Any) -> RedHandLangChainHandler:
    return RedHandLangChainHandler(client=client, session_id=uuid4(), **kwargs)


# --- reading usage -----------------------------------------------------------------------------------------------------------------------

def test_openai_style_token_usage_is_read() -> None:
    assert extract_usage(result({"token_usage": {"prompt_tokens": 120, "completion_tokens": 30}})) == (120, 30)


def test_anthropic_style_usage_is_read() -> None:
    assert extract_usage(result({"usage": {"input_tokens": 90, "output_tokens": 15}})) == (90, 15)


def test_message_usage_metadata_is_read_and_summed_across_generations() -> None:
    two = result(messages=[message({"input_tokens": 10, "output_tokens": 4}), message({"input_tokens": 5, "output_tokens": 1})])
    assert extract_usage(two) == (15, 5)


def test_llm_output_wins_over_message_metadata_so_one_call_is_never_counted_twice() -> None:
    both = result({"token_usage": {"prompt_tokens": 100, "completion_tokens": 20}}, [message({"input_tokens": 100, "output_tokens": 20})])
    assert extract_usage(both) == (100, 20)


@pytest.mark.parametrize(
    "response",
    [
        result(None),
        result({}),
        result({"token_usage": None}),
        result({"token_usage": {}}),
        result({"token_usage": "lots"}),
        result({"token_usage": {"prompt_tokens": "12", "completion_tokens": 3.5}}),
        result({"token_usage": {"prompt_tokens": True, "completion_tokens": True}}),
        result({"token_usage": {"prompt_tokens": -5, "completion_tokens": -1}}),
        result({"token_usage": {"prompt_tokens": 10**12, "completion_tokens": 10**12}}),
        result(messages=[message(None), message("nope")]),
        SimpleNamespace(),
        None,
    ],
)
def test_missing_or_unusable_usage_is_not_reported_never_guessed(response: Any) -> None:
    assert extract_usage(response) == (0, 0)


def test_one_bad_number_does_not_throw_away_the_good_one() -> None:
    assert extract_usage(result({"token_usage": {"prompt_tokens": 40, "completion_tokens": -2}})) == (40, 0)


# --- reading the model -------------------------------------------------------------------------------------------------------------------

def test_the_model_is_what_the_provider_reported() -> None:
    assert extract_model(result({"model_name": "claude-sonnet-5-5"})) == "claude-sonnet-5-5"
    assert extract_model(result({"model": "claude-haiku-5-5"})) == "claude-haiku-5-5"
    assert extract_model(result(messages=[message(meta={"model_name": "claude-opus-5-5"})])) == "claude-opus-5-5"


@pytest.mark.parametrize("response", [result(None), result({"model_name": ""}), result({"model_name": 7}), result({"model_name": "x" * 500}), None])
def test_no_model_is_reported_as_no_model(response: Any) -> None:
    assert extract_model(response) == ""


# --- the handler -------------------------------------------------------------------------------------------------------------------------

def test_no_model_is_invented_when_the_caller_names_none() -> None:
    client = RecordingClient()
    h = handler(client)
    h.on_llm_start({"name": "ChatSomething"}, ["hello"], run_id=uuid4())
    assert h.model_provider == "" and h.model_name == ""
    start = client.spans[0]
    assert start.model_provider is None and start.model_name is None, "an unnamed model is not reported as a made-up one"


def test_the_class_name_is_not_mistaken_for_the_model() -> None:
    client = RecordingClient()
    h = handler(client, model_provider="anthropic", model_name="claude-sonnet-5-5")
    h.on_llm_start({"name": "ChatAnthropic"}, ["hello"], run_id=uuid4())
    assert client.spans[0].model_name == "claude-sonnet-5-5"


def test_the_end_of_a_call_reports_tokens_with_the_model_the_call_reported() -> None:
    client = RecordingClient()
    h = handler(client, model_provider="anthropic")
    run = uuid4()
    h.on_llm_start({"name": "ChatAnthropic"}, ["hello"], run_id=run)
    h.on_llm_end(result({"model": "claude-sonnet-5-5", "usage": {"input_tokens": 1_000, "output_tokens": 200}}), run_id=run)
    usage_span = client.spans[-1]
    assert (usage_span.prompt_tokens, usage_span.completion_tokens) == (1_000, 200)
    assert (usage_span.model_provider, usage_span.model_name) == ("anthropic", "claude-sonnet-5-5")
    assert usage_span.step_type is StepType.OBSERVATION
    assert usage_span.observation_payload is None, "the usage span carries no prompt or completion text"
    assert usage_span.thought_content is None
    assert usage_span.parent_span_id == client.spans[0].span_id


def test_a_call_whose_provider_gave_no_usage_reports_no_span_at_all() -> None:
    client = RecordingClient()
    h = handler(client, model_provider="anthropic", model_name="claude-sonnet-5-5")
    run = uuid4()
    h.on_llm_start({}, ["hello"], run_id=run)
    h.on_llm_end(result({}), run_id=run)
    assert len(client.spans) == 1, "only the start span: nothing is invented for a call with no usage"


def test_the_model_given_at_start_is_used_when_the_result_does_not_name_one() -> None:
    client = RecordingClient()
    h = handler(client, model_provider="openai")
    run = uuid4()
    h.on_llm_start({"name": "ChatOpenAI"}, ["hi"], run_id=run, invocation_params={"model": "gpt-x"})
    h.on_llm_end(result({"token_usage": {"prompt_tokens": 7, "completion_tokens": 2}}), run_id=run)
    assert client.spans[-1].model_name == "gpt-x" and client.spans[0].model_name == "gpt-x"


def test_a_result_with_usage_but_no_model_is_reported_without_a_model() -> None:
    client = RecordingClient()
    h = handler(client)
    h.on_llm_end(result({"token_usage": {"prompt_tokens": 7, "completion_tokens": 2}}), run_id=uuid4())
    span = client.spans[-1]
    assert (span.prompt_tokens, span.completion_tokens) == (7, 2)
    assert span.model_name is None and span.model_provider is None


def test_a_failed_call_forgets_its_run_so_nothing_leaks() -> None:
    client = RecordingClient()
    h = handler(client)
    run = uuid4()
    h.on_llm_start({}, ["hi"], run_id=run, invocation_params={"model": "m"})
    h.on_llm_error(RuntimeError("provider down"), run_id=run)
    assert h.pending_runs == 0
    assert len(client.spans) == 1


def test_runs_that_never_end_cannot_grow_the_handler_without_bound() -> None:
    client = RecordingClient()
    h = handler(client)
    for _ in range(5_000):
        h.on_llm_start({}, ["hi"], run_id=uuid4(), invocation_params={"model": "m"})
    assert h.pending_runs <= 1_000


def test_a_malformed_result_never_raises_into_the_callers_agent() -> None:
    client = RecordingClient()
    h = handler(client)
    h.on_llm_end(object(), run_id=uuid4())
    h.on_llm_end(None, run_id=None)
    assert client.spans == []


def test_provider_is_taken_from_the_integration_package_when_the_caller_names_none() -> None:
    client = RecordingClient()
    h = handler(client)
    run = uuid4()
    h.on_llm_start({"id": ["langchain_anthropic", "chat_models", "ChatAnthropic"]}, ["hi"], run_id=run)
    h.on_llm_end(result({"model": "claude-sonnet-5-5", "usage": {"input_tokens": 5, "output_tokens": 1}}), run_id=run)
    assert client.spans[-1].model_provider == "anthropic"


def test_an_unrecognised_integration_package_leaves_the_provider_unnamed() -> None:
    client = RecordingClient()
    h = handler(client)
    run = uuid4()
    h.on_llm_start({"id": ["langchain_something_new", "chat_models", "Chat"]}, ["hi"], run_id=run)
    h.on_llm_end(result({"model": "m", "usage": {"input_tokens": 5, "output_tokens": 1}}), run_id=run)
    assert client.spans[-1].model_provider is None


def test_the_caller_named_provider_wins_over_the_inferred_one() -> None:
    client = RecordingClient()
    h = handler(client, model_provider="bedrock")
    run = uuid4()
    h.on_llm_start({"id": ["langchain_anthropic", "x", "ChatAnthropic"]}, ["hi"], run_id=run)
    h.on_llm_end(result({"model": "claude-sonnet-5-5", "usage": {"input_tokens": 5, "output_tokens": 1}}), run_id=run)
    assert client.spans[-1].model_provider == "bedrock"


def test_a_span_that_cannot_be_built_is_dropped_not_raised_into_the_agent() -> None:
    client = RecordingClient()
    h = handler(client, model_provider="p" * 100)  # longer than the span's provider field allows
    h.on_llm_end(result({"model": "m", "usage": {"input_tokens": 5, "output_tokens": 1}}), run_id=uuid4())
    assert client.spans == []
