"""
OpenTelemetry distributed tracing setup for AgentWall.
"""

from contextlib import contextmanager
from typing import Any, Generator
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.trace import Status, StatusCode, Tracer

_tracer_initialized = False


def setup_telemetry(service_name: str = "agentwall-proxy", export_console: bool = False) -> Tracer:
    global _tracer_initialized
    if not _tracer_initialized:
        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        if export_console:
            provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        trace.set_tracer_provider(provider)
        _tracer_initialized = True
    return trace.get_tracer(service_name)


def get_tracer() -> Tracer:
    return trace.get_tracer("agentwall-proxy")


@contextmanager
def trace_span(span_name: str, attributes: dict[str, Any] | None = None) -> Generator[trace.Span, None, None]:
    tracer = get_tracer()
    with tracer.start_as_current_span(span_name) as span:
        if attributes:
            for k, v in attributes.items():
                span.set_attribute(k, str(v) if not isinstance(v, (bool, int, float, str)) else v)
        try:
            yield span
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            raise

