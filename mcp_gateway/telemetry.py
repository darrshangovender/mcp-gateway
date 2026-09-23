"""One span per call, with OpenTelemetry when it is installed and a no-op
tracer when it is not.

``get_tracer()`` never raises on a missing package: telemetry is something
you turn on, not something the gateway needs in order to run.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Protocol


class Span(Protocol):
    def set_attribute(self, key: str, value: Any) -> None: ...
    def record_error(self, message: str, exc: BaseException | None = None) -> None: ...


class Tracer(Protocol):
    def span(self, name: str, **attributes: Any) -> Any: ...


class NoopSpan:
    def set_attribute(self, key: str, value: Any) -> None:
        return None

    def record_error(self, message: str, exc: BaseException | None = None) -> None:
        return None


class NoopTracer:
    @contextmanager
    def span(self, name: str, **attributes: Any) -> Iterator[NoopSpan]:
        yield NoopSpan()


@dataclass
class RecordedSpan:
    name: str
    attributes: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    exception: BaseException | None = None

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def record_error(self, message: str, exc: BaseException | None = None) -> None:
        self.error = message
        self.exception = exc


class RecordingTracer:
    """Keeps every span in memory; used by tests and useful in a REPL."""

    def __init__(self) -> None:
        self.spans: list[RecordedSpan] = []

    @contextmanager
    def span(self, name: str, **attributes: Any) -> Iterator[RecordedSpan]:
        rec = RecordedSpan(name=name, attributes=dict(attributes))
        self.spans.append(rec)
        try:
            yield rec
        except BaseException as exc:
            if rec.error is None:
                rec.record_error(str(exc) or exc.__class__.__name__, exc)
            raise


class _OTelSpan:
    def __init__(self, span: Any, status_cls: Any, status_code: Any) -> None:
        self._span = span
        self._status_cls = status_cls
        self._status_code = status_code

    def set_attribute(self, key: str, value: Any) -> None:
        if isinstance(value, (str, bool, int, float)):
            self._span.set_attribute(key, value)
        else:
            self._span.set_attribute(key, str(value))

    def record_error(self, message: str, exc: BaseException | None = None) -> None:
        if exc is not None:
            self._span.record_exception(exc)
        self._span.set_status(self._status_cls(self._status_code.ERROR, message))


class OTelTracer:
    """Adapter over ``opentelemetry.trace``; import fails loudly at construction."""

    def __init__(self, service_name: str = "mcp-gateway") -> None:
        from opentelemetry import trace  # lazy: optional dependency
        from opentelemetry.trace import Status, StatusCode

        self._tracer = trace.get_tracer(service_name)
        self._status_cls = Status
        self._status_code = StatusCode

    @contextmanager
    def span(self, name: str, **attributes: Any) -> Iterator[_OTelSpan]:
        with self._tracer.start_as_current_span(name) as raw:
            wrapped = _OTelSpan(raw, self._status_cls, self._status_code)
            for k, v in attributes.items():
                wrapped.set_attribute(k, v)
            try:
                yield wrapped
            except BaseException as exc:
                wrapped.record_error(str(exc) or exc.__class__.__name__, exc)
                raise


def get_tracer(service_name: str = "mcp-gateway", *, prefer_otel: bool = True) -> Tracer:
    """OpenTelemetry if importable and wanted, otherwise a no-op tracer."""
    if prefer_otel:
        try:
            return OTelTracer(service_name)
        except ImportError:
            pass
    return NoopTracer()
