"""Telemetry: span per call, no-op fallback when OpenTelemetry is absent."""

from __future__ import annotations

import builtins

import pytest

from mcp_gateway import NoopTracer, RecordingTracer, get_tracer
from mcp_gateway.telemetry import OTelTracer
from tests.conftest import KEY_A, call_tool


def test_recording_tracer_captures_attributes_and_errors():
    t = RecordingTracer()
    with t.span("a", x=1) as s:
        s.set_attribute("y", 2)
    with pytest.raises(RuntimeError), t.span("b"):
        raise RuntimeError("bad")
    assert t.spans[0].attributes == {"x": 1, "y": 2} and t.spans[0].error is None
    assert t.spans[1].error == "bad"


def test_noop_tracer_is_silent():
    with NoopTracer().span("x", a=1) as s:
        s.set_attribute("k", "v")
        s.record_error("ignored")


def test_get_tracer_falls_back_to_noop_without_otel(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name.startswith("opentelemetry"):
            raise ImportError("no otel")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert isinstance(get_tracer(), NoopTracer)
    with pytest.raises(ImportError):
        OTelTracer()


def test_get_tracer_can_skip_otel_explicitly():
    assert isinstance(get_tracer(prefer_otel=False), NoopTracer)


async def test_gateway_emits_one_span_per_call_with_outcome(gateway, tracer):
    await call_tool(gateway, KEY_A, "echo", {"text": "hi"})
    await call_tool(gateway, None, "echo", {"text": "hi"})
    assert [s.name for s in tracer.spans] == ["mcp.tools/call", "mcp.tools/call"]
    ok, denied = tracer.spans
    assert ok.attributes["tool"] == "echo" and ok.attributes["tenant_id"] == "tenant-a"
    assert ok.error is None
    assert denied.error == "missing API key"
