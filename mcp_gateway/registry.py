"""Decorators that turn plain functions into MCP tools, resources and prompts.

A decorated function keeps working as a normal function; the decorator only
attaches a spec (``__mcp_spec__``) describing its name, models, scopes, rate
tier and guardrail policy. ``Registry`` collects specs and produces the
``tools/list`` / ``resources/list`` / ``prompts/list`` payloads.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from .guardrails import DEFAULT_POLICY, ToolPolicy
from .protocol import PromptArgument, PromptDefinition, ResourceDefinition, ToolDefinition

SPEC_ATTR = "__mcp_spec__"


async def _call(handler: Callable[..., Any], *args: Any) -> Any:
    """Call a sync or async handler, passing only as many positionals as it accepts."""
    try:
        sig = inspect.signature(handler)
        positional = [
            p
            for p in sig.parameters.values()
            if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        accepts_var = any(p.kind == p.VAR_POSITIONAL for p in sig.parameters.values())
        n = len(args) if accepts_var else min(len(args), len(positional))
    except (TypeError, ValueError):
        n = len(args)
    result = handler(*args[:n])
    if inspect.isawaitable(result):
        result = await result
    return result


@dataclass
class ToolSpec:
    name: str
    handler: Callable[..., Any]
    input_model: type[BaseModel]
    output_model: type[BaseModel] | None = None
    description: str = ""
    scopes: tuple[str, ...] = ()
    rate_tier: str | None = None
    policy: ToolPolicy = field(default_factory=lambda: DEFAULT_POLICY)

    def definition(self) -> ToolDefinition:
        return ToolDefinition(
            name=self.name,
            description=self.description,
            inputSchema=self.input_model.model_json_schema(),
        )

    async def invoke(self, args: BaseModel, ctx: Any) -> Any:
        return await _call(self.handler, args, ctx)


@dataclass
class ResourceSpec:
    uri: str
    handler: Callable[..., Any]
    name: str = ""
    description: str | None = None
    mime_type: str = "text/plain"

    def definition(self) -> ResourceDefinition:
        return ResourceDefinition(
            uri=self.uri, name=self.name or self.uri, description=self.description,
            mimeType=self.mime_type,
        )

    async def read(self, ctx: Any) -> Any:
        return await _call(self.handler, ctx)


@dataclass
class PromptSpec:
    name: str
    handler: Callable[..., Any]
    description: str | None = None
    arguments: tuple[PromptArgument, ...] = ()

    def definition(self) -> PromptDefinition:
        return PromptDefinition(
            name=self.name, description=self.description, arguments=list(self.arguments)
        )

    async def render(self, arguments: dict[str, str], ctx: Any) -> Any:
        return await _call(self.handler, arguments, ctx)


Spec = ToolSpec | ResourceSpec | PromptSpec


def tool(
    name: str | None = None,
    *,
    input_model: type[BaseModel],
    output_model: type[BaseModel] | None = None,
    description: str | None = None,
    scopes: Iterable[str] = (),
    rate_tier: str | None = None,
    policy: ToolPolicy | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Register ``fn(args: input_model, ctx) -> output_model`` as an MCP tool."""

    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        spec = ToolSpec(
            name=name or fn.__name__,
            handler=fn,
            input_model=input_model,
            output_model=output_model,
            description=(description or inspect.getdoc(fn) or "").strip(),
            scopes=tuple(scopes),
            rate_tier=rate_tier,
            policy=policy or DEFAULT_POLICY,
        )
        setattr(fn, SPEC_ATTR, spec)
        return fn

    return deco


def resource(
    uri: str,
    *,
    name: str | None = None,
    description: str | None = None,
    mime_type: str = "text/plain",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Register ``fn(ctx) -> str`` as a readable MCP resource."""

    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        spec = ResourceSpec(
            uri=uri,
            handler=fn,
            name=name or fn.__name__,
            description=(description or inspect.getdoc(fn) or None),
            mime_type=mime_type,
        )
        setattr(fn, SPEC_ATTR, spec)
        return fn

    return deco


def prompt(
    name: str | None = None,
    *,
    description: str | None = None,
    arguments: Iterable[PromptArgument | dict[str, Any]] = (),
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Register ``fn(arguments: dict, ctx) -> str | list[PromptMessage]`` as a prompt."""

    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        args = tuple(
            a if isinstance(a, PromptArgument) else PromptArgument.model_validate(a)
            for a in arguments
        )
        spec = PromptSpec(
            name=name or fn.__name__,
            handler=fn,
            description=(description or inspect.getdoc(fn) or None),
            arguments=args,
        )
        setattr(fn, SPEC_ATTR, spec)
        return fn

    return deco


def spec_of(obj: Any) -> Spec:
    if isinstance(obj, (ToolSpec, ResourceSpec, PromptSpec)):
        return obj
    spec = getattr(obj, SPEC_ATTR, None)
    if spec is None:
        raise TypeError(f"{obj!r} is not decorated with @tool, @resource or @prompt")
    return spec


class Registry:
    def __init__(self, items: Iterable[Any] = ()) -> None:
        self.tools: dict[str, ToolSpec] = {}
        self.resources: dict[str, ResourceSpec] = {}
        self.prompts: dict[str, PromptSpec] = {}
        for item in items:
            self.add(item)

    def add(self, obj: Any) -> Spec:
        spec = spec_of(obj)
        if isinstance(spec, ToolSpec):
            if spec.name in self.tools:
                raise ValueError(f"duplicate tool name: {spec.name}")
            self.tools[spec.name] = spec
        elif isinstance(spec, ResourceSpec):
            if spec.uri in self.resources:
                raise ValueError(f"duplicate resource uri: {spec.uri}")
            self.resources[spec.uri] = spec
        else:
            if spec.name in self.prompts:
                raise ValueError(f"duplicate prompt name: {spec.name}")
            self.prompts[spec.name] = spec
        return spec

    def tool_definitions(self) -> list[ToolDefinition]:
        return [t.definition() for t in self.tools.values()]

    def resource_definitions(self) -> list[ResourceDefinition]:
        return [r.definition() for r in self.resources.values()]

    def prompt_definitions(self) -> list[PromptDefinition]:
        return [p.definition() for p in self.prompts.values()]
