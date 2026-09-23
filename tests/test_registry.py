"""Registry: decorators attach specs, duplicates rejected, handler shapes supported."""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from mcp_gateway import Registry, prompt, resource, tool
from mcp_gateway.registry import ResourceSpec, ToolSpec, spec_of


class In(BaseModel):
    n: int


class Out(BaseModel):
    doubled: int


def test_tool_decorator_attaches_spec_and_keeps_function_callable():
    @tool("double", input_model=In, output_model=Out, scopes=("math:run",), rate_tier="free")
    def double(args: In, ctx) -> Out:
        """Double a number."""
        return Out(doubled=args.n * 2)

    spec = spec_of(double)
    assert isinstance(spec, ToolSpec)
    assert spec.name == "double" and spec.scopes == ("math:run",) and spec.rate_tier == "free"
    assert spec.description == "Double a number."
    assert double(In(n=2), None).doubled == 4
    assert spec.definition().inputSchema["required"] == ["n"]


def test_tool_name_defaults_to_function_name():
    @tool(input_model=In)
    def triple(args, ctx):
        return {"x": args.n * 3}

    assert spec_of(triple).name == "triple"


async def test_invoke_supports_sync_async_and_single_arg_handlers():
    @tool(input_model=In)
    def one_arg(args):
        return {"n": args.n}

    @tool(input_model=In)
    async def two_args(args, ctx):
        return {"n": args.n, "ctx": ctx}

    assert await spec_of(one_arg).invoke(In(n=1), "ctx") == {"n": 1}
    assert await spec_of(two_args).invoke(In(n=2), "ctx") == {"n": 2, "ctx": "ctx"}


def test_resource_and_prompt_decorators():
    @resource("mem://x", mime_type="application/json")
    def x(ctx):
        return "{}"

    @prompt("p", arguments=[{"name": "q", "required": True}])
    def p(arguments, ctx):
        return arguments["q"]

    rs = spec_of(x)
    assert isinstance(rs, ResourceSpec) and rs.definition().mimeType == "application/json"
    ps = spec_of(p)
    assert ps.definition().arguments[0].required is True


def test_registry_rejects_duplicates_and_undecorated():
    @tool("same", input_model=In)
    def a(args, ctx):
        return {}

    @tool("same", input_model=In)
    def b(args, ctx):
        return {}

    reg = Registry([a])
    with pytest.raises(ValueError, match="duplicate tool"):
        reg.add(b)
    with pytest.raises(TypeError):
        reg.add(lambda: None)
    assert [d.name for d in reg.tool_definitions()] == ["same"]
