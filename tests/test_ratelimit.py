"""Rate limiting: bucket refill maths, tier separation, Redis fallback."""

from __future__ import annotations

import pytest

from mcp_gateway import RATE_LIMITED, MemoryRateLimiter, RedisRateLimiter, Tier
from mcp_gateway.ratelimit import RateLimited, TokenBucket
from tests.conftest import KEY_A, KEY_B, call_tool


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def test_bucket_drains_then_refills_at_rate():
    b = TokenBucket(capacity=3, refill_per_second=1.0, now=0.0)
    assert all(b.try_acquire(0.0) for _ in range(3))
    assert not b.try_acquire(0.0)
    assert b.retry_after() == pytest.approx(1.0)
    assert not b.try_acquire(0.5)
    assert b.retry_after() == pytest.approx(0.5)
    assert b.try_acquire(1.0)
    assert not b.try_acquire(1.0)


def test_bucket_never_exceeds_capacity():
    b = TokenBucket(capacity=2, refill_per_second=10.0, now=0.0)
    b.refill(100.0)
    assert b.tokens == 2.0


def test_bucket_ignores_clock_going_backwards():
    b = TokenBucket(capacity=2, refill_per_second=1.0, now=10.0)
    assert b.try_acquire(10.0)
    b.refill(5.0)
    assert b.tokens == pytest.approx(1.0)


def test_tier_validation():
    with pytest.raises(ValueError):
        Tier(capacity=0, refill_per_second=1)
    with pytest.raises(ValueError):
        Tier(capacity=1, refill_per_second=0)
    with pytest.raises(ValueError):
        MemoryRateLimiter({"a": Tier(1, 1)}, default_tier="missing")


async def test_memory_limiter_decision_and_retry_after():
    clock = FakeClock()
    lim = MemoryRateLimiter({"std": Tier(2, 0.5)}, default_tier="std", clock=clock)
    d1 = await lim.acquire("t", "tool")
    d2 = await lim.acquire("t", "tool")
    d3 = await lim.acquire("t", "tool")
    assert (d1.allowed, d2.allowed, d3.allowed) == (True, True, False)
    assert d3.retry_after == pytest.approx(2.0)
    clock.t += 2.0
    assert (await lim.acquire("t", "tool")).allowed


async def test_buckets_are_separate_per_tenant_and_tool():
    lim = MemoryRateLimiter({"std": Tier(1, 0.001)}, default_tier="std", clock=FakeClock())
    assert (await lim.acquire("a", "x")).allowed
    assert not (await lim.acquire("a", "x")).allowed
    assert (await lim.acquire("b", "x")).allowed
    assert (await lim.acquire("a", "y")).allowed


async def test_tiers_are_separate_and_unknown_tier_falls_back_to_default():
    tiers = {"free": Tier(1, 0.001), "premium": Tier(5, 0.001)}
    lim = MemoryRateLimiter(tiers, default_tier="free", clock=FakeClock())
    assert (await lim.acquire("a", "x", "free")).allowed
    assert not (await lim.acquire("a", "x", "free")).allowed
    prem = [await lim.acquire("a", "x", "premium") for _ in range(5)]
    assert all(d.allowed and d.tier == "premium" for d in prem)
    assert not (await lim.acquire("a", "x", "premium")).allowed
    fallback = await lim.acquire("z", "x", "nonexistent")
    assert fallback.tier == "free"


def test_decision_raises_with_structured_data():
    lim_decision = MemoryRateLimiter({"s": Tier(1, 1)}, default_tier="s")
    assert lim_decision.default_tier == "s"
    from mcp_gateway.ratelimit import RateDecision

    d = RateDecision(allowed=False, remaining=0.0, retry_after=2.5, tier="s")
    with pytest.raises(RateLimited) as exc:
        d.raise_if_denied("t", "tool")
    assert exc.value.code == RATE_LIMITED
    assert exc.value.data["retry_after"] == 2.5


async def test_rate_limit_trips_end_to_end(gateway, audit):
    ok1 = await call_tool(gateway, KEY_A, "limited")
    ok2 = await call_tool(gateway, KEY_A, "limited")
    denied = await call_tool(gateway, KEY_A, "limited")
    assert "result" in ok1 and "result" in ok2
    assert denied["error"]["code"] == RATE_LIMITED
    assert denied["error"]["data"]["tier"] == "tiny"
    assert audit.records[-1].outcome == "denied"
    # other tenant has its own bucket
    assert "result" in await call_tool(gateway, KEY_B, "limited")


async def test_redis_limiter_degrades_to_memory_without_redis_package(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name.startswith("redis"):
            raise ImportError("no redis here")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    lim = RedisRateLimiter("redis://localhost:6379/0", {"s": Tier(1, 0.001)}, default_tier="s")
    assert (await lim.acquire("t", "x")).allowed
    assert lim.degraded and "not installed" in lim.degraded_reason
    assert not (await lim.acquire("t", "x")).allowed


class FailingRedis:
    async def eval(self, *a, **k):
        raise ConnectionError("refused")


class ScriptedRedis:
    """Enough of redis.asyncio to exercise the Lua path's result handling."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    async def eval(self, script, numkeys, key, *args):
        self.calls.append((key, args))
        return self.replies.pop(0)


async def test_redis_limiter_degrades_on_connection_failure():
    lim = RedisRateLimiter("redis://x", {"s": Tier(2, 1.0)}, default_tier="s", client=FailingRedis())
    d = await lim.acquire("t", "x")
    assert d.allowed and lim.degraded and "unavailable" in lim.degraded_reason


async def test_redis_limiter_parses_script_replies():
    client = ScriptedRedis([[1, "1.0"], [0, "0.25"]])
    lim = RedisRateLimiter("redis://x", {"s": Tier(2, 0.5)}, default_tier="s", client=client)
    d1 = await lim.acquire("acme", "search", "s")
    d2 = await lim.acquire("acme", "search", "s")
    assert d1.allowed and d1.remaining == 1.0
    assert not d2.allowed and d2.retry_after == pytest.approx(1.5)
    assert client.calls[0][0] == "mcpgw:rl:acme:search:s"
    assert not lim.degraded
