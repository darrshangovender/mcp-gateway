"""Token-bucket rate limiting per (tenant, tool), with named tiers.

``MemoryRateLimiter`` is the default and is what the tests exercise.
``RedisRateLimiter`` lazy-imports ``redis`` so it is not a hard dependency,
and degrades to the in-memory limiter if the package is missing or the
server is unreachable — a rate limiter that takes the gateway down with it
is worse than one that briefly limits per-process.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .protocol import RATE_LIMITED, GatewayError


class RateLimited(GatewayError):
    code = RATE_LIMITED


@dataclass(frozen=True)
class Tier:
    capacity: int
    refill_per_second: float

    def __post_init__(self) -> None:
        if self.capacity < 1:
            raise ValueError("capacity must be >= 1")
        if self.refill_per_second <= 0:
            raise ValueError("refill_per_second must be > 0")


DEFAULT_TIERS: dict[str, Tier] = {
    "free": Tier(capacity=10, refill_per_second=10 / 60),
    "standard": Tier(capacity=60, refill_per_second=1.0),
    "premium": Tier(capacity=600, refill_per_second=10.0),
}


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    remaining: float
    retry_after: float
    tier: str

    def raise_if_denied(self, tenant_id: str, tool: str) -> None:
        if not self.allowed:
            raise RateLimited(
                f"rate limit exceeded for '{tool}' (tier {self.tier}); "
                f"retry in {self.retry_after:.1f}s",
                data={
                    "reason": "rate_limited",
                    "tenant_id": tenant_id,
                    "tool": tool,
                    "tier": self.tier,
                    "retry_after": round(self.retry_after, 3),
                },
            )


class TokenBucket:
    """Classic token bucket: ``capacity`` tokens, refilled continuously."""

    def __init__(self, capacity: int, refill_per_second: float, now: float) -> None:
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self.tokens = float(capacity)
        self.updated = now

    def refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(float(self.capacity), self.tokens + elapsed * self.refill_per_second)
        self.updated = now

    def try_acquire(self, now: float, cost: float = 1.0) -> bool:
        self.refill(now)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

    def retry_after(self, cost: float = 1.0) -> float:
        deficit = cost - self.tokens
        return 0.0 if deficit <= 0 else deficit / self.refill_per_second


class RateLimiter(Protocol):
    default_tier: str

    async def acquire(self, tenant_id: str, tool: str, tier: str | None = None) -> RateDecision: ...


class MemoryRateLimiter:
    def __init__(
        self,
        tiers: Mapping[str, Tier] | None = None,
        *,
        default_tier: str = "standard",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.tiers: dict[str, Tier] = dict(tiers or DEFAULT_TIERS)
        if default_tier not in self.tiers:
            raise ValueError(f"default tier '{default_tier}' not in tiers")
        self.default_tier = default_tier
        self._clock = clock
        self._buckets: dict[tuple[str, str, str], TokenBucket] = {}

    def _tier(self, name: str | None) -> tuple[str, Tier]:
        key = name if name in self.tiers else self.default_tier
        return key, self.tiers[key]

    async def acquire(self, tenant_id: str, tool: str, tier: str | None = None) -> RateDecision:
        name, spec = self._tier(tier)
        now = self._clock()
        key = (tenant_id, tool, name)
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = TokenBucket(spec.capacity, spec.refill_per_second, now)
            self._buckets[key] = bucket
        allowed = bucket.try_acquire(now)
        return RateDecision(
            allowed=allowed,
            remaining=bucket.tokens,
            retry_after=0.0 if allowed else bucket.retry_after(),
            tier=name,
        )

    def reset(self) -> None:
        self._buckets.clear()


# Atomic token bucket in Redis. KEYS[1] = bucket hash; ARGV = capacity,
# refill/s, cost, now (seconds, float), ttl. Returns {allowed, tokens}.
_LUA_TOKEN_BUCKET = """
local cap = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local now = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])
local data = redis.call('HMGET', KEYS[1], 'tokens', 'updated')
local tokens = tonumber(data[1])
local updated = tonumber(data[2])
if tokens == nil then tokens = cap end
if updated == nil then updated = now end
local elapsed = now - updated
if elapsed < 0 then elapsed = 0 end
tokens = math.min(cap, tokens + elapsed * rate)
local allowed = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'updated', now)
redis.call('EXPIRE', KEYS[1], ttl)
return {allowed, tostring(tokens)}
"""


class RedisRateLimiter:
    """Shared token buckets in Redis; falls back to memory when Redis is absent.

    ``degraded`` is True once the fallback has been engaged, so operators can
    alert on it rather than discover it from a traffic spike.
    """

    def __init__(
        self,
        url: str,
        tiers: Mapping[str, Tier] | None = None,
        *,
        default_tier: str = "standard",
        prefix: str = "mcpgw:rl",
        fallback: MemoryRateLimiter | None = None,
        client: Any = None,
    ) -> None:
        self.url = url
        self.tiers: dict[str, Tier] = dict(tiers or DEFAULT_TIERS)
        if default_tier not in self.tiers:
            raise ValueError(f"default tier '{default_tier}' not in tiers")
        self.default_tier = default_tier
        self.prefix = prefix
        self.fallback = fallback or MemoryRateLimiter(self.tiers, default_tier=default_tier)
        self.degraded = False
        self.degraded_reason: str | None = None
        self._client = client
        self._connect_attempted = client is not None

    def _connect(self) -> Any:
        if self._connect_attempted:
            return self._client
        self._connect_attempted = True
        try:
            import redis.asyncio as redis_asyncio  # lazy: optional dependency
        except ImportError:
            self._degrade("redis package not installed")
            return None
        self._client = redis_asyncio.from_url(self.url, decode_responses=True)
        return self._client

    def _degrade(self, reason: str) -> None:
        self.degraded = True
        self.degraded_reason = reason
        self._client = None

    async def acquire(self, tenant_id: str, tool: str, tier: str | None = None) -> RateDecision:
        client = self._connect()
        if client is None:
            return await self.fallback.acquire(tenant_id, tool, tier)
        name = tier if tier in self.tiers else self.default_tier
        spec = self.tiers[name]
        key = f"{self.prefix}:{tenant_id}:{tool}:{name}"
        ttl = int(spec.capacity / spec.refill_per_second) + 1
        try:
            allowed, tokens = await client.eval(
                _LUA_TOKEN_BUCKET,
                1,
                key,
                spec.capacity,
                spec.refill_per_second,
                1,
                time.time(),
                ttl,
            )
        except Exception as exc:  # noqa: BLE001 - any transport failure degrades
            self._degrade(f"redis unavailable: {exc.__class__.__name__}")
            return await self.fallback.acquire(tenant_id, tool, tier)
        remaining = float(tokens)
        ok = bool(int(allowed))
        retry_after = 0.0 if ok else (1.0 - remaining) / spec.refill_per_second
        return RateDecision(allowed=ok, remaining=remaining, retry_after=retry_after, tier=name)
