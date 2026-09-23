"""In-process pub/sub hub feeding the SSE transport.

The gateway publishes a small, PII-free event per tool call scoped to the
calling tenant; an SSE subscriber authenticated as that tenant receives it.
Subscribers of other tenants never see it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

CLOSE = object()


@dataclass(frozen=True)
class Event:
    event: str
    data: dict[str, Any]
    tenant_id: str | None = None


@dataclass
class EventHub:
    max_queue: int = 256
    _subscribers: dict[int, tuple[str | None, asyncio.Queue[Any]]] = field(default_factory=dict)
    _next_id: int = 0
    closed: bool = False

    @contextmanager
    def subscribe(self, tenant_id: str | None = None) -> Iterator[asyncio.Queue[Any]]:
        """Queue of events for ``tenant_id`` (``None`` = every tenant, for operators)."""
        sub_id = self._next_id
        self._next_id += 1
        queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=self.max_queue)
        self._subscribers[sub_id] = (tenant_id, queue)
        try:
            yield queue
        finally:
            self._subscribers.pop(sub_id, None)

    def publish(self, event: Event) -> int:
        """Deliver to matching subscribers; returns how many received it."""
        delivered = 0
        for tenant, queue in list(self._subscribers.values()):
            if tenant is not None and tenant != event.tenant_id:
                continue
            try:
                queue.put_nowait(event)
                delivered += 1
            except asyncio.QueueFull:
                # A slow consumer loses events rather than stalling the gateway.
                continue
        return delivered

    def close(self) -> None:
        self.closed = True
        for _, queue in list(self._subscribers.values()):
            try:
                queue.put_nowait(CLOSE)
            except asyncio.QueueFull:
                continue

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)
