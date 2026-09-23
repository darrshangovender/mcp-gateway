"""Append-only JSONL audit log.

Every call is recorded — allowed, denied, or errored — with who made it,
which tool, a hash of the arguments (never the arguments: they carry PII),
the outcome, latency and any denial reason. The log is a compliance
artefact, so nothing is ever rewritten or removed.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field

Outcome = Literal["ok", "denied", "error"]


class AuditRecord(BaseModel):
    ts: str = Field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="milliseconds"))
    request_id: int | str | None = None
    transport: str = "unknown"
    tenant_id: str | None = None
    key_id: str | None = None
    method: str
    tool: str | None = None
    args_hash: str | None = None
    outcome: Outcome
    error_code: int | None = None
    denial_reason: str | None = None
    latency_ms: float = 0.0


def hash_args(arguments: Any) -> str:
    """sha256 of the canonical JSON form; the same args always hash the same."""
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class AuditLog(Protocol):
    def write(self, record: AuditRecord) -> None: ...


class JSONLAuditLog:
    """One JSON object per line, appended under a lock, flushed per write."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, record: AuditRecord) -> None:
        line = record.model_dump_json(exclude_none=True)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()

    def read_all(self) -> list[AuditRecord]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as fh:
            return [AuditRecord.model_validate_json(line) for line in fh if line.strip()]


class MemoryAuditLog:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []
        self._lock = threading.Lock()

    def write(self, record: AuditRecord) -> None:
        with self._lock:
            self.records.append(record)

    def clear(self) -> None:
        with self._lock:
            self.records.clear()


class NullAuditLog:
    def write(self, record: AuditRecord) -> None:
        return None
