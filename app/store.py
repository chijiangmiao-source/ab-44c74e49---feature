"""In-memory store of frozen audit conclusions."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone


def fingerprint(payload: dict) -> str:
    """Stable digest of a canonicalized request payload."""
    blob = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditRecord:
    """Immutable per-audit conclusion set."""

    audit_id: str
    digest: str
    rules: list
    verdicts: list
    created_at: str

    def response(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "created_at": self.created_at,
            "rules": self.rules,
            "verdicts": self.verdicts,
        }


class AuditStore:
    """Thread-safe audit_id -> AuditRecord map.  Records never change."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, AuditRecord] = {}

    def get(self, audit_id: str) -> AuditRecord | None:
        with self._lock:
            return self._records.get(audit_id)

    def put_if_absent(self, record: AuditRecord) -> AuditRecord:
        """Store the record; return whatever record owns the slot."""
        with self._lock:
            existing = self._records.get(record.audit_id)
            if existing is not None:
                return existing
            self._records[record.audit_id] = record
            return record


def new_record(audit_id: str, payload: dict, verdicts: list) -> AuditRecord:
    return AuditRecord(
        audit_id=audit_id,
        digest=fingerprint(payload),
        rules=payload["rules"],
        verdicts=verdicts,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


@dataclass(frozen=True)
class ReorderRecord:
    """Immutable reorder conclusion; never mutates its source audit."""

    reorder_id: str
    digest: str
    audit_id: str
    constraints: list
    result: dict
    created_at: str

    def response(self) -> dict:
        return {
            "reorder_id": self.reorder_id,
            "audit_id": self.audit_id,
            "created_at": self.created_at,
            "constraints": self.constraints,
            "result": self.result,
        }


class ReorderStore:
    """Thread-safe reorder_id -> ReorderRecord map.  Records never change."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, ReorderRecord] = {}

    def get(self, reorder_id: str) -> ReorderRecord | None:
        with self._lock:
            return self._records.get(reorder_id)

    def put_if_absent(self, record: ReorderRecord) -> ReorderRecord:
        """Store the record; return whatever record owns the slot."""
        with self._lock:
            existing = self._records.get(record.reorder_id)
            if existing is not None:
                return existing
            self._records[record.reorder_id] = record
            return record


def reorder_payload(
    audit_id: str, constraints: list[dict]
) -> dict:
    """Canonical identity of a reorder submission: source plus constraints."""
    return {"audit_id": audit_id, "constraints": constraints}


def new_reorder_record(
    reorder_id: str, audit_id: str, constraints: list[dict], result: dict
) -> ReorderRecord:
    return ReorderRecord(
        reorder_id=reorder_id,
        digest=fingerprint(reorder_payload(audit_id, constraints)),
        audit_id=audit_id,
        constraints=constraints,
        result=result,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
