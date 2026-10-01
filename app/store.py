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


@dataclass(frozen=True)
class ReorderRecord:
    """Immutable reorder conclusion, bound to one frozen source audit."""

    reorder_id: str
    audit_id: str
    digest: str
    constraints: list
    result: dict
    created_at: str

    def response(self) -> dict:
        body = {
            "reorder_id": self.reorder_id,
            "audit_id": self.audit_id,
            "created_at": self.created_at,
            "constraints": self.constraints,
        }
        body.update(self.result)
        return body


class AuditStore:
    """Thread-safe frozen-conclusion maps.  Records never change.

    Reorder conclusions live in a separate map keyed by ``reorder_id``;
    they never touch or rewrite the source audit's frozen record.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, AuditRecord] = {}
        self._reorders: dict[str, ReorderRecord] = {}

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

    def get_reorder(self, reorder_id: str) -> ReorderRecord | None:
        with self._lock:
            return self._reorders.get(reorder_id)

    def put_reorder_if_absent(self, record: ReorderRecord) -> ReorderRecord:
        """Store the reorder record; return whatever record owns the slot."""
        with self._lock:
            existing = self._reorders.get(record.reorder_id)
            if existing is not None:
                return existing
            self._reorders[record.reorder_id] = record
            return record


def new_record(audit_id: str, payload: dict, verdicts: list) -> AuditRecord:
    return AuditRecord(
        audit_id=audit_id,
        digest=fingerprint(payload),
        rules=payload["rules"],
        verdicts=verdicts,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def reorder_fingerprint(audit_id: str, constraints: list) -> str:
    """Digest binding a reorder id to its source audit and constraint set."""
    return fingerprint({"audit_id": audit_id, "constraints": constraints})


def new_reorder_record(
    reorder_id: str, audit_id: str, constraints: list, result: dict
) -> ReorderRecord:
    return ReorderRecord(
        reorder_id=reorder_id,
        audit_id=audit_id,
        digest=reorder_fingerprint(audit_id, constraints),
        constraints=constraints,
        result=result,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
