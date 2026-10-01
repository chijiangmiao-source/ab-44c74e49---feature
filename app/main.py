"""HTTP API for the flight data link rule isolation auditor."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse

from .engine import analyze
from .reorder import (
    MAX_REORDER_RULES,
    ReorderError,
    constraint_cycle,
    normalize_constraints,
    plan_reorder,
)
from .schemas import AuditRequest, ReorderRequest, Rule
from .store import AuditStore, fingerprint, new_record, new_reorder_record

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="飞行数据链路规则隔离审计", version="1.0.0")
store = AuditStore()


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    errors = [
        {
            "loc": [str(part) for part in err.get("loc", [])],
            "msg": str(err.get("msg", "")),
            "type": str(err.get("type", "")),
        }
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={"detail": "请求未通过校验", "errors": errors},
    )


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/api/audits", status_code=201)
def create_audit(req: AuditRequest):
    """Freeze per-rule verdicts for a new audit identifier.

    Replaying the identical payload under the same audit id returns the
    existing frozen conclusions (200).  The same audit id with a different
    payload is rejected (409) and never rewrites the stored conclusions.
    """
    payload = req.model_dump(mode="json")
    digest = fingerprint(payload)

    existing = store.get(req.audit_id)
    if existing is not None:
        if existing.digest == digest:
            return JSONResponse(status_code=200, content=existing.response())
        raise HTTPException(status_code=409, detail=_conflict_detail(req.audit_id))

    record = new_record(req.audit_id, payload, analyze(req.rules))
    winner = store.put_if_absent(record)
    if winner.digest != digest:
        raise HTTPException(status_code=409, detail=_conflict_detail(req.audit_id))
    status_code = 201 if winner is record else 200
    return JSONResponse(status_code=status_code, content=winner.response())


@app.get("/api/audits/{audit_id}")
def get_audit(audit_id: str):
    """Return the frozen conclusions for an audit identifier."""
    record = store.get(audit_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "audit_not_found",
                "message": f"审计标识 {audit_id!r} 不存在。",
                "audit_id": audit_id,
            },
        )
    return record.response()


@app.post("/api/audits/{audit_id}/reorders", status_code=201)
def create_reorder(audit_id: str, req: ReorderRequest):
    """Freeze a stable reorder conclusion for rules of a frozen audit.

    The source audit must exist and contain at most
    :data:`MAX_REORDER_RULES` rules.  Precedence pairs must reference
    existing rule ids and form an acyclic graph; otherwise HTTP 422 with
    no trace left.  Replaying the identical source/constraints under the
    same ``reorder_id`` returns the frozen conclusion (200); reusing the
    reorder id with another source audit or changed constraints is
    rejected (409) without rewriting anything.
    """
    source = store.get(audit_id)
    if source is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "audit_not_found",
                "message": f"来源审计标识 {audit_id!r} 不存在，无法发起重排序。",
                "audit_id": audit_id,
            },
        )

    n = len(source.rules)
    if n == 0 or n > MAX_REORDER_RULES:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "reorder_rules_out_of_range",
                "message": (
                    f"重排仅支持 1 至 {MAX_REORDER_RULES} 条规则的冻结审计，"
                    f"来源审计 {audit_id!r} 含 {n} 条。"
                ),
                "audit_id": audit_id,
            },
        )

    rules = [Rule.model_validate(raw) for raw in source.rules]
    rule_ids = [rule.id for rule in rules]
    raw_constraints = req.model_dump(mode="json")["constraints"]
    try:
        pairs = normalize_constraints(raw_constraints, rule_ids)
    except ReorderError as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_precedence_constraint", "message": str(exc)},
        ) from exc

    cycle = constraint_cycle(pairs, n)
    if cycle is not None:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "cyclic_precedence_constraint",
                "message": "优先约束构成循环，不存在满足全部约束的顺序："
                + " → ".join(rule_ids[i] for i in cycle),
                "cycle": [rule_ids[i] for i in cycle],
            },
        )

    # Canonicalize: de-duplicated pairs in first-occurrence order.
    constraints = [
        {"before": rule_ids[i], "after": rule_ids[j]} for i, j in pairs
    ]
    result = plan_reorder(rules, pairs)

    record = new_reorder_record(req.reorder_id, audit_id, constraints, result)
    existing = store.get_reorder(req.reorder_id)
    if existing is not None:
        if existing.digest == record.digest:
            return JSONResponse(status_code=200, content=existing.response())
        raise HTTPException(
            status_code=409, detail=_reorder_conflict_detail(req.reorder_id)
        )

    winner = store.put_reorder_if_absent(record)
    if winner.digest != record.digest:
        raise HTTPException(
            status_code=409, detail=_reorder_conflict_detail(req.reorder_id)
        )
    status_code = 201 if winner is record else 200
    return JSONResponse(status_code=status_code, content=winner.response())


@app.get("/api/reorders/{reorder_id}")
def get_reorder(reorder_id: str):
    """Return the frozen reorder conclusion for a reorder identifier."""
    record = store.get_reorder(reorder_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "reorder_not_found",
                "message": f"重排序标识 {reorder_id!r} 不存在。",
                "reorder_id": reorder_id,
            },
        )
    return record.response()


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


def _conflict_detail(audit_id: str) -> dict:
    return {
        "error": "audit_id_conflict",
        "message": (
            f"审计标识 {audit_id!r} 已存在且载荷不同；"
            "既有结论已冻结，拒绝改写。"
        ),
        "audit_id": audit_id,
    }


def _reorder_conflict_detail(reorder_id: str) -> dict:
    return {
        "error": "reorder_id_conflict",
        "message": (
            f"重排序标识 {reorder_id!r} 已绑定其他来源审计或不同的优先约束；"
            "既有重排结论已冻结，拒绝改写。"
        ),
        "reorder_id": reorder_id,
    }
