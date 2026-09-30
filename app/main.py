"""HTTP API for the flight data link rule isolation auditor."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse

from .engine import analyze
from .reorder import ReorderError, reorder as compute_reorder
from .schemas import MAX_REORDER_RULES, AuditRequest, ReorderRequest, Rule
from .store import (
    AuditStore,
    ReorderStore,
    fingerprint,
    new_record,
    new_reorder_record,
    reorder_payload,
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="飞行数据链路规则隔离审计", version="1.0.0")
store = AuditStore()
reorder_store = ReorderStore()


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


@app.post("/api/reorders", status_code=201)
def create_reorder(req: ReorderRequest):
    """Freeze a reorder conclusion for a stable reorder identifier.

    The source audit must exist and carry at most
    ``MAX_REORDER_RULES`` rules.  Replaying the identical source and
    constraint set under the same reorder id returns the existing frozen
    conclusion (200); changing the source audit or the constraints under
    the same id is rejected (409) and never rewrites it.  Unknown
    sources, dangling or cyclic constraints are rejected without leaving
    a record.  Source audit conclusions are never modified.
    """
    audit = store.get(req.audit_id)
    if audit is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "audit_not_found",
                "message": f"审计标识 {req.audit_id!r} 不存在，无法发起重排序。",
                "audit_id": req.audit_id,
            },
        )
    if len(audit.rules) > MAX_REORDER_RULES:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "too_many_rules",
                "message": (
                    f"重排序仅接受至多 {MAX_REORDER_RULES} 条规则的审计；"
                    f"审计 {req.audit_id!r} 含 {len(audit.rules)} 条。"
                ),
                "audit_id": req.audit_id,
                "rule_count": len(audit.rules),
            },
        )

    payload = req.model_dump(mode="json")
    constraints = payload["constraints"]
    digest = fingerprint(reorder_payload(req.audit_id, constraints))

    existing = reorder_store.get(req.reorder_id)
    if existing is not None:
        if existing.digest == digest:
            return JSONResponse(status_code=200, content=existing.response())
        raise HTTPException(
            status_code=409, detail=_reorder_conflict_detail(req.reorder_id)
        )

    try:
        rules = [Rule.model_validate(rule) for rule in audit.rules]
        result = compute_reorder(rules, constraints)
    except ReorderError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "error": exc.code,
                "message": exc.message,
                "issues": exc.details,
                "reorder_id": req.reorder_id,
            },
        ) from exc

    record = new_reorder_record(
        req.reorder_id, req.audit_id, constraints, result
    )
    winner = reorder_store.put_if_absent(record)
    if winner.digest != digest:
        raise HTTPException(
            status_code=409, detail=_reorder_conflict_detail(req.reorder_id)
        )
    status_code = 201 if winner is record else 200
    return JSONResponse(status_code=status_code, content=winner.response())


@app.get("/api/reorders/{reorder_id}")
def get_reorder(reorder_id: str):
    """Re-open a frozen reorder conclusion by its stable identifier."""
    record = reorder_store.get(reorder_id)
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
            f"重排序标识 {reorder_id!r} 已存在，但来源审计或优先约束不同；"
            "既有重排结论已冻结，拒绝改写。"
        ),
        "reorder_id": reorder_id,
    }
