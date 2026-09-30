"""One-shot verification gate.

Runs, in order:
  1. build check   — byte-compile every shipped Python module
  2. code tests    — the pytest suite (region algebra, engine, API)
  3. HTTP smoke    — against the live service: one partially shadowed rule,
                     one fully shadowed rule, and an illegal retransmission
                     (same audit id, different payload)

Exits 0 only if every step passes; the Compose ``verify`` service surfaces
this as its container exit code.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_URL = os.environ.get("APP_URL", "http://127.0.0.1:8080").rstrip("/")


def log(msg: str) -> None:
    print(msg, flush=True)


def sh(cmd: list[str]) -> bool:
    log(f"\n$ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=ROOT).returncode == 0


def build_check() -> bool:
    return sh([sys.executable, "-m", "compileall", "-q", "app", "verify", "tests"])


def code_tests() -> bool:
    return sh([sys.executable, "-m", "pytest", "-q", "tests"])


def http(method: str, path: str, body=None):
    """JSON request; returns (status, parsed_body_or_text)."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        APP_URL + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, raw
    try:
        return resp.status, json.loads(raw)
    except json.JSONDecodeError:
        return resp.status, raw


def wait_ready(timeout: float = 90.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, body = http("GET", "/healthz")
            if status == 200 and isinstance(body, dict) and body.get("status") == "ok":
                return True
        except Exception:
            pass
        time.sleep(1.0)
    return False


def smoke() -> None:
    assert wait_ready(), f"服务在 {APP_URL} 上未通过健康检查"

    audit_id = f"smoke-{int(time.time())}"
    rules = [
        # r1: baseline rule.
        {"id": "r1", "protocol": "tcp",
         "src_cidr": "10.0.0.0/24", "dst_cidr": "192.168.0.0/24",
         "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 80, "end": 85}},
        # r2: partially shadowed by r1 — only dst ports 86..90 remain.
        {"id": "r2", "protocol": "tcp",
         "src_cidr": "10.0.0.128/25", "dst_cidr": "192.168.0.0/25",
         "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 80, "end": 90}},
        # r3: fully contained in r1 — never matches any packet.
        {"id": "r3", "protocol": "tcp",
         "src_cidr": "10.0.0.0/25", "dst_cidr": "192.168.0.0/25",
         "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 82, "end": 84}},
    ]

    status, body = http("POST", "/api/audits", {"audit_id": audit_id, "rules": rules})
    assert status == 201, f"创建审计失败: HTTP {status} {body}"
    verdicts = {v["rule_id"]: v for v in body["verdicts"]}

    v1 = verdicts["r1"]
    assert v1["status"] == "hit" and v1["witness"] == {
        "protocol": "tcp", "src_ip": "10.0.0.0", "dst_ip": "192.168.0.0",
        "src_port": 0, "dst_port": 80,
    }, f"r1 结论错误: {v1}"

    v2 = verdicts["r2"]
    assert v2["status"] == "hit" and v2["witness"] == {
        "protocol": "tcp", "src_ip": "10.0.0.128", "dst_ip": "192.168.0.0",
        "src_port": 0, "dst_port": 86,
    }, f"部分遮蔽的 r2 结论或最小见证错误: {v2}"

    v3 = verdicts["r3"]
    assert v3["status"] == "shadowed" and v3["covered_by"] == ["r1"], (
        f"完全遮蔽的 r3 结论或覆盖集合错误: {v3}"
    )
    log("  ✓ 部分遮蔽 / 完全遮蔽裁决与最小见证正确")

    # Frozen conclusions are retrievable by audit id.
    status, again = http("GET", f"/api/audits/{audit_id}")
    assert status == 200 and again["verdicts"] == body["verdicts"], (
        "按审计标识复查到的结论与提交时不一致"
    )

    # Idempotent replay of the identical payload.
    status, replay = http("POST", "/api/audits", {"audit_id": audit_id, "rules": rules})
    assert status == 200 and replay["verdicts"] == body["verdicts"], (
        f"相同载荷的幂等重放失败: HTTP {status}"
    )

    # Illegal retransmission: same audit id, different payload -> 409,
    # and the stored conclusions must stay untouched.
    tampered = json.loads(json.dumps({"audit_id": audit_id, "rules": rules}))
    tampered["rules"][1]["dst_port"]["end"] = 91
    status, conflict = http("POST", "/api/audits", tampered)
    assert status == 409, f"非法重传未被拒绝: HTTP {status} {conflict}"
    status, after = http("GET", f"/api/audits/{audit_id}")
    assert status == 200 and after["verdicts"] == body["verdicts"], (
        "非法重传改写了既有冻结结论"
    )
    log("  ✓ 非法重传被拒绝（409）且既有结论未被改写")

    # Invalid CIDR must be rejected and must not create a record.
    bad_id = audit_id + "-bad"
    bad = {"audit_id": bad_id, "rules": [dict(rules[0], src_cidr="10.0.0.0/33")]}
    status, _ = http("POST", "/api/audits", bad)
    assert status == 422, f"非法 CIDR 未被拒绝: HTTP {status}"
    status, _ = http("GET", f"/api/audits/{bad_id}")
    assert status == 404, "被拒绝的请求不应留下审计记录"
    log("  ✓ 非法 CIDR 被拒绝（422）且未留下记录")

    # The page is served.
    status, page = http("GET", "/")
    assert status == 200 and "规则隔离审计" in page, "页面不可用"
    log("  ✓ 页面与健康端点可用")


def reorder_smoke() -> None:
    """Stable reordering acceptance scenarios against the live service."""
    assert wait_ready(), f"服务在 {APP_URL} 上未通过健康检查"
    stamp = int(time.time())

    # Source audit: three rules where the original order shadows one.
    #   r1 = tcp ...:80-90, r2 = udp ...:80-90, r3 = both ...:80-85
    # In the frozen audit r3 is fully shadowed (r1 takes TCP, r2 takes UDP);
    # only a reordered sequence makes every rule first-hit some packet.
    audit_id = f"reorder-audit-{stamp}"
    rules = [
        {"id": "r1", "protocol": "tcp",
         "src_cidr": "10.0.0.0/24", "dst_cidr": "192.168.0.0/24",
         "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 80, "end": 90}},
        {"id": "r2", "protocol": "udp",
         "src_cidr": "10.0.0.0/24", "dst_cidr": "192.168.0.0/24",
         "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 80, "end": 90}},
        {"id": "r3", "protocol": "both",
         "src_cidr": "10.0.0.0/24", "dst_cidr": "192.168.0.0/24",
         "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 80, "end": 85}},
    ]
    status, body = http("POST", "/api/audits", {"audit_id": audit_id, "rules": rules})
    assert status == 201, f"来源审计创建失败: HTTP {status} {body}"
    original_verdicts = body["verdicts"]
    assert {v["rule_id"]: v["status"] for v in original_verdicts} == {
        "r1": "hit", "r2": "hit", "r3": "shadowed",
    }, "来源审计的原顺序中 r3 应被完全遮蔽"

    def submit(rid, constraints, ok=(200, 201)):
        st, bd = http(
            "POST",
            "/api/reorders",
            {"reorder_id": rid, "audit_id": audit_id, "constraints": constraints},
        )
        assert st in ok, f"重排序提交异常: HTTP {st} {bd}"
        return st, bd

    # --- 1. group that needs a reorder to make all rules reachable --------
    rid1 = f"reorder-{stamp}-a"
    status, first = submit(rid1, [])
    assert status == 201
    result = first["result"]
    assert result["status"] == "feasible", result
    assert result["order"] == ["r1", "r3", "r2"], result["order"]
    assert result["inversions"] == 1
    assert [e["rule_id"] for e in result["ordered_witnesses"]] == result["order"]

    # Recompute every witness's first-match space from the frozen rules:
    # the reported packet must be the exact lexicographic minimum of
    # rule_region - union(earlier new-order rule regions), in five dims.
    import ipaddress as _ip

    from app.engine import box_of, witness_dict
    from app.region import min_point, subtract_region
    from app.schemas import Rule

    models = [Rule.model_validate(r) for r in rules]
    box_by_id = {r.id: box_of(r) for r in models}
    union: list = []
    for entry in result["ordered_witnesses"]:
        box = box_by_id[entry["rule_id"]]
        remainder = [box]
        for covered in union:
            remainder = subtract_region(remainder, covered)
        expected = witness_dict(min_point(remainder))
        assert entry["witness"] == expected, (entry, expected)
        # Guard: recomputed packet really lies outside earlier rules.
        point = (
            {"tcp": 0, "udp": 1}[expected["protocol"]],
            int(_ip.IPv4Address(expected["src_ip"])),
            int(_ip.IPv4Address(expected["dst_ip"])),
            expected["src_port"],
            expected["dst_port"],
        )
        for covered in union:
            assert not all(
                covered[d][0] <= point[d] <= covered[d][1] for d in range(5)
            ), f"见证 {entry['rule_id']} 落在更早规则区域内"
        new_pieces = [box]
        for covered in union:
            new_pieces = subtract_region(new_pieces, covered)
        union.extend(new_pieces)
    log("  ✓ 需调整顺序才全部可达的规则组：逆序对最少，逐规则最小见证可精确复算")

    # Frozen conclusion re-opens by its stable identifier.
    status, reopened = http("GET", f"/api/reorders/{rid1}")
    assert status == 200 and reopened == first, "重排结论无法按标识原样重开"

    # Idempotent replay under the same identifier.
    status, replay = submit(rid1, [])
    assert status == 200 and replay == first

    # --- 2. equal-cost tie broken by the complete rule-id sequence --------
    # Geometry: r1 = tcp:80-90, r2 = udp:80-90, r3 = tcp:80-85 (subset of r1).
    # The two optimum orders (r2,r3,r1) and (r3,r1,r2) both cost 2
    # inversions; id-order comparison must deterministically pick r2 first.
    tie_audit = f"reorder-tie-{stamp}"
    tie_rules = [
        dict(rules[0]),
        dict(rules[1]),
        {**rules[2], "id": "r3", "protocol": "tcp"},
    ]
    status, tie_body = http(
        "POST", "/api/audits", {"audit_id": tie_audit, "rules": tie_rules}
    )
    assert status == 201, tie_body
    rid2 = f"reorder-{stamp}-b"
    st2, tie = http(
        "POST",
        "/api/reorders",
        {"reorder_id": rid2, "audit_id": tie_audit, "constraints": []},
    )
    assert st2 == 201, tie
    assert tie["result"]["status"] == "feasible"
    assert tie["result"]["inversions"] == 2, tie["result"]
    assert tie["result"]["order"] == ["r2", "r3", "r1"], tie["result"]["order"]
    log("  ✓ 同成本顺序裁决：逆序对相同则按规则标识序比较完整顺序")

    # --- 3. infeasible constraints return a stable infeasible conclusion ---
    rid3 = f"reorder-{stamp}-c"
    st3, infeasible = http(
        "POST",
        "/api/reorders",
        {"reorder_id": rid3, "audit_id": audit_id,
         "constraints": [{"before": "r1", "after": "r3"},
                         {"before": "r2", "after": "r3"}]},
    )
    assert st3 == 201, (st3, infeasible)
    assert infeasible["result"]["status"] == "infeasible", infeasible["result"]
    blocked = {b["rule_id"]: b for b in infeasible["result"]["blocked_rules"]}
    assert "r3" in blocked
    assert blocked["r3"]["reason"] == "region_covered"
    # Infeasible is itself a frozen, stable conclusion.
    st3b, replay_inf = http(
        "POST",
        "/api/reorders",
        {"reorder_id": rid3, "audit_id": audit_id,
         "constraints": [{"before": "r1", "after": "r3"},
                         {"before": "r2", "after": "r3"}]},
    )
    assert st3b == 200 and replay_inf == infeasible
    log("  ✓ 不可行约束：稳定返回不可行结论并可按标识重开")

    # Dangling / cyclic constraints are rejected without a record.
    st4, bad = http(
        "POST",
        "/api/reorders",
        {"reorder_id": f"reorder-{stamp}-d", "audit_id": audit_id,
         "constraints": [{"before": "r1", "after": "ghost"}]},
    )
    assert st4 == 422 and bad["detail"]["error"] == "invalid_constraints", (st4, bad)
    st5, cyc = http(
        "POST",
        "/api/reorders",
        {"reorder_id": f"reorder-{stamp}-e", "audit_id": audit_id,
         "constraints": [{"before": "r1", "after": "r2"},
                         {"before": "r2", "after": "r3"},
                         {"before": "r3", "after": "r1"}]},
    )
    assert st5 == 422 and cyc["detail"]["error"] == "cyclic_constraints", (st5, cyc)
    st_unknown, _ = http(
        "POST",
        "/api/reorders",
        {"reorder_id": f"reorder-{stamp}-f", "audit_id": f"missing-{stamp}",
         "constraints": []},
    )
    assert st_unknown == 404
    log("  ✓ 悬空约束、循环约束、来源不存在均被拒绝且不留痕")

    # --- 4. conflicting retransmission rejected, first conclusion kept -----
    st6, conflict = http(
        "POST",
        "/api/reorders",
        {"reorder_id": rid1, "audit_id": audit_id,
         "constraints": [{"before": "r1", "after": "r3"}]},
    )
    assert st6 == 409 and conflict["detail"]["error"] == "reorder_id_conflict", (
        st6, conflict
    )
    st6b, kept = http("GET", f"/api/reorders/{rid1}")
    assert st6b == 200 and kept == first, "冲突重传改写了既有重排结论"

    # Switching the source audit under the same identifier is also a conflict.
    st7, src_conflict = http(
        "POST",
        "/api/reorders",
        {"reorder_id": rid1, "audit_id": tie_audit, "constraints": []},
    )
    assert st7 == 409 and src_conflict["detail"]["error"] == "reorder_id_conflict"
    st7b, kept2 = http("GET", f"/api/reorders/{rid1}")
    assert kept2 == first
    log("  ✓ 冲突重传（改换约束/改换来源）返回 409 且不改写冻结结论")

    # --- 5. pre-existing audits, shadow verdicts and reviews unchanged -----
    status, audit_after = http("GET", f"/api/audits/{audit_id}")
    assert status == 200
    assert audit_after["verdicts"] == original_verdicts, "旧审计结论被重排序改动"
    assert {v["rule_id"]: v["status"] for v in audit_after["verdicts"]} == {
        "r1": "hit", "r2": "hit", "r3": "shadowed",
    }
    log("  ✓ 已有审计提交、遮蔽裁决与复查行为保持不变")


def main() -> int:
    results: list[tuple[str, bool]] = []
    results.append(("构建检查 (compileall)", build_check()))
    results.append(("代码测试 (pytest)", code_tests()))
    try:
        smoke()
        results.append(("HTTP 冒烟（审计）", True))
    except Exception as exc:  # noqa: BLE001 - report any smoke failure
        log(f"  ✗ HTTP 冒烟失败: {exc}")
        results.append(("HTTP 冒烟（审计）", False))
    try:
        reorder_smoke()
        results.append(("HTTP 冒烟（稳定重排序）", True))
    except Exception as exc:  # noqa: BLE001 - report any smoke failure
        log(f"  ✗ 重排序冒烟失败: {exc}")
        results.append(("HTTP 冒烟（稳定重排序）", False))

    log("\n================ 验证结果 ================")
    for name, ok in results:
        log(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    ok = all(ok for _, ok in results)
    log(f"  总体: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
