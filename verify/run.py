"""One-shot verification gate.

Runs, in order:
  1. build check   — byte-compile every shipped Python module
  2. code tests    — the pytest suite (region algebra, engine, API,
                     reorder planner and reorder lifecycle)
  3. HTTP smoke    — against the live service: shadow analysis, illegal
                     retransmission and validation rejections
  4. reorder smoke — required swaps for full reachability, equal-cost
                     tie-breaking, infeasible and cyclic/dangling
                     constraints, conflicting retransmissions, and the
                     guarantee that frozen audits never change

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
    """Stable reordering: required swap, equal-cost tie-break,
    infeasible constraints, conflicting retransmission, and the proof
    that the source audit's frozen conclusions stay untouched.
    """
    # Rules whose original order shadows everything after the broad one;
    # only the reverse order lets all three keep first-match space.
    audit_id = f"smoke-reorder-{int(time.time())}"
    rules = [
        {"id": "r1", "protocol": "tcp",
         "src_cidr": "10.0.0.0/24", "dst_cidr": "192.168.0.0/24",
         "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 0, "end": 300}},
        {"id": "r2", "protocol": "tcp",
         "src_cidr": "10.0.0.0/24", "dst_cidr": "192.168.0.0/24",
         "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 0, "end": 200}},
        {"id": "r3", "protocol": "tcp",
         "src_cidr": "10.0.0.0/24", "dst_cidr": "192.168.0.0/24",
         "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 0, "end": 100}},
    ]
    status, body = http("POST", "/api/audits", {"audit_id": audit_id, "rules": rules})
    assert status == 201, f"重排来源审计创建失败: HTTP {status} {body}"
    original_verdicts = body["verdicts"]
    assert [v["status"] for v in original_verdicts] == ["hit", "shadowed", "shadowed"]
    base = f"/api/audits/{audit_id}/reorders"

    # 1) A reorder is required to make every rule reachable.
    rid1 = audit_id + "-a"
    status, res = http("POST", base, {"reorder_id": rid1, "constraints": []})
    assert status == 201, f"重排序提交失败: HTTP {status} {res}"
    assert res["feasible"] is True, f"应存在可行顺序: {res}"
    assert res["order"] == ["r3", "r2", "r1"], res["order"]
    assert res["inversions"] == 3, res["inversions"]
    ports = [w["witness"]["dst_port"] for w in res["witnesses"]]
    assert ports == [0, 101, 201], ports
    # Every witness packet must be outside earlier rules' boxes.
    for i, w in enumerate(res["witnesses"]):
        assert w["rank"] == i + 1 and w["rule_id"] == res["order"][i]
    log("  ✓ 需调整顺序才全部可达：最优顺序与逐规则最小见证正确")

    # Frozen reorder conclusion is retrievable by reorder id.
    status, again = http("GET", f"/api/reorders/{rid1}")
    assert status == 200 and again == res, "重排序结论复查不一致"

    # Idempotent replay of the identical body.
    status, replay = http("POST", base, {"reorder_id": rid1, "constraints": []})
    assert status == 200 and replay == res, f"幂等重放失败: HTTP {status}"

    # Same id with changed constraints is a conflicting retransmission.
    status, changed = http("POST", base, {
        "reorder_id": rid1,
        "constraints": [{"before": "r3", "after": "r1"}],
    })
    assert status == 409, f"同标识改换约束必须 409，实际 HTTP {status}"
    status, kept = http("GET", f"/api/reorders/{rid1}")
    assert kept["constraints"] == [], "冲突重传改写了既有约束集合"
    log("  ✓ 同一重排序标识改换约束被拒绝（409）且结论未改写")

    # 2) Equal-cost tie-break on DISJOINT rules (every permutation is
    # reachable): r3 before r1 forces at least 2 inversions, and both
    # [r2,r3,r1] (1,2,0) and [r3,r1,r2] (2,0,1) cost 2.  The complete
    # order that is lexicographically smaller by rule id must win.
    tie_audit = audit_id + "-tie"
    disjoint = [
        dict(rules[0], dst_port={"start": 40, "end": 49}),
        dict(rules[1], dst_port={"start": 20, "end": 29}),
        dict(rules[2], dst_port={"start": 0, "end": 9}),
    ]
    status, tie_body = http("POST", "/api/audits", {"audit_id": tie_audit, "rules": disjoint})
    assert status == 201, f"同成本来源审计创建失败: HTTP {status}"
    rid2 = tie_audit + "-b"
    # Duplicate pair supplied twice: normalization makes the replay equal.
    status, tie = http("POST", f"/api/audits/{tie_audit}/reorders", {
        "reorder_id": rid2,
        "constraints": [
            {"before": "r3", "after": "r1"},
            {"after": "r1", "before": "r3"},
        ],
    })
    assert status == 201 and tie["feasible"] is True, f"同成本裁决请求失败: {tie}"
    assert tie["inversions"] == 2 and tie["order"] == ["r2", "r3", "r1"], (
        f"同成本顺序裁决错误: inv={tie.get('inversions')} order={tie.get('order')}"
    )
    assert tie["constraints"] == [{"before": "r3", "after": "r1"}]
    tie_ports = [w["witness"]["dst_port"] for w in tie["witnesses"]]
    assert tie_ports == [20, 0, 40], tie_ports
    status, tie_replay = http("POST", f"/api/audits/{tie_audit}/reorders", {
        "reorder_id": rid2,
        "constraints": [{"before": "r3", "after": "r1"}],
    })
    assert status == 200 and tie_replay == tie, "同成本结论幂等重放失败"
    log("  ✓ 同逆序对成本时按规则标识序裁决完整顺序")

    # 3) Infeasible constraint (broad r1 must precede r2) is a stable
    # frozen *conclusion* (201, feasible=false), not a validation error.
    rid3 = audit_id + "-c"
    status, bad = http("POST", base, {
        "reorder_id": rid3,
        "constraints": [{"before": "r1", "after": "r2"}],
    })
    assert status == 201 and bad["feasible"] is False, (
        f"区域不可行应为冻结的不可行结论: HTTP {status} {bad}"
    )
    blocked = {b["rule_id"]: b["reason"] for b in bad["dead_end"]["blocked"]}
    assert "r2" in blocked, bad["dead_end"]
    status, bad_replay = http("POST", base, {
        "reorder_id": rid3,
        "constraints": [{"before": "r1", "after": "r2"}],
    })
    assert status == 200 and bad_replay == bad, "不可行结论重放不稳定"
    log("  ✓ 不可行约束稳定冻结为 feasible=false 且可幂等重放")

    # 4) Cyclic and dangling constraints are 422 rejections with no trace.
    status, cyc = http("POST", base, {
        "reorder_id": audit_id + "-cyc",
        "constraints": [{"before": "r1", "after": "r2"}, {"before": "r2", "after": "r1"}],
    })
    assert status == 422, f"循环约束应 422，实际 {status}: {cyc}"
    status, dangling = http("POST", base, {
        "reorder_id": audit_id + "-dangling",
        "constraints": [{"before": "r1", "after": "rx"}],
    })
    assert status == 422, f"悬空约束应 422，实际 {status}: {dangling}"
    status, _ = http("GET", f"/api/reorders/{audit_id}-cyc")
    assert status == 404, "循环约束拒绝后不得留下记录"
    log("  ✓ 循环与悬空约束被拒绝（422）且不留痕")

    # 5) Same reorder id bound to another source audit -> 409.
    other_audit = audit_id + "-other"
    status, _ = http("POST", "/api/audits", {"audit_id": other_audit, "rules": rules})
    assert status == 201
    status, other_conflict = http(
        "POST", f"/api/audits/{other_audit}/reorders",
        {"reorder_id": rid1, "constraints": []},
    )
    assert status == 409, f"同标识改换来源应 409，实际 {status}"
    status, kept = http("GET", f"/api/reorders/{rid1}")
    assert kept["audit_id"] == audit_id, "冲突重传改换了重排结论的来源"
    log("  ✓ 同一重排序标识改换来源审计被拒绝（409）且来源绑定不变")

    # Unknown source audit and unknown reorder id are 404.
    status, _ = http("POST", f"/api/audits/{audit_id}-missing/reorders",
                     {"reorder_id": "x", "constraints": []})
    assert status == 404
    status, _ = http("GET", "/api/reorders/" + audit_id + "-nope")
    assert status == 404

    # 6) The source audit's frozen conclusions are provably unchanged.
    status, source = http("GET", f"/api/audits/{audit_id}")
    assert status == 200 and source["verdicts"] == original_verdicts, (
        "重排序行为改写了既有冻结审计结论"
    )
    log("  ✓ 既有审计提交、遮蔽裁决与复查结论保持不变")


def main() -> int:
    results: list[tuple[str, bool]] = []
    results.append(("构建检查 (compileall)", build_check()))
    results.append(("代码测试 (pytest)", code_tests()))
    try:
        smoke()
        results.append(("HTTP 冒烟", True))
    except Exception as exc:  # noqa: BLE001 - report any smoke failure
        log(f"  ✗ HTTP 冒烟失败: {exc}")
        results.append(("HTTP 冒烟", False))
    try:
        reorder_smoke()
        results.append(("重排序 HTTP 冒烟", True))
    except Exception as exc:  # noqa: BLE001 - report any smoke failure
        log(f"  ✗ 重排序 HTTP 冒烟失败: {exc}")
        results.append(("重排序 HTTP 冒烟", False))

    log("\n================ 验证结果 ================")
    for name, ok in results:
        log(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    ok = all(ok for _, ok in results)
    log(f"  总体: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
