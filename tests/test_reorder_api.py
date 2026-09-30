"""API tests for stable rule reordering against frozen audits."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def fresh(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def make_audit(audit_id, dp2_end=90):
    """Three TCP rules: r3 is fully shadowed by r1 in the original order."""
    return {
        "audit_id": audit_id,
        "rules": [
            {
                "id": "r1",
                "protocol": "tcp",
                "src_cidr": "10.0.0.0/24",
                "dst_cidr": "192.168.0.0/24",
                "src_port": {"start": 0, "end": 65535},
                "dst_port": {"start": 80, "end": 85},
            },
            {
                "id": "r2",
                "protocol": "tcp",
                "src_cidr": "10.0.0.128/25",
                "dst_cidr": "192.168.0.0/25",
                "src_port": {"start": 0, "end": 65535},
                "dst_port": {"start": 80, "end": dp2_end},
            },
            {
                "id": "r3",
                "protocol": "tcp",
                "src_cidr": "10.0.0.0/25",
                "dst_cidr": "192.168.0.0/25",
                "src_port": {"start": 0, "end": 65535},
                "dst_port": {"start": 82, "end": 84},
            },
        ],
    }


def create_audit(payload):
    resp = client.post("/api/audits", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


def post_reorder(reorder_id, audit_id, constraints):
    return client.post(
        "/api/reorders",
        json={
            "reorder_id": reorder_id,
            "audit_id": audit_id,
            "constraints": constraints,
        },
    )


class TestFeasibleReorder:
    def test_group_that_needs_reorder_becomes_all_reachable(self):
        audit_id = fresh("aud")
        audit = create_audit(make_audit(audit_id))
        # Original audit: r3 is shadowed.
        verdicts = {v["rule_id"]: v for v in audit["verdicts"]}
        assert verdicts["r3"]["status"] == "shadowed"

        reorder_id = fresh("reo")
        resp = post_reorder(reorder_id, audit_id, [])
        assert resp.status_code == 201, resp.text
        body = resp.json()
        result = body["result"]
        assert result["status"] == "feasible"
        # Tie at two inversions: (r2,r3,r1) beats (r3,r1,r2) by id order.
        assert result["order"] == ["r2", "r3", "r1"]
        assert result["inversions"] == 2
        witnesses = {w["rule_id"]: w for w in result["ordered_witnesses"]}
        # r3, disjoint from r2 in the source-address axis, first-hits at its
        # minimal corner once r2 is the only earlier rule.
        r3w = witnesses["r3"]["witness"]
        assert r3w["src_ip"] == "10.0.0.0"
        assert r3w["dst_ip"] == "192.168.0.0"
        assert (r3w["src_port"], r3w["dst_port"]) == (0, 82)
        assert [w["position"] for w in result["ordered_witnesses"]] == [1, 2, 3]

    def test_constraints_are_echoed_and_satisfied(self):
        audit_id = fresh("aud")
        create_audit(make_audit(audit_id))
        resp = post_reorder(
            fresh("reo"),
            audit_id,
            [{"before": "r3", "after": "r1"}],
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["constraints"] == [{"before": "r3", "after": "r1"}]
        order = body["result"]["order"]
        assert order.index("r3") < order.index("r1")

    def test_idempotent_replay_returns_200_and_same_body(self):
        audit_id = fresh("aud")
        create_audit(make_audit(audit_id))
        reorder_id = fresh("reo")
        first = post_reorder(reorder_id, audit_id, []).json()
        replay = post_reorder(reorder_id, audit_id, [])
        assert replay.status_code == 200
        assert replay.json() == first

    def test_reopen_by_identifier(self):
        audit_id = fresh("aud")
        create_audit(make_audit(audit_id))
        reorder_id = fresh("reo")
        created = post_reorder(reorder_id, audit_id, []).json()
        again = client.get(f"/api/reorders/{reorder_id}")
        assert again.status_code == 200
        assert again.json() == created

    def test_unknown_reorder_identifier_404(self):
        resp = client.get("/api/reorders/" + fresh("missing"))
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "reorder_not_found"


class TestInfeasibleReorder:
    def test_impossible_constraint_returns_stable_infeasible(self):
        audit_id = fresh("aud")
        create_audit(make_audit(audit_id))
        reorder_id = fresh("reo")
        # Forcing r1 (which contains r3) before r3 leaves r3 no first hit.
        resp = post_reorder(reorder_id, audit_id, [{"before": "r1", "after": "r3"}])
        assert resp.status_code == 201, resp.text
        result = resp.json()["result"]
        assert result["status"] == "infeasible"
        assert result["reachable_count"] < result["total_rules"]
        blocked = {b["rule_id"]: b for b in result["blocked_rules"]}
        assert "r3" in blocked

        # Infeasible conclusions freeze just like feasible ones.
        again = post_reorder(reorder_id, audit_id, [{"before": "r1", "after": "r3"}])
        assert again.status_code == 200
        assert again.json()["result"] == result
        reopened = client.get(f"/api/reorders/{reorder_id}")
        assert reopened.status_code == 200
        assert reopened.json()["result"]["status"] == "infeasible"


class TestRejections:
    def test_unknown_source_audit_404_and_no_record(self):
        reorder_id = fresh("reo")
        missing = fresh("aud")
        resp = post_reorder(reorder_id, missing, [])
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "audit_not_found"
        assert client.get(f"/api/reorders/{reorder_id}").status_code == 404

    def test_dangling_constraint_422_and_no_record(self):
        audit_id = fresh("aud")
        create_audit(make_audit(audit_id))
        reorder_id = fresh("reo")
        resp = post_reorder(reorder_id, audit_id, [{"before": "r1", "after": "nope"}])
        assert resp.status_code == 422
        assert resp.json()["detail"]["error"] == "invalid_constraints"
        assert client.get(f"/api/reorders/{reorder_id}").status_code == 404

    def test_cyclic_constraints_422(self):
        audit_id = fresh("aud")
        create_audit(make_audit(audit_id))
        resp = post_reorder(
            fresh("reo"),
            audit_id,
            [
                {"before": "r1", "after": "r2"},
                {"before": "r2", "after": "r3"},
                {"before": "r3", "after": "r1"},
            ],
        )
        assert resp.status_code == 422
        assert resp.json()["detail"]["error"] == "cyclic_constraints"

    def test_self_loop_and_duplicate_pair_422(self):
        audit_id = fresh("aud")
        create_audit(make_audit(audit_id))
        resp = post_reorder(fresh("reo"), audit_id, [{"before": "r1", "after": "r1"}])
        assert resp.status_code == 422
        resp = post_reorder(
            fresh("reo"),
            audit_id,
            [
                {"before": "r1", "after": "r2"},
                {"before": "r1", "after": "r2"},
            ],
        )
        assert resp.status_code == 422

    def test_more_than_twelve_rules_422(self):
        audit_id = fresh("big-aud")
        payload = {
            "audit_id": audit_id,
            "rules": [
                {
                    "id": f"r{i}",
                    "protocol": "tcp",
                    "src_cidr": "10.0.0.0/24",
                    "dst_cidr": f"10.{i}.0.0/16",
                    "src_port": {"start": 0, "end": 65535},
                    "dst_port": {"start": 0, "end": 65535},
                }
                for i in range(13)
            ],
        }
        create_audit(payload)
        reorder_id = fresh("reo")
        resp = post_reorder(reorder_id, audit_id, [])
        assert resp.status_code == 422
        assert resp.json()["detail"]["error"] == "too_many_rules"
        assert client.get(f"/api/reorders/{reorder_id}").status_code == 404

    def test_bad_identifier_shapes_422(self):
        audit_id = fresh("aud")
        create_audit(make_audit(audit_id))
        for bad in ["", "has space", "-lead", "x" * 65]:
            resp = client.post(
                "/api/reorders",
                json={"reorder_id": bad, "audit_id": audit_id, "constraints": []},
            )
            assert resp.status_code == 422, bad

    def test_constraints_field_may_be_omitted(self):
        audit_id = fresh("aud")
        create_audit(make_audit(audit_id))
        resp = client.post(
            "/api/reorders",
            json={"reorder_id": fresh("reo"), "audit_id": audit_id},
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["constraints"] == []


class TestConflictRetransmission:
    def test_changed_constraints_conflict_keeps_first_conclusion(self):
        audit_id = fresh("aud")
        create_audit(make_audit(audit_id))
        reorder_id = fresh("reo")
        first = post_reorder(reorder_id, audit_id, []).json()
        assert first["result"]["status"] == "feasible"

        conflict = post_reorder(
            reorder_id, audit_id, [{"before": "r1", "after": "r3"}]
        )
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["error"] == "reorder_id_conflict"

        frozen = client.get(f"/api/reorders/{reorder_id}").json()
        assert frozen == first
        assert frozen["constraints"] == []

    def test_changed_source_audit_conflict_keeps_first_conclusion(self):
        audit_a = fresh("aud-a")
        audit_b = fresh("aud-b")
        create_audit(make_audit(audit_a))
        create_audit(make_audit(audit_b))
        reorder_id = fresh("reo")
        first = post_reorder(reorder_id, audit_a, []).json()

        conflict = post_reorder(reorder_id, audit_b, [])
        assert conflict.status_code == 409
        assert client.get(f"/api/reorders/{reorder_id}").json() == first

    def test_source_audit_conclusions_never_modified(self):
        audit_id = fresh("aud")
        original = make_audit(audit_id)
        audit = create_audit(original)
        post_reorder(fresh("reo"), audit_id, [{"before": "r1", "after": "r3"}])
        post_reorder(fresh("reo"), audit_id, [])
        after = client.get(f"/api/audits/{audit_id}")
        assert after.status_code == 200
        assert after.json() == audit
        assert after.json()["rules"] == original["rules"]
        still_shadowed = {
            v["rule_id"]: v["status"] for v in after.json()["verdicts"]
        }
        assert still_shadowed == {"r1": "hit", "r2": "hit", "r3": "shadowed"}
