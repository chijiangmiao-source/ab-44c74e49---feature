"""API tests for frozen stable reordering."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def fresh(prefix: str) -> str:
    return f"{prefix}-" + uuid.uuid4().hex[:10]


def nested_rules(audit_id, n=3):
    return {
        "audit_id": audit_id,
        "rules": [
            {
                "id": f"r{i+1}",
                "protocol": "tcp",
                "src_cidr": "10.0.0.0/24",
                "dst_cidr": "192.168.0.0/24",
                "src_port": {"start": 0, "end": 65535},
                "dst_port": {"start": 0, "end": 1000 - i * 50},
            }
            for i in range(n)
        ],
    }


def create_audit(payload):
    resp = client.post("/api/audits", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


class TestReorderLifecycle:
    def test_feasible_reorder_frozen_and_retrievable(self):
        audit_id = fresh("aud")
        create_audit(nested_rules(audit_id))
        reorder_id = fresh("reo")
        resp = client.post(
            f"/api/audits/{audit_id}/reorders",
            json={"reorder_id": reorder_id, "constraints": []},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["feasible"] is True
        assert body["order"] == ["r3", "r2", "r1"]
        assert body["inversions"] == 3
        assert body["audit_id"] == audit_id
        assert [w["rule_id"] for w in body["witnesses"]] == ["r3", "r2", "r1"]
        assert [w["rank"] for w in body["witnesses"]] == [1, 2, 3]
        ports = [w["witness"]["dst_port"] for w in body["witnesses"]]
        assert ports == [0, 901, 951]

        got = client.get(f"/api/reorders/{reorder_id}")
        assert got.status_code == 200
        assert got.json() == body

    def test_idempotent_replay_same_constraints(self):
        audit_id = fresh("aud")
        create_audit(nested_rules(audit_id))
        reorder_id = fresh("reo")
        body = {"reorder_id": reorder_id, "constraints": [{"before": "r3", "after": "r1"}]}
        first = client.post(f"/api/audits/{audit_id}/reorders", json=body)
        assert first.status_code == 201
        # Same payload, different serialization/order of duplicated pairs.
        replay_body = {
            "reorder_id": reorder_id,
            "constraints": [
                {"after": "r1", "before": "r3"},
                {"before": "r3", "after": "r1"},
            ],
        }
        replay = client.post(f"/api/audits/{audit_id}/reorders", json=replay_body)
        assert replay.status_code == 200
        assert replay.json() == first.json()

    def test_reorder_constraints_are_returned_and_normalized(self):
        audit_id = fresh("aud")
        create_audit(nested_rules(audit_id))
        reorder_id = fresh("reo")
        resp = client.post(
            f"/api/audits/{audit_id}/reorders",
            json={
                "reorder_id": reorder_id,
                "constraints": [
                    {"before": "r3", "after": "r1"},
                    {"before": "r3", "after": "r1"},
                ],
            },
        )
        assert resp.status_code == 201
        assert resp.json()["constraints"] == [{"before": "r3", "after": "r1"}]

    def test_unknown_reorder_id_404(self):
        resp = client.get("/api/reorders/" + fresh("missing"))
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "reorder_not_found"


class TestReorderConflicts:
    def test_source_audit_missing_404(self):
        resp = client.post(
            f"/api/audits/{fresh('nope')}/reorders",
            json={"reorder_id": fresh("reo"), "constraints": []},
        )
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "audit_not_found"

    def test_same_reorder_id_other_source_audit_rejected(self):
        a1, a2 = fresh("aud"), fresh("aud")
        create_audit(nested_rules(a1))
        create_audit(nested_rules(a2))
        reorder_id = fresh("reo")
        first = client.post(
            f"/api/audits/{a1}/reorders",
            json={"reorder_id": reorder_id, "constraints": []},
        )
        assert first.status_code == 201
        conflict = client.post(
            f"/api/audits/{a2}/reorders",
            json={"reorder_id": reorder_id, "constraints": []},
        )
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["error"] == "reorder_id_conflict"
        # Original reorder conclusion is untouched.
        frozen = client.get(f"/api/reorders/{reorder_id}").json()
        assert frozen["audit_id"] == a1

    def test_same_reorder_id_changed_constraints_rejected(self):
        audit_id = fresh("aud")
        create_audit(nested_rules(audit_id))
        reorder_id = fresh("reo")
        client.post(
            f"/api/audits/{audit_id}/reorders",
            json={
                "reorder_id": reorder_id,
                "constraints": [{"before": "r3", "after": "r1"}],
            },
        )
        conflict = client.post(
            f"/api/audits/{audit_id}/reorders",
            json={
                "reorder_id": reorder_id,
                "constraints": [{"before": "r3", "after": "r2"}],
            },
        )
        assert conflict.status_code == 409
        frozen = client.get(f"/api/reorders/{reorder_id}").json()
        assert frozen["constraints"] == [{"before": "r3", "after": "r1"}]


class TestReorderValidation:
    def test_dangling_constraint_rejected_422(self):
        audit_id = fresh("aud")
        create_audit(nested_rules(audit_id))
        resp = client.post(
            f"/api/audits/{audit_id}/reorders",
            json={
                "reorder_id": fresh("reo"),
                "constraints": [{"before": "r1", "after": "r9"}],
            },
        )
        assert resp.status_code == 422
        assert resp.json()["detail"]["error"] == "invalid_precedence_constraint"

    def test_self_loop_rejected_422(self):
        audit_id = fresh("aud")
        create_audit(nested_rules(audit_id))
        resp = client.post(
            f"/api/audits/{audit_id}/reorders",
            json={
                "reorder_id": fresh("reo"),
                "constraints": [{"before": "r1", "after": "r1"}],
            },
        )
        assert resp.status_code == 422

    def test_cycle_rejected_422_and_frozen_as_nothing(self):
        audit_id = fresh("aud")
        create_audit(nested_rules(audit_id))
        reorder_id = fresh("reo")
        resp = client.post(
            f"/api/audits/{audit_id}/reorders",
            json={
                "reorder_id": reorder_id,
                "constraints": [
                    {"before": "r1", "after": "r2"},
                    {"before": "r2", "after": "r1"},
                ],
            },
        )
        assert resp.status_code == 422
        assert resp.json()["detail"]["error"] == "cyclic_precedence_constraint"
        assert client.get(f"/api/reorders/{reorder_id}").status_code == 404

    def test_source_audit_over_rule_limit_rejected_422(self):
        audit_id = fresh("aud-big")
        payload = nested_rules(audit_id, n=13)
        create_audit(payload)  # the audit itself (max 18) freezes fine
        resp = client.post(
            f"/api/audits/{audit_id}/reorders",
            json={"reorder_id": fresh("reo"), "constraints": []},
        )
        assert resp.status_code == 422
        assert resp.json()["detail"]["error"] == "reorder_rules_out_of_range"

    def test_rejected_reorder_leaves_no_record(self):
        audit_id = fresh("aud")
        create_audit(nested_rules(audit_id))
        reorder_id = fresh("reo")
        resp = client.post(
            f"/api/audits/{audit_id}/reorders",
            json={
                "reorder_id": reorder_id,
                "constraints": [{"before": "r1", "after": "nope"}],
            },
        )
        assert resp.status_code == 422
        assert client.get(f"/api/reorders/{reorder_id}").status_code == 404

    def test_invalid_reorder_id_shape_422(self):
        audit_id = fresh("aud")
        create_audit(nested_rules(audit_id))
        resp = client.post(
            f"/api/audits/{audit_id}/reorders",
            json={"reorder_id": "-bad", "constraints": []},
        )
        assert resp.status_code == 422


class TestInfeasibleConclusion:
    def test_region_infeasibility_is_frozen_conclusion_not_error(self):
        audit_id = fresh("aud")
        create_audit(nested_rules(audit_id))
        reorder_id = fresh("reo")
        resp = client.post(
            f"/api/audits/{audit_id}/reorders",
            json={
                "reorder_id": reorder_id,
                "constraints": [{"before": "r1", "after": "r2"}],
            },
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["feasible"] is False
        assert "order" not in body
        assert body["dead_end"]["blocked"]
        # Stable: replay returns the identical infeasible conclusion.
        replay = client.post(
            f"/api/audits/{audit_id}/reorders",
            json={
                "reorder_id": reorder_id,
                "constraints": [{"before": "r1", "after": "r2"}],
            },
        )
        assert replay.status_code == 200
        assert replay.json() == body


class TestSourceAuditUntouched:
    def test_reorder_does_not_change_frozen_audit(self):
        audit_id = fresh("aud")
        audit_body = create_audit(nested_rules(audit_id))
        client.post(
            f"/api/audits/{audit_id}/reorders",
            json={"reorder_id": fresh("reo"), "constraints": []},
        )
        again = client.get(f"/api/audits/{audit_id}")
        assert again.status_code == 200
        assert again.json() == audit_body
        # Original shadow verdicts keep their meaning and order.
        statuses = [v["status"] for v in again.json()["verdicts"]]
        assert statuses == ["hit", "shadowed", "shadowed"]
