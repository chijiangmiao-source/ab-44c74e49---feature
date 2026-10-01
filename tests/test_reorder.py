"""Tests for the stable reorder planner (exact 5-D reachability DP)."""

from __future__ import annotations

import itertools

import pytest

from app.engine import witness_dict
from app.reorder import (
    MAX_REORDER_RULES,
    ReorderError,
    constraint_cycle,
    normalize_constraints,
    plan_reorder,
)
from app.region import min_point, rule_box, subtract_region
from app.schemas import PortRange, Rule


def make_rule(
    rid,
    protocol="tcp",
    src="10.0.0.0/24",
    dst="192.168.0.0/24",
    sp=(0, 65535),
    dp=(0, 65535),
):
    return Rule(
        id=rid,
        protocol=protocol,
        src_cidr=src,
        dst_cidr=dst,
        src_port=PortRange(start=sp[0], end=sp[1]),
        dst_port=PortRange(start=dp[0], end=dp[1]),
    )


def box_of(rule):
    return rule_box(
        rule.protocol,
        rule.src_cidr,
        rule.dst_cidr,
        (rule.src_port.start, rule.src_port.end),
        (rule.dst_port.start, rule.dst_port.end),
    )


class TestReorderRequired:
    def test_nested_rules_need_reverse_order_to_all_reach(self):
        # Original order r1 (broad) -> r2 -> r3 (narrow) shadows r2/r3;
        # only the reverse order lets every rule keep first-match space.
        rules = [
            make_rule("r1", dp=(0, 200)),
            make_rule("r2", dp=(0, 150)),
            make_rule("r3", dp=(0, 100)),
        ]
        res = plan_reorder(rules, [])
        assert res["feasible"] is True
        assert res["order"] == ["r3", "r2", "r1"]
        # Reverse of a 3-rule order is 3 inversions.
        assert res["inversions"] == 3
        assert [w["rule_id"] for w in res["witnesses"]] == ["r3", "r2", "r1"]
        ports = [w["witness"]["dst_port"] for w in res["witnesses"]]
        assert ports == [0, 101, 151]

    def test_every_witness_is_in_rule_and_outside_all_earlier_boxes(self):
        import ipaddress

        from app.region import PROTOCOL_INTERVALS

        rules = [
            make_rule("r1", dp=(0, 200)),
            make_rule("r2", dp=(0, 150)),
            make_rule("r3", dp=(0, 100)),
        ]
        res = plan_reorder(rules, [])
        boxes = {rule.id: box_of(rule) for rule in rules}
        placed: list[tuple] = []
        for item in res["witnesses"]:
            w = item["witness"]
            point = (
                PROTOCOL_INTERVALS[w["protocol"]][0],
                int(ipaddress.IPv4Address(w["src_ip"])),
                int(ipaddress.IPv4Address(w["dst_ip"])),
                w["src_port"],
                w["dst_port"],
            )
            own = boxes[item["rule_id"]]
            assert all(own[d][0] <= point[d] <= own[d][1] for d in range(5))
            for prior in placed:
                assert not all(
                    prior[d][0] <= point[d] <= prior[d][1] for d in range(5)
                ), f"{item['rule_id']} 的见证被更早规则遮蔽"
            placed.append(own)

    def test_witness_is_lexicographic_minimum_of_first_match_space(self):
        # r2 placed first claims ports 0..100; r1 then keeps 101..200 and
        # its minimum witness packet is exactly port 101.
        rules = [make_rule("r1", dp=(0, 200)), make_rule("r2", dp=(0, 100))]
        res = plan_reorder(rules, [])
        assert res["order"] == ["r2", "r1"]
        by_id = {w["rule_id"]: w for w in res["witnesses"]}
        assert by_id["r2"]["witness"]["dst_port"] == 0
        assert by_id["r1"]["witness"]["dst_port"] == 101

    def test_original_order_kept_when_already_all_reaching(self):
        # Disjoint rule set: identity order has zero inversions and wins.
        rules = [
            make_rule("r1", dp=(0, 10)),
            make_rule("r2", dp=(20, 30)),
            make_rule("r3", dp=(40, 50)),
        ]
        res = plan_reorder(rules, [])
        assert res["feasible"] is True
        assert res["order"] == ["r1", "r2", "r3"]
        assert res["inversions"] == 0


class TestTieBreak:
    def test_equal_inversion_orders_tie_broken_by_rule_id(self):
        # Disjoint rules with ids shuffled relative to original indices:
        # index 0 -> "b", 1 -> "a", 2 -> "c".  Constraint r2(idx2="c")
        # before r0(idx0="b") forces at least 2 inversions; both
        # ["c","b","a"] (= 2,0,1) and ["a","c","b"] (= 1,2,0) cost 2,
        # and the id-lexicographically smaller complete order wins.
        rules = [
            make_rule("b", dp=(0, 9)),
            make_rule("a", dp=(20, 29)),
            make_rule("c", dp=(40, 49)),
        ]
        res = plan_reorder(rules, [(2, 0)])
        assert res["feasible"] is True
        assert res["order"] == ["a", "c", "b"]
        assert res["inversions"] == 2

    def test_inversion_minimality_exhaustive_on_small_case(self):
        # Exhaustive permutation oracle for one multi-dimensional setup.
        rules = [
            make_rule("r1", protocol="tcp", dp=(0, 5)),
            make_rule("r2", protocol="both", dp=(3, 8)),
            make_rule("r3", protocol="udp", dp=(0, 8)),
            make_rule("r4", dp=(6, 10)),
        ]
        boxes = [box_of(r) for r in rules]
        n = len(rules)

        def feasible(perm, pairs):
            pred = [0] * n
            for i, j in pairs:
                pred[j] |= 1 << i
            placed = 0
            union: list[tuple] = []
            for j in perm:
                if pred[j] & ~placed:
                    return False
                remainder = [boxes[j]]
                for prior in union:
                    remainder = subtract_region(remainder, prior)
                if not remainder:
                    return False
                placed |= 1 << j
                union.append(boxes[j])
            return True

        pairs = [(1, 0)]
        res = plan_reorder(rules, pairs)
        costs = []
        for perm in itertools.permutations(range(n)):
            if feasible(perm, pairs):
                inv = sum(
                    1
                    for a in range(n)
                    for b in range(a + 1, n)
                    if perm[a] > perm[b]
                )
                costs.append((inv, tuple(rules[j].id for j in perm)))
        assert costs
        assert res["inversions"] == min(inv for inv, _ in costs)
        optimal = sorted(
            t for inv, t in costs if inv == res["inversions"]
        )
        assert tuple(res["order"]) == optimal[0]


class TestInfeasible:
    def test_constraint_forcing_broad_first_is_infeasible(self):
        rules = [
            make_rule("r1", dp=(0, 200)),
            make_rule("r2", dp=(0, 150)),
            make_rule("r3", dp=(0, 100)),
        ]
        res = plan_reorder(rules, [(0, 1)])  # r1 must be earlier than r2
        assert res["feasible"] is False
        dead = res["dead_end"]
        blocked_ids = {item["rule_id"] for item in dead["blocked"]}
        assert "r2" in blocked_ids
        # The reported prefix itself reaches every rule it contains.
        assert set(dead["prefix"]) <= {"r1", "r2", "r3"}
        assert len(dead["prefix"]) < 3

    def test_all_identical_rules_only_one_can_reach(self):
        rules = [make_rule(f"r{i}", dp=(80, 80)) for i in range(4)]
        res = plan_reorder(rules, [])
        assert res["feasible"] is False
        assert len(res["dead_end"]["prefix"]) == 1
        assert {b["rule_id"] for b in res["dead_end"]["blocked"]} == {
            f"r{i}" for i in range(1, 4)
        }

    def test_region_infeasibility_uses_exact_dimensions(self):
        # Two identical-box rules can never both have first-match space,
        # regardless of order — distinct ids do not help.
        rules = [
            make_rule("x", protocol="both", src="10.0.0.0/30", dp=(1, 2)),
            make_rule("y", protocol="both", src="10.0.0.0/30", dp=(1, 2)),
        ]
        assert plan_reorder(rules, [])["feasible"] is False
        # Differing on the protocol axis makes both orders reachable.
        rules[1] = make_rule("y", protocol="tcp", src="10.0.0.0/30", dp=(1, 2))
        assert plan_reorder(rules, [])["feasible"] is True


class TestConstraintValidation:
    def test_dangling_before_rule_rejected(self):
        with pytest.raises(ReorderError):
            normalize_constraints([{"before": "r9", "after": "r1"}], ["r1", "r2"])

    def test_dangling_after_rule_rejected(self):
        with pytest.raises(ReorderError):
            normalize_constraints([{"before": "r1", "after": "r9"}], ["r1", "r2"])

    def test_self_loop_rejected(self):
        with pytest.raises(ReorderError):
            normalize_constraints([{"before": "r1", "after": "r1"}], ["r1"])

    def test_cycle_detected(self):
        pairs = normalize_constraints(
            [{"before": "a", "after": "b"}, {"before": "b", "after": "a"}],
            ["a", "b"],
        )
        assert constraint_cycle(pairs, 2) is not None

    def test_duplicate_constraints_normalized_away(self):
        pairs = normalize_constraints(
            [
                {"before": "r1", "after": "r2"},
                {"before": "r1", "after": "r2"},
            ],
            ["r1", "r2"],
        )
        assert pairs == [(0, 1)]

    def test_rule_count_limit(self):
        rules = [make_rule(f"r{i}") for i in range(MAX_REORDER_RULES + 1)]
        with pytest.raises(ReorderError):
            plan_reorder(rules, [])


class TestWitnessRecompute:
    def test_recomputed_minimum_matches_reported_witness(self):
        rules = [
            make_rule("r1", protocol="both", src="10.0.0.0/24", dp=(0, 100)),
            make_rule("r2", protocol="tcp", src="10.0.0.0/25", dp=(0, 100)),
            make_rule("r3", protocol="tcp", src="10.0.0.0/24", dp=(50, 150)),
        ]
        res = plan_reorder(rules, [])
        assert res["feasible"]
        boxes = [box_of(r) for r in rules]
        ids = [r.id for r in rules]
        # Independently replay the reported order with the region algebra.
        union: list[tuple] = []
        for item in res["witnesses"]:
            j = ids.index(item["rule_id"])
            remainder = [boxes[j]]
            for prior in union:
                remainder = subtract_region(remainder, prior)
            assert remainder
            assert witness_dict(min_point(remainder)) == item["witness"]
            union.append(boxes[j])
