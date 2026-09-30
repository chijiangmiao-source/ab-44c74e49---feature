"""Tests for exact stable rule reordering."""

from __future__ import annotations

import ipaddress

import pytest

from app.engine import box_of
from app.reorder import ReorderError, reorder, validate_constraints
from app.schemas import PortRange, Rule


def make_rule(
    rid,
    protocol="both",
    src="10.0.0.0/24",
    dst="192.168.0.0/24",
    sp=(0, 65535),
    dp=(80, 90),
):
    return Rule(
        id=rid,
        protocol=protocol,
        src_cidr=src,
        dst_cidr=dst,
        src_port=PortRange(start=sp[0], end=sp[1]),
        dst_port=PortRange(start=dp[0], end=dp[1]),
    )


def point_of(witness):
    return (
        {"tcp": 0, "udp": 1}[witness["protocol"]],
        int(ipaddress.IPv4Address(witness["src_ip"])),
        int(ipaddress.IPv4Address(witness["dst_ip"])),
        witness["src_port"],
        witness["dst_port"],
    )


def assert_witness_first_hit(result, rules):
    """Every witness lies in its rule's remainder vs all earlier new-order rules."""
    by_id = {rule.id: rule for rule in rules}
    union: list[tuple] = []
    for entry in result["ordered_witnesses"]:
        box = box_of(by_id[entry["rule_id"]])
        point = point_of(entry["witness"])
        assert all(lo <= value <= hi for value, (lo, hi) in zip(point, box))
        for other in union:
            assert not all(
                other[d][0] <= point[d] <= other[d][1] for d in range(5)
            ), f"witness of {entry['rule_id']} lies inside an earlier rule"
        # Witness is the exact lexicographic minimum of the remainder.
        from app.region import min_point, subtract_region

        remainder = [box]
        for other in union:
            remainder = subtract_region(remainder, other)
        assert point == min_point(remainder)
        pieces = [box]
        for other in union:
            pieces = subtract_region(pieces, other)
        union.extend(pieces)


class TestReorderRequired:
    def test_group_needs_reorder_for_all_reachable(self):
        # Original order leaves r3 fully shadowed:
        #   r1 = tcp:80-90, r2 = udp:80-90, r3 = both:80-85
        # r3 must move up between the two protocol slices (or before both)
        # so every rule keeps a first-hit packet.
        rules = [
            make_rule("r1", protocol="tcp"),
            make_rule("r2", protocol="udp"),
            make_rule("r3", protocol="both", dp=(80, 85)),
        ]
        result = reorder(rules, [])
        assert result["status"] == "feasible"
        # [r1,r3,r2] and [r2,r3,r1] both cost 1 inversion; id order picks r1 first.
        assert result["inversions"] == 1
        assert result["order"] == ["r1", "r3", "r2"]
        witnesses = {w["rule_id"]: w for w in result["ordered_witnesses"]}
        assert witnesses["r1"]["witness"]["dst_port"] == 80
        assert witnesses["r1"]["witness"]["protocol"] == "tcp"
        # r3 loses its TCP slice to r1 and first-hits on UDP.
        assert witnesses["r3"]["witness"]["protocol"] == "udp"
        assert witnesses["r3"]["witness"]["dst_port"] == 80
        assert witnesses["r2"]["witness"]["dst_port"] == 86
        assert_witness_first_hit(result, rules)

    def test_constraint_forces_a_move(self):
        # Forcing r3 before r1 is honoured by the optimal permutation.
        rules = [
            make_rule("r1", protocol="tcp"),
            make_rule("r2", protocol="udp"),
            make_rule("r3", protocol="both", dp=(80, 85)),
        ]
        result = reorder(rules, [{"before": "r3", "after": "r1"}])
        assert result["status"] == "feasible"
        positions = {rid: i for i, rid in enumerate(result["order"])}
        assert positions["r3"] < positions["r1"]
        assert_witness_first_hit(result, rules)

    def test_infeasible_when_rules_identical(self):
        rules = [make_rule("r1"), make_rule("r2"), make_rule("r3")]
        result = reorder(rules, [])
        assert result["status"] == "infeasible"
        assert result["reachable_count"] == 1
        assert result["total_rules"] == 3
        blocked = {b["rule_id"]: b for b in result["blocked_rules"]}
        assert set(blocked) == {"r2", "r3"}
        # Each identical rule can itself be the first rule, but no prefix
        # containing it can ever complete — mutual exclusion, not a forced
        # coverage by constraints.
        assert all(b["reason"] == "no_completion" for b in blocked.values())


class TestTieBreaking:
    def test_equal_inversions_then_rule_id_sequence(self):
        # r1 = tcp:80-90, r2 = udp:80-90, r3 = tcp:80-85 (subset of r1).
        # r1 must come after r3; with r2 free there are two optimum orders
        # at the same inversion cost: [r1,r3,r2] and [r2,r3,r1];
        # the complete rule-id sequence comparison picks r1.. first.
        rules = [
            make_rule("r1", protocol="tcp"),
            make_rule("r2", protocol="udp"),
            make_rule("r3", protocol="tcp", dp=(80, 85)),
        ]
        result = reorder(rules, [])
        assert result["status"] == "feasible"
        assert result["inversions"] == 2
        assert result["order"] == ["r2", "r3", "r1"]
        witnesses = {w["rule_id"]: w for w in result["ordered_witnesses"]}
        assert witnesses["r2"]["witness"]["dst_port"] == 80
        assert witnesses["r3"]["witness"]["dst_port"] == 80
        assert witnesses["r1"]["witness"]["dst_port"] == 86
        assert_witness_first_hit(result, rules)

    def test_original_order_wins_when_already_feasible(self):
        rules = [
            make_rule("r1", protocol="tcp"),
            make_rule("r2", protocol="udp"),
            make_rule("r3", protocol="tcp", src="10.0.1.0/24"),
        ]
        result = reorder(rules, [])
        assert result["status"] == "feasible"
        assert result["inversions"] == 0
        assert result["order"] == ["r1", "r2", "r3"]

    def test_lexicographic_ids_not_dependent_on_insertion(self):
        # Same geometry with alphabetic ids out of geometric order:
        # alpha = tcp superset (original index 0), mu = udp disjoint (1),
        # zeta = tcp subset (2).  Two orders tie at 2 inversions:
        # (mu, zeta, alpha) vs (zeta, alpha, mu); the id sequence picks mu.
        rules = [
            make_rule("alpha", protocol="tcp"),
            make_rule("mu", protocol="udp"),
            make_rule("zeta", protocol="tcp", dp=(80, 85)),
        ]
        result = reorder(rules, [])
        assert result["status"] == "feasible"
        assert result["order"] == ["mu", "zeta", "alpha"]
        assert result["inversions"] == 2


class TestConstraintValidation:
    def test_dangling_constraint_rejected(self):
        rules = [make_rule("r1"), make_rule("r2", protocol="udp")]
        with pytest.raises(ReorderError) as exc:
            validate_constraints(["r1", "r2"], [{"before": "r1", "after": "ghost"}])
        assert exc.value.code == "invalid_constraints"

    def test_self_loop_rejected(self):
        with pytest.raises(ReorderError) as exc:
            validate_constraints(["r1"], [{"before": "r1", "after": "r1"}])
        assert exc.value.code == "invalid_constraints"

    def test_duplicate_pair_rejected(self):
        with pytest.raises(ReorderError) as exc:
            validate_constraints(
                ["r1", "r2"],
                [
                    {"before": "r1", "after": "r2"},
                    {"before": "r1", "after": "r2"},
                ],
            )
        assert exc.value.code == "invalid_constraints"

    def test_cycle_rejected(self):
        with pytest.raises(ReorderError) as exc:
            validate_constraints(
                ["r1", "r2", "r3"],
                [
                    {"before": "r1", "after": "r2"},
                    {"before": "r2", "after": "r3"},
                    {"before": "r3", "after": "r1"},
                ],
            )
        assert exc.value.code == "cyclic_constraints"

    def test_valid_constraints_deduplicated(self):
        pairs = validate_constraints(
            ["r1", "r2"], [{"before": "r1", "after": "r2"}]
        )
        assert pairs == [("r1", "r2")]


class TestConstrainedInfeasibility:
    def test_big_rule_forced_before_subset_is_infeasible(self):
        # Without the constraint [r2, r1] is feasible; forcing r1 first
        # covers r2's whole region no matter what.
        rules = [
            make_rule("r1", protocol="tcp", dp=(80, 90)),
            make_rule("r2", protocol="tcp", dp=(80, 85)),
        ]
        free = reorder(rules, [])
        assert free["status"] == "feasible"
        forced = reorder(rules, [{"before": "r1", "after": "r2"}])
        assert forced["status"] == "infeasible"
        blocked = {b["rule_id"]: b for b in forced["blocked_rules"]}
        assert blocked["r2"]["reason"] == "region_covered"
        assert blocked["r2"]["covered_in_state"] == ["r1"]

    def test_mutual_exclusion_reported_as_no_completion(self):
        # r1 covers ports 80-90 while r2/r3 split it into 80-85/86-90:
        # any two can coexist, all three never can.  Each rule nevertheless
        # belongs to some size-2 reachable prefix, so the obstruction is
        # "no completion", not simple coverage.
        rules = [
            make_rule("r1", protocol="tcp", dp=(80, 90)),
            make_rule("r2", protocol="tcp", dp=(80, 85)),
            make_rule("r3", protocol="tcp", dp=(86, 90)),
        ]
        result = reorder(rules, [])
        assert result["status"] == "infeasible"
        assert result["reachable_count"] == 2
        assert len(result["max_reachable_order"]) == 2
        assert len(result["blocked_rules"]) == 1
        blocked = result["blocked_rules"][0]
        assert blocked["reason"] == "no_completion"

    def test_constraint_can_make_otherwise_feasible_set_infeasible(self):
        rules = [
            make_rule("r1", protocol="tcp"),
            make_rule("r2", protocol="udp"),
            make_rule("r3", protocol="both", dp=(80, 85)),
        ]
        # Forcing r1 before r3: r3 keeps its UDP part, so still feasible;
        # forcing both slices before r3 covers it entirely.
        still = reorder(
            rules, [{"before": "r1", "after": "r3"}]
        )
        assert still["status"] == "feasible"
        dead = reorder(
            rules,
            [
                {"before": "r1", "after": "r3"},
                {"before": "r2", "after": "r3"},
            ],
        )
        assert dead["status"] == "infeasible"
        blocked = {b["rule_id"]: b for b in dead["blocked_rules"]}
        assert blocked["r3"]["reason"] == "region_covered"
        assert set(blocked["r3"]["covered_in_state"]) == {"r1", "r2"}
