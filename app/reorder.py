"""Stable rule reordering under exact 5-D region coverage.

Given the frozen rules of an audit, the security engineer submits a stable
reorder identifier plus a set of precedence constraints ("rule A must appear
earlier than rule B").  The service checks whether the existing rules can be
re-permuted so that **every** rule keeps at least one packet it matches first:

* the union of already-placed rule regions is maintained as a disjoint box
  list in the exact 5-D space (protocol x src IPv4 x dst IPv4 x src port x
  dst port);
* a candidate rule extends the order only when
    - all rules that must precede it have already been placed, and
    - its region minus the current union is non-empty;
* the minimal packet witness of that remaining region is reported for the
  resulting position, so the first-match space can be recomputed rule by rule.

This is **not** a greedy "pick the next workable rule": the search over
subsets keeps every feasible partial order and selects the global optimum.
Among all feasible permutations it first minimizes the number of inversions
relative to the original (submission) order, then compares the complete rule
id sequences lexicographically.

Unfeasible answers are stable too: the same reorder identifier always
re-opens the same frozen conclusion, and a retransmission that changes the
source audit or the constraints is rejected without rewriting it.
"""

from __future__ import annotations

from .engine import box_of, witness_dict
from .region import min_point, subtract_region
from .schemas import MAX_CONSTRAINTS


class ReorderError(ValueError):
    """A reorder request is invalid (bad source, bad constraints, ...)."""

    def __init__(self, code: str, message: str, details: list | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or []


def validate_constraints(rule_ids: list[str], constraints: list[dict]) -> list[tuple[str, str]]:
    """Validate precedence pairs against the audit's rule identifiers.

    Accepted pairs are returned as a deduplicated list in request order.
    Rejected: unknown endpoints, self loops, duplicate pairs (any form),
    and constraint sets that contain a directed cycle.
    """
    known = set(rule_ids)
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    details: list[str] = []

    if len(constraints) > MAX_CONSTRAINTS:
        raise ReorderError(
            "too_many_constraints",
            f"优先约束至多 {MAX_CONSTRAINTS} 条，当前 {len(constraints)} 条。",
        )

    for idx, con in enumerate(constraints):
        earlier = con.get("before")
        later = con.get("after")
        if not isinstance(earlier, str) or not isinstance(later, str):
            details.append(f"第 {idx + 1} 条约束缺少规则标识字段 before/after。")
            continue
        missing = [rid for rid in (earlier, later) if rid not in known]
        if missing:
            details.append(
                f"第 {idx + 1} 条约束 {earlier!r} -> {later!r} 引用了审计中不存在的规则标识 "
                f"{', '.join(sorted(set(missing)))}。"
            )
            continue
        if earlier == later:
            details.append(f"第 {idx + 1} 条约束 {earlier!r} 要求自身早于自身。")
            continue
        pair = (earlier, later)
        if pair in seen:
            details.append(f"第 {idx + 1} 条约束 {earlier!r} -> {later!r} 重复。")
            continue
        seen.add(pair)
        pairs.append(pair)

    if details:
        raise ReorderError("invalid_constraints", "优先约束校验未通过。", details)

    cycle = _find_cycle(rule_ids, pairs)
    if cycle is not None:
        raise ReorderError(
            "cyclic_constraints",
            "优先约束存在循环，无法同时满足：" + " -> ".join(cycle) + "。",
            [f"{' -> '.join(cycle)} -> {cycle[0]}"],
        )
    return pairs


def _find_cycle(rule_ids: list[str], pairs: list[tuple[str, str]]) -> list[str] | None:
    """Return one directed cycle as an ordered id list, or None."""
    adjacency: dict[str, list[str]] = {rid: [] for rid in rule_ids}
    for earlier, later in pairs:
        adjacency[earlier].append(later)

    WHITE, GRAY, BLACK = 0, 1, 2
    color = {rid: WHITE for rid in rule_ids}
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        color[node] = GRAY
        stack.append(node)
        for nxt in adjacency[node]:
            if color[nxt] == GRAY:
                start = stack.index(nxt)
                return stack[start:]
            if color[nxt] == WHITE:
                found = visit(nxt)
                if found is not None:
                    return found
        stack.pop()
        color[node] = BLACK
        return None

    for rid in rule_ids:
        if color[rid] == WHITE:
            found = visit(rid)
            if found is not None:
                return found
    return None


def reorder(rules, constraints: list[dict]) -> dict:
    """Compute the optimal feasible permutation or an infeasible conclusion.

    ``rules`` are the audit's validated rule models in their original
    (frozen) priority order.  Returns a result dict with either
    ``status == "feasible"`` (ordered witnesses) or ``status ==
    "infeasible"`` (the exact region obstruction is reported per rule).
    """
    rule_ids = [rule.id for rule in rules]
    pairs = validate_constraints(rule_ids, constraints)

    n = len(rules)
    boxes = [box_of(rule) for rule in rules]
    index_of = {rid: i for i, rid in enumerate(rule_ids)}

    # predecessors[i] = bitmask of rules that must appear before rule i
    predecessors = [0] * n
    for earlier, later in pairs:
        predecessors[index_of[later]] |= 1 << index_of[earlier]

    full = (1 << n) - 1

    # For each explored placed-set: the exact disjoint-box union of the
    # placed rules' regions, shared by every optimal partial sequence that
    # reaches the set (the union depends only on the set, never the order).
    unions: dict[int, list[tuple]] = {0: []}
    # dp[mask] = best (inversion_count, rule_id_tuple) reaching that mask.
    dp: dict[int, tuple[int, tuple[str, ...]]] = {0: (0, ())}

    for mask in range(full + 1):
        if mask not in dp:
            continue
        inv_count, seq = dp[mask]
        union = unions[mask]
        remaining_rules = full ^ mask
        candidates = remaining_rules
        while candidates:
            bit = candidates & -candidates
            candidates ^= bit
            i = bit.bit_length() - 1
            if predecessors[i] & ~mask:
                continue  # a required predecessor is not placed yet
            remainder = _remaining_region(boxes[i], union)
            if not remainder:
                continue  # rule i would be fully shadowed in this position
            new_mask = mask | bit
            new_inv = inv_count + _added_inversions(i, mask)
            new_key = (new_inv, seq + (rule_ids[i],))
            old = dp.get(new_mask)
            if old is None or new_key < old:
                dp[new_mask] = new_key
                unions.setdefault(new_mask, _add_box(union, boxes[i]))

    if full in dp:
        order_ids = dp[full][1]
        return _feasible_result(rules, boxes, index_of, order_ids, dp[full][0])

    return _infeasible_result(rules, predecessors, dp)


def _added_inversions(i: int, mask: int) -> int:
    """Inversions created by appending original-index i after set ``mask``.

    Appending i is an inversion against every already-placed rule whose
    original index is greater than i; rules with smaller index already
    precede i and stay correctly ordered.
    """
    return (mask >> (i + 1)).bit_count()


def _remaining_region(box: tuple, union: list[tuple]) -> list[tuple]:
    """Exact region of ``box`` not covered by any box of the union."""
    region = [box]
    for covered in union:
        if not region:
            break
        region = subtract_region(region, covered)
    return region


def _add_box(union: list[tuple], box: tuple) -> list[tuple]:
    """Add a box to a disjoint box list, keeping pieces disjoint."""
    new_pieces = _remaining_region(box, union)
    return union + new_pieces


def _feasible_result(rules, boxes, index_of, order_ids, inversions) -> dict:
    """Replay the winning order to attach the per-rule minimal witness."""
    union: list[tuple] = []
    ordered: list[dict] = []
    for position, rid in enumerate(order_ids, start=1):
        i = index_of[rid]
        remainder = _remaining_region(boxes[i], union)
        ordered.append(
            {
                "position": position,
                "rule_id": rid,
                "original_position": i + 1,
                "witness": witness_dict(min_point(remainder)),
            }
        )
        union = _add_box(union, boxes[i])
    return {
        "status": "feasible",
        "inversions": inversions,
        "order": list(order_ids),
        "ordered_witnesses": ordered,
    }


def _infeasible_result(rules, predecessors, dp) -> dict:
    """Explain the obstruction without any greedy/port/CIDR shortcuts.

    A rule is "reachable" if it can be placed in some explored prefix.  In
    the forward search a rule whose predecessors are satisfied and whose
    remaining region is non-empty is always extendable, so pruning only
    discards alternative sequences for the same placed set, never a
    feasible extension.  Three obstruction kinds are distinguished:

    * ``precedence_blocked`` — no reachable prefix satisfies the rule's
      required predecessors;
    * ``region_covered`` — such prefixes exist, but the union of earlier
      rules covers the rule's whole 5-D region in every one of them;
    * ``no_completion`` — the rule itself is placeable in some prefix, but
      no prefix containing it can be extended to place every rule (mutual
      exclusion between rules).
    """
    n = len(rules)
    full = (1 << n) - 1
    best_mask = max(dp, key=lambda m: (m.bit_count(), -m))
    blocked: list[dict] = []
    for i, rule in enumerate(rules):
        bit = 1 << i
        if best_mask & bit:
            continue
        containing = [mask for mask in dp if mask & bit]
        if not containing:
            pred_masks = [
                mask for mask in dp if (predecessors[i] & ~mask) == 0
            ]
            if pred_masks:
                witness_mask = min(pred_masks, key=lambda m: (m.bit_count(), m))
                blocked.append(
                    {
                        "rule_id": rule.id,
                        "reason": "region_covered",
                        "message": (
                            "在所有满足优先约束的可达状态下，该规则的五维区域"
                            "都被更早规则的并集完全覆盖。"
                        ),
                        "covered_in_state": [
                            rules[j].id for j in range(n) if (witness_mask >> j) & 1
                        ],
                    }
                )
            else:
                blocked.append(
                    {
                        "rule_id": rule.id,
                        "reason": "precedence_blocked",
                        "message": "不存在满足其全部优先前驱的可达状态。",
                        "required_predecessors": [
                            rules[j].id
                            for j in range(n)
                            if (predecessors[i] >> j) & 1
                        ],
                    }
                )
            continue
        completable = any(mask == full for mask in containing)
        if not completable:
            blocked.append(
                {
                    "rule_id": rule.id,
                    "reason": "no_completion",
                    "message": (
                        "该规则可在某些前缀中首先命中，但包含它的任何前缀都无法"
                        "扩展到全部规则（规则间存在相互排斥的覆盖关系）。"
                    ),
                    "reachable_prefix_count": len(containing),
                }
            )
    return {
        "status": "infeasible",
        "reachable_count": best_mask.bit_count(),
        "total_rules": n,
        "max_reachable_order": [
            rules[i].id for i in range(n) if (best_mask >> i) & 1
        ],
        "blocked_rules": blocked,
    }
