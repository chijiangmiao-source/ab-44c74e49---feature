"""Stable rule reordering under exact 5-D region reachability.

Given the frozen rules of an audit (at most :data:`MAX_REORDER_RULES`
rules) and a set of ``A before B`` precedence constraints, decide whether
the rules can be permuted so that **every** rule keeps a non-empty region
after the union of the rules placed earlier is subtracted, i.e. every
rule still matches at least one packet for which it is the *first*
matching rule.

Reachability is decided by the same exact box algebra the shadow engine
uses (``app.region``): the union of an already-placed prefix is a list of
5-D boxes and a rule may extend the order only while its remaining region
(rule box minus the union, exact subtraction) is non-empty.  There is no
CIDR-overlap heuristic, no port sampling and no greedy choice of the
next rule: feasibility and optimality are established by exhaustive
subset dynamic programming over the (at most 2**12) prefix subsets.

Among all feasible orders the result minimizes, in turn:

1. the number of inversions relative to the original submission order;
2. the complete order compared lexicographically by rule identifier.

The tie-break is recovered *after* the exact DP: the optimal suffix cost
table lets the reconstruction choose, at each position, the smallest
identifier that still permits a globally optimal completion — this yields
the lexicographically smallest complete optimal order without ever
greedily committing to feasibility.
"""

from __future__ import annotations

from .engine import witness_dict
from .region import min_point, rule_box, subtract_region

MAX_REORDER_RULES = 12


class ReorderError(ValueError):
    """Validation failure on a reorder request (HTTP 422)."""


def rule_box_of(rule) -> tuple:
    return rule_box(
        rule.protocol,
        rule.src_cidr,
        rule.dst_cidr,
        (rule.src_port.start, rule.src_port.end),
        (rule.dst_port.start, rule.dst_port.end),
    )


def normalize_constraints(constraints, rule_ids: list[str]) -> list[tuple[int, int]]:
    """Validate ``{before, after}`` pairs against the audit's rule ids.

    Returns the de-duplicated index pairs in first-occurrence order.
    Rejects malformed pairs, self loops and unknown (dangling) rule ids.
    Cyclic pairs are detected separately by :func:`constraint_cycle`.
    """
    index = {rid: i for i, rid in enumerate(rule_ids)}
    pairs: list[tuple[int, int]] = []
    seen: set[tuple[int, int]] = set()
    for pos, con in enumerate(constraints or []):
        if not isinstance(con, dict) or "before" not in con or "after" not in con:
            raise ReorderError(
                f"第 {pos + 1} 条优先约束必须同时给出 before 与 after 规则标识"
            )
        before, after = con["before"], con["after"]
        if not isinstance(before, str) or not isinstance(after, str):
            raise ReorderError(f"第 {pos + 1} 条优先约束的规则标识必须为字符串")
        if before not in index:
            raise ReorderError(
                f"第 {pos + 1} 条优先约束引用了来源审计中不存在的规则标识 {before!r}（悬空约束）"
            )
        if after not in index:
            raise ReorderError(
                f"第 {pos + 1} 条优先约束引用了来源审计中不存在的规则标识 {after!r}（悬空约束）"
            )
        i, j = index[before], index[after]
        if i == j:
            raise ReorderError(f"优先约束 {before!r} 必须早于自身，构成自环")
        if (i, j) not in seen:
            seen.add((i, j))
            pairs.append((i, j))
    return pairs


def _remainder(box: tuple, union: list[tuple]) -> list[tuple]:
    """Exact region of ``box`` not covered by the union's boxes."""
    remainder = [box]
    for prior in union:
        if not remainder:
            break
        remainder = subtract_region(remainder, prior)
    return remainder


def constraint_cycle(pairs: list[tuple[int, int]], n: int) -> list[int] | None:
    """Return one directed constraint cycle as node indices, else None."""
    succ_mask = [0] * n
    for i, j in pairs:
        succ_mask[i] |= 1 << j
    return _find_cycle(n, succ_mask)


def plan_reorder(rules, pairs) -> dict:
    """Compute the optimal feasible order or an infeasibility conclusion.

    ``rules`` are the frozen audit's rule models in original submission
    order; ``pairs`` are normalized precedence index pairs (see
    :func:`normalize_constraints`; the caller rejects cyclic pairs).

    Feasible result::

        {"feasible": True, "order": [ids], "inversions": k,
         "witnesses": [{"rank", "rule_id", "witness"}]}

    Infeasible result::

        {"feasible": False,
         "dead_end": {"prefix": [ids], "blocked": [
             {"rule_id": id, "reason": "region_covered"},
             {"rule_id": id, "reason": "awaiting_predecessor",
              "awaits": [ids]}]}}
    """
    n = len(rules)
    if n == 0 or n > MAX_REORDER_RULES:
        raise ReorderError(f"重排仅支持 1 至 {MAX_REORDER_RULES} 条规则的冻结审计")

    ids = [rule.id for rule in rules]
    boxes = [rule_box_of(rule) for rule in rules]

    pred_mask = [0] * n  # rules that must be strictly earlier
    for i, j in pairs:
        pred_mask[j] |= 1 << i

    full = (1 << n) - 1
    INF = n * n + 1

    # higher_mask[j]: rules whose original submission index is greater
    # than j's; placing j after any of them creates exactly one inversion
    # relative to the original order.
    higher_mask = [full ^ ((1 << (j + 1)) - 1) for j in range(n)]

    # Forward subset DP.
    # reach[S] is cached so the exact subtraction never recomputes prior
    # boxes: the union of a prefix is order-independent.  Only subsets
    # that admit at least one feasible ordering are present.
    reach: dict[int, list[tuple]] = {0: []}
    # dp[S] = minimum inversion count of any feasible ordering of S.
    dp: dict[int, int] = {0: 0}
    # parent[S] = S without the last rule of one optimal ordering.
    parent: dict[int, int] = {0: -1}

    for size in range(1, n + 1):
        for S in range(1, full + 1):
            if S.bit_count() != size:
                continue
            best_cost = INF
            last = S
            chosen = -1
            while last:
                bit = last & -last
                j = bit.bit_length() - 1
                last ^= bit
                prev = S ^ bit
                cost_prev = dp.get(prev)
                if cost_prev is None:
                    continue
                if pred_mask[j] & ~prev:
                    continue  # a required predecessor is not yet placed
                if not _remainder(boxes[j], reach[prev]):
                    continue  # rule would be fully shadowed at this rank
                # Placing j after prev inverts exactly the already-placed
                # rules that originally appeared after j.
                added = (prev & higher_mask[j]).bit_count()
                cost = cost_prev + added
                if cost < best_cost:
                    best_cost = cost
                    chosen = j
            if chosen >= 0:
                dp[S] = best_cost
                prev = S ^ (1 << chosen)
                parent[S] = prev
                reach[S] = reach[prev] + [boxes[chosen]]

    if full not in dp:
        return {
            "feasible": False,
            "dead_end": _dead_end(n, ids, boxes, pred_mask, reach, parent),
        }

    # Backward suffix costs: g[S] is the minimum total inversion count of
    # any feasible complete ordering that starts from placed prefix S
    # (including inversions its future steps create against S).
    g = {full: 0}
    for size in range(n - 1, -1, -1):
        for S in range(full + 1):
            if S.bit_count() != size or S not in reach:
                continue
            best_cost = INF
            remaining = full ^ S
            cand = remaining
            while cand:
                bit = cand & -cand
                j = bit.bit_length() - 1
                cand ^= bit
                if pred_mask[j] & ~S:
                    continue
                nxt = S | bit
                g_next = g.get(nxt)
                if g_next is None:
                    continue
                if not _remainder(boxes[j], reach[S]):
                    continue
                added = (S & higher_mask[j]).bit_count()
                best_cost = min(best_cost, added + g_next)
            if best_cost < INF:
                g[S] = best_cost

    # Reconstruct the lexicographically smallest optimal complete order:
    # at each rank pick the smallest identifier whose choice preserves
    # the globally optimal cost (never a feasibility heuristic).
    order_idx: list[int] = []
    S = 0
    while S != full:
        best_cost = g[S]
        candidates: list[tuple[str, int]] = []
        remaining = full ^ S
        cand = remaining
        while cand:
            bit = cand & -cand
            j = bit.bit_length() - 1
            cand ^= bit
            if pred_mask[j] & ~S:
                continue
            g_next = g.get(S | bit)
            if g_next is None:
                continue
            if not _remainder(boxes[j], reach[S]):
                continue
            added = (S & higher_mask[j]).bit_count()
            if added + g_next == best_cost:
                candidates.append((ids[j], j))
        _, j = min(candidates, key=lambda item: item[0])
        order_idx.append(j)
        S |= 1 << j

    # Per-rule witnesses: replay the exact chosen order and report the
    # lexicographically smallest packet of each rule's first-match space.
    witnesses: list[dict] = []
    union: list[tuple] = []
    for rank, j in enumerate(order_idx):
        remainder = _remainder(boxes[j], union)
        assert remainder, "DP 证明可行的顺序上出现空剩余区域"
        witnesses.append(
            {
                "rank": rank + 1,
                "rule_id": ids[j],
                "witness": witness_dict(min_point(remainder)),
            }
        )
        union.append(boxes[j])

    return {
        "feasible": True,
        "order": [ids[j] for j in order_idx],
        "inversions": dp[full],
        "witnesses": witnesses,
    }


def _dead_end(n, ids, boxes, pred_mask, reach, parent) -> dict:
    """Describe a longest feasible prefix that cannot be completed.

    Every rule still outside that prefix is either blocked because its
    exact remaining region against the prefix union is empty, or because
    a required predecessor rule is itself outside the prefix.  This
    diagnosis is exact: the forward DP proves no longer feasible prefix
    exists.
    """
    # Largest reachable prefix; the mask tie-break keeps output stable.
    S_star = max(reach.keys(), key=lambda S: (S.bit_count(), -S))

    # Reconstruct one optimal ordering of the dead-end prefix.
    prefix_idx: list[int] = []
    cur = S_star
    while cur:
        bit = cur ^ parent[cur]
        prefix_idx.append(bit.bit_length() - 1)
        cur = parent[cur]
    prefix_idx.reverse()

    blocked: list[dict] = []
    remaining = ((1 << n) - 1) ^ S_star
    union = reach[S_star]
    while remaining:
        bit = remaining & -remaining
        j = bit.bit_length() - 1
        remaining ^= bit
        missing = pred_mask[j] & ~S_star
        if missing:
            blocked.append(
                {
                    "rule_id": ids[j],
                    "reason": "awaiting_predecessor",
                    "awaits": [ids[k] for k in range(n) if (missing >> k) & 1],
                }
            )
        else:
            # Maximality of S_star guarantees an empty remainder here.
            assert not _remainder(boxes[j], union)
            blocked.append({"rule_id": ids[j], "reason": "region_covered"})
    blocked.sort(key=lambda item: item["rule_id"])
    return {
        "prefix": [ids[j] for j in prefix_idx],
        "blocked": blocked,
    }


def _find_cycle(n: int, succ_mask: list[int]) -> list[int] | None:
    """Return one directed cycle as node indices, else None."""
    color = [0] * n  # 0 white, 1 gray, 2 black
    stack: list[int] = []

    def visit(v: int) -> list[int] | None:
        color[v] = 1
        stack.append(v)
        nxt = succ_mask[v]
        while nxt:
            bit = nxt & -nxt
            u = bit.bit_length() - 1
            nxt ^= bit
            if color[u] == 1:
                start = stack.index(u)
                return stack[start:] + [u]
            if color[u] == 0:
                found = visit(u)
                if found is not None:
                    return found
        stack.pop()
        color[v] = 2
        return None

    for v in range(n):
        if color[v] == 0:
            found = visit(v)
            if found is not None:
                return found
    return None
