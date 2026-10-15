"""
W4 Ch7 — The live rule check: the only thing that decides at the edge (given)

An LLM never sits in the request path here. What runs at the checkout is this
check: the small, AND-only rules of rules/active.json (defenses/rules.py),
evaluated against the session's card. Deterministic, milliseconds per
checkout, auditable line by line. A rule reaches active.json only through
defenses/rule_gate.py (replay) and tools/approve.py (a person).

Levels (DEFENSE_LEVEL):
  0  the engine is not consulted
  1  shadow: LADDER[1] runs this check shadowed — matches are recorded in
     rule_hits (mode "shadow") and in the decision log's X-Lab-Shadow, nobody
     is blocked
  2  enforce: LADDER[2] runs it for real — a match at the checkout is a hard
     block before any order is written. The rule id stays server-side: telling
     the client which rule fired is a free oracle.

The card is built from the same summary the analyst and the gate read
(defenses/sessionize.py): one summary, no train/serve skew.
"""

import time

from . import rule_store, sessionize
from .pipeline import Check, Signal, Verdict
from .rules import RuleEngine

ENGINE = RuleEngine()
PHASES = ("action:checkout", "action:drop_buy")


def _evaluate(ctx):
    t0 = time.perf_counter()
    with rule_store.make_engine().connect() as conn:
        card = sessionize.card_for_sid(conn, ctx.session.sid)
    hit, _ = ENGINE.evaluate(sessionize.flatten(card)) if card else (None, 0.0)
    return hit, (time.perf_counter() - t0) * 1000


def _record(ctx, hit, mode):
    with rule_store.make_engine().begin() as conn:
        conn.execute(rule_store.rule_hits_t.insert().values(
            ts=time.time(), sid=ctx.session.sid, rule_id=hit.get("id"), mode=mode))


def _block(hit):
    return Verdict("block", 100, signals=(Signal("rules", "rule_match", 100, str(hit.get("id"))),))


def _check(ctx):
    """LADDER[2]: enforce."""
    hit, ms = _evaluate(ctx)
    ctx.note(rules_ms=round(ms, 3))
    if hit is None:
        return None
    ctx.note(rule_id=hit.get("id"))
    _record(ctx, hit, "enforce")
    return _block(hit)


def _check_shadow(ctx):
    """LADDER[1]: the same evaluation, shadowed. At level 2 the enforcing copy
    runs instead, so a checkout is never evaluated (or recorded) twice."""
    if ctx.level >= 2:
        return None
    hit, ms = _evaluate(ctx)
    ctx.note(rules_ms=round(ms, 3))
    if hit is None:
        return None
    _record(ctx, hit, "shadow")
    return _block(hit)


CHECK = Check("rules", _check, phases=PHASES)
SHADOW = Check("rules_shadow", _check_shadow, phases=PHASES, shadow=True)
