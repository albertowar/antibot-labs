"""Round 5 defense [STUDENT FILE] — "pay with money, or pay with work": a proof-of-work gate.

Round 4 charged the crawlers you can name. Round 3 taxed the careless ones you cannot. What is left is
the careful crawler nobody can name: Chrome UA, residential addresses, hygiene good enough to walk
around the maze. Chapter 1's policy could only answer such a client with a placeholder `challenge`;
this module is the answer a client can EARN, in the style of Anubis (the open-source gate in front
of many Git forges and docs sites): before the store hands over product records, the client solves a
hashcash puzzle (defenses/pow_core.py, the one from W1 Ch6) and gets a pass.

  * Who is gated: any request for a catalogue carrier (policy.POW_PROTECTED) from a client without a
    verified identity. A verified operator (Web Bot Auth, Chapter 2) is exempt: it is handled by
    the policy (Round 2) and the 402 paywall (Round 4). Money pays at the paywall, work pays here.
  * What the pass is: the gate's clearance for the `pow` challenge (a session cookie), narrowed three
    ways so that it is not a free ticket (Anubis's known weakness is a pass that is reusable):
      budget   POW_PASS_BUDGET protected requests per solve, then it is gone
      time     POW_PASS_TTL seconds (the clearance expires on its own)
      binding  the pass only works from the IP + User-Agent that earned it
  * What it asks of the crawler: ~2**POW_BITS hashes per pass, i.e. a cost per record of
    (cost of a solve) / POW_PASS_BUDGET, and one pass per address it rotates through.

What it catches: every crawler that cannot or will not run the solver, which is most scripts.
What it misses: one that pays. At a difficulty a phone tolerates the price is a fraction of a cent per
thousand records; the gate raises the floor, it is not a wall.
Who it hurts: every client without JavaScript or a solver, on every page behind the gate: text
browsers (the lab's readers), some assistive technology, feed readers and plain API clients; and every
low-end phone pays more than a laptop. The difficulty is a tax on everyone you cannot name.

How it reaches the wire: `challenge` is a verdict the gate already knows, and demo_site/ext/pow.py
registers the `pow` type (defenses/pow_challenge.py issues and verifies). The gate DOWNGRADES a
challenge verdict while the session holds a clearance, so a check that decides a pass is spent, stolen
or over budget must revoke it before returning the verdict (revoke() below).

TODO (Round 5): evaluate() and client_tag(); everything else is given.
Fell behind? python tools/checkpoint.py --round 5 --catch-up
"""

from __future__ import annotations

from . import bot_identity, crawl_policy, policy
from .pipeline import Check, Signal, Verdict


def protected(path: str) -> bool:
    return path.startswith(policy.POW_PROTECTED)


def has_pass(ctx) -> bool:
    """The gate's clearance key for the `pow` type (the same one the gate writes on a verified answer)."""
    return bool(ctx.redis.get(f"lab:s:{ctx.session.sid}:clear:pow"))


def revoke(ctx) -> None:
    ctx.redis.delete(f"lab:s:{ctx.session.sid}:clear:pow")
    ctx.session.delete("cleared:pow")


def client_tag(ctx) -> str:
    """TODO 2 (Round 5): what a pass is bound to. pow_challenge.verify() stores it in the session when
    a solve is accepted; _check() compares it on every later request. Return the address and the
    User-Agent: f"{ip}|{ua}". Until then the pass is bound to nothing and can be carried to any address."""
    return ""


def evaluate(held: bool, bound_ok: bool, used: int):
    """TODO 1 (Round 5): decide whether this request must (re)solve. Return None to let it through,
    or a short reason string (it goes to the decision log, never to the client).
      * no pass held                        -> "no_pass"
      * pass bound to another client        -> "pass_bound_elsewhere"
      * used > policy.POW_PASS_BUDGET       -> "pass_used_up"
      * otherwise                           -> None
    `held`: the session holds a pass. `bound_ok`: it was earned by this IP + User-Agent. `used`: how many
    protected requests this pass has now paid for, this one included (0 when none is held). The pass's age
    needs no code: the clearance expires after POW_PASS_TTL on its own, and then `held` is False.
    Until then everyone passes, and the careful crawler reads the catalogue for free."""
    return None


def _check(ctx):
    """Given: exempt the policy documents and the verified, count the pass's use, ask evaluate()."""
    if crawl_policy.exempt(ctx.path) or not protected(ctx.path):
        return None
    if bot_identity.identify(ctx).verified:
        return None                                     # named operators pay at the paywall, not here
    held = has_pass(ctx)
    bound_ok = held and (ctx.session.get("pow:bind") or "") == client_tag(ctx)
    used = 0
    if held:
        key = ctx.session.ns("pow") + "used"
        used = int(ctx.redis.incr(key))
        ctx.redis.expire(key, policy.POW_PASS_TTL)
        ctx.note(pow_used=used)
    reason = evaluate(held, bound_ok, used)
    if reason is None:
        return None
    if held:
        revoke(ctx)                                     # else the gate downgrades the verdict below
    ctx.note(pow_reason=reason)
    return Verdict("challenge", signals=(Signal("pow_gate", reason, policy.POW_POINTS, ctx.path[:40]),), challenge="pow")


CHECK = Check("pow_gate", _check)
