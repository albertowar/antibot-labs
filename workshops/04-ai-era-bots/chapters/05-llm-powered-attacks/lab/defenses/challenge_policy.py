"""
Round 2 defense (YOUR CODE): what a solved challenge is worth.

The puzzle is dead: attacks/round2_llm_solver.py solves every text puzzle and every tile grid the gate can
produce. The gate itself stays as it is (the `puzzle` challenge type, registered by the ext). What you
decide here is the *policy* around it. Two functions, both over the dict `facts(ctx)` builds:

  serve(f)   -> (challenge_this_registration: bool, pow_bits: int)
                Who gets a puzzle at all, and how much proof-of-work is bound to it. The stub challenges
                everyone with no PoW: maximum friction for humans, zero cost for the solver.
  verdict(f) -> ("allow" | "challenge" | "block", reason)
                Evaluated on the retry *after* a correct solve. A solve is evidence that someone (or
                something) answered. It is not evidence that the registration is wanted.

facts (the registration being attempted counts):
    net_type            str    "datacenter" (a published cloud range or hosting ASN) or "residential"
    reg_count_ip        int    registrations from this egress IP in the last 5 minutes
    reg_count_device    int    registrations from this device cookie (`did`) in the last 5 minutes
    solves_by_device_1h int    puzzles this device has solved this hour
    solve_ms            float  time between issue and answer (0 until a puzzle has been solved)
    accessible          bool   the client asked for the text alternative (`"mode": "text"`)

Keep the accessible path: never make `accessible` a risk signal on its own.

How the pieces meet (plumbing, already written): the CHECK below runs on `POST /api/register`. First leg: if
`serve()` says yes it returns a `challenge` verdict naming the `puzzle` type, and the gate answers 403
`challenge_required` with a puzzle whose PoW bits come from `serve()`. Client solves it, posts the answer to
`/api/challenge/verify`, and retries the registration. Second leg: the session holds a one-use clearance,
`verdict()` decides, and a `challenge` there revokes the clearance and asks again.

`python tools/checkpoint.py --round 2 --catch-up` drops in the reference solution.
"""

from .pipeline import Check, Signal, Verdict

POW_BITS_RISKY = 16
IP_CAP = 8
DEVICE_CAP = 2
SOLVE_FLOOR_MS = 800


def facts(ctx, count=True):
    """Plumbing. `count=False` reads the windows without adding this attempt (used to price a puzzle)."""
    from . import netintel
    device = ctx.cookies.get("did") or f"sid-{ctx.session.sid}"
    ip_key, dev_key = f"lab:reg:ip:{ctx.ip}", f"lab:reg:dev:{device}"
    if count:
        by_ip, by_dev = ctx.redis.incr(ip_key), ctx.redis.incr(dev_key)
        ctx.redis.expire(ip_key, 300)
        ctx.redis.expire(dev_key, 300)
    else:
        by_ip, by_dev = int(ctx.redis.get(ip_key) or 1), int(ctx.redis.get(dev_key) or 1)
    body = ctx.json if isinstance(ctx.json, dict) else {**ctx.args, **ctx.form}
    return {"net_type": netintel.net_type(ctx.ip, ctx.edge.asn), "reg_count_ip": by_ip, "reg_count_device": by_dev,
            "solves_by_device_1h": int(ctx.redis.get(f"lab:llm:solves:{device}") or 0),
            "solve_ms": float(ctx.session.get("llm_solve_ms") or 0.0), "accessible": body.get("mode") == "text"}


def serve(f):
    # TODO (Round 2): serve on risk, not to everyone. Something like
    #   risky = f["net_type"] == "datacenter" or f["reg_count_ip"] > 3 or f["reg_count_device"] > 1
    #   return risky, (POW_BITS_RISKY if risky else 0)
    return True, 0


def verdict(f):
    # TODO (Round 2): a solve is not a pass.
    #   reg_count_ip > IP_CAP, reg_count_device > DEVICE_CAP or solves_by_device_1h > DEVICE_CAP -> "block"
    #   solve_ms < SOLVE_FLOOR_MS -> "challenge" (step-up)
    return "allow", "puzzle solved (no policy wired yet)"


def pow_bits(ctx):
    """The proof-of-work bound to a puzzle served to this client (read by the ext when it issues one)."""
    return serve(facts(ctx, count=False))[1]


def _check(ctx):
    from demo_site import gate
    if gate.clearance_valid(ctx, "puzzle"):                      # second leg: a puzzle was just solved
        f = facts(ctx, count=False)
        action, why = verdict(f)
        if action == "block":
            return Verdict("block", signals=(Signal("challenge_policy", "solve_not_a_pass", 90, why),))
        if action == "challenge":
            gate.revoke_clearance(ctx, "puzzle")
            return Verdict("challenge", signals=(Signal("challenge_policy", "step_up", 45, why),), challenge="puzzle")
        # Allowed: say "challenge" once more so the gate's downgrade rule spends the one-use clearance.
        return Verdict("challenge", signals=(Signal("challenge_policy", "solved", 40, why),), challenge="puzzle")
    f = facts(ctx)
    if serve(f)[0]:
        return Verdict("challenge", signals=(Signal("challenge_policy", "puzzle_served", 40,
                                                    f"{f['net_type']}, ip {f['reg_count_ip']}, device {f['reg_count_device']}"),),
                       challenge="puzzle")
    return None


CHECK = Check("challenge_policy", _check, phases=("action:register",))
