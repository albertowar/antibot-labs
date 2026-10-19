"""
Round 2 defense (REFERENCE SOLUTION): what a solved challenge is worth.

The puzzle is dead: the LLM/VLM solver answers every text puzzle and every tile grid the gate can
produce. Three moves, none of which make the puzzle harder (that race is lost):

1. **Serve on risk.** Only a registration with a risk signal (datacenter egress, a busy IP, a repeated
   device) sees a puzzle. Everyone else registers with no friction. This is where the human cost goes from
   "everyone" to "a few".
2. **Bind a cost to it.** A risky registration carries POW_BITS_RISKY bits of hashcash on the token
   (W1 Ch6). It does not stop a solver; it meters it. At 16 bits that is ~65k hashes, tens of milliseconds
   of CPU per solve in Python; tune it to the attacker's margin, not to zero.
3. **A solve is not a pass.** After a correct answer the same velocity caps still apply, and a solve
   faster than a person can read the puzzle gets a step-up rather than an account. The pace floor is weak
   on its own (a solver adds `sleep()`), so it is a CHALLENGE, never a BLOCK.

False positives, named honestly: CGNAT and shared campus egress trip `reg_count_ip` for real people; that
is why they get a puzzle (recoverable) and only a flood from one address is refused. Set the caps from
your own registrations-per-IP distribution. A household signing up two accounts on one laptop is
`reg_count_device == 2`: challenged, not blocked.

facts: see challenge_policy.py in lab/defenses/ (the stub documents them).

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
    risky = f["net_type"] == "datacenter" or f["reg_count_ip"] > 3 or f["reg_count_device"] > 1
    return risky, (POW_BITS_RISKY if risky else 0)


def verdict(f):
    if f["reg_count_ip"] > IP_CAP:
        return "block", f"registration velocity per egress IP: {f['reg_count_ip']}"
    if f["reg_count_device"] > DEVICE_CAP or f["solves_by_device_1h"] > DEVICE_CAP:
        return "block", f"device cluster: {max(f['reg_count_device'], f['solves_by_device_1h'])} registrations/solves from one device"
    if f["solve_ms"] < SOLVE_FLOOR_MS:
        return "challenge", f"solved in {f['solve_ms']:.0f} ms, faster than a person reads: step-up"
    return "allow", "solved, identity within caps"


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
