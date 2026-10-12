"""Round 2 defense (REFERENCE SOLUTION) — what a solved challenge is worth.

Three moves, none of which make the puzzle harder (that race is lost):

1. **Serve on risk.** Only a registration with a risk signal — datacenter egress,
   a repeated IP, a repeated device — sees a puzzle. Everyone else registers with
   no friction. This is where the human cost goes from "everyone" to "a few".
2. **Bind a cost to it.** A risky registration carries POW_BITS_RISKY bits of
   hashcash on the token (W1 Ch6). It does not stop a solver; it meters it. At 16
   bits that is ~65k hashes, ~30-60 ms of CPU per solve in Python; tune it to
   the attacker's margin, not to zero.
3. **A solve is not a pass.** After a correct answer the same velocity caps still
   apply, and a solve faster than a person can read the puzzle gets a step-up
   (e-mail verification) rather than an account. The pace floor is weak on its
   own — a solver adds `sleep()` — so it is a CHALLENGE, never a BLOCK.

False positives, named honestly: CGNAT and shared campus egress trip
``reg_count_ip`` for real people; that is why they get a puzzle (recoverable) and
only the third one in the window is refused. Set the caps from your own
registrations-per-IP distribution. A household signing up two accounts on one
laptop is ``fp_cluster == 2``: challenged, not blocked.
"""

from __future__ import annotations

from store import allow, block, challenge, Decision

POW_BITS_RISKY = 16
IP_CAP = 2
FP_CAP = 2
SOLVE_FLOOR_MS = 800


def serve(ctx) -> tuple[bool, int]:
    risky = (ctx["net_type"] == "datacenter" or ctx["reg_count_ip"] > 1
             or ctx["fp_cluster"] > 1)
    return risky, (POW_BITS_RISKY if risky else 0)


def verdict(ctx) -> Decision:
    if ctx["reg_count_ip"] > IP_CAP:
        return block(f"registration velocity per egress IP: {ctx['reg_count_ip']}", score=90.0)
    if ctx["fp_cluster"] > FP_CAP or ctx["solves_by_fp_1h"] > FP_CAP:
        return block(f"device cluster: {max(ctx['fp_cluster'], ctx['solves_by_fp_1h'])} "
                     f"registrations/solves from one fingerprint", score=85.0)
    if ctx["solve_ms"] < SOLVE_FLOOR_MS:
        return challenge(f"solved in {ctx['solve_ms']:.0f} ms, faster than a person reads: "
                         f"step-up (e-mail verification)", score=50.0)
    return allow("solved, identity within caps")
