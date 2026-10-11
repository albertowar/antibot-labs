"""Round 2 defense (YOUR CODE) — what a solved challenge is worth.

The puzzle is dead: attacks/round2_llm_solver.py solves every text puzzle and
every tile grid the gate can produce. The gate itself stays as it is. What you
decide here is the *policy* around it:

  serve(ctx)   -> (challenge_this_registration: bool, pow_bits: int)
                  Who gets a puzzle at all, and how much proof-of-work is bound
                  to it. The stub challenges everyone with no PoW — maximum
                  friction for humans, zero cost for the solver.
  verdict(ctx) -> Decision, evaluated *after* a correct solve.
                  A solve is evidence that someone (or something) answered. It is
                  not evidence that the registration is wanted.

ctx keys (both functions):
    net_type        : str    residential / datacenter / unknown
    reg_count_ip    : int    registrations from this IP in the window (incl. this one)
    fp_cluster      : int    registrations from this device fingerprint in the window
    solves_by_fp_1h : int    puzzles this fingerprint has solved this hour (verdict only)
    solve_ms        : float  time between issue and answer (verdict only)
    accessible      : bool   the client asked for the text alternative

Keep the accessible path: never make ``accessible`` a risk signal on its own.
`python tools/checkpoint.py --round 2 --catch-up` drops in the reference solution.
"""

from __future__ import annotations

from store import allow, Decision

POW_BITS_RISKY = 16
IP_CAP = 2
FP_CAP = 2
SOLVE_FLOOR_MS = 800


def serve(ctx) -> tuple[bool, int]:
    # TODO (Round 2): serve on risk, not to everyone. Something like
    #   risky = net_type == "datacenter" or reg_count_ip > 1 or fp_cluster > 1
    #   return risky, (POW_BITS_RISKY if risky else 0)
    return True, 0


def verdict(ctx) -> Decision:
    # TODO (Round 2): a solve is not a pass.
    #   reg_count_ip > IP_CAP or fp_cluster > FP_CAP or solves_by_fp_1h > FP_CAP -> block
    #   solve_ms < SOLVE_FLOOR_MS -> challenge (step-up: e-mail verification)
    return allow("puzzle solved (no policy wired yet)")
