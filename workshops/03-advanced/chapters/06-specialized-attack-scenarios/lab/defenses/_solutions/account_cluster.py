"""Round 4 defense (REFERENCE SOLUTION) — registration anti-farming.

Economic chokepoint: the farm needs *many* accounts cheaply. Each account looks
fine alone; the signal is in the cluster and the velocity. Three cheap signals,
each attacking a cost the farm tried to avoid:
  1. disposable email domain      -> the farm dodged real inboxes (BLOCK)
  2. too many registrations per IP/egress in the window -> velocity (BLOCK)
  3. one fingerprint minting many accounts -> device reuse across the farm (BLOCK)

False positive, named honestly: universities, offices and CGNAT put thousands of
real people behind one egress, and privacy browsers make many real users share a
fingerprint. Per-IP and per-fingerprint caps hit them first. Treat these as
scoring signals feeding a step-up (email/phone verification), not a hard block, and
set thresholds from your real per-IP registration distribution.
"""

from __future__ import annotations

from store import allow, block, challenge, Decision

IP_CAP = 3    # registrations per egress per window
FP_CAP = 2    # accounts per fingerprint per window


def evaluate(ctx) -> Decision:
    if ctx["disposable"]:
        return block("disposable email domain", score=100.0)
    if ctx["reg_count_ip"] > IP_CAP:
        return block(f"{ctx['reg_count_ip']} registrations from this egress", score=90.0)
    if ctx["fp_cluster"] > FP_CAP:
        return challenge(f"fingerprint minted {ctx['fp_cluster']} accounts", score=80.0)
    return allow("plausible new account")
