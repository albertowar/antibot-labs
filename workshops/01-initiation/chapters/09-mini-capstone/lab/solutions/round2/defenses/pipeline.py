"""
W1 Ch9 — The gate: which layers run, and in what order. (reference: end of Round 2)

The store calls ladder.run_gate(ctx, LAYERS, CHALLENGE_ENABLED) on every
request. Each layer returns Signals on the 0-100 scale; the ladder adds them
up and picks allow / monitor / challenge / block (bands in policy.py).

Order matters for cost, not for the verdict: the sum is the same in any
order, but a rate-limit hit stops the gate before the slower layers run.
Cheapest and most certain first: rate limit, traps, headers, IP, session.

After editing, restart the store (Ctrl+C, then python demo_site/app.py), and
check where you are:
    python tools/checkpoint.py --round N
Fell behind? Install the reference version of this file for round N, then
restart the store:
    python tools/checkpoint.py --round N --catch-up
"""

# Every layer is imported for you; LAYERS below decides which ones run.
import headers  # noqa: F401
import ip_reputation  # noqa: F401
import rate_limit  # noqa: F401
import session_guard  # noqa: F401
import traps  # noqa: F401

LAYERS = [
    rate_limit.check,
    headers.check,
    ip_reputation.check,
]

CHALLENGE_ENABLED = False

PURCHASES_PER_SESSION = None
