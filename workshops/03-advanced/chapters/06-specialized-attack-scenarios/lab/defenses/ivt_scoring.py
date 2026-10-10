"""Round 5 defense (YOUR CODE) — invalid-traffic (IVT) scoring.

attacks/round5_click_fraud.py floods the ad click tracker. The naive flood is
General Invalid Traffic (GIVT): datacenter, no referrer, junk UA. The --sivt
variant is Sophisticated Invalid Traffic: it sends an impression first and spoofs a
residential, well-dressed request, but its engagement funnel is hollow.

ctx keys:
    net_type          : str   -- "datacenter" / "residential" / "unknown"
    user_agent        : str
    referrer          : str
    had_impression    : bool  -- a matching impression earlier this session?
    dwell_ms          : float -- impression -> click gap
    clicks_in_session : int

Return BLOCK for invalid traffic, ALLOW for a valid click. Tag the reason "givt:..."
or "sivt:..." so the scoreboard can split the two tiers.
`python tools/checkpoint.py --round 5 --catch-up` drops in the reference solution.
"""

from __future__ import annotations

from store import allow, Decision

MIN_DWELL_MS = 400
CLICK_CAP = 8


def evaluate(ctx) -> Decision:
    # TODO (Round 5): GIVT hard filters first (datacenter / bad UA / no referrer),
    # then SIVT funnel checks (no impression / near-zero dwell / click velocity).
    return allow("counted (no IVT checks wired yet)")
