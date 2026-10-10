"""Round 4 defense (YOUR CODE) — registration anti-farming.

attacks/round4_account_farm.py registers accounts in bulk with disposable inboxes
and fresh contexts. Any single registration looks real; the signal is the cluster.

ctx keys:
    disposable    : bool -- is the email on the disposable-domain blocklist?
    reg_count_ip  : int  -- registrations from this egress in the window
    fp_cluster    : int  -- accounts this fingerprint has minted in the window
    email_domain  : str

Return BLOCK or CHALLENGE (email/phone verification) when a registration is part of
a farm. `python tools/checkpoint.py --round 4 --catch-up` drops in the solution.
"""

from __future__ import annotations

from store import allow, Decision

IP_CAP = 3
FP_CAP = 2


def evaluate(ctx) -> Decision:
    # TODO (Round 4):
    #   1. ctx["disposable"]              -> block
    #   2. ctx["reg_count_ip"] > IP_CAP   -> block  (egress velocity)
    #   3. ctx["fp_cluster"] > FP_CAP     -> challenge (device reuse)
    return allow("account created (no cluster checks wired yet)")
