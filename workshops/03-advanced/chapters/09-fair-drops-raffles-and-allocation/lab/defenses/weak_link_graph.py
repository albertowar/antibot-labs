"""
weak_link_graph (Round 4): merge on evidence, step up at the claim, and re-score after the draw.

Round 3 merged on ANY shared strong key and paid for it: an apartment block, a household and two spouses with
one card were treated as resellers. The fix is not a better key; it is to stop treating one coincidence as proof.

1. THE GRAPH (raffle:draw). Give every pair of entries points for what they share and merge at MERGE_AT (100):

       same inbox (canon_email)               100
       same card fingerprint                   60
       same address, same unit                 50
       same building, different unit           30
       same BIN, when BIN_MIN+ entries use it  30     a virtual-card batch; ordinary BINs have thousands of users
       created in the same 2-hour batch        40     when BATCH_MIN+ entered accounts were
       entered in the same 10-second burst     30     from one client (ja4, ua), when BURST_MIN+ did

   One coincidence never merges; a card batch plus a creation batch plus a burst does. Then keep one entry per
   cluster (keep_best from Round 3).

2. THE CLAIM (action:raffle_claim), facts in ctx.attrs["claim"] (card_new, ship.new, ship.changed, ship.line1/city/
   postcode):
     - the card is not the entry's card         -> Verdict("challenge", 45, ..., challenge="otp_session") unless
                                                   ctx.auth shows a fresh "otp_session" (OTP_FRESH_S)
     - ships to a forwarder (data/reshippers.txt) -> ctx.attrs["hold"] = {"reason": "forwarder"}: HOLD, do not refuse
     - ships to a new address the entry did not use -> hold for review ("new_ship_to"): gifts look like this

3. THE RE-SCORE (raffle:rescore). entries carry v["status"] and v["claim"]. If FORWARDER_CONVERGENCE_MIN or more
   claims ship to forwarders, cancel them (v["verdict"] = "cancel", v["excluded"] = "forwarder_convergence"), burn
   their BINs on the waitlist (v["excluded"] = "burned_bin"), and release the other held orders
   (v["verdict"] = "release").

Run Round 4 and read the three costs (a hold, a code, a cancelled forwarder customer) next to what is left: the
crowd of paid real people, whose entries are genuine.

Reference: solutions/round4/defenses/weak_link_graph.py (or `checkpoint.py --round 4 --catch-up`)
"""

import os

from .entity_resolution import UnionFind, canon_email, keep_best, split_address, street_key
from .pipeline import Check, Signal, Verdict

MERGE_AT = 100
EMAIL, CARD, ADDRESS, BUILDING, BIN, BATCH, BURST = 100, 60, 50, 30, 30, 40, 30
BIN_MIN, BATCH_MIN, BURST_MIN = 12, 12, 25
BATCH_S, BURST_S = 7200, 10
FORWARDER_CONVERGENCE_MIN = 3
OTP_FRESH_S = 900
HERE = os.path.dirname(os.path.abspath(__file__))
_forwarders = {}


def forwarders():
    if not _forwarders:
        with open(os.path.join(HERE, "..", "data", "reshippers.txt")) as fh:
            for ln in fh:
                if ln.strip() and not ln.startswith("#"):
                    street, city, post = [x.strip() for x in ln.split(",")]
                    _forwarders[street_key(street, city, post)] = ln.strip()
    return set(_forwarders)


def pair_points(entries):
    """{(i, j): points}: the evidence between every pair that shares anything."""
    # TODO (Round 4): group entries by each key above (the crowd-sized ones only when the group reaches its
    #   minimum) and add the points for every pair in a group. Same building but a different unit is BUILDING.
    return {}


def _draw(ctx):
    entries = ctx.attrs.get("entries") or []
    # TODO (Round 4): union the pairs at MERGE_AT or more, keep_best per cluster, and
    #   ctx.note(clusters=..., merged_away=..., linked_pairs=..., merge_at=MERGE_AT, rule="...")
    return None


def _claim(ctx):
    c = ctx.attrs.get("claim")
    if not c:
        return None
    # TODO (Round 4): the three claim rules above. Return a list of Signals, a Verdict, or None.
    return None


def _rescore(ctx):
    entries = ctx.attrs.get("entries") or []
    # TODO (Round 4): forwarder convergence -> cancel and burn; the other held orders -> release.
    return None


def _check(ctx):
    if ctx.phase == "raffle:draw":
        return _draw(ctx)
    if ctx.phase == "raffle:rescore":
        return _rescore(ctx)
    return _claim(ctx)


CHECK = Check("weak_link_graph", _check, phases=("raffle:draw", "action:raffle_claim", "raffle:rescore"))
