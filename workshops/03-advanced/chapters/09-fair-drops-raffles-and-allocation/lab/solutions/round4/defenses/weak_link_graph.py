"""
weak_link_graph (Round 4, reference): merge on evidence, step up at the claim, and re-score after the draw.

Round 3 merged on ANY shared strong key and paid for it: an apartment block, a household and two spouses with
one card were treated as resellers. The fix is not a better key; it is to stop treating one coincidence as proof.

1. THE GRAPH (raffle:draw). Every pair of entries gets points for what they share, on the same 0 to 100 scale as
   every other check. Two entries are the same person or crew when their points reach MERGE_AT (100):

       same inbox (after canon_email)        100     a hard key: one mailbox is one holder
       same card fingerprint                  60
       same address, same unit                50
       same building, different unit          40     "10 Harbour St" has five households in it
       same BIN, when 12+ entries use it      30     a virtual-card batch; ordinary BINs have thousands of users
       created in the same 2-hour batch      40     when 12+ entered accounts were (a script, not a habit)
       entered in the same 10-second burst   30     from one client fingerprint, when 25+ did

   One coincidence never merges (a building is 40, a card is 60, a household's address is 50). A crew that
   shares a building AND a card batch AND a burst does (40 + 30 + 30); so does one that shares a card batch AND
   a creation batch AND a burst (30 + 40 + 30). Then, as in Round 3, one entry
   per cluster survives. The household, the apartment block and the couple are no longer cost.

2. THE CLAIM (action:raffle_claim). A win is not a sale. Three things happen at the moment of payment:
     - the card is not the entry's card (or the entry had none) -> an in-session code (challenge otp_session, 45)
     - the pair ships to a forwarding address (data/reshippers.txt) -> the order is HELD, not refused: honest
       customers use forwarders too
     - the pair ships somewhere the account has not shipped before -> the order is held for review (gifts)
   A hold keeps the unit reserved and the customer waiting. It is friction with a price.

3. THE RE-SCORE (raffle:rescore). After the claims, the claim-time facts exist that did not at the draw. If
   FORWARDER_CONVERGENCE_MIN or more claims ship to forwarders, that is a reseller's pattern: cancel them (the
   units go back, orders.cancel_order), burn their BINs on the waitlist, and let the draw promote the next
   entries. Held orders that do not converge are released: the review found nothing.

What it misses, and Round 4 shows it: paid real people. A reseller that pays 24 strangers to enter with their own
accounts, cards and homes is not a pattern in any of this data. Their entries are genuine; only their intent
isn't. That residual is what no allocation rule removes (limits, identity verification at claim and delivery
audit can shave it; the lab does not model them).

Who it hurts. A gift buyer waits in review; a fan with no saved card is asked for a code; a real forwarder
customer in a convergent batch is cancelled. The report prices each.

Reference for the lesson; the stub is defenses/weak_link_graph.py (or `checkpoint.py --round 4 --catch-up`).
"""

import os
from collections import defaultdict

from .entity_resolution import UnionFind, canon_email, keep_best, split_address, street_key
from .pipeline import Check, Signal, Verdict

MERGE_AT = 100
EMAIL, CARD, ADDRESS, BUILDING, BIN, BATCH, BURST = 100, 60, 50, 40, 30, 40, 30
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
    pts = defaultdict(int)

    def group(keyed, points, min_size=2):
        buckets = defaultdict(list)
        for i, k in keyed:
            buckets[k].append(i)
        for members in buckets.values():
            if len(members) >= min_size:
                for a in range(len(members)):
                    for b in range(a + 1, len(members)):
                        pts[(members[a], members[b])] += points

    group(((i, canon_email(v["email"])) for i, v in enumerate(entries)), EMAIL)
    group(((i, v["card_fp"]) for i, v in enumerate(entries) if v["card_fp"]), CARD)
    group(((i, (street_key(v["line1"], v["city"], v["postcode"]), split_address(v["line1"])[1]))
           for i, v in enumerate(entries)), ADDRESS)
    building = defaultdict(list)                                  # same building, a different unit: the weaker link
    for i, v in enumerate(entries):
        building[street_key(v["line1"], v["city"], v["postcode"])].append(i)
    for members in building.values():
        for a in range(len(members)):
            for b in range(a + 1, len(members)):
                i, j = members[a], members[b]
                if split_address(entries[i]["line1"])[1] != split_address(entries[j]["line1"])[1]:
                    pts[(i, j)] += BUILDING
    group(((i, v["bin6"]) for i, v in enumerate(entries) if v["bin6"]), BIN, BIN_MIN)
    group(((i, int(v["created_ts"] // BATCH_S)) for i, v in enumerate(entries) if v["created_ts"]), BATCH, BATCH_MIN)
    group(((i, (v["ja4"], v["ua"], int(v["t"] // BURST_S))) for i, v in enumerate(entries) if v["ja4"]), BURST, BURST_MIN)
    return pts


def _draw(ctx):
    entries = ctx.attrs.get("entries") or []
    uf = UnionFind(len(entries))
    pts = pair_points(entries)
    for (i, j), p in pts.items():
        if p >= MERGE_AT:
            uf.union(i, j)
    dropped = clusters = 0
    for members in uf.groups():
        if len(members) > 1:
            clusters += 1
            dropped += keep_best(entries, members)
    ctx.note(clusters=clusters, merged_away=dropped, linked_pairs=len(pts), merge_at=MERGE_AT,
             rule="evidence points per pair, merge at 100")
    return None


def _claim(ctx):
    c = ctx.attrs.get("claim")
    if not c:
        return None
    ship, signals = c["ship"], []
    if street_key(ship["line1"], ship["city"], ship["postcode"]) in forwarders():
        ctx.attrs["hold"] = {"reason": "forwarder"}
        signals.append(Signal("claim", "forwarder_ship_to", 30, "the pair ships to a package forwarder"))
    elif ship["new"] and ship["changed"]:
        ctx.attrs["hold"] = {"reason": "new_ship_to"}
        signals.append(Signal("claim", "new_ship_to", 10, "shipping somewhere this account has not shipped before"))
    fresh = "otp_session" in ctx.auth["methods"] and (ctx.auth["age_s"] or 1e9) < OTP_FRESH_S
    if c["card_new"] and not fresh:
        return Verdict("challenge", 45, tuple(signals) + (Signal("claim", "card_not_on_entry", 45, "card differs from the entry's"),),
                       challenge="otp_session")
    return signals or None


def _rescore(ctx):
    entries = ctx.attrs.get("entries") or []
    fwd = forwarders()
    claimed = [v for v in entries if v["status"] in ("claimed", "held")]
    hits = [v for v in claimed if v["claim"] and street_key(v["claim"]["ship"]["line1"], v["claim"]["ship"]["city"],
                                                           v["claim"]["ship"]["postcode"]) in fwd]
    converged = len(hits) >= FORWARDER_CONVERGENCE_MIN
    burned = set()
    if converged:
        for v in hits:
            v["verdict"], v["excluded"] = "cancel", "forwarder_convergence"
            burned.add(v["bin6"])
        for v in entries:
            if v["status"] == "waitlist" and v["bin6"] in burned:
                v["excluded"] = "burned_bin"
    for v in claimed:
        if v["status"] == "held" and v["verdict"] is None and v not in hits:
            v["verdict"] = "release"
    ctx.note(forwarder_claims=len(hits), converged=converged, burned_bins=sorted(burned))
    return None


def _check(ctx):
    if ctx.phase == "raffle:draw":
        return _draw(ctx)
    if ctx.phase == "raffle:rescore":
        return _rescore(ctx)
    return _claim(ctx)


CHECK = Check("weak_link_graph", _check, phases=("raffle:draw", "action:raffle_claim", "raffle:rescore"))
