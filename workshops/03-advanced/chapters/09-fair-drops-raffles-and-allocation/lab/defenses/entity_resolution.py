"""
entity_resolution (Round 3): one entry per person, decided over the whole entry list.

Rounds 1 and 2 judged each entry alone. A raffle lets the defender see every entry side by side before anything
is awarded. Entity resolution asks "which of these entries are the same person?" by comparing what they share,
then keeps one per person. The comparison needs NORMALIZED keys, because the cheapest cheat is spelling:

  email    "m.arlowe+9@gmail.example" and "marlowe@gmail.example" are one inbox. Gmail ignores dots and "+tag"
           (Gmail Help: "Dots don't matter in Gmail addresses"); the lab's Gmail-like domains are GMAIL_LIKE.
  address  "3 Pier Avenue Apt 7", "3 Pier Ave #12", "3 Pier Ave., Unit 31" are one building. USPS Publication 28
           (section 213, Appendix C2) fixes the secondary-unit words (APT, UNIT, STE, FL, RM, BLDG ...) and
           discourages "#". Map them to one form and keep only the street part (the UNITS and SUFFIXES tables).
  card     ctx.attrs["entries"][i]["card_fp"]: the same card is one payer.

Link the entries that share a key (a union-find), and keep ONE ENTRY PER CLUSTER: the best member (most paid
orders, then the oldest account) stays; the rest get v["excluded"] = "cluster:<id>" and every member gets
v["cluster"] = <id>. That is the household rule, stated plainly: one entry per household.

Run Round 3 and count both columns: the crews it collapses, and the real people it collapses with them.

From Round 4 on, defenses/weak_link_graph.py replaces this merge rule (and reuses your helpers), so the check
steps aside at GRAPH_LEVEL.

Reference: solutions/round3/defenses/entity_resolution.py (or `checkpoint.py --round 3 --catch-up`)
"""

import re

from .pipeline import Check

GMAIL_LIKE = ("gmail.com", "googlemail.com", "gmail.example")
GRAPH_LEVEL = 4                        # from here the weighted graph decides; this check steps aside

UNITS = {"APARTMENT": "APT", "APT": "APT", "BUILDING": "BLDG", "BLDG": "BLDG", "DEPARTMENT": "DEPT", "DEPT": "DEPT",
         "FLOOR": "FL", "FL": "FL", "ROOM": "RM", "RM": "RM", "SUITE": "STE", "STE": "STE", "UNIT": "UNIT"}
SUFFIXES = {"STREET": "ST", "ST": "ST", "AVENUE": "AVE", "AVE": "AVE", "ROAD": "RD", "RD": "RD", "LANE": "LN", "LN": "LN",
            "COURT": "CT", "CT": "CT", "DRIVE": "DR", "DR": "DR", "BOULEVARD": "BLVD", "BLVD": "BLVD",
            "PARKWAY": "PKWY", "PKWY": "PKWY"}


def canon_email(email):
    """One inbox, one string: lower-case, drop "+tag", and drop the dots of a Gmail-like local part."""
    # TODO (Round 3)
    return str(email).strip().lower()


def split_address(line1):
    """("10 HARBOUR ST", "APT 1"): the street part with its suffix abbreviated, and the unit part (maybe '')."""
    # TODO (Round 3): upper-case, "#" -> UNIT, punctuation out; the first UNITS word starts the unit part;
    #   street words go through SUFFIXES.
    return str(line1).upper(), ""


def street_key(line1, city, postcode):
    """The building: street part, city and postcode, with the unit left out."""
    street, _ = split_address(line1)
    return f"{street}|{str(city).strip().upper()}|{str(postcode).strip()}"


class UnionFind:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, i):
        while self.p[i] != i:
            self.p[i] = self.p[self.p[i]]
            i = self.p[i]
        return i

    def union(self, i, j):
        ri, rj = self.find(i), self.find(j)
        if ri != rj:
            self.p[max(ri, rj)] = min(ri, rj)

    def groups(self):
        out = {}
        for i in range(len(self.p)):
            out.setdefault(self.find(i), []).append(i)
        return list(out.values())


def keep_best(entries, members, reason="cluster"):
    """Mark every member of a cluster but the best one as excluded. Returns how many were dropped."""
    # TODO (Round 3): best = most paid_orders, then oldest age_days, then lowest id. cid = "c<lowest id>".
    return 0


def _draw(ctx):
    if ctx.level >= GRAPH_LEVEL:
        return None
    entries = ctx.attrs.get("entries") or []
    # TODO (Round 3): union entries that share canon_email, street_key or card_fp; keep_best per cluster;
    #   ctx.note(clusters=..., merged_away=..., rule="any shared email, card or building")
    return None


CHECK = Check("entity_resolution", _draw, phases=("raffle:draw",))
