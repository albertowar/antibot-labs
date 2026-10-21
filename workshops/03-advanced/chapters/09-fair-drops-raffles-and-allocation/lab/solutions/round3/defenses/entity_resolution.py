"""
entity_resolution (Round 3, reference): one entry per person, decided over the whole entry list.

Rounds 1 and 2 judged each entry alone. A raffle gives the defender something a first-come sale never does:
every entry, side by side, before anything is awarded. Entity resolution asks "which of these entries are the
same person?" by comparing what the entries share, then keeps one per person.

The comparison needs NORMALIZED keys, because the cheapest cheat is spelling:

  email      "m.arlowe+9@gmail.example" and "marlowe@gmail.example" are one inbox. Gmail ignores dots and
             "+tag"; so does this check (canon_email) for the domains in GMAIL_LIKE. The lab treats a "+tag" as
             removable everywhere, which is a trade-off: on a provider that treats "+" literally it merges two
             real people.
  address    "3 Pier Avenue Apt 7", "3 Pier Ave #12", "3 Pier Ave., Unit 31" are one building. USPS
             Publication 28 (section 213, Appendix C2) fixes the secondary-unit words (APT, UNIT, STE, FL,
             RM, BLDG ...) and says the pound sign is discouraged; split_address maps them to one form and
             street_key keeps only the street part. (Pub 28 is a printing standard; using it to compare is this
             check's own technique.)
  card       the fingerprint of the card number: the same card is one payer.

Entries that share a key are linked, and a union-find turns the links into clusters. ONE ENTRY PER CLUSTER: the
best member (most paid orders, then oldest account) stays; the rest are excluded with reason "cluster:<id>".
That is also the household rule, stated plainly: one entry per household.

What it catches: the aged farm (one drop address) and the jig farm (a hundred spellings of one building and five
mailboxes). A hundred entries become a handful.
What it costs, and Round 3 shows it: the rule cannot tell a jig from a real building. Five unrelated people in
10 Harbour Street, three people in one household and two partners sharing a card are each ONE cluster. Four
neighbours, six family members and two spouses lose their entries to a rule that was aimed at a reseller.
What it misses: a crew with genuinely different mailboxes, addresses and cards. Round 4's graph takes that.

Reference for the lesson; the stub is defenses/entity_resolution.py (or `checkpoint.py --round 3 --catch-up`).
From Round 4 on, defenses/weak_link_graph.py replaces this check's merge rule (it reuses these helpers).
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
    local, _, domain = str(email).strip().lower().partition("@")
    local = local.split("+", 1)[0]
    if domain in GMAIL_LIKE:
        local = local.replace(".", "")
    return f"{local}@{domain}"


def split_address(line1):
    """("10 HARBOUR ST", "APT 1"): the street part with its suffix abbreviated, and the unit part (maybe '')."""
    toks = re.sub(r"[^\w\s]", " ", str(line1).upper().replace("#", " UNIT ")).split()
    street, unit, in_unit = [], [], False
    for t in toks:
        if not in_unit and t in UNITS:
            in_unit = True
            unit.append(UNITS[t])
        elif in_unit:
            unit.append(t)
        else:
            street.append(SUFFIXES.get(t, t))
    return " ".join(street), " ".join(unit)


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
    best = max(members, key=lambda i: (entries[i]["paid_orders"], entries[i]["age_days"], -entries[i]["id"]))
    cid = f"c{min(entries[i]['id'] for i in members)}"
    for i in members:
        entries[i]["cluster"] = cid
        if i != best:
            entries[i]["excluded"] = f"{reason}:{cid}"
    return len(members) - 1


def _draw(ctx):
    if ctx.level >= GRAPH_LEVEL:
        return None
    entries = ctx.attrs.get("entries") or []
    uf = UnionFind(len(entries))
    first = {}
    for i, v in enumerate(entries):
        keys = [("email", canon_email(v["email"])), ("addr", street_key(v["line1"], v["city"], v["postcode"]))]
        if v["card_fp"]:
            keys.append(("card", v["card_fp"]))
        for k in keys:
            if k in first:
                uf.union(first[k], i)
            else:
                first[k] = i
    dropped = clusters = 0
    for members in uf.groups():
        if len(members) > 1:
            clusters += 1
            dropped += keep_best(entries, members)
    ctx.note(clusters=clusters, merged_away=dropped, rule="any shared email, card or building")
    return None


CHECK = Check("entity_resolution", _draw, phases=("raffle:draw",))
