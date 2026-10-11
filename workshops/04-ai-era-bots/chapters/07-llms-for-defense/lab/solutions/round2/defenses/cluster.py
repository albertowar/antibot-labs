"""
W4 Chapter 7 — Clustering and pre-filtering  [STUDENT FILE: prefilter, cluster_key]

cluster_sig() and clusters_of() are given: the rulesmith uses them to group
flagged sessions. What Round 3b needs you to write is the pair that keeps a
flood from costing one model call per session:

  prefilter(cards)   drop sessions no rule could act on
  cluster_key(cards) group by SHAPE (not random bytes) and return
                     (representatives, members)

Until you implement them, triage --cluster still calls the model once per
session, so the flood costs exactly what the attacker wants.
"""

import re

from sessionize import flatten

UA_FAMILY = re.compile(r"(HeadlessChrome|Chrome|Firefox|Safari|python|httpx|curl|wget|scrapy|bot)", re.I)


def _len_bucket(n):
    return "s" if n < 64 else "m" if n < 256 else "l" if n < 1024 else "xl"


def _charset(s):
    s = s or ""
    if re.fullmatch(r"[A-Za-z0-9+/=]{20,}", s):
        return "b64ish"
    if len(set(s)) > 40 and " " not in s[:40]:
        return "random"
    return "normal"


def _ua_family(ua):
    m = UA_FAMILY.search(ua or "")
    return m.group(1).lower() if m else "other"


def cluster_sig(card):
    """A shape signature built only from structural features (given)."""
    flat = flatten(card)
    return "|".join([
        flat["asn_type"], _ua_family(flat["ua"]),
        _len_bucket(len(flat["ua"] or "")), _charset(flat["ua"]),
        f"p{flat['n_pages']}", f"a{1 if flat['n_assets'] else 0}",
        "hp" if flat["honeypot_hit"] else "-",
        "/".join(p.rstrip("0123456789") for p in flat["paths"][:4]),
    ])


def clusters_of(cards):
    """{signature: [(sid, card), ...]} (given; used by rulesmith)."""
    groups = {}
    for sid, card in cards:
        groups.setdefault(cluster_sig(card), []).append((sid, card))
    return groups


def prefilter(cards):
    """Keep only sessions a rule could plausibly act on.

    TODO (Round 3): drop the obviously non-actionable ones (for example a
    single request that never reached the cart). Return the survivors.
    For now: keep everything.
    """
    return cards


def cluster_key(cards):
    """Return (representatives, members): one card per shape, plus the rest.

    TODO (Round 3): group the cards by cluster_sig(card). For each group pick
    one representative to send to the model; the others inherit its verdict.
    Return (list_of_representatives, {rep_sid: [(sid, card), ...]}).
    For now: every session is its own cluster (no savings).
    """
    return [(s, c) for s, c in cards], {}


if __name__ == "__main__":
    import sys
    from sessionize import cards_for_run
    from store import make_engine
    run = sys.argv[1] if len(sys.argv) > 1 else "simulate-1"
    with make_engine().connect() as conn:
        cards = cards_for_run(conn, run)
    reps, members = cluster_key(prefilter(cards))
    print(f"{run}: {len(cards)} sessions -> {len(reps)} clusters (stub = one per session)")
