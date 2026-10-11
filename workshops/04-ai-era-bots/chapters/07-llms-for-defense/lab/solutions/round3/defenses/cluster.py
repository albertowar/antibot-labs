"""
W4 Chapter 7 — Clustering and pre-filtering: don't pay the model per session

A flood is thousands of sessions that differ only in random header bytes.
Triaging each one is exactly the bill the attacker wants you to pay (OWASP
LLM10). Two cheap, deterministic steps cut it down:

  prefilter(cards)   drop sessions there is no point asking a model about:
                     a one-request touch with no cart, nothing a rule could
                     act on. Returns the cards still worth triaging.

  cluster_key(cards) group the rest by a shape signature built only from
                     trusted/structural features (ASN, UA family, length
                     bucket, path signature, charset class). Returns
                     (representatives, members): one card per cluster to send
                     to the model, and the sessions each representative stands
                     for, which inherit its verdict.

The signature must NOT include the random bytes the flood varies, or every
session lands in its own cluster and you have saved nothing. That is the
whole exercise.
"""

import re

from sessionize import flatten

UA_FAMILY = re.compile(r"(HeadlessChrome|Chrome|Firefox|Safari|python|httpx|curl|wget|scrapy|bot)", re.I)


def _len_bucket(n):
    if n < 64:
        return "s"
    if n < 256:
        return "m"
    if n < 1024:
        return "l"
    return "xl"


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
    flat = flatten(card)
    return "|".join([
        flat["asn_type"], _ua_family(flat["ua"]),
        _len_bucket(len(flat["ua"] or "")), _charset(flat["ua"]),
        f"p{flat['n_pages']}", f"a{1 if flat['n_assets'] else 0}",
        "hp" if flat["honeypot_hit"] else "-",
        "/".join(p.rstrip("0123456789") for p in flat["paths"][:4]),
    ])


def prefilter(cards):
    """Keep sessions a rule could plausibly act on."""
    keep = []
    for sid, card in cards:
        r = card["requests"]
        if r["n"] <= 1 and not r["reached_cart"]:
            continue   # a single touch with no cart: nothing to decide
        keep.append((sid, card))
    return keep


def cluster_key(cards):
    """Return (representatives, members). One representative per shape."""
    groups = {}
    for sid, card in cards:
        groups.setdefault(cluster_sig(card), []).append((sid, card))
    reps, members = [], {}
    for sig, items in groups.items():
        rep_sid, rep_card = items[0]
        reps.append((rep_sid, rep_card))
        members[rep_sid] = items[1:]
    return reps, members


def clusters_of(cards):
    """{signature: [(sid, card), ...]} — used by rulesmith and the --flagged view."""
    groups = {}
    for sid, card in cards:
        groups.setdefault(cluster_sig(card), []).append((sid, card))
    return groups


if __name__ == "__main__":
    import sys
    from sessionize import cards_for_run
    from store import make_engine
    run = sys.argv[1] if len(sys.argv) > 1 else "simulate-1"
    with make_engine().connect() as conn:
        cards = cards_for_run(conn, run)
    kept = prefilter(cards)
    reps, members = cluster_key(kept)
    print(f"{run}: {len(cards)} sessions → {len(kept)} after prefilter → {len(reps)} clusters")
    for sid, card in reps[:8]:
        print(f"  {cluster_sig(card):<60} ×{1 + len(members.get(sid, []))}")
