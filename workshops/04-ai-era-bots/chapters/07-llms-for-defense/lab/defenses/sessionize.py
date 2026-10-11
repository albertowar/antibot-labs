"""
W4 Chapter 7 — The session card: ONE summary for the analyst, the rules and the gate

Everything downstream reads a session through this module: the heuristic,
the LLM prompt, the live rule engine at /checkout and the gate's replay. If
the prompt saw one summary and the rule engine another, a rule that looked
safe in replay could block people live (train/serve skew). So there is one
function, and it always summarizes the requests *before* checkout.

A card is nested JSON for readability. `flatten()` gives the flat field
names from defenses/fields.py that rules and verdict reasons refer to.

Durations are divided by LAB_TIME_SCALE so they read as real seconds. The
LLM's own latency is wall-clock and is never scaled.
"""

import hashlib
import statistics
from urllib.parse import urlparse

from sqlalchemy import select

from fields import CAPS
from netinfo import lookup
from store import LAB_TIME_SCALE, accounts_t, logins_t, requests_t, sessions_t

HONEYPOT_PATHS = ("/specials-archive",)
API_V0 = "/api/v0/"
MAX_PATHS = 12
MAX_REFERERS = 3


def short_id(sid):
    return hashlib.sha1(str(sid).encode()).hexdigest()[:8]


def _is_local(url):
    host = urlparse(url).hostname
    return host in ("localhost", "127.0.0.1", "::1")


def card_from_rows(sid, rows, login_account=None):
    """Build a card from request rows (dicts) ordered by ts; stops at /checkout."""
    pre = []
    for r in rows:
        if r["path"] == "/checkout" and r["method"] == "POST":
            break
        pre.append(r)
    rows = pre or rows[:1]
    ip = rows[0]["ip"] if rows else ""
    net = lookup(ip)
    ua = next((r["ua"] for r in rows if r["ua"]), "")
    lang = next((r["accept_language"] for r in rows if r["accept_language"]), "")
    referers, paths = [], []
    for r in rows:
        ref = r["referer"] or ""
        if ref and not _is_local(ref) and ref not in referers:
            referers.append(ref)
        if not r["is_asset"] and (not paths or paths[-1] != r["path"]):
            paths.append(r["path"])
    pages = [r for r in rows if not r["is_asset"]]
    assets = [r for r in rows if r["is_asset"]]
    ts = [r["ts"] for r in rows]
    gaps = [(b - a) / LAB_TIME_SCALE for a, b in zip(ts, ts[1:]) if b > a]
    return {
        "id": short_id(sid),
        "net": {"asn": net["asn"], "asn_type": net["asn_type"], "country": net["country"]},
        "client": {"user_agent": ua, "accept_language": lang,
                   "referers": referers[:MAX_REFERERS]},
        "requests": {
            "n": len(rows), "pages": len(pages), "assets": len(assets),
            "asset_ratio": round(len(assets) / len(rows), 2) if rows else 0.0,
            "errors_4xx": sum(1 for r in rows if 400 <= (r["status"] or 0) < 500),
            "duration_s": round((ts[-1] - ts[0]) / LAB_TIME_SCALE, 1) if len(ts) > 1 else 0.0,
            "median_gap_s": round(statistics.median(gaps), 2) if gaps else 0.0,
            "honeypot_hit": any(r["path"] in HONEYPOT_PATHS for r in rows),
            "api_v0_hit": any(str(r["path"]).startswith(API_V0) for r in rows),
            "reached_cart": any(r["path"] == "/cart/add" for r in rows),
        },
        "paths": paths[:MAX_PATHS],
        "login": {"account": login_account},
    }


def card_for_sid(conn, sid):
    rows = conn.execute(select(requests_t).where(requests_t.c.sid == sid)
                        .order_by(requests_t.c.ts, requests_t.c.id)).mappings().all()
    if not rows:
        return None
    acct = conn.execute(select(logins_t.c.account).where(logins_t.c.sid == sid)
                        .order_by(logins_t.c.ts)).scalar()
    return card_from_rows(sid, [dict(r) for r in rows], acct)


def sids_for_run(conn, run):
    return [r[0] for r in conn.execute(select(sessions_t.c.sid).where(sessions_t.c.run == run)
                                       .order_by(sessions_t.c.first_ts))]


def cards_for_run(conn, run, limit=None):
    sids = sids_for_run(conn, run)
    if limit:
        sids = sids[:limit]
    out = []
    for sid in sids:
        card = card_for_sid(conn, sid)
        if card:
            out.append((sid, card))
    return out


def verified_sids(conn):
    """Sessions that logged into a long-standing account: the gate's legit cohort.

    Deliberately NOT ground truth. It is what production has: customers you
    already trust. It under-represents people who rarely log in (privacy
    browsers, VPN users), which is exactly the bias the gate inherits.
    """
    q = (select(logins_t.c.sid).join(accounts_t, accounts_t.c.account == logins_t.c.account)
         .where(accounts_t.c.orders >= 3, accounts_t.c.age_days >= 120))
    return sorted({r[0] for r in conn.execute(q)})


def flatten(card):
    r, c, n = card["requests"], card["client"], card["net"]
    return {
        "ua": c["user_agent"], "accept_language": c["accept_language"],
        "referers": list(c["referers"]), "paths": list(card["paths"]),
        "account": card["login"]["account"],
        "asn": n["asn"], "asn_type": n["asn_type"], "country": n["country"],
        "n_requests": r["n"], "n_pages": r["pages"], "n_assets": r["assets"],
        "asset_ratio": r["asset_ratio"], "errors_4xx": r["errors_4xx"],
        "duration_s": r["duration_s"], "median_gap_s": r["median_gap_s"],
        "honeypot_hit": r["honeypot_hit"], "api_v0_hit": r["api_v0_hit"],
        "reached_cart": r["reached_cart"], "logged_in": card["login"]["account"] is not None,
    }


def untrusted_text(card):
    """The client-written strings in a card, in a fixed order (ua, referers, paths, account)."""
    c = card["client"]
    parts = [c["user_agent"], c["accept_language"], *c["referers"], *card["paths"]]
    if card["login"]["account"]:
        parts.append(card["login"]["account"])
    return [p for p in parts if p]


def chars(card):
    """Size of the untrusted text, the part a flood inflates."""
    return sum(len(p) for p in untrusted_text(card))


if __name__ == "__main__":
    import json
    import sys
    from store import make_engine
    with make_engine().connect() as conn:
        run = sys.argv[1] if len(sys.argv) > 1 else "simulate-1"
        for sid, card in cards_for_run(conn, run, limit=2):
            print(json.dumps(card, indent=1))
        print(f"\nverified sessions: {len(verified_sids(conn))}  (caps: {CAPS})")
