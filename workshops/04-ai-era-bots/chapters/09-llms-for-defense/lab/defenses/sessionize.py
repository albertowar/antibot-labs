"""
W4 Ch9 — The session card: ONE summary for the analyst, the rules and the gate

Everything downstream reads a session through this module: the heuristic, the
LLM prompt, the live rule check at checkout and the gate's replay. If the
prompt saw one summary and the rule engine another, a rule that looked safe in
replay could block people live (train/serve skew). So there is one function,
and it always summarizes the requests *before* the checkout.

A card is nested JSON for readability. `flatten()` gives the flat field names
from defenses/fields.py that rules and verdict reasons refer to.

Where the rows come from (contract 1.7): the ext's hooks.on_response observer
writes one row per response into defenses/rule_store.py's tables — assets
included — and hooks.on_action("login") records every login attempt. "Runs"
are time windows (data/runs.json), recorded by whatever sent the traffic: in
production you would select a window in your log store the same way.

Durations are divided by LAB_TIME_SCALE so they read as real seconds. The
LLM's own latency is wall-clock and is never scaled.
"""

import hashlib
import json
import os
import statistics
from urllib.parse import urlparse

from sqlalchemy import func, select, text

from .fields import CAPS
from .netinfo import lookup
from .rule_store import LAB, LAB_TIME_SCALE, logins_t, requests_t

HONEYPOT_PATHS = ("/specials-archive",)
DISALLOWED_PATHS = ("/partner-feed",)
CHECKOUT = {("POST", "/checkout"), ("POST", "/api/checkout"), ("POST", "/api/buy")}
RUNS_FILE = os.path.join(LAB, "data", "runs.json")
MAX_PATHS = 12
MAX_REFERERS = 3

# The verified cohort: customers who signed in to a long-standing account.
VERIFIED_MIN_ORDERS = 3
VERIFIED_MIN_AGE_DAYS = 120


def short_id(sid):
    return hashlib.sha1(str(sid).encode()).hexdigest()[:8]


def _is_local(url):
    host = urlparse(url).hostname
    return host in ("localhost", "127.0.0.1", "::1")


def _is_checkout(r):
    return (r["method"], r["path"]) in CHECKOUT or \
        (r["method"] == "POST" and str(r["path"]).startswith("/drop/"))


def card_from_rows(sid, rows, login_account=None, login_ok=False):
    """Build a card from request rows (dicts) ordered by ts; stops at the checkout."""
    pre = []
    for r in rows:
        if _is_checkout(r):
            break
        pre.append(r)
    rows = pre or rows[:1]
    first = rows[0] if rows else {}
    net = {"asn": first.get("asn") or "?", "country": first.get("country") or "??",
           "asn_type": lookup(first.get("ip", ""))["asn_type"]}
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
        "net": net,
        "client": {"user_agent": ua, "accept_language": lang,
                   "referers": referers[:MAX_REFERERS]},
        "requests": {
            "n": len(rows), "pages": len(pages), "assets": len(assets),
            "asset_ratio": round(len(assets) / len(rows), 2) if rows else 0.0,
            "errors_4xx": sum(1 for r in rows if 400 <= (r["status"] or 0) < 500),
            "duration_s": round((ts[-1] - ts[0]) / LAB_TIME_SCALE, 1) if len(ts) > 1 else 0.0,
            "median_gap_s": round(statistics.median(gaps), 2) if gaps else 0.0,
            "honeypot_hit": any(r["path"] in HONEYPOT_PATHS for r in rows),
            "disallowed_hit": any(r["path"] in DISALLOWED_PATHS for r in rows),
            "reached_cart": any(str(r["path"]).endswith("/cart/add") for r in rows),
        },
        "paths": paths[:MAX_PATHS],
        # `ok`: the session actually signed in. The attempted name is kept either way —
        # it is attacker text — but a failed login must not read as "logged in".
        "login": {"account": login_account, "ok": bool(login_ok)},
    }


def card_for_sid(conn, sid):
    rows = conn.execute(select(requests_t).where(requests_t.c.sid == sid)
                        .order_by(requests_t.c.ts, requests_t.c.id)).mappings().all()
    if not rows:
        return None
    attempts = conn.execute(select(logins_t.c.account, logins_t.c.ok)
                            .where(logins_t.c.sid == sid).order_by(logins_t.c.ts)).all()
    acct = attempts[0][0] if attempts else None
    ok = any(a[1] for a in attempts)
    return card_from_rows(sid, [dict(r) for r in rows], acct, ok)


def record_run(name, t0, t1):
    """Register a named time window (every attack and simulator calls this when it ends)."""
    runs = {}
    if os.path.exists(RUNS_FILE):
        with open(RUNS_FILE) as fh:
            runs = json.load(fh)
    runs[name] = [t0, t1]
    os.makedirs(os.path.dirname(RUNS_FILE), exist_ok=True)
    with open(RUNS_FILE, "w") as fh:
        json.dump(runs, fh, indent=1)


def run_window(run):
    """[t0, t1] for a named run; 'all' means everything in the tables."""
    if run == "all":
        return [0.0, float("inf")]
    if not os.path.exists(RUNS_FILE):
        raise SystemExit(f"no runs recorded yet ({os.path.relpath(RUNS_FILE)}): run a simulator or attack first")
    with open(RUNS_FILE) as fh:
        runs = json.load(fh)
    if run not in runs:
        raise SystemExit(f"unknown run {run!r}; recorded: {', '.join(sorted(runs))} (or 'all')")
    return runs[run]


def sids_for_run(conn, run):
    """Sessions whose FIRST request falls inside the run's window, in arrival order."""
    t0, t1 = run_window(run)
    q = (select(requests_t.c.sid, func.min(requests_t.c.ts).label("first_ts"))
         .group_by(requests_t.c.sid).having(func.min(requests_t.c.ts) >= t0,
                                            func.min(requests_t.c.ts) <= t1)
         .order_by("first_ts"))
    return [r[0] for r in conn.execute(q)]


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
    """Sessions that signed in to a long-standing account: the gate's legit cohort.

    Deliberately NOT ground truth. It is what production has: customers you
    already trust (an account older than VERIFIED_MIN_AGE_DAYS with at least
    VERIFIED_MIN_ORDERS orders, from the store's own users/orders tables). It
    under-represents people who rarely log in (privacy browsers, VPN users),
    which is exactly the bias the gate inherits.
    """
    q = text(f"""
        SELECT DISTINCT l.sid FROM llm_logins l
        WHERE l.ok = 1 AND l.user_id IN (
            SELECT u.id FROM users u JOIN orders o ON o.user_id = u.id
            WHERE u.created_at <= datetime('now', '-{VERIFIED_MIN_AGE_DAYS} days')
            GROUP BY u.id HAVING COUNT(o.id) >= {VERIFIED_MIN_ORDERS})
    """) if conn.engine.url.get_backend_name() == "sqlite" else text(f"""
        SELECT DISTINCT l.sid FROM llm_logins l
        WHERE l.ok = 1 AND l.user_id IN (
            SELECT u.id FROM users u JOIN orders o ON o.user_id = u.id
            WHERE u.created_at <= now() - interval '{VERIFIED_MIN_AGE_DAYS} days'
            GROUP BY u.id HAVING COUNT(o.id) >= {VERIFIED_MIN_ORDERS})
    """)
    return sorted(r[0] for r in conn.execute(q))


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
        "honeypot_hit": r["honeypot_hit"], "disallowed_hit": r["disallowed_hit"],
        "reached_cart": r["reached_cart"],
        "logged_in": bool(card["login"].get("ok", card["login"]["account"] is not None)),
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
    import sys
    from .rule_store import make_engine
    with make_engine().connect() as conn:
        run = sys.argv[1] if len(sys.argv) > 1 else "all"
        for sid, card in cards_for_run(conn, run, limit=2):
            print(json.dumps(card, indent=1))
        print(f"\nverified sessions: {len(verified_sids(conn))}  (caps: {CAPS})")
