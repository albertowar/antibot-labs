"""
Shared helpers for the Chapter 2 attack scripts.

Rules of engagement, enforced in code: every script reaches the store through tools/labclient.py,
which asks labnet.py at the lab root for DEMO_URL and refuses anything that is not this machine.
Browsers get the same guard (labclient.browser_context aborts every non-local request). The sign-up
farm's "rotating residential proxies" are addresses rented from data/world.json, one per account;
no proxy is ever used, and every e-mail address is synthetic (@example.test, RFC 2606).

Every bot runs a sign-up farm: it claims the account (and its welcome offer) over and over,
each time with a fresh browser context (new cookies, new session) and a different source address,
so the IP rate limits of W1 Ch2/Ch3 see unrelated visitors. It reports one result per attempt and ends
by printing one JSON line for tools/checkpoint.py:

    {"attempted": n, "succeeded": <accounts created>, "refused": k, "collect_ms": ..., ...}

The store's X-Lab-Signals header says which layers fired: teaching only, never in production.
The full reasons are in the store's log: curl localhost:5000/lab/fp/logs
"""

import argparse
import json
import os
import secrets
import statistics
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from labclient import BASE_URL, admin, browser_context, reset, world_pool  # noqa: E402,F401

PASSWORD = "Synthetic-Passw0rd!"
SIGNUP_PAGE = "/register"
SIGNUP_API = "/api/register"


def bot_ip(i):
    """The i-th rented 'residential' exit: the farm pays for clean addresses (W1 Ch3), one per account."""
    pool = world_pool("residential_proxy_net")
    return pool[(i * 37) % len(pool)]


def new_context(browser, actor, i, **kw):
    """A browser context that carries the lab headers (rented IP, bot label) and stays on this machine."""
    return browser_context(browser, f"bot:{actor}", ip=bot_ip(i), **kw)


def bot_email(round_no, i):
    return f"r{round_no}-bot{i}-{secrets.token_hex(3)}@example.test"


def sign_up(page, email, timeout_ms=15000):
    """
    Load the sign-up page, wait for the fingerprint collector to finish, then submit the sign-up
    from inside the page (same cookies, same headers as the form). Returns
    {"status", "verdict", "score", "signals", "collect_ms", "payload_bytes"}.
    """
    page.goto(f"{BASE_URL}{SIGNUP_PAGE}")
    page.wait_for_function("window.__fpResult !== undefined", timeout=timeout_ms)
    result = page.evaluate(
        """async ([email, password, api]) => {
             const r = await fetch(api, {
               method: "POST", headers: {"Content-Type": "application/json"},
               body: JSON.stringify({email, password, name: "Sam Synthetic"})});
             return {status: r.status, verdict: r.headers.get("x-lab-verdict"),
                     score: Number(r.headers.get("x-lab-score") || 0),
                     signals: (r.headers.get("x-lab-signals") || "").split(",").filter(Boolean)};
           }""",
        [email, PASSWORD, SIGNUP_API],
    )
    # What the real collector cost in this browser (before any payload swap)
    result["collect_ms"] = page.evaluate("window.__fp.collect_ms")
    result["payload_bytes"] = page.evaluate("JSON.stringify(window.__fp).length")
    return result


def common_args(description, default_signups=20, payload=None):
    """Argument parser every attack shares: --signups, --no-reset (the checkpoint's), optional --payload."""
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("--signups", type=int, default=default_signups)
    ap.add_argument("--no-reset", action="store_true",
                    help="keep the store's accounts (tools/checkpoint.py runs every bot on one store)")
    if payload:
        ap.add_argument("--payload", default=payload, help="harvested payload, or a profile from /lab/fp/profile")
    return ap


def reasons(n):
    """The reasons the fingerprint layers gave for the last n sign-up decisions (from /lab/fp/logs)."""
    try:
        return admin("GET", "/lab/fp/logs", params={"limit": n})
    except Exception:
        return []


def report(title, results):
    """Print a per-attempt log and the bottom line: accounts created out of attempts."""
    print(f"=== {title} ===")
    for i, r in enumerate(results):
        mark = "created" if r["status"] == 201 else f"refused {r['status']}"
        print(f"  #{i + 1:<3} {mark:<12} verdict={r['verdict']} score={r['score']}  {' '.join(r['signals'])}")
    refused = [row for row in reasons(len(results)) if row["status"] != 201 and row["reasons"]]
    if refused:
        print("\n  Why the first refusal (the store's log, /lab/fp/logs):")
        for line in refused[-1]["reasons"][:4]:
            print(f"    - {line}")
    created = sum(r["status"] == 201 for r in results)
    print(f"\n  Accounts created: {created}/{len(results)}")
    return created


def finish(name, results):
    """The last line every attack prints: one JSON object for tools/checkpoint.py."""
    out = {"attack": name, "attempted": len(results), "succeeded": sum(r["status"] == 201 for r in results),
           "refused": sum(r["status"] == 403 for r in results),
           "collect_ms": round(statistics.median(r["collect_ms"] for r in results)) if results else None,
           "payload_bytes": round(statistics.median(r["payload_bytes"] for r in results)) if results else None,
           "signals": sorted({s for r in results for s in r["signals"]})}
    print(json.dumps(out))
    return out
