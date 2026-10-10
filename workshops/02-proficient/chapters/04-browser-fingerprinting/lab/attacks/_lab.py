"""
Chapter 4 — Shared Helpers for the Attack Scripts

Rules of engagement, enforced in code:
  - the target must be this machine (localhost / 127.0.0.1 / ::1);
  - "rotating IPs" are documentation addresses (RFC 5737 TEST-NET-3,
    203.0.113.0/24) sent in a lab-only header. No proxy is ever used;
  - every e-mail address is synthetic (@example.test, RFC 2606).
"""

import os
import secrets
import sys
from urllib.parse import urlparse

BASE_URL = os.environ.get("DEMO_URL", "http://localhost:5000")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
PASSWORD = "Synthetic-Passw0rd!"


def require_local(url=BASE_URL):
    """Refuse to run against anything that isn't this machine."""
    host = urlparse(url).hostname
    if host not in LOCAL_HOSTS:
        sys.exit(f"Refusing to attack {host!r}: lab scripts only target localhost.")
    return url


def lab_ip(i):
    """The i-th simulated client address (TEST-NET-3, never routed on the internet)."""
    return f"203.0.113.{(i % 254) + 1}"


def bot_email(round_no, i):
    return f"r{round_no}-bot{i}-{secrets.token_hex(3)}@example.test"


def sign_up(page, email, timeout_ms=15000):
    """
    Load the store, wait for the fingerprint collector to finish, then
    submit the sign-up from inside the page (same cookies, same headers as
    the form). Returns {"status", "body", "collect_ms", "payload_bytes"}.
    """
    page.goto(f"{BASE_URL}/")
    page.wait_for_function("window.__fpResult !== undefined", timeout=timeout_ms)
    result = page.evaluate(
        """async ([email, password]) => {
             const r = await fetch("/signup", {
               method: "POST", headers: {"Content-Type": "application/json"},
               body: JSON.stringify({email, password})});
             return {status: r.status, body: await r.json()};
           }""",
        [email, PASSWORD],
    )
    # What the real collector cost in this browser (before any payload swap)
    result["collect_ms"] = page.evaluate("window.__fp.collect_ms")
    result["payload_bytes"] = page.evaluate("JSON.stringify(window.__fp).length")
    return result


def report(title, results):
    """Print a per-attempt log and the bottom line: accounts created out of attempts."""
    print(f"=== {title} ===")
    for i, r in enumerate(results):
        body = r["body"]
        mark = "✅ created" if r["status"] == 201 else f"⛔ {r['status']}"
        print(f"  #{i + 1:<3} {mark:<10} verdict={body.get('verdict')} score={body.get('score')}")
        if r["status"] != 201:
            for reason in body.get("reasons", [])[:3]:
                print(f"         - {reason}")
    created = sum(r["status"] == 201 for r in results)
    print(f"\n  Accounts created: {created}/{len(results)}")
    return created
