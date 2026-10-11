"""
W4 Ch9 Capstone — an HTTP-level model of an agent session (shared by the simulator and Round 2)

W4 Ch4 drove real browsers with Playwright. The capstone models agents at the
HTTP layer so a round takes seconds and needs no Chromium: a session loads the
pages a browser would, posts the telemetry collector.js would (a fingerprint
from tools/profiles and synthetic input from tools/synthetic_input), and places
an order. What varies is exactly what the defenses look at:

    declared     "none"   an agent in the user's own Chrome, says nothing (the Comet case)
                 "ua"     an agent token in the User-Agent (ChatGPT-User / Claude-User style)
                 "signed" Web Bot Auth: Signature-Agent + an RFC 9421 signature with `key`
    egress       residential or datacenter (RFC 5737, claimed via X-Lab-Egress)
    fp_seed      sessions sharing a seed share a fingerprint (a fleet on one machine)
    a11y         the session uses the accessibility API (assistive agent, or a mimic)
    attended     can the operator read the account's inbox / answer a code? A shopper's
                 agent hands it back to the shopper; an unattended farm cannot
    solve        the operator answers challenges: a proof of work always; an image
                 challenge only if `can_see` (an LLM/VLM solver via the lab oracle)
    mandate      the id of a mandate the account holder granted (verified operators)

This is a measurement harness for the student's own store, nothing more. The
loopback guard in _common.target() runs before any request. Accounts and IPs
are synthetic.

run_session(...) returns one result dict; the Round 2 campaigns and the
legitimate simulator both call it.
"""

import json
import os
import random
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "tools"))
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))
import httpsig  # noqa: E402
import synthetic_input as si  # noqa: E402
from challenges import solve_pow  # noqa: E402
from crawl import BROWSER_HEADERS, CHROME_UA  # noqa: E402

PROFILES = os.path.join(LAB_DIR, "tools", "profiles")
DROP = "lab-runner-9"
SCALE = float(os.environ.get("LAB_TIME_SCALE", "0.3"))   # shrink the think-time sleeps for fast rounds
LAB_AGENT_UA = CHROME_UA + " LabAgent/1.0 (+https://agents.lab-provider.test)"
TOKEN_UA = {"chatgpt.com": CHROME_UA + " ChatGPT-User/1.0 (+https://openai.com/bot)",
            "anthropic.com": CHROME_UA + " Claude-User/1.0 (+https://anthropic.com)",
            "agents.lab-provider.test": LAB_AGENT_UA}


def _profile(name, rng):
    with open(os.path.join(PROFILES, f"{name}.json")) as f:
        profile = json.load(f)
    fp = json.loads(json.dumps(profile["fp"]))
    fp.update({"webdriver": False, "automation_globals": []})
    fp["worker"] = {"ua": fp["ua"], "platform": fp["platform"], "hc": fp.get("hc"), "languages": fp.get("languages")}
    # A per-seed canvas: sessions with the SAME fp_seed share a fingerprint (a farm on one
    # machine); distinct seeds (distinct shoppers) get distinct fingerprints.
    fp["canvas"] = f"{rng.getrandbits(32):08x}"
    return profile, fp


def _nap(rng, lo, hi):
    time.sleep(rng.uniform(lo, hi) * SCALE)


def _ua_for(declared, operator, profile):
    if declared == "ua" and operator:
        return TOKEN_UA.get(operator, LAB_AGENT_UA)
    return profile.get("headers", {}).get("User-Agent", profile["fp"]["ua"])


def _sign(session, base, operator, key):
    k = httpsig.load_private_key(key)
    session.headers.update(httpsig.sign(k, base.split("//", 1)[-1], operator))


def run_session(base, account, *, actor, egress, profile="chrome-win", behavior="agent", declared="none",
                operator=None, key=None, fp_seed=None, a11y=False, attended=True, can_see=True,
                mandate=None, register=False, review=None):
    """Drive one agent (or human) checkout. Returns a result dict."""
    rng = random.Random(fp_seed if fp_seed is not None else account["email"])
    profile_d, fp = _profile(profile, rng)
    s = requests.Session()
    s.headers.update({"User-Agent": _ua_for(declared, operator, profile_d), **BROWSER_HEADERS, "X-Lab-Actor": actor,
                      "X-Lab-Egress": egress})

    def telemetry(page, events):
        s.post(f"{base}/api/telemetry", json={"page": page, "fp": fp, "events": events}, timeout=15)

    def maybe_sign():
        if declared == "signed" and key and operator:
            _sign(s, base, operator, key)

    result = {"email": account["email"], "actor": actor, "stage": "login", "outcome": "error",
              "reasons": [], "status": None, "challenges": [], "success": False}
    s.get(f"{base}/")
    _nap(rng, 0.2, 1.0)
    if register:
        s.get(f"{base}/register")
        telemetry("/register", si.typing_events(rng, [("email", 24), ("password", 18), ("address", 30)],
                                                si.login_style(behavior)))
        r = s.post(f"{base}/api/register", json={"email": account["email"], "password": account["password"],
                                                 "address": account["address"]}, timeout=15)
    else:
        s.get(f"{base}/login")
        telemetry("/login", si.typing_events(rng, [("email", 18), ("password", 14)], si.login_style(behavior)))
        r = s.post(f"{base}/api/login", json={"email": account["email"], "password": account["password"]}, timeout=15)
    if r.status_code >= 400 or _json(r).get("outcome") != "allow":
        result.update(outcome=_json(r).get("outcome", "error"), status=r.status_code, reasons=_json(r).get("reasons", []))
        return result

    if review is not None:
        maybe_sign()
        rr = s.post(f"{base}/api/review", json={"sku": review["sku"], "text": review["text"], "rating": 5}, timeout=15)
        result.update(stage="review", outcome=_json(rr).get("outcome", "error"), status=rr.status_code,
                      reasons=_json(rr).get("reasons", []), success=_json(rr).get("outcome") == "allow")
        return result

    s.get(f"{base}/catalog?page=1")
    _nap(rng, 0.3, 1.2)
    s.get(f"{base}/product/{DROP}")
    _nap(rng, 0.3, 1.4)
    maybe_sign()
    s.post(f"{base}/api/cart/add", json={"sku": DROP}, timeout=15)
    s.get(f"{base}/checkout")
    dwell = rng.uniform(1.2, 3.5)
    _nap(rng, dwell, dwell)
    telemetry("/checkout", si.events_for(behavior, rng, dwell * 1000, a11y=a11y))
    maybe_sign()
    r = s.post(f"{base}/api/checkout", json={"mandate": mandate}, timeout=15)
    body = _json(r)
    result.update(stage="buy", outcome=body.get("outcome", "error"), status=r.status_code, reasons=body.get("reasons", []))

    # Answer up to two challenges/step-ups, the way this operator can.
    for _ in range(2):
        if body.get("outcome") != "challenge":
            break
        chal = body.get("challenge") or {}
        kind = chal.get("kind") or ("confirm_code" if body.get("step_up") else None)
        if kind:
            result["challenges"].append(kind)
        maybe_sign()
        if kind == "pow":
            sol = solve_pow(chal["nonce"], chal["bits"])
            r = s.post(f"{base}/api/checkout/confirm", json={"token": chal["token"], "solution": sol}, timeout=20)
        elif kind == "captcha_image":
            if not can_see:
                result.update(outcome="challenge", reasons=["image challenge with no non-visual path"])
                break
            ans = requests.get(f"{base}/lab/answer/{chal['token']}", timeout=10).json().get("answer")
            r = s.post(f"{base}/api/checkout/confirm", json={"token": chal["token"], "answer": ans}, timeout=15)
        elif kind == "confirm_code":
            if not attended:
                result.update(outcome="challenge", reasons=["unattended: nobody to answer the emailed code"])
                break
            code = requests.get(f"{base}/lab/mailbox/{account['email']}", timeout=10).json().get("message") or {}
            if not code.get("code"):
                break
            r = s.post(f"{base}/api/checkout/confirm", json={"code": code["code"]}, timeout=15)
        else:
            break
        body = _json(r)
        result.update(outcome=body.get("outcome", "error"), status=r.status_code, reasons=body.get("reasons", []))
    result["success"] = result["outcome"] == "allow" and result["stage"] == "buy"
    return result


def _json(r):
    try:
        return r.json()
    except ValueError:
        return {"outcome": "block" if r.status_code == 403 else "error", "reasons": []}
