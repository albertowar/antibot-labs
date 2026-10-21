"""
W4 Ch11 Capstone — an HTTP-level model of an agent session (shared by the simulator and Round 2)

W4 Ch4 drove real browsers with Playwright. The capstone models agents at the
HTTP layer so a round takes seconds and needs no Chromium: a session loads the
pages a browser would, posts the telemetry capstone.js would (a fingerprint
from tools/profiles and synthetic input from tools/synthetic_input), and buys
the drop. What varies is exactly what the defenses look at:

    declared     "none"   an agent in the user's own Chrome, says nothing (the Comet case)
                 "ua"     an agent token in the User-Agent (ChatGPT-User / Claude-User style)
                 "signed" Web Bot Auth: Signature-Agent + an RFC 9421 signature by `operator`
    egress       residential or datacenter, from the shared world (X-Lab-Client-IP)
    fp_seed      sessions sharing a seed share a fingerprint (a fleet on one machine)
    a11y         the session uses the accessibility API (assistive agent, or a mimic)
    attended     can the operator read the account's inbox / answer a code? A shopper's
                 agent hands it back to the shopper; an unattended farm cannot
    can_see      an image challenge needs eyes; the sighted simulator reads the lab
                 oracle (/lab/answer), the way a person who looked would answer
    mandate      the id of a mandate the account holder granted (verified operators)

This is a measurement harness for the student's own store, nothing more. The
loopback guard (labnet.py, via tools/labclient.py) runs before any request.
Accounts and IPs are synthetic.

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
sys.path.insert(0, LAB_DIR)

import labclient  # noqa: E402  (runs the labnet guard on import)
import synthetic_input as si  # noqa: E402
from crawl import BROWSER_HEADERS, CHROME_UA  # noqa: E402
from defenses import httpsig  # noqa: E402
from defenses.challenges import solve_pow  # noqa: E402

PROFILES = os.path.join(LAB_DIR, "tools", "profiles")
DROP = "lab-runner-9"
DROP_SIZE = "9"
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


class _AgentKey:
    """The operator's signing key, loaded once per process."""

    _cache = {}

    @classmethod
    def get(cls, operator):
        if operator not in cls._cache:
            import make_keys
            cls._cache[operator] = make_keys.load_signer(operator)
        return cls._cache[operator]


def _signed_headers(base, claimed_operator, key_origin):
    """Sign as `key_origin` but present Signature-Agent for `claimed_operator`.
    When they differ (Round 2's forgery) the signature will not verify against the
    claimed origin's published key: that is the `invalid` path."""
    private, keyid = _AgentKey.get(key_origin)
    authority = base.split("//", 1)[-1]
    ctx = httpsig.MessageContext("POST", authority, "/", {}, "http", "")
    return httpsig.agent_headers(private, keyid, f"https://{claimed_operator}", ctx)


def run_session(base, account, *, actor, egress, profile="chrome-win", behavior="agent", declared="none",
                operator=None, sign=False, key_origin=None, fp_seed=None, a11y=False, attended=True,
                can_see=True, mandate=None, register=False, review=None):
    """Drive one agent (or human) drop purchase. Returns a result dict."""
    rng = random.Random(fp_seed if fp_seed is not None else account["email"])
    profile_d, fp = _profile(profile, rng)
    s = requests.Session()
    s.headers.update({"User-Agent": _ua_for(declared, operator, profile_d), **BROWSER_HEADERS,
                      "X-Lab-Actor": actor, "X-Lab-Client-IP": egress})

    def telemetry(page, events):
        s.post(f"{base}/api/telemetry", json={"kind": "capstone", "page": page, "fp": fp, "events": events},
               timeout=15)

    def signed():
        # a fresh signature (fresh nonce) for every signed request: the verifier replay-checks nonces
        if declared == "signed" and sign and operator:
            return _signed_headers(base, operator, key_origin or operator)
        return {}

    result = {"email": account["email"], "actor": actor, "stage": "login", "outcome": "error",
              "reasons": [], "status": None, "challenges": [], "success": False}
    s.get(f"{base}/")
    _nap(rng, 0.2, 1.0)
    if register:
        s.get(f"{base}/register")
        telemetry("/register", si.typing_events(rng, [("email", 24), ("password", 18), ("name", 14)],
                                                si.login_style(behavior)))
        r = s.post(f"{base}/api/register", json={"email": account["email"], "password": account["password"],
                                                 "name": account["email"].split("@")[0][:40]}, timeout=15)
    else:
        s.get(f"{base}/login")
        telemetry("/login", si.typing_events(rng, [("email", 18), ("password", 14)], si.login_style(behavior)))
        r = s.post(f"{base}/api/login", json={"email": account["email"], "password": account["password"]},
                   timeout=15)
    if r.status_code >= 400 or not _json(r).get("ok"):
        result.update(outcome=_outcome(r), status=r.status_code, reasons=_reasons(r))
        return result

    if review is not None:
        rr = s.post(f"{base}/api/review", json={"sku": review["sku"], "body": review["text"], "rating": 5},
                    headers=signed(), timeout=15)
        result.update(stage="review", outcome="allow" if rr.status_code < 400 else _outcome(rr),
                      status=rr.status_code, reasons=_reasons(rr), success=rr.status_code < 400)
        return result

    s.get(f"{base}/catalog?page=1")
    _nap(rng, 0.3, 1.2)
    s.get(f"{base}/product/{DROP}")
    dwell = rng.uniform(1.2, 3.5)
    _nap(rng, dwell, dwell)
    # The behaviour sample is labelled "/checkout": that is the page defenses/capstone.py's
    # session_state reads when it scores the buy, so an agent's no-pointer / regular-cadence
    # events reach the governance (an undeclared agent that "goes dark" is caught here).
    telemetry("/checkout", si.events_for(behavior, rng, dwell * 1000, a11y=a11y))
    body = {"sku": DROP, "size": DROP_SIZE}
    if mandate:
        body["mandate"] = mandate
    r = s.post(f"{base}/api/buy", json=body, headers=signed(), timeout=15)
    result.update(stage="buy", outcome=_outcome(r), status=r.status_code, reasons=_reasons(r))

    # Answer up to two challenges/step-ups, the way this operator can, then retry the buy.
    for _ in range(2):
        if result["outcome"] != "challenge":
            break
        err = _json(r).get("error") or {}
        kind, payload = err.get("challenge"), err.get("payload") or {}
        if not kind:
            break
        result["challenges"].append(kind)
        if kind == "pow":
            answer = {"token": payload.get("token"), "solution": solve_pow(payload["nonce"], payload["bits"])}
        elif kind == "captcha_image":
            if not can_see:
                result["reasons"].append("image challenge with no non-visual path")
                break
            oracle = requests.get(f"{base}/lab/answer/{payload.get('token')}", timeout=10).json()
            answer = {"token": payload.get("token"), "answer": oracle.get("answer")}
        elif kind == "confirm_code":
            if not attended:
                result["reasons"].append("unattended: nobody to answer the emailed code")
                break
            msgs = requests.get(f"{base}/lab/mailbox/{account['email']}", timeout=10).json().get("messages") or []
            codes = [m.get("code") for m in msgs if m.get("code")]
            if not codes:
                result["reasons"].append("no code arrived")
                break
            answer = {"code": codes[-1]}
        else:
            result["reasons"].append(f"unsolvable challenge type {kind}")
            break
        v = s.post(f"{base}/api/challenge/verify", json={"type": kind, "answer": answer},
                   headers=signed(), timeout=20)
        if v.status_code >= 400:
            result.update(outcome="challenge", reasons=_reasons(v))
            break
        r = s.post(f"{base}/api/buy", json=body, headers=signed(), timeout=15)
        result.update(outcome=_outcome(r), status=r.status_code, reasons=_reasons(r))
    result["success"] = result["outcome"] == "allow" and result["stage"] == "buy"
    if result["success"]:
        result["order"] = (_json(r).get("order") or {}).get("number")
    return result


def _json(r):
    try:
        return r.json()
    except ValueError:
        return {}


def _outcome(r):
    """Map a starter reply to the capstone's outcome vocabulary."""
    if r.status_code < 400:
        return "allow"
    err = (_json(r).get("error") or {})
    code = err.get("code", "")
    if code == "challenge_required":
        return "challenge"
    if r.status_code == 429:
        return "rate_limit"
    if r.status_code in (401, 403) or code in ("blocked",):
        return "block"
    return code or "error"


def _reasons(r):
    err = (_json(r).get("error") or {})
    out = []
    if err.get("message"):
        out.append(str(err["message"])[:160])
    if err.get("reason"):
        out.append(str(err["reason"])[:160])
    return out
