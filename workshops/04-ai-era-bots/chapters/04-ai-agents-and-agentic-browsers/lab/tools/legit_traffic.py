"""
W4 Ch4 — Legitimate-traffic simulator ("measuring both sides")

Forty simulated customers (tools/personas.py) shop alongside the agents. Each
one runs over plain HTTP (there is no TLS-fingerprint layer in this chapter),
sending the same telemetry collector.js would: a browser fingerprint from
tools/profiles/*.json and synthetic input from tools/synthetic_input.py.

Two cohorts are reported separately, because they mean different things:

    humans        38 people, including the false-positive cohort an agent-aware
                  defence threatens: screen-reader and voice-control users,
                  password-manager autofill, an RPA macro, touch and privacy
                  browsers, an office NAT. A defence that BLOCKS any of them is a
                  failure; a CHALLENGE is friction we count.
    legit agents  2 people whose OWN agent buys for them, declared and signed by
                  a trusted operator. A store that refuses all agent checkout
                  refuses these too — which is why they can only buy once the
                  store supports verified, mandated agents (DEFENSE_LEVEL 3–4).

Run:
    python tools/legit_traffic.py       # one pass, summary per persona
"""

import json
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "defenses"))
import httpsig  # noqa: E402
import personas  # noqa: E402
import synthetic_input as si  # noqa: E402
from lab import BASE_URL, authority, ensure_local  # noqa: E402

PROFILES = os.path.join(HERE, "profiles")
DROP = "lab-runner-9"
LAB_KEY = os.path.join(HERE, "..", "data", "keys", "lab-provider.pem")
LAB_AGENT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/150.0.0.0 Safari/537.36 LabAgent/1.0 (+https://agents.lab-provider.test)")


def load_profile(name):
    with open(os.path.join(PROFILES, f"{name}.json")) as f:
        return json.load(f)


def build_fp(profile, rng):
    fp = json.loads(json.dumps(profile["fp"]))
    fp.update({"webdriver": False, "automation_globals": []})
    fp["worker"] = {"ua": fp["ua"], "platform": fp["platform"], "hc": fp.get("hc"),
                    "languages": fp.get("languages")}
    if "canvas" in profile.get("farble", []):
        fp["canvas"] = f"{rng.getrandbits(32):08x}"
    return fp


def _server_ms(resp):
    t = resp.headers.get("Server-Timing", "")
    return float(t.split("dur=")[1].split(",")[0]) if "dur=" in t else None


def _result(user, persona, stage, resp):
    try:
        body = resp.json()
    except ValueError:
        body = {"outcome": "block" if resp.status_code == 403 else "error", "reasons": []}
    cohort = "legit-agent" if persona["name"] == "agent-user" else "human"
    return {"persona": persona["name"], "cohort": cohort, "email": user["email"], "stage": stage,
            "outcome": body.get("outcome", "error"), "reasons": body.get("reasons", []),
            "status": resp.status_code, "score_ms": _server_ms(resp), "success": body.get("outcome") == "allow" and stage == "buy"}


def _sign(base, session, operator="agents.lab-provider.test"):
    key = httpsig.load_private_key(LAB_KEY)
    session.headers.update(httpsig.sign(key, authority(base), operator))


def simulate(user, persona, base):
    rng = random.Random(user["email"])
    profile = load_profile(persona["profile"])
    behavior = persona["behavior"]
    is_agent = persona["name"] == "agent-user"
    s = requests.Session()
    ua = LAB_AGENT_UA if is_agent else profile.get("headers", {}).get("User-Agent", profile["fp"]["ua"])
    s.headers.update({"User-Agent": ua, "Accept-Language": "en-US,en;q=0.9", "Sec-Fetch-Mode": "navigate",
                      "X-Lab-Actor": "agent-user" if is_agent else "human"})
    egress = persona.get("egress") or f"203.0.113.{int(user['email'].encode().hex()[:4], 16) % 200 + 20}"
    s.headers["X-Lab-Egress"] = egress
    fp = build_fp(profile, rng)

    def telemetry(page, events):
        s.post(f"{base}/api/telemetry", json={"page": page, "fp": fp, "events": events})

    def signed_post(path, payload):
        if is_agent:
            _sign(base, s)
        return s.post(f"{base}{path}", json=payload)

    s.get(f"{base}/")
    time.sleep(rng.uniform(0.2, 1.4))

    # Register or log in.
    if user["register"]:
        s.get(f"{base}/register")
        telemetry("/register", si.typing_events(rng, [("email", 24), ("password", 18), ("address", 30)],
                                                 si.login_style(behavior)))
        email = f"firsttimer.{rng.getrandbits(32):08x}@customers.example"
        r = s.post(f"{base}/api/register", json={"email": email, "password": "first-time-buyer-pw",
                                                 "address": "12 Juniper Ct, Boise ID 83702"})
    else:
        s.get(f"{base}/login")
        telemetry("/login", si.typing_events(rng, [("email", len(user["email"])), ("password", 14)],
                                             si.login_style(behavior)))
        r = s.post(f"{base}/api/login", json={"email": user["email"], "password": user["password"]})
    if r.status_code >= 400 or r.json().get("outcome") != "allow":
        return _result(user, persona, "login", r)

    # A legit agent's human grants a mandate first (needed at L4).
    mandate_id = None
    if is_agent:
        human = requests.Session()
        human.headers.update({"User-Agent": profile["fp"]["ua"], "Accept-Language": "en", "Sec-Fetch-Mode": "navigate",
                              "X-Lab-Actor": "agent-owner", "X-Lab-Egress": egress})
        human.get(f"{base}/login")
        human.post(f"{base}/api/login", json={"email": user["email"], "password": user["password"]})
        mr = human.post(f"{base}/api/account/mandates", json={"operator": "agents.lab-provider.test", "sku": DROP, "ttl_min": 15})
        mandate_id = (mr.json() or {}).get("mandate", {}).get("id")

    # Browse to the product, add to cart, dwell on checkout, buy.
    s.get(f"{base}/products")
    time.sleep(rng.uniform(0.3, 1.8))
    s.get(f"{base}/product/{DROP}")
    time.sleep(rng.uniform(0.4, 2.2))
    signed_post("/api/cart/add", {"sku": DROP}) if is_agent else s.post(f"{base}/api/cart/add", json={"sku": DROP})
    s.get(f"{base}/checkout")
    dwell = rng.uniform(1.5, 4.5)
    time.sleep(dwell)
    telemetry("/checkout", si.events_for(behavior, rng, dwell * 1000))
    r = signed_post("/api/checkout", {"mandate": mandate_id})
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    # A real user answers a step-up; the legit agent hands it back to its human, who answers.
    if body.get("outcome") == "challenge" and body.get("step_up"):
        code = requests.get(f"{base}/lab/mailbox/{user['email'] if not user['register'] else email}").json().get("message", {})
        if code and code.get("code"):
            r = signed_post("/api/checkout/confirm", {"code": code["code"]})
    return _result(user, persona, "buy", r)


def population(base):
    by = {p["name"]: p for p in personas.PERSONAS}
    return [(u, by[u["persona"]]) for u in personas.legit_users()]


def run(base=BASE_URL, workers=10):
    ensure_local(base)
    jobs = population(base)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(simulate, u, p, base) for u, p in jobs]
        out = []
        for f in futures:
            try:
                out.append(f.result())
            except Exception as exc:
                out.append({"persona": "error", "cohort": "human", "email": "", "stage": "error",
                            "outcome": "error", "reasons": [repr(exc)], "status": None, "score_ms": None,
                            "success": False})
    return out


def summarize(results):
    by = {}
    for r in results:
        row = by.setdefault(r["persona"], {"cohort": r["cohort"], "allow": 0, "challenge": 0, "block": 0, "other": 0})
        row[r["outcome"] if r["outcome"] in ("allow", "challenge", "block") else "other"] += 1
    return by


if __name__ == '__main__':
    started = time.time()
    results = run()
    print(f"=== {len(results)} simulated customers in {time.time() - started:.1f} s ===")
    for name, row in sorted(summarize(results).items(), key=lambda kv: kv[1]["cohort"]):
        ok = row["block"] == 0 and row["other"] == 0 and (row["cohort"] == "human" or row["allow"] > 0 or row["challenge"] == 0)
        print(f"  {'✅' if ok else '⚠️ '} [{row['cohort']:<11}] {name:<16} "
              f"allow {row['allow']} challenge {row['challenge']} block {row['block']} other {row['other']}")
    for r in results:
        if r["outcome"] not in ("allow",) and r["cohort"] == "human":
            print(f"     {r['persona']:<16} {r['stage']:<8} {r['outcome']:<9} {r['reasons'][:2]}")
