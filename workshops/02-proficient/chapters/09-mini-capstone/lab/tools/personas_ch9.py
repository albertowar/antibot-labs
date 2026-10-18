"""
Chapter 9 shoppers: the 40 population personas, buying the drop as real browsers do.

tools/population.py's shoppers are Python, not browsers, so nobody runs the page's JavaScript for them.
This file registers the scenario "ch9_drop": each shopper replays, in order, what its browser would do.

    1. GET /                 with the browser's own headers in wire order (tools/profiles, W2 Ch1)
    2. POST /api/telemetry   the sensor report that browser produces (kind "sensor")
    3. sign in               POST /api/login with the login token the page would mint (level 5 asks for
                             it; the page always fetches one), or register live (the first-timer)
    4. GET /drop/<sku>       the drop page, whose layout the server drew (W2 Ch3)
    5. POST /api/telemetry   the behavior record the collector would have made (tools/humans.py, W2 Ch3)
    6. wait, then POST the form; when the gate answers with the "proof" challenge, solve it and submit again

Who is who is fixed per persona (PEOPLE below), so a cohort's false positives show up under the same name
in every run. The mix is chosen to contain the people the layers hurt: a Citrix/VDI desktop (software
WebGL, just like a headless bot), a privacy extension, Brave, Firefox with resistFingerprinting, two
keyboard-only and two screen-reader users, a voice-control user, a user with a tremor, eight phones on two
carrier IPs, a password-manager user, a customer buying the moment the drop opens, a first-timer whose
account is as fresh as a farm's, an old Chrome and a no-JavaScript visitor.

Outcomes: bought · sold_out · blocked (a false positive; the round fails on it, except no_js) ·
stuck_on_challenge. `challenged` is counted apart: friction, not a loss.

    python tools/population.py --scenario ch9_drop      # once, at the store's current level
"""

import glob
import html
import json
import os
import re
import time

import humans
import population
import profile_replay
from labclient import BASE_URL, csrf_of

DROP = "/drop/lab-runner-9"
NONCE = re.compile(r"ShopSensor\.send\(\"([^\"]+)\"\)")
PAYLOAD = re.compile(r'id="proof-payload">(.*?)</script>', re.S)
FIRST_TIMER = "human:home:20"
CHECKOUT_STOCK = 200

# The JA4 a+b each browser family puts on the wire (defenses/known_fingerprints.json); part c is a placeholder.
CLAIMED_JA4 = {"chrome": "t13d1516h2_8daaf6152771_806a8c22fdea",
               "firefox": "t13d1517h2_8daaf6152771_a87ad97598a9",
               "safari": "t13d2013h2_a09f3c656075_7f0f34a4126d"}

WIN, MAC, EDGE, FF, FF_RFP = ("chrome-153-windows", "chrome-153-macos", "edge-153-windows", "firefox-157-windows",
                              "firefox-157-resistfingerprinting")
KEYS = "chrome-153-windows-keyboard"
# actor -> (browser profile for the sensor and the headers, behavior profile for the collector)
PEOPLE = {
    "human:home:00": (WIN, "voice"), "human:home:01": (KEYS, "keyboard"), "human:home:02": (KEYS, "keyboard"),
    "human:home:03": (KEYS, "screen_reader"), "human:home:04": (KEYS, "screen_reader"),
    "human:home:05": (WIN, "tremor"), "human:home:06": (WIN, "tremor"), "human:home:07": (WIN, "tremor"),
    "human:home:08": ("chrome-153-vdi-swiftshader", "mouse"), "human:home:09": (FF, "mouse"),
    "human:home:10": (MAC, "trackpad"), "human:home:11": (MAC, "trackpad"), "human:home:12": (MAC, "trackpad"),
    "human:home:13": (FF_RFP, "mouse"), "human:home:14": ("chrome-153-privacy-extension", "mouse"),
    "human:home:15": (WIN, "password_mgr"), "human:home:16": (FF, "mouse"), "human:home:17": ("safari-26-macos", "mouse"),
    "human:home:18": (MAC, "mouse"), "human:home:19": ("chromium-153-linux", "mouse"), FIRST_TIMER: (WIN, "mouse"),
    "human:home:21": (EDGE, "mouse"), "human:home:22": (FF, "mouse"), "human:home:23": (WIN, "mouse"),
    "human:consumer_vpn:00": ("chrome-153-vdi-swiftshader", "mouse"), "human:consumer_vpn:01": (WIN, "mouse"),
    "human:consumer_vpn:02": ("brave-153-linux", "mouse"),
    "human:private_relay:00": ("safari-26-macos", "mouse"), "human:private_relay:01": ("safari-26-macos", "mouse"),
    "human:old_chrome:00": (WIN, "mouse"), "human:autofill:00": (WIN, "password_mgr"),
    "human:no_js:00": ("chrome-153-windows-nojs", None),
}


def captured():
    """YOUR browser, if you saved it at /lab/capture (tools/profiles/captured-<name>.json): it shops as human:home:23."""
    mine = sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles", "captured-*.json")))
    return os.path.splitext(os.path.basename(mine[0]))[0] if mine else None


def assignment(p):
    if p.actor == "human:home:23" and captured():
        return captured(), "mouse"
    if p.actor in PEOPLE:
        return PEOPLE[p.actor]
    if p.persona == "mobile_cgnat":
        return "chrome-153-android-touch", "touch"
    return WIN, "mouse"


def family(name):
    if name.startswith("captured-"):                  # your own browser: read it off the captured User-Agent
        ua = next((v for k, v in profile_replay.profile(name)["navigation_headers"] if k.lower() == "user-agent"), "")
        return "firefox" if "Firefox/" in ua else "safari" if "Version/" in ua and "Chrome/" not in ua else "chrome"
    return "firefox" if name.startswith("firefox") else "safari" if name.startswith("safari") else "chrome"


def _older(prof, major=138):
    """The same browser, five versions behind (the old_chrome shopper)."""
    text = json.dumps(prof).replace("Chrome/153", f"Chrome/{major}").replace('v=\\"153\\"', f'v=\\"{major}\\"')
    text = text.replace("Chrome/153", f"Chrome/{major}").replace("/153", f"/{major}")
    return json.loads(text)


def _profile(p, name):
    prof = profile_replay.profile(name)
    return _older(prof) if p.persona == "old_chrome" else prof


def _link(headers, referer):
    """Navigation headers turned into 'clicked a link on this site': same-origin, with a Referer."""
    out = []
    for k, v in headers:
        if k.lower() == "sec-fetch-site":
            v = "same-origin"
        if k.lower() == "accept-encoding":
            out.append(("Referer", referer))
        out.append((k, v))
    return out


def _form(post_headers, nav_headers, referer):
    """The page's form submit: the profile's POST headers, but a navigation (urlencoded, document)."""
    accept = next(v for k, v in nav_headers if k.lower() == "accept")
    out = []
    for k, v in post_headers:
        lk = k.lower()
        if lk == "content-type":
            v = "application/x-www-form-urlencoded"
        elif lk == "accept":
            v = accept
        elif lk == "sec-fetch-mode":
            v = "navigate"
        elif lk == "sec-fetch-dest":
            v = "document"
        elif lk == "referer":
            v = referer
        out.append((k, v))
    return out


def _wants_otp(r):
    """True when the gate answered the login with the Round 4 otp step-up."""
    try:
        e = r.json().get("error") or {}
    except ValueError:
        return False
    return e.get("code") == "challenge_required" and e.get("challenge") == "otp"


def _enter_otp(client, email, hdr_fetch, hdr_post):
    """What a stepped-up customer does: read the code the store mailed them, type it in. The mailbox
    belongs to the shopper's own account; a stuffer has no such inbox to read."""
    m = client.get(f"/lab/mailbox/{email}", hdr_fetch)
    msgs = m.json().get("messages", []) if m.status_code == 200 else []
    codes = [x.get("code") for x in msgs if x.get("code")]
    if not codes:
        return False
    v = client.post("/api/challenge/verify", json={"type": "otp", "answer": {"code": codes[-1]}},
                    headers=hdr_post)
    return v.status_code == 200


def _solve_proof(client, r, post_headers):
    """What proof.js does on the interstitial: solve the payload, POST the answer. Returns True if verified."""
    from demo_site.ext.drop9 import solve_proof
    m = PAYLOAD.search(r.text) if "text/html" in r.headers.get("Content-Type", "") else None
    payload = json.loads(html.unescape(m.group(1))) if m else (r.json().get("error") or {}).get("payload")
    if not payload:
        return False
    counter = solve_proof(payload["nonce"], payload["bits"])
    v = client.post("/api/challenge/verify", json={"type": "proof", "answer": {"nonce": payload["nonce"], "counter": counter}},
                    headers=post_headers)
    return v.status_code == 200


def _page(p, client, path, headers, post):
    """GET a page; when the request phase answers with the "proof" challenge (a stale browser, say), solve it as the page would."""
    r = client.get(path, headers, ip=p.ip)
    if r.status_code == 403 and 'data-challenge="proof"' in r.text:
        p.result["challenged"] = 1
        if _solve_proof(client, r, post):
            r = client.get(path, headers, ip=p.ip)
    return r


def _login_token(client, hdr_fetch, hdr_post):
    """What login9.js does: mint the login token for this session and fingerprint. '' when there is no report."""
    from defenses.token_binding import zero_bits
    import hashlib
    r = client.get("/api/login/challenge", hdr_fetch)
    if r.status_code != 200:
        return ""
    c = r.json()
    counter = 0
    while zero_bits(hashlib.sha256(f"{c['nonce']}:{c['fp_hash']}:{counter}".encode()).digest()) < c["bits"]:
        counter += 1
    t = client.post("/api/login/token", json={"nonce": c["nonce"], "counter": counter}, headers=hdr_post)
    return t.json().get("token", "") if t.status_code == 200 else ""


def _gate_ms(server_timing):
    m = re.search(r"gate;dur=([\d.]+)", server_timing)
    return float(m.group(1)) if m else None


def scenario_ch9_drop(p, client, rng):
    from demo_site.seed import password_for, username
    name, behavior = assignment(p)
    prof = _profile(p, name)
    p.result.update(profile=name, behavior=behavior or "no_telemetry")
    client.ja4 = CLAIMED_JA4[family(name)]
    nav = profile_replay.headers(client, prof["navigation_headers"])
    time.sleep(rng.uniform(0, 3))

    post = profile_replay.headers(client, prof["post_headers"])
    r = _page(p, client, "/", nav, post)
    if r.status_code != 200:
        return population._stop(p, client, "blocked", r)
    m = NONCE.search(r.text)
    post = profile_replay.headers(client, prof["post_headers"])
    fetch = profile_replay.headers(client, prof["fetch_headers"])
    if prof.get("signals") is not None and m:                       # a browser with JavaScript runs the sensor
        client.post("/api/telemetry", headers=post, json={"kind": "sensor", "nonce": m.group(1), "signals": prof["signals"]})
    time.sleep(rng.uniform(0.3, 1.0))

    if p.actor == FIRST_TIMER:
        tag = f"{rng.getrandbits(24):06x}"
        r = client.post("/api/register", headers=post, json={
            "email": f"first.timer.{tag}@example.test", "password": "first-time-buyer-pw", "name": "Pat First",
            "address": f"{rng.randint(10, 990)} Juniper Ct, Boise ID 83702"})
        stage = "register"
    else:
        token = _login_token(client, fetch, post)
        i = p.account if p.account is not None else 100
        r = client.post("/api/login", headers=post + [("X-Login-Token", token)],
                        json={"email": username(i), "password": password_for(i)})
        stage = "login"
        if r.status_code == 403 and _wants_otp(r):       # Round 4's campaign step-up: friction, not a loss
            p.result["challenged"] = 1
            if not _enter_otp(client, username(i), fetch, post):
                p.result.update(stage=stage)
                return population._stop(p, client, "stuck_on_challenge", r)
            r = None                                     # the code opened the session the login was holding
    if r is not None and r.status_code >= 400:
        p.result.update(stage=stage)
        return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)

    time.sleep(rng.uniform(0.3, 1.0))
    r = _page(p, client, DROP, _link(nav, BASE_URL + "/"), post)
    rel = None
    if r.status_code == 200:
        m = re.search(r"data-layout='([^']+)'", r.text)
        rel = json.loads(html.unescape(m.group(1))) if m else None
    if rel is None:
        return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)
    page = r
    who = humans.identity(rng)
    if behavior is not None:
        telemetry, who, _ = humans.make_session(rel, behavior, rng)
        t = client.post("/api/telemetry", json=dict(telemetry, kind="behavior"), headers=post)
        p.result["telemetry_bytes"] = len(t.request.body or b"")
    time.sleep(rng.uniform(*p.fill) if p.autofill else rng.uniform(5.0, 8.0))        # the dwell
    form = _form(post, nav, BASE_URL + DROP)
    data = {"csrf": csrf_of(page.text), "name": who["name"], "email": f"{p.actor.replace(':', '.')}@example.test",
            "size": who["size"], "address": ""}
    for attempt in range(2):
        r = client.post(DROP, data, form, ip=p.checkout_ip, allow_redirects=False)
        if r.status_code == 403 and 'data-challenge="proof"' in r.text and attempt == 0:
            p.result["challenged"] = 1
            if not _solve_proof(client, r, post):
                break
            continue
        break
    verdict = r.headers.get("X-Lab-Verdict")
    p.result.update(score=int(r.headers.get("X-Lab-Score") or 0), signals=r.headers.get("X-Lab-Signals", ""),
                    gate_ms=_gate_ms(r.headers.get("Server-Timing", "")))
    if r.status_code == 200 and "order-confirmed" in r.text:
        return population._stop(p, client, "bought", r)
    if r.status_code == 410:
        return population._stop(p, client, "sold_out", r)
    if verdict == "challenge" or p.result.get("challenged"):
        return population._stop(p, client, "stuck_on_challenge", r)
    return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)


population.SCENARIOS["ch9_drop"] = scenario_ch9_drop
