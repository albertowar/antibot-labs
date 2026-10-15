"""
W2 Ch8's customers: the 200 people whose logins every decision engine is measured against.

This lab ships no bot traffic. Each round's attacker is a signal profile you score with
`python tools/sweep.py --signals a,b,c`; what runs live is the other half of every defense: what the
decision engine costs the real people who sign in. This module replaces the starter's 40 browsing
shoppers with 200 people who only sign in (seed users user000..199), generated from a fixed seed so
every checkpoint sees the same people. Most are unremarkable browsers on home broadband. The ones
who matter are the minorities, because each one trips exactly the kind of weak signal a layer was
tuned on:

    persona        share   trips                        why it is a real person
    vpn            ~6%     datacenter_asn, tz mismatch  privacy, work VPN, travel
    cgnat          ~5%     ip_elevated / ip_burst       mobile carrier NAT (two shared addresses)
    privacy        ~3%     fp_randomized                Firefox RFP, Brave, extensions
    tor            ~1%     tor_exit + fp_randomized     Tor Browser
    a11y           ~2%     no_pointer                   keyboard-only, screen readers
    autofill       ~10%    no_keystrokes                password managers, paste
    old_device     ~2%     outdated_browser             can't upgrade the hardware
    typo           ~8%     (a failed login)             people mistype passwords

Traits are drawn independently, so some people carry two ("vpn+autofill"). Real users complete
challenges: their browser solves the proof of work, and they read their own mailbox for a step-up
code. Each person signs in the way the page's script does (tools/personas_ch8.py plays risk.js): the
page, the telemetry POST, POST /api/login, then whatever challenge comes back.

Outcomes of a person's sign-in:

    logged_in       200
    typo_rejected   a typo, correctly told "Wrong email or password"
    blocked         refused (403), or - from level 3 - deceived: the store's X-Lab-Verdict says "deceive"
                    although the answer looked like a typo. That counts as hurt.
    stuck_on_challenge   a challenge they could not complete

Friction, not harm: `challenge` records the rung they met ("pow" or "step_up"), `pow_ms` the CPU a
Python client spent (a browser's WebCrypto is faster).

Safety rails: source addresses come from data/world.json (documentation ranges), the client is
tools/labclient.py (refuses a non-local DEMO_URL), the credentials are the synthetic seed users'.

The people run ONE AT A TIME (every Round sets threads=1): the per-IP and per-cluster counters
see the same order on every run, so a checkpoint prints the same numbers every time.
"""

import os
import random
import sys
import time
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import population  # noqa: E402
from labclient import BASE_URL, WORLD, LabClient, world_pool  # noqa: E402
from defenses import sensor_tls  # noqa: E402
from demo_site.ext.risk import solve_pow  # noqa: E402
from demo_site.seed import password_for, username  # noqa: E402

SIZE = 200
SEED = 2026
CHROME_MAJOR, FIREFOX_MAJOR, SAFARI_MAJOR = 153, 155, 26
BUTTON = (640, 420)

DEVICES = {
    "chrome-win": {"engine": "chrome", "platform": "Win32", "mobile": False,
                   "ua": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36",
                   "ch_platform": '"Windows"',
                   "gpus": ["ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002504) Direct3D11 vs_5_0 ps_5_0, D3D11)",
                            "ANGLE (AMD, AMD Radeon RX 6600 (0x000073FF) Direct3D11 vs_5_0 ps_5_0, D3D11)",
                            "ANGLE (Intel, Intel(R) UHD Graphics 620 (0x00005917) Direct3D11 vs_5_0 ps_5_0, D3D11)"]},
    "chrome-mac": {"engine": "chrome", "platform": "MacIntel", "mobile": False,
                   "ua": f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36",
                   "ch_platform": '"macOS"',
                   "gpus": ["ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)",
                            "ANGLE (Apple, ANGLE Metal Renderer: Apple M3 Pro, Unspecified Version)"]},
    "chrome-android": {"engine": "chrome", "platform": "Linux armv81", "mobile": True,
                       "ua": f"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Mobile Safari/537.36",
                       "ch_platform": '"Android"', "gpus": ["Adreno (TM) 740", "Mali-G715-Immortalis MC11"]},
    "firefox-win": {"engine": "firefox", "platform": "Win32", "mobile": False,
                    "ua": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{FIREFOX_MAJOR}.0) Gecko/20100101 Firefox/{FIREFOX_MAJOR}.0",
                    "gpus": ["ANGLE (NVIDIA, NVIDIA GeForce GTX 980 Direct3D11 vs_5_0 ps_5_0), or similar",
                             "ANGLE (Intel, Intel(R) HD Graphics 400 Direct3D11 vs_5_0 ps_5_0), or similar"]},
    "firefox-linux": {"engine": "firefox", "platform": "Linux x86_64", "mobile": False,
                      "ua": f"Mozilla/5.0 (X11; Linux x86_64; rv:{FIREFOX_MAJOR}.0) Gecko/20100101 Firefox/{FIREFOX_MAJOR}.0",
                      "gpus": ["Mesa Intel(R) UHD Graphics 620 (KBL GT2)", "AMD Radeon Graphics (radeonsi, renoir)"]},
    "safari-mac": {"engine": "safari", "platform": "MacIntel", "mobile": False,
                   "ua": f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{SAFARI_MAJOR}.0 Safari/605.1.15",
                   "gpus": ["Apple GPU"]},
    "safari-ios": {"engine": "safari", "platform": "iPhone", "mobile": True,
                   "ua": f"Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{SAFARI_MAJOR}.0 Mobile/15E148 Safari/604.1",
                   "gpus": ["Apple GPU"]},
    # Old hardware stuck on the last Chrome that supports Windows 7
    "chrome-win7": {"engine": "chrome", "platform": "Win32", "mobile": False,
                    "ua": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
                    "ch_platform": '"Windows"', "ch_major": 109,
                    "gpus": ["ANGLE (Intel, Intel(R) HD Graphics 4000 Direct3D11 vs_5_0 ps_5_0, D3D11)"]},
}
WEIGHTED_DEVICES = [("chrome-win", 36), ("chrome-mac", 10), ("safari-mac", 8), ("firefox-win", 8),
                    ("firefox-linux", 3), ("safari-ios", 20), ("chrome-android", 15)]
HOME_POOLS = ["home_broadband", "home_cable", "home_fiber", "home_v6"]


def _weighted(rng, items):
    return rng.choices([i for i, _ in items], weights=[w for _, w in items])[0]


def browser_headers(name, accept_language="en-US,en;q=0.9"):
    """Headers of the page's fetch() POST, in the order the engine sends them (W1 Ch4)."""
    b = DEVICES[name]
    origin, referer = BASE_URL, f"{BASE_URL}/login"
    if b["engine"] == "chrome":
        major = b.get("ch_major", CHROME_MAJOR)
        return [("sec-ch-ua", f'"Chromium";v="{major}", "Not:A-Brand";v="99", "Google Chrome";v="{major}"'),
                ("sec-ch-ua-mobile", "?1" if b["mobile"] else "?0"), ("sec-ch-ua-platform", b["ch_platform"]),
                ("User-Agent", b["ua"]), ("Accept", "*/*"), ("Origin", origin),
                ("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Mode", "cors"), ("Sec-Fetch-Dest", "empty"),
                ("Referer", referer), ("Accept-Encoding", "gzip, deflate, br, zstd"), ("Accept-Language", accept_language)]
    if b["engine"] == "firefox":
        return [("User-Agent", b["ua"]), ("Accept", "*/*"), ("Accept-Language", accept_language),
                ("Accept-Encoding", "gzip, deflate, br, zstd"), ("Referer", referer), ("Origin", origin),
                ("Sec-Fetch-Dest", "empty"), ("Sec-Fetch-Mode", "cors"), ("Sec-Fetch-Site", "same-origin")]
    return [("Accept", "*/*"), ("Sec-Fetch-Site", "same-origin"), ("Accept-Language", accept_language),
            ("Sec-Fetch-Mode", "cors"), ("Accept-Encoding", "gzip, deflate, br"), ("Origin", origin),
            ("User-Agent", b["ua"]), ("Referer", referer), ("Sec-Fetch-Dest", "empty")]


# --- what the collector would report -------------------------------------------------------------

def fingerprint(rng, device, tz, languages, randomized=False):
    import string
    b = DEVICES[device]
    canvas = "".join(rng.choices(string.hexdigits.lower(), k=24))
    return {"platform": b["platform"], "webgl_renderer": rng.choice(b["gpus"]), "canvas": canvas,
            "canvas2": "".join(rng.choices(string.hexdigits.lower(), k=24)) if randomized else canvas,
            "screen": rng.choice(["390x844", "412x915"]) if b["mobile"] else
            rng.choice(["1920x1080", "1536x864", "2560x1440", "1440x900"]),
            "timezone": tz, "languages": list(languages), "webdriver": False, "cdp": False,
            "hardware_concurrency": rng.choice([4, 8, 8, 12, 16])}


def human_path(rng):
    """A hand: a curved path with overshoot noise and uneven event spacing."""
    import math
    sx, sy = rng.uniform(100, 1200), rng.uniform(80, 700)
    ex, ey = BUTTON[0] + rng.uniform(-30, 30), BUTTON[1] + rng.uniform(-8, 8)
    dx, dy = ex - sx, ey - sy
    length = math.hypot(dx, dy) or 1
    nx, ny = -dy / length, dx / length
    bend1, bend2 = rng.uniform(0.15, 0.4) * length * rng.choice([-1, 1]), rng.uniform(0.05, 0.3) * length
    c1 = (sx + dx * 0.3 + nx * bend1, sy + dy * 0.3 + ny * bend1)
    c2 = (sx + dx * 0.7 + nx * bend2, sy + dy * 0.7 + ny * bend2)
    n, t, points = rng.randint(25, 60), 0, []
    for i in range(n):
        u = i / (n - 1)
        x = (1 - u) ** 3 * sx + 3 * (1 - u) ** 2 * u * c1[0] + 3 * (1 - u) * u ** 2 * c2[0] + u ** 3 * ex
        y = (1 - u) ** 3 * sy + 3 * (1 - u) ** 2 * u * c1[1] + 3 * (1 - u) * u ** 2 * c2[1] + u ** 3 * ey
        t += max(4, rng.gauss(16, 6))
        points.append([round(t), round(x + rng.gauss(0, 1.5)), round(y + rng.gauss(0, 1.5))])
    return points


def taps(rng):
    t, points = 0, []
    for _ in range(rng.randint(3, 6)):
        t += rng.uniform(300, 1500)
        points.append([round(t), round(rng.uniform(20, 370)), round(rng.uniform(100, 800))])
    return points


def keystrokes(rng, count):
    t, keys = rng.uniform(500, 1500), []
    for _ in range(count):
        t += rng.uniform(80, 260)
        keys.append([round(t), round(t + rng.uniform(50, 140))])
    return keys


# --- the people ------------------------------------------------------------------------------------

def make_people(size=SIZE, seed=SEED):
    """Persona records, same draw order as the chapter has always used: the numbers depend on it."""
    rng = random.Random(seed)
    next_ip = Counter()
    pools = {n: world_pool(n) for n in HOME_POOLS + ["consumer_vpn", "tor_exit", "mobile_cgnat"]}
    people = []
    for i in range(size):
        device = _weighted(rng, [(d, w) for d, w in WEIGHTED_DEVICES])
        home = rng.choice(HOME_POOLS)
        traits = []
        if rng.random() < 0.02 and not DEVICES[device]["mobile"]:
            device = "chrome-win7"
            traits.append("old_device")
        if rng.random() < 0.01:
            device, traits = "firefox-win", traits + ["tor"]
        elif rng.random() < 0.03:
            traits.append("privacy")
        if DEVICES[device]["mobile"] and rng.random() < 0.15:
            traits.append("cgnat")
        elif not DEVICES[device]["mobile"] and "tor" not in traits and rng.random() < 0.06:
            traits.append("vpn")
        if not DEVICES[device]["mobile"] and rng.random() < 0.02:
            traits.append("a11y")
        if rng.random() < 0.10:
            traits.append("autofill")
        if rng.random() < 0.08:
            traits.append("typo")

        pool = "tor_exit" if "tor" in traits else "consumer_vpn" if "vpn" in traits else \
            "mobile_cgnat" if "cgnat" in traits else home
        # VPN and Tor exits are shared by many users, carrier NAT by even more; homes are not
        index = rng.randrange(8) if pool in ("consumer_vpn", "tor_exit") else next_ip[pool]
        next_ip[pool] += 1
        spanish = rng.random() < 0.08
        people.append({
            "id": i, "traits": traits, "device": device, "ip": pools[pool][index % len(pools[pool])],
            "home_tz": "UTC" if "tor" in traits else WORLD["pools"][home]["tz"],
            "languages": ["es-US", "es", "en"] if spanish else ["en-US", "en"],
            "accept_language": "es-US,es;q=0.9,en;q=0.8" if spanish else "en-US,en;q=0.9",
            "seed": seed * 10_000 + i,
        })
    return people


def people(seed=population.SEED, n=None):
    """Replaces population.personas(): the chapter's 200 customers as population Personas."""
    out = []
    for rec in make_people():
        persona = "+".join(rec["traits"]) or "typical"
        p = population.Persona(f"human:{persona}:{rec['id']:03d}", persona, (rec["device"],), rec["ip"], account=rec["id"])
        p.rec = rec
        out.append(p)
    return out[:n] if n else out


# --- one sign-in -----------------------------------------------------------------------------------

def _gate_ms(response):
    for part in response.headers.get("Server-Timing", "").split(","):
        name, _, dur = part.strip().partition(";dur=")
        if name == "gate" and dur:
            return float(dur)
    return None


def _complete(client, headers, email, kind, payload, res):
    """What a customer does with a challenge. Returns True if the answer verified."""
    if kind == "pow":
        started = time.perf_counter()
        nonce = solve_pow(payload["prefix"], payload["bits"])
        res["pow_ms"] = res.get("pow_ms", 0) + (time.perf_counter() - started) * 1000
        answer = {"type": "pow", "answer": {"nonce": nonce}}
    else:
        mail = client.get(f"/lab/mailbox/{email}").json()["messages"]
        codes = [m["code"] for m in mail if "code" in m]
        answer = {"type": "step_up", "answer": {"code": codes[-1] if codes else "000000"}}
    return client.post("/api/challenge/verify", json=answer, headers=headers).status_code == 200


def scenario_ch8_login(p, client, rng):
    rec = p.rec
    traits, device = rec["traits"], rec["device"]
    b = DEVICES[device]
    mine = random.Random(rec["seed"])
    client.ja4 = sensor_tls.JA4[b["engine"]]
    headers = browser_headers(device, rec["accept_language"])
    client.get("/login", headers)

    email, password = username(rec["id"]), password_for(rec["id"])
    if "typo" in traits:
        password = password[:-1] + ("1" if password[-1] != "1" else "2")     # always a different password
    if "a11y" in traits:
        mouse, pointer = [], "mouse"
    elif b["mobile"]:
        mouse, pointer = taps(mine), "touch"
    else:
        mouse, pointer = human_path(mine), "mouse"
    keys = [] if "autofill" in traits else keystrokes(mine, len(email) + len(password))
    fp = fingerprint(mine, device, rec["home_tz"], rec["languages"], randomized=bool({"privacy", "tor"} & set(traits)))
    client.post("/api/telemetry", json={"kind": "risk", "fp": fp, "behavior": {"mouse": mouse, "keys": keys, "pointer_type": pointer}},
                headers=headers)

    res = p.result
    res.update(challenge="", pow_ms=0.0, gate_ms=None)
    body = {"email": email, "password": password, "website": ""}
    r = client.post("/api/login", json=body, headers=headers)
    res["gate_ms"] = _gate_ms(r)
    for _ in range(2):
        err = (r.json().get("error") or {}) if r.status_code == 403 else {}
        if err.get("code") != "challenge_required":
            break
        res["challenge"] = res["challenge"] or err["challenge"]
        if not _complete(client, headers, email, err["challenge"], err["payload"], res):
            res.update(outcome="stuck_on_challenge", status=r.status_code, requests=client.requests, verdict=client.verdict())
            return res
        r = client.post("/api/login", json=body, headers=headers)

    verdict = client.verdict()
    if r.status_code == 200:
        outcome = "logged_in"
    elif r.status_code == 401 and verdict and verdict[0] == "deceive":
        outcome = "blocked"                           # the answer looked like a typo; the store says it was a block
    elif r.status_code == 401:
        outcome = "typo_rejected" if "typo" in traits else "failed"
    else:
        outcome = "blocked" if r.status_code in (403, 429) else "failed"
    res.update(outcome=outcome, status=r.status_code, requests=client.requests, verdict=verdict)
    return res


population.SCENARIOS["ch8_login"] = scenario_ch8_login
population.HAPPY |= {"typo_rejected"}                 # a mistyped password correctly rejected is not a false positive
# The 200 customers and the one-at-a-time ordering reach the checkpoint declaratively since
# contract 1.7: every Round in tools/checkpoint.py sets people=people and threads=1 (the per-IP
# and per-cluster counters see the same order on every run, so a checkpoint prints the same
# numbers every time).


def summarize(results):
    """{persona: {"people", "blocked", "pow", "step_up", "stuck"}} for the checkpoint and the README."""
    out = defaultdict(lambda: {"people": 0, "blocked": 0, "pow": 0, "step_up": 0, "stuck": 0})
    for r in results:
        row = out[r["persona"]]
        row["people"] += 1
        row["blocked"] += r.get("outcome") == "blocked"
        row["stuck"] += r.get("outcome") == "stuck_on_challenge"
        if r.get("challenge") in ("pow", "step_up"):
            row[r["challenge"]] += 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]["people"]))


if __name__ == "__main__":
    import labclient
    labclient.wait_for_store()
    results = population.run("ch8_login", people=people(), threads=1, quiet=True)
    population.print_results(results)
