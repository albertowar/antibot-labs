"""
Shopper engine shared by the real-user simulation and every attack

A `Persona` describes one session: network, browser, fingerprint, behaviour and pacing. `shop()` walks
the drop-day journey the store is built around:

    home -> (sign in) -> browse products -> the limited drop -> buy

Real users (tools/personas_ch7.py) and bots (attacks/*.py) use the SAME engine. They differ only in
their Persona, which is exactly the point: the model can only learn from what the persona leaks.

Fingerprints and behaviour summaries stand in for what the page collectors from W2 Ch5 (behaviour)
and W2 Ch2 (fingerprinting) would POST to /api/telemetry. No real browser runs in this lab.

Lab time. `think()` sleeps a VIRTUAL duration times LAB_TIME_SCALE (default 0.02), so a 10 s pause is
0.2 s. The sleep only paces the store; the TIMESTAMP every request carries is the session's virtual
clock (`X-Virtual-Ts`, advanced by exactly the virtual duration), so the recorded history is
deterministic: the same seed writes the same timeline whatever the machine's load. Before this,
features divided measured wall gaps by LAB_TIME_SCALE, which amplified scheduling jitter 50x and
trained a different model on every fresh run (the chapter's old P1).

Ground truth (who was actually a bot) is the actor label every request carries to the store's edge
(`human:<cohort>:<n>`, `bot:<family>:<n>`). The edge strips it before any defense runs; only the
scoreboard, the decision log and tools/audit.py read it.
"""

import hashlib
import math
import os
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import labclient  # noqa: E402  (runs the labnet guard on import)
import population  # noqa: E402
from labclient import BASE_URL, LabClient, csrf_of  # noqa: E402
from demo_site.seed import password_for, username  # noqa: E402

LAB_TIME_SCALE = float(os.environ.get("LAB_TIME_SCALE", "0.02"))
DROP = "lab-hoodie-1"
N_PRODUCTS = 40

# Simulated page weight for the attacker's bandwidth bill
PAGE_WITH_ASSETS_KB = 1800
PAGE_ONLY_KB = 60
API_KB = 4

HTML_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

UA = {
    "chrome_win": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
    "firefox_win": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0",
    "chrome_mac": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
    "safari_mac": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
                  "(KHTML, like Gecko) Version/26.0 Safari/605.1.15",
    "chrome_linux": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
    "firefox_linux": "Mozilla/5.0 (X11; Linux x86_64; rv:155.0) Gecko/20100101 Firefox/155.0",
    "safari_iphone": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 "
                     "(KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
    "chrome_android": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/153.0.0.0 Mobile Safari/537.36",
}

# name: platform, gpu, screens, dpr, hardwareConcurrency, touch points, UAs, weight, canvas variants
DEVICES = {
    "win-nvidia": ("Win32", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
                   ["1920x1080", "2560x1440"], [1.0], [8, 12, 16], [0], ["chrome_win", "firefox_win"], 3, 4),
    "win-intel": ("Win32", "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)",
                  ["1920x1080", "1536x864", "1366x768"], [1.0, 1.25], [4, 8], [0, 0, 0, 10],
                  ["chrome_win", "firefox_win"], 4, 4),
    "win-amd": ("Win32", "ANGLE (AMD, AMD Radeon RX 6600 Direct3D11 vs_5_0 ps_5_0, D3D11)",
                ["1920x1080", "2560x1440"], [1.0], [12, 16], [0], ["chrome_win"], 2, 4),
    "mac-m1": ("MacIntel", "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)",
               ["1440x900", "1512x982"], [2.0], [8], [0], ["chrome_mac", "safari_mac"], 3, 3),
    "mac-m3": ("MacIntel", "ANGLE (Apple, ANGLE Metal Renderer: Apple M3 Pro, Unspecified Version)",
               ["1728x1117", "1512x982"], [2.0], [11, 12], [0], ["chrome_mac", "safari_mac"], 2, 3),
    "linux-intel": ("Linux x86_64", "Mesa Intel(R) UHD Graphics 630 (CFL GT2)",
                    ["1920x1080"], [1.0], [8], [0], ["chrome_linux", "firefox_linux"], 1, 3),
    "iphone-15": ("iPhone", "Apple GPU", ["393x852"], [3.0], [4], [5], ["safari_iphone"], 4, 1),
    "iphone-13": ("iPhone", "Apple GPU", ["390x844"], [3.0], [4], [5], ["safari_iphone"], 3, 1),
    "pixel-8": ("Linux armv81", "Mali-G715", ["412x915"], [2.625], [8], [5], ["chrome_android"], 2, 2),
    "galaxy-s23": ("Linux armv81", "Adreno (TM) 740", ["360x780"], [3.0], [8], [5], ["chrome_android"], 2, 2),
}
DESKTOPS = [d for d in DEVICES if not d.startswith(("iphone", "pixel", "galaxy"))]
MOBILES = [d for d in DEVICES if d not in DESKTOPS]

# tz, languages, country, weight
LOCALES = [
    ("Europe/Madrid", ["es-ES", "es", "en"], "ES", 2),
    ("America/New_York", ["en-US", "en"], "US", 3),
    ("America/Chicago", ["en-US", "en"], "US", 1),
    ("America/Los_Angeles", ["en-US", "en"], "US", 2),
    ("Europe/Berlin", ["de-DE", "de", "en"], "DE", 2),
    ("Europe/London", ["en-GB", "en"], "GB", 1),
]


def weighted(rng, items, weights):
    return rng.choices(items, weights=weights, k=1)[0]


def pick_device(rng, mobile=False):
    names = MOBILES if mobile else DESKTOPS
    return weighted(rng, names, [DEVICES[n][7] for n in names])


def pick_locale(rng, countries=None):
    locs = [loc for loc in LOCALES if not countries or loc[2] in countries]
    return weighted(rng, locs, [loc[3] for loc in locs])


def accept_language(langs):
    parts = [langs[0]] + [f"{lang};q={0.9 - 0.1 * i:.1f}" for i, lang in enumerate(langs[1:])]
    return ",".join(parts)


def fingerprint(rng, device, locale, ua_key, canvas=None):
    """A fingerprint that is internally consistent: what a real device reports."""
    platform, gpu, screens, dprs, hws, touches, _uas, _w, variants = DEVICES[device]
    screen, dpr = rng.choice(screens), rng.choice(dprs)
    hw, touch = rng.choice(hws), rng.choice(touches)
    variant = rng.randrange(variants)
    if canvas is None:
        # Same hardware + driver + fonts = same canvas: identical devices collide
        canvas = hashlib.sha1(f"{device}:{variant}".encode()).hexdigest()[:16]
    return {"platform": platform, "ua": UA[ua_key], "gpu": gpu, "screen": screen, "dpr": dpr,
            "tz": locale[0], "langs": locale[1], "hw": hw, "touch": touch,
            "webdriver": False, "canvas": canvas}


# --- behaviour summaries (what the W2 Ch5 collector would report) -------------

def _clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


def desktop_behavior(rng, pace=1.0):
    keys = rng.choice([0, 0, rng.randint(5, 40)])
    return {"mouse_moves": int(rng.lognormvariate(5.6, 0.5) / pace),
            "straightness": round(_clamp(rng.betavariate(5, 3)), 3),
            "speed_cv": round(rng.uniform(0.55, 1.3), 3),
            "clicks": rng.randint(3, 12), "keys": keys,
            "key_cv": round(rng.uniform(0.3, 0.8), 3) if keys else None,
            "touches": 0, "scrolls": rng.randint(4, 40),
            "first_input_ms": int(rng.lognormvariate(7.3, 0.5) / pace)}


def mobile_behavior(rng):
    keys = rng.choice([0, 0, rng.randint(3, 20)])
    return {"mouse_moves": 0, "straightness": None, "speed_cv": None,
            "clicks": rng.randint(3, 10), "keys": keys,
            "key_cv": round(rng.uniform(0.3, 0.9), 3) if keys else None,
            "touches": rng.randint(15, 90), "scrolls": rng.randint(10, 60),
            "first_input_ms": int(rng.lognormvariate(7.1, 0.5))}


def keyboard_behavior(rng):
    """Screen-reader / keyboard-only users: no pointer at all, lots of Tab."""
    return {"mouse_moves": 0, "straightness": None, "speed_cv": None,
            "clicks": rng.randint(0, 1), "keys": rng.randint(60, 200),
            "key_cv": round(rng.uniform(0.3, 0.6), 3),
            "touches": 0, "scrolls": rng.randint(0, 5),
            "first_input_ms": int(rng.lognormvariate(7.6, 0.4))}


def human_think(mean_s=6.0):
    """Log-normal think time: mostly a few seconds, occasionally much longer."""
    mu = math.log(mean_s) - 0.32

    def _think(rng):
        return rng.lognormvariate(mu, 0.8)
    return _think


def fixed_think(seconds, jitter=0.05):
    def _think(rng):
        return seconds * (1 + rng.uniform(-jitter, jitter))
    return _think


SIM_EPOCH = 1_760_000_000.0   # synthetic "drop day" origin for the virtual clock (not wall time)
ARRIVAL_WINDOW_S = 6000.0     # sessions arrive across this many virtual seconds of the drop day
REQUEST_COST_S = 0.05         # virtual cost of one request (network + render), so back-to-back calls still tick

_VCLOCK = threading.local()


def _clock():
    if not hasattr(_VCLOCK, "now"):
        _VCLOCK.now = SIM_EPOCH
    return _VCLOCK


def start_virtual_session(arrival_s):
    """Pin this thread's virtual clock to the session's seeded arrival time on the drop day."""
    _VCLOCK.now = SIM_EPOCH + arrival_s


def virtual_now():
    return _clock().now


def think(virtual_seconds):
    """Sleep a virtual duration, compressed by LAB_TIME_SCALE; the virtual clock advances the full amount."""
    v = max(virtual_seconds, 0)
    _clock().now += v
    time.sleep(v * LAB_TIME_SCALE)


@dataclass
class Persona(population.Persona):
    """One session. `persona` (inherited) is the cohort or bot family; `actor` is the ground-truth label."""
    ua: str = ""
    accept_language: Optional[str] = "en-US,en;q=0.9"
    browser_like: bool = True                # Accept, Accept-Language and Sec-Fetch-* headers like a browser
    fp: Optional[dict] = None                # None: never runs JS
    behavior: Optional[dict] = None
    think: Callable = field(default_factory=human_think)
    browse: int = 2                          # product pages before the drop
    loads_assets: bool = True
    honeypot: float = 0.0                    # P(follow the hidden link)
    partner_feed: float = 0.0                # P(call the robots.txt-disallowed endpoint)
    usd_per_gb: float = 0.0
    extra_usd: float = 0.0                   # e.g. a purchased fingerprint
    config: dict = field(default_factory=dict)   # attack knobs, for reports
    arrival_s: float = 0.0                   # seeded offset into the drop day; the session's virtual clock starts here


class _Headers:
    """Header sets in wire order, with the Referer chain of a browser that clicked through the site."""

    def __init__(self, p):
        self.p, self.last = p, None

    @staticmethod
    def _ts():
        """Tick the session's virtual clock one request forward and stamp it on the wire."""
        c = _clock()
        c.now += REQUEST_COST_S
        return ("X-Virtual-Ts", f"{c.now:.3f}")

    def nav(self, post=False):
        p = self.p
        h = [("User-Agent", p.ua), ("Accept", HTML_ACCEPT if p.browser_like else "*/*")]
        if p.browser_like:
            if p.accept_language:
                h.append(("Accept-Language", p.accept_language))
            h += [("Sec-Fetch-Site", "same-origin" if self.last else "none"), ("Sec-Fetch-Mode", "navigate")]
        if self.last:
            h.append(("Referer", self.last))
        h.append(self._ts())
        return h

    def ajax(self):
        p = self.p
        h = [("User-Agent", p.ua), ("Accept", "application/json")]
        if p.browser_like:
            h += [("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Mode", "cors")]
        if self.last:
            h.append(("Referer", self.last))
        h.append(self._ts())
        return h

    def asset(self):
        p = self.p
        h = [("User-Agent", p.ua), ("Accept", "*/*")]
        if p.browser_like:
            h += [("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Mode", "no-cors")]
        if self.last:
            h.append(("Referer", self.last))
        h.append(self._ts())
        return h


def _score_of(client):
    v = client.verdict()
    try:
        return int(v[1]) if v else None
    except (TypeError, ValueError):
        return None


def shop(p, client, rng):
    """Walk the drop-day journey once. Fills and returns p.result."""
    start_virtual_session(p.arrival_s)
    out = p.result
    out.update(actor=p.actor, persona=p.persona, is_bot=p.actor.startswith("bot:"), ip=p.ip, kb=0, usd=0.0,
               config=p.config, final=None, order=None, score=None)
    h = _Headers(p)

    def page(path):
        r = client.get(path, headers=h.nav(), allow_redirects=False)
        h.last = BASE_URL + path
        out["kb"] += PAGE_WITH_ASSETS_KB if p.loads_assets else PAGE_ONLY_KB
        if p.loads_assets:
            client.get("/static/css/store.css", headers=h.asset())
            client.get("/static/js/store.js", headers=h.asset())
            if path == "/" or path.startswith(("/product/", "/drop/")):
                client.get("/img/p001.svg" if path == "/" else f"/img/{path.rsplit('/', 1)[-1]}.svg", headers=h.asset())
        return r

    def telemetry(kind, payload):
        out["kb"] += API_KB
        client.post("/api/telemetry", json=dict(payload, kind=kind), headers=h.ajax())

    try:
        page("/")
        if p.fp is not None:
            telemetry("fp", p.fp)
        if rng.random() < p.honeypot:
            think(p.think(rng))
            page("/archive")
        if rng.random() < p.partner_feed:
            out["kb"] += API_KB
            client.get("/partner-feed", headers=h.ajax())
        if p.account is not None:
            think(p.think(rng))
            out["kb"] += API_KB
            client.post("/api/login", json={"email": username(p.account), "password": password_for(p.account)},
                        headers=h.ajax())
        for _ in range(p.browse):
            think(p.think(rng))
            page(f"/product/p{rng.randint(1, N_PRODUCTS):03d}")
        think(p.think(rng))
        r = page(f"/drop/{DROP}")
        if r.status_code != 200:
            out.update(final="blocked" if r.status_code in (403, 429) else f"http_{r.status_code}", score=_score_of(client))
            return out
        fields = {"csrf": csrf_of(r.text), "size": "M"}
        if p.account is None:
            fields["email"] = f"{p.actor.replace(':', '.')}@example.test"
        think(p.think(rng))
        if p.behavior is not None:
            telemetry("beh", p.behavior)
        think(p.think(rng))
        out["kb"] += API_KB
        r = client.post(f"/drop/{DROP}", data=fields, headers=h.nav(post=True), allow_redirects=False)
        out.update(score=_score_of(client), status=r.status_code, verdict=client.verdict())
        if r.status_code == 200 and "order-confirmed" in r.text:
            out["final"] = "confirmed"
        elif r.status_code == 202:
            out.update(final="pending", order=r.json().get("order"))
        elif r.status_code == 403:
            out["final"] = "blocked"
        elif r.status_code == 410:
            out["final"] = "sold_out"
        else:
            out["final"] = f"http_{r.status_code}"
    except Exception as e:                              # a transport error must not kill the run
        out["final"] = f"error: {e.__class__.__name__}"
    finally:
        out["sid"] = client.http.cookies.get("sid")
        out["usd"] = out["kb"] / 1024 / 1024 * p.usd_per_gb + p.extra_usd
        out["requests"] = client.requests
    return out


def resolve_pending(results, timeout=120):
    """Level 4: the purchase answered 202. Wait for the review, then read what it decided."""
    pending = [r for r in results if r.get("final") == "pending" and r.get("order")]
    deadline = time.time() + timeout
    while pending and time.time() < deadline:
        still = []
        for r in pending:
            status = labclient.admin("GET", f"/lab/ml/orders/{r['order']}")["status"]
            if status == "pending":
                still.append(r)
            else:
                r["final"] = status
        pending = still
        if pending:
            time.sleep(0.5)


def succeeded(r):
    """A purchase that ends as a shipped order."""
    return r.get("final") == "confirmed"


def run_sessions(personas, seed=0, workers=16):
    """Run personas concurrently (each with its own client); resolve deferred orders. One result per persona."""
    def one(args):
        p, k = args
        rng = random.Random(seed * 100003 + k)
        # A seeded arrival into the drop day, fixed per (seed, k), so the recorded virtual timeline
        # and every cohort window are identical on any machine regardless of thread scheduling.
        if not p.arrival_s:
            p.arrival_s = random.Random(seed * 100019 + k).uniform(0, ARRIVAL_WINDOW_S)
        return shop(p, LabClient(p.actor, ip=p.ip, rng=rng), rng)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(one, [(p, k) for k, p in enumerate(personas)]))
    resolve_pending(results)
    return results


def summarize_attack(results, **extra):
    """The one JSON line an attack ends with (tools/checkpoint_core reads attempted and succeeded)."""
    return dict({"attempted": len(results), "succeeded": sum(succeeded(r) for r in results),
                 "usd": round(sum(r["usd"] for r in results), 2)}, **extra)

