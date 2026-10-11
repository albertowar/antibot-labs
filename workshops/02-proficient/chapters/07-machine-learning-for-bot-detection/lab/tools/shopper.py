"""
Chapter 7 — Shopper engine shared by real-user simulation and every attack

A `Persona` describes one session: network, browser, fingerprint, behavior
and pacing. `shop()` walks the drop-day journey the store is built around:

    home → (login) → browse products → limited drop → add to cart → checkout

Real users (tools/simulate.py) and bots (attacks/*.py) use the SAME engine.
They differ only in their Persona, which is exactly the point: the model
can only learn from what the persona leaks.

Fingerprints and behavior summaries stand in for what the page collectors
from W2 Ch3 (behavior) and W2 Ch4 (fingerprinting) would POST to
/api/telemetry. No real browser runs in this lab.

Ground truth (who was actually a bot) is appended to data/truth.jsonl.
Only the scoreboard and `labels.py --audit` may read it: production has no
such file, and a model trained on it would be cheating.
"""

import hashlib
import json
import os
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Optional

import httpx

import labclient as labnet

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
TRUTH_FILE = os.path.join(DATA_DIR, "truth.jsonl")
_truth_lock = threading.Lock()

N_PRODUCTS = 40

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


def browser_headers(langs):
    return {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": accept_language(langs),
            "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate"}


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


# --- behavior summaries (what the W2 Ch3 collector would report) -------------

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
    import math
    mu = math.log(mean_s) - 0.32

    def _think(rng):
        return rng.lognormvariate(mu, 0.8)
    return _think


def fixed_think(seconds, jitter=0.05):
    def _think(rng):
        return seconds * (1 + rng.uniform(-jitter, jitter))
    return _think


@dataclass
class Persona:
    actor: str                  # "human" or the attack script name
    cohort: str                 # human cohort or bot family
    is_bot: bool
    ip: str
    user_agent: str
    headers: dict = field(default_factory=dict)
    fp: Optional[dict] = None             # None: never runs JS
    behavior: Optional[dict] = None
    think: Callable = field(default_factory=human_think)
    browse: int = 2                       # product pages before the drop
    loads_assets: bool = True
    account: Optional[str] = None
    honeypot: float = 0.0                 # P(follow the hidden link)
    api_v0: float = 0.0                   # P(call the robots.txt-disallowed API)
    usd_per_gb: float = 0.0
    config: dict = field(default_factory=dict)   # attack knobs, for reports


def _server_ms(r):
    for part in r.headers.get("Server-Timing", "").split(","):
        if part.strip().startswith("mlscore;dur="):
            return float(part.split("=")[1])
    return None


def shop(p, rng):
    """Walk the drop-day journey once. Returns a result dict for the scoreboard."""
    c = labnet.Client(p.ip, p.user_agent, p.headers)
    out = {"actor": p.actor, "cohort": p.cohort, "is_bot": p.is_bot, "ip": p.ip,
           "sid": None, "status": None, "order_id": None, "score": None,
           "score_ms": None, "final": None, "kb": 0, "usd": 0.0, "config": p.config}
    try:
        def page(path):
            c.get(path, page=True, assets=p.loads_assets)
            if p.loads_assets:
                img = path.rsplit("/", 1)[-1] if path.startswith("/product/") else "hero"
                c.get(f"/img/{img}.svg")

        page("/")
        if p.loads_assets:
            c.get("/static/app.js")
            c.get("/static/style.css")
        if p.fp is not None:
            c.post("/api/telemetry", {"kind": "fp", "data": p.fp})
        if rng.random() < p.honeypot:
            labnet.think(p.think(rng))
            page("/specials-archive")
        if rng.random() < p.api_v0:
            c.get("/api/v0/products")
        if p.account:
            labnet.think(p.think(rng))
            c.post("/login", {"username": p.account})
        for _ in range(p.browse):
            labnet.think(p.think(rng))
            page(f"/product/{rng.randint(1, N_PRODUCTS)}")
        labnet.think(p.think(rng))
        page("/product/drop")
        labnet.think(p.think(rng))
        c.post("/cart/add", {"sku": "DROP-1"})
        if p.behavior is not None:
            c.post("/api/telemetry", {"kind": "beh", "data": p.behavior})
        labnet.think(p.think(rng))
        r = c.post("/checkout", {"sku": "DROP-1", "qty": 1})
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        out.update(status=r.status_code, order_id=body.get("order_id"),
                   score=body.get("score"), score_ms=_server_ms(r),
                   final={200: "confirmed", 403: "blocked"}.get(r.status_code, body.get("status")))
    except httpx.HTTPError as e:
        out.update(status=-1, final=f"error: {e.__class__.__name__}")
    finally:
        out["sid"] = c.sid
        out["kb"] = c.kb
        out["usd"] = c.kb / 1024 / 1024 * p.usd_per_gb
        c.close()
    return out


def log_truth(results, run):
    os.makedirs(DATA_DIR, exist_ok=True)
    with _truth_lock, open(TRUTH_FILE, "a") as fh:
        for r in results:
            if r["sid"]:
                fh.write(json.dumps({"sid": r["sid"], "actor": r["actor"], "cohort": r["cohort"],
                                     "is_bot": r["is_bot"], "run": run}) + "\n")


def run_sessions(personas, seed=0, workers=16, run="run"):
    """Run personas concurrently; log ground truth; resolve deferred (Round 4) orders."""
    rngs = [random.Random(seed * 100003 + i) for i in range(len(personas))]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(shop, personas, rngs))
    log_truth(results, run)
    resolve_pending(results)
    return results


def resolve_pending(results):
    """Round 4: checkout returns 202 'pending review'. Wait for the review, then read the outcome."""
    pending = [r for r in results if r["status"] == 202 and r["order_id"]]
    if not pending:
        return
    with httpx.Client(base_url=labnet.target(), headers={"X-Lab-Client-IP": "10.2.0.2"},
                      timeout=10) as http:
        deadline = time.time() + 120
        while pending and time.time() < deadline:
            still = []
            for r in pending:
                body = http.get(f"/orders/{r['order_id']}").json()
                if body["status"] == "pending":
                    still.append(r)
                else:
                    r["final"] = body["status"]
            pending = still
            if pending:
                time.sleep(0.5)


def succeeded(r):
    """A checkout that results in a shipped order."""
    return r["final"] == "confirmed"
