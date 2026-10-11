"""
W4 Chapter 7 — Shopper engine shared by real-user simulation and every attack

A `Persona` describes one session: network, browser headers, pacing, and
(for attacks) where it puts its text. `shop()` walks the drop-day journey:

    home → (probes) → (login) → browse products → limited drop → cart → checkout

Real users (tools/simulate.py) and bots (attacks/*.py) use the SAME engine.
They differ only in their Persona. In this chapter the interesting
difference is textual: an attacker chooses every byte of User-Agent,
Referer, Accept-Language, request path and login name, and the analyst
reads all of them.

Ground truth (who was actually a bot, and which payload it carried) is
appended to data/truth.jsonl. Only tools/scoreboard.py may read it:
production has no such file.
"""

import json
import os
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Optional

import httpx

import labnet

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
DESKTOP_UAS = ["chrome_win", "chrome_win", "chrome_win", "firefox_win", "chrome_mac",
               "safari_mac", "chrome_linux", "firefox_linux"]
MOBILE_UAS = ["safari_iphone", "safari_iphone", "chrome_android"]

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
    think: Callable = field(default_factory=human_think)
    browse: int = 2                       # product pages before the drop
    loads_assets: bool = True
    account: Optional[str] = None         # any string: the login name is attacker text too
    honeypot: float = 0.0                 # P(follow the hidden link)
    api_v0: float = 0.0                   # P(call the robots.txt-disallowed API)
    probe_paths: list = field(default_factory=list)   # extra GETs after home (404s are logged)
    header_seq: Optional[Callable] = None  # (rng, page_index) -> extra headers for that page
    journey: str = "full"                 # "full" journey, or "touch": one or two pages, no checkout
    payload: Optional[str] = None         # None | single | stitched | flood (for truth only)
    usd_per_gb: float = 0.0
    config: dict = field(default_factory=dict)   # attack knobs, for reports


def _server_ms(r):
    for part in r.headers.get("Server-Timing", "").split(","):
        if part.strip().startswith("rules;dur="):
            return float(part.split("=")[1])
    return None


def shop(p, rng, run="manual"):
    """Walk the journey once. Returns a result dict for the scoreboard."""
    c = labnet.Client(p.ip, p.user_agent, p.headers, run=run)
    out = {"actor": p.actor, "cohort": p.cohort, "is_bot": p.is_bot, "ip": p.ip,
           "payload": p.payload, "sid": None, "status": None, "order_id": None,
           "rules_ms": None, "final": None, "kb": 0, "usd": 0.0, "config": p.config}
    try:
        page_index = [0]

        def page(path):
            extra = p.header_seq(rng, page_index[0]) if p.header_seq else {}
            page_index[0] += 1
            c.get(path, page=True, assets=p.loads_assets, headers=extra)
            if p.loads_assets:
                img = path.rsplit("/", 1)[-1] if path.startswith("/product/") else "hero"
                c.get(f"/img/{img}.svg")

        page("/")
        if p.loads_assets:
            c.get("/static/app.js")
            c.get("/static/style.css")
        for probe in p.probe_paths:
            labnet.think(p.think(rng))
            page(probe)
        if p.journey == "touch":
            if rng.random() < 0.5:
                labnet.think(p.think(rng))
                page(f"/product/{rng.randint(1, N_PRODUCTS)}")
            out["final"] = "no_checkout"
            return out
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
        labnet.think(p.think(rng))
        r = c.post("/checkout", {"sku": "DROP-1", "qty": 1})
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        out.update(status=r.status_code, order_id=body.get("order_id"), rules_ms=_server_ms(r),
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
                                     "is_bot": r["is_bot"], "payload": r["payload"],
                                     "run": run}) + "\n")


def run_sessions(personas, seed=0, workers=16, run="run"):
    """Run personas concurrently and log ground truth."""
    rngs = [random.Random(seed * 100003 + i) for i in range(len(personas))]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda pr: shop(pr[0], pr[1], run), zip(personas, rngs)))
    log_truth(results, run)
    return results


def succeeded(r):
    """A checkout that results in a shipped order."""
    return r["final"] == "confirmed"


def load_truth():
    """{sid: row}. Scoreboard only."""
    out = {}
    if os.path.exists(TRUTH_FILE):
        with open(TRUTH_FILE) as fh:
            for line in fh:
                row = json.loads(line)
                out[row["sid"]] = row
    return out
