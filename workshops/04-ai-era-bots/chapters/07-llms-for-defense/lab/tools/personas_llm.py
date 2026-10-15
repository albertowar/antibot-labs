"""
W4 Ch7 — Drop-day personas: the six human cohorts, the shared journey, the bot runner

Real users (this module, via the `llm_shop` scenario) and bots (attacks/*.py)
walk the SAME journey against the real store:

    home → (probes) → (login) → browse products → cart → checkout

They differ only in their persona. In this chapter the interesting difference
is textual: an attacker chooses every byte of User-Agent, Referer,
Accept-Language, request path and login name, and the analyst reads all of
them from the ext's request log.

Six human cohorts, each chosen because it breaks a naive rule somewhere:

  desktop          the "typical" shopper; ~15% sit behind corporate egress
  mobile_cgnat     phones on carrier CGNAT: many people per IP
  power_user       sneakerheads who know the drop: fast, few pages
  vpn              commercial VPN: a hosting ASN. Round 2's bait bot exits
                   from the SAME pool.
  privacy_browser  Firefox resistFingerprinting / Brave: generic
                   Accept-Language, often Firefox on Linux
  keyboard_only    screen-reader and keyboard users: slow, few pages

Logins: some users sign in to real seed accounts (their only "verification").
Privacy-browser and VPN users log in less, so the gate's trusted cohort
under-represents exactly them — the bias defenses/rule_gate.py inherits.

Ground truth is the actor label (`human:<cohort>:<n>`, `bot:<family>:<n>`),
which the store's edge strips before any defense runs; only the checkpoint's
scoreboard reads it back from /lab/decisions. There is no truth file.

Lab time: think() sleeps a VIRTUAL duration times LAB_TIME_SCALE (default
0.02), and the session card divides measured gaps by the same factor.
"""

import math
import os
import random
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import population  # noqa: E402
from labclient import BASE_URL, LabClient, world_pool  # noqa: E402
from defenses.rule_store import LAB_TIME_SCALE  # noqa: E402
from defenses.sessionize import record_run  # noqa: E402

N_BROWSE_SKUS = 40          # shoppers browse p001..p040 (each seeded with 500 units)

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

LANGS = [["es-ES", "es", "en"], ["en-US", "en"], ["en-US", "en"], ["de-DE", "de", "en"],
         ["en-GB", "en"], ["en-US", "en"]]

COHORTS = {"desktop": 0.40, "mobile_cgnat": 0.25, "power_user": 0.10,
           "vpn": 0.10, "privacy_browser": 0.08, "keyboard_only": 0.07}
# P(logs in), P(account is long-standing-ish | logs in) — "loyal" picks a low seed
# index (the oldest accounts cluster there only by chance; what matters is the rate)
LOGIN = {"desktop": (0.6, 0.7), "mobile_cgnat": (0.5, 0.7), "power_user": (0.8, 0.9),
         "vpn": (0.5, 0.6), "privacy_browser": (0.35, 0.6), "keyboard_only": (0.5, 0.7)}


def accept_language(langs):
    parts = [langs[0]] + [f"{lang};q={0.9 - 0.1 * i:.1f}" for i, lang in enumerate(langs[1:])]
    return ",".join(parts)


def browser_headers(ua, langs):
    """Ordered headers the way a browser sends them (the analyst reads the text, not the order)."""
    return [("User-Agent", ua),
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            ("Accept-Language", accept_language(langs) if isinstance(langs, list) else langs),
            ("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Mode", "navigate")]


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


def think(virtual_seconds):
    """Sleep a virtual duration, compressed by LAB_TIME_SCALE."""
    time.sleep(max(virtual_seconds, 0) * LAB_TIME_SCALE)


@dataclass
class Rec:
    """One session's script. Humans and bots differ only in these fields."""
    cohort: str
    is_bot: bool
    ip: str
    ua: str
    langs: object = None                  # list of languages, or a raw Accept-Language string
    extra_headers: dict = field(default_factory=dict)   # e.g. a Referer
    think: Callable = None
    browse: int = 2
    loads_assets: bool = True
    account: Optional[str] = None         # login email AS SUBMITTED (attacker text allowed)
    password: Optional[str] = None        # None: an email that cannot sign in still gets logged
    honeypot: float = 0.0                 # P(follow the hidden link)
    disallowed: float = 0.0               # P(call the robots.txt-disallowed /partner-feed)
    probe_paths: list = field(default_factory=list)     # extra GETs after home (404s are logged)
    header_seq: Optional[Callable] = None  # (rng, page_index) -> extra headers for that page
    journey: str = "full"                 # "full", or "touch": one or two pages, no checkout
    payload: Optional[str] = None         # None | single | stitched | bait | flood (actor label only)
    usd_per_gb: float = 0.0
    config: dict = field(default_factory=dict)

    def headers(self, extra=None):
        hdrs = browser_headers(self.ua, self.langs or ["en-US", "en"])
        for k, v in {**self.extra_headers, **(extra or {})}.items():
            hdrs.append((k, v))
        return hdrs


def _kb(r):
    return len(r.content) / 1024 if r.content is not None else 0


def journey(rec, client, rng):
    """The shared drop-day journey. Returns the session's result dict."""
    out = {"cohort": rec.cohort, "is_bot": rec.is_bot, "payload": rec.payload,
           "status": None, "final": None, "kb": 0.0, "config": rec.config}
    page_index = [0]
    kb = [0.0]

    def page(path):
        extra = rec.header_seq(rng, page_index[0]) if rec.header_seq else {}
        page_index[0] += 1
        r = client.get(path, rec.headers(extra))
        kb[0] += _kb(r)
        if rec.loads_assets:
            sku = path.rsplit("/", 1)[-1] if path.startswith("/product/") else "p001"
            kb[0] += _kb(client.get(f"/img/{sku}.svg", rec.headers()))
        return r

    page("/")
    if rec.loads_assets:
        kb[0] += _kb(client.get("/static/css/store.css", rec.headers()))
    for probe in rec.probe_paths:
        think(rec.think(rng))
        page(probe)
    if rec.journey == "touch":
        if rng.random() < 0.5:
            think(rec.think(rng))
            page(f"/product/p{rng.randint(1, N_BROWSE_SKUS):03d}")
        out["final"] = "no_checkout"
    else:
        if rng.random() < rec.honeypot:
            think(rec.think(rng))
            page("/specials-archive")
        if rng.random() < rec.disallowed:
            kb[0] += _kb(client.get("/partner-feed", rec.headers()))
        if rec.account:
            think(rec.think(rng))
            client.post("/api/login", json={"email": rec.account, "password": rec.password or "x"},
                        headers=rec.headers())
        sku = f"p{rng.randint(1, N_BROWSE_SKUS):03d}"
        for _ in range(rec.browse):
            think(rec.think(rng))
            sku = f"p{rng.randint(1, N_BROWSE_SKUS):03d}"
            page(f"/product/{sku}")
        think(rec.think(rng))
        client.post("/api/cart/add", json={"sku": sku, "qty": 1}, headers=rec.headers())
        think(rec.think(rng))
        email = rec.account if rec.account and "@" in rec.account else "drop.day@example.test"
        r = client.post("/api/checkout", json={"email": email}, headers=rec.headers())
        out["status"] = r.status_code
        out["final"] = {201: "confirmed", 403: "blocked", 429: "rate_limited"}.get(r.status_code, "failed")
    out["kb"] = kb[0]
    out["usd"] = kb[0] / 1024 / 1024 * rec.usd_per_gb
    return out


# --- the six human cohorts, as population personas -----------------------------------------------

def pick_account(rng, cohort):
    from demo_site.seed import password_for, username
    p_login, p_loyal = LOGIN[cohort]
    if rng.random() >= p_login:
        return None, None
    i = rng.randrange(0, 150) if rng.random() < p_loyal else rng.randrange(150, 300)
    return username(i), password_for(i)


def human_rec(rng, cohort):
    mobile = cohort == "mobile_cgnat"
    langs = rng.choice(LANGS)
    ua_key = rng.choice(MOBILE_UAS if mobile else DESKTOP_UAS)
    think_fn, browse = human_think(6.0), rng.randint(1, 5)

    if mobile:
        ip = rng.choice(world_pool("mobile_cgnat"))
        browse = rng.randint(1, 4)
    elif cohort == "vpn":
        ip = rng.choice(world_pool("consumer_vpn"))
        if rng.random() < 0.4:
            ua_key = "firefox_linux"
    elif cohort == "desktop" and rng.random() < 0.15:
        langs = ["en-US", "en"]
        ip = rng.choice(world_pool("corporate"))
    else:
        ip = rng.choice(world_pool("home_broadband") + world_pool("home_cable"))

    if cohort == "power_user":
        think_fn, browse = human_think(2.0), rng.randint(0, 1)
    elif cohort == "keyboard_only":
        think_fn = human_think(9.0)
    elif cohort == "privacy_browser":
        ua_key = "firefox_linux" if rng.random() < 0.5 else rng.choice(["firefox_win", "chrome_win"])
        langs = ["en-US", "en"]

    account, password = pick_account(rng, cohort)
    return Rec(cohort=cohort, is_bot=False, ip=ip, ua=UA[ua_key], langs=langs,
               think=think_fn, browse=browse, account=account, password=password)


def people(n=600, seed=1):
    """The drop-day humans as population Personas (each Round's `people=`)."""
    rng = random.Random(seed)
    cohorts = rng.choices(list(COHORTS), weights=list(COHORTS.values()), k=n)
    out = []
    for i, cohort in enumerate(cohorts):
        rec = human_rec(rng, cohort)
        p = population.Persona(f"human:{cohort}:{i:03d}", cohort, ("chrome", 153), rec.ip)
        p.rec = rec
        out.append(p)
    return out


def people_200(seed=1):
    return people(200, seed)


def scenario_llm_shop(p, client, rng):
    rec = p.rec
    out = journey(rec, client, rng)
    outcome = {"confirmed": "bought", "blocked": "blocked", "rate_limited": "blocked",
               "no_checkout": "browsed"}.get(out["final"], "failed")
    p.result.update(outcome=outcome, status=out["status"], requests=client.requests,
                    verdict=client.verdict())
    return p.result


population.SCENARIOS["llm_shop"] = scenario_llm_shop


# --- the bot runner shared by attacks/*.py --------------------------------------------------------

def run_bots(recs, family, seed=0, workers=16, run=None):
    """Run bot sessions concurrently. Returns results; records the run window."""
    t0 = time.time()
    results = [None] * len(recs)
    sem = threading.Semaphore(workers)

    def one(i, rec):
        with sem:
            rng = random.Random(seed * 100003 + i)
            client = LabClient(f"bot:{rec.cohort}:{i:03d}", ip=rec.ip, rng=rng)
            try:
                results[i] = journey(rec, client, rng)
            except Exception as e:      # noqa: BLE001 — a lab attack reports, never crashes the wave
                results[i] = {"cohort": rec.cohort, "is_bot": True, "final": f"error: {e!r}",
                              "status": -1, "kb": 0.0, "usd": 0.0, "payload": rec.payload}

    threads = [threading.Thread(target=one, args=(i, rec)) for i, rec in enumerate(recs)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    record_run(run or family, t0, time.time())
    return results


def summary_line(results):
    """The one JSON line every attack prints last (checkpoint contract)."""
    import json
    attempted = len(results)
    succeeded = sum(1 for r in results if r["final"] == "confirmed")
    usd = round(sum(r.get("usd", 0.0) for r in results), 4)
    return json.dumps({"attempted": attempted, "succeeded": succeeded, "usd": usd})
