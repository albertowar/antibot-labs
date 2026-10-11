"""
Traffic engine for simulated customers and bots (inherited from W2 Ch8)

Every simulated visit goes through LabSession: the browser it claims, its
headers in that browser's order, the telemetry the page's collector would
post, the address it connects from, how it completes a challenge, and (new
in W3 Ch4) *when* on the lab calendar it happened: X-Lab-Week and
X-Lab-Clock let tools/weeks.py replay five weeks in minutes.

The world moves between weeks. From week 3, Chrome 146 is out: a new major,
a new JA4 the week-0 table has never seen, and a different header order on
fetch(). browser_headers() and ja4_for() take a week for that reason.

Safety rails (do not remove):
- DEMO_URL must point at localhost; anything else is refused.
- Source addresses come only from ../world.json documentation ranges.
- Credentials are synthetic (*@example.test).
"""

import hashlib
import ipaddress
import json
import math
import os
import random
import string
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(LAB, "demo_site"))
sys.path.insert(0, os.path.join(LAB, "defenses"))

import users  # noqa: E402  (the store's seed, so simulated humans know their passwords)
from ladder import leading_zero_bits  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://localhost:5000")

with open(os.path.join(LAB, "world.json")) as f:
    WORLD = json.load(f)
JA4 = WORLD["ja4"]

# --------------------------------------------------------------------------
# Network: addresses from the simulated internet
# --------------------------------------------------------------------------
_NETS = {name: ipaddress.ip_network(p["cidr"]) for name, p in WORLD["pools"].items()}


def ip_from(pool, index):
    net = _NETS[pool]
    return str(net[index % net.num_addresses])


def ip_in(cidr, index):
    """An address inside an arbitrary documentation range (the reassigned block in Round 2)."""
    net = ipaddress.ip_network(cidr)
    return str(net[index % net.num_addresses])


def pool_tz(pool):
    return WORLD["pools"][pool]["tz"]


# --------------------------------------------------------------------------
# Browsers: what each one sends on a same-origin fetch()
# --------------------------------------------------------------------------
CHROME_MAJOR, FIREFOX_MAJOR, SAFARI_MAJOR = 145, 155, 26
CHROME_RELEASE_WEEK, CHROME_NEW_MAJOR = 3, 146          # the browser release the corpus has not seen
JA4_CHROME_NEW = "t13d1517h2_8daaf6152771_b0da82dd1658"  # illustrative, like the week-0 table

BROWSERS = {
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
                       "ch_platform": '"Android"',
                       "gpus": ["Adreno (TM) 740", "Mali-G715-Immortalis MC11"]},
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


def chrome_is_new(name, week):
    b = BROWSERS[name]
    return b["engine"] == "chrome" and "ch_major" not in b and week >= CHROME_RELEASE_WEEK


def ja4_for(engine, week=1, name=None):
    """The JA4 a client stack shows this week. Chrome's changes with the release."""
    if name and chrome_is_new(name, week):
        return JA4_CHROME_NEW
    return JA4[engine]


def browser_headers(name, accept_language="en-US,en;q=0.9", week=1):
    """Headers of a page's fetch() POST, in the order the engine sends them."""
    b = BROWSERS[name]
    origin, referer = BASE_URL, f"{BASE_URL}/login"
    if b["engine"] == "chrome":
        major = b.get("ch_major", CHROME_MAJOR)
        ua = b["ua"]
        ch = [("sec-ch-ua", f'"Chromium";v="{major}", "Not:A-Brand";v="99", "Google Chrome";v="{major}"'),
              ("sec-ch-ua-mobile", "?1" if b["mobile"] else "?0"),
              ("sec-ch-ua-platform", b["ch_platform"])]
        if chrome_is_new(name, week):
            # Chrome 146: the Sec-Fetch-* trio moved ahead of User-Agent (illustrative)
            major = CHROME_NEW_MAJOR
            ua = ua.replace(f"Chrome/{CHROME_MAJOR}.", f"Chrome/{major}.")
            ch[0] = ("sec-ch-ua", f'"Chromium";v="{major}", "Not:A-Brand";v="99", "Google Chrome";v="{major}"')
            return ch + [("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Mode", "cors"),
                         ("Sec-Fetch-Dest", "empty"), ("User-Agent", ua), ("Accept", "*/*"),
                         ("Origin", origin), ("Referer", referer),
                         ("Accept-Encoding", "gzip, deflate, br, zstd"), ("Accept-Language", accept_language)]
        return ch + [("User-Agent", ua), ("Accept", "*/*"), ("Origin", origin),
                     ("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Mode", "cors"),
                     ("Sec-Fetch-Dest", "empty"), ("Referer", referer),
                     ("Accept-Encoding", "gzip, deflate, br, zstd"), ("Accept-Language", accept_language)]
    if b["engine"] == "firefox":
        return [("User-Agent", b["ua"]), ("Accept", "*/*"), ("Accept-Language", accept_language),
                ("Accept-Encoding", "gzip, deflate, br, zstd"), ("Referer", referer),
                ("Origin", origin), ("Sec-Fetch-Dest", "empty"), ("Sec-Fetch-Mode", "cors"),
                ("Sec-Fetch-Site", "same-origin")]
    return [("Accept", "*/*"), ("Sec-Fetch-Site", "same-origin"), ("Accept-Language", accept_language),
            ("Sec-Fetch-Mode", "cors"), ("Accept-Encoding", "gzip, deflate, br"), ("Origin", origin),
            ("User-Agent", b["ua"]), ("Referer", referer), ("Sec-Fetch-Dest", "empty")]


# --------------------------------------------------------------------------
# Telemetry: fingerprints and behaviour traces
# --------------------------------------------------------------------------
BUTTON = (640, 420)


def fingerprint(rng, browser, tz, languages=("en-US", "en"), randomized=False, platform=None,
                renderer=None):
    b = BROWSERS[browser]
    canvas = "".join(rng.choices(string.hexdigits.lower(), k=24))
    return {"platform": platform or b["platform"], "webgl_renderer": renderer or rng.choice(b["gpus"]),
            "canvas": canvas,
            "canvas2": "".join(rng.choices(string.hexdigits.lower(), k=24)) if randomized else canvas,
            "screen": rng.choice(["390x844", "412x915"]) if b["mobile"] else
            rng.choice(["1920x1080", "1536x864", "2560x1440", "1440x900"]),
            "timezone": tz, "languages": list(languages), "webdriver": False, "cdp": False,
            "hardware_concurrency": rng.choice([4, 8, 8, 12, 16])}


def human_path(rng):
    """A hand: a curved path with overshoot noise and uneven event spacing."""
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


# --------------------------------------------------------------------------
# Challenges and sessions
# --------------------------------------------------------------------------
def solve_pow(prefix, bits):
    nonce = 0
    while leading_zero_bits(hashlib.sha256(f"{prefix}:{nonce}".encode()).digest()) < bits:
        nonce += 1
    return str(nonce)


class LabSession:
    """One visit: GET /login, POST /telemetry, POST /login, and any challenge.

    week/clock stamp the visit on the lab calendar. owns_mailbox says whether
    this client can read the account's inbox for a step-up code: a real user
    can, a credential stuffer cannot. extra headers are sent as-is (the
    known-good cohort's token)."""

    def __init__(self, actor, ip, ja4, headers, week=0, clock=0, owns_mailbox=True, extra=None):
        self.s = requests.Session()
        self.s.headers.clear()
        for name, value in headers:
            self.s.headers[name] = value
        self.lab = {"X-Lab-Client-IP": ip, "X-Lab-JA4": ja4, "X-Lab-Actor": actor,
                    "X-Lab-Week": str(week), "X-Lab-Clock": str(int(clock)), **(extra or {})}
        self.owns_mailbox = owns_mailbox
        self.requests_sent, self.pow_ms = 0, 0.0

    @property
    def sid(self):
        return self.s.cookies.get("sid")

    def _post(self, path, **kw):
        self.requests_sent += 1
        headers = {**kw.pop("headers", {}), **self.lab}
        return self.s.post(f"{BASE_URL}{path}", headers=headers, timeout=10, **kw)

    def open_login(self):
        self.requests_sent += 1
        self.s.get(f"{BASE_URL}/login", headers=self.lab, timeout=10)

    def send_telemetry(self, fp, mouse, keys, pointer_type="mouse"):
        self._post("/telemetry", json={"fp": fp, "behavior": {
            "mouse": mouse, "keys": keys, "pointer_type": pointer_type}})

    def login(self, username, password, extra=None):
        """Returns (outcome, response); outcome is ok, invalid or blocked.
        A real user's browser solves the proof-of-work, and the user reads
        their own inbox for a step-up code."""
        form = {"username": username, "password": password, **(extra or {})}
        r = self._post("/login", data=form)
        body = r.json()
        if body.get("action") == "challenge":
            started = time.perf_counter()
            nonce = solve_pow(body["pow"]["prefix"], body["pow"]["bits"])
            self.pow_ms += (time.perf_counter() - started) * 1000
            r = self._post("/login", data=form, headers={"X-PoW": nonce})
            body = r.json()
        elif body.get("action") == "verify":
            code = None
            if self.owns_mailbox:
                code = requests.get(f"{BASE_URL}/lab/mailbox/{username}", timeout=10).json()["code"]
            r = self._post("/login/verify", json={"code": code or "000000"})
            body = r.json()
        if r.status_code == 200:
            return "ok", r
        if r.status_code == 401:
            return "invalid", r
        return "blocked", r

