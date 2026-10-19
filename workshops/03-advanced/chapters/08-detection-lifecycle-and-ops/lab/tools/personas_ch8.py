"""
The legitimate-user population, one week at a time.

200 simulated customers sign in every week, generated from a fixed seed per week so every
checkpoint sees the same people. Most are unremarkable browsers on home broadband. The minorities
matter, because each one trips exactly the kind of weak signal a layer was tuned on:

    persona        share   trips                        why it is a real person
    vpn            ~6%     datacenter_asn, tz mismatch  privacy, work VPN, travel
    cgnat          ~5%     ip_elevated / ip_burst       mobile carrier NAT
    privacy        ~3%     fp_randomized                Firefox RFP, Brave, extensions
    tor            ~1%     tor_exit + fp_randomized     Tor Browser
    a11y           ~2%     no_pointer                   keyboard-only, screen readers
    autofill       ~10%    no_keystrokes                password managers, paste
    old_device     ~2%     outdated_browser             can't upgrade the hardware
    typo           ~8%     (a failed login)             people mistype passwords

The world moves under the stack (tools/weeks.py replays the weeks):

    week 3+  Chrome 146 ships: a new header order and a new JA4 (the week-0 corpus has never seen it)
    week 3+  the mobile share doubles (a marketing push)
    week 3+  Example Fiber bought 203.0.113.0/27 from Example Cloud; 40% of fiber customers now
             connect from it. The store's feeds still say "datacenter", and the first /29 is still
             on an old community blocklist. Real people, blocked by stale data.

And the known-good cohort: ten synthetic monitors (persona `monitor`) that sign in twice a week
with the X-Known-Good token. They are scored like everyone else and never enforced against
(defenses/allowlist.py); the signals that fire on them are the live false-positive rate.

Real customers complete challenges: their browser solves the proof of work, and they read their own
mailbox for a step-up code. Safety rails: source addresses are rented from data/world.json
(documentation ranges), the client is tools/labclient.py (refuses a non-local DEMO_URL), the
credentials are the synthetic seed users'.

Run by itself against a running store:
    python tools/personas_ch8.py --week 1
"""

import argparse
import ipaddress
import math
import os
import random
import string
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import labclient  # noqa: E402  (lab root on sys.path; runs the labnet guard)
from defenses import corpus  # noqa: E402
from demo_site.seed import password_for, username  # noqa: E402
from labclient import BASE_URL, WORLD, world_pool  # noqa: E402
from signin import OpsClient, sign_in  # noqa: E402

SEED = 2026
SIZE = 200
WEEK_SECONDS = 7 * 86400
BUTTON = (640, 420)

CHROME_MAJOR, FIREFOX_MAJOR, SAFARI_MAJOR = 145, 155, 26
CHROME_RELEASE_WEEK, CHROME_NEW_MAJOR = 3, 146          # the browser release the corpus has not seen
JA4_CHROME_NEW = "t13d1517h2_8daaf6152771_b0da82dd1658"  # illustrative, like the week-0 table
MOBILE_PUSH_WEEK = 3
REASSIGN_WEEK, REASSIGNED_RANGE, REASSIGNED_SHARE = 3, "203.0.113.0/27", 0.4
REASSIGNED_POOL = "home_fiber"     # who owns REASSIGNED_RANGE once the refresh has run

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
HOME_POOLS = [("home_broadband", 28), ("home_cable", 24), ("home_fiber", 24), ("home_v6", 24)]

# (device, pool) of the ten monitors; each checks twice a week
MONITORS = [("chrome-win", "home_broadband"), ("chrome-win", "home_broadband"), ("chrome-win", "home_fiber"),
            ("chrome-win", "home_cable"), ("chrome-mac", "home_broadband"), ("firefox-linux", "home_v6"),
            ("safari-ios", "home_broadband"), ("safari-ios", "home_fiber"), ("chrome-android", "home_broadband"),
            ("chrome-android", "home_cable")]
KNOWN_GOOD = ("X-Known-Good", os.environ.get("KNOWN_GOOD_TOKEN", "lab-monitor-7f3a"))


# --- the browsers ----------------------------------------------------------------------------------

def chrome_is_new(device, week):
    b = DEVICES[device]
    return b["engine"] == "chrome" and "ch_major" not in b and week >= CHROME_RELEASE_WEEK


def ja4_for(engine, week=1, device=None):
    """The JA4 a client stack shows this week. Chrome's changes with the release."""
    if device and chrome_is_new(device, week):
        return JA4_CHROME_NEW
    return corpus.snapshot()["ja4"][engine]


def browser_headers(name, accept_language="en-US,en;q=0.9", week=1):
    """Headers of the page's fetch() POST, in the order the engine sends them (W1 Ch4)."""
    b = DEVICES[name]
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


# --- what the collector would report -----------------------------------------------------------------

def fingerprint(rng, device, tz, languages=("en-US", "en"), randomized=False, renderer=None):
    b = DEVICES[device]
    canvas = "".join(rng.choices(string.hexdigits.lower(), k=24))
    return {"platform": b["platform"], "webgl_renderer": renderer or rng.choice(b["gpus"]), "canvas": canvas,
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


# --- the people --------------------------------------------------------------------------------------

def _weighted(rng, items):
    return rng.choices([i for i, _ in items], weights=[w for _, w in items])[0]


def week_start(week):
    return week * WEEK_SECONDS


def _reassigned(index):
    """An address inside the range Example Fiber bought: .1 upward (the first /29 is the stale blocklist's)."""
    net = ipaddress.ip_network(REASSIGNED_RANGE)
    return str(net[1 + index % (net.num_addresses - 1)])


def make_people(week=1, size=SIZE, seed=SEED):
    rng = random.Random(seed * 100 + week)
    devices = list(WEIGHTED_DEVICES)
    if week >= MOBILE_PUSH_WEEK:
        devices = [(d, w * 2 if DEVICES[d]["mobile"] else w) for d, w in devices]
    pools = {n: world_pool(n) for n in [p for p, _ in HOME_POOLS] + ["consumer_vpn", "tor_exit", "mobile_cgnat"]}
    next_ip = Counter()
    people = []
    for i in range(size):
        device = _weighted(rng, devices)
        home = _weighted(rng, HOME_POOLS)
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
        ip = pools[pool][index % len(pools[pool])]
        if pool == REASSIGNED_POOL and week >= REASSIGN_WEEK and rng.random() < REASSIGNED_SHARE:
            ip = _reassigned(next_ip["reassigned"])
            next_ip["reassigned"] += 1
            traits.append("new_range")
        spanish = rng.random() < 0.08
        people.append({
            "id": i, "persona": "+".join(t for t in traits if t != "new_range") or "typical",
            "traits": traits, "device": device, "pool": pool, "ip": ip,
            "home_tz": "UTC" if "tor" in traits else WORLD["pools"][home]["tz"],
            "languages": ["es-US", "es", "en"] if spanish else ["en-US", "en"],
            "accept_language": "es-US,es;q=0.9,en;q=0.8" if spanish else "en-US,en;q=0.9",
            "seed": seed * 10_000 + week * 1000 + i,
            "clock": week_start(week) + rng.randrange(WEEK_SECONDS),
            "known_good": False,
        })
    return people


def make_monitors(week=1, seed=SEED):
    """Ten monitors, each checking twice a week at fixed times, from addresses nobody else uses."""
    people = []
    for j, (device, pool) in enumerate(MONITORS):
        hosts = world_pool(pool)
        ip = hosts[(len(hosts) - 10 + j) % len(hosts)]
        if pool == REASSIGNED_POOL and week >= REASSIGN_WEEK:
            ip = _reassigned(3 if j == 2 else 19)          # one lands in the stale blocklist's /29
        for check in range(2):
            people.append({
                "id": 250 + j, "persona": "monitor", "traits": [], "device": device, "pool": pool,
                "ip": ip, "home_tz": WORLD["pools"][pool]["tz"], "languages": ["en-US", "en"],
                "accept_language": "en-US,en;q=0.9", "seed": seed * 50_000 + week * 100 + j * 2 + check,
                "clock": week_start(week) + (2 + check * 3) * 86400 + 3600 * (9 + j), "known_good": True,
            })
    return people


def visit(person, week=1):
    """One real customer signing in. Returns (outcome, result): logged_in | typo_rejected | blocked | stuck."""
    rng = random.Random(person["seed"])
    b = DEVICES[person["device"]]
    traits = person["traits"]
    client = OpsClient(f"human:{person['persona']}:{person['id']:03d}", ip=person["ip"], week=week,
                       clock=person["clock"], rng=rng, ja4=ja4_for(b["engine"], week, person["device"]))
    headers = browser_headers(person["device"], person["accept_language"], week)
    if person["known_good"]:
        headers = headers + [KNOWN_GOOD]
    email, password = username(person["id"]), password_for(person["id"])
    if "typo" in traits:
        password = password[:-1] + ("1" if password[-1] != "1" else "2")       # always a different password
    if "a11y" in traits:
        mouse, pointer = [], "mouse"
    elif b["mobile"]:
        mouse, pointer = taps(rng), "touch"
    else:
        mouse, pointer = human_path(rng), "mouse"
    keys = [] if "autofill" in traits else keystrokes(rng, len(email) + len(password))
    fp = fingerprint(rng, person["device"], person["home_tz"], person["languages"],
                     randomized=bool({"privacy", "tor"} & set(traits)))
    res = sign_in(client, headers, email, password, fp, mouse, keys, pointer, owns_mailbox=True)
    if res["stuck"]:
        outcome = "stuck"
    elif res["status"] == 200:
        outcome = "logged_in"
    elif res["status"] == 401:
        # 'invalid' is correct for a typo; for anyone else it is a deceptive block (the verdict header says so)
        deceived = bool(res["verdict"]) and res["verdict"][0] == "deceive"
        outcome = "blocked" if deceived else ("typo_rejected" if "typo" in traits else "failed")
    else:
        outcome = "blocked"
    return outcome, res


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send one week's customers through the login")
    parser.add_argument("--week", type=int, default=1)
    args = parser.parse_args()
    labclient.wait_for_store()
    people = sorted(make_people(args.week) + make_monitors(args.week), key=lambda p: p["clock"])
    by_persona = defaultdict(Counter)
    for person in people:
        outcome, _ = visit(person, args.week)
        by_persona[person["persona"]][outcome] += 1
    print(f"=== week {args.week}: {len(people)} simulated customers (what each one experienced) ===")
    for persona, outcomes in sorted(by_persona.items(), key=lambda kv: -sum(kv[1].values())):
        print(f"  {persona:<22} {sum(outcomes.values()):>4}   " + ", ".join(f"{k} {v}" for k, v in sorted(outcomes.items())))
    print("\n  'typo_rejected' is correct. 'blocked' is a customer the stack refused (a deceptive block looks")
    print("  like a typo to the customer: the store's verdict header tells the two apart).")
