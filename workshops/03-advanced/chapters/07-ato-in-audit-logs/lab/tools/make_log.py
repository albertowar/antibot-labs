"""
Chapter 7: generate the account-activity audit log the investigation runs over.

Ninety days of a store's account audit log (2026-10-01 to 2026-12-29): roughly
ten thousand accounts, a few hundred thousand events, eight account-takeover
campaigns buried in it and a long list of legitimate behaviour that looks like
one. Production logs never carry ground truth; here it goes to
solutions/answer_key.json so the scorer can report recall per campaign and
false positives per legitimate cohort.

    tier  campaign                 victims  built to evade
    A     A1_datacenter_stuffing     14     (nothing: rules catch it)
    A     A2_reset_abuse              6     (nothing)
    A     A3_impossible_travel        6     (nothing)
    B     B1_phishing_kit            20     Round 1 rules: no high-risk event, rotating identifiers
    B     B2_session_replay          10     Round 1 rules: session_id rotation, legit roaming
    B     B3_oauth_hijack             8     Round 1 rules: degree ties with duplicate-account owners
    B     B4_support_ring             8     Round 1 rules: legit recoveries also come from new devices
    C     C1_low_and_slow            18     Rounds 1-2: no shared infrastructure, only weak deviations
    -     D_prehijack (bonus)         6     a sequence invariant, unscored

Every address is non-routable: 198.18.0.0/15 (RFC 2544 benchmark space) for
residential, mobile and datacenter pools, 100.64.0.0/10 (RFC 6598) for CGNAT
egress, the RFC 5737 /24s for VPN, Tor and one hosting block, 2001:db8::/32
for IPv6. Nothing here can ever point at a real network, and every person,
agent and account is invented.

The generator is deterministic: the same seed gives the same file on Python
3.10 to 3.12 (string-seeded random.Random sub-streams, no set iteration, no
hash()), which is what makes the README's expected-results table reproducible.

Run:
    python tools/make_log.py                   # writes data/account_activity.jsonl.gz (seed 2026)
    python tools/make_log.py --csv             # also data/account_activity.csv
    python tools/make_log.py --scale 0.1       # a tenth of the accounts, same campaigns, for tests
    python tools/make_log.py --seed 7 --out-dir /tmp/other
"""

import argparse
import gzip
import hashlib
import json
import math
import os
import random
import sys
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
DATA_DIR = os.path.join(LAB, "data")
SOLUTIONS_DIR = os.path.join(LAB, "solutions")

SEED = 2026
SCHEMA_VERSION = 1
N_ACCOUNTS = 10000
START_DAY = (2026, 10, 1)        # window start, UTC midnight
DAYS = 90                        # emitted window
PREHISTORY_DAYS = 30             # simulated but not emitted: fixes every account's baseline

SECOND = 1000
MINUTE = 60 * SECOND
HOUR = 60 * MINUTE
DAY = 24 * HOUR


# ----------------------------------------------------------------------------
# Small deterministic helpers
# ----------------------------------------------------------------------------

def rng_for(seed, *parts):
    """A random stream derived from the master seed and a label. String seeds
    are hashed with SHA-512 inside random.Random, so this is stable across
    Python versions; tuple seeds would go through hash() and are not."""
    return random.Random(":".join([str(seed)] + [str(p) for p in parts]))


def weighted(rng, items):
    """items: list of (value, weight). Implemented on rng.random() so the
    draw sequence is bit-exact across Python versions."""
    total = 0.0
    for _, w in items:
        total += w
    r = rng.random() * total
    acc = 0.0
    for v, w in items:
        acc += w
        if r < acc:
            return v
    return items[-1][0]


def lognormal(rng, median, sigma):
    """Log-normal with the given median, via Box-Muller on rng.random()."""
    u1 = rng.random() or 1e-12
    u2 = rng.random()
    z = math.sqrt(-2.0 * math.log(u1)) * math.cos(2 * math.pi * u2)
    return median * math.exp(sigma * z)


def gauss(rng, mu, sigma):
    u1 = rng.random() or 1e-12
    u2 = rng.random()
    return mu + sigma * math.sqrt(-2.0 * math.log(u1)) * math.cos(2 * math.pi * u2)


def hexid(seed, label, n, length=16):
    return hashlib.sha256(f"{seed}:{label}:{n}".encode()).hexdigest()[:length]


def epoch_ms(y, m, d, hh=0, mm=0, ss=0):
    """UTC epoch milliseconds without datetime arithmetic surprises."""
    # days from civil (Howard Hinnant's algorithm), integer-only
    y2 = y - (1 if m <= 2 else 0)
    era = (y2 if y2 >= 0 else y2 - 399) // 400
    yoe = y2 - era * 400
    mp = (m + 9) % 12
    doy = (153 * mp + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    days = era * 146097 + doe - 719468
    return ((days * 24 + hh) * 60 + mm) * 60 * SECOND + ss * SECOND


def iso(ms):
    s, ms_part = divmod(ms, SECOND)
    days, rem = divmod(s, 86400)
    hh, rem = divmod(rem, 3600)
    mm, ss = divmod(rem, 60)
    # civil from days (Hinnant)
    z = days + 719468
    era = (z if z >= 0 else z - 146096) // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + 3 if mp < 10 else mp - 9
    if m <= 2:
        y += 1
    return f"{y:04d}-{m:02d}-{d:02d}T{hh:02d}:{mm:02d}:{ss:02d}.{ms_part:03d}Z"


START_MS = epoch_ms(*START_DAY)
END_MS = START_MS + DAYS * DAY
SIM_START_MS = START_MS - PREHISTORY_DAYS * DAY


def day_ms(day_index):
    """UTC midnight of window day N (0-based; negative = pre-history)."""
    return START_MS + day_index * DAY


# ----------------------------------------------------------------------------
# World model
# ----------------------------------------------------------------------------

COUNTRIES = {
    # code: (tz hours, language, population weight, cities [(name, lat, lon)])
    "US": (-5, "en-US", 30, [("New York", 40.71, -74.01), ("Chicago", 41.88, -87.63), ("Austin", 30.27, -97.74), ("Seattle", 47.61, -122.33)]),
    "GB": (0, "en-GB", 12, [("London", 51.51, -0.13), ("Manchester", 53.48, -2.24), ("Edinburgh", 55.95, -3.19)]),
    "DE": (1, "de-DE", 10, [("Berlin", 52.52, 13.41), ("Munich", 48.14, 11.58), ("Hamburg", 53.55, 9.99)]),
    "FR": (1, "fr-FR", 7, [("Paris", 48.86, 2.35), ("Lyon", 45.76, 4.84)]),
    "ES": (1, "es-ES", 6, [("Madrid", 40.42, -3.70), ("Barcelona", 41.39, 2.17)]),
    "NL": (1, "nl-NL", 5, [("Amsterdam", 52.37, 4.90), ("Rotterdam", 51.92, 4.48)]),
    "BR": (-3, "pt-BR", 6, [("Sao Paulo", -23.55, -46.63), ("Rio de Janeiro", -22.91, -43.17)]),
    "IN": (5.5, "en-IN", 7, [("Mumbai", 19.08, 72.88), ("Bengaluru", 12.97, 77.59), ("Delhi", 28.61, 77.21)]),
    "JP": (9, "ja-JP", 4, [("Tokyo", 35.68, 139.69), ("Osaka", 34.69, 135.50)]),
    "AU": (10, "en-AU", 4, [("Sydney", -33.87, 151.21), ("Melbourne", -37.81, 144.96)]),
    "CA": (-5, "en-CA", 5, [("Toronto", 43.65, -79.38), ("Montreal", 45.50, -73.57)]),
    "MX": (-6, "es-MX", 4, [("Mexico City", 19.43, -99.13), ("Guadalajara", 20.66, -103.35)]),
    "SG": (8, "en-SG", 0, [("Singapore", 1.35, 103.82)]),
    "CH": (1, "de-CH", 0, [("Zurich", 47.38, 8.54)]),
}
COUNTRY_CODES = list(COUNTRIES.keys())
POPULATED = [(c, COUNTRIES[c][2]) for c in COUNTRY_CODES if COUNTRIES[c][2] > 0]

# Browser / client families. ja4 values are synthetic but shaped like JA4
# (t13d<ciphers><ext>h2_<hash>_<hash>). Chrome and Edge share one, as in life.
FAMILIES = {
    # family: (client, ua, ja4, share among legit devices, desktop?)
    "chrome_win":     ("web", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", "t13d1516h2_8daaf6152771_e5627efa2ab1", 26, True),
    "chrome_mac":     ("web", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", "t13d1516h2_8daaf6152771_e5627efa2ab1", 9, True),
    "edge_win":       ("web", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0", "t13d1516h2_8daaf6152771_e5627efa2ab1", 6, True),
    "firefox_win":    ("web", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0", "t13d1715h2_5b57614c22b0_3d5edc0f1d7b", 5, True),
    "safari_mac":     ("web", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15", "t13d2014h2_a09f3c656075_e8a523a41297", 5, True),
    "chromium_linux": ("web", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", "t13d1516h2_8daaf6152771_b0da82dd1658", 1.5, True),
    "chrome_legacy":  ("web", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36", "t13d1516h2_8daaf6152771_aa5f2e0bd4c1", 0.8, True),
    "chrome_android": ("web", "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36", "t13d1517h2_8daaf6152771_b0da82dd1658", 13, False),
    "safari_ios":     ("web", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1", "t13d2014h2_a09f3c656075_14788d8d241b", 13, False),
    "samsung":        ("web", "Mozilla/5.0 (Linux; Android 15; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/28.0 Chrome/130.0.0.0 Mobile Safari/537.36", "t13d1516h2_8daaf6152771_02713d6af862", 3, False),
    "app_ios":        ("ios", "ShopApp/7.4.1 (iPhone; iOS 18.6; Scale/3.00)", "t13d1312h2_c866b44c5a62_8e8f8d8bb13b", 10, False),
    "app_android":    ("android", "ShopApp/7.4.1 (Android 15; Pixel 8a)", "t13d1313h2_c866b44c5a62_1cf2f3a5e8d9", 8, False),
}
JA4_PYTHON = "t13d1312h2_e8f1e7e0e8f0_1a2b3c4d5e6f"      # requests/httpx-style stack (QA, A1)
JA4_ANTIDETECT = FAMILIES["chromium_linux"][2]            # B1's stack: same as a real minority browser
UA_PYTHON = "python-requests/2.34.2"
DESKTOP_FAMILIES = [(f, v[3]) for f, v in FAMILIES.items() if v[4]]
MOBILE_FAMILIES = [(f, v[3]) for f, v in FAMILIES.items() if not v[4]]

OAUTH_PROVIDERS = [("google", 55), ("apple", 30), ("facebook", 15)]
EMAIL_DOMAINS = [("mail.example", 45), ("post.example", 20), ("inbox.example", 15), ("corp.example", 10), ("uni.example", 5), ("fast.example", 5)]
DISPOSABLE_DOMAINS = ["tempbox.example", "10min.example", "throwaway.example"]
SUPPORT_AGENTS = [f"agent-{n:03d}" for n in range(1, 41)]
RING_AGENTS = ["agent-007", "agent-019", "agent-033"]
SVC_MFA = "svc-mfa-migrate"


@dataclass
class Block:
    cidr: str          # /24 (or /48 for v6)
    kind: str          # residential | mobile | datacenter | vpn | tor | cgnat
    country: str
    city: str
    asn: int
    asn_org: str
    v6: bool = False

    def ip(self, host):
        if self.v6:
            return f"{self.cidr.split('::')[0]}:{host % 65535 + 1:x}::1"
        base = self.cidr.split("/")[0].rsplit(".", 1)[0]
        return f"{base}.{host % 254 + 1}"


@dataclass
class World:
    blocks: list = field(default_factory=list)
    residential: dict = field(default_factory=dict)    # country -> [Block]
    residential_v6: dict = field(default_factory=dict)
    mobile: dict = field(default_factory=dict)         # country -> [Block]
    cgnat: dict = field(default_factory=dict)          # country -> [ip]
    datacenter: list = field(default_factory=list)
    vpn: list = field(default_factory=list)
    tor: list = field(default_factory=list)
    hosting: list = field(default_factory=list)
    glitch_block: Block = None
    glitch_days: tuple = (50, 53)                      # [from, to)
    glitch_country: str = "BR"


def build_world(seed):
    """Allocate the non-routable address space to ISPs, carriers and hosters."""
    rng = rng_for(seed, "world")
    w = World()
    third = [0]

    def next24(kind, country, city, asn, org):
        n = third[0]
        third[0] += 1
        if n >= 512:
            raise RuntimeError("198.18.0.0/15 exhausted")
        b = Block(f"198.{18 + n // 256}.{n % 256}.0/24", kind, country, city, asn, org)
        w.blocks.append(b)
        return b

    asn = [64512]

    def next_asn():
        asn[0] += 1
        return asn[0]

    v6 = [0]
    total_weight = sum(wt for _, wt in POPULATED)
    for code, wt in POPULATED:
        cities = COUNTRIES[code][3]
        n_blocks = max(6, round(300 * wt / total_weight))
        isps = [(next_asn(), f"{code} Broadband {i + 1}") for i in range(2 if wt < 8 else 3)]
        w.residential[code] = []
        w.residential_v6[code] = []
        for i in range(n_blocks):
            a, org = isps[i % len(isps)]
            city = cities[i % len(cities)][0]
            w.residential[code].append(next24("residential", code, city, a, org))
        for a, org in isps:
            v6[0] += 1
            b = Block(f"2001:db8:{v6[0]:x}::/48", "residential", code, cities[0][0], a, org, v6=True)
            w.blocks.append(b)
            w.residential_v6[code].append(b)
        carriers = [(next_asn(), f"{code} Mobile {i + 1}") for i in range(2)]
        w.mobile[code] = []
        w.cgnat[code] = []
        for i, (a, org) in enumerate(carriers):
            w.mobile[code].append(next24("mobile", code, cities[i % len(cities)][0], a, org))
            # one CGNAT egress address per carrier, shared by hundreds of subscribers
            cg = Block(f"100.{64 + (v6[0] + i) % 60}.{i}.0/24", "cgnat", code, cities[i % len(cities)][0], a, org)
            w.blocks.append(cg)
            w.cgnat[code].append(cg.ip(7 + i))
    for code, org in [("US", "CloudNine Hosting"), ("US", "CloudNine Hosting"), ("US", "Boxcar Cloud"), ("DE", "Hetzgrid"), ("DE", "Hetzgrid"),
                      ("NL", "Tulip Datacenters"), ("NL", "Tulip Datacenters"), ("SG", "Lion Cloud"), ("FR", "Ovoid Hosting"), ("GB", "Thames DC")]:
        a = 64600 + ["CloudNine Hosting", "Boxcar Cloud", "Hetzgrid", "Tulip Datacenters", "Lion Cloud", "Ovoid Hosting", "Thames DC"].index(org)
        for _ in range(3):
            w.datacenter.append(next24("datacenter", code, COUNTRIES[code][3][0][0], a, org))
    # VPN exits: one /24, many countries
    for i, code in enumerate(["US", "NL", "GB", "DE", "CH", "JP", "SG", "CA"]):
        b = Block(f"192.0.2.{i * 32}/27", "vpn", code, COUNTRIES[code][3][0][0], 64700, "PrivateTunnel VPN")
        w.blocks.append(b)
        w.vpn.append(b)
    for i, code in enumerate(["DE", "NL", "US", "FR"]):
        b = Block(f"198.51.100.{i * 64}/26", "tor", code, COUNTRIES[code][3][0][0], 64710, "Tor exit")
        w.blocks.append(b)
        w.tor.append(b)
    b = Block("203.0.113.0/24", "datacenter", "NL", "Amsterdam", 64720, "Bulletgrid Hosting")
    w.blocks.append(b)
    w.hosting.append(b)
    # the geo-IP glitch: one GB residential block that the provider mis-maps for three days
    w.glitch_block = w.residential["GB"][3]
    return w


def vpn_ip(w, rng, exit_block):
    base = exit_block.cidr.split("/")[0].rsplit(".", 1)
    return f"{base[0]}.{int(base[1]) + rng.randrange(1, 30)}"


def world_json(w):
    rows = []
    for b in w.blocks:
        rows.append({"cidr": b.cidr, "asn": b.asn, "asn_org": b.asn_org, "asn_type": b.kind, "country": b.country, "city": b.city})
    cities = []
    for code, (tz, lang, _, cs) in COUNTRIES.items():
        for name, lat, lon in cs:
            cities.append({"country": code, "city": name, "lat": lat, "lon": lon, "tz_offset_min": int(tz * 60), "language": lang})
    return {
        "_comment": [
            "The simulated internet for the W3 Ch7 audit log. Residential, mobile and datacenter",
            "pools live in 198.18.0.0/15 (RFC 2544 benchmark space, non-routable), CGNAT egress in",
            "100.64.0.0/10 (RFC 6598), VPN/Tor/hosting in the RFC 5737 /24s, IPv6 in 2001:db8::/32.",
            "Nothing here can point at a real network. Private ASNs (RFC 6996).",
            "The geo table is what the store's geo-IP provider *thinks*; see the generator for the one",
            "block it mis-maps for three days.",
        ],
        "blocks": rows,
        "cities": cities,
        "families": {f: {"client": v[0], "user_agent": v[1], "ja4": v[2]} for f, v in FAMILIES.items()},
    }


# ----------------------------------------------------------------------------
# Accounts, devices, contexts and the event sink
# ----------------------------------------------------------------------------

@dataclass
class Device:
    device_id: str
    fp_hash: str
    family: str

    @property
    def ua(self):
        return FAMILIES[self.family][1]

    @property
    def ja4(self):
        return FAMILIES[self.family][2]

    @property
    def client(self):
        return FAMILIES[self.family][0]


@dataclass
class Ctx:
    """Everything a session carries: where it comes from and what it looks like."""
    ip: str
    asn: int
    asn_type: str
    country: str
    city: str
    device: Device
    tz_offset: int
    accept_language: str
    session_id: str
    ua: str = None
    ja4: str = None
    fp_hash: str = None
    client: str = None


@dataclass
class Account:
    idx: int
    account_id: str
    email_domain: str
    country: str
    city: str
    tz_offset: int
    accept_language: str
    created_ms: int
    home_block: Block
    home_host: int
    v6_block: Block
    devices: list
    hour_center: float
    hour_sd: float
    rate_per_day: float
    order_rate: float
    order_median: float
    remember_me: bool
    mfa: str                    # none | totp | sms | push
    passkey: bool
    oauth: list                 # [(provider, sub_hash)]
    mobile_share: float
    cohorts: list = field(default_factory=list)
    traits: dict = field(default_factory=dict)
    # mutable state
    alerts: bool = True
    known_devices: list = field(default_factory=list)
    last_session_id: str = None
    last_session_ctx: Ctx = None
    n_events_pre: int = 0       # events before day 25, for campaign preconditions
    campaign: str = None        # set by injectors; an account is a victim of at most one
    sessions: list = field(default_factory=list)   # (start_ms, ctx) of baseline sessions


class Sink:
    """Collects events; assigns ids after the global sort."""

    def __init__(self, seed):
        self.seed = seed
        self.rows = []
        self.seq = 0
        self.req = 0

    def emit(self, acct, ms, etype, ctx, outcome="success", actor="user", auth=None, mfa=None, details=None, request_id=None, late_ok=True):
        self.seq += 1
        if request_id is None:
            self.req += 1
            request_id = hexid(self.seed, "req", self.req, 20)
        row = {
            "account_id": acct.account_id if acct else None,
            "event_type": etype,
            "outcome": outcome,
            "actor": actor,
            "client": ctx.client or ctx.device.client,
            "session_id": ctx.session_id,
            "ip": ctx.ip,
            "asn": ctx.asn,
            "asn_type": ctx.asn_type,
            "country": ctx.country,
            "city": ctx.city,
            "user_agent": ctx.ua or ctx.device.ua,
            "device_id": ctx.device.device_id,
            "fp_hash": ctx.fp_hash or ctx.device.fp_hash,
            "ja4": ctx.ja4 or ctx.device.ja4,
            "accept_language": ctx.accept_language,
            "tz_offset": ctx.tz_offset,
            "auth_method": auth,
            "mfa_method": mfa,
            "request_id": request_id,
            "details": details or {},
        }
        self.rows.append([ms, acct.account_id if acct else "", self.seq, row, late_ok])
        return self.seq


class Ids:
    def __init__(self, seed):
        self.seed = seed
        self.n = {}

    def new(self, label, length=16):
        self.n[label] = self.n.get(label, 0) + 1
        return hexid(self.seed, label, self.n[label], length)


def make_device(ids, family):
    return Device(ids.new("dev"), ids.new("fp"), family)


def ctx_from(w, acct, device, ms, rng, mobile=None, block=None, session_id=None, ids=None):
    """A session context in the account's normal habitat."""
    if block is None:
        if device.family in ("app_ios", "app_android", "chrome_android", "safari_ios", "samsung"):
            if "cgnat" in acct.cohorts:
                b = w.mobile[acct.country][acct.traits["carrier"]]
                ip = acct.traits["cgnat_ip"]
                return Ctx(ip, b.asn, "cgnat", b.country, b.city, device, acct.tz_offset, acct.accept_language, session_id or ids.new("sess"))
            if rng.random() < 0.55:          # phones are on wifi more than half the time
                block = acct.home_block
            else:
                block = w.mobile[acct.country][acct.traits.get("carrier", 0)]
                return Ctx(block.ip(rng.randrange(254)), block.asn, "mobile", block.country, block.city, device, acct.tz_offset, acct.accept_language, session_id or ids.new("sess"))
        else:
            block = acct.home_block
    if block is acct.home_block and acct.v6_block is not None and rng.random() < 0.30:
        b = acct.v6_block
        return Ctx(b.ip(acct.idx), b.asn, "residential", acct.country, acct.city, device, acct.tz_offset, acct.accept_language, session_id or ids.new("sess"))
    host = acct.home_host if block is acct.home_block else rng.randrange(254)
    return Ctx(block.ip(host), block.asn, block.kind, block.country, block.city, device, acct.tz_offset, acct.accept_language, session_id or ids.new("sess"))


def apply_geo_glitch(w, ctx, ms):
    """What the geo-IP provider reported: for three days one GB block looks Brazilian."""
    if ctx.ip.startswith(w.glitch_block.cidr.rsplit(".", 1)[0] + ".") and day_ms(w.glitch_days[0]) <= ms < day_ms(w.glitch_days[1]):
        ctx.country = w.glitch_country
        ctx.city = COUNTRIES[w.glitch_country][3][0][0]
    return ctx


# ----------------------------------------------------------------------------
# Population
# ----------------------------------------------------------------------------

def local_hour_to_ms(rng, day_index, acct, center=None, sd=None):
    """A timestamp on the given window day at one of the account's usual local hours."""
    center = acct.hour_center if center is None else center
    sd = acct.hour_sd if sd is None else sd
    h = gauss(rng, center, sd) % 24
    local = day_ms(day_index) + int(h * HOUR)
    return local - acct.tz_offset * MINUTE


def make_population(seed, w, n_accounts, scale):
    ids = Ids(seed)
    rng = rng_for(seed, "population")
    accounts = []
    for i in range(n_accounts):
        r = rng_for(seed, "acct", i)
        country = weighted(r, POPULATED)
        tz, lang, _, cities = COUNTRIES[country]
        blocks = w.residential[country]
        home_block = blocks[r.randrange(len(blocks))]
        city = home_block.city
        v6_block = w.residential_v6[country][r.randrange(len(w.residential_v6[country]))] if r.random() < 0.5 else None
        devices = [make_device(ids, weighted(r, DESKTOP_FAMILIES))]
        mobile_share = 0.0
        if r.random() < 0.62:
            devices.append(make_device(ids, weighted(r, MOBILE_FAMILIES)))
            mobile_share = 0.3 + 0.5 * r.random()
        elif r.random() < 0.25:                      # phone-only people
            devices = [make_device(ids, weighted(r, MOBILE_FAMILIES))]
            mobile_share = 1.0
        created_ms = SIM_START_MS - int(lognormal(r, 400, 0.9) * DAY)   # most accounts are years old
        mfa = weighted(r, [("none", 62), ("totp", 14), ("sms", 16), ("push", 8)])
        passkey = r.random() < 0.08
        oauth = []
        if r.random() < 0.22:
            prov = weighted(r, OAUTH_PROVIDERS)
            oauth.append((prov, ids.new("sub")))
        acct = Account(
            idx=i, account_id=f"acc_{i + 1:06d}", email_domain=weighted(r, EMAIL_DOMAINS), country=country, city=city,
            tz_offset=int(tz * 60), accept_language=lang, created_ms=created_ms, home_block=home_block, home_host=r.randrange(254),
            v6_block=v6_block, devices=devices, hour_center=weighted(r, [(9, 1), (12, 2), (19, 4), (21, 3)]) + gauss(r, 0, 1.0),
            hour_sd=2.0 + 1.5 * r.random(), rate_per_day=lognormal(r, 0.085, 0.75), order_rate=lognormal(r, 0.35, 0.8),
            order_median=lognormal(r, 48, 0.6), remember_me=r.random() < 0.7, mfa=mfa, passkey=passkey, oauth=oauth, mobile_share=mobile_share,
        )
        acct.traits["carrier"] = r.randrange(2)
        acct.known_devices = list(devices)
        accounts.append(acct)
    return accounts, ids


def assign_cohorts(seed, w, accounts, scale):
    """Draw cohort membership in a fixed order. Returns cohort -> [account]."""
    rng = rng_for(seed, "cohorts")
    n = len(accounts)
    pool = list(accounts)
    cohorts = {}

    def take(name, count, pred=lambda a: True, exclusive=True):
        count = max(1, round(count * scale)) if count else 0
        cands = [a for a in pool if pred(a) and name not in a.cohorts]
        chosen = []
        for _ in range(min(count, len(cands))):
            a = cands.pop(rng.randrange(len(cands)))
            a.cohorts.append(name)
            chosen.append(a)
            if exclusive and a in pool:
                pool.remove(a)
        cohorts[name] = chosen
        return chosen

    # the ones that reshape an account's whole history
    take("vpn_always_on", 350, lambda a: a.mobile_share < 1.0)
    take("cgnat", 600, lambda a: len(a.devices) > 1 or a.mobile_share == 1.0)
    take("household", 300)
    take("privacy_browser", 300, lambda a: a.mobile_share < 1.0)
    take("qa_robot", 40)
    take("night_shift", 250)
    take("shared_access_couple", 200)
    take("geo_glitch", 150, lambda a: a.country == "GB")
    # the ones that add an episode to an otherwise typical history (non-exclusive)
    take("traveller", 400, exclusive=False)
    take("new_phone", 500, lambda a: a.mobile_share < 1.0, exclusive=False)
    take("relocator", 60, exclusive=False)
    take("pw_manager_migrant", 250, exclusive=False)
    take("email_migrant", 150, exclusive=False)
    take("forgetful", 500, exclusive=False)
    take("support_recovery", 120, exclusive=False)
    take("dormant_returner", 300, exclusive=False)
    take("gift_buyer", 400, exclusive=False)
    take("duplicate_owner", 80, lambda a: not a.oauth, exclusive=False)
    take("bulk_mfa_reenrol", 500, lambda a: a.mfa != "none", exclusive=False)
    take("stuffing_target", 900, exclusive=False)
    take("spray_target", 600, lambda a: "stuffing_target" not in a.cohorts, exclusive=False)
    take("forced_reset", 300, lambda a: "stuffing_target" in a.cohorts, exclusive=False)
    for a in accounts:
        if not a.cohorts:
            a.cohorts.append("typical")
    cohorts["typical"] = [a for a in accounts if a.cohorts == ["typical"]]
    # overlay parameters
    for a in cohorts["geo_glitch"]:
        a.home_block = w.glitch_block
        a.city = w.glitch_block.city
        a.v6_block = None
    for a in cohorts["night_shift"]:
        a.hour_center = 3.0 + rng.random() * 2
        a.hour_sd = 1.5
    for a in cohorts["cgnat"]:
        a.traits["cgnat_ip"] = w.cgnat[a.country][a.traits["carrier"]]
        a.mobile_share = max(a.mobile_share, 0.8)
    for a in cohorts["vpn_always_on"]:
        a.traits["vpn_exit"] = w.vpn[rng.randrange(len(w.vpn))]
    for a in cohorts["qa_robot"]:
        a.remember_me = False
        a.mfa = "none"
    # households: groups of 2-4 accounts share one desktop (and keep their phones)
    hh = cohorts["household"]
    i = 0
    g = 0
    while i < len(hh):
        size = 2 + rng.randrange(3)
        group = hh[i:i + size]
        shared = make_device(Ids(f"{seed}:hh{g}"), weighted(rng, DESKTOP_FAMILIES))
        home = group[0].home_block
        for a in group:
            a.devices = [shared] + [d for d in a.devices if d.family in [f for f, _ in MOBILE_FAMILIES]]
            a.known_devices = list(a.devices)
            a.home_block, a.home_host, a.country, a.city = home, group[0].home_host, group[0].country, group[0].city
            a.tz_offset, a.accept_language = group[0].tz_offset, group[0].accept_language
            a.traits["household"] = g
        i += size
        g += 1
    # duplicate-account owners: pairs that are one person with two accounts
    dup = cohorts["duplicate_owner"]
    for j in range(0, len(dup) - 1, 2):
        a, b = dup[j], dup[j + 1]
        prov = weighted(rng, OAUTH_PROVIDERS)
        sub = hexid(seed, "dupsub", j)
        a.oauth = [(prov, sub)]
        b.oauth = [(prov, sub)]
        b.devices = list(a.devices)
        b.known_devices = list(a.devices)
        b.home_block, b.home_host, b.country, b.city, b.tz_offset, b.accept_language = a.home_block, a.home_host, a.country, a.city, a.tz_offset, a.accept_language
    # shared-access couples: a second device in the same city with its own hours and locale
    for a in cohorts["shared_access_couple"]:
        other = make_device(Ids(f"{seed}:couple{a.idx}"), weighted(rng, DESKTOP_FAMILIES + MOBILE_FAMILIES))
        a.devices.append(other)
        a.known_devices.append(other)
        a.traits["couple_device"] = other
        a.traits["couple_hour"] = (a.hour_center + 6 + rng.random() * 6) % 24
        a.traits["couple_lang"] = weighted(rng, [(a.accept_language, 6), ("en-US", 2), ("es-ES", 1), ("de-DE", 1)])
    return cohorts


# ----------------------------------------------------------------------------
# Baseline behaviour
# ----------------------------------------------------------------------------

HIGH_RISK = ["password_change", "email_change_confirmed", "mfa_disabled", "recovery_email_change", "notification_settings_changed", "phone_change"]


def pick_device(acct, rng):
    phones = [d for d in acct.devices if d.family in [f for f, _ in MOBILE_FAMILIES]]
    desks = [d for d in acct.devices if d not in phones]
    if phones and (not desks or rng.random() < acct.mobile_share):
        return phones[rng.randrange(len(phones))]
    return desks[rng.randrange(len(desks))] if desks else phones[0]


def mfa_challenge(sink, acct, ms, ctx, rng, force=False):
    """A real user's MFA: usually passes, sometimes after a mistyped code."""
    if acct.mfa == "none" and not acct.passkey:
        return ms
    if acct.passkey:
        return ms
    if not force and acct.remember_me and ctx.device in acct.known_devices and rng.random() < 0.7:
        return ms
    for _ in range(1 if rng.random() > 0.08 else 1 + rng.randrange(2)):
        if rng.random() < 0.06:
            ms += 20 * SECOND + rng.randrange(40 * SECOND)
            sink.emit(acct, ms, "mfa_challenge_failure", ctx, outcome="failure", mfa=acct.mfa, details={"reason": "bad_code" if acct.mfa != "push" else "push_timeout"})
    ms += 8 * SECOND + rng.randrange(40 * SECOND)
    sink.emit(acct, ms, "mfa_challenge_success", ctx, mfa=acct.mfa)
    return ms


def login(sink, acct, ms, ctx, rng, w, new_device_alert=True):
    """One legitimate login. Returns the timestamp after it."""
    apply_geo_glitch(w, ctx, ms)
    known = ctx.device in acct.known_devices
    if acct.remember_me and known and acct.last_session_id and rng.random() < 0.6:
        # remember-me: the browser resumes; the server rotates the session id for newer clients
        parent = acct.last_session_id
        details = {"parent_session_hash": hashlib.sha256(parent.encode()).hexdigest()[:12]} if rng.random() < 0.5 else {}
        sink.emit(acct, ms, "login_success", ctx, auth="session_resume", details=details)
    else:
        if acct.passkey and known and rng.random() < 0.7:
            sink.emit(acct, ms, "login_success", ctx, auth="passkey")
        elif acct.oauth and rng.random() < 0.5:
            prov, sub = acct.oauth[0]
            sink.emit(acct, ms, "login_success", ctx, auth=f"oauth:{prov}", details={"provider": prov, "provider_sub_hash": sub})
        else:
            ms2 = mfa_challenge(sink, acct, ms, ctx, rng, force=not known)
            sink.emit(acct, ms2, "login_success", ctx, auth="password", mfa=acct.mfa if ms2 != ms else None)
            ms = ms2
    if not known:
        acct.known_devices.append(ctx.device)
        if new_device_alert and acct.alerts:
            sink.emit(acct, ms + 2 * SECOND, "new_device_alert_sent", ctx, actor="system", details={"channel": "email"})
    acct.last_session_id = ctx.session_id
    acct.last_session_ctx = ctx
    return ms + 3 * SECOND


def browse(sink, acct, ms, ctx, rng, max_actions=4):
    """What people do once logged in: look at orders, occasionally buy."""
    n = rng.randrange(max_actions + 1)
    for _ in range(n):
        ms += 15 * SECOND + rng.randrange(150 * SECOND)
        r = rng.random()
        if r < 0.45:
            sink.emit(acct, ms, "orders_viewed", ctx)
        elif r < 0.55:
            sink.emit(acct, ms, "payment_methods_viewed", ctx)
        elif r < 0.62:
            sink.emit(acct, ms, "profile_updated", ctx, details={"fields": ["display_name"]})
        elif r < 0.66:
            sink.emit(acct, ms, "address_added", ctx, details={"country": acct.country})
        elif r < 0.69:
            sink.emit(acct, ms, "payment_method_added", ctx, details={"kind": "card"})
        else:
            break
    return ms


def maybe_order(sink, acct, ms, ctx, rng, gift=False, amount=None):
    amount = amount if amount is not None else round(lognormal(rng, acct.order_median, 0.5), 2)
    new_addr = gift or rng.random() < 0.06
    ship_country = acct.country
    if gift and rng.random() < 0.35:
        ship_country = weighted(rng, POPULATED)
    sink.emit(acct, ms, "order_placed", ctx, details={"amount": amount, "currency": "USD", "ship_to_new_address": new_addr, "ship_country": ship_country})
    return ms + 5 * SECOND


def session(sink, acct, start_ms, ctx, rng, w, gift=False, max_actions=4):
    ms = login(sink, acct, start_ms, ctx, rng, w)
    if ctx.device.family in dict(MOBILE_FAMILIES) and ctx.asn_type == "residential" and rng.random() < 0.08:
        mb = w.mobile[acct.country][acct.traits.get("carrier", 0)]
        ctx = Ctx(acct.traits.get("cgnat_ip") or mb.ip(rng.randrange(254)), mb.asn, "cgnat" if "cgnat" in acct.cohorts else "mobile", mb.country, mb.city,
                  ctx.device, ctx.tz_offset, ctx.accept_language, ctx.session_id, ua=ctx.ua, ja4=ctx.ja4, fp_hash=ctx.fp_hash, client=ctx.client)
        ms += 20 * SECOND
    ms = browse(sink, acct, ms, ctx, rng, max_actions=max_actions)
    if rng.random() < acct.order_rate * 0.25 or gift:
        ms += 30 * SECOND + rng.randrange(4 * MINUTE)
        ms = maybe_order(sink, acct, ms, ctx, rng, gift=gift)
    if rng.random() < 0.3:
        ms += 10 * SECOND + rng.randrange(2 * MINUTE)
        sink.emit(acct, ms, "logout", ctx)
    return ms


def rare_settings_event(sink, acct, ms, ctx, rng):
    """The low-rate legitimate sensitive actions every population has."""
    r = rng.random()
    if r < 0.30:
        sink.emit(acct, ms, "password_change", ctx, details={"reason": "user_initiated"})
    elif r < 0.45:
        acct.alerts = rng.random() < 0.4
        sink.emit(acct, ms, "notification_settings_changed", ctx, details={"alerts_enabled": acct.alerts, "marketing_enabled": rng.random() < 0.5})
    elif r < 0.60:
        sink.emit(acct, ms, "phone_change", ctx, details={"verified": True})
    elif r < 0.75:
        prov = weighted(rng, OAUTH_PROVIDERS)
        sink.emit(acct, ms, "third_party_linked", ctx, details={"provider": prov, "provider_sub_hash": hexid(acct.account_id, "lsub", ms)})
    elif r < 0.85:
        sink.emit(acct, ms, "mfa_enabled", ctx, mfa=weighted(rng, [("totp", 5), ("sms", 3), ("push", 2)]))
        acct.mfa = acct.mfa if acct.mfa != "none" else "totp"
    elif r < 0.93:
        sink.emit(acct, ms, "passkey_added", ctx, details={"authenticator": "platform"})
        acct.passkey = True
    elif r < 0.97:
        sink.emit(acct, ms, "api_token_created", ctx, details={"scope": "orders:read"})
    else:
        sink.emit(acct, ms, "sessions_revoked_all", ctx)


def baseline(sink, w, acct, ids, seed):
    """The account's own life over pre-history plus window, before any overlay."""
    rng = rng_for(seed, "baseline", acct.idx)
    rate = acct.rate_per_day
    if "qa_robot" in acct.cohorts:
        return qa_robot(sink, w, acct, ids, rng)
    dormant_from = None
    if "dormant_returner" in acct.cohorts:
        dormant_from = -PREHISTORY_DAYS + rng.randrange(10)        # silent for 40-80 days, then back
        acct.traits["dormant_until"] = dormant_from + 40 + rng.randrange(40)
    vpn = acct.traits.get("vpn_exit")
    day = -PREHISTORY_DAYS
    while day < DAYS:
        if dormant_from is not None and dormant_from <= day < acct.traits["dormant_until"]:
            day += 1
            continue
        # Poisson-ish: number of sessions today
        k = 0
        p = rate
        while rng.random() < p and k < 4:
            k += 1
            p *= 0.4
        for _ in range(k):
            dev = pick_device(acct, rng)
            lang_override = None
            start = local_hour_to_ms(rng, day, acct)
            if "shared_access_couple" in acct.cohorts and rng.random() < 0.4:
                dev = acct.traits["couple_device"]
                start = local_hour_to_ms(rng, day, acct, center=acct.traits["couple_hour"], sd=1.5)
                lang_override = acct.traits["couple_lang"]
            if vpn is not None and dev.family not in ("app_ios", "app_android"):
                ctx = Ctx(vpn_ip(w, rng, vpn), vpn.asn, "vpn", vpn.country, vpn.city, dev, acct.tz_offset, acct.accept_language, ids.new("sess"))
            else:
                ctx = ctx_from(w, acct, dev, start, rng, ids=ids)
            if lang_override:
                ctx.accept_language = lang_override
            if "privacy_browser" in acct.cohorts and dev.family not in ("app_ios", "app_android"):
                ctx.fp_hash = ids.new("pfp")                     # randomised canvas every session
                if rng.random() < 0.3:
                    ctx.device = Device(ids.new("pdev"), ctx.fp_hash, dev.family)   # cookies cleared too
                    acct.known_devices.append(ctx.device)
            gift = "gift_buyer" in acct.cohorts and 60 <= day < 88 and rng.random() < 0.35
            end = session(sink, acct, start, ctx, rng, w, gift=gift)
            acct.sessions.append((start, ctx))
            if rng.random() < 0.012:
                rare_settings_event(sink, acct, end + 20 * SECOND + rng.randrange(MINUTE), ctx, rng)
            if 0 <= day < 25:
                acct.n_events_pre += 3
        day += 1
    if acct.created_ms >= SIM_START_MS:
        pass
    return None


def qa_robot(sink, w, acct, ids, rng):
    """Test accounts: an automated smoke test from the CI runner, every few hours."""
    dc = w.datacenter[acct.idx % len(w.datacenter)]
    shared = Device(hexid("qa", "dev", acct.idx % 3), hexid("qa", "fp", acct.idx % 3), "chrome_win")
    acct.devices = [shared]
    acct.known_devices = [shared]
    for day in range(-PREHISTORY_DAYS, DAYS):
        for hour in (3, 15):
            if rng.random() < 0.5:
                continue
            ms = day_ms(day) + hour * HOUR + (acct.idx % 7) * MINUTE + rng.randrange(5 * SECOND)
            ctx = Ctx(dc.ip(10 + acct.idx % 5), dc.asn, "datacenter", dc.country, dc.city, shared, 0, "en-US", ids.new("sess"), ua=UA_PYTHON, ja4=JA4_PYTHON, client="api")
            sink.emit(acct, ms, "login_success", ctx, auth="password")
            sink.emit(acct, ms + 2 * SECOND, "orders_viewed", ctx)
            if rng.random() < 0.3:
                sink.emit(acct, ms + 4 * SECOND, "order_placed", ctx, details={"amount": 1.0, "currency": "USD", "ship_to_new_address": False, "ship_country": "US", "test": True})
            sink.emit(acct, ms + 6 * SECOND, "logout", ctx)
            if 0 <= day < 25:
                acct.n_events_pre += 3


def lifecycle_for_new(sink, w, acct, ids, rng, created_day, disposable=False, block=None, device=None):
    """account_created and verification for accounts born inside the window."""
    ms = local_hour_to_ms(rng, created_day, acct)
    acct.created_ms = ms
    dev = device or pick_device(acct, rng)
    ctx = ctx_from(w, acct, dev, ms, rng, block=block, ids=ids)
    domain = DISPOSABLE_DOMAINS[rng.randrange(len(DISPOSABLE_DOMAINS))] if disposable else acct.email_domain
    acct.email_domain = domain
    sink.emit(acct, ms, "account_created", ctx, details={"email_domain": domain, "signup_channel": acct.traits.get("signup_channel", "organic")})
    sink.emit(acct, ms + 1 * SECOND, "terms_accepted", ctx, details={"version": "2026-07"})
    sink.emit(acct, ms + 2 * SECOND, "email_verification_sent", ctx, actor="system")
    if not acct.traits.get("never_verifies"):
        ms2 = ms + 30 * SECOND + rng.randrange(20 * MINUTE)
        sink.emit(acct, ms2, "email_verified", ctx)
        ms = ms2
    acct.known_devices = [dev]
    acct.last_session_id = ctx.session_id
    return ms, ctx


# ----------------------------------------------------------------------------
# Legitimate episodes (the red herrings)
# ----------------------------------------------------------------------------

def overlays(sink, w, accounts, cohorts, ids, seed):
    rng = rng_for(seed, "overlays")

    for a in cohorts["traveller"]:
        r = rng_for(seed, "travel", a.idx)
        for _ in range(1 + r.randrange(2)):
            start_day = r.randrange(0, DAYS - 10)
            length = 3 + r.randrange(8)
            dest = weighted(r, [(c, wt) for c, wt in POPULATED if c != a.country])
            blocks = w.residential[dest] + w.mobile[dest]
            dev = pick_device(a, r)
            for d in range(start_day, start_day + length):
                if r.random() < 0.5:
                    continue
                b = blocks[r.randrange(len(blocks))]
                ms = local_hour_to_ms(r, d, a) + int(COUNTRIES[dest][0] * 60 - a.tz_offset) * MINUTE * 0  # device keeps its home tz
                ctx = Ctx(b.ip(r.randrange(254)), b.asn, b.kind, b.country, b.city, dev, a.tz_offset, a.accept_language, ids.new("sess"))
                end = session(sink, a, ms, ctx, r, w, max_actions=3)
                if d == start_day + 2 and r.random() < 0.25:
                    end = mfa_challenge(sink, a, end + 40 * SECOND, ctx, r, force=True)
                    sink.emit(a, end + 10 * SECOND, "password_change", ctx, details={"reason": "user_initiated"})

    for a in cohorts["new_phone"]:
        r = rng_for(seed, "newphone", a.idx)
        d = 5 + r.randrange(DAYS - 10)
        old = [x for x in a.devices if x.family in [f for f, _ in MOBILE_FAMILIES]]
        fam = weighted(r, MOBILE_FAMILIES)
        new = make_device(ids, fam)
        ms = local_hour_to_ms(r, d, a)
        ctx = ctx_from(w, a, new, ms, r, ids=ids)
        auth = "passkey" if a.passkey and r.random() < 0.5 else "password"
        if auth == "password":
            ms = mfa_challenge(sink, a, ms, ctx, r, force=True)
        sink.emit(a, ms, "login_success", ctx, auth=auth, mfa=a.mfa if auth == "password" and a.mfa != "none" else None)
        a.known_devices.append(new)
        if a.alerts:
            sink.emit(a, ms + 2 * SECOND, "new_device_alert_sent", ctx, actor="system", details={"channel": "email"})
        ms = browse(sink, a, ms + 5 * SECOND, ctx, r)
        if r.random() < 0.5:
            sink.emit(a, ms + 30 * SECOND, "address_added", ctx, details={"country": a.country})
        if r.random() < 0.4 and a.mfa != "none":
            sink.emit(a, ms + 60 * SECOND, "mfa_enabled", ctx, mfa=a.mfa, details={"reason": "re_enrolled_new_device"})
        a.devices = [x for x in a.devices if x not in old] + [new]

    for a in cohorts["relocator"]:
        r = rng_for(seed, "reloc", a.idx)
        d = 10 + r.randrange(DAYS - 25)
        dest = weighted(r, [(c, wt) for c, wt in POPULATED if c != a.country])
        a.country, a.city = dest, COUNTRIES[dest][3][0][0]
        a.home_block = w.residential[dest][r.randrange(len(w.residential[dest]))]
        a.v6_block = None
        a.tz_offset = int(COUNTRIES[dest][0] * 60)
        for dd in range(d, min(DAYS, d + 20)):
            if r.random() < 0.3:
                ms = local_hour_to_ms(r, dd, a)
                ctx = ctx_from(w, a, pick_device(a, r), ms, r, ids=ids)
                end = session(sink, a, ms, ctx, r, w)
                if dd == d:
                    sink.emit(a, end + 20 * SECOND, "address_added", ctx, details={"country": dest})
                    end = mfa_challenge(sink, a, end + 60 * SECOND, ctx, r, force=True)
                    sink.emit(a, end + 5 * SECOND, "phone_change", ctx, details={"verified": True})
                    sink.emit(a, end + 40 * SECOND, "order_placed", ctx, details={"amount": round(lognormal(r, a.order_median, 0.5), 2), "currency": "USD", "ship_to_new_address": True, "ship_country": dest})

    for a in cohorts["pw_manager_migrant"]:
        r = rng_for(seed, "pwm", a.idx)
        d = r.randrange(DAYS)
        ms = local_hour_to_ms(r, d, a)
        dev = [x for x in a.devices if x.family not in [f for f, _ in MOBILE_FAMILIES]]
        ctx = ctx_from(w, a, dev[0] if dev else a.devices[0], ms, r, ids=ids)
        ms = login(sink, a, ms, ctx, r, w)
        ms = mfa_challenge(sink, a, ms + 40 * SECOND, ctx, r, force=True)
        sink.emit(a, ms + 5 * SECOND, "password_change", ctx, details={"reason": "user_initiated", "strength": "generated"})
        if a.mfa == "none":
            sink.emit(a, ms + 90 * SECOND, "mfa_enabled", ctx, mfa="totp")
            a.mfa = "totp"
        sink.emit(a, ms + 150 * SECOND, "passkey_added", ctx, details={"authenticator": "password_manager"})
        a.passkey = True
        sink.emit(a, ms + 170 * SECOND, "mfa_backup_codes_regenerated", ctx)

    for a in cohorts["email_migrant"]:
        r = rng_for(seed, "emig", a.idx)
        d = r.randrange(DAYS)
        ms = local_hour_to_ms(r, d, a)
        ctx = ctx_from(w, a, pick_device(a, r), ms, r, ids=ids)
        ms = login(sink, a, ms, ctx, r, w)
        new_dom = weighted(r, [(x, wt) for x, wt in EMAIL_DOMAINS if x != a.email_domain])
        sink.emit(a, ms + 30 * SECOND, "email_change_requested", ctx, details={"old_domain": a.email_domain, "new_domain": new_dom})
        ms = mfa_challenge(sink, a, ms + 45 * SECOND, ctx, r, force=True)
        sink.emit(a, ms + 5 * SECOND, "email_verification_sent", ctx, actor="system", details={"domain": new_dom})
        ms2 = ms + 2 * MINUTE + r.randrange(30 * MINUTE)
        sink.emit(a, ms2, "email_verified", ctx, details={"domain": new_dom})
        sink.emit(a, ms2 + 1 * SECOND, "email_change_confirmed", ctx, details={"old_domain": a.email_domain, "new_domain": new_dom})
        a.email_domain = new_dom

    for a in cohorts["forgetful"]:
        r = rng_for(seed, "forget", a.idx)
        d = r.randrange(DAYS)
        ms = local_hour_to_ms(r, d, a)
        ctx = ctx_from(w, a, pick_device(a, r), ms, r, ids=ids)
        for _ in range(2 + r.randrange(4)):
            sink.emit(a, ms, "login_failure", ctx, outcome="failure", auth="password", details={"reason": "bad_password"})
            ms += 8 * SECOND + r.randrange(40 * SECOND)
        sink.emit(a, ms, "password_reset_requested", ctx, details={"channel": "email"})
        ms += 1 * MINUTE + r.randrange(10 * MINUTE)
        sink.emit(a, ms, "password_reset_completed", ctx)
        ms = login(sink, a, ms + 5 * SECOND, ctx, r, w)
        browse(sink, a, ms, ctx, r)

    for a in cohorts["support_recovery"]:
        r = rng_for(seed, "suprec", a.idx)
        d = r.randrange(DAYS)
        ms = local_hour_to_ms(r, d, a)
        new_dev = r.random() < 0.4
        dev = make_device(ids, weighted(r, DESKTOP_FAMILIES + MOBILE_FAMILIES)) if new_dev else pick_device(a, r)
        ctx = ctx_from(w, a, dev, ms, r, ids=ids)
        agent = SUPPORT_AGENTS[r.randrange(len(SUPPORT_AGENTS))]
        ticket = ids.new("tkt", 8)
        sink.emit(a, ms, "support_ticket_opened", ctx, details={"ticket_id": ticket, "channel": weighted(r, [("phone", 6), ("chat", 4)]), "reason": "lost_device" if new_dev else "locked_out"})
        ms += 5 * MINUTE + r.randrange(40 * MINUTE)
        sink.emit(a, ms, "support_reset_issued", ctx, actor="support", details={"ticket_id": ticket, "agent_id": agent, "identity_check": "passed"})
        ms += 2 * MINUTE + r.randrange(20 * MINUTE)
        sink.emit(a, ms, "password_reset_completed", ctx)
        ms = login(sink, a, ms + 10 * SECOND, ctx, r, w)
        if a.mfa != "none" and new_dev:
            sink.emit(a, ms + 60 * SECOND, "mfa_enabled", ctx, mfa=a.mfa, details={"reason": "re_enrolled_after_recovery"})
        browse(sink, a, ms, ctx, r)

    for a in cohorts["bulk_mfa_reenrol"]:
        r = rng_for(seed, "bulkmfa", a.idx)
        ms = day_ms(33) + 9 * HOUR + r.randrange(2 * HOUR)
        last = a.last_session_ctx or ctx_from(w, a, a.devices[0], ms, r, ids=ids)
        ctx = Ctx("10.0.4.21", 0, "internal", "US", "New York", Device("svc-mfa-migrate", "svc-mfa-migrate", "chrome_win"), 0, "en-US", "svc-batch-2026-11-03", ua="SupportConsole/3.2 batch", ja4=None, client="api")
        sink.emit(a, ms, "mfa_disabled", ctx, actor="support", mfa=a.mfa, details={"reason": "policy_reenrol", "agent_id": SVC_MFA, "batch": "mfa-migration-2026-11"})
        if r.random() < 0.8:
            ms2 = ms + DAY + r.randrange(3 * DAY)
            c2 = ctx_from(w, a, pick_device(a, r), ms2, r, ids=ids)
            ms2 = login(sink, a, ms2, c2, r, w)
            sink.emit(a, ms2 + 40 * SECOND, "mfa_enabled", c2, mfa=a.mfa, details={"reason": "policy_reenrol"})

    for j, a in enumerate(cohorts["duplicate_owner"]):
        r = rng_for(seed, "dup", a.idx)
        if j % 2 == 1 and a.oauth:
            d = r.randrange(DAYS)
            ms = local_hour_to_ms(r, d, a)
            ctx = ctx_from(w, a, a.devices[0], ms, r, ids=ids)
            ms = login(sink, a, ms, ctx, r, w)
            prov, sub = a.oauth[0]
            sink.emit(a, ms + 30 * SECOND, "third_party_linked", ctx, details={"provider": prov, "provider_sub_hash": sub})
        elif a.oauth:
            d = r.randrange(DAYS)
            ms = local_hour_to_ms(r, d, a)
            ctx = ctx_from(w, a, a.devices[0], ms, r, ids=ids)
            ms = login(sink, a, ms, ctx, r, w)
            prov, sub = a.oauth[0]
            sink.emit(a, ms + 30 * SECOND, "third_party_linked", ctx, details={"provider": prov, "provider_sub_hash": sub})

    # a marketing campaign: 600 new accounts on day 12, organic signups the rest of the time
    return None


def new_accounts(sink, w, accounts, cohorts, ids, seed, scale):
    """Accounts born inside the window: a marketing burst, organic signups, the farm."""
    rng = rng_for(seed, "newaccounts")
    n0 = len(accounts)
    created = []

    def spawn(label, country=None):
        i = len(accounts)
        r = rng_for(seed, "acct", i)
        country = country or weighted(r, POPULATED)
        tz, lang, _, _ = COUNTRIES[country]
        blocks = w.residential[country]
        hb = blocks[r.randrange(len(blocks))]
        fam = weighted(r, DESKTOP_FAMILIES + MOBILE_FAMILIES)
        a = Account(idx=i, account_id=f"acc_{i + 1:06d}", email_domain=weighted(r, EMAIL_DOMAINS), country=country, city=hb.city, tz_offset=int(tz * 60),
                    accept_language=lang, created_ms=0, home_block=hb, home_host=r.randrange(254), v6_block=None, devices=[make_device(ids, fam)],
                    hour_center=12 + 8 * r.random(), hour_sd=3.0, rate_per_day=lognormal(r, 0.06, 0.6), order_rate=lognormal(r, 0.3, 0.8),
                    order_median=lognormal(r, 40, 0.6), remember_me=r.random() < 0.7, mfa="none", passkey=False, oauth=[], mobile_share=1.0 if fam in dict(MOBILE_FAMILIES) else 0.0)
        a.traits["carrier"] = r.randrange(2)
        a.cohorts.append(label)
        accounts.append(a)
        created.append(a)
        return a

    cohorts["marketing_burst"] = []
    for _ in range(max(1, round(600 * scale))):
        a = spawn("marketing_burst")
        a.traits["signup_channel"] = "promo_email"
        r = rng_for(seed, "mkt", a.idx)
        ms, ctx = lifecycle_for_new(sink, w, a, ids, r, 12)
        ms = browse(sink, a, ms + 20 * SECOND, ctx, r)
        if r.random() < 0.3:
            sink.emit(a, ms + 30 * SECOND, "gift_card_redeemed", ctx, details={"code_prefix": "WELCOME", "amount": 10.0})
        cohorts["marketing_burst"].append(a)
        baseline_after(sink, w, a, ids, seed, 13)
    cohorts["organic_signup"] = []
    for _ in range(max(1, round(400 * scale))):
        a = spawn("organic_signup")
        r = rng_for(seed, "org", a.idx)
        d = r.randrange(DAYS - 2)
        ms, ctx = lifecycle_for_new(sink, w, a, ids, r, d)
        browse(sink, a, ms + 20 * SECOND, ctx, r)
        cohorts["organic_signup"].append(a)
        baseline_after(sink, w, a, ids, seed, d + 1)
    # the fake-account farm: clusters of 12-40 accounts on shared fingerprints, promo abuse, no history
    cohorts["fake_account_farm"] = []
    n_farm = max(12, round(250 * scale))
    cluster = 0
    made = 0
    while made < n_farm:
        size = min(n_farm - made, 12 + rng.randrange(29))
        country = weighted(rng, POPULATED)
        fam = weighted(rng, DESKTOP_FAMILIES)
        shared_fp = ids.new("farmfp")
        start_day = 20 + rng.randrange(21)
        for k in range(size):
            a = spawn("fake_account_farm", country)
            a.traits["signup_channel"] = "organic"
            r = rng_for(seed, "farm", a.idx)
            dev = Device(ids.new("farmdev"), shared_fp if r.random() < 0.8 else ids.new("farmfp2"), fam)
            a.devices = [dev]
            d = min(DAYS - 3, start_day + rng.randrange(3))
            ms, ctx = lifecycle_for_new(sink, w, a, ids, r, d, disposable=True, block=w.residential[country][(cluster * 7 + k // 6) % len(w.residential[country])], device=dev)
            ms += 40 * SECOND + r.randrange(3 * MINUTE)
            sink.emit(a, ms, "gift_card_redeemed", ctx, details={"code_prefix": "WELCOME", "amount": 10.0})
            sink.emit(a, ms + 30 * SECOND, "address_added", ctx, details={"country": country})
            sink.emit(a, ms + 70 * SECOND, "order_placed", ctx, details={"amount": round(9.0 + r.random() * 3, 2), "currency": "USD", "ship_to_new_address": True, "ship_country": country})
            if r.random() < 0.3:
                ms2 = ms + DAY * (1 + r.randrange(5))
                c2 = Ctx(ctx.ip, ctx.asn, ctx.asn_type, ctx.country, ctx.city, dev, a.tz_offset, a.accept_language, ids.new("sess"))
                sink.emit(a, ms2, "login_success", c2, auth="password")
                sink.emit(a, ms2 + 20 * SECOND, "orders_viewed", c2)
            cohorts["fake_account_farm"].append(a)
            made += 1
        cluster += 1
    return created


def baseline_after(sink, w, acct, ids, seed, from_day):
    """Light baseline for accounts created inside the window."""
    rng = rng_for(seed, "baseline", acct.idx)
    for day in range(from_day, DAYS):
        if rng.random() < acct.rate_per_day:
            start = local_hour_to_ms(rng, day, acct)
            ctx = ctx_from(w, acct, pick_device(acct, rng), start, rng, ids=ids)
            session(sink, acct, start, ctx, rng, w, max_actions=3)
            acct.sessions.append((start, ctx))
            if 0 <= day < 25:
                acct.n_events_pre += 2


# ----------------------------------------------------------------------------
# The campaigns
# ----------------------------------------------------------------------------

class Key:
    """Ground truth, keyed by account. Filled by the injectors, written at the end."""

    def __init__(self):
        self.victims = {}        # account_id -> dict
        self.bonus = {}
        self.b1_devices = set()  # the phishing kit's rotating device ids, for --check

    def add(self, acct, campaign, tier, first_seq, level, bonus=False):
        acct.campaign = campaign
        rec = {"account_id": acct.account_id, "campaign": campaign, "tier": tier, "first_compromise_seq": first_seq, "level": level, "recovery_seq": None}
        (self.bonus if bonus else self.victims)[acct.account_id] = rec
        return rec


def actx(ids, block, host, device, tz, lang, ua=None, ja4=None, fp=None, client=None, session_id=None, ip=None):
    return Ctx(ip or block.ip(host), block.asn, block.kind, block.country, block.city, device, tz, lang, session_id or ids.new("sess"), ua=ua, ja4=ja4, fp_hash=fp, client=client)


def attacker_mfa_relay(sink, acct, ms, ctx, rng):
    """A phishing kit or SIM swap passes the victim's MFA; the log shows a success."""
    if acct.mfa == "none":
        return ms
    ms += 15 * SECOND + rng.randrange(60 * SECOND)
    sink.emit(acct, ms, "mfa_challenge_success", ctx, mfa=acct.mfa)
    return ms


def persist(sink, acct, ms, ctx, rng, after_password_change=True):
    """Keep the account: kick the owner out, add a credential of your own."""
    if after_password_change:
        ms += 1 * MINUTE + rng.randrange(4 * MINUTE)
        sink.emit(acct, ms, "sessions_revoked_all", ctx)
    r = rng.random()
    ms += 20 * SECOND + rng.randrange(2 * MINUTE)
    if r < 0.4:
        sink.emit(acct, ms, "passkey_added", ctx, details={"authenticator": "cross-platform"})
    elif r < 0.7:
        sink.emit(acct, ms, "api_token_created", ctx, details={"scope": "orders:write"})
    else:
        sink.emit(acct, ms, "mfa_backup_codes_regenerated", ctx)
    return ms


def monetize(sink, acct, ms, ctx, rng, ship_country, big=False):
    r = rng.random()
    ms += 1 * MINUTE + rng.randrange(6 * MINUTE)
    if r < 0.45:
        sink.emit(acct, ms, "gift_card_purchased", ctx, details={"amount": float(weighted(rng, [(100, 3), (200, 4), (500, 2)])), "currency": "USD", "recipient_domain": "fast.example"})
    else:
        sink.emit(acct, ms, "address_added", ctx, details={"country": ship_country})
        ms += 30 * SECOND + rng.randrange(2 * MINUTE)
        amount = round(lognormal(rng, acct.order_median * (3.0 if big else 1.6), 0.4), 2)
        sink.emit(acct, ms, "order_placed", ctx, details={"amount": amount, "currency": "USD", "ship_to_new_address": True, "ship_country": ship_country})
    return ms


def recovery(sink, w, acct, ms, ids, rng, rec):
    """Weeks later the owner notices. The ticket is the realistic source of labels."""
    gap = int(lognormal(rng, 2 * DAY, 1.1))
    gap = max(3 * HOUR, min(gap, 12 * DAY))
    ms += gap
    if ms >= END_MS - HOUR:
        return
    dev = acct.known_devices[0]
    ctx = ctx_from(w, acct, dev, ms, rng, ids=ids)
    ticket = ids.new("tkt", 8)
    seq = sink.emit(acct, ms, "support_ticket_opened", ctx, details={"ticket_id": ticket, "channel": "phone", "reason": "account_hacked"})
    rec["recovery_seq"] = seq
    ms += 2 * MINUTE + rng.randrange(10 * MINUTE)
    sink.emit(acct, ms, "account_locked", ctx, actor="system", details={"reason": "support_hold", "ticket_id": ticket})
    ms += 10 * MINUTE + rng.randrange(50 * MINUTE)
    agent = SUPPORT_AGENTS[rng.randrange(len(SUPPORT_AGENTS))]
    sink.emit(acct, ms, "support_reset_issued", ctx, actor="support", details={"ticket_id": ticket, "agent_id": agent, "identity_check": "passed"})
    ms += 1 * MINUTE + rng.randrange(10 * MINUTE)
    sink.emit(acct, ms, "account_unlocked", ctx, actor="support", details={"ticket_id": ticket, "agent_id": agent})
    sink.emit(acct, ms + 30 * SECOND, "password_reset_completed", ctx)
    ms += 60 * SECOND
    sink.emit(acct, ms, "login_success", ctx, auth="password")
    sink.emit(acct, ms + 20 * SECOND, "sessions_revoked_all", ctx)
    if acct.mfa == "none":
        sink.emit(acct, ms + 90 * SECOND, "mfa_enabled", ctx, mfa="totp", details={"reason": "after_incident"})
    acct.alerts = True
    sink.emit(acct, ms + 120 * SECOND, "notification_settings_changed", ctx, details={"alerts_enabled": True, "marketing_enabled": False})


def pick_victims(rng, pool, n, pred):
    cands = sorted([a for a in pool if a.campaign is None and pred(a)], key=lambda a: a.idx)
    out = []
    for _ in range(min(n, len(cands))):
        out.append(cands.pop(rng.randrange(len(cands))))
    return out


def n_scaled(n, scale):
    return max(2, round(n * scale))


def inject_A1(sink, w, accounts, cohorts, ids, seed, key, scale):
    """Datacenter credential stuffing: loud failures, a few hits, immediate lockout of the owner."""
    rng = rng_for(seed, "camp", "A1")
    infra = w.hosting + w.datacenter[:6]
    ips = [(b, h) for b in infra for h in range(5, 45)]
    tool_dev = Device(ids.new("a1dev"), None, "chrome_win")        # no JS ran: no fingerprint collected
    targets = cohorts["stuffing_target"]
    victims = pick_victims(rng, targets, n_scaled(14, scale), lambda a: a.mfa == "none" and a.n_events_pre >= 3 and "geo_glitch" not in a.cohorts)
    vset = set(a.account_id for a in victims)
    for a in targets:
        r = rng_for(seed, "a1", a.idx)
        n_fail = 1 + r.randrange(3)
        base = day_ms(28) + r.randrange(3 * DAY)
        ms = base
        for _ in range(n_fail):
            b, h = ips[r.randrange(len(ips))]
            ctx = actx(ids, b, h, tool_dev, 0, "en-US", ua=FAMILIES["chrome_win"][1], ja4=JA4_PYTHON, client="web")
            sink.emit(a, ms, "login_failure", ctx, outcome="failure", auth="password", details={"reason": "bad_password"})
            ms += 10 * MINUTE + r.randrange(6 * HOUR)
        if a.account_id in vset:
            b, h = ips[r.randrange(len(ips))]
            ctx = actx(ids, b, h, tool_dev, 0, "en-US", ua=FAMILIES["chrome_win"][1], ja4=JA4_PYTHON, client="web")
            seq = sink.emit(a, ms, "login_success", ctx, auth="password")
            level = "access_only" if r.random() < 0.4 else ("persisted" if r.random() < 0.5 else "monetized")
            rec = key.add(a, "A1_datacenter_stuffing", "A", seq, level)
            # the operator comes back in a real browser to work the account
            bdev = Device(ids.new("a1b"), ids.new("a1bfp"), "chrome_win")
            b2, h2 = ips[r.randrange(len(ips))]
            ms2 = ms + 3 * MINUTE + r.randrange(40 * MINUTE)
            c2 = actx(ids, b2, h2, bdev, 60, "en-US", client="web")
            sink.emit(a, ms2, "login_success", c2, auth="password")
            sink.emit(a, ms2 + 25 * SECOND, "orders_viewed", c2)
            sink.emit(a, ms2 + 50 * SECOND, "payment_methods_viewed", c2)
            if level != "access_only":
                ms3 = ms2 + 2 * MINUTE + r.randrange(5 * MINUTE)
                sink.emit(a, ms3, "password_change", c2, details={"reason": "user_initiated"})
                sink.emit(a, ms3 + 40 * SECOND, "email_change_requested", c2, details={"old_domain": a.email_domain, "new_domain": "fast.example"})
                sink.emit(a, ms3 + 90 * SECOND, "email_change_confirmed", c2, details={"old_domain": a.email_domain, "new_domain": "fast.example"})
                sink.emit(a, ms3 + 120 * SECOND, "notification_settings_changed", c2, details={"alerts_enabled": False, "marketing_enabled": False})
                a.alerts = False
                if r.random() < 0.5:
                    ms3 = persist(sink, a, ms3, c2, r)
                if level == "monetized":
                    ms3 = monetize(sink, a, ms3, c2, r, "US")
                ms2 = ms3
            if r.random() < 0.35:
                recovery(sink, w, a, ms2, ids, r, rec)
        elif r.random() < 0.05:
            # a real owner mistyping once that same week, then logging in: not a takeover
            ms4 = base + DAY + r.randrange(3 * DAY)
            ctx = ctx_from(w, a, pick_device(a, r), ms4, r, ids=ids)
            sink.emit(a, ms4, "login_failure", ctx, outcome="failure", auth="password", details={"reason": "bad_password"})
            session(sink, a, ms4 + 25 * SECOND, ctx, r, w, max_actions=2)
    # password spraying on day 44: one attempt per account, one IP per request
    spray_ips = [(b, h) for b in w.datacenter[6:18] for h in range(2, 250)]
    for a in cohorts["spray_target"]:
        r = rng_for(seed, "spray", a.idx)
        b, h = spray_ips[r.randrange(len(spray_ips))]
        ctx = actx(ids, b, h, tool_dev, 0, "en-US", ua=FAMILIES["chrome_win"][1], ja4=JA4_PYTHON, client="web")
        sink.emit(a, day_ms(44) + r.randrange(DAY), "login_failure", ctx, outcome="failure", auth="password", details={"reason": "bad_password"})
    # the store's own response: forced resets for stuffed accounts the next morning
    svc = Ctx("10.0.4.22", 0, "internal", "US", "New York", Device("svc-credential-policy", "svc-credential-policy", "chrome_win"), 0, "en-US", "svc-batch-2026-11-01", ua="PolicyEngine/1.9", ja4=None, client="api")
    for a in cohorts["forced_reset"]:
        r = rng_for(seed, "forced", a.idx)
        ms = day_ms(31) + 9 * HOUR + r.randrange(HOUR)
        sink.emit(a, ms, "password_reset_requested", svc, actor="system", details={"reason": "compromised_credential_policy", "channel": "email"})
        if r.random() < 0.7 and a.campaign is None:
            ms2 = ms + 2 * HOUR + r.randrange(4 * DAY)
            ctx = ctx_from(w, a, pick_device(a, r), ms2, r, ids=ids)
            sink.emit(a, ms2, "password_reset_completed", ctx)
            session(sink, a, ms2 + 10 * SECOND, ctx, r, w, max_actions=2)
    return victims


def inject_A2(sink, w, accounts, cohorts, ids, seed, key, scale):
    """Reset abuse: a SIM swap for SMS users, push bombing for push users."""
    rng = rng_for(seed, "camp", "A2")
    pool = [a for a in accounts if a.cohorts != ["qa_robot"] and "fake_account_farm" not in a.cohorts]
    sms = pick_victims(rng, pool, n_scaled(3, scale), lambda a: a.mfa == "sms" and a.n_events_pre >= 3)
    push = pick_victims(rng, pool, n_scaled(3, scale), lambda a: a.mfa == "push" and a.n_events_pre >= 3)
    for a in sms + push:
        r = rng_for(seed, "a2", a.idx)
        far = weighted(r, [(c, wt) for c, wt in POPULATED if c != a.country])
        b = w.mobile[far][r.randrange(2)]
        dev = Device(ids.new("a2dev"), ids.new("a2fp"), "chrome_android")
        ctx = actx(ids, b, r.randrange(254), dev, int(COUNTRIES[far][0] * 60), COUNTRIES[far][1], client="web")
        ms = day_ms(30 + r.randrange(50)) + r.randrange(DAY)
        if a.mfa == "sms":
            seq = sink.emit(a, ms, "password_reset_requested", ctx, details={"channel": "sms"})
            ms += 40 * SECOND + r.randrange(3 * MINUTE)
            sink.emit(a, ms, "mfa_challenge_success", ctx, mfa="sms")
            ms += 20 * SECOND
            sink.emit(a, ms, "password_reset_completed", ctx)
            ms += 15 * SECOND
            sink.emit(a, ms, "login_success", ctx, auth="password", mfa="sms")
        else:
            seq = None
            n = 6 + r.randrange(15)
            for i in range(n):
                s = sink.emit(a, ms, "mfa_challenge_failure", ctx, outcome="failure", mfa="push", details={"reason": "push_timeout" if r.random() < 0.7 else "push_denied"})
                seq = seq or s
                ms += 20 * SECOND + r.randrange(40 * SECOND)
            sink.emit(a, ms, "mfa_challenge_success", ctx, mfa="push")
            ms += 10 * SECOND
            sink.emit(a, ms, "login_success", ctx, auth="password", mfa="push")
        rec = key.add(a, "A2_reset_abuse", "A", seq, "persisted")
        ms += 1 * MINUTE + r.randrange(3 * MINUTE)
        sink.emit(a, ms, "recovery_email_change", ctx, details={"new_domain": "fast.example"})
        ms += 30 * SECOND
        sink.emit(a, ms, "mfa_disabled", ctx, mfa=a.mfa, details={"reason": "user_initiated"})
        ms += 40 * SECOND
        sink.emit(a, ms, "mfa_enabled", ctx, mfa="sms", details={"phone_country": far})
        ms += 30 * SECOND
        sink.emit(a, ms, "password_change", ctx, details={"reason": "user_initiated"})
        ms = persist(sink, a, ms, ctx, r)
        if r.random() < 0.7:
            rec["level"] = "monetized"
            ms = monetize(sink, a, ms, ctx, r, far)
        if r.random() < 0.35:
            recovery(sink, w, a, ms, ids, r, rec)
    return sms + push


def inject_A3(sink, w, accounts, cohorts, ids, seed, key, scale, b1_ja4_dev):
    """Impossible travel: the owner at home, then the account on another continent within the hour."""
    rng = rng_for(seed, "camp", "A3")
    pool = [a for a in accounts if a.cohorts != ["qa_robot"] and "fake_account_farm" not in a.cohorts and "vpn_always_on" not in a.cohorts and "traveller" not in a.cohorts]
    victims = pick_victims(rng, pool, n_scaled(5, scale), lambda a: a.mfa == "none" and a.n_events_pre >= 3 and "geo_glitch" not in a.cohorts)
    victims += pick_victims(rng, pool, 1, lambda a: "geo_glitch" in a.cohorts and a.mfa == "none" and a.n_events_pre >= 3)
    far_of = {"US": "DE", "CA": "IN", "MX": "NL", "BR": "JP", "GB": "AU", "DE": "US", "FR": "BR", "ES": "JP", "NL": "US", "IN": "US", "JP": "US", "AU": "GB"}
    for i, a in enumerate(victims):
        r = rng_for(seed, "a3", a.idx)
        day = 51 if "geo_glitch" in a.cohorts else 30 + r.randrange(55)
        ms = local_hour_to_ms(r, day, a)
        home = ctx_from(w, a, pick_device(a, r), ms, r, ids=ids)
        end = session(sink, a, ms, home, r, w, max_actions=2)
        far = far_of[a.country]
        pool_blocks = w.residential[far] if r.random() < 0.5 else w.datacenter
        b = pool_blocks[r.randrange(len(pool_blocks))]
        if i < 3 and b1_ja4_dev is not None:
            dev = Device(ids.new("a3dev"), b1_ja4_dev.fp_hash, "chromium_linux")     # the same operator as the phishing kit
        else:
            dev = Device(ids.new("a3dev"), ids.new("a3fp"), weighted(r, [("chrome_win", 5), ("firefox_win", 2), ("chrome_mac", 2)]))
        ctx = actx(ids, b, r.randrange(254), dev, int(COUNTRIES[b.country][0] * 60), COUNTRIES[far][1], client="web")
        ms = end + 20 * MINUTE + r.randrange(30 * MINUTE)
        seq = sink.emit(a, ms, "login_success", ctx, auth="password")
        rec = key.add(a, "A3_impossible_travel", "A", seq, "persisted")
        ms += 1 * MINUTE + r.randrange(3 * MINUTE)
        sink.emit(a, ms, "password_change", ctx, details={"reason": "user_initiated"})
        ms += 45 * SECOND
        sink.emit(a, ms, "email_change_requested", ctx, details={"old_domain": a.email_domain, "new_domain": "fast.example"})
        sink.emit(a, ms + 60 * SECOND, "email_change_confirmed", ctx, details={"old_domain": a.email_domain, "new_domain": "fast.example"})
        ms += 90 * SECOND
        sink.emit(a, ms, "notification_settings_changed", ctx, details={"alerts_enabled": False, "marketing_enabled": False})
        if r.random() < 0.5:
            ms = persist(sink, a, ms, ctx, r)
        if r.random() < 0.6:
            rec["level"] = "monetized"
            ms = monetize(sink, a, ms, ctx, r, far)
        if r.random() < 0.35:
            recovery(sink, w, a, ms, ids, r, rec)
    return victims


def inject_B1(sink, w, accounts, cohorts, ids, seed, key, scale):
    """Phishing kit: correct credentials, relayed MFA, residential proxies in the victim's
    country, only medium-risk actions, and identifiers that rotate so no single key has
    more than household-level degree. Three operators, one stack."""
    rng = rng_for(seed, "camp", "B1")
    pool = [a for a in accounts if a.cohorts != ["qa_robot"] and "fake_account_farm" not in a.cohorts]
    victims = pick_victims(rng, pool, n_scaled(20, scale), lambda a: a.n_events_pre >= 3 and a.mfa in ("none", "sms", "totp") and not a.passkey)
    n_ops = 3 if len(victims) >= 9 else 1
    ops = []
    for k in range(n_ops):
        base_fp = ids.new("b1fp")
        ops.append({"fps": [base_fp], "fp": base_fp, "dev": ids.new("b1dev"), "dev_uses": 0, "dev_limit": 4 + rng.randrange(3)})
    first_dev = None
    for i, a in enumerate(victims):
        op = ops[i % n_ops]
        r = rng_for(seed, "b1", a.idx)
        n_sessions = 1 + r.randrange(3)
        day = 35 + r.randrange(40)
        rec = None
        ms = 0
        for s in range(n_sessions):
            if op["dev_uses"] >= op["dev_limit"]:
                op["dev"], op["dev_uses"], op["dev_limit"] = ids.new("b1dev"), 0, 4 + r.randrange(3)
            if r.random() < 1 / 3:
                op["fp"] = ids.new("b1fp")
                op["fps"].append(op["fp"])
            dev = Device(op["dev"], op["fp"], "chromium_linux")
            key.b1_devices.add(dev.device_id)
            if first_dev is None:
                first_dev = dev
            blocks = w.residential[a.country]
            b = blocks[r.randrange(len(blocks))]
            ctx = actx(ids, b, r.randrange(254), dev, a.tz_offset + weighted(r, [(0, 5), (60, 3), (-60, 2)]), a.accept_language, client="web")
            ms = local_hour_to_ms(r, day, a, center=(a.hour_center + 3) % 24, sd=4)
            ms0 = attacker_mfa_relay(sink, a, ms, ctx, r)
            seq = sink.emit(a, ms0, "login_success", ctx, auth="password", mfa=a.mfa if a.mfa != "none" else None)
            ms = ms0
            if rec is None:
                rec = key.add(a, "B1_phishing_kit", "B", seq, "access_only")
            ms += 20 * SECOND + r.randrange(MINUTE)
            sink.emit(a, ms, "orders_viewed", ctx)
            ms += 15 * SECOND + r.randrange(MINUTE)
            sink.emit(a, ms, "payment_methods_viewed", ctx)
            if s == n_sessions - 1 or r.random() < 0.5:
                ms += 40 * SECOND + r.randrange(3 * MINUTE)
                sink.emit(a, ms, "address_added", ctx, details={"country": a.country})
                if r.random() < 0.3:
                    ms += 30 * SECOND
                    sink.emit(a, ms, "payment_method_added", ctx, details={"kind": "card"})
                ms += 30 * SECOND + r.randrange(2 * MINUTE)
                sink.emit(a, ms, "order_placed", ctx, details={"amount": round(lognormal(r, a.order_median * 1.6, 0.4), 2), "currency": "USD", "ship_to_new_address": True, "ship_country": a.country})
                rec["level"] = "monetized"
            op["dev_uses"] += 1
            day += 1 + r.randrange(6)
            if day >= DAYS - 1:
                break
        if r.random() < 0.35:
            recovery(sink, w, a, ms, ids, r, rec)
    return victims, first_dev


def inject_B2(sink, w, accounts, cohorts, ids, seed, key, scale):
    """Session-cookie replay from an infostealer log: no password event at all."""
    rng = rng_for(seed, "camp", "B2")
    pool = [a for a in accounts if a.remember_me and a.last_session_id and a.cohorts != ["qa_robot"] and "fake_account_farm" not in a.cohorts]
    victims = pick_victims(rng, pool, n_scaled(10, scale), lambda a: a.n_events_pre >= 3 and a.sessions)
    buyer = Device(ids.new("b2dev"), ids.new("b2fp"), "chrome_legacy")
    exits = w.vpn + w.datacenter[18:24]
    for a in victims:
        r = rng_for(seed, "b2", a.idx)
        # the stolen cookie came from the owner's most recent desktop session before day 40
        sessions = [s for s in a.sessions if s[0] < day_ms(40)] or a.sessions
        stolen_ms, stolen_ctx = sessions[-1]
        b = exits[r.randrange(len(exits))]
        ip = vpn_ip(w, r, b) if b.kind == "vpn" else b.ip(r.randrange(254))
        rotated = r.random() < 0.5
        sid = ids.new("sess") if rotated else stolen_ctx.session_id
        ctx = Ctx(ip, b.asn, b.kind, b.country, b.city, buyer, stolen_ctx.tz_offset, stolen_ctx.accept_language, sid, ua=stolen_ctx.ua or stolen_ctx.device.ua, client="web")
        ms = max(stolen_ms + 6 * HOUR, day_ms(40)) + r.randrange(20 * DAY)
        details = {"parent_session_hash": hashlib.sha256(stolen_ctx.session_id.encode()).hexdigest()[:12]} if rotated else {}
        seq = sink.emit(a, ms, "login_success", ctx, auth="session_resume", details=details)
        rec = key.add(a, "B2_session_replay", "B", seq, "access_only")
        ms += 30 * SECOND + r.randrange(2 * MINUTE)
        sink.emit(a, ms, "payment_methods_viewed", ctx)
        ms += 20 * SECOND + r.randrange(MINUTE)
        sink.emit(a, ms, "orders_viewed", ctx)
        if r.random() < 0.7:
            rec["level"] = "monetized"
            ms = monetize(sink, a, ms, ctx, r, b.country)
        if r.random() < 0.4:
            rec["level"] = "persisted" if rec["level"] == "access_only" else rec["level"]
            ms = persist(sink, a, ms, ctx, r, after_password_change=False)
        if r.random() < 0.35:
            recovery(sink, w, a, ms, ids, r, rec)
    return victims


def inject_B3(sink, w, accounts, cohorts, ids, seed, key, scale):
    """OAuth link hijack: the attacker's provider identity gets linked, then signs in with it."""
    rng = rng_for(seed, "camp", "B3")
    pool = [a for a in accounts if a.cohorts != ["qa_robot"] and "fake_account_farm" not in a.cohorts and "duplicate_owner" not in a.cohorts]
    victims = pick_victims(rng, pool, n_scaled(8, scale), lambda a: a.mfa == "none" and a.n_events_pre >= 3)
    identities = []
    for k in range(max(1, len(victims) // 2)):
        identities.append((weighted(rng, [("google", 6), ("apple", 4)]), ids.new("b3sub"), Device(ids.new("b3dev"), ids.new("b3fp"), "chrome_win")))
    for i, a in enumerate(victims):
        prov, sub, dev = identities[i // 2 % len(identities)]
        r = rng_for(seed, "b3", a.idx)
        b = w.datacenter[r.randrange(len(w.datacenter))] if r.random() < 0.5 else w.vpn[r.randrange(len(w.vpn))]
        ip = vpn_ip(w, r, b) if b.kind == "vpn" else b.ip(r.randrange(254))
        ctx = Ctx(ip, b.asn, b.kind, b.country, b.city, dev, int(COUNTRIES[b.country][0] * 60), "en-US", ids.new("sess"), client="web")
        ms = day_ms(32 + r.randrange(40)) + r.randrange(DAY)
        seq = sink.emit(a, ms, "login_success", ctx, auth="password")
        rec = key.add(a, "B3_oauth_hijack", "B", seq, "persisted")
        ms += 40 * SECOND + r.randrange(2 * MINUTE)
        sink.emit(a, ms, "third_party_linked", ctx, details={"provider": prov, "provider_sub_hash": sub})
        # days later: sign in through the provider, as if the password had been changed
        ms2 = ms + DAY * (2 + r.randrange(8)) + r.randrange(DAY)
        ctx2 = Ctx(ip, b.asn, b.kind, b.country, b.city, dev, ctx.tz_offset, "en-US", ids.new("sess"), client="web")
        sink.emit(a, ms2, "login_success", ctx2, auth=f"oauth:{prov}", details={"provider": prov, "provider_sub_hash": sub})
        ms2 += 30 * SECOND + r.randrange(MINUTE)
        sink.emit(a, ms2, "payment_methods_viewed", ctx2)
        if r.random() < 0.75:
            rec["level"] = "monetized"
            ms2 = monetize(sink, a, ms2, ctx2, r, b.country)
        if r.random() < 0.35:
            recovery(sink, w, a, ms2, ids, r, rec)
    return victims


def inject_B4(sink, w, accounts, cohorts, ids, seed, key, scale):
    """Social-engineered (or complicit) support agents: the reset is issued, the attacker completes it."""
    rng = rng_for(seed, "camp", "B4")
    pool = [a for a in accounts if a.cohorts != ["qa_robot"] and "fake_account_farm" not in a.cohorts and "support_recovery" not in a.cohorts]
    victims = pick_victims(rng, pool, n_scaled(8, scale), lambda a: a.n_events_pre >= 3)
    ring_dev = Device(ids.new("b4dev"), ids.new("b4fp"), "chrome_mac")
    for a in victims:
        r = rng_for(seed, "b4", a.idx)
        agent = RING_AGENTS[r.randrange(len(RING_AGENTS))]
        blocks = w.residential[a.country]
        b = blocks[r.randrange(len(blocks))]
        ctx = actx(ids, b, r.randrange(254), ring_dev, a.tz_offset, a.accept_language, client="web")
        ms = day_ms(34 + r.randrange(45)) + 9 * HOUR + r.randrange(9 * HOUR)
        ticket = ids.new("tkt", 8)
        seq = sink.emit(a, ms, "support_ticket_opened", ctx, details={"ticket_id": ticket, "channel": "chat", "reason": "lost_device"})
        rec = key.add(a, "B4_support_ring", "B", seq, "persisted")
        ms += 4 * MINUTE + r.randrange(25 * MINUTE)
        sink.emit(a, ms, "support_reset_issued", ctx, actor="support", details={"ticket_id": ticket, "agent_id": agent, "identity_check": "passed"})
        if a.mfa != "none":
            ms += 30 * SECOND
            sink.emit(a, ms, "mfa_disabled", ctx, actor="support", mfa=a.mfa, details={"reason": "support_recovery", "ticket_id": ticket, "agent_id": agent})
        ms += 2 * MINUTE + r.randrange(10 * MINUTE)
        sink.emit(a, ms, "password_reset_completed", ctx)
        ms += 20 * SECOND
        sink.emit(a, ms, "login_success", ctx, auth="password")
        ms += 1 * MINUTE + r.randrange(3 * MINUTE)
        sink.emit(a, ms, "payment_methods_viewed", ctx)
        ms += 30 * SECOND + r.randrange(2 * MINUTE)
        # the ring keeps the owner's email: the reset itself is the persistence
        if r.random() < 0.5:
            ms = persist(sink, a, ms, ctx, r, after_password_change=False)
        if r.random() < 0.7:
            rec["level"] = "monetized"
            ms = monetize(sink, a, ms, ctx, r, a.country, big=True)
        if r.random() < 0.35:
            recovery(sink, w, a, ms, ids, r, rec)
    return victims


LANG_VARIANT = {"en-US": "en-GB", "en-GB": "en-US", "de-DE": "de-AT", "fr-FR": "fr-CA", "es-ES": "es-MX", "es-MX": "es-ES", "nl-NL": "nl-BE",
                "pt-BR": "pt-PT", "en-IN": "en-GB", "ja-JP": "en-US", "en-AU": "en-GB", "en-CA": "en-US"}


def inject_C1(sink, w, accounts, cohorts, ids, seed, key, scale):
    """Low and slow, by hand: one operator per victim, nothing shared, only weak deviations."""
    rng = rng_for(seed, "camp", "C1")
    pool = [a for a in accounts if a.cohorts != ["qa_robot"] and "fake_account_farm" not in a.cohorts and "vpn_always_on" not in a.cohorts and "privacy_browser" not in a.cohorts]
    active = pick_victims(rng, pool, n_scaled(13, scale), lambda a: a.mfa == "none" and a.n_events_pre >= 15 and "dormant_returner" not in a.cohorts)
    dormant = pick_victims(rng, pool, n_scaled(5, scale), lambda a: a.mfa == "none" and "dormant_returner" in a.cohorts)
    for a in active + dormant:
        r = rng_for(seed, "c1", a.idx)
        fam = weighted(r, [("chrome_win", 5), ("safari_ios", 2), ("chrome_android", 2), ("chrome_mac", 1)])
        dev = Device(ids.new("c1dev"), ids.new("c1fp"), fam)
        blocks = [b for b in w.residential[a.country] if b.city == a.city] or w.residential[a.country]
        b = blocks[r.randrange(len(blocks))]
        host = r.randrange(254)
        tz = a.tz_offset + weighted(r, [(60, 3), (120, 3), (180, 2), (-60, 2)])
        lang = LANG_VARIANT.get(a.accept_language, a.accept_language)
        hour = (a.hour_center + 6 + r.random() * 3) % 24
        if "dormant_returner" in a.cohorts:
            day0 = max(26, a.traits["dormant_until"] - 10 - r.randrange(10))
        else:
            day0 = 30 + r.randrange(40)
        n_sessions = 2 + r.randrange(3)
        day = day0
        rec = None
        alerts_off_day = day0 + 1 + r.randrange(4) if r.random() < 0.4 else None
        ms = 0
        for s in range(n_sessions):
            ctx = actx(ids, b, host, dev, tz, lang, client="web")
            ms = local_hour_to_ms(r, day, a, center=hour, sd=1.0)
            seq = sink.emit(a, ms, "login_success", ctx, auth="password")
            if rec is None:
                rec = key.add(a, "C1_low_and_slow", "C", seq, "access_only")
            ms += 25 * SECOND + r.randrange(2 * MINUTE)
            sink.emit(a, ms, "orders_viewed", ctx)
            if s == 0:
                ms += 20 * SECOND + r.randrange(MINUTE)
                sink.emit(a, ms, "payment_methods_viewed", ctx)
            else:
                if alerts_off_day is not None and day >= alerts_off_day and a.alerts:
                    ms += 40 * SECOND + r.randrange(2 * MINUTE)
                    sink.emit(a, ms, "notification_settings_changed", ctx, details={"alerts_enabled": False, "marketing_enabled": True})
                    a.alerts = False
                ms += 40 * SECOND + r.randrange(3 * MINUTE)
                sink.emit(a, ms, "address_added", ctx, details={"country": a.country})
                ms += 45 * SECOND + r.randrange(2 * MINUTE)
                sink.emit(a, ms, "order_placed", ctx, details={"amount": round(lognormal(r, a.order_median * 2.5, 0.3), 2), "currency": "USD", "ship_to_new_address": True, "ship_country": a.country})
                rec["level"] = "monetized"
            gap = max(1, int(lognormal(r, 2.0, 0.7)))
            day += gap
            if day >= DAYS - 1:
                break
        if r.random() < 0.35:
            recovery(sink, w, a, ms, ids, r, rec)
    return active + dormant


def inject_D(sink, w, accounts, cohorts, ids, seed, key, scale):
    """Bonus: pre-hijack. The attacker registers with the victim's address first; the victim
    later 'recovers' an account that was never theirs, and no session is revoked."""
    rng = rng_for(seed, "camp", "D")
    victims = []
    for k in range(n_scaled(6, scale)):
        i = len(accounts)
        r = rng_for(seed, "acct", i)
        country = weighted(r, POPULATED)
        tz, lang, _, _ = COUNTRIES[country]
        hb = w.residential[country][r.randrange(len(w.residential[country]))]
        a = Account(idx=i, account_id=f"acc_{i + 1:06d}", email_domain=weighted(r, EMAIL_DOMAINS), country=country, city=hb.city, tz_offset=int(tz * 60),
                    accept_language=lang, created_ms=0, home_block=hb, home_host=r.randrange(254), v6_block=None, devices=[make_device(ids, weighted(r, DESKTOP_FAMILIES + MOBILE_FAMILIES))],
                    hour_center=19, hour_sd=2.5, rate_per_day=0.1, order_rate=0.3, order_median=45, remember_me=True, mfa="none", passkey=False, oauth=[], mobile_share=0.3)
        a.traits["carrier"] = 0
        a.traits["never_verifies"] = True
        a.cohorts.append("prehijack_bonus")
        accounts.append(a)
        att_dev = Device(ids.new("ddev"), ids.new("dfp"), "chrome_win")
        att_block = w.datacenter[r.randrange(len(w.datacenter))]
        att_ctx = actx(ids, att_block, r.randrange(254), att_dev, 60, "en-US", client="web")
        d0 = 5 + r.randrange(15)
        ms, _ = lifecycle_for_new(sink, w, a, ids, r, d0, device=att_dev, block=att_block)
        seq = sink.emit(a, ms + 5 * SECOND, "login_success", att_ctx, auth="password")
        rec = key.add(a, "D_prehijack", "D", seq, "access_only", bonus=True)
        a.traits["never_verifies"] = False
        # the real person: a reset from their own device, verification, their payment method
        d1 = d0 + 10 + r.randrange(25)
        own = a.devices[0]
        ms1 = local_hour_to_ms(r, d1, a)
        oc = ctx_from(w, a, own, ms1, r, ids=ids)
        sink.emit(a, ms1, "password_reset_requested", oc, details={"channel": "email"})
        ms1 += 2 * MINUTE + r.randrange(10 * MINUTE)
        sink.emit(a, ms1, "password_reset_completed", oc)
        sink.emit(a, ms1 + 10 * SECOND, "email_verified", oc)
        sink.emit(a, ms1 + 30 * SECOND, "login_success", oc, auth="password")
        sink.emit(a, ms1 + 2 * MINUTE, "payment_method_added", oc, details={"kind": "card"})
        a.known_devices = [own]
        # ... and the attacker's remember-me session, never revoked, is still alive
        ms2 = ms1 + DAY * (1 + r.randrange(6)) + r.randrange(DAY)
        c2 = Ctx(att_ctx.ip, att_ctx.asn, att_ctx.asn_type, att_ctx.country, att_ctx.city, att_dev, 60, "en-US", att_ctx.session_id, client="web")
        sink.emit(a, ms2, "login_success", c2, auth="session_resume")
        sink.emit(a, ms2 + 30 * SECOND, "payment_methods_viewed", c2)
        sink.emit(a, ms2 + 90 * SECOND, "order_placed", c2, details={"amount": round(60 + r.random() * 200, 2), "currency": "USD", "ship_to_new_address": True, "ship_country": att_block.country})
        rec["level"] = "monetized"
        victims.append(a)
    return victims


# ----------------------------------------------------------------------------
# Post-processing, writers, checks
# ----------------------------------------------------------------------------

def finalize(sink, seed, victim_ids):
    """Total order, stable ids, ingestion delays, then the data-quality noise."""
    rng = rng_for(seed, "noise")
    rows = [r for r in sink.rows if START_MS <= r[0] < END_MS]
    # retries: same request, new event, a few seconds later (before ids are assigned)
    extra = []
    for r in rows:
        if r[1] not in victim_ids and rng.random() < 0.003:
            row = dict(r[3])
            row["details"] = dict(row["details"])
            row["details"]["retry"] = True
            sink.seq += 1
            extra.append([r[0] + SECOND + rng.randrange(29 * SECOND), r[1], sink.seq, row, True])
    rows.extend(extra)
    # clock skew: a client whose clock runs ahead
    for r in rows:
        if r[1] not in victim_ids and rng.random() < 0.0005:
            r[0] += 5 * MINUTE + rng.randrange(10 * MINUTE)
            r[3]["details"] = dict(r[3]["details"], clock_skew=True)
    rows.sort(key=lambda r: (r[0], r[1], r[2]))
    seq_to_id = {}
    out = []
    for n, r in enumerate(rows, 1):
        eid = f"evt_{n:07d}"
        seq_to_id[r[2]] = eid
        ms = r[0]
        ing = ms + 200 + rng.randrange(2800)
        if "clock_skew" in r[3]["details"]:
            ing = ms - 5 * MINUTE - rng.randrange(10 * MINUTE)
            r[3]["details"] = {k: v for k, v in r[3]["details"].items() if k != "clock_skew"}
        elif r[1] not in victim_ids and rng.random() < 0.004:
            ing = ms + 30 * MINUTE + rng.randrange(330 * MINUTE)
        row = {"event_id": eid, "ts": iso(ms), "ingested_at": iso(ing)}
        row.update(r[3])
        out.append(row)
        if r[1] not in victim_ids and rng.random() < 0.006:
            dup = dict(row)
            dup["ingested_at"] = iso(ing + SECOND + rng.randrange(19 * SECOND))
            out.append(dup)
    return out, seq_to_id


def write_outputs(rows, seq_to_id, key, cohorts, accounts, w, seed, out_dir, csv, scale):
    os.makedirs(out_dir, exist_ok=True)
    jsonl_path = os.path.join(out_dir, "account_activity.jsonl.gz")
    h = hashlib.sha256()
    with gzip.GzipFile(jsonl_path, "wb", mtime=0) as f:
        for row in rows:
            line = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
            h.update(line)
            f.write(line)
    digest = h.hexdigest()
    if csv:
        import csv as csvmod
        cols = ["event_id", "ts", "ingested_at", "account_id", "event_type", "outcome", "actor", "client", "session_id", "ip", "asn", "asn_type", "country", "city",
                "user_agent", "device_id", "fp_hash", "ja4", "accept_language", "tz_offset", "auth_method", "mfa_method", "request_id", "details"]
        with open(os.path.join(out_dir, "account_activity.csv"), "w", newline="") as f:
            wr = csvmod.writer(f)
            wr.writerow(cols)
            for row in rows:
                wr.writerow([json.dumps(row["details"], sort_keys=True, separators=(",", ":")) if c == "details" else row.get(c) for c in cols])
    with open(os.path.join(out_dir, "world.json"), "w") as f:
        json.dump(world_json(w), f, indent=1, sort_keys=True)
    with open(os.path.join(out_dir, "sample.jsonl"), "w") as f:
        for row in rows[:2000]:
            f.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    # the answer key
    camps = {}
    for rec in key.victims.values():
        c = camps.setdefault(rec["campaign"], {"tier": rec["tier"], "accounts": []})
        c["accounts"].append({"account_id": rec["account_id"], "first_compromise_event_id": seq_to_id.get(rec["first_compromise_seq"]), "level": rec["level"],
                              "recovery_event_id": seq_to_id.get(rec["recovery_seq"]) if rec["recovery_seq"] else None})
    for c in camps.values():
        c["accounts"].sort(key=lambda x: x["account_id"])
    bonus = {}
    for rec in key.bonus.values():
        bonus.setdefault(rec["campaign"], []).append({"account_id": rec["account_id"], "first_compromise_event_id": seq_to_id.get(rec["first_compromise_seq"]), "level": rec["level"]})
    cohort_ids = {name: sorted(a.account_id for a in members) for name, members in cohorts.items()}
    answer = {
        "seed": seed, "schema_version": SCHEMA_VERSION, "scale": scale, "accounts": len(accounts), "events": len(rows), "sha256_uncompressed": digest,
        "window": {"start": iso(START_MS), "end": iso(END_MS)},
        "campaigns": dict(sorted(camps.items())),
        "bonus": bonus,
        "cohorts": cohort_ids,
        "cohort_info": COHORT_INFO,
    }
    sol_dir = os.path.join(os.path.dirname(out_dir), "solutions")
    os.makedirs(sol_dir, exist_ok=True)
    with open(os.path.join(sol_dir, "answer_key.json"), "w") as f:
        json.dump(answer, f, indent=1, sort_keys=True)
    return jsonl_path, digest, answer


COHORT_INFO = {
    "typical": {"red_herring": False, "why": "home broadband, one or two devices, nothing unusual"},
    "traveller": {"red_herring": True, "why": "new country on a known device; a quarter change their password on the trip"},
    "household": {"red_herring": True, "why": "2-4 accounts on one shared desktop for months: a legitimate graph hub"},
    "cgnat": {"red_herring": True, "why": "hundreds of accounts behind one carrier egress address"},
    "vpn_always_on": {"red_herring": True, "why": "datacenter ASN and a foreign country, every day, for months"},
    "privacy_browser": {"red_herring": True, "why": "fingerprint changes every session, cookies sometimes cleared: looks like device churn"},
    "qa_robot": {"red_herring": True, "why": "automated smoke tests from a datacenter on a shared device, every few hours"},
    "night_shift": {"red_herring": True, "why": "habitual 02:00-05:00 local logins: a login-hour anomaly that is their normal"},
    "shared_access_couple": {"red_herring": True, "why": "two people, two devices, different hours and locale on one account"},
    "geo_glitch": {"red_herring": True, "why": "the geo-IP provider mapped their block to Brazil for three days: fake impossible travel"},
    "new_phone": {"red_herring": True, "why": "new device, fingerprint and TLS stack, same network and timezone, MFA passed"},
    "relocator": {"red_herring": True, "why": "permanent move: new country, new address, new phone number, and it stays that way"},
    "pw_manager_migrant": {"red_herring": True, "why": "password change, MFA enabled and passkey added within minutes, from the known device"},
    "email_migrant": {"red_herring": True, "why": "email change with MFA step-up and verification, from the known device"},
    "forgetful": {"red_herring": True, "why": "several failures then a self-service reset, all from the known device"},
    "support_recovery": {"red_herring": True, "why": "ticket, support reset, login; 40% from a new device because the old one is gone"},
    "dormant_returner": {"red_herring": True, "why": "silent for 40-80 days, then back on the known device"},
    "gift_buyer": {"red_herring": True, "why": "December orders shipped to other people in other countries"},
    "duplicate_owner": {"red_herring": True, "why": "one person with two accounts linked to the same provider identity"},
    "bulk_mfa_reenrol": {"red_herring": True, "why": "500 mfa_disabled by a support service account in two hours: a policy migration"},
    "marketing_burst": {"red_herring": True, "why": "600 real signups in six hours after a promo email"},
    "organic_signup": {"red_herring": False, "why": "accounts created during the window"},
    "stuffing_target": {"red_herring": True, "why": "attacked and not taken over: the failures are the attacker's, the account is still the owner's"},
    "spray_target": {"red_herring": True, "why": "one failed attempt from the spraying wave; no takeover"},
    "forced_reset": {"red_herring": True, "why": "the store's own compromised-credential policy forced a reset after the wave"},
    "fake_account_farm": {"red_herring": True, "why": "abuse, but not account takeover: no real owner existed before the farm"},
    "prehijack_bonus": {"red_herring": False, "why": "bonus campaign D: unscored; the account was the attacker's before it was the victim's"},
}


def check(answer, rows, accounts, scale, key):
    """Invariants the tiering depends on. Raises on violation."""
    camps = answer["campaigns"]
    s = scale
    want = {"A1_datacenter_stuffing": n_scaled(14, s), "A2_reset_abuse": 2 * n_scaled(3, s), "A3_impossible_travel": n_scaled(5, s) + 1, "B1_phishing_kit": n_scaled(20, s),
            "B2_session_replay": n_scaled(10, s), "B3_oauth_hijack": n_scaled(8, s), "B4_support_ring": n_scaled(8, s), "C1_low_and_slow": n_scaled(13, s) + n_scaled(5, s)}
    problems = []
    for name, n in want.items():
        got = len(camps.get(name, {}).get("accounts", []))
        if got != n:
            problems.append(f"{name}: {got} victims, wanted {n}")
    victims = {a["account_id"] for c in camps.values() for a in c["accounts"]}
    first = {a["first_compromise_event_id"] for c in camps.values() for a in c["accounts"]}
    by_id = {r["event_id"]: r for r in rows}
    for eid in first:
        if eid is None or eid not in by_id:
            problems.append(f"first compromise event {eid} not in the window")
        elif by_id[eid]["ts"] < iso(day_ms(25)):
            problems.append(f"first compromise event {eid} before day 25")
    # B1: no single device_id touches more than 6 accounts
    from collections import defaultdict
    dev_acc = defaultdict(set)
    for r in rows:
        if r["account_id"] in victims and r["device_id"]:
            dev_acc[r["device_id"]].add(r["account_id"])
    for dev in sorted(key.b1_devices):
        if len(dev_acc.get(dev, ())) > 6:
            problems.append(f"B1 device {dev} touches {len(dev_acc[dev])} accounts (> 6)")
    if problems:
        raise SystemExit("CHECK FAILED:\n  " + "\n  ".join(problems))
    return True


def generate(seed=SEED, scale=1.0):
    w = build_world(seed)
    n = max(200, round(N_ACCOUNTS * scale))
    sink = Sink(seed)
    accounts, ids = make_population(seed, w, n, scale)
    cohorts = assign_cohorts(seed, w, accounts, scale)
    for a in accounts:
        baseline(sink, w, a, ids, seed)
    overlays(sink, w, accounts, cohorts, ids, seed)
    new_accounts(sink, w, accounts, cohorts, ids, seed, scale)
    key = Key()
    inject_A1(sink, w, accounts, cohorts, ids, seed, key, scale)
    inject_A2(sink, w, accounts, cohorts, ids, seed, key, scale)
    _, b1_dev = inject_B1(sink, w, accounts, cohorts, ids, seed, key, scale)
    inject_A3(sink, w, accounts, cohorts, ids, seed, key, scale, b1_dev)
    inject_B2(sink, w, accounts, cohorts, ids, seed, key, scale)
    inject_B3(sink, w, accounts, cohorts, ids, seed, key, scale)
    inject_B4(sink, w, accounts, cohorts, ids, seed, key, scale)
    inject_C1(sink, w, accounts, cohorts, ids, seed, key, scale)
    inject_D(sink, w, accounts, cohorts, ids, seed, key, scale)
    cohorts["prehijack_bonus"] = [a for a in accounts if "prehijack_bonus" in a.cohorts]
    victim_ids = set(key.victims) | set(key.bonus)
    rows, seq_to_id = finalize(sink, seed, victim_ids)
    return w, accounts, cohorts, key, rows, seq_to_id


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--scale", type=float, default=1.0, help="fraction of the 10,000 accounts (campaign sizes scale too)")
    ap.add_argument("--out-dir", default=DATA_DIR)
    ap.add_argument("--csv", action="store_true", help="also write account_activity.csv")
    ap.add_argument("--check", action="store_true", help="assert the invariants the tiering depends on")
    args = ap.parse_args()
    import time
    t0 = time.time()
    w, accounts, cohorts, key, rows, seq_to_id = generate(args.seed, args.scale)
    path, digest, answer = write_outputs(rows, seq_to_id, key, cohorts, accounts, w, args.seed, args.out_dir, args.csv, args.scale)
    print(f"wrote {len(rows)} events for {len(accounts)} accounts to {os.path.relpath(path)} (seed {args.seed}, scale {args.scale}, {time.time() - t0:.1f}s)")
    print(f"  sha256 (uncompressed): {digest}")
    print("  campaigns: " + ", ".join(f"{k} {len(v['accounts'])}" for k, v in answer["campaigns"].items()) + f"; bonus D {sum(len(v) for v in answer['bonus'].values())}")
    print("  cohorts:   " + ", ".join(f"{k} {len(v)}" for k, v in sorted(answer["cohorts"].items(), key=lambda kv: -len(kv[1]))))
    if args.check:
        check(answer, rows, accounts, args.scale, key)
        print("  check: ok")


if __name__ == "__main__":
    main()
