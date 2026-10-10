"""
Chapter 6 lab: shared settings and helpers for every script in this lab.

Everything here is lab plumbing, not defense or attack logic:

  - URLs for the demo store, the mock CAPTCHA provider and Redis
  - the ethics guardrail: every client refuses non-local targets
  - simulated time: LAB_TIME_SCALE=5 means one real second counts as five
    simulated seconds, so a 40-second farm solve takes 8 real seconds
  - simulated client IPs: the demo store trusts X-Lab-Client-IP from
    127.0.0.1 only, standing in for the edge proxy from Chapter 3
  - "eyes": look_at() lets simulated humans and the simulated solving farm
    read a CAPTCHA the way a person would. It reads a lab-only Redis key.
    Bot scripts other than the farm must never call it.
"""

import ipaddress
import os
import random
import secrets
import ssl
import sys
import time
from urllib.parse import urlparse

import httpx

BASE_URL = os.environ.get("DEMO_URL", "http://localhost:5000")
PROVIDER_URL = os.environ.get("PROVIDER_URL", "http://localhost:5001")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
TIME_SCALE = float(os.environ.get("LAB_TIME_SCALE", "5"))

# The mock provider's key pair. Site keys are public by design: they ship in
# your HTML. The secret only ever lives on your server.
SITEKEY = "lab-sitekey-0000"
SECRET = os.environ.get("CAPTCHA_SECRET", "lab-secret-0000")

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# Building an SSL context costs ~80 ms; share one across every client.
_SSL = ssl.create_default_context()

# RFC 5737 documentation ranges: never routable, so never somebody's real IP.
HUMAN_NET = ipaddress.ip_network("198.51.100.0/24")   # TEST-NET-2
BOT_NET = ipaddress.ip_network("203.0.113.0/24")      # TEST-NET-3
FARM_NET = ipaddress.ip_network("192.0.2.0/24")       # TEST-NET-1


def require_local(*urls):
    """Ethics guardrail: refuse to send lab traffic anywhere but this machine."""
    for url in urls or (BASE_URL, PROVIDER_URL):
        host = urlparse(url).hostname
        if host not in LOCAL_HOSTS:
            sys.exit(f"Refusing to run against {url}: this lab only targets "
                     f"localhost. Attack only systems you own.")


def sim_sleep(sim_seconds):
    """Sleep for a simulated duration (divided by LAB_TIME_SCALE)."""
    time.sleep(max(0.0, sim_seconds) / TIME_SCALE)


def sim_now():
    """Current time on the simulated clock (seconds)."""
    return time.time() * TIME_SCALE


def random_ip(net, rng=random):
    return str(net[rng.randrange(1, net.num_addresses - 1)])


def client(ip, ua, actor, base_url=BASE_URL):
    """An httpx client that looks like one browser on one IP.

    X-Lab-Actor (human / bot / farm) is used ONLY by tools/scoreboard.py to
    colour the solve-time histogram. The defenses never see it; reading it
    in a defense would be cheating.
    """
    require_local(base_url)
    return httpx.Client(base_url=base_url, timeout=15, follow_redirects=False, verify=_SSL,
                        headers={"User-Agent": ua, "X-Lab-Client-IP": ip,
                                 "X-Lab-Actor": actor, "Accept": "application/json"})


_provider = httpx.Client(verify=_SSL)


def mint_token(ip, action, hostname="localhost", sitekey=SITEKEY, cdata=""):
    """Ask the mock provider for a token, as its widget would after a pass.

    The mock cannot tell people from programs (no provider can, perfectly),
    so the lab models the provider's cost by a rule of engagement:
    bot scripts mint interactive tokens for *your* hostname only through
    attacks/farm.py, which charges the going rate. See README, Round 1.
    """
    require_local(PROVIDER_URL)
    r = _provider.post(f"{PROVIDER_URL}/lab/mint", timeout=5,
                   headers={"X-Lab-Client-IP": ip},
                   json={"sitekey": sitekey, "action": action,
                         "hostname": hostname, "cdata": cdata})
    r.raise_for_status()
    return r.json()["token"]


_redis = None


def redis_client():
    global _redis
    if _redis is None:
        import redis
        _redis = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    return _redis


def look_at(challenge_id):
    """LAB ONLY: what a human sees in the image. Stands in for human eyes.

    Used by tools/legit_traffic.py and attacks/farm.py (a farm is humans).
    """
    return redis_client().get(f"lab:eyes:{challenge_id}")


def typo(text, rng=random):
    """A plausible human misread: one character swapped for a lookalike."""
    lookalikes = {"B": "8", "8": "B", "S": "5", "5": "S", "Z": "2", "2": "Z",
                  "G": "6", "6": "G", "U": "V", "V": "U", "M": "N", "N": "M"}
    i = rng.randrange(len(text))
    c = text[i]
    wrong = lookalikes.get(c) or rng.choice([x for x in "ACDEFHKRTWXY" if x != c])
    return text[:i] + wrong + text[i + 1:]


def new_email(prefix, rng=random):
    return f"{prefix}-{secrets.token_hex(4)}@example.test"


def server_timing(response):
    """Parse Server-Timing into {name: ms}."""
    out = {}
    for part in response.headers.get("Server-Timing", "").split(","):
        name, _, rest = part.strip().partition(";dur=")
        if name and rest:
            try:
                out[name] = float(rest)
            except ValueError:
                pass
    return out
