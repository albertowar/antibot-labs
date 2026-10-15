"""Shared helpers and the ethics guardrail for every attack script and for the genuine crawlers in tools/personas_ch2.py.

Rules of engagement are absolute: these scripts run ONLY against the local demo store and the
local mock internet you run yourself. ``tools/labclient.py`` asks the lab-root ``labnet.py``
guard for the store URL, and that guard refuses a target that is not this machine before a
single request is sent; the mock internet's URL goes through the same guard (``mock_url()``).

Source addresses are rented from ``data/world.json`` (RFC 5737 documentation ranges) and sent in
``X-Lab-Client-IP``, which the store's edge honours only from loopback and only inside a pool:
an attacker may rent a different address, never invent one. Operators and the attacker rent from
the same pools as everyone else (``cloud_gcp``, ``cloud_vm``, ``hosting_asn``); what tells them
apart is what they can prove (reverse DNS, published ranges, a signature), not which pool they
sit in. The "hosting panel" the Round 2 and Round 4 attacks use is the mock's, and it only
accepts changes to the attacker's own synthetic zone. Nothing in this folder can touch a real
operator, a real resolver or a third party, and nothing should be adapted to.
"""

from __future__ import annotations

import json
import os
import re
import sys
from urllib.parse import urlparse

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(os.path.dirname(HERE), "tools")
sys.path.insert(0, TOOLS)
from labclient import BASE_URL, LabClient, admin, world_pool  # noqa: E402  (runs the labnet guard on import)
import labnet  # noqa: E402
import make_keys  # noqa: E402  (generates the Ed25519 fixtures on first use; nothing secret is committed)
from defenses import httpsig  # noqa: E402  (labclient put the lab root on sys.path)

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/153.0.0.0 Safari/537.36")
UA = {
    "scraper": "python-httpx/0.28.1",
    "Googlebot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/141.0.0.0 Safari/537.36",
    "bingbot": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Applebot": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko; compatible; Applebot/0.1; +http://www.apple.com/go/applebot)",
    "GPTBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.4; +https://openai.com/gptbot",
    "ClaudeBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
    "PerplexityBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
    "ChatGPT-User": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
    "Google-Read-Aloud": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36 (compatible; Google-Read-Aloud; +https://support.google.com/webmasters/answer/1061943)",
    "AcmeShoppingAgent": "Mozilla/5.0 (compatible; AcmeShoppingAgent/0.9)",
}
HTML = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
_LOC = re.compile(r"<loc>[^<]*(/product/p\d{3})</loc>")

# The attacker's rented hosting boxes (pool hosting_asn, 203.0.113.64/26): one per attack, so each
# keeps its own anonymous budget and its own PTR. The panel in tools/mock_internet.py edits only these.
ATTACKER = {"honest": 0, "ua_spoof": 1, "ptr_substring": 2, "ptr_forged": 3, "gptbot_claim": 4,
            "self_signed": 5, "replay_stale": 6, "replay_fresh": 7}
SQUAT_POOL, SQUAT_INDEX = "cloud_vm", 55         # 203.0.113.56: a tenant VM on the shared "App Engine" slice


def attacker_ip(name: str) -> str:
    return world_pool("hosting_asn")[ATTACKER[name]]


def authority() -> str:
    """The Host the store sees (and so the @authority a signature must cover). verify.py picks a free port."""
    return urlparse(BASE_URL).netloc


def mock_url() -> str:
    """The mock internet: $MOCK_URL, else where the store says it started it, else the default. Guarded."""
    url = os.environ.get("MOCK_URL")
    if not url:
        try:
            url = admin("GET", "/lab/identity").get("mock_url")
        except (requests.RequestException, ValueError):
            url = None
    return labnet.require_local((url or "http://127.0.0.1:5001").rstrip("/"), what="MOCK_URL")


def mock(method: str, path: str, **kw) -> dict:
    r = requests.request(method, mock_url() + path, timeout=10, **kw)
    r.raise_for_status()
    return r.json()


def key_of(owner: str):
    """(private key, public JWK, thumbprint) of a fixture key, generated on first use."""
    k = make_keys.load(owner)
    return httpsig.load_private(k["seed_hex"]), k["jwk"], k["thumbprint"]


def catalog_paths() -> list[str]:
    """The scraper's crawl plan: product URLs from /sitemap.xml, fetched like a browser would."""
    c = LabClient("recon:sitemap:00", ip=world_pool("home_broadband")[0])
    return list(dict.fromkeys(_LOC.findall(c.get("/sitemap.xml", headers=[("User-Agent", BROWSER_UA)]).text)))


def first_rejection(actor: str) -> str:
    """Why the gate first said no to this actor (the decision log; the response body never says)."""
    for row in admin("GET", "/lab/decisions", params={"actor": actor, "limit": 5000})["items"]:
        if row["status"] != 200:
            return "; ".join((row.get("extra") or {}).get("reasons", []))[:260]
    return ""


def scrape(name: str, ip: str, ua: str, paths: list[str], extra_headers=None) -> dict:
    """Fetch every product page as fast as the store allows; report how far we got and in which lane.

    extra_headers: callable(path) -> list of (name, value), e.g. a fresh signature per request.
    """
    actor = f"bot:{name}:00"
    c = LabClient(actor, ip=ip)
    statuses, fast = [], 0
    for path in paths:
        c.http.cookies.clear()                       # a crawler keeps no session
        hdrs = [("User-Agent", ua), ("Accept", HTML)] + (extra_headers(path) if extra_headers else [])
        r = c.get(path, headers=hdrs)
        statuses.append(r.status_code)
        fast += r.status_code == 200 and r.headers.get("X-Lane") == "verified"
    out = {"name": name, "attempted": len(paths), "succeeded": statuses.count(200), "fast_lane": fast,
           "status_429": statuses.count(429), "status_403": statuses.count(403), "first_rejection": first_rejection(actor)}
    return out


def report(title: str, s: dict) -> None:
    lane = "FAST LANE" if s["fast_lane"] >= 0.9 * s["attempted"] else ("refused (403)" if s["status_403"] > s["attempted"] // 2 else "held to the anonymous lane")
    print(f"[{title}] {s['succeeded']}/{s['attempted']} product pages, {s['fast_lane']} in the verified lane, "
          f"429s={s['status_429']} 403s={s['status_403']} -> {lane}")
    if s["first_rejection"]:
        print(f"    first rejection: {s['first_rejection']}")


def finish(result: dict) -> dict:
    """Print the one JSON line tools/checkpoint.py reads, and return it."""
    print(json.dumps(result))
    return result
