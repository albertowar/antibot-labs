"""Shared helpers and the ethics guardrail for every attack script.

Rules of engagement are absolute: attacks run **only** against the local demo
store and the local mock internet you run yourself. ``require_local_target``
refuses anything that is not loopback before a single request is sent. Every
address here is an RFC 5737 documentation address claimed in a header the store
honours only from loopback; the "hosting panel" the Round 2 and Round 4 attacks
use is the mock's, and it only accepts changes to the attacker's own synthetic
zone. Nothing in this folder can touch a real operator, a real resolver or a
third party, and nothing should be adapted to.
"""

from __future__ import annotations

import os
import sys
import time

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://127.0.0.1:5000")
MOCK_URL = target("MOCK_URL", "http://127.0.0.1:5001")
require_local_target = require_local

ATTACKER_IP = "192.0.2.77"            # a box in the attacker's hosting allocation
SQUAT_IP = "203.0.113.99"             # a tenant VM on shared cloud egress (App Engine style)
CATALOG = 200

UA_GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
UA_GPTBOT = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.3; +https://openai.com/gptbot"
UA_READ_ALOUD = "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36 (compatible; Google-Read-Aloud; +https://support.google.com/webmasters/answer/1061943)"
UA_SCRAPER = "python-httpx/0.28 scraper"


def headers(actor: str, egress_ip: str, ua: str, extra: dict | None = None) -> dict:
    h = {"X-Lab-Actor": actor, "X-Lab-Egress": egress_ip, "User-Agent": ua}
    if extra:
        h.update(extra)
    return h


def get(client: httpx.Client, path: str, headers: dict, retries: int = 5) -> httpx.Response:
    """GET with a retry on transport errors: the dev server drops idle keep-alive sockets."""
    for attempt in range(retries + 1):
        try:
            return client.get(path, headers=headers)
        except httpx.TransportError:
            if attempt == retries:
                raise
            time.sleep(0.2 * (attempt + 1))
    raise AssertionError("unreachable")


def scrape_catalog(client: httpx.Client, hdrs: dict, per_request=None) -> dict:
    """Fetch /product/1..CATALOG as fast as the store allows; report how far we got."""
    t0 = time.perf_counter()
    statuses, lanes, first_reason = [], set(), ""
    for pid in range(1, CATALOG + 1):
        h = dict(hdrs)
        if per_request:
            h.update(per_request(pid))
        resp = get(client, f"/product/{pid}", h)
        statuses.append(resp.status_code)
        lanes.add(resp.headers.get("X-Lane", "?"))
        if resp.status_code != 200 and not first_reason:
            try:
                first_reason = "; ".join(resp.json().get("reasons", []))[:120]
            except ValueError:
                first_reason = resp.text[:120]
    return {"scraped": statuses.count(200), "total": CATALOG, "status_429": statuses.count(429),
            "status_403": statuses.count(403), "lanes": sorted(lanes), "first_reason": first_reason,
            "seconds": round(time.perf_counter() - t0, 2)}


def report(name: str, s: dict) -> None:
    verdict = "fast lane" if s["scraped"] == s["total"] else ("BLOCKED" if s["status_403"] else "budget")
    print(f"[{name}] scraped {s['scraped']}/{s['total']} products in {s['seconds']}s  "
          f"lane={','.join(s['lanes'])}  429s={s['status_429']} 403s={s['status_403']}  -> {verdict}")
    if s["first_reason"]:
        print(f"    first rejection: {s['first_reason']}")
