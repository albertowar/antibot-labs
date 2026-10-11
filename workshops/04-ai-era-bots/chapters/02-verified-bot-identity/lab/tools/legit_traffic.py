"""Legitimate traffic: the other half of every scoreboard, in two cohorts.

**Humans (20).** Browser sessions from residential addresses: the home page, a
catalogue page, three product pages, one search. They claim no identity, so the
gate should cost them nothing and block none of them, at any level.

**Genuine crawlers (8).** Each is what it says it is and asks for 60 pages in a
burst, which only the verified lane allows (anonymous = 30/min). "Admitted" means
all 60 came back 200. They are the false-positive cohort of this chapter: a
verification method an operator does not support, a stale range file, or a
signature your proxy stripped turns a real crawler into a throttled one.

  googlebot       198.51.100.10  PTR crawl-….googlebot.com, forward-confirmed
  bingbot         198.51.100.12  PTR msnbot-….search.msn.com
  applebot        198.51.100.14  PTR ….applebot.apple.com, publishes no range file
  gptbot          198.51.100.21  no PTR; in openai/gptbot.json (old prefix)
  gptbot-new      198.51.100.25  no PTR; in a prefix OpenAI added after the snapshot
  claudebot       198.51.100.41  no PTR; in anthropic/bots.json
  perplexitybot   198.51.100.50  no PTR; in perplexity/perplexitybot.json
  chatgpt-agent   198.51.100.60  in no list; signs with chatgpt.com's key (Web Bot Auth)

    python tools/legit_traffic.py
"""

from __future__ import annotations

import json
import os
import random
import sys
import time

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))
import httpsig  # noqa: E402

BASE_URL = os.environ.get("DEMO_URL", "http://127.0.0.1:5000")
HUMAN_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
N_HUMANS, CRAWL_PAGES = 20, 60

CRAWLERS = [
    ("googlebot", "198.51.100.10", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    ("bingbot", "198.51.100.12", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
    ("applebot", "198.51.100.14", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko; compatible; Applebot/0.1; +http://www.apple.com/go/applebot)"),
    ("gptbot", "198.51.100.21", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.3; +https://openai.com/gptbot"),
    ("gptbot-new", "198.51.100.25", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.3; +https://openai.com/gptbot"),
    ("claudebot", "198.51.100.41", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"),
    ("perplexitybot", "198.51.100.50", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)"),
    ("chatgpt-agent", "198.51.100.60", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"),
]


def _agent_key():
    with open(os.path.join(HERE, "fixtures", "keys", "chatgpt.com.json")) as fh:
        k = json.load(fh)
    return httpsig.load_private(k["seed_hex"]), k["thumbprint"]


def get(c: httpx.Client, path: str, headers: dict, retries: int = 5) -> httpx.Response:
    """GET with a retry on transport errors: the dev server drops idle keep-alive sockets."""
    for attempt in range(retries + 1):
        try:
            return c.get(path, headers=headers)
        except httpx.TransportError:
            if attempt == retries:
                raise
            time.sleep(0.2 * (attempt + 1))
    raise AssertionError("unreachable")


def human(c: httpx.Client, n: int) -> tuple[int, int]:
    h = {"X-Lab-Actor": "legit-human", "X-Lab-Egress": f"198.51.100.{130 + n}", "User-Agent": HUMAN_UA}
    paths = ["/", "/api/products?page=2"] + [f"/product/{p}" for p in random.sample(range(1, 201), 3)] + ["/api/search?q=runner"]
    ok = sum(1 for p in paths if get(c, p, h).status_code == 200)
    return ok, len(paths)


def crawler(c: httpx.Client, name: str, ip: str, ua: str, authority: str, priv, kid) -> tuple[int, int]:
    h = {"X-Lab-Actor": f"legit-crawler-{name}", "X-Lab-Egress": ip, "User-Agent": ua}
    ok = 0
    for pid in range(1, CRAWL_PAGES + 1):
        hdrs = dict(h)
        if name == "chatgpt-agent":
            ctx = httpsig.MessageContext("GET", authority, f"/product/{pid}", {"user-agent": ua})
            hdrs.update(httpsig.agent_headers(priv, kid, "https://chatgpt.com", ctx))
        if get(c, f"/product/{pid}", hdrs).status_code == 200:
            ok += 1
    return ok, CRAWL_PAGES


def run(base: str = BASE_URL, quiet: bool = False) -> dict:
    random.seed(42)
    priv, kid = _agent_key()
    authority = base.split("://", 1)[1].rstrip("/")
    out = {"humans_ok": 0, "humans_total": 0, "humans_blocked": 0, "crawlers": {}}
    with httpx.Client(base_url=base, timeout=10) as c:
        for n in range(N_HUMANS):
            ok, total = human(c, n)
            out["humans_ok"] += ok
            out["humans_total"] += total
        out["humans_blocked"] = out["humans_total"] - out["humans_ok"]
        for name, ip, ua in CRAWLERS:
            ok, total = crawler(c, name, ip, ua, authority, priv, kid)
            out["crawlers"][name] = {"ok": ok, "total": total, "admitted": ok == total}
    out["crawlers_admitted"] = sum(1 for v in out["crawlers"].values() if v["admitted"])
    out["crawlers_total"] = len(CRAWLERS)
    if not quiet:
        print(f"👤 humans:   {out['humans_ok']}/{out['humans_total']} requests served, "
              f"{out['humans_blocked']} blocked (false positives)")
        for name, v in out["crawlers"].items():
            mark = "✅" if v["admitted"] else "⛔"
            print(f"{mark} {name:14} {v['ok']:>3}/{v['total']} pages  {'admitted' if v['admitted'] else 'throttled: a genuine crawler in the anonymous lane'}")
        print(f"🕷  genuine crawlers admitted: {out['crawlers_admitted']}/{out['crawlers_total']}")
    return out


if __name__ == "__main__":
    run()
