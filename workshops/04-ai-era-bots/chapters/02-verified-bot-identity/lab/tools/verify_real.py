"""Bonus (networked): verify an IP from *your own* server logs the way the gate does.

    python tools/verify_real.py 66.249.66.1 --claim googlebot
    python tools/verify_real.py 2001:db8::1 --claim gptbot --ranges-from https://openai.com

This is the only tool in the lab that talks to the real internet, and it only ever
does two things a log reviewer does by hand: a DNS lookup of an address you already
received a request from, and a download of an operator's published range file. It
sends nothing to the operator's crawler, to the address, or to anyone else. Do not
point it at addresses from logs you do not own.

Requires dnspython (in requirements.txt). Range-file URLs are the operators'
documented ones; they change, so check the docs in defenses/operators.py.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "defenses"))
os.environ.setdefault("LAB_DNS", "system")
from operators import OPERATORS  # noqa: E402
from resolver import SystemResolver  # noqa: E402

RANGE_URLS = {
    "google/common-crawlers.json": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    "google/user-triggered-fetchers.json": "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json",
    "bing/bingbot.json": "https://www.bing.com/toolbox/bingbot.json",
    "openai/gptbot.json": "https://openai.com/gptbot.json",
    "openai/searchbot.json": "https://openai.com/searchbot.json",
    "openai/chatgpt-user.json": "https://openai.com/chatgpt-user.json",
    "anthropic/bots.json": "https://claude.com/crawling/bots.json",
    "perplexity/perplexitybot.json": "https://www.perplexity.com/perplexitybot.json",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ip")
    ap.add_argument("--claim", required=True, choices=sorted(OPERATORS))
    args = ap.parse_args()
    op = OPERATORS[args.claim]
    ip = str(ipaddress.ip_address(args.ip))
    res = SystemResolver()

    if op["rdns_suffixes"]:
        names = res.ptr(ip)
        print(f"PTR {ip} -> {names or 'none'}")
        for name in names:
            if any(name == s.lstrip(".") or name.endswith(s) for s in op["rdns_suffixes"]):
                addrs = res.a(name)
                print(f"A   {name} -> {addrs}")
                print("FCrDNS:", "✅ verified" if ip in addrs else "❌ forward lookup does not return the IP")
                break
        else:
            print(f"FCrDNS: ❌ no PTR under {op['rdns_suffixes']}")
    else:
        print(f"{args.claim} documents no reverse DNS; checking published ranges")

    for list_path in op["ranges"]:
        url = RANGE_URLS.get(list_path)
        if not url:
            continue
        try:
            doc = httpx.get(url, timeout=10, follow_redirects=True).json()
        except Exception as exc:
            print(f"range {list_path}: fetch failed ({exc.__class__.__name__})")
            continue
        prefixes = [p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in doc.get("prefixes", [])]
        hit = next((p for p in prefixes if p and ipaddress.ip_address(ip) in ipaddress.ip_network(p, strict=False)), None)
        print(f"range {list_path} ({doc.get('creationTime', '?')}, {len(prefixes)} prefixes): "
              + (f"✅ {ip} in {hit}" if hit else f"❌ {ip} not listed"))


if __name__ == "__main__":
    main()
