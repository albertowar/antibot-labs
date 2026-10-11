"""Build data/world.json: the pretend Internet the lab store sits on.

On a laptop every request arrives from 127.0.0.1, so there is nothing to look up:
no source address, no ASN, no reverse DNS. This file invents a small world so the
identification techniques have something to work on:

  * pools of RFC 5737 documentation addresses, each with an ASN and a class
    (isp, mobile, cloud, hosting, operator)
  * a PTR table (what a reverse-DNS lookup would answer for each address)
  * a forward table (what the PTR name resolves back to), so forward-confirmed
    reverse DNS (FCrDNS) can succeed or fail on purpose

The operator pools are the ones the snapshots in data/published_ranges/ list.
None of these addresses or names belong to a real operator. The lab store only
honours them from loopback (demo_site/lab_edge.py).

    python tools/build_world.py      # rewrites data/world.json deterministically
"""

from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "data", "world.json")


def ips(prefix, lo, hi):
    return [f"{prefix}.{i}" for i in range(lo, hi + 1)]


def build():
    pools = {
        # Where real people come from.
        "home-isp":      {"asn": 64601, "asn_name": "Iberia Fibra (lab)",     "asn_class": "isp",      "ips": ips("198.51.100", 1, 254)},
        "mobile-cgnat":  {"asn": 64610, "asn_name": "Movil CGNAT (lab)",      "asn_class": "mobile",   "ips": ips("203.0.113", 1, 100)},
        # Privacy relays and corporate secure-web-gateways egress from cloud space:
        # real users whose address looks like a datacenter. The false-positive cohort.
        "relay-egress":  {"asn": 64630, "asn_name": "RelayCDN egress (lab)",  "asn_class": "cloud",    "ips": ips("203.0.113", 101, 130)},
        # Rentable cloud and hosting: where scrapers and undeclared crawlers live.
        "cloud-a":       {"asn": 64620, "asn_name": "NimbusCloud (lab)",      "asn_class": "cloud",    "ips": ips("192.0.2", 1, 100)},
        "hosting-b":     {"asn": 64621, "asn_name": "Stratus Hosting (lab)",  "asn_class": "hosting",  "ips": ips("192.0.2", 128, 190)},
        # A fictional small search engine: identifiable, never verifiable.
        "localsearch":   {"asn": 64621, "asn_name": "Stratus Hosting (lab)",  "asn_class": "hosting",  "ips": ips("192.0.2", 200, 203)},
        # Operator pools. These match the prefixes in data/published_ranges/.
        "openai-chatgpt-user": {"asn": 64640, "asn_name": "OpenAI (lab stand-in)",       "asn_class": "operator", "ips": ips("203.0.113", 144, 159)},
        "openai-searchbot":    {"asn": 64640, "asn_name": "OpenAI (lab stand-in)",       "asn_class": "operator", "ips": ips("203.0.113", 160, 175)},
        "openai-gptbot":       {"asn": 64640, "asn_name": "OpenAI (lab stand-in)",       "asn_class": "operator", "ips": ips("203.0.113", 176, 191)},
        "anthropic":           {"asn": 64641, "asn_name": "Anthropic (lab stand-in)",    "asn_class": "operator", "ips": ips("203.0.113", 192, 207)},
        "google":              {"asn": 64642, "asn_name": "Google (lab stand-in)",       "asn_class": "operator", "ips": ips("203.0.113", 208, 223)},
        "commoncrawl":         {"asn": 64643, "asn_name": "Common Crawl (lab stand-in)", "asn_class": "operator", "ips": ips("203.0.113", 224, 239)},
        "perplexity":          {"asn": 64644, "asn_name": "Perplexity (lab stand-in)",   "asn_class": "operator", "ips": ips("203.0.113", 240, 254)},
    }

    ptr, forward = {}, {}

    def fcrdns(ip, name):
        """A well-run network: PTR -> name, name -> the same IP."""
        ptr[ip] = name
        forward.setdefault(name, []).append(ip)

    for ip in pools["home-isp"]["ips"]:
        fcrdns(ip, f"{ip.replace('.', '-')}.dyn.iberiafibra.example")
    # CGNAT: no PTR at all (common for mobile carriers).
    for ip in pools["relay-egress"]["ips"]:
        fcrdns(ip, f"egress-{ip.split('.')[-1]}.relay.example")
    for ip in pools["cloud-a"]["ips"]:
        fcrdns(ip, f"vm-{ip.replace('.', '-')}.nimbus.example")
    for ip in pools["hosting-b"]["ips"]:
        fcrdns(ip, f"srv-{ip.split('.')[-1]}.stratus.example")
    for ip in pools["localsearch"]["ips"]:
        fcrdns(ip, f"crawler-{ip.split('.')[-1]}.localsearch.example")
    # Google-style and Common-Crawl-style PTR names, forward-confirmed.
    for ip in pools["google"]["ips"]:
        fcrdns(ip, f"crawl-{ip.replace('.', '-')}.googlebot.com")
    for ip in pools["commoncrawl"]["ips"]:
        fcrdns(ip, f"crawl-{ip.split('.')[-1]}.crawl.commoncrawl.org")
    # OpenAI, Anthropic and Perplexity document IP ranges, not reverse DNS: their
    # pools have generic cloud-looking PTRs, which is exactly why you match ranges.
    for pool in ("openai-chatgpt-user", "openai-searchbot", "openai-gptbot", "anthropic", "perplexity"):
        for ip in pools[pool]["ips"]:
            fcrdns(ip, f"{ip.replace('.', '-')}.cloudhost.example")

    # The trap: a hosting customer who set a Googlebot-looking PTR on their own
    # address. Reverse DNS says googlebot.com; the forward lookup of that name
    # points at Google's address, not theirs. FCrDNS catches this, a PTR check alone does not.
    liar = "192.0.2.150"
    ptr[liar] = "crawl-203-0-113-209.googlebot.com"   # already forward-maps to 203.0.113.209
    return {
        "_comment": "Generated by tools/build_world.py. RFC 5737 documentation addresses only; nothing here is a real host.",
        "student_ip": "198.51.100.42",
        "pools": pools,
        "ptr": ptr,
        "forward": forward,
    }


if __name__ == "__main__":
    world = build()
    with open(OUT, "w") as fh:
        json.dump(world, fh, indent=1, sort_keys=False)
    n = sum(len(p["ips"]) for p in world["pools"].values())
    print(f"wrote {OUT}: {len(world['pools'])} pools, {n} addresses, {len(world['ptr'])} PTR records")
