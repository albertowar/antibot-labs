"""
W4 Ch9 Capstone — the published crawl policy: one reservation, four channels (GIVEN)

The reservation stack students built in W4 Ch8 Round 1 lives in reservation/:

    robots.txt     access rules (RFC 9309) plus the usage lines crawlers read there:
                   Content-Signal (Cloudflare, 2025; Search / Agent / Training split 2026)
                   and Content-Usage (IETF aipref drafts, 2026)
    headers.json   the same preferences as response headers for clients that never
                   fetch robots.txt: Content-Usage, TDM-Reservation/TDM-Policy, an RSL Link
    terms.json     clickwrap terms with an automated-access and an AI-training clause
    logging.json   what the store logs about crawlers and for how long (retention_days)

None of this is enforcement. It is the contract that lets the live layers
(crawl_governance.py) tell a crawler that ignored the rules from one that never
saw them, and it is what a complaint to a Code of Practice signatory or the AI
Office points at (W4 Ch8 §8.1).

Purpose rules: search is allowed (we want the referrals), ai-input is denied,
ai-train is *licensed*: allowed for a verified crawler that pays the RSL price
through the 402 exchange (W4 Ch3 Round 4). The price lives in paywall.PAYWALL.
"""

import json
import os

import paywall

LAB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESERVATION = os.path.join(LAB_DIR, "reservation")
TRAPS = ["/maze/", "/lab/", "/admin/", "/account"]
RULES = {"search": "allow", "ai-train": "licensed", "ai-input": "deny"}


def _read(name):
    with open(os.path.join(RESERVATION, name)) as f:
        return f.read()


def _json(name):
    return json.loads(_read(name))


def rules():
    return dict(RULES)


def price_usd():
    return float(paywall.PAYWALL["price_usd"])


def robots_txt(base_url, level):
    """At L0 the store says nothing. From L1 it serves the reservation stack."""
    if level < 1:
        return "User-agent: *\nAllow: /\n"
    text = _read("robots.txt").rstrip("\n") + "\n"
    text += f"\nLicense: {base_url}/license.xml\nSitemap: {base_url}/sitemap.xml\n"
    return text


def response_headers(base_url, level):
    if level < 1:
        return {}
    hdrs = dict(_json("headers.json")["headers"])
    hdrs["Link"] = f'<{base_url}/license.xml>; rel="license"; type="application/rsl+xml"'
    hdrs["TDM-Policy"] = f"{base_url}/.well-known/tdm-policy.json"
    return hdrs


def terms():
    return _json("terms.json")


def logging_policy():
    return _json("logging.json")


def rsl_xml(base_url, price):
    """RSL 1.0 licence document: what is permitted free, what is priced, what is prohibited."""
    r = rules()
    permits = [p for p, v in r.items() if v == "allow"]
    licensed = [p for p, v in r.items() if v == "licensed"]
    prohibits = [p for p, v in r.items() if v == "deny"]
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<rsl xmlns="https://rslstandard.org/rsl" max-age="7">',
           f'  <content url="{base_url}/">']
    if permits:
        out += ['    <license>', f'      <permits type="usage">{" ".join(permits)}</permits>',
                '      <payment type="free"/>', '    </license>']
    if licensed:
        out += ['    <license>', f'      <permits type="usage">{" ".join(licensed)}</permits>',
                '      <payment type="crawl">', f'        <amount currency="USD">{price:.2f}</amount>',
                '        <accepts type="application/x402+json"/>', '      </payment>', '    </license>']
    if prohibits:
        out += ['    <license>', f'      <prohibits type="usage">{" ".join(prohibits)}</prohibits>', '    </license>']
    out += ['  </content>', '</rsl>', '']
    return "\n".join(out)


def is_disallowed(rule, path):
    """Would robots.txt forbid this path for a crawler under `rule`?"""
    if rule == "deny":
        return True
    return any(path.startswith(t) for t in TRAPS)


if __name__ == '__main__':
    print(robots_txt("http://127.0.0.1:8409", 1))
    print(response_headers("http://127.0.0.1:8409", 1))
