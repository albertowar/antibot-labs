"""Round 1 defense [REFERENCE SOLUTION] — publish the crawl policy in machine-readable form.

One policy, several dialects, because no single one is honoured by every crawler:

  * **robots.txt** (RFC 9309): per-User-agent groups with Allow/Disallow. The only one every honest
    crawler reads. A `deny` purpose gets `Disallow: /`.
  * **AIPREF** (IETF drafts `aipref-attach` / `aipref-vocab`, 2026): a `Content-Usage:` line in
    robots.txt and an HTTP `Content-Usage` response header. Vocabulary `train-ai`, `ai-use`,
    `search`, values `y` / `n`.
  * **Content Signals** (Cloudflare's robots.txt extension, 2025): one
    `Content-Signal: search=yes, ai-input=no, ai-train=no` line.
  * **RSL 1.0** (Dec 2025): a `License:` line pointing at an RSL XML document that says what is
    permitted, prohibited and, in Round 4, priced; plus a
    `Link: <...>; rel="license"; type="application/rsl+xml"` response header.
  * **TDMRep** (W3C community group): `tdm-reservation` / `tdm-policy` headers and
    `/.well-known/tdmrep.json`. Served by the lab's extension; not part of this exercise.

None of these is enforcement. They are the contract that lets the *next* rounds tell a crawler that
ignored the rules from one that never saw them.

How it reaches the wire: the store's `GET /robots.txt` already prints a catch-all group
(`User-agent: *`, `Allow: /`, a few Disallows). `demo_site/ext/deterrence.py` appends the lines
`robots_lines()` returns, at DEFENSE_LEVEL >= 1: they extend that catch-all group first, then
open one group per declared crawler. It adds `response_headers()` to every gated response.
(Known gap: the base group begins `Allow: /`, which a first-match parser such as Python's
`urllib.robotparser` honours before it reaches a later `Disallow`; RFC 9309 matches the longest
rule. The attack scripts use the crawler's own group, which has no such line.)

Done in this file: robots_lines() and response_headers(). effective_rules(), signals(),
rsl_xml(), is_disallowed(), exempt() and the CHECK that logs violations were given.
"""

from __future__ import annotations

from . import crawler_registry as registry
from .pipeline import Check, Signal

POLICY = {
    # Paths nobody should crawl: the decoy maze (Round 3). Listing a trap here is what makes a hit
    # on it a hard tell (W1 Ch8). The store's own robots.txt already disallows /lab/ and the cart.
    "traps": ["/maze/"],
    "license_path": "/license.xml",
}

# The policy documents themselves. Every crawler must be able to read them, whatever the rule says
# about it: a crawler that cannot fetch robots.txt cannot obey it. Never enforced, never charged.
EXEMPT = ("/robots.txt", "/license.xml", "/llms.txt", "/.well-known/")


def exempt(path: str) -> bool:
    return path.startswith(EXEMPT)


def effective_rules(level: int) -> dict:
    """purpose -> allow | deny | licensed. Round 4's paywall flips the licensed purposes."""
    rules = {"search": "allow", "ai-train": "deny", "ai-input": "deny"}
    if level >= 4:
        from . import paywall
        if paywall.PAYWALL["enabled"]:
            for purpose in paywall.PAYWALL["purposes"]:
                rules[purpose] = "licensed"
    return rules


def signals(rules: dict):
    """One policy, two dialects. Both vocabularies are yes/no: a *licensed* purpose is expressed as
    allowed here, and the price lives in the RSL document."""
    yn = lambda p: "no" if rules.get(p, "deny") == "deny" else "yes"  # noqa: E731
    content_signal = f"search={yn('search')}, ai-input={yn('ai-input')}, ai-train={yn('ai-train')}"
    content_usage = f"search={yn('search')[0]}, ai-use={yn('ai-input')[0]}, train-ai={yn('ai-train')[0]}"
    return content_signal, content_usage


def robots_lines(base_url: str, rules: dict) -> list:
    """The robots.txt lines this policy adds to the store's catch-all group: the traps, the
    Content-Signal / Content-Usage / License lines, then one group per declared crawler."""
    traps = POLICY["traps"]
    cs, cu = signals(rules)
    lines = [f"Disallow: {p}" for p in traps]                      # still the `User-agent: *` group
    lines += [f"Content-Signal: {cs}", f"Content-Usage: {cu}", f"License: {base_url}{POLICY['license_path']}"]
    for name, op in registry.OPERATORS.items():
        rule = rules.get(op["purpose"], "deny")
        lines += ["", f"# {name}: purpose {op['purpose']} -> {rule}", f"User-agent: {op['ua_token']}"]
        if rule == "deny":
            lines.append("Disallow: /")
        else:
            lines += [f"Disallow: {p}" for p in traps]
            lines.append("Allow: /")
    return lines


def rsl_xml(base_url: str, rules: dict, price_usd: float = 0.0) -> str:
    """RSL 1.0 licence document. Prohibitions win over permissions in RSL."""
    permits = [p for p, r in rules.items() if r == "allow"]
    licensed = [p for p, r in rules.items() if r == "licensed"]
    prohibits = [p for p, r in rules.items() if r == "deny"]
    out = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<rsl xmlns="https://rslstandard.org/rsl" max-age="7">',
        f'  <content url="{base_url}/">',
    ]
    if permits:
        out += ['    <license>',
                f'      <permits type="usage">{" ".join(permits)}</permits>',
                '      <payment type="free"/>',
                '    </license>']
    if licensed:
        out += ['    <license>',
                f'      <permits type="usage">{" ".join(licensed)}</permits>',
                '      <payment type="crawl">',
                f'        <amount currency="USD">{price_usd:.2f}</amount>',
                '        <accepts type="application/x402+json"/>',
                '      </payment>',
                '    </license>']
    if prohibits:
        out += ['    <license>',
                f'      <prohibits type="usage">{" ".join(prohibits)}</prohibits>',
                '    </license>']
    out += ['  </content>', '</rsl>', '']
    return "\n".join(out)


def response_headers(base_url: str, path: str, rules: dict) -> dict:
    """Per-response preference signals, for clients that never read robots.txt."""
    _cs, cu = signals(rules)
    return {
        "Content-Usage": cu,
        "Link": f'<{base_url}{POLICY["license_path"]}>; rel="license"; type="application/rsl+xml"',
    }


def is_disallowed(rule, path: str) -> bool:
    """Would robots.txt forbid this path for a crawler under `rule`? (GIVEN helper)"""
    if rule == "deny":
        return True
    return any(path.startswith(t) for t in POLICY["traps"])


def _check(ctx):
    """Round 1 (given): log, do not enforce. A request that breaks the published rules is served
    and recorded as `crawl_policy:robots_violation` in the decision log. Round 2 enforces on it."""
    from . import bot_identity
    if exempt(ctx.path):
        return None
    ident = bot_identity.identify(ctx)
    rule = effective_rules(ctx.level).get(ident.purpose) if ident.operator else None
    if is_disallowed(rule, ctx.path):
        who = ident.operator or "an undeclared client"
        return [Signal("crawl_policy", "robots_violation", 5, f"{who} fetched {ctx.path[:60]}, which robots.txt forbids it")]
    return None


CHECK = Check("crawl_policy", _check)
