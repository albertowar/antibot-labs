"""Round 1 defense (REFERENCE SOLUTION) — publish the crawl policy in machine-readable form.

One policy, three dialects, because no single one is honoured by every crawler:

  * **robots.txt** (RFC 9309): per-User-agent groups with Allow/Disallow. The
    only one every honest crawler reads. A `deny` purpose gets `Disallow: /`.
  * **AIPREF** (IETF drafts `aipref-attach` / `aipref-vocab`, 2026): a
    `Content-Usage:` line in robots.txt and an HTTP `Content-Usage` response
    header. Vocabulary `train-ai`, `ai-use`, `search`, values `y` / `n`.
  * **Content Signals** (Cloudflare's robots.txt extension, 2025): one
    `Content-Signal: search=yes, ai-input=no, ai-train=no` line.
  * **RSL 1.0** (Dec 2025): a `License:` line pointing at an RSL XML document
    that says what is permitted, prohibited and, in Round 4, priced; plus a
    `Link: <...>; rel="license"; type="application/rsl+xml"` response header.

None of these is enforcement. They are the contract that lets the *next* rounds
tell a crawler that ignored the rules from one that never saw them.
"""

from __future__ import annotations

from defenses import crawler_registry as registry

POLICY = {
    # Paths nobody should crawl: the decoy maze (Round 3) and the lab oracle.
    # Listing a trap here is what makes a hit on it a hard tell (W1 Ch8).
    "traps": ["/maze/", "/lab/"],
    "license_path": "/license.xml",
}


def signals(rules: dict):
    """One policy, two dialects. Both vocabularies are yes/no: a *licensed* purpose
    is expressed as allowed here, and the price lives in the RSL document."""
    yn = lambda p: "no" if rules.get(p, "deny") == "deny" else "yes"  # noqa: E731
    content_signal = f"search={yn('search')}, ai-input={yn('ai-input')}, ai-train={yn('ai-train')}"
    content_usage = f"search={yn('search')[0]}, ai-use={yn('ai-input')[0]}, train-ai={yn('ai-train')[0]}"
    return content_signal, content_usage

# robots.txt group per declared crawler token, then the catch-all group.
# `rules` maps purpose -> "allow" | "deny" | "licensed" (Round 4 flips ai-train).


def robots_txt(base_url: str, rules: dict) -> str:
    traps = POLICY["traps"]
    lines = []
    for name, op in registry.OPERATORS.items():
        rule = rules.get(op["purpose"], "deny")
        lines.append(f"# {name}: purpose {op['purpose']} -> {rule}")
        lines.append(f"User-agent: {op['ua_token']}")
        if rule == "deny":
            lines.append("Disallow: /")
        else:
            lines.extend(f"Disallow: {p}" for p in traps)
            lines.append("Allow: /")
        lines.append("")
    lines.append("User-agent: *")
    lines.extend(f"Disallow: {p}" for p in traps)
    lines.append("Allow: /")
    lines.append("")
    cs, cu = signals(rules)
    lines.append(f"Content-Signal: {cs}")
    lines.append(f"Content-Usage: {cu}")
    lines.append(f"License: {base_url}{POLICY['license_path']}")
    lines.append(f"Sitemap: {base_url}/sitemap.xml")
    return "\n".join(lines) + "\n"


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
