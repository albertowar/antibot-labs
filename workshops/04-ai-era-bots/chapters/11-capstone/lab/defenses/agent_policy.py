"""
W4 Ch11 Capstone — who says they are an agent (GIVEN, from W4 Ch4 Round 1)

Agents that identify themselves come in two forms:

    User-Agent tokens       "… ChatGPT-User/1.0; +https://openai.com/bot", "Claude-User/1.0; …",
                            "Perplexity-User/1.0; …" (user-directed fetchers), or our lab operator's
                            "LabAgent/1.0 (+https://agents.lab-provider.test)"
    Signature-Agent header  the Web Bot Auth way: "I am operated by <host>". Here it is a *claim*;
                            Round 3 verifies it.

Classification, not policy. In W4 Ch4 this layer refused every declared agent
at checkout. After W4 Ch10 (Amazon v. Perplexity: the agent is the user) the
capstone treats "declared agent" as a client type and lets
policies/agent_policy.json decide what it may do: browse, read Markdown, add
to cart, and buy once a person has confirmed (or, for a verified operator,
once the account holder granted a mandate).
"""

import re

# Token in the User-Agent -> the operator it belongs to. Vendor docs, 2026. Keep this list
# short and dated; it is a convenience, not a security boundary.
KNOWN_AGENT_TOKENS = {
    "ChatGPT-User": "chatgpt.com",
    "Claude-User": "anthropic.com",
    "Perplexity-User": "perplexity.ai",
    "LabAgent": "agents.lab-provider.test",
}
_TOKEN_RE = re.compile(r"\b(" + "|".join(map(re.escape, KNOWN_AGENT_TOKENS)) + r")/[\d.]+", re.I)
_URL_RE = re.compile(r"\+https?://([a-z0-9.-]+)", re.I)

AGENT_POLICY = {
    "version": "2026-10",
    "browse": "allow",
    "search": "allow",
    "cart": "allow",
    "checkout": "allowed: undeclared agents take a proof of work; every agent checkout is confirmed by the account holder (emailed code) or covered by a mandate from them (verified operators)",
    "formats": ["text/html", "text/markdown"],
    "contact": "security@lab-store.test",
    "appeal": "/appeal",
    "terms": "clickwrap; declared agents only (see reservation/terms.json)",
}


def classify(headers):
    """Return {"kind": "human" | "declared_agent", "operator": host | None, "evidence": [...]}."""
    ua = headers.get("User-Agent", "") or ""
    evidence, operator = [], None
    m = _TOKEN_RE.search(ua)
    if m:
        token = next(t for t in KNOWN_AGENT_TOKENS if t.lower() == m.group(1).lower())
        evidence.append(f"User-Agent token {token}")
        url = _URL_RE.search(ua)
        operator = url.group(1).lower() if url else KNOWN_AGENT_TOKENS[token]
    sig_agent = headers.get("Signature-Agent")
    if sig_agent:
        host = sig_agent.strip().strip('"').lower()
        evidence.append(f"Signature-Agent {host} (unverified claim)")
        operator = host
    if evidence:
        return {"kind": "declared_agent", "operator": operator, "evidence": evidence}
    return {"kind": "human", "operator": None, "evidence": []}




def wants_markdown(headers, principal):
    """Cloudflare's 'Markdown for Agents' (2026) is content negotiation: Accept: text/markdown."""
    accept = headers.get("Accept", "") or ""
    return "text/markdown" in accept or principal["kind"] in ("declared_agent", "verified_agent")


def markdown_catalog(products):
    lines = ["# Lab Store catalogue", "", "| SKU | Product | Price | Notes |", "|---|---|---|---|"]
    for sku, p in products.items():
        note = f"limited drop, {p.get('stock', '')} units, one per account" if p.get("drop") else ""
        lines.append(f"| `{sku}` | {p['name']} | ${p['price']} | {note} |")
    lines += ["", "Add to cart: `POST /api/cart/add {\"sku\": …}`. Checkout policy: `GET /agent-policy`."]
    text = "\n".join(lines) + "\n"
    return text, max(1, len(text) // 4)  # rough token estimate, as x-markdown-tokens does


if __name__ == '__main__':
    print(classify({"User-Agent": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"}))
    print(classify({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/150.0.0.0 Safari/537.36"}))
    print(classify({"Signature-Agent": '"agents.lab-provider.test"'}))
