"""
W4 Ch4 — L1 agent policy: who says they are an agent, and what may they do? (Round 1)

Agents that identify themselves come in two forms:

    User-Agent tokens       "… ChatGPT-User/1.0; +https://openai.com/bot", "Claude-User/1.0; …",
                            "Perplexity-User/1.0; …" (user-directed fetchers), or our lab operator's
                            "LabAgent/1.0 (+https://agents.lab-provider.test)"
    Signature-Agent header  the Web Bot Auth way: "I am operated by <host>". Here it is a *claim*;
                            Round 3 verifies it.

Policy, not detection. Once we know a session is a declared agent we don't ask
"is it a bot?" (it told us). We ask what agents may do here:

    browse / search / read     allow — and serve them Markdown (cheaper for both sides)
    add to cart                allow
    checkout                   refuse until the agent is verified (L3) and mandated (L4)

Why it works: a declared agent is a cooperative counterparty. Why it fails:
it sorts the cooperative from everyone else, and the undeclared agent in a
stock Chrome sails through (Round 1's attack). False positives: real users of
agentic browsers whose purchase you just refused. Count those as lost sales.
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
    "checkout": "verified agent (Web Bot Auth, trusted operator) with a mandate from the account holder",
    "formats": ["text/html", "text/markdown"],
    "contact": "security@lab-store.test",
}


def classify(headers):
    """Return {"kind": "human" | "declared_agent", "operator": host | None, "evidence": [...]}."""
    ua = headers.get("User-Agent", "") or ""
    evidence, operator = [], None
    # TODO (Round 1): recognise a declared agent.
    #   1. _TOKEN_RE.search(ua): a KNOWN_AGENT_TOKENS token in the User-Agent. Record the
    #      evidence and the operator (the +https://host in the UA via _URL_RE, else the
    #      token's default host).
    #   2. A Signature-Agent header: strip quotes, lower-case, record it as an UNVERIFIED claim
    #      and use it as the operator.
    #   3. Any evidence -> {"kind": "declared_agent", ...}; none -> human.
    # python tools/checkpoint.py --round 1 --catch-up drops in the reference solution.
    return {"kind": "human", "operator": operator, "evidence": evidence}


def score_checkout(principal):
    """L1 at checkout: declared agents are refused, with a machine-readable hint."""
    # TODO (Round 1): a "declared_agent" principal gets 60 points (block) and a reason that
    # tells the agent what to do instead (GET /agent-policy). Humans and verified agents: 0.
    return 0, []


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
