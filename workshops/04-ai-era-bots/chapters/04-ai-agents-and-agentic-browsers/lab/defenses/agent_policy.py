"""
W4 Ch4, L1 agent policy: who says they are an agent, and what may they do? (Round 1)

Agents that identify themselves come in two forms:

    User-Agent tokens       "... ChatGPT-User/1.0; +https://openai.com/bot", "Claude-User/1.0; ...",
                            "Perplexity-User/1.0; ..." (user-directed fetchers), or our lab operator's
                            "LabAgent/1.0 (+https://agents.lab-provider.test)"
    Signature-Agent header  the Web Bot Auth way: "I am operated by <origin>". Here it is a *claim*;
                            Round 3 verifies it.

Policy, not detection. Once we know a session is a declared agent we don't ask "is it a bot?" (it
told us). We ask what agents may do here:

    browse / search / read     allow, and serve them Markdown (cheaper for both sides)
    add to cart                allow
    buy the drop               refuse until the agent is verified (L3) and mandated (L4)

Why it works: a declared agent is a cooperative counterparty. Why it fails: it sorts the cooperative
from everyone else, and the undeclared agent in a stock Chrome sails through (Round 1's attack).
False positives: real users of agentic browsers whose purchase you just refused. Count those as lost
sales.

What you write: classify() and score_checkout(). Given: the CHECK that runs them on the drop purchase,
and the Markdown negotiation.
"""

import re
from urllib.parse import urlparse

from .pipeline import Check, Signal

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
    "drop": "verified agent (Web Bot Auth, trusted operator) with a mandate from the account holder",
    "formats": ["text/html", "text/markdown"],
    "contact": "security@kestrel.example",
}


def classify(ctx):
    """Return {"kind": "human" | "declared_agent", "operator": host | None, "evidence": [...]}."""
    ua = ctx.ua.raw or ""
    evidence, operator = [], None
    # TODO (Round 1): recognise a declared agent.
    #   1. _TOKEN_RE.search(ua): a KNOWN_AGENT_TOKENS token in the User-Agent. Record the
    #      evidence and the operator (the +https://host in the UA via _URL_RE, else the
    #      token's default host).
    #   2. A Signature-Agent header (ctx.header): strip the quotes, lower-case it, take the host if it
    #      is an origin like https://host, record it as an UNVERIFIED claim and use it as the operator.
    #   3. Any evidence -> {"kind": "declared_agent", ...}; none -> human.
    # python tools/checkpoint.py --round 1 --catch-up drops in the reference solution.
    return {"kind": "human", "operator": operator, "evidence": evidence}


def score_checkout(principal):
    """L1 at the drop: declared agents are refused, with a pointer to the policy they can read."""
    # TODO (Round 1): a "declared_agent" principal gets 60 points (block) and a reason that
    # tells the agent what to do instead (GET /agent-policy). Humans and verified agents: 0.
    return 0, []


def wants_markdown(accept, principal):
    """Cloudflare's 'Markdown for Agents' (2026) is content negotiation: Accept: text/markdown."""
    return "text/markdown" in (accept or "") or principal["kind"] in ("declared_agent", "verified_agent")


def markdown_catalog(items, page=1, pages=1):
    """A product listing as Markdown: the same facts in a fraction of the tokens."""
    lines = ["# Kestrel Outfitters catalogue", "", f"Page {page} of {pages}.", "",
             "| SKU | Product | Price |", "|---|---|---|"]
    for p in items:
        lines.append(f"| `{p['sku']}` | {p['name']} | ${p['price']:.2f} |")
    lines += ["", "Add to cart: `POST /api/cart/add {\"sku\": ...}`. The limited drop is `/drop/lab-runner-9`. "
              "Policy: `GET /agent-policy`."]
    text = "\n".join(lines) + "\n"
    return text, max(1, len(text) // 4)  # rough token estimate, as x-markdown-tokens does


def _check(ctx):
    from . import principal as who      # principal.py imports this module: import it late
    p = who.principal(ctx)
    points, reasons = score_checkout(p)
    return [Signal("agent_policy", p["kind"], points, "; ".join(reasons)[:140])] if points else None


CHECK = Check("agent_policy", _check, phases=("action:drop_buy",))


if __name__ == '__main__':
    class _Ctx:
        def __init__(self, ua, **h):
            self.ua = type("UA", (), {"raw": ua})
            self._h = h

        def header(self, name, default=None):
            return self._h.get(name, default)

    print(classify(_Ctx("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot")))
    print(classify(_Ctx("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/153.0.0.0 Safari/537.36")))
    print(classify(_Ctx("Mozilla/5.0", **{"Signature-Agent": '"https://agents.lab-provider.test"'})))
