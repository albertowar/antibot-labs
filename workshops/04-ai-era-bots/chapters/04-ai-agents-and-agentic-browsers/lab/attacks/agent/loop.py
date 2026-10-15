"""
The observe -> decide -> act loop.

This is the whole agent, 60 lines: snapshot the page, ask the policy what to do, do it, repeat until
the policy says done or we run out of steps. browser-use and the MCP browser tools are larger, but
this is their core, and it is enough to drive the store's buy funnel.

run_agent_session() is what every round's attack calls. It signs in (the agent's "user" is a seeded
account) or registers a throwaway one, then loops toward the goal. It returns a result dict for the
attack's summary: outcome, whether the order was placed, how many steps it took, and what the store
said when it refused (the X-Lab-* headers of the last page, which the lab store sends so you can see why).
"""

import time
from urllib.parse import urlparse

from . import observe
from .act import Executor
from .policy import make_policy

SUBMITS = ("#drop-buy", "#stepup-submit", "#login-form button[type=submit]", "#register-form button[type=submit]")


def _navigating_click(page, ex, selector):
    """Click a control that submits a form, and wait for the page it leads to."""
    from playwright.sync_api import TimeoutError as PlaywrightTimeout
    if selector not in SUBMITS:
        return ex.click(selector)
    try:
        with page.expect_navigation(timeout=8000, wait_until="domcontentloaded"):
            ex.click(selector)
    except PlaywrightTimeout:
        pass                                         # the page answered without navigating (a wrong code)


def sign_in(ex, page, base, account, register=False):
    """Log in with a seeded account, or register a throwaway one (the fleet)."""
    form, button = ("#register-form", "#register-form button[type=submit]") if register else \
        ("#login-form", "#login-form button[type=submit]")
    ex.goto("/register" if register else "/login")
    if register:
        ex.fill(f"{form} input[name=name]", account["name"])
    ex.fill(f"{form} input[name=email]", account["email"])
    ex.fill(f"{form} input[name=password]", account["password"])
    ex.flush()
    _navigating_click(page, ex, button)
    return urlparse(page.url).path == "/account"


def run_agent_session(page, base, account, sku, *, executor=None, policy=None, register_first=False,
                      mandate=None, mailbox=None, highlight=False, max_steps=14, label="agent"):
    """Drive one agent session to buy `sku`. Returns a result dict for the attack's summary."""
    ex = executor or Executor(page, base)
    pol = policy or make_policy(sku)
    memory = {"mandate": mandate}
    result = {"persona": label, "email": account["email"], "outcome": "error", "success": False,
              "steps": 0, "reasons": []}
    seen = {}
    page.on("response", lambda r: seen.update(last=r) if r.request.resource_type == "document" else None)

    if not sign_in(ex, page, base, account, register=register_first):
        result["reasons"] = ["agent could not " + ("register" if register_first else "log in")]
        return result

    for _ in range(max_steps):
        result["steps"] += 1
        snap = observe.snapshot(page, highlight=highlight)
        action = pol.decide(f"buy {sku}", snap, memory)
        kind = action.get("action")
        res = snap.get("last_result")
        if res:
            result["outcome"] = res["outcome"]
        if kind == "done":
            result["success"] = res is not None and res["outcome"] == "allow"
            break
        if kind == "goto":
            ex.goto(action["path"])
            continue
        if kind == "fill":
            ex.flush()
            ex.fill(action["selector"], action["text"])
        elif kind == "click":
            ex.flush()
            try:
                _navigating_click(page, ex, action["selector"])
            except Exception:
                result["reasons"] = [f"could not click {action['selector']}"]
                break
            time.sleep(0.3)
        elif kind == "read_code":
            code = mailbox(account["email"]) if mailbox else None
            memory["code"], memory["await_code"] = code, False
            if not code:
                result["reasons"] = ["step-up required: no code reachable (hand-off to a human)"]
                result["outcome"] = "challenge"
                break

    final = observe.snapshot(page)
    if final.get("confirmed"):
        result["outcome"], result["success"] = "allow", True
    if not result["success"]:
        resp = seen.get("last")
        signals = resp.headers.get("x-lab-signals", "") if resp is not None else ""
        result["reasons"] = result["reasons"] or ([signals] if signals else [])
    return result
