"""
The observe -> decide -> act loop.

This is the whole agent, 40 lines: snapshot the page, ask the policy what to
do, do it, repeat until the policy says done or we run out of steps. browser-use
and the MCP browser tools are larger, but this is their core, and it is enough
to drive the store's buy funnel.

run_agent_session() is what every round's attack calls. It handles login (the
agent's "user" is a seeded account), then loops toward the goal. It returns a
result dict for the scoreboard: outcome, whether the order was placed, how many
steps it took, and any block/challenge reasons the store gave.
"""

import time

from . import observe
from .act import Executor
from .policy import make_policy


def login(executor, page, base, account):
    executor.goto("/login")
    page.fill("#login-form input[name=email]", account["email"])
    page.fill("#login-form input[name=password]", account["password"])
    executor.flush()
    page.click("#login-submit")
    try:
        page.wait_for_url(f"{base}/account", timeout=6000)
        return True
    except Exception:
        return page.query_selector("nav a[href='/account']") is not None


def register(executor, page, base, account):
    """Create a brand-new account in this browser session (used by the Round 4 fleet)."""
    executor.goto("/register")
    page.fill("#register-form input[name=email]", account["email"])
    page.fill("#register-form input[name=password]", account["password"])
    page.fill("#register-form input[name=address]", account["address"])
    executor.flush()
    page.click("#register-submit")
    try:
        page.wait_for_url(f"{base}/account", timeout=6000)
        return True
    except Exception:
        return page.query_selector("nav a[href='/account']") is not None


def run_agent_session(page, base, account, sku, *, executor=None, policy=None, register_first=False,
                      mandate=None, mailbox=None, highlight=False, max_steps=14, label="agent"):
    """Drive one agent session to buy `sku`. Returns a result dict for the scoreboard."""
    ex = executor or Executor(page, base)
    pol = policy or make_policy(sku)
    memory = {"mandate": mandate, "mailbox": mailbox}
    result = {"persona": label, "email": account["email"], "outcome": "error", "success": False,
              "steps": 0, "reasons": []}

    entered = register(ex, page, base, account) if register_first else login(ex, page, base, account)
    if not entered:
        result["reasons"] = ["agent could not " + ("register" if register_first else "log in")]
        return result

    for _ in range(max_steps):
        result["steps"] += 1
        snap = observe.snapshot(page, highlight=highlight)
        action = pol.decide(f"buy {sku}", snap, memory)
        kind = action.get("action")

        if kind == "done":
            break
        if kind == "goto":
            ex.goto(action["path"])
        elif kind == "fill":
            ex.flush()
            ex.fill(action["selector"], action["text"])
        elif kind == "click":
            ex.flush()
            try:
                ex.click(action["selector"])
            except Exception:
                result["reasons"] = [f"could not click {action['selector']}"]
                break
            time.sleep(0.4)
        elif kind == "read_code":
            code = mailbox(account["email"]) if mailbox else None
            memory["code"] = code
            memory["await_code"] = False
            if not code:
                result["reasons"] = ["step-up required: no code reachable (hand-off to a human)"]
                result["outcome"] = "challenge"
                break
            continue

        res = observe.snapshot(page).get("last_result")
        if res:
            result["outcome"] = res["outcome"]
            result["reasons"] = _reasons(page)
            if res["outcome"] == "allow" and "order confirmed" in res["text"].lower():
                result["success"] = True
                break
            if res["outcome"] == "challenge" and "code" in res["text"].lower():
                memory["await_code"] = True   # next step reads the mailbox

    return result


def _reasons(page):
    try:
        return [li.inner_text() for li in page.query_selector_all("#result li")][:4]
    except Exception:
        return []
