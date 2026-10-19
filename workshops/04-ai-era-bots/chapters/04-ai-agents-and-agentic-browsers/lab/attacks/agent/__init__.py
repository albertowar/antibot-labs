"""
W4 Ch4: a small browser agent in the shape of browser-use / Playwright MCP / Chrome DevTools MCP

    observe.py    read the page the way an agent does: interactive elements with roles and names,
                  the visible text, what the last action did. Optionally draws the numbered
                  highlight boxes some agent tools draw over the page (Round 2 detects them).
    policy.py     decide the next action from the snapshot. ScriptedPolicy is a deterministic
                  stand-in for the LLM (default); OllamaPolicy asks a local open model.
    act.py        perform the action with Playwright. Executor is the stock way (click(), fill());
                  HumanizedExecutor reuses the W2 Ch5 cursor and typing model.
    identity.py   sign requests as an operator (Web Bot Auth) via Playwright request interception.
    loop.py       observe -> decide -> act until done.

The browser itself comes from attacks/_common.py (one Chromium, one context per agent session,
every context behind labclient.browser_context, which refuses anything that is not this machine).

It exists to train defenders against the student's own local store. It is deliberately not
general-purpose tooling: no site adapters, no retries, no proxies, and it refuses non-local targets.
"""
