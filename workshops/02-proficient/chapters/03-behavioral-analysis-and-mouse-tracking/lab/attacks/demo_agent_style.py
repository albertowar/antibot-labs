"""
Chapter 3: instructor demo, an AI agent's behavior (Section 3.8).

A deterministic mock of a computer-use agent loop. No LLM, no API keys:
    screenshot -> "think" for a few seconds -> click a coordinate -> type

The "model" here is a lookup of element boxes plus a few pixels of error,
which is what a vision model's coordinate prediction looks like from the
server. What matters is the behavior agents share (Akamai 2026; Choudhary
et al. 2026): almost no pointer movement, teleport clicks, long pauses
between actions, and text that arrives either as instant keystrokes or as
inserted text with no keys at all.

    python attacks/demo_agent_style.py              # types with xdotool-style 12 ms keys
    python attacks/demo_agent_style.py --dictate    # inserts text, no key events

Watch the verdicts at DEFENSE_LEVEL 1 and 2, then compare with the
"voice" user in tools/humans.py. With --dictate the agent and a
voice-control user produce the same signals for the same reasons.
"""

import random
import sys

from playwright.sync_api import sync_playwright

from common import box, identity, open_drop, report, sleep_ms, wait_result


def run(dictate=False, verbose=False):
    with sync_playwright() as p:
        browser, page = open_drop(p, "agent_dictate" if dictate else "agent")
        who = identity()
        for field in ("name", "email", "size", "reserve"):
            page.screenshot()                          # what the agent "sees"
            sleep_ms(random.uniform(1500, 3500))       # model latency
            b = box(page, f"#{field}")
            page.mouse.click(b["x"] + b["width"] / 2 + random.uniform(-4, 4),
                             b["y"] + b["height"] / 2 + random.uniform(-3, 3))
            if field == "reserve":
                break
            sleep_ms(random.uniform(300, 800))
            if dictate:
                page.keyboard.insert_text(who[field])
            else:
                page.keyboard.type(who[field], delay=12)
        result = wait_result(page)
        browser.close()
    if verbose:
        report("agent (dictate)" if dictate else "agent", result)
    return [result]


if __name__ == "__main__":
    print("=== Demo: agent-style automation ===")
    run(dictate="--dictate" in sys.argv, verbose=True)
