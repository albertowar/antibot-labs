"""Round 4, pre-wired — the deny-list the store shipped with its LLM features.

The first thing every team writes when they hear "prompt injection": a regex
list of phrases attackers use. It is in the OWASP LLM01 mitigations as a
*supporting* control, and this round shows why it cannot be the main one:

  * it only matches the exact phrasing it was written for — paraphrase, zero-width
    characters, confusable letters, encoding, splitting across two reviews, or
    hiding in an HTML comment all walk past it;
  * it matches real customers who write "ignore the instructions on the box",
    and every match is a lost review.

Not student-edited. llm_guard.py (your code) decides whether to keep using it.
"""

from __future__ import annotations

import re

from decision import allow, block, Decision

PATTERNS = [
    r"\[SYSTEM[:\s\]]",
    r"\[ASSISTANT[:\s\]]",
    r"ignore (your |all |previous |the |prior )?instructions",
    r"you are now",
    r"new persona",
    r"disregard (your |all |previous |the |other )?",
]
_RX = [re.compile(p, re.I) for p in PATTERNS]


def evaluate(text: str) -> Decision:
    for rx in _RX:
        if rx.search(text):
            return block(f"injection deny-list: /{rx.pattern}/", score=80.0)
    return allow("deny-list passed")
