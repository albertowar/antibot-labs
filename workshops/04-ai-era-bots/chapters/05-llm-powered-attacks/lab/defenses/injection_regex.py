"""
Round 4, pre-wired: the deny-list the store shipped with its LLM features.

The first thing every team writes when they hear "prompt injection": a regex list of phrases attackers
use. It is in the OWASP LLM01 mitigations as a *supporting* control, and this round shows why it cannot be
the main one:

  * it only matches the exact phrasing it was written for: paraphrase, zero-width characters, confusable
    letters, encoding, splitting across two reviews, or hiding in an HTML comment all walk past it;
  * it matches real customers who write "ignore the instructions on the box", and every match is a lost
    review.

Not student-edited. The stub `llm_guard.py` calls it; deciding whether to keep it is Round 4's step 3.
"""

import re

PATTERNS = [
    r"\[SYSTEM[:\s\]]",
    r"\[ASSISTANT[:\s\]]",
    r"ignore (your |all |previous |the |prior )?instructions",
    r"you are now",
    r"new persona",
    r"disregard (your |all |previous |the |other )?",
]
_RX = [re.compile(p, re.I) for p in PATTERNS]


def match(text):
    """The pattern that matched, or None."""
    for rx in _RX:
        if rx.search(text):
            return rx.pattern
    return None
