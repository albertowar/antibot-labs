"""Round 1, pre-wired — the content heuristics the store already had.

This is what stopped review spam before LLMs: exact duplicates, templated text
(shingle overlap with recent reviews), links, very short text, disposable
sender domains. It catches the scripted farm (``round1_review_farm.py
--scripted``) cold, because a template with slots *is* a shingle pattern.

It is not student-edited. Round 1 keeps it running and shows what it misses when
every review is unique and on-topic: nothing in the text itself gives the farm
away any more, so the signal has to come from somewhere else (review_signals.py).

Also here: ``looks_generated``, a deliberately toy "AI-text detector", used only
by the scoreboard to show why that idea is not a bot signal — it flags polished
human prose just as happily.

ctx keys:
    text          : str        the review body
    recent_texts  : list[str]  published/held reviews from the last window
    email_domain  : str
    disposable    : bool
"""

from __future__ import annotations

import re

from .decision import allow, block, challenge, Decision

MIN_CHARS = 20
SHINGLE = 5
TEMPLATE_JACCARD = 0.5
_URL = re.compile(r"https?://|www\.", re.I)
_WORD = re.compile(r"[a-z0-9']+")


def shingles(text: str, k: int = SHINGLE) -> set:
    w = _WORD.findall(text.lower())
    return {" ".join(w[i:i + k]) for i in range(max(0, len(w) - k + 1))}


def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def evaluate(ctx) -> Decision:
    text = ctx["text"].strip()
    if ctx.get("disposable"):
        return block("disposable sender domain", score=80.0)
    if _URL.search(text):
        return block("link in review", score=90.0)
    if len(text) < MIN_CHARS:
        return challenge("very short review: held for moderation", score=30.0)
    norm = " ".join(text.lower().split())
    mine = shingles(text)
    for other in ctx.get("recent_texts", []):
        if " ".join(other.lower().split()) == norm:
            return challenge("duplicate of a recent review: held", score=60.0)
        if jaccard(mine, shingles(other)) >= TEMPLATE_JACCARD:
            return challenge("templated text (shingle overlap): held", score=70.0)
    return allow("content heuristics passed")


_CONNECTIVES = re.compile(r"\b(overall|additionally|furthermore|highly recommend|in conclusion|"
                          r"what stands out|by contrast|that about sums it up|would buy again|"
                          r"compared with|value for money|exactly as pictured)\b", re.I)


def looks_generated(text: str) -> bool:
    """Toy AI-text detector: 'polished, connective-heavy, no typos, no shouting'.

    Real detectors are better than this, but share its failure mode: careful human
    writers (and non-native speakers who write formally) look 'generated', while a
    model asked for a casual tone does not. A bot signal has to be about the
    *account and the traffic*, not the prose (W4 Ch6 returns to this).
    """
    words = _WORD.findall(text.lower())
    if len(words) < 12:
        return False
    uniq = len(set(words)) / len(words)
    polished = text[0].isupper() and text.rstrip()[-1] in ".!" and "!!" not in text
    connectives = len(_CONNECTIVES.findall(text))
    lowercase_i = bool(re.search(r"\bi\b", text))     # people write "i", models don't
    return polished and not lowercase_i and (connectives >= 1 or uniq > 0.8)
