"""
Round 1, pre-wired: the content heuristics the store already had.

This is what stopped review spam before LLMs: exact duplicates, templated text (shingle overlap with
recent reviews), links, very short text, disposable sender domains. It catches the scripted farm
(`round1_review_farm.py --scripted`) cold, because a template with slots *is* a shingle pattern.

It is not student-edited. Round 1 keeps it running and shows what it misses when every review is
unique and on-topic: nothing in the text itself gives the farm away any more, so the signal has to come
from somewhere else (review_signals.py). It is wired at LADDER[1], ahead of the student's review_signals, because the store had it in front of the
review form before the LLMs arrived (and a level-0 store must publish a four-letter review: the contract's smoke).

What it returns: a link or a disposable domain is a hard block; a duplicate, a template or a one-liner
is a *hold*. A hold is not a verdict the gate knows (the verdict set is closed), so the check records
`ctx.attrs["review_hold"]` and `demo_site/ext/llm_surfaces.py`'s post-write hook parks the review as
`pending` and answers 202. The hold costs a point or two of score only so it shows in the log.

Also here: `looks_generated`, a deliberately toy "AI-text detector", used only by the scoreboard note to
show why that idea is not a bot signal: it flags polished human prose just as happily.
"""

import re

from .pipeline import Check, Signal, Verdict

MIN_CHARS = 20
SHINGLE = 5
TEMPLATE_JACCARD = 0.5
RECENT_WINDOW = 60
DISPOSABLE = {"guerrillamail.com", "mailinator.com", "10minutemail.com", "tempmail.io",
              "trashmail.com", "sharklasers.com", "yopmail.com", "getnada.com"}
_URL = re.compile(r"https?://|www\.", re.I)
_WORD = re.compile(r"[a-z0-9']+")


def shingles(text, k=SHINGLE):
    w = _WORD.findall(text.lower())
    return {" ".join(w[i:i + k]) for i in range(max(0, len(w) - k + 1))}


def jaccard(a, b):
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def review_text(ctx):
    """The review body from a JSON or a form post."""
    src = ctx.json if isinstance(ctx.json, dict) else ctx.form
    return str(src.get("body") or "").strip()


def _recent_texts():
    from demo_site.models import Review
    rows = Review.query.filter(Review.status != "removed").order_by(Review.id.desc()).limit(RECENT_WINDOW).all()
    return [r.body or "" for r in rows]


def _check(ctx):
    text = review_text(ctx)
    domain = (ctx.user.email.split("@")[-1] if ctx.user else "").lower()
    if domain in DISPOSABLE:
        return Verdict("block", signals=(Signal("content", "disposable_domain", 80, domain),))
    if _URL.search(text):
        return Verdict("block", signals=(Signal("content", "link_in_review", 90, "http/www in the text"),))
    if len(text) < MIN_CHARS:
        ctx.attrs["review_hold"] = "very short review"
        return [Signal("content", "too_short", 10, f"{len(text)} chars")]
    norm = " ".join(text.lower().split())
    mine = shingles(text)
    for other in _recent_texts():
        if " ".join(other.lower().split()) == norm:
            ctx.attrs["review_hold"] = "duplicate of a recent review"
            return [Signal("content", "duplicate", 10)]
        if jaccard(mine, shingles(other)) >= TEMPLATE_JACCARD:
            ctx.attrs["review_hold"] = "templated text (shingle overlap)"
            return [Signal("content", "templated", 10)]
    return None


CHECK = Check("content", _check, phases=("action:review",))


_CONNECTIVES = re.compile(r"\b(overall|additionally|furthermore|highly recommend|in conclusion|"
                          r"what stands out|by contrast|that about sums it up|would buy again|"
                          r"compared with|value for money|exactly as pictured)\b", re.I)


def looks_generated(text):
    """Toy AI-text detector: 'polished, connective-heavy, no typos, no shouting'.

    Real detectors are better than this, but share its failure mode: careful human writers (and
    non-native speakers who write formally) look 'generated', while a model asked for a casual tone does
    not. A bot signal has to be about the *account and the traffic*, not the prose (W4 Ch6 returns to this).
    """
    words = _WORD.findall(text.lower())
    if len(words) < 12:
        return False
    uniq = len(set(words)) / len(words)
    polished = text[0].isupper() and text.rstrip()[-1] in ".!" and "!!" not in text
    connectives = len(_CONNECTIVES.findall(text))
    lowercase_i = bool(re.search(r"\bi\b", text))
    return polished and not lowercase_i and (connectives >= 1 or uniq > 0.8)
