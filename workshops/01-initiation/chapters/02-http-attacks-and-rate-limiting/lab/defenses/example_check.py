"""
A worked example of a check. Not wired; copy it to start a chapter's defense.

A check receives a Ctx and returns one of:
    None                      nothing to say
    [Signal(...), ...]        evidence, on the 0-100 scale; the engine adds it up
    Verdict(action=...)       a hard answer that stops the gate (rate_limit, block, deceive),
                              or a challenge request: Verdict("challenge", 40, challenge="pow")

Docstrings in a real check say what it catches, what it misses, and who it
hurts (its false-positive profile). That is the part students read.
"""

from .pipeline import Check, Signal


def _check(ctx):
    signals = []
    if ctx.ua.is_library:
        signals.append(Signal("example", "library_ua", 15, ctx.ua.raw[:40]))
    if ctx.header("Accept-Language") is None:
        signals.append(Signal("example", "no_accept_language", 10))
    return signals


CHECK = Check("example", _check)
