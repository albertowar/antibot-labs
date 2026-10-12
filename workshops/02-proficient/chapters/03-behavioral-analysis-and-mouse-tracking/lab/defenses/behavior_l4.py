"""
Chapter 3, Layer 4: layout jitter & replay signatures (Section 3.6, Round 4).

Layers 1-3 ask "does this look human?" A replayed human recording *is*
human, so it passes all of them. Commercial tooling does this today:
Camoufox's `humanize` replays one of ~2,000 recorded human cursor traces,
reshaped to fit the start and end points.

Two defenses, two different replay styles:

    rule                        points  catches
    click outside its target    70      forged sensor payloads: the recording's click
                                        coordinates don't match where THIS session drew
                                        the button (layout jitter: behavior.new_layout)
    replayed typing             70      the hold and gap of every keystroke match another
                                        session's within a few ms (median over >= 12 keys)
    replayed path               70      an approach whose fine-grained wobble correlates
                                        > 0.995 with an approach of another session

Signatures (behavior_features.path_signature, behavior_features.key_signature) don't depend
on where the page drew things, so a recording warped onto a new layout
keeps them. Typing is the stronger fingerprint: two people never hold 20
keys for the same milliseconds. Path wobble is weaker: smooth human paths
look alike once normalised. Measured on 60,000 pairs of synthetic humans,
the closest independent pair correlated 0.989; replays through Playwright
correlate 0.996+ with their source. That margin is thin, so the bar is high.

Trade-offs:
    - Memory and cost: we compare against the last 2,000 sessions by brute
      force, and the checkpoint shows the time grow. Production systems use
      locality-sensitive hashing and per-signature counters with a TTL.
    - "First use is free": a recording the store has never seen passes. This
      catches reuse, so it works against scale (one template, many sessions),
      not against a single replay. The attacker answer is a big corpus or a
      generative model; the defender answer is signals the attacker can't
      record (Section 3.9).
    - False positives: identical automation also matches itself (every
      `keyboard.type(delay=100)` bot types the same way). Two independent
      people essentially never do; check with tools/humans.py.

Enabled for POST /drop/<sku> (action:drop_buy) when DEFENSE_LEVEL >= 4. The page
jitters its layout from Level 4 on (demo_site/ext/behavior.py).
"""

from . import behavior
from .pipeline import Check

PATH_CORR = 0.995
MIN_PATH_MATCHES = 1
MIN_KEYS = 12
HOLD_MS, GAP_MS = 6, 8


def _corr(a, b):
    return sum(x * y for x, y in zip(a, b)) / len(a)


def _median(values):
    values = sorted(values)
    n = len(values)
    return values[n // 2] if n % 2 else (values[n // 2 - 1] + values[n // 2]) / 2


def typing_matches(mine, other):
    n = min(len(mine), len(other))
    if n < MIN_KEYS:
        return False
    return (_median([abs(mine[k][0] - other[k][0]) for k in range(n)]) <= HOLD_MS
            and _median([abs(mine[k][1] - other[k][1]) for k in range(n)]) <= GAP_MS)


def path_matches(mine, other):
    """How many of my approaches have a near-identical wobble in `other`."""
    return sum(1 for a in mine if any(_corr(a, b) > PATH_CORR for b in other))


def score_replay(features, ctx=None):
    """[(points, name, reason)]. `ctx` gives the store's memory of other sessions; offline there is none."""
    if features is None:
        return []
    reasons = []
    outside = [c for c in features["clicks"] if c.get("inside") is False]
    if outside:
        c = outside[0]
        reasons.append((70, "click_outside", f"Click outside its target: '{c['target']}' clicked "
                                            f"{c['center_offset']:.0f} px from its centre"))

    if ctx is None:
        return reasons
    mine = features["signature"]
    typed = path = None
    for other_sid, other in behavior.recent_signatures(ctx.redis, ctx.session.sid):
        if typed is None and typing_matches(mine["keys"], other["keys"]):
            typed = other_sid
        if path is None and path_matches(mine["paths"], other["paths"]) >= MIN_PATH_MATCHES:
            path = other_sid
        if typed and path:
            break
    if typed:
        reasons.append((70, "replayed_typing", f"Replayed typing: every keystroke timed like session {typed[:8]}…"))
    elif path:
        reasons.append((70, "replayed_path", f"Replayed path: approaches match session {path[:8]}…"))
    return reasons


CHECK = Check("behavior_l4", lambda ctx: behavior.signals("l4", score_replay(behavior.features(ctx), ctx)),
              phases=("action:drop_buy",))
