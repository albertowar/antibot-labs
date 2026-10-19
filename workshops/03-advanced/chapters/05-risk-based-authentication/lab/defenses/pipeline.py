"""
The engine: Signal, Verdict, Check and run().

Every check turns what it sees into Signals on one 0-100 scale, or into a hard
Verdict. The engine adds the points up and policy.decide() maps the sum to
allow / monitor / challenge / block. One scale, because:
  - weak evidence adds up: an odd header (15) from a hosting ASN (25) earns a
    challenge (40); either alone does not;
  - strong evidence still wins alone: a honeypot hit (100) blocks by itself;
  - every decision can be explained: the log lists each signal and its points.

Order matters for cost, not for the verdict. A hard verdict (rate_limit, block,
deceive) stops the gate, so put the cheap, certain checks first.

Levels: ladder.LADDER[k] runs enforced when k <= DEFENSE_LEVEL. Higher levels
run in shadow when LAB_SHADOW=1 (logged, never enforced), which is how you
measure a new layer's false positives before turning it on.

Trade-off baked in here: additive scores assume independent signals. They are
not (a cloud VM is usually also a hosting ASN). W2 Ch8 replaces the sum with
calibrated weights; the starter keeps it readable.
"""

import inspect
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

HARD_ACTIONS = ("rate_limit", "block", "deceive")
ACTIONS = ("allow", "monitor", "challenge") + HARD_ACTIONS

# How bad each action is for the client, worst last. The gate reports the most severe
# decision of a request (X-Lab-Verdict, the log's `action`), not the highest-scoring one:
# a 429 from a zero-score rate limit must not read "allow" because an earlier pass
# accumulated points (contract 1.7).
SEVERITY = {"allow": 0, "monitor": 1, "challenge": 2, "rate_limit": 3, "deceive": 4, "block": 5}


@dataclass(frozen=True)
class Signal:
    layer: str              # which check produced it: "headers", "ip_reputation", ...
    name: str               # what it means: "datacenter", "honeypot_field", ...
    points: int = 0
    detail: str = ""

    def flag(self):
        return f"{self.layer}:{self.name}"


@dataclass(frozen=True)
class Verdict:
    action: str = "allow"
    score: int = 0
    signals: tuple = ()
    challenge: Optional[str] = None     # challenge type to serve when action == "challenge"
    retry_after: int = 0                # seconds, for rate_limit


@dataclass(frozen=True)
class Check:
    name: str
    fn: Callable
    phases: tuple = ("request",)        # "request" | "action:<name>" | "action:*" | "response" | "ws:*"
    shadow: bool = False                # force shadow regardless of level

    def applies(self, phase):
        for p in self.phases:
            if p == phase or p == "*":
                return True
            if p.endswith("*") and phase.startswith(p[:-1]):
                return True
        return False


@dataclass
class Decision:
    action: str = "allow"
    score: int = 0
    signals: list = field(default_factory=list)
    checks: list = field(default_factory=list)       # [(name, ms)]
    shadow: list = field(default_factory=list)       # signals from shadow checks
    challenge: Optional[str] = None
    retry_after: int = 0
    hard_by: Optional[str] = None                    # check that short-circuited

    def flags(self):
        return [s.flag() for s in self.signals if s.points or s.layer == "rate_limit" or s.name in ("hard", "trap")]

    def shadow_flags(self):
        return [s.flag() for s in self.shadow if s.points]


def _normalise(check, out):
    """A check may return None, an iterable of Signals, or a Verdict."""
    if out is None:
        return Verdict()
    if isinstance(out, Verdict):
        if out.action not in HARD_ACTIONS and out.score and not out.signals:
            # A soft verdict's points only count through its signals, so a bare
            # Verdict("challenge", 40) would sum to 0 and decide "allow". Carry the
            # points as one synthesized signal instead (contract 1.7).
            return Verdict(out.action, out.score, (Signal(check.name, out.action, out.score, "verdict"),),
                           out.challenge, out.retry_after)
        return out
    sigs = tuple(out)
    return Verdict(action="allow", score=sum(s.points for s in sigs), signals=sigs)


_WANTS_CTX = {}


def _decide(policy, score, signals, level, ctx):
    """Call policy.decide, passing ctx only when the override's signature takes it."""
    fn = policy.decide
    key = id(fn)
    if key not in _WANTS_CTX:
        try:
            params = inspect.signature(fn).parameters
            _WANTS_CTX[key] = "ctx" in params or any(p.kind == p.VAR_KEYWORD for p in params.values())
        except (TypeError, ValueError):
            _WANTS_CTX[key] = False
    if _WANTS_CTX[key]:
        return fn(score, signals, level, ctx=ctx)
    return fn(score, signals, level)


def run(phase, ctx, ladder, level, shadow_enabled=False, shadow_names=(), policy=None):
    """Run every applicable check for `phase`. Returns a Decision."""
    from . import policy as default_policy
    policy = policy or default_policy
    d = Decision()
    ctx.phase, ctx.level = phase, level
    for k in sorted(ladder):
        enforced = k <= level
        if not enforced and not shadow_enabled:
            continue
        for check in ladder[k]:
            if not check.applies(phase):
                continue
            is_shadow = (not enforced) or check.shadow or check.name in shadow_names
            t0 = time.perf_counter()
            try:
                v = _normalise(check, check.fn(ctx))
            except Exception as e:                      # a broken check must never take the store down
                v = Verdict(signals=(Signal(check.name, "error", 0, repr(e)),))
            d.checks.append((check.name, (time.perf_counter() - t0) * 1000))
            if is_shadow:
                d.shadow.extend(v.signals)
                if v.action in HARD_ACTIONS:
                    d.shadow.append(Signal(check.name, v.action, 100, "shadow hard verdict"))
                continue
            d.signals.extend(v.signals)
            if v.action in HARD_ACTIONS:
                d.action, d.hard_by, d.retry_after = v.action, check.name, v.retry_after
                d.score = 100 if v.action != "rate_limit" else d.score
                if not v.signals:
                    d.signals.append(Signal(check.name, "hard", 0, v.action))
                return d
            if v.challenge and not d.challenge:
                d.challenge = v.challenge
    d.score = min(100, sum(s.points for s in d.signals))
    d.action = _decide(policy, d.score, d.signals, level, ctx)
    if d.action == "challenge" and not d.challenge:
        d.challenge = policy.DEFAULT_CHALLENGE
    return d
