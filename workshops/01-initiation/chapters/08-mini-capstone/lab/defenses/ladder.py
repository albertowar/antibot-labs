"""
W1 Ch8 — The decision ladder (Section 8.2).

Every layer turns what it sees into Signals on one 0-100 scale. The ladder
adds them up and maps the total to allow / monitor / challenge / block.

Why one scale instead of "any layer may block"?
  - Weak evidence adds up. A slightly odd header (15) on a hosting ASN (25)
    is worth a challenge (40); either alone is not.
  - Strong evidence still wins alone. A honeypot hit (100) blocks by itself.
  - Every decision can be explained: the log lists each signal and its points.

Trade-off: additive scores assume signals are independent. They are not
(a cloud VM is usually also a hosting ASN), so correlated signals
double-count. W2 Ch8 replaces hand-set points with calibrated weights; in
W1 we keep them hand-set and readable.
"""

from dataclasses import dataclass, field

import policy

DECISIONS = ("allow", "monitor", "challenge", "block")


@dataclass
class Signal:
    layer: str          # which layer produced it: "headers", "ip_reputation", ...
    name: str           # what it means: "datacenter", "honeypot_field", ...
    points: int
    detail: str = ""


@dataclass
class RequestContext:
    """Everything a layer may look at. Built once per request by the store."""
    ip: str
    network: dict               # ip_reputation.lookup(ip): asn, org, country, provider
    method: str
    path: str
    host: str
    headers: object             # case-insensitive mapping
    header_names: list          # in the order they arrived
    cookies: dict
    form: dict
    session: object             # session_guard.Session
    redis: object


@dataclass
class Result:
    score: int = 0
    decision: str = "allow"
    signals: list = field(default_factory=list)
    layers: list = field(default_factory=list)
    rate_limited: bool = False
    deceive: bool = False       # caught by a trap: answer with a fake success, not a 403

    def flags(self):
        return [f"{s.layer}:{s.name}" for s in self.signals if s.points or s.name == "rate_limited"]


def decision_for(score):
    """Map a 0-100 score to a band."""
    if score >= policy.BANDS["block"]:
        return "block"
    if score >= policy.BANDS["challenge"]:
        return "challenge"
    if score >= policy.BANDS["monitor"]:
        return "monitor"
    return "allow"


def run_gate(ctx, layers, challenge_enabled):
    """
    Run each layer in order and decide.

    Layers run cheapest first. A rate-limit hit stops the gate immediately:
    there is no point paying for the remaining layers on a request we are
    going to refuse anyway.

    Without a challenge (before Round 4) the challenge band has nowhere to go,
    so it is enforced as a block. That is the cost Round 2 makes visible.
    """
    result = Result()
    for layer in layers:
        result.layers.append(f"{layer.__module__}.{layer.__name__}")
        signals = layer(ctx)
        result.signals.extend(signals)
        if any(s.name == "rate_limited" for s in signals):
            result.rate_limited = True
            result.decision = "block"
            return result

    result.score = min(100, sum(s.points for s in result.signals))
    result.decision = decision_for(result.score)
    result.deceive = any(s.layer == "traps" and s.points >= policy.BANDS["block"] for s in result.signals)
    if result.decision == "challenge" and not challenge_enabled:
        result.decision = "block"
    return result
