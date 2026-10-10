"""
Chapter 8: The detection pipeline

    edge attributes + request + session telemetry
        -> sensors (always; cheapest first)
        -> correlation (level >= 3) -> campaign (level >= 4)
        -> decision engine: none (0), veto chain (1), score + ladder (2+)

    Level 0  shadow mode: every sensor runs and logs, nothing is enforced
    Level 1  veto chain:  any layer over its own line blocks       (veto.py)
    Level 2  risk score:  one score, response ladder               (policy.py)
    Level 3  + correlation layer, opaque and deceptive responses   (correlation.py)
    Level 4  + campaign layer and step-up                          (campaign.py)

The pipeline returns a Decision and never touches the response. Turning a
decision into an HTTP response (and choosing how much to tell the client)
is the app's job; see respond() in demo_site/app.py.
"""

import time
from dataclasses import dataclass, field

import campaign
import correlation
import policy
import veto
from sensors import BASE_SENSORS


@dataclass
class Context:
    edge: dict          # resolved by the edge: ip, asn, type, tz, blocklisted
    ja4: str            # from the edge's TLS terminator
    headers: list       # [(name, value)] in arrival order, lab headers removed
    ua: dict            # parsed User-Agent
    telemetry: dict     # features from /telemetry, or None
    form: dict
    counters: object
    sid: str


@dataclass
class Decision:
    signals: dict = field(default_factory=dict)   # {layer: [signal, ...]}
    score: int = 0
    action: str = "allow"                         # allow | pow | step_up | block
    veto_layer: str = None
    ms: float = 0.0

    def reasons(self):
        return [f"[{layer}] {s} (+{policy.WEIGHTS.get(s, 0)})"
                for layer, sigs in self.signals.items() for s in sigs]


def evaluate(ctx, level):
    started = time.perf_counter()
    signals = {sensor.LAYER: sensor.sense(ctx) for sensor in BASE_SENSORS}
    if level >= 3:
        signals[correlation.LAYER] = correlation.sense(ctx)
    if level >= 4:
        signals[campaign.LAYER] = campaign.sense(ctx)

    flat = [s for sigs in signals.values() for s in sigs]
    decision = Decision(signals={k: v for k, v in signals.items() if v},
                        score=policy.score(flat))
    if level == 1:
        decision.action, decision.veto_layer = veto.decide(signals)
    elif level >= 2:
        decision.action, _ = policy.decide(flat)
    decision.ms = (time.perf_counter() - started) * 1000
    return decision
