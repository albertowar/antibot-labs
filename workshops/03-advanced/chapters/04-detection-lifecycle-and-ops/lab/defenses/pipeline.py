"""
The detection pipeline (inherited from W2 Ch8, now operated)

    edge attributes + request + session telemetry
        -> sensors (always; cheapest first)
        -> correlation layer (always: this is the W2 end state)
        -> campaign layer   (when the operator turns it on: config.campaign)
        -> the model        (prod acts, shadow logs, canary acts for a few)
        -> decision engine: one score, one ladder, operator overrides on top

The pipeline returns a Decision and never touches the response. Turning a
decision into an HTTP response is the app's job (demo_site/app.py), and so
is deciding not to enforce it (allowlist.py).

What changed since W2 Ch8: nothing in how a request is judged, everything in
who can change the judging and how fast. Weights, thresholds and the
campaign switch come from config.effective() per request; model roles come
from the registry. Both hot-reload. "Sensors report, engines decide" was the
W2 rule; "operators change engines without deploys" is this chapter's.
"""

import time
from dataclasses import dataclass, field

import campaign
import correlation
import model
import policy
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
    weights: dict = field(default_factory=dict)   # the weights that scored it
    model: dict = field(default_factory=dict)     # {prod|shadow|canary: {version, p, verdict}, acting}
    ms: float = 0.0

    def reasons(self):
        return [f"[{layer}] {s} (+{self.weights.get(s, 0)})"
                for layer, sigs in self.signals.items() for s in sigs]


def evaluate(ctx, cfg):
    """cfg is config.effective(clock): the operator's overrides for this request."""
    started = time.perf_counter()
    signals = {sensor.LAYER: sensor.sense(ctx) for sensor in BASE_SENSORS}
    signals[correlation.LAYER] = correlation.sense(ctx)
    if cfg.get("campaign"):
        signals[campaign.LAYER] = campaign.sense(ctx)
    flat = [s for sigs in signals.values() for s in sigs]
    model_signals, model_info = model.sense(ctx, flat)
    if model_signals:
        signals[model.LAYER] = model_signals
        flat += model_signals

    weights = {**policy.WEIGHTS, **cfg.get("weights", {})}
    action, score = policy.decide(flat, weights, cfg.get("challenge_at"), cfg.get("block_at"))
    # Blunt containment (Round 4): step up a whole exit ASN. It catches a
    # signal-less farm hiding in that ASN, and it challenges every real
    # customer there too. That cost is the point; keep it behind a TTL.
    if cfg.get("stepup_asn") and ctx.edge.get("asn") == cfg["stepup_asn"] and action == "allow":
        action = "step_up"
        signals.setdefault("containment", []).append("asn_stepup")
    decision = Decision(signals={k: v for k, v in signals.items() if v}, score=score,
                        action=action, weights=weights, model=model_info)
    decision.ms = (time.perf_counter() - started) * 1000
    return decision
