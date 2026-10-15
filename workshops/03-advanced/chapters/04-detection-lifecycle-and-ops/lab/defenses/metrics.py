"""
What the store exposes to Prometheus

The defender's view of the defender's own system, and nothing else. There is
deliberately no "is this a bot" label here: production has no ground truth,
and a metric that needs one is a metric you will never have. What you can
measure without truth:

    signal_fired_total{signal}            how often each sensor speaks
    decisions_total{action}               what the engine did: allow / pow / step_up / block
    logins_total{cred}                    the business metric that catches what sensors miss:
                                          valid / wrong_password / unknown_user
    known_good_signal_total{signal}       signals fired on the known-good cohort (your
                                          monitors and QA accounts): the only false-positive
                                          rate you can measure live, and a biased one
    known_good_total                      size of that cohort, for the rate
    model_score{role}                     histogram of model output per role (prod/shadow/canary)
    shadow_verdicts_total{prod,shadow}    the agreement matrix between production and shadow
    pipeline_seconds                      what detection costs per login
    corpus_age_weeks{corpus}              how stale the data a sensor depends on is

Rates are Prometheus' job (rate(), increase()), so everything here is a
counter, a gauge or a histogram, never a precomputed percentage.

Scraped by Prometheus at /metrics (docker compose --profile monitoring; demo_site/ext/ops.py serves
it) and readable with curl, so the lab works with or without Docker.
"""

from prometheus_client import (CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest)

signal_fired = Counter("signal_fired_total", "Times each detection signal fired", ["signal"])
decisions = Counter("decisions_total", "Decisions by action", ["action"])
logins = Counter("logins_total", "Login attempts by credential outcome", ["cred"])
known_good_total = Counter("known_good_total", "Logins from the known-good cohort")
known_good_signal = Counter("known_good_signal_total",
                            "Signals fired on the known-good cohort (live false positives)", ["signal"])
model_score = Histogram("model_score", "Model probability per role", ["role"],
                        buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
shadow_verdicts = Counter("shadow_verdicts_total", "Production verdict vs shadow verdict",
                          ["prod", "shadow"])
pipeline_seconds = Histogram("pipeline_seconds", "Pipeline time per login",
                             buckets=[0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1])
corpus_age = Gauge("corpus_age_weeks", "Lab weeks since this data source was refreshed", ["corpus"])


def observe_decision(signals, action, known_good, model_info, gate_ms):
    """One scored sign-in (the first attempt, not the retry after a solved challenge).
    signals: {layer: [name, ...]}; action: allow | pow | step_up | block."""
    for names in signals.values():
        for s in names:
            signal_fired.labels(signal=s).inc()
            if known_good:
                known_good_signal.labels(signal=s).inc()
    if known_good:
        known_good_total.inc()
    decisions.labels(action=action).inc()
    pipeline_seconds.observe(gate_ms / 1000)
    for role in ("prod", "shadow", "canary"):
        info = (model_info or {}).get(role)
        if info:
            model_score.labels(role=role).observe(info["p"])
    if (model_info or {}).get("prod") and model_info.get("shadow"):
        shadow_verdicts.labels(prod=model_info["prod"]["verdict"],
                               shadow=model_info["shadow"]["verdict"]).inc()


def observe_login(cred):
    """The password outcome, once the route has checked it: valid | wrong_password | unknown_user."""
    logins.labels(cred=cred).inc()


def render():
    return generate_latest(), CONTENT_TYPE_LATEST
