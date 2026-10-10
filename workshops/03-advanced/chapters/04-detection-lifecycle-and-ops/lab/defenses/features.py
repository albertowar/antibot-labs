"""
Chapter 4 (W3): One feature function for training and for serving

The model sees exactly what the rules see, plus the four numbers the
behaviour sensor thresholds, plus the edge's network type. Nothing else:

    every signal name            0/1, from the sensors and the correlation layer
    pointer_events, straightness, interval_std_ms, keystrokes
                                 the raw telemetry numbers (W2 Ch3), -1 when absent
    has_telemetry                0/1
    edge_<type>                  one-hot of residential / mobile / datacenter / tor / unknown

The same function builds the vector from a live request (defenses/model.py)
and from a decision-log line (defenses/train.py). That is the whole point:
the most common way a model "drifts" the day it ships is that training and
serving computed a feature differently. W2 Ch7 made the same rule.

Deliberately absent: anything only the lab knows (actor, pool, cluster key),
anything that is the *verdict* (action, score), and the model's own signals.
"""

import correlation
from sensors import BASE_SENSORS

SIGNALS = [s for module in BASE_SENSORS for s in module.SIGNALS] + list(correlation.SIGNALS)
NUMERIC = ["pointer_events", "straightness", "interval_std_ms", "keystrokes"]
EDGE_TYPES = ["residential", "mobile", "datacenter", "tor", "unknown"]
COLUMNS = SIGNALS + NUMERIC + ["has_telemetry"] + [f"edge_{t}" for t in EDGE_TYPES]


def telemetry_numbers(t):
    """The four numbers we log per decision, or None."""
    if not t:
        return None
    return {k: t.get(k) for k in NUMERIC}


def vector(signals, tel, edge_type):
    """signals: flat list of signal names; tel: telemetry_numbers() or None;
    edge_type: the edge's ASN type. Returns a list aligned with COLUMNS."""
    present = set(signals)
    row = [1 if s in present else 0 for s in SIGNALS]
    for k in NUMERIC:
        v = (tel or {}).get(k)
        row.append(-1.0 if v is None else float(v))
    row.append(1 if tel else 0)
    row += [1 if edge_type == t else 0 for t in EDGE_TYPES]
    return row


def from_log(entry):
    """The same vector, from a decision-log line (see tools/report.py)."""
    flat = [s for sigs in entry["signals"].values() for s in sigs
            if s in SIGNALS]  # drops model_* and campaign_cluster on purpose
    return vector(flat, entry.get("tel"), entry.get("edge_type", "unknown"))
