"""
Chapter 9 — L3 session and account model (W2 Ch7), enabled at DEFENSE_LEVEL >= 3

By Round 3 the attacker's browser is coherent (Camoufox) and its cursor
moves like a hand (humanize=True). What the browser can't fake is the
*account*: a scalper needs one account per pair, so a farm registers dozens
of fresh accounts that ship to the same reshipper address. This layer feeds
browser, behavior and account features into one model:

    account_age_days, prior_orders     fresh accounts with no history
    addr_accounts_24h                  other accounts shipping to this address (normalized)
    l1_points, l2_points               what the rule layers thought, even in shadow mode
    n_moves, n_keys, n_touches, ...    behavior volume
    dwell_ms, pages_seen               how the session got here

Model: scikit-learn HistGradientBoostingClassifier. It handles missing values
and the interactions that additive points can't express ("fresh account" is
fine on its own; "fresh account + reused address + 2 s session" is not).
tools/train_model.py trains it from the decisions table and picks the
threshold with pick_threshold() below.

Where it fails:
  - Labels: the model learns whatever your labels say. Here they come from
    the lab's own traffic generators. In production they come late and noisy
    (chargebacks, manual review, honeypots), and a model trained on last
    month's bots misses this month's.
  - Real first-time customers have fresh accounts too.
  - Account takeover hands the attacker aged accounts with order history
    (Round 4).
"""

import os
import re

import joblib
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "instance", "session_model.joblib")
FEATURES = [
    "account_age_days", "prior_orders", "addr_accounts_24h", "email_digits",
    "l1_points", "l2_points", "n_moves", "n_clicks", "n_keys", "n_touches",
    "dwell_ms", "pages_seen", "has_telemetry",
]
UNIT = re.compile(r"\b(apt|apartment|unit|suite|ste|flat|fl|floor|rm|room|#)\s*\.?\s*[\w-]+", re.I)


def normalize_address(address):
    """'12 Dock Rd, Apt 7B' and '12 dock rd #19' are the same reshipper."""
    a = UNIT.sub(" ", (address or "").lower())
    a = re.sub(r"#\s*[\w-]+", " ", a)
    a = re.sub(r"[^a-z0-9 ]", " ", a)
    return " ".join(a.split())


def build_features(sess, user, l1_points, l2_points):
    events = sess["events"] or {}
    page_views = [t for t, path in sess["flow"] if path == sess["page"]]
    local = user["email"].split("@")[0]
    return {
        "account_age_days": round(user["account_age_days"], 4),
        "prior_orders": user["prior_orders"],
        "addr_accounts_24h": user["addr_accounts_24h"],
        "email_digits": sum(ch.isdigit() for ch in local),
        "l1_points": l1_points,
        "l2_points": l2_points,
        "n_moves": len(events.get("moves", [])),
        "n_clicks": len(events.get("clicks", [])),
        "n_keys": len(events.get("keys", [])),
        "n_touches": len(events.get("touches", [])),
        "dwell_ms": (sess["now_ms"] - page_views[-1]) if page_views else None,
        "pages_seen": len(sess["flow"]),
        "has_telemetry": int(sess["events"] is not None),
    }


def vectorize(rows):
    return np.array([[np.nan if r.get(f) is None else float(r[f]) for f in FEATURES] for r in rows])


def load_model(path=MODEL_PATH):
    if not os.path.exists(path):
        return None
    return joblib.load(path)


def score_session(features, model):
    if model is None:
        return 0, []
    p_bot = float(model["model"].predict_proba(vectorize([features]))[0, 1])
    t = model["threshold"]
    if p_bot >= t:
        return 60, [f"Session model: p(bot)={p_bot:.2f} >= threshold {t:.2f}"]
    if p_bot >= t / 2:
        return 30, [f"Session model: p(bot)={p_bot:.2f}, above half the threshold ({t:.2f})"]
    return 0, []


def pick_threshold(y_true, p_bot, max_fpr=0.01):
    """
    Choose the decision threshold on a validation set.

    y_true  1 = bot, 0 = human
    p_bot   the model's predicted bot probability for each row
    max_fpr the share of humans you are willing to challenge or block

    TODO (Round 3): 0.5 is a default, not a policy. Return the LOWEST
    threshold whose false-positive rate on the humans in this validation set
    is <= max_fpr. That catches as many bots as the FP budget allows.
    Hint: sort the humans' scores; the threshold must sit above all but
    floor(max_fpr * n_humans) of them.
    """
    return 0.5


if __name__ == '__main__':
    print(normalize_address("12 Dock Rd, Apt 7B, Newark NJ"))
    print(normalize_address("12 dock rd #19 newark nj"))
    print(pick_threshold(np.array([0, 0, 0, 1]), np.array([0.1, 0.2, 0.3, 0.9])))
