"""
Chapter 7 — Enforcement: what the client learns from a decision (Round 4, Section 7.5)

Levels 1–3 answer immediately: 200 with an order, or 403. They also echo
`risk` in the body, a "teaching aid" that is really a gift to the attacker.
Every response is a labeled training example for THEIR search, and
`risk` is a gradient they can follow (attacks/round3_oracle_prober.py).

Level 4 denies the oracle:
  - every checkout gets the same answer: 202 "order received, pending review"
  - no score, no reason, same body and timing for allowed and blocked sessions
  - the real decision is applied at review time, REVIEW_DELAY_S later, and
    the bot's order is quietly cancelled

What it costs, honestly:
  - bots hold inventory until review. On a limited drop, that is real damage
  - a real customer who is wrongly cancelled finds out later, by email,
    which is worse than a CAPTCHA now. Support tickets go up
  - it slows a prober down; it does not stop one. A patient attacker
    batches probes and waits for the reviews (`--patient`). You have bought
    time and made their search cost more, and you have not fixed the model
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from store import LAB_TIME_SCALE  # noqa: E402

# TODO (Round 4): a longer review window slows a patient prober down, but
# bots hold inventory longer and wrongly-cancelled customers wait longer.
REVIEW_DELAY_S = 600  # virtual seconds (10 minutes)


def respond(level, risk, order_id):
    """Return (http_status, body, order_status, review_at)."""
    blocked = risk >= 1.0
    if level >= 4:
        review_at = time.time() + REVIEW_DELAY_S * LAB_TIME_SCALE
        body = {"order_id": order_id, "status": "pending",
                "message": "Order received. We'll email you a confirmation shortly."}
        return 202, body, "pending", review_at
    if level == 0 or not blocked:
        body = {"order_id": order_id, "status": "confirmed"}
        if level > 0:
            body["score"] = round(risk, 3)  # teaching aid; never do this in production
        return 200, body, "confirmed", None
    return 403, {"error": "blocked", "score": round(risk, 3)}, "blocked", None


def review_status(order):
    """What /orders/<id> shows: pending until the review runs."""
    if order["status"] != "pending":
        return order["status"]
    if time.time() < order["review_at"]:
        return "pending"
    return "cancelled" if order["decision"] == "block" else "confirmed"
