"""
Enforcement: what the client learns from a decision (Round 4)

Levels 1 to 3 answer immediately: the purchase goes through, or the gate answers 403. Both answers
come with `X-Lab-Score` (and `X-Lab-Signals`), the gate's teaching-aid headers, and the score is a
gradient: every response is a labeled training example for THE ATTACKER'S search, and
`attacks/round3_oracle_prober.py` follows it. In production you run with LAB_HEADERS=0 and the
answer alone is still an oracle (200 or 403).

Level 4 denies the oracle:
  - ml_check.py scores the session but emits no signal and never blocks: the score is 0 for everyone
  - every purchase gets the same answer: 202 "order received, pending review" (demo_site/ext/ml.py)
  - the real decision is applied at review time, REVIEW_DELAY_S later: a bot's order is quietly
    cancelled and the unit goes back on the shelf

What it costs, honestly:
  - bots hold inventory until review. On a limited drop, that is real damage
  - a real customer who is wrongly cancelled finds out later, by email, which is worse than a
    CAPTCHA now. Support tickets go up
  - it slows a prober down; it does not stop one. A patient attacker batches probes and waits for the
    reviews (`--patient`). You have bought time and made their search cost more, and you have not
    fixed the model
"""

from .features import LAB_TIME_SCALE

# EXERCISE (Round 4): a longer review window slows a patient prober down, but bots hold inventory
# longer and wrongly-cancelled customers wait longer.
REVIEW_DELAY_S = 600  # virtual seconds (10 minutes)


def decide_later(risk, now):
    """The review record kept for one order, written when the purchase is accepted."""
    # TODO (Round 4): return {"block": <did the model want this blocked? risk >= 1.0>,
    #                         "review_at": <when the review runs: now + REVIEW_DELAY_S virtual seconds,
    #                                       and a virtual second is LAB_TIME_SCALE real ones>}
    return {"block": False, "review_at": now}


def state(record, now):
    """What the order is now: 'pending' until the review runs, then 'cancelled' or 'confirmed'."""
    # TODO (Round 4): 'pending' before record["review_at"]; after it, 'cancelled' if the record says
    # block, else 'confirmed'.
    return "confirmed"
