"""
Weak labels: where "bot" and "human" come from

Nobody hands you a labeled dataset. You assemble one from signals that are high-precision but
low-coverage:

  bot    = the session hit a honeypot (the hidden /archive link or the robots-disallowed
           /partner-feed endpoint, W1 Ch7)
  human  = the session signed in to a long-standing account
           (>= 3 past orders, account older than 90 days)
  manual = analyst decisions in data/history/manual_labels.jsonl (Round 2:
           tools/label_cluster.py writes them). Manual labels win.
  everything else is UNLABELED and is left out of training.

Bias you are signing up for:
  - Bot labels only cover bots dumb enough to touch a honeypot. The model learns "what
    honeypot-hitting bots look like", not "what bots look like".
  - Human labels only cover loyal, signed-in customers. Privacy-browser and VPN users rarely sign
    in, so the model barely sees them, and your false-positive estimate is measured on the users
    least likely to be false positives.
  - Account takeover poisons the human label: a stuffed credential (W2 Ch6) turns a bot session
    into a "loyal customer".

`python tools/audit.py labels` compares these labels with the simulator's answer key. That file
only exists in the lab. Use it to see the bias, never to train.
"""

import numpy as np
import pandas as pd

from . import history

LOYAL_MIN_ORDERS = 3
LOYAL_MIN_AGE_DAYS = 90


def loyal_accounts(accounts):
    return {a["account"] for a in accounts if a["orders"] >= LOYAL_MIN_ORDERS and a["age_days"] >= LOYAL_MIN_AGE_DAYS}


def weak_labels(df, accounts, manual=True):
    """Return a Series: 1 = bot, 0 = human, NaN = unlabeled."""
    loyal = loyal_accounts(accounts)
    label = pd.Series(np.nan, index=df.index)
    label[df["account"].isin(loyal)] = 0
    label[df["honeypot_hits"] > 0] = 1          # a honeypot hit beats a login
    if manual:
        analyst = history.manual_labels()
        hit = df["sid"].isin(analyst)
        label[hit] = df.loc[hit, "sid"].map(analyst).astype(float)
    return label
