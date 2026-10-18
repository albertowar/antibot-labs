"""
rba_score (Round 2): how unusual is this login for THIS account? A per-user likelihood ratio.

The model is the one Freeman et al. published from LinkedIn's login data (NDSS 2016). For each
feature k of the login (the remembered device, the ASN, the country, the browser), compare how
often the value is seen across everyone (the attacker is assumed to draw from the population) with
how often this account has used it:

    llr_k = log( p(x_k) / p(x_k | user) )          score = sum of llr_k  (+ a reputation prior)

with the smoothing that keeps one unseen value from being infinitely suspicious:

    p(x)        = (count(x) + 1) / (total + V_k)            V_k: distinct values of feature k seen
    p(x | user) = (count_u(x) + ALPHA * p(x)) / (N_u + ALPHA)

`hist` is the account's counters and `glob` the population's, both {"<feature>:<value>": n,
"_n": logins} (demo_site/ext/rba.py loads them; tools/calibrate.py builds the same offline).

Then band(): low (step down, no prompt), medium (emailed code) or high (refuse), from
policy.RBA_BANDS, and never "low" for an account with fewer than policy.RBA_COLD_START logins.

Check your work offline before you run the round: `python tools/calibrate.py` prints every cohort
member's and attacker's score and band, and the friction they add up to.

Reference: solutions/round2/defenses/rba_score.py (or `checkpoint.py --round 2 --catch-up`)
"""

import math  # noqa: F401  (math.log)

from . import policy

FEATURES = ("dev", "asn", "cc", "ua")


def _vocab(glob, k):
    """V_k: the number of distinct values of feature k in the population, plus one for 'unseen'."""
    return sum(1 for key in glob if key.startswith(k + ":")) + 1


def llr(k, value, hist, glob):
    # TODO (Round 2): return log(p(x) / p(x | user)) for feature k with the smoothing above.
    #   pg = (glob.get(f"{k}:{value}", 0) + 1) / (glob["_n"] + _vocab(glob, k))
    #   pu = (hist.get(f"{k}:{value}", 0) + policy.RBA_ALPHA * pg) / (hist.get("_n", 0) + policy.RBA_ALPHA)
    return 0.0


def score(features, hist, glob, net_type=""):
    """(total, parts): the login's risk score and each feature's contribution, for the log."""
    parts = {k: llr(k, features[k], hist, glob) for k in FEATURES}
    rep = policy.RBA_REPUTATION.get(net_type, 0.0)
    if rep:
        parts["net"] = rep
    return sum(parts.values()), parts


def band(total, hist):
    # TODO (Round 2): "high" at or above policy.RBA_BANDS["high"]; "medium" at or above
    #   policy.RBA_BANDS["medium"], or whenever hist["_n"] < policy.RBA_COLD_START (no baseline to
    #   step down from); otherwise "low".
    return "low"
