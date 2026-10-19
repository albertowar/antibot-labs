"""
rba_score (Round 2): how unusual is this login for THIS account? A per-user likelihood ratio.

The model is the one Freeman et al. published from LinkedIn's login data (NDSS 2016). For each
feature k of the login (the remembered device, the ASN, the country, the browser), compare how
often the value is seen across everyone (the attacker is assumed to draw from the population) with
how often this account has used it:

    llr_k = log( p(x_k) / p(x_k | user) )          score = sum of llr_k  (+ a reputation prior)

A value the account uses all the time and almost nobody else does (its own remembered laptop)
scores strongly negative: that is the step-down. A value the account has never used scores
log((N + ALPHA) / ALPHA) whatever it is, where N is the account's history length: a long history
makes novelty more surprising, a short one less. Smoothing is what keeps one unseen value from
being infinitely suspicious:

    p(x)        = (count(x) + 1) / (total + V_k)            V_k: distinct values of feature k seen
    p(x | user) = (count_u(x) + ALPHA * p(x)) / (N_u + ALPHA)

Two additions the paper's estimator does not have, because p(x) is a poor stand-in for the
attacker on two points:

  * a reputation prior: a datacenter network (defenses/netinfo.py) adds REPUTATION points, since
    real customers rarely sign in from one and credential replay usually does;
  * cold start: an account with fewer than MIN_HISTORY logins has no baseline to step down from,
    so it is never "low" (policy.RBA_COLD_START).

What it misses: anything the attacker can copy. The remembered-device cookie is a bearer token, so
a stealer log that carries it buys the step-down (this round's attacker). And a residential proxy
in the victim's own ISP looks like home (`residential_proxy` shares Example Broadband's ASN).

Who it hurts: anyone whose login is new to the account: a new laptop, cleared cookies, a hotel in
another country, a VPN, a shared family laptop. They land in the medium band and answer an emailed
code. tools/calibrate.py shows the band of every cohort member and attacker for the thresholds in
policy.py; choose them against the friction budget, not by eye.
"""

import math

from . import policy

FEATURES = ("dev", "asn", "cc", "ua")


def _vocab(glob, k):
    return sum(1 for key in glob if key.startswith(k + ":")) + 1


def llr(k, value, hist, glob):
    """log p(x_k) / p(x_k | user) for one feature, with the smoothing above."""
    total = glob.get("_n", 0)
    pg = (glob.get(f"{k}:{value}", 0) + 1) / (total + _vocab(glob, k))
    n_u = hist.get("_n", 0)
    pu = (hist.get(f"{k}:{value}", 0) + policy.RBA_ALPHA * pg) / (n_u + policy.RBA_ALPHA)
    return math.log(pg / pu)


def score(features, hist, glob, net_type=""):
    """(total, parts): the login's risk score and each feature's contribution, for the log."""
    parts = {k: llr(k, features[k], hist, glob) for k in FEATURES}
    rep = policy.RBA_REPUTATION.get(net_type, 0.0)
    if rep:
        parts["net"] = rep
    return sum(parts.values()), parts


def band(total, hist):
    """low (step down: no prompt), medium (step up: emailed code) or high (refuse)."""
    if total >= policy.RBA_BANDS["high"]:
        return "high"
    if total >= policy.RBA_BANDS["medium"] or hist.get("_n", 0) < policy.RBA_COLD_START:
        return "medium"
    return "low"
