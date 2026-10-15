"""
Round 2: Drift

Health (health.py) watches what the sensors *say*. Drift watches what they
*see*: the distribution of each input, this week against a reference week.
Two tests, both on numbers you already log per decision:

  Population Stability Index (PSI), from credit scoring. Bin the reference
  values (10 quantile bins), count how the current values fall into the
  same bins, and sum (cur% - ref%) * ln(cur% / ref%). Rules of thumb that
  the whole industry inherited without a proof: < 0.1 quiet, 0.1-0.2 look,
  > 0.2 act. For a 0/1 signal the "bins" are just the two values, and PSI
  becomes a one-number summary of "how much more often does this fire".

  Two-sample Kolmogorov-Smirnov: the largest gap between the two empirical
  CDFs, with the asymptotic p-value. Scale-free and threshold-free, which
  is why monitoring products default to it, and sensitive to sample size
  in the way PSI is not: on ten thousand rows everything "drifts".

Also here: corpus freshness. The header-order corpus, the JA4 table and the
IP->ASN database are *data*, and data has a date. A sensor whose data is
older than the world it judges does not degrade loudly; it starts charging
the wrong people (Round 2's stale IP range).

Neither test says why. A PSI of 0.4 on `header_order_mismatch` is a browser
release, a bot wave, or a broken sensor, and the drift report's job is to
make you look *this week* instead of in the quarterly review.
"""

import math
from collections import defaultdict

import numpy as np

import report as _lab  # noqa: F401  (puts the lab root on sys.path and runs the labnet guard)

from defenses import corpus  # noqa: E402  (the lab root is on sys.path once report/labclient is imported)

# TODO (Round 2): the thresholds everyone copies. Keep them, or tie
# "act" to the known-good false-positive rate instead? Then decide which
# features earn a line in the report; too many and nobody reads it.
PSI_WARN, PSI_ACT = 0.10, 0.20
KS_P = 0.01
CORPUS_MAX_AGE_WEEKS = 2
NUMERIC = ["score", "pointer_events", "straightness", "interval_std_ms", "keystrokes", "model_p"]


def psi(reference, current, bins=10, eps=1e-4):
    reference, current = np.asarray(reference, float), np.asarray(current, float)
    if len(reference) == 0 or len(current) == 0:
        return 0.0
    if len(np.unique(reference)) <= 2:   # a 0/1 signal, or a constant
        edges = np.array([-np.inf, 0.5, np.inf])
    else:
        edges = np.unique(np.quantile(reference, np.linspace(0, 1, bins + 1)))
        edges[0], edges[-1] = -np.inf, np.inf
    ref = np.histogram(reference, edges)[0] / len(reference) + eps
    cur = np.histogram(current, edges)[0] / len(current) + eps
    ref, cur = ref / ref.sum(), cur / cur.sum()
    return float(np.sum((cur - ref) * np.log(cur / ref)))


def ks(reference, current):
    """Two-sample KS: (D, asymptotic p-value)."""
    a, b = np.sort(np.asarray(reference, float)), np.sort(np.asarray(current, float))
    if len(a) == 0 or len(b) == 0:
        return 0.0, 1.0
    grid = np.concatenate([a, b])
    cdf_a = np.searchsorted(a, grid, side="right") / len(a)
    cdf_b = np.searchsorted(b, grid, side="right") / len(b)
    d = float(np.max(np.abs(cdf_a - cdf_b)))
    en = math.sqrt(len(a) * len(b) / (len(a) + len(b)))
    lam = (en + 0.12 + 0.11 / en) * d
    p = 2 * sum((-1) ** (k - 1) * math.exp(-2 * k * k * lam * lam) for k in range(1, 101))
    return d, float(min(max(p, 0.0), 1.0))


def columns(entries):
    """{feature: np.array} for one week's decisions: numerics plus every signal as 0/1."""
    out = defaultdict(list)
    signals = sorted({s for e in entries for sigs in e["signals"].values() for s in sigs})
    for e in entries:
        tel = e.get("tel") or {}
        out["score"].append(e["score"])
        for k in ("pointer_events", "straightness", "interval_std_ms", "keystrokes"):
            v = tel.get(k)
            out[k].append(-1.0 if v is None else v)
        p = (e.get("model") or {}).get("prod", {}).get("p")
        if p is not None:
            out["model_p"].append(p)
        present = {s for sigs in e["signals"].values() for s in sigs}
        for s in signals:
            out[s].append(1.0 if s in present else 0.0)
    return {k: np.array(v) for k, v in out.items()}


def report(entries, ref_week, cur_week):
    by_week = defaultdict(list)
    for e in entries:
        by_week[e.get("week", 0)].append(e)
    ref, cur = columns(by_week.get(ref_week, [])), columns(by_week.get(cur_week, []))
    rows = []
    for name in sorted(set(ref) | set(cur), key=lambda n: (n not in NUMERIC, n)):
        a, b = ref.get(name, np.array([])), cur.get(name, np.array([]))
        value = psi(a, b)
        d, p = ks(a, b)
        status = "ACT" if value >= PSI_ACT else "look" if value >= PSI_WARN else ""
        rows.append({"feature": name, "psi": value, "ks_d": d, "ks_p": p, "status": status,
                     "ref_mean": float(a.mean()) if len(a) else None,
                     "cur_mean": float(b.mean()) if len(b) else None})
    return rows


def corpus_ages(week):
    """{corpus: age in weeks}: how old is the data each sensor leans on?"""
    built = corpus.snapshot().get("built_week", 0)
    refreshed = corpus.updates().get("refreshed_week", {})
    return {name: week - refreshed.get(name, built) for name in ("asn_database", "header_order", "ja4_table")}
