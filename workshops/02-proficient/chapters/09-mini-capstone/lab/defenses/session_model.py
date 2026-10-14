"""
session_model (Round 3): the session and account model. Enabled at DEFENSE_LEVEL >= 4.

By Round 3 the attacker's browser is coherent (Camoufox) and its cursor moves like a hand
(humanize=True). What the browser cannot fake is the ACCOUNT: a scalper needs one account per pair, so a
farm registers dozens of fresh accounts that ship to the same reshipper address. This layer feeds
account, session and behavior features into one model:

    account_age_days, prior_orders     a fresh account with no history
    addr_accounts                      accounts that signed up with this shipping address (24 h)
    session_age_s, dwell_ms            how long the session had been alive, how long the page was open
    n_pointer, submit_ms               how much the hand did, how long the form took (Chapter 3's features)
    software_gpu                       the sensor report's renderer is software (Chapter 1's signal)

It is the capstone's OWN code: W2 Ch7's scorer reads a per-session request log that this store does not
keep, so its module cannot be copied without that whole pipeline. The idea is Ch7's; the features are
this chapter's.

Model: scikit-learn HistGradientBoostingClassifier. It handles missing values (a guest has no account) and
the interactions an additive score cannot say: "fresh account" is fine on its own (every customer was new
once); "fresh account AND an address shared with ten others AND a three-second form" is not.

Training data: tools/train_data.py-style rows generated here (`synthetic_rows`), from a fixed seed. The
labels are the lab's own: in production they arrive late and noisy (chargebacks, manual review, honeypots)
and a model trained on last month's bots is already a little behind this month's. Two engineering details:

  - Small data breaks defaults. HistGradientBoostingClassifier will not split a node below
    min_samples_leaf (default 20); on a small training set it never splits and silently predicts the base
    rate: a model that looks trained and detects nothing. Try `python -m defenses.session_model --rows 40
    --leaf 20` (one distinct score for everybody) against `--leaf 5`. The shipped generator is big enough
    for the default; MIN_SAMPLES_LEAF = 5 is the number you reach for when yours is not.
  - The threshold is a policy, not a default. pick_threshold() returns the LOWEST threshold whose
    false-positive rate on a validation set of humans stays under policy.MODEL_MAX_FPR.

Where it fails: real first-time customers have fresh accounts too (the lab's first-timer is one);
account takeover hands the attacker AGED accounts with order history (Round 4); and the model is only as
good as the bots in its training data.
"""

import random
import re
import time

import numpy as np

from . import policy
from .pipeline import Check, Signal

FEATURES = ["account_age_days", "prior_orders", "addr_accounts", "session_age_s", "dwell_ms",
            "n_pointer", "submit_ms", "software_gpu"]
MIN_SAMPLES_LEAF = 5          # the default (20) never splits on a few hundred rows
ADDR_TTL_S = 24 * 3600
UNIT = re.compile(r"\b(apt|apartment|unit|suite|ste|flat|fl|floor|rm|room|#)\s*\.?\s*[\w-]+", re.I)
_MODEL = {}


# --- the account side: addresses ------------------------------------------------------------------

def normalize_address(address):
    """'12 Dock Rd, Apt 7B' and '12 dock rd #19' are the same reshipper."""
    a = UNIT.sub(" ", (address or "").lower())
    a = re.sub(r"#\s*[\w-]+", " ", a)
    a = re.sub(r"[^a-z0-9 ]", " ", a)
    return " ".join(a.split())


def record_address(redis, user_id, address):
    """Remember that this account signed up shipping to this address."""
    norm = normalize_address(address)
    if not norm:
        return
    redis.set(f"lab:acct:addr:{user_id}", norm, ex=ADDR_TTL_S)
    redis.sadd(f"lab:addr:{norm}", str(user_id))
    redis.expire(f"lab:addr:{norm}", ADDR_TTL_S)


def addr_accounts(ctx):
    """How many accounts signed up with this account's address in the last 24 h (1 = nobody else)."""
    uid = ctx.user.id
    norm = ctx.redis.get(f"lab:acct:addr:{uid}")
    if not norm:
        return 1
    return max(1, int(ctx.redis.scard(f"lab:addr:{norm}")))


# --- the features -------------------------------------------------------------------------------

def build_features(ctx):
    from . import behavior, sensor
    from demo_site.models import Order
    user = ctx.user
    sig = sensor.report(ctx) or {}
    renderer = ((sig.get("webgl") or {}).get("renderer") or "").lower()
    beh = behavior.features(ctx) or {}
    viewed = ctx.session.get("drop_view_ms")
    feats = {
        "account_age_days": None, "prior_orders": None, "addr_accounts": None,
        "session_age_s": round(ctx.session.age_seconds, 1),
        "dwell_ms": (int(time.time() * 1000) - int(viewed)) if viewed else None,
        "n_pointer": beh.get("n_pointer"), "submit_ms": beh.get("submit_ms"),
        "software_gpu": int(any(w in renderer for w in ("swiftshader", "llvmpipe", "basic render", "software"))),
    }
    if user is not None:
        from demo_site.models import utcnow
        feats["account_age_days"] = round((utcnow() - user.created_at).total_seconds() / 86400, 4)
        feats["prior_orders"] = Order.query.filter_by(user_id=user.id).count()
        feats["addr_accounts"] = addr_accounts(ctx)
    return feats


def vectorize(rows):
    return np.array([[np.nan if r.get(f) is None else float(r[f]) for f in FEATURES] for r in rows])


# --- training data (the lab's labels) -----------------------------------------------------------

def synthetic_rows(n_humans=1100, n_bots=300, seed=11):
    """
    Rows [(features, is_bot)] drawn from the distributions the lab's shoppers and farm produce.

    Humans: mostly aged accounts with history, one address each. Some are first-timers (a fresh account is
    normal: every customer was new once), a few are guests, a few use software rendering.
    Bots: a farm account (fresh, no orders, many accounts on one address); a few are guests and a few have
    already aged an account (the stolen accounts of Round 4).

    The farm is HUMANIZED (Round 3): its dwell, session length, form time and pointer volume come from the
    same distributions as the humans'. An attacker that has beaten Round 2 leaves the model nothing to read
    in the session, only the account, and that overlap is the lesson. (Production has the opposite problem:
    the bots' behavior is almost never identical, and a model happily learns the differences of last
    month's bots.)
    """
    rng = random.Random(seed)

    def session(gpu_rate):
        return {"session_age_s": rng.uniform(15, 900), "dwell_ms": rng.uniform(4000, 60000),
                "n_pointer": rng.choice([0, rng.randint(8, 60), rng.randint(60, 900)]),
                "submit_ms": rng.uniform(6000, 40000), "software_gpu": int(rng.random() < gpu_rate)}

    rows = []
    for _ in range(n_humans):
        kind = rng.random()
        guest, first_timer = kind < 0.05, 0.05 <= kind < 0.17
        rows.append(({
            "account_age_days": None if guest else (rng.uniform(0, 0.05) if first_timer else rng.uniform(1, 900)),
            "prior_orders": None if guest else (0 if first_timer else rng.choice([0, 1, 2, 3, 4, 6, 9])),
            "addr_accounts": None if guest else (1 if rng.random() < 0.95 else 2), **session(0.05)}, 0))
    for _ in range(n_bots):
        guest, aged = rng.random() < 0.08, rng.random() < 0.05
        rows.append(({
            "account_age_days": None if guest else (rng.uniform(30, 300) if aged else rng.uniform(0, 0.05)),
            "prior_orders": None if guest else (rng.choice([0, 1]) if aged else 0),
            "addr_accounts": None if guest else (1 if aged else rng.randint(2, 30)), **session(0.15)}, 1))
    rng.shuffle(rows)
    return rows


def pick_threshold(y_true, p_bot, max_fpr=policy.MODEL_MAX_FPR):
    """
    The LOWEST decision threshold whose false-positive rate on the humans of a validation set is at most
    max_fpr. 0.5 is a default, not a policy: the real question is "how many real customers am I willing to
    challenge to catch more bots?". The humans' scores sorted, the threshold sits just above all but
    floor(max_fpr * n_humans) of them.
    """
    humans = np.sort(np.asarray(p_bot)[np.asarray(y_true) == 0])
    allowed = int(max_fpr * len(humans))
    cut = humans[len(humans) - allowed - 1] if len(humans) > allowed else 0.0
    return float(min(0.99, max(0.01, np.nextafter(cut, 1.0))))


def train(seed=11, rows=None, leaf=MIN_SAMPLES_LEAF):
    """Train on the generator's rows (all of them, or the first `rows`), hold a quarter out to pick the threshold."""
    from sklearn.ensemble import HistGradientBoostingClassifier
    data = synthetic_rows(seed=seed)[: rows or None]
    split = int(len(data) * 0.75)
    X, y = vectorize([r for r, _ in data]), np.array([b for _, b in data])
    model = HistGradientBoostingClassifier(max_iter=120, learning_rate=0.1, min_samples_leaf=leaf, random_state=7)
    model.fit(X[:split], y[:split])
    held_out = model.predict_proba(X[split:])[:, 1]
    return {"model": model, "threshold": pick_threshold(y[split:], held_out), "held_out": held_out}


def load_model():
    if not _MODEL:
        m = train()
        _MODEL.update(model=m["model"], threshold=m["threshold"])
    return _MODEL


# --- the check ---------------------------------------------------------------------------------

def _check(ctx):
    m = load_model()
    feats = build_features(ctx)
    p_bot = float(m["model"].predict_proba(vectorize([feats]))[0, 1])
    t = m["threshold"]
    ctx.note(model_p_bot=round(p_bot, 3), model_threshold=round(t, 3),
             model_features={k: (None if v is None else round(v, 2)) for k, v in feats.items()})
    if p_bot >= t:
        return [Signal("session_model", "p_bot", policy.MODEL_BLOCK_POINTS, f"p(bot)={p_bot:.2f} >= threshold {t:.2f}")]
    if p_bot >= t / 2:
        return [Signal("session_model", "p_bot_half", policy.MODEL_CHALLENGE_POINTS,
                       f"p(bot)={p_bot:.2f}, above half the threshold ({t:.2f})")]
    return None


CHECK = Check("session_model", _check, phases=("action:drop_buy",))


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Train the model and look at it")
    ap.add_argument("--rows", type=int, default=None, help="train on this many generated rows (default: all 1400)")
    ap.add_argument("--leaf", type=int, default=MIN_SAMPLES_LEAF, help="min_samples_leaf (the library default is 20)")
    a = ap.parse_args()
    m = train(rows=a.rows, leaf=a.leaf)
    farm = {"account_age_days": 0.0, "prior_orders": 0, "addr_accounts": 3, "session_age_s": 30.0, "dwell_ms": 10000,
            "n_pointer": 170, "submit_ms": 8000, "software_gpu": 0}
    first_timer = dict(farm, addr_accounts=1)
    p = lambda f: float(m["model"].predict_proba(vectorize([f]))[0, 1])
    print(f"rows {a.rows or 1400}, min_samples_leaf {a.leaf}: threshold {m['threshold']:.3f}, "
          f"{len(set(m['held_out'].round(6)))} distinct held-out scores, "
          f"p(farm account) {p(farm):.3f}, p(first-timer) {p(first_timer):.3f}")
    print(normalize_address("12 Dock Rd, Apt 7B, Newark NJ"), "|", normalize_address("12 dock rd #19 newark nj"))
