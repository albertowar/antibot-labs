"""
Chapter 9 — Train the L3 session model (Section 9.6, Round 3)

The model needs labelled sessions. In production the labels come late and
noisy (chargebacks, review, honeypots). In the lab we make them the honest
way the chapter can afford: run the people and the bots through the store
and read the decisions table.

    humans:  tools/legit_traffic.py, a few passes
    bots:    the Round 1–3 attacks (headless Patchright, Camoufox, humanized
             farm), captured while the store runs with the model OFF so their
             features are recorded without being blocked by L3

It pulls the feature vectors back from /admin/decisions, fits a
HistGradientBoostingClassifier, picks a threshold with
defenses/session_model.pick_threshold (the Round 3 TODO), and saves
instance/session_model.joblib. Deterministic given the seeds, but it does
drive real browsers, so it takes a few minutes.

Run (store at DEFENSE_LEVEL 0 or 1 so nothing is blocked while labelling):
    python tools/train_model.py
    python tools/train_model.py --quick     # fewer bot sessions, for a fast rebuild
"""

import argparse
import importlib
import os
import sys

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))
sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))

import legit_traffic  # noqa: E402
import session_model  # noqa: E402
from lab import admin, ensure_local, server_status  # noqa: E402

MODEL_PATH = os.path.join(LAB_DIR, "instance", "session_model.joblib")


def collect(quick):
    """Run humans and bots through the store; return (features, label) with 1 = bot."""
    ensure_local()
    admin("POST", "/admin/reset?decisions=1")
    human_passes = 2 if quick else 3
    for _ in range(human_passes):
        legit_traffic.run(include_mine=False)
    human_sids = {r["sid"] for r in collect_sids("buy") if r}

    bot_specs = [("inherited_patchright", {"sessions": 2 if quick else 4}),
                 ("inherited_camoufox", {"sessions": 2 if quick else 4}),
                 ("inherited_humanized_farm", {"sessions": 2 if quick else 3})]
    bot_sids = set()
    for name, kwargs in bot_specs:
        module = importlib.import_module(name)
        bot_sids.update(module.run(**kwargs)["sids"])

    rows = admin("GET", "/admin/decisions?action=buy&limit=100000")
    X, y, seen = [], [], set()
    for r in rows:
        sid = r["sid"]
        if sid in seen or not r.get("features"):
            continue
        if sid in bot_sids:
            label = 1
        elif sid in human_sids:
            label = 0
        else:
            continue
        seen.add(sid)
        X.append([np.nan if r["features"].get(f) is None else float(r["features"][f])
                  for f in session_model.FEATURES])
        y.append(label)
    return np.array(X), np.array(y)


def collect_sids(action):
    return admin("GET", f"/admin/decisions?action={action}&limit=100000")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    try:
        server_status()
    except Exception:
        sys.exit("Demo store not reachable. Start it at DEFENSE_LEVEL 0 or 1 first.")

    print("Collecting labelled sessions (this drives real browsers; give it a few minutes)...")
    X, y = collect(args.quick)
    n_bot, n_human = int(y.sum()), int((y == 0).sum())
    print(f"  {n_human} human + {n_bot} bot sessions")
    if n_bot < 4 or n_human < 8:
        sys.exit("Too few sessions to train. Is the store at a level that blocks them (use 0 or 1)?")

    X_tr, X_val, y_tr, y_val = train_test_split(X, y, test_size=0.4, random_state=0, stratify=y)
    # min_samples_leaf defaults to 20, which can't split a lab-sized training
    # set (~40 rows), so the model would just predict the base rate. Lower it.
    model = HistGradientBoostingClassifier(max_depth=4, learning_rate=0.2, max_iter=200,
                                           min_samples_leaf=5, l2_regularization=1.0, random_state=0)
    model.fit(X_tr, y_tr)

    p_val = model.predict_proba(X_val)[:, 1]
    threshold = session_model.pick_threshold(y_val, p_val, max_fpr=0.01)
    tp = int(((p_val >= threshold) & (y_val == 1)).sum())
    fp = int(((p_val >= threshold) & (y_val == 0)).sum())
    recall = tp / max(1, int((y_val == 1).sum()))
    fpr = fp / max(1, int((y_val == 0).sum()))
    print(f"  threshold {threshold:.3f}: bot recall {recall:.0%}, human FPR {fpr:.0%} on validation")

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump({"model": model, "threshold": float(threshold), "features": session_model.FEATURES}, MODEL_PATH)
    print(f"✅ Saved {os.path.relpath(MODEL_PATH, LAB_DIR)}")
    print("   Reload it: restart the store, or `curl -k -X POST .../admin/reload-model` with the admin key.")
    try:
        admin("POST", "/admin/reload-model")
        print("   (reloaded in the running store)")
    except Exception:
        pass


if __name__ == '__main__':
    main()
