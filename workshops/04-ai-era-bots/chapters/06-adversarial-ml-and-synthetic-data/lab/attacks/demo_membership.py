"""
Bonus demo (NOT a judged round): "Did my fleet end up in your training labels?"

Membership inference is a model-extraction cousin. Extraction (Round 1) asks "can I copy your model?";
membership inference asks "was THIS record in the data you trained it on?". A model that was fitted to
a record tends to treat it a little differently from one it has never seen, typically by putting it
further from the decision boundary. Shokri et al. (2017) read that from a model's confidence scores.
Choquette-Choo et al. (2021, "Label-Only Membership Inference Attacks") showed that the allow/refuse bit
is enough: perturb the candidate, and the further you must push before the label flips, the likelier it
was a training record. The store is exactly that oracle: a purchase is allowed or refused, nothing else.

Why a bot author cares. The defender's bot labels come from honeypot hits (defenses/labels.py), so
"my session is in the training set as a bot" means "the defender saw it, labelled it and learned from
it". A fleet that knows which of its configurations were absorbed knows which fingerprints to retire
before the next retrain, without waiting to be blocked. The same fact is a privacy question on the
defender's side: the training set is real customers' sessions (the loyal sign-ins are the human labels),
so if membership can be inferred from the model's answers, the model leaks personal data. Under GDPR a
model can count as personal data when that is possible.

The attack (the attacker's side)
  - Candidates: the baseline headless scalper fleet of the drop day (attacks/round0_baseline.py, seed 1).
    The attacker has its own fleet's configurations (fingerprint, behaviour numbers, browse depth). The
    naive scalpers are left out on purpose: they are one script with one coin flip (the User-Agent), so
    there is nothing per-session for a model to memorise.
  - For each candidate it bisects a line from "the session as it is" (t=0) to "behaviour numbers of a
    typical human" (t=1, mouse, scroll, typing, first input), asking the store at each point whether the
    purchase would go through. The distance to the boundary is the smallest t that flips. Members are
    predicted to sit further away. Any t > 0 also swaps SwiftShader for a real GPU (see humanise()).
  - Only the 200-or-403 of each purchase is read (advlib.verdict). Never X-Lab-Score, never the decision
    log's ml_p / ml_risk: a score API would hand over far more, and this chapter's oracle is decision-only.

What the evaluator knows and the attacker does not
  The membership list (which drop-day sessions were labelled, so the model was FITTED on them) comes
  from the defender's training pipeline (ground_truth()). It is used for exactly two things: to pick the
  candidates (equal numbers of members and non-members, from the SAME fleet and the SAME day, so nothing
  but "was labelled" separates them) and to SCORE the attack afterwards, as the checkpoint scores a round
  with actor labels. The attack itself never sees it.

Two runs, same candidates
  guarded  every query comes from the extractor's own few boxes (advlib.CHEAP_BOXES). Round 1's per-address
           budget (defenses/oracle_guard.py) answers the first few truthfully and then goes constant.
  funded   the queries are spread over 180 datacenter exits (cloud_vm, hosting_asn, free_proxy), a few per
           address, so the budget never fires. This is what a patient attacker with a proxy bill gets.
  Exits stay in the datacenter class on purpose: the bots' own address type is a feature of the model,
  and a residential exit would change the answer for a reason that has nothing to do with membership.

Trade-offs, honestly
  - Small samples: about 33 members and 33 non-members. An AUC then has a standard error near 0.07, so read
    the printed 95% interval, not the point estimate. 0.5 is chance.
  - The advantage (TPR - FPR) is taken at a threshold the attacker could pick without labels (the median
    distance); the AUC needs no threshold. With the guard on, nearly every candidate ties at "never
    flips", so there is no guess to score and TPR = FPR = 0.
  - A replay is not bit-exact: a live session re-measures its own timings and lands in the store's cohort
    windows, so some answers are noise even without a guard.
  - The line is one direction towards a human, searched by bisection. The paper's boundary attacks search
    in all directions; this is a lower bound on what an expert gets.
  - A null result here says "this model, this oracle". It is not a proof that membership cannot leak.

Requires a store (python demo_site/app.py) with the drop-day history, model v2 and the reference oracle
guard installed: python tools/checkpoint.py --round 1 --catch-up builds all three. The script sets
DEFENSE_LEVEL 1 and resets the store itself, and puts the level back afterwards.

Run:
    python attacks/demo_membership.py
    python attacks/demo_membership.py --n 30 --seed 5
"""

import argparse
import dataclasses
import json
import os
import random
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, ".."))
sys.path[:0] = [HERE, LAB]

import advlib  # noqa: E402
import labclient  # noqa: E402  (runs the labnet guard)
import round0_baseline  # noqa: E402
import shopper  # noqa: E402

DROP_STOCK = 20000
FLEET = "headless_scalper"
HISTORY_SEED = 1                         # tools/simulate.py's default: the drop-day fleet
BISECT = 6                               # bisection rounds: the boundary is located to 1/64 of the line
CENSORED = 1.5                           # "still refused when fully human-like": the boundary is out of reach
BEHAVIOR_NUMBERS = ("mouse_moves", "straightness", "speed_cv", "clicks", "keys", "key_cv", "scrolls",
                    "first_input_ms")
# One session at a time against the budget: with concurrent sessions, WHICH probes get the few truthful
# answers would depend on thread scheduling. The funded arm has no budget to race, so it runs 8 at a time.
WORKERS = {"guarded": 1, "funded": 8}
REAL_GPU = {"Win32": shopper.DEVICES["win-nvidia"][1], "Linux x86_64": shopper.DEVICES["linux-intel"][1]}
EXITS = {"guarded": lambda: advlib.cheap_boxes("datacenter"),
         "funded": lambda: (labclient.world_pool("cloud_vm") + labclient.world_pool("hosting_asn")
                           + labclient.world_pool("free_proxy"))}


# ---------------------------------------------------------------- evaluator side (never the attacker)

def training_view():
    """EVALUATOR ONLY. (frame, fitted) for model v2: one row per drop-day purchase attempt, and the sessions
    defenses/baseline_model.py fitted on (the drop wave, weak-labelled). A production attacker has neither."""
    from defenses import features, labels, waves
    hist = waves.for_stage("base")
    df = features.build_dataset(hist, with_cohort=True)
    return df, set(df.loc[labels.weak_labels(df, hist["accounts"]).notna(), "sid"])


def ground_truth(df, fitted):
    """EVALUATOR ONLY. {fleet index: True if that drop-day session was in model v2's training set}, through the
    simulator's answer key (defenses/history.py: lab tooling reads it, no defense and no attack may)."""
    from defenses import history
    seen, in_log = {}, set(df["sid"])
    for sid, actor in history.load_truth().items():
        _, family, index = actor.split(":")
        if family == FLEET and sid in in_log:
            seen[int(index)] = sid in fitted
    return seen


def score_api_control(df, fitted):
    """EVALUATOR ONLY. What a SCORE API would leak on the same question: the AUC of the model's own raw score
    (log-odds) for 'was fitted on' over the fleet's recorded sessions, members against the never-labelled
    ones. No oracle, no replay, no bisection: the best case for the attacker, an upper bound for this model."""
    import numpy as np
    from defenses import models
    from defenses.history import load_truth
    booster, meta = models.load_model(2)
    fleet = {sid for sid, actor in load_truth().items() if actor.split(":")[1] == FLEET}
    rows = df[df["sid"].isin(fleet)]
    raw = booster.predict(rows[meta["features"]], raw_score=True)
    member = rows["sid"].isin(fitted).to_numpy()
    return {"auc": round(float(auc(list(raw), list(member))), 3), "members": int(member.sum()),
            "others": int((~member).sum()), "mean_logit_members": round(float(raw[member].mean()), 3),
            "mean_logit_others": round(float(raw[~member].mean()), 3)}


def pick_candidates(n, seed, view):
    """Equal numbers of members and non-members from the same fleet. Returns [(index, persona, member)]."""
    fleet = [p for p in round0_baseline.personas(150, HISTORY_SEED) if p.persona == FLEET]
    truth = ground_truth(*view)
    rng = random.Random(seed)
    members = sorted(i for i, m in truth.items() if m)
    others = sorted(i for i, m in truth.items() if not m)
    k = min(n, len(members), len(others))
    chosen = [(i, True) for i in rng.sample(members, k)] + [(i, False) for i in rng.sample(others, k)]
    return [(i, fleet[i], m) for i, m in chosen]


# ---------------------------------------------------------------- attacker side

def humanise(persona, t, target):
    """The candidate, `t` of the way towards a typical human's behaviour numbers. t=0 is the candidate.

    Any t > 0 also buys the one fix every cloud fleet buys first: a GPU-backed host instead of the
    SwiftShader software renderer. That tell is checked by the defender's separate human-only anomaly
    detector (defenses/anomaly.py), which never trained on a bot at all, so left in place it would
    mask the supervised model's answer, whoever the candidate is.
    """
    if t == 0 or persona.behavior is None:
        return persona
    mine, out = persona.behavior, dict(persona.behavior)
    for key in BEHAVIOR_NUMBERS:
        a, b = mine.get(key), target.get(key)
        if a is None or b is None:
            out[key] = b if t >= 0.5 else a
        else:
            blend = a + t * (b - a)
            out[key] = round(blend, 3) if isinstance(b, float) else int(round(blend))
    fp = dict(persona.fp)
    if "SwiftShader" in fp["gpu"]:
        fp["gpu"] = REAL_GPU[fp["platform"]]
    return dataclasses.replace(persona, behavior=out, fp=fp)


class Oracle:
    """The store's allow/refuse bit, queried from a ring of exit addresses. Counts queries and spend."""

    def __init__(self, exits, rng, workers):
        self.workers = workers
        self.exits, self.rng, self.sent, self.usd, self.refused = exits, rng, 0, 0.0, 0
        self.target = shopper.desktop_behavior(random.Random(5))       # the "typical human" to move towards

    def ask(self, probes):
        """probes: [(persona, t)]. Returns [1 if refused else 0], in order. Each probe is a fresh session."""
        order = list(range(len(probes)))
        self.rng.shuffle(order)                  # so a budget, if there is one, bites at random
        people = []
        for k, i in enumerate(order):
            persona, t = probes[i]
            # result={} matters: a Persona carries its result dict, and a replace() would share it
            people.append(dataclasses.replace(humanise(persona, t, self.target),
                                              ip=self.exits[(self.sent + k) % len(self.exits)], result={}))
        results = shopper.run_sessions(people, seed=71 + self.sent, workers=self.workers)
        self.sent += len(probes)
        self.usd += sum(r["usd"] for r in results)
        out = [None] * len(probes)
        for i, r in zip(order, results):
            out[i] = advlib.verdict(r)
        self.refused += sum(out)
        return out


def boundary_distance(oracle, candidates):
    """Label-only distance to the decision boundary, per candidate, by bisection along the humanise line.

    Round 0 asks t=0 (the session as is) and t=1 (fully human-like). If t=0 is already allowed the
    candidate is at distance 0; if t=1 is still refused the boundary is out of reach (CENSORED). Otherwise
    each round halves the interval that must contain the flip. The distance is the smallest t known to flip.
    """
    probes = [(p, t) for _, p, _ in candidates for t in (0.0, 1.0)]
    answers = oracle.ask(probes)
    state = []
    for c in range(len(candidates)):
        base, full = answers[2 * c], answers[2 * c + 1]
        state.append({"lo": 0.0, "hi": 1.0, "done": base == 0 or full == 1,
                      "dist": 0.0 if base == 0 else (CENSORED if full == 1 else None)})
    for _ in range(BISECT):
        live = [c for c, st in enumerate(state) if not st["done"]]
        mids = {c: (state[c]["lo"] + state[c]["hi"]) / 2 for c in live}
        for c, refused in zip(live, oracle.ask([(candidates[c][1], mids[c]) for c in live])):
            state[c]["lo" if refused else "hi"] = mids[c]
    return [st["dist"] if st["dist"] is not None else st["hi"] for st in state]


def auc(scores, member):
    """P(a member scores higher than a non-member), ties count half: the threshold-free advantage."""
    pos = [s for s, m in zip(scores, member) if m]
    neg = [s for s, m in zip(scores, member) if not m]
    wins = sum((p > q) + 0.5 * (p == q) for p in pos for q in neg)
    return wins / (len(pos) * len(neg))


def evaluate(scores, candidates, seed):
    """Membership scores (distances) scored against the evaluator's list."""
    member = [m for _, _, m in candidates]
    cut = float(np.median(scores))                      # a threshold the attacker can pick without labels
    guess = [s > cut for s in scores]
    tpr = sum(g and m for g, m in zip(guess, member)) / max(1, sum(member))
    fpr = sum(g and not m for g, m in zip(guess, member)) / max(1, len(member) - sum(member))
    rng = random.Random(seed)
    boots = []
    for _ in range(1000):
        idx = [rng.randrange(len(scores)) for _ in scores]
        if 0 < sum(member[i] for i in idx) < len(idx):
            boots.append(auc([scores[i] for i in idx], [member[i] for i in idx]))
    lo, hi = np.percentile(boots, [2.5, 97.5])
    mean = lambda flag: round(float(np.mean([s for s, m in zip(scores, member) if m == flag])), 3)
    return {"auc": round(auc(scores, member), 3), "auc_ci95": [round(float(lo), 3), round(float(hi), 3)],
            "tpr": round(tpr, 3), "fpr": round(fpr, 3), "advantage": round(tpr - fpr, 3),
            "mean_distance_members": mean(True), "mean_distance_others": mean(False),
            "censored": round(sum(s == CENSORED for s in scores) / len(scores), 3)}


def run_arm(name, candidates, seed):
    labclient.reset(stock=DROP_STOCK)                   # a clean slate: the guard's counters start empty
    exits = EXITS[name]()
    oracle = Oracle(exits, random.Random(seed), WORKERS[name])
    stats = evaluate(boundary_distance(oracle, candidates), candidates, seed)
    stats.update(arm=name, exits=len(exits), queries=oracle.sent, usd=round(oracle.usd, 2),
                 refused_share=round(oracle.refused / oracle.sent, 3), allowed=oracle.sent - oracle.refused)
    return stats


def main():
    parser = argparse.ArgumentParser(description="Label-only membership inference (bonus demo, not judged).")
    parser.add_argument("--n", type=int, default=30, help="candidates per side (capped by the members there are)")
    parser.add_argument("--seed", type=int, default=3)
    args = parser.parse_args()
    labclient.wait_for_store()
    level = labclient.admin("GET", "/lab/status")["level"]
    labclient.set_level(1)
    try:
        view = training_view()
        candidates = pick_candidates(args.n, args.seed, view)
        k = sum(m for _, _, m in candidates)
        print(f"=== Bonus demo: membership inference, label-only -> {labclient.BASE_URL} ===")
        print(f"  {len(candidates)} candidate headless scalpers: {k} fitted on, {len(candidates) - k} never labelled "
              f"(list used only to score)")
        arms = [run_arm(name, candidates, args.seed) for name in ("guarded", "funded")]
    finally:
        labclient.set_level(level)
    control = score_api_control(*view)
    print(f"\n  {'run':<8} {'exits':>5} {'queries':>7} {'refused':>8} {'no flip':>8}  {'AUC [95% CI]':<18} {'TPR':>5} {'FPR':>5} "
          f"{'advantage':>9} {'spend':>7}")
    for a in arms:
        ci = f"{a['auc']:.2f} [{a['auc_ci95'][0]:.2f}, {a['auc_ci95'][1]:.2f}]"
        print(f"  {a['arm']:<8} {a['exits']:>5} {a['queries']:>7} {a['refused_share']:>8.0%} {a['censored']:>8.0%}  {ci:<18} "
              f"{a['tpr']:>5.2f} {a['fpr']:>5.2f} {a['advantage']:>+9.2f} ${a['usd']:>6.2f}")
    print("\n  mean boundary distance (0 = already allowed, 1.5 = never flips): " + "; ".join(
        f"{a['arm']} members {a['mean_distance_members']} vs others {a['mean_distance_others']}" for a in arms))
    print(f"  control (evaluator only, NOT available to the attacker): the model's own score on the "
          f"{control['members']} + {control['others']} recorded sessions,\n"
          f"    AUC {control['auc']:.2f}; mean log-odds {control['mean_logit_members']} (fitted on) "
          f"vs {control['mean_logit_others']} (never labelled)")
    print(json.dumps({"attempted": sum(a["queries"] for a in arms),
                      "succeeded": sum(a["allowed"] for a in arms), "score_api_control": control,
                      "arms": arms}))


if __name__ == "__main__":
    main()
