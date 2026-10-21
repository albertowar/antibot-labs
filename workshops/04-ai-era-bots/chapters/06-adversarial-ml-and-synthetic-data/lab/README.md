# W4 Ch6 Lab: Adversarial ML & Synthetic Data

Starts from: `workshops/04-ai-era-bots/starter/` (contract 1.7). Adds: see the block below.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/anomaly.py`
- `defenses/augment.py`
- `defenses/baseline_model.py`
- `defenses/cohort.py`
- `defenses/features.py`
- `defenses/history.py`
- `defenses/labels.py`
- `defenses/ml_check.py`
- `defenses/models.py`
- `defenses/oracle_guard.py`
- `defenses/provenance.py`
- `defenses/retrain.py`
- `defenses/robust_train.py`
- `defenses/train.py`
- `defenses/waves.py`
- `demo_site/ext/ml.py`
- `demo_site/ext/ml_store.py`
- `demo_site/ext/templates/ml/honeypot.html`
- `tools/analyst.py`
- `tools/audit.py`
- `tools/ml_setup.py`
- `tools/personas_ch6.py`
- `tools/shopper.py`
- `tools/simulate.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `demo_site/templates/account.html`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`,
  which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service
  URLs such as `REDIS_URL` too). The store's edge accepts the lab headers only from loopback.
- Source addresses are rented from `data/world.json` (documentation ranges), never invented, never real. No public
  proxy lists, no third-party sites, no real users or credentials.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and
  container images.

## Setup

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python tools/doctor.py
python demo_site/app.py
```

## Rounds

| Round | Defense (level) | Attack | Expected |
|---|---|---|---|
| 0 | None, log only (level 0): the bare store, labels audited (`tools/audit.py`) | `attacks/round0_baseline.py`: naive and headless scalpers | baseline 90–100% succeed; 0 wrong weak labels covering 20–85% of bots; 0 customers refused |
| 1 | `defenses/oracle_guard.py`: per-address query budget in front of model v2 (level 1) | `attacks/round1_extract.py`: cheap extractor, then `--patient` (rotating exits) | baseline ≤10%; cheap clone finds ≤50% of the allowed region, patient clone ≥90%; ≤6 of 200 customers refused |
| 2 | `defenses/robust_train.py`: adversarial training plus monotone constraints, model v3 (level 2) | `attacks/round2_evade.py`: evasion crafted from the cloned surrogate | baseline ≤10%, evade ≤20%; ≤10 of 200 customers refused |
| 3 | `defenses/provenance.py`: sanitized training set, model v4 (level 3) | `attacks/round3_poison.py`: honeypot-label availability poison aimed at privacy-browser users | baseline ≤10%, evade ≤20%; privacy-browser customers refused ≤15%; ≤10 of 200 refused. **Currently fails the evade budget from a fresh environment (see Known issue below)** |
| 4 | `defenses/augment.py`: SMOTE for the rare class, model v5 (level 4) | `attacks/round4_rareclass.py`: the slow mobile reseller | baseline ≤10%, evade ≤20%, reseller ≤25%; privacy-browser ≤15%; ≤12 of 200 refused. **Currently fails the reseller budget from a fresh environment (see Known issue below)** |

## Bonus demo: membership inference (not judged)

Extraction asks whether the attacker can copy your model. Membership inference asks whether a given session was
in the data you trained it on: "did my fleet end up in your training labels?" A bot author who knows that knows
which fingerprints to retire before the next retrain. On the defender's side the same question is a privacy one,
because the training set is real customers' sessions. `attacks/demo_membership.py` runs a *label-only* version
of the attack (Choquette-Choo et al., 2021) against the Round 1 model: for each candidate it bisects a line from
"the session as it is" to "typical human behaviour", reads only the allow or refuse bit, and takes the distance
to the flip as the membership score (members are expected to sit further from the boundary). It is **not a
round**: `tools/checkpoint.py` does not run it, judge it or count it, and it needs nothing beyond Round 1.

```bash
python tools/checkpoint.py --round 1 --catch-up   # history, model v2 and the reference guard (skip if you have them)
python demo_site/app.py                           # in another terminal
python attacks/demo_membership.py                 # about 3 minutes
python tools/checkpoint.py --restore              # puts your own oracle_guard.py back
```

The candidates are the 30 drop-day headless scalpers whose sessions got a weak label (so model v2 was fitted on
them) and 30 from the same fleet and the same day that never did. The membership list comes from the training
pipeline and is used only to pick the candidates and to score the result afterwards, like the checkpoint scores
a round with the actor labels; the attack never sees it. The script runs twice over the same candidates:
`guarded` sends every query from the extractor's own four boxes (Round 1's guard is in the way), `funded`
spreads them over 180 datacenter exits so the budget never fires.

Measured on 2026-10-18 (fresh history, model v2 trained by `--catch-up`; three runs gave identical output, and
`first_input_s` carries 96% of the model's gain in this history too):

| Run | Exits | Queries | Refused | Candidates that never flip | AUC (95% interval) | TPR / FPR | Spend |
|---|---|---|---|---|---|---|---|
| guarded | 4 | 210 | 93% | 75% | 0.45 (0.33–0.56) | 0.00 / 0.00 | $0.10 |
| funded | 180 | 480 | 44% | 0% | 0.46 (0.32–0.61) | 0.40 / 0.47 | $0.23 |

Mean distance to the boundary (0 = already allowed, 1.5 = never flips): funded, fitted-on 0.278 against
never-labelled 0.282. The evaluator-only control line (the model's own score, not available to an attacker) reads
AUC 0.34 to 0.38 (two histories), mean log-odds 8.336 against 8.339 to 8.342. The attack's own numbers were
identical on both.

**The honest read.**

- **Membership is not inferable from this oracle.** An AUC of 0.5 is chance, and both intervals contain it. The
  funded attacker pays for 480 queries and learns nothing about who was in the labels (advantage -0.07, which is
  noise). Nothing was tuned to make the attack look better or worse.
- **Why the guard "works" here, and why that is not the lesson.** With four boxes the budget answers about two
  dozen probes truthfully and then goes constant, so 75% of candidates never flip and there is nothing to rank.
  But the funded run finds nothing either, so the guard is blunting a measurement that had no signal to give.
  Against a model that did leak, the same budget would be doing real work. It is still the control that
  decides who gets to ask 480 questions.
- **Why there is nothing to read.** Model v2 is, in effect, one threshold. `first_input_s` carries 96% of its
  gain and the main split sits at 0.271 s; the scripted fleet's first input is 30–120 ms whether or not a
  honeypot coin-flip made a session a training row. The bisection lands at t≈0.28 for both groups, which is
  exactly where the blend crosses 0.271 s. A model that decides on one threshold that generalises has memorised
  nothing about individual sessions.
- **What a score API would change, measured.** The control reads the model's raw score on the recorded sessions
  and gets AUC 0.34 to 0.38, but both groups sit at log-odds 8.34 and differ by at most 0.006. That AUC is ranking third-decimal
  differences, which line up with the sessions that visited the honeypot (they load more assets), not with
  memorisation, and it points the wrong way for an overfitting leak. A score API would not have helped the
  attacker on this model. It would on a model with something to memorise.
- **Limits.** This is one small, saturated model, trained on 278 labelled rows of near-identical scripted
  bots, queried along one direction with 30 candidates per side. A production model on thousands of
  heterogeneous customer sessions, with high-cardinality features and deeper trees, has far more to memorise.
  Read the result as "this model, this oracle", never as "decision-only answers are safe".

## Expected results (self-check)

Generated from `python tools/verify.py --all --catch-up --markdown` (against your own store:
`python tools/checkpoint.py --all --markdown`) on 2026-10-15, Linux x86_64 (WSL2), Python 3.12,
LightGBM 4.7, contract 1.7, in-process Redis, fresh history. Success percentages for the model
rounds move a few points between fresh histories (the features embed measured timings); judge
against the budget column, not the exact figure.

| Round | Level | Attackers (succeeded) | Budget | Customers refused |
|---|---|---|---|---|
| 0 | 0 | baseline 100% | 90–100% (nothing enforced) | 0/200 |
| 1 | 1 | baseline 0% · extract cheap 5% · extract patient 26% | ≤10% · ≤10% · 10–60% | 1/200 |
| 2 | 2 | baseline 5% · evade 8% | ≤10% · ≤20% | 10/200 |

**Known issue (Rounds 3–4).** On a freshly generated history the sanitized (v4) and augmented
(v5) models can miss their budgets (measured 2026-10-15: round 3's evade 52% vs ≤20%; round 4's
reseller 100% vs ≤25%) — the same fresh-environment training fragility recorded for W2 Ch7,
whose pipeline this chapter extends. The rounds still demonstrate their attacks and defenses;
their PASS gates are honest only on the history they were tuned against. The defect and fix
direction are in [`../TODO.md`](../TODO.md).
