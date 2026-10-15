# 06-adversarial-ml-and-synthetic-data: lab

Starts from: `workshops/04-ai-era-bots/starter/` (contract 1.7). Adds: see the block below.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `data/surrogate_patient.json`
- `data/surrogate_patient.txt`
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
