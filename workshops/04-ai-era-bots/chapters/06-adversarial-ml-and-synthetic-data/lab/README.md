# Chapter 7 Lab: Machine Learning for Bot Detection

**Format:** 4 rounds of attack ⚔️ defend plus a data round, ~125 min of lab (including a 10-min break) inside the 3-hour chapter. See `../chapter_07_content.md`, §7.6.

It is drop day at the demo store: a limited sneaker release. You play both sides. As the **defender**, you train a model on the store's event log and switch it on at checkout. As the **attacker**, you run the bot that beats it. Every round ends with a checkpoint that reports bots caught *and* real customers blocked.

> ⚠️ **Rules of engagement.** Run these scripts only against the local demo site. Every client goes through `tools/labnet.py`, which refuses any `DEMO_URL` that is not `localhost`. Residential proxies, VPNs and carriers are *simulated* with private address ranges. No lab traffic goes through a real proxy or anyone else's infrastructure. All users, accounts and fingerprints are synthetic.

```
lab/
  README.md              this file
  requirements.txt       pinned Python dependencies
  docker-compose.yml     PostgreSQL on 127.0.0.1:5432 (optional: SQLite works too)
  demo_site/app.py       the store: event logging, scoring at /checkout, DEFENSE_LEVEL 0–4
  defenses/
    store.py             event tables (sessions, requests, telemetry, logins, accounts, orders)
    netinfo.py           simulated ASN database for the private lab prefixes
    features.py          session features: ONE function for training and serving
    cohort.py            population features (Round 2)
    labels.py            weak labels + `--audit` against lab ground truth
    train.py             LightGBM v1/v2 + logistic-regression baseline, threshold from an FPR budget
    explain.py           TreeSHAP explanations via LightGBM `pred_contrib`
    anomaly.py           device-claim likelihood model on verified humans (Round 3)
    scorer.py            what /checkout runs inline; combines model + anomaly
    enforcement.py       what the client learns from a decision (Round 4)
  attacks/
    round0_baseline.py   naive + headless scalpers (the bots you already know)
    round1_humanized.py  human-like behavior, one stealth profile, residential exits
    round2_farm.py       a randomized fingerprint per session
    round3_oracle_prober.py  black-box search over bot configurations
  tools/
    labnet.py            localhost guard, simulated proxy pools, lab time
    shopper.py           the shopping-session engine shared by users and bots
    simulate.py          a drop day: 600 real users in six cohorts + baseline bots
    label_cluster.py     analyst triage: label fingerprint clusters (Round 2)
    scoreboard.py        both sides of every round
    checkpoint.py        per-round check, --catch-up, --reset
  data/                  truth.jsonl (simulator ground truth), manual_labels.jsonl
  artifacts/             model_v*.txt/.json, anomaly_v3.json, reference_features.parquet
```

**Why Python only:** everything in this chapter is server-side. The work is feature extraction from logs, model training and inline scoring, and Python's data and ML stack (pandas, scikit-learn, LightGBM) is the standard tool for it. The browser-side collectors that produce the telemetry were built in W2 Ch3 and W2 Ch4. Here the simulators send the same summaries directly, so no browser is needed.

---

## Setup (before the session)

```bash
cd lab
docker compose up -d --wait                 # PostgreSQL on 127.0.0.1:5432
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

**No Docker?** Use SQLite. Export it once in **every** terminal you use, and run every command from `lab/`:

```bash
export DATABASE_URL=sqlite:///ml_lab.db
```

Start the store (terminal 1) and check it from another (terminal 2):

```bash
DEFENSE_LEVEL=0 python demo_site/app.py     # http://localhost:5000
curl -s localhost:5000/lab/status           # level, model, row counts
```

| `DEFENSE_LEVEL` | At `/checkout` | Needs |
|---|---|---|
| 0 | log only, every order confirmed | – |
| 1 | model v1 (per-session features) | `artifacts/model_v1.*` |
| 2 | model v2 (+ cohort features) | `artifacts/model_v2.*` |
| 3 | v2 + anomaly detector, `risk = max(p/t, a/t_a)` | + `artifacts/anomaly_v3.json` |
| 4 | level 3 scoring, deferred enforcement: 202 for everyone, cancel at review | same as 3 |

A checkout is blocked when `risk ≥ 1.0`. At levels 1–3 the response includes `score` (the risk). That is a **teaching aid, and a deliberate mistake**: Round 3 exploits it and Round 4 removes it.

Models hot-reload when their files change, so retraining doesn't need a restart. Changing `DEFENSE_LEVEL` does.

**Lab time.** Simulated users think for seconds between pages. `LAB_TIME_SCALE=0.02` (the default) sleeps 2% of that, and the server divides every measured gap by the same factor. A drop day of 900 sessions takes about 1–2 minutes. Don't change it between runs.

**Troubleshooting**

| Problem | Fix |
|---|---|
| Port 5000 taken (macOS AirPlay Receiver) | `PORT=5050 DEFENSE_LEVEL=… python demo_site/app.py` and `export DEMO_URL=http://localhost:5050` |
| `connection refused` on 5432 | `docker compose ps` should say `healthy`; or switch to SQLite |
| Tools see no data, but the site has data | Different databases: both must use the same `DATABASE_URL`, run from `lab/` |
| Checkout returns 503 `model not trained` | Train the model for that level, or `python tools/checkpoint.py --round N --catch-up` |
| `⚠️ N sessions failed with transport errors` | The site was restarted or overloaded mid-run. Re-run the step |
| Start over completely | `python tools/checkpoint.py --reset`, then restart the site |

---

## How to measure a round

Every round ends with:

```bash
python tools/checkpoint.py --round N
```

It sends 200 fresh simulated customers mixed with every attack so far, then prints both sides:

```text
=== Checkpoint: Round 3 (server at DEFENSE_LEVEL=3, scoring {'anomaly_threshold': 4.0781, 'fpr_budget': 0.01, 'model': 'v2', 'threshold': 0.7032}) ===

Sending 300 sessions (200 real users + attacks so far)...
Running the oracle prober (probe, then exploit)...
  prober: 6 probe sessions, chose fingerprint=purchased behavior=humanized pool=datacenter browse=0

Bot traffic                         checkouts succeeded
  ✅ round0_baseline              0/40 (0%)      expected: ≤ 5%
  ✅ round1_humanized             2/30 (7%)      expected: ≤ 10%
  ✅ round2_farm                  1/30 (3%)      expected: ≤ 15%
  ✅ round3_oracle_prober         30/30 (100%)   expected: gets through

Real users (simulated cohorts)      blocked or cancelled
     desktop                      0/80 (0%)
     keyboard_only                0/15 (0%)
     mobile_cgnat                 0/54 (0%)
     power_user                   0/22 (0%)
     privacy_browser              0/14 (0%)
     vpn                          0/15 (0%)
  ✅ total 0/200 (0%)   (budget ≤ 4%)

Defender cost
  ML scoring: median 98.5 ms, p95 269.4 ms per checkout

Attacker cost (simulated)
  round0_baseline              $   0.01 total · no successful checkout
  round1_humanized             $   1.01 total · $0.51 per successful checkout
  round2_farm                  $   0.97 total · $0.97 per successful checkout
  round3_oracle_prober         $  17.01 total · $0.57 per successful checkout

✅ Round 3 checkpoint passed.
```

- **Bot traffic:** share of each attack's checkouts that succeeded, against the expected result.
- **Real users:** customers blocked (or cancelled at review), **per cohort**. A defense that blocks real users must show up as a cost. The checkpoint fails if the total exceeds the round's budget.
- **Defender cost:** scoring latency from `Server-Timing: mlscore`.
- **Attacker cost:** simulated proxy and fingerprint spend per successful checkout.

Ground truth (who is really a bot) comes from `data/truth.jsonl`, which the simulators write. Only the scoreboard and `labels.py --audit` read it. **Never train on it**: production has no such file.

**Fell behind?** `python tools/checkpoint.py --round N --catch-up` rebuilds the round's reference state (traffic, labels, models) with the reference code, then tells you which `DEFENSE_LEVEL` to restart with.

---

## Round 0: Drop day, data and labels (15 min)

| Step | Do | Expected |
|---|---|---|
| 🔵 Generate | `python tools/simulate.py` (site at level 0) | 900 sessions, all orders `confirmed` |
| 🔍 Audit | Read `defenses/labels.py`, then `python defenses/labels.py --audit` | 0 wrong labels; ~50% of bots labeled; few VPN/privacy users labeled human |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | baseline bots 100% succeed · 0 real users blocked |

**Discuss:** which bots carry a label, and which humans do? What will a model trained on these labels learn "bot" means?

---

## Round 1: Model v1 ⚔️ the humanized bot (35 min)

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | `python defenses/train.py --round 1` | AUC 1.000 for both models; the budget can't place the line, floor 0.5 used |
| 🔵 Exercise | `python defenses/train.py --round 1 --include-leaky` | top features: `honeypot_hits`, `logged_in`, the label definition |
| 🔵 Exercise | `TODO (Round 1)` in `defenses/train.py`: try `FPR_BUDGET` 0.002 and 0.05 | the threshold barely moves: easy labels |
| 🔵 Switch on | restart with `DEFENSE_LEVEL=1`, then `python attacks/round0_baseline.py` | 0/30 and 0/30 |
| 🔴 Attack | read, then run `python attacks/round1_humanized.py` | ≈ 60/60 succeed |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | baseline ≤ 5% · humanized gets through · real users ≤ 3%, but keyboard-only ≈ 25% |

**Discuss:** the validation AUC was 1.000 and the model still lets every humanized bot through. What did the AUC measure? And why are keyboard-only users blocked? (`python defenses/explain.py --model 1 --sid <sid>` on one of them: look at `scrolls`.)

---

## Round 2: Cohort features ⚔️ the fingerprint farm (30 min + break)

| Step | Do | Expected |
|---|---|---|
| 🔍 Triage | `python defenses/explain.py --model 1 --allowed 4` | every contribution says "human"; the `fp` column repeats |
| 🔵 Label | `python tools/label_cluster.py`, answer `y` | the stealth profile: one fingerprint over dozens of /24s, labeled. iPhone clusters with verified customers: not labeled |
| 🔵 Defend | `python defenses/train.py --round 2`, then `--random-split` | temporal holdout AUC collapses (unseen campaign); random split hides it; top features now cohort |
| 🔵 Exercise | `TODO (Round 2)` in `defenses/cohort.py`: add your own cohort feature, retrain | – |
| 🔵 Switch on | restart with `DEFENSE_LEVEL=2`, `python attacks/round1_humanized.py` | ≈ 0–3 of 60 get through; `explain.py --model 2 --sid <sid>` shows `fp_ip24_fanout_1h` doing the work |
| ☕ | **Break (10 min)** | |
| 🔴 Attack | `python attacks/round2_farm.py` | ≈ all succeed: every cohort count is 1 |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | humanized ≤ 20% · farm gets through · real users ≤ 3% |

**Discuss:** the burst is caught because its sessions overlap in time. How would you change `round1_humanized.py` to stay under every cohort count, and what would that cost the attacker on a drop that sells out in minutes?

---

## Round 3: Anomaly detector ⚔️ the oracle prober (25 min)

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | read `defenses/anomaly.py`, then `python defenses/anomaly.py --audit` | farm 100% flagged; every human cohort 0% (Firefox allowlist on) |
| 🔵 Switch on | restart with `DEFENSE_LEVEL=3`, `python attacks/round2_farm.py` | farm mostly blocked |
| 🔵 Exercise | `TODO (Round 3)` in `defenses/anomaly.py` (empty the allowlist, re-audit) or `defenses/scorer.py` (change how the two scores combine, re-run the checkpoint) | privacy-browser users flagged without the allowlist; more farm through if anomalies need supervised suspicion |
| 🔴 Attack | `python attacks/round3_oracle_prober.py` | finds a passing config in ~6 probe sessions (purchased fingerprints + humanized, even from a datacenter); exploit 30/30 |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | farm ≤ 15% · prober gets through · real users ≤ 4% |

**False-positive check:** with the allowlist emptied, which cohort pays for the anomaly detector? Is that acceptable on a drop day? On a login page?

**Discuss:** the prober's winning config uses datacenter IPs. Why didn't the model learn that datacenter traffic is suspicious?

---

## Round 4: Deny the oracle (10 min)

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | read `defenses/enforcement.py`, restart with `DEFENSE_LEVEL=4` | every checkout: 202 `pending` |
| 🔴 Re-run | `python attacks/round3_oracle_prober.py` | every probe looks identical; buys the cheapest config; exploit ≈ 0% after review |
| 🔴 Patient | `python attacks/round3_oracle_prober.py --patient` | tries all 16 configs (32 probes), waits one review, then the exploit works again |
| 🔵 Exercise | `TODO (Round 4)` in `defenses/enforcement.py`: `REVIEW_DELAY_S` | longer review: slower prober, longer-held inventory |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | prober ≤ 10% · real users ≤ 4% |

---

## Wrap-up: both sides of the ledger (10 min)

- Compare the five scoreboards. Which defense cost the most real customers, and which cohort paid?
- Which attack would you expect next, and which layer from Chapter 8 would you add instead of another feature?
- Keep `artifacts/reference_features.parquet` and `artifacts/model_v2.*`: W3 Ch4 monitors drift against them.

---

## Instructor: expected results

Reference run on 2026-10-10: Python 3.10, SQLite, `LAB_TIME_SCALE=0.02`, default seeds, on a shared WSL2 machine under heavy load. Success = share of that attack's checkouts confirmed. Checkpoint traffic per run: 200 real users, 40 baseline, 30 humanized, 30 farm, 30 prober-exploit sessions.

| Attack ↓ / `DEFENSE_LEVEL` → | 0 | 1 | 2 | 3 | 4 |
|---|---|---|---|---|---|
| `round0_baseline` (naive + headless) | 100% | **0%** | 0% | 0% | 0% |
| `round1_humanized` | 100%¹ | 100% (60/60) | **0%** (0/30 checkpoint, 0/60 standalone) | 0–7% | 3% |
| `round2_farm` | 100%¹ | 100%¹ | 100% (60/60) | **0–3%** (0/60 standalone) | 0% |
| `round3_oracle_prober`: probes to a pass | – | – | – | 6 sessions, ≈ $2 | default: none (buys the cheapest) · `--patient`: 32 sessions, ≈ $8.40, one review cycle |
| `round3_oracle_prober`: exploit | – | – | – | 100% (30/30) | **0%** default · 100% `--patient` |
| Real users blocked (of 200) | 0 | 3 (all keyboard-only: 3/13) | 0 | 0 | 1 (desktop) |
| ML scoring p50 / p95, checkpoint load | – | 79 / 202 ms | 124 / 274 ms | 99 / 269 ms | 104 / 249 ms |
| ML scoring p50 / p95, one checkout at a time | – | 0.8 / 1.1 ms | 2.1 / 2.3 ms | 1.6 / 2.4 ms | as level 3 |

¹ Not measured at that level. The attack beats an earlier, weaker level, so it can only succeed there too.

Training: v1 in ~1 s, v2 in ~2 s (5-fold out-of-fold threshold included), anomaly model < 1 s. `simulate.py` (900 sessions): 1.5–2.5 min on the loaded reference machine. `checkpoint.py --round 3 --catch-up` from a wiped database: 1 min 13 s, followed by a passing Round 3 checkpoint.

**Labels after Round 0** (900 sessions): 157 bot / 194 human / 549 unlabeled. 0 wrong labels; 52% of real bots carry a label (naive 83%, headless 22%); VPN 6/55 and privacy-browser 7/49 users carry a human label.

**Things to watch for**

- **Concurrency changes latency, not decisions.** One checkout scores in about 1–2 ms when scored on its own. The checkpoint sends 16 concurrent sessions to a single-process Flask development server, so its p50 is mostly queueing for the GIL (the reference machine was also heavily loaded). Discuss it as a deployment lesson: in production, scoring runs in its own service. Personas are deterministic per seed, but thread scheduling changes which sessions overlap in time (and so the cohort counts), so success counts vary by a few sessions between runs.
- **Round 2 depends on Round 1's attack traffic** being in the database. Students who skipped the attack have no cluster to label: `--catch-up` runs it for them.
- **`--include-leaky` and `--random-split` never save a model**, so they are safe to run any time.
- **Never let anyone train on `data/truth.jsonl`.** It is the scoreboard's answer key.

---

## Bonus challenges

1. **Hindsight review.** At level 4, recompute cohort features at *review* time, with a window that includes sessions after the checkout. How much of the prober's exploit wave does that catch, and why can't you do it inline?
2. **Smarter prober.** Make `round3_oracle_prober.py` ignore `score` and use only the status code at level 3. How many more probes does it need?
3. **Positive-unlabeled learning.** Train on "labeled bot vs. everything else" instead of "labeled bot vs. verified human". What happens to false positives on VPN users?
4. **Calibration.** Wrap the model in scikit-learn's `CalibratedClassifierCV`, or compare it with `TunedThresholdClassifierCV` using a cost metric: 1 blocked customer costs as much as 20 missed bots.

---

## Why these tools

| Tool | Why |
|---|---|
| LightGBM 4.7 (MIT) | Native missing values and categoricals, fast one-row inference, built-in TreeSHAP (`pred_contrib`), text model format (no pickle) |
| scikit-learn 1.7 (BSD-3) | Logistic-regression baseline, metrics, `KFold` |
| pandas / numpy / pyarrow | Dataset assembly and the Parquet reference set for W3 Ch4 |
| Flask 3.1 + SQLAlchemy 2.0 | The demo store, on PostgreSQL or SQLite with the same code |
| httpx 0.28 | Simulated customers and bots |

The pins are the newest releases that still support Python 3.10 (the lab was verified on 3.10). On Python 3.11+, scikit-learn 1.9 and pandas 3.0 are current, but this lab has not been tested with them.
