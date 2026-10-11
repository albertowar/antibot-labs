# Chapter 4 Lab: Detection Signal Lifecycle & Ops

**Format:** Round 0 plus 4 attack ⚔️ defend rounds, ~94 min of the 2.5-hour chapter (including a 10-min break). See `../chapter_04_content.md`, §4.6.

The W2 stack is in production. The eight sensors, the correlation layer, the risk score and the response ladder you built in **W2 Ch8** are live, and the **W2 Ch7** model joins them as one more sensor with three roles. Nothing new is *built* here. The job is to **operate** what you have as the world moves: notice a signal going quiet, measure drift before it becomes a crisis, retrain and ship a model without hurting anyone, and run the incident when an attack finally slips through.

The lab compresses five weeks of production into a few minutes. A seeded replayer (`tools/weeks.py`) sends each week's 200 customers, 10 monitors and that week's bots through the live store, stamped with a lab calendar so every tool can slice by week.

> ⚠️ **Rules of engagement.** Everything runs against the local demo site only. `tools/labclient.py` refuses any `DEMO_URL` that is not localhost. Every address is a documentation range (RFC 5737/3849), every ASN a documentation ASN, every account a synthetic `*@example.test`. The five adversary profiles in `attacks/` exist to train you against your own store; each is only as strong as it needs to be to beat the previous round. No lab traffic ever touches a real proxy, network or person.

```
lab/
  demo_site/        app.py (login + /metrics + /lab/config), edge.py (CDN edge + corpus), users.py
  defenses/sensors/ net · headers · tls · velocity · honeypot · automation · fingerprint · behavior  (W2 Ch8)
  defenses/         policy · ladder · correlation · campaign · pipeline · store · telemetry           (W2 Ch8)
                    config (hot overrides) · metrics (Prometheus) · health (R1) · drift (R2)
                    model · features · train · registry · gate · labels · allowlist · corpus          (new)
  attacks/          week1_baseline … week5_humanized_farm  (one operator, five weeks)
  tools/            weeks (replayer) · ops (scoreboard) · alerts · configure · refresh_corpus
                    roles · canary · rollback_watcher · shadow_report · label · contain · snapshot
                    incident · checkpoint · sweep (W2 Ch8 replay) · population · labclient · report
  monitoring/       docker-compose profile: Prometheus + Grafana with a provisioned dashboard (optional)
  data/             decision_log.jsonl, truth.jsonl, labels.jsonl, ops_config.json, world_updates.json
  models/           manifest.json + model_v*.txt (built by train.py)
```

**Why Python only.** Everything here is server-side: reading a decision log, computing drift, training and scoring a model, and flipping operational config. Pandas, NumPy, scikit-learn and LightGBM are the standard tools, and PSI and the KS test are a few lines of NumPy (no SciPy). The browser-side collectors that produce the telemetry were built in W2 Ch3–Ch4; here the replayer sends their summaries directly, so no browser is needed.

---

## Setup (before the session)

```bash
cd lab
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export REDIS_URL=memory://                       # no Docker needed; see the note below
python demo_site/app.py                          # http://localhost:5000
```

Leave the store running for the whole chapter; the five weeks accumulate in one decision log. In a second terminal (same `venv`), drive the weeks and read the scoreboard:

```bash
export DEMO_URL=http://localhost:5000
python tools/weeks.py --week 1                   # replay a week of traffic
python tools/ops.py                              # the operations scoreboard (latest week)
python tools/ops.py --all                        # the five-week story, one row per week
python tools/checkpoint.py --round N             # run a round end to end and verify it
```

**Docker is optional, two reasons it exists.** The shared counters use Redis in production; here `REDIS_URL=memory://` is an in-process stand-in, and `docker compose up -d --wait` gives you the real thing (`redis:8.10.2-alpine` on `127.0.0.1:6379`) if you want it. Separately, the capstone (W3 Ch9) asks for a Grafana dashboard, so `docker compose --profile monitoring up -d` brings up Prometheus (`v3.15.0`) scraping `/metrics` and Grafana (`13.2.3`) with a provisioned signal-health dashboard on `127.0.0.1:3000` (admin/admin). **The required path needs neither:** `/metrics` is readable with `curl`, and `tools/ops.py` and `tools/alerts.py` are a terminal dashboard over the same data.

**Troubleshooting**

| Problem | Fix |
|---|---|
| Port 5000 in use (macOS AirPlay) | `PORT=5050 python demo_site/app.py`, then `export DEMO_URL=http://localhost:5050` |
| You edited a file under `defenses/` and nothing changed | the app runs with the reloader off; restart it. Config, corpus, labels and model files are hot-reloaded, code is not |
| Lost track of state | `curl -X POST localhost:5000/lab/reset` wipes the log, counters, config, corpus, labels and models. The checkpoint does this for you |
| `Cannot reach Redis` | you set `REDIS_URL` to a Redis you did not start; unset it for `memory://`, or `docker compose up -d --wait` |

---

## How to read a round

Each round is one lab week. You replay the week, read the scoreboard, and respond with the operator tools. The scoreboard shows **both sides**:

```
=== week 3: 370 logins (220 customers, 150 bots) ===

Detection (acting on a session = positive)
  precision    0%   recall    0%   TP 0  FP 9  FN 150
  bot outcomes: allow 150   (a proof-of-work is solved by the bot, so 'pow' is not a stop)
Bots that reached an account: 5   (of 5 with a valid pair)

Real users hurt: 0 blocked, 9 challenged, of 220 (4.1%)
  vpn  pow 5  |  tor  pow 2  |  a11y+autofill  pow 1 ...
```

- **Detection** treats "the stack acted" as the positive class, scored against ground truth (the lab's actor label, which production never has). A proof-of-work is counted as acting, but it does **not stop a bot**: the bot solves it. Watch "bots that reached an account" for the real loss.
- **Real users hurt** names every customer blocked or challenged, by persona. Each is a false positive with a cost.
- **Known-good cohort** is the ten monitors; the signals that fire on them are the only live false-positive rate you have, and a biased floor.

Finish every round with its checkpoint, which drives the whole round from a clean slate and verifies it:

```bash
python tools/checkpoint.py --round 3
```

**Fell behind?** `tools/checkpoint.py --round N` *is* the reference solution: it replays weeks 1..N and applies every fix the round teaches, then checks the result. Read its `solve()` to see the exact operator commands.

---

## Round 0: Baseline — a stack that wins (10 min)

🔵 Replay week 1 and record what "normal" looks like. The naive stuffer and the pre-stealth headless bot are exactly what the W2 stack was built against.

```bash
python tools/weeks.py --week 1
python tools/ops.py --week 1
curl -s localhost:5000/metrics | grep signal_fired_total      # the same numbers Prometheus scrapes
python tools/checkpoint.py --round 0
```

Every bot is blocked; 7.7% of customers hit a challenge (the irreducible VPN/Tor/privacy/a11y tax of the shipped policy). Those per-signal fire rates are the **baseline** every later week is compared against.

---

## Round 1: A signal goes quiet ⚔️ burned signals (18 min)

🔴 Week 2: the operator read a week of 403s and upgraded half the fleet to a TLS-impersonation library and a stealth browser. The library User-Agent, the non-browser JA4 and the wrong header order **stop appearing**.

```bash
python tools/weeks.py --week 2
python tools/alerts.py --week 2          # 🟠 silent: headless_gpu -100%, webdriver_flag -100%, ...
python tools/ops.py --week 2             # block rate has fallen from 100% to ~75%
```

Nothing errored. Three signals just went silent, and the block rate fell with them. 🔵 Demote the burned signals to intelligence-only (weight 0) and lift the behaviour signals the impersonator still trips, then prove with a replay of last week's log that it helps before you ship it:

```bash
python tools/sweep.py --weight mouse_too_straight=25 --weight timing_too_regular=25   # replay first
python tools/configure.py --weight header_order_mismatch=0 \
    --weight mouse_too_straight=25 --weight timing_too_regular=25
python tools/checkpoint.py --round 1     # block rate back to ~100%, users hurt 4.5%
```

**Discuss:** you raised two weights to cover for one burned signal. Who did you borrow that detection from? (`tools/sweep.py --signal timing_too_regular`.)

---

## Round 2: The world moves under you ⚔️ drift (18 min)

🔴 Week 3, two changes land at once. Chrome 146 ships (a new header order and a new JA4 the week-0 corpus has never seen), and Example Fiber buys an address range that your edge's six-month-old map still calls a datacenter on the community blocklist. The same week, the bots switch to residential exits and a humanized mouse, so on week-3 signals they are **invisible**.

```bash
python tools/weeks.py --week 3
python tools/ops.py --week 3             # real users BLOCKED now, not just challenged
python tools/alerts.py --week 3 --drift  # 🔴 known_good: header_order_mismatch on 70% of monitors; corpus stale
```

Before you refresh, the scoreboard shows ~7.3% of customers hurt, including real customers **blocked** by the stale blocklist, and the monitors catch it. 🔵 Refresh the data the sensors depend on, then replay:

```bash
python tools/refresh_corpus.py --all --week 3
python tools/checkpoint.py --round 2     # blocked customers back to 0, hurt back to ~4%
```

The drift report flags the bot behavioural shift (PSI > 0.2 on the score and the timing features) in the same run. 🔵 This is also where the team puts the **W2 Ch7 model** into production as another sensor; the checkpoint trains `v1` on the clean weeks and promotes it.

**Discuss:** the refresh fixed the false positives but caught **zero** of the new bots. Health and drift bought you the question a week early; they did not answer it. What answers it?

---

## ☕ Break (10 min)

---

## Round 3: Retrain without poisoning yourself ⚔️ the feedback loop (20 min)

🔴 Week 4: the evaders now sign in with the valid pairs they found. The weak-label rule — *signed in, so it is human* — labels every one of them human. A retrain on those labels learns that evader traffic is a customer.

```bash
python tools/weeks.py --week 4
python defenses/train.py --weeks 2-4 --labels weak     # v2, the naive retrain
python defenses/gate.py --candidate v2                 # ❌ REFUSE: no analyst-confirmed bots to judge on
```

🔵 The gate refuses to promote a model judged only on circular labels. So you label a sample a person actually looked at, retrain on it, and ship it the safe way:

```bash
python tools/label.py --queue --week 4                 # the sessions worth a human eye
python tools/label.py --cluster "<evader cluster>" --as bot --week 4
python defenses/train.py --weeks 2-4 --labels weak+analyst   # v3
python defenses/gate.py --candidate v3                 # ✅ PASS: 90% recall on the labelled set, 0 FP
python tools/roles.py shadow v3                        # score and log, act on no one
python tools/shadow_report.py --week 4                 # v3 would catch 121 more bots, 0 new real users
python tools/roles.py canary v3 && python tools/canary.py --pct 50
python tools/rollback_watcher.py                       # 🟢 canary within budget
python tools/checkpoint.py --round 3
```

**Discuss:** the naive model `v2` looked perfect by every automatic metric (AUC 1.0). Why? What made the difference not a better model but a better *label*?

---

## Round 4: When one slips through ⚔️ incident response (16 min)

🔴 Week 5: a farm with a fresh fingerprint per session, residential exits and a real hand's mouse timing. It shows **no signal** the stack has, the model included, and it reaches 42 accounts. You cannot re-weight your way out; there is nothing to weight.

```bash
python tools/weeks.py --week 5
python tools/ops.py --week 5                           # 42 accounts reached, 0 signals fired
python tools/snapshot.py --week 5 --label inc-2026-05  # preserve evidence before it rolls
python tools/label.py --cluster "<farm cluster>" --as bot --week 5
python tools/incident.py --week 5 --id INC-2026-05     # pre-fill the report
```

🔵 Contain. The farm hides in one ISP's ASN, so the only lever that stops it in the moment also challenges that ISP's real customers. Put it behind a TTL so it undoes itself:

```bash
python tools/contain.py --step-up-asn 64496 --for-weeks 1
python tools/weeks.py --week 6                         # the containment window
python tools/checkpoint.py --round 4
```

In the containment window the farm reaches **0** accounts, at the cost of challenging **a third of all customers**. That is the trade an incident forces when the attack is signal-less. The lasting fix is not the step-up; it is the labelled sessions you preserved, which become the training data and the new signal the W3 capstone builds on.

---

## Debrief (12 min)

```bash
python tools/ops.py --all
python tools/label.py --audit            # how wrong "obviously fine" labels were
```

- Walk the five-week scoreboard. Where did the stack lose, and was it a model problem or a label problem?
- Which measure warned you earliest each week: a silent signal, a known-good misfire, a drift score, or the business metric (failed logins, accounts reached)?
- The six false-positive archetypes (`chapter_04_content.md` §4.7). Which did you meet, and what did each exemption cost?
- Finish the `incident/incident_report.md` you generated. It is a capstone deliverable.

---

## Instructor: expected results

Verified end to end on Python 3.10 with the pinned `requirements.txt` and `REDIS_URL=memory://`. The population and the bots are seeded, so counts are exact; pipeline timings vary with the machine. Each `checkpoint.py --round N` resets and replays weeks 1..N with every fix applied, so the numbers reproduce.

Five-week scoreboard (`tools/ops.py --all` after `checkpoint.py --round 4`):

| Week | Round | Bots | Bot block rate | Bots that reached an account | Real users hurt |
|---|---|---|---|---|---|
| 1 | 0 baseline | 100 | 100% | 0 | 17 (7.7%) |
| 2 | 1 after re-weight | 150 | 100% | 0 | 10 (4.5%) |
| 3 | 2 after refresh | 150 | 0% | 5 | 9 (4.1%) |
| 4 | 3 | 160 | 0% | 41 | 7 (3.2%) |
| 5 | 4 incident | 120 | 0% | 42 | 16 (7.3%) |
| 6 | 4 containment window | 120 | 100% (step-up) | **0** | **74 (33.6%)** |

Per round, before the fix vs after:

| Round | Signal it turns on | Before the fix | After the fix |
|---|---|---|---|
| 1 | silent-signal alert (`alerts.py`) | week 2 block rate ~75%; `silent` fires on `headless_gpu`, `webdriver_flag`, `tz_geo_mismatch` | block rate back to ~100%, users hurt 4.5% |
| 2 | drift + known-good (`alerts.py --drift`) | week 3 ~7.3% hurt incl. real customers **blocked**; `known_good` fires (header-order on 70% of monitors); corpus 3 weeks stale | 0 blocked, hurt back to ~4.1% |
| 3 | the promotion gate (`gate.py`) | `v2` (weak labels) REFUSED: 0% recall on the analyst holdout | `v3` (weak+analyst) PASS: 90% recall, 0 FP; shadow would catch 121/160 more bots with 0 new real users |
| 4 | containment with a TTL (`contain.py`) | week 5 farm reaches 42 accounts, 0 signals fire | containment window: farm reaches 0, but 33.6% of customers challenged |

Things to watch for:

- **A proof-of-work is not a stop.** The scoreboard counts `pow` as "acted" for precision/recall, but the bot solves it. "Bots that reached an account" is the honest loss. Weeks 3–5 show high FN because the evaders are invisible to the rules and to `v1`.
- **The model's value is shown offline.** `v1` is prod through weeks 3–5 and never catches the signal-less evaders live. `tools/shadow_report.py` and `defenses/gate.py` show what `v3` would do, which is the whole point of shadow mode.
- **Redis vs. memory.** Counts are identical; only the store line in `/lab/status` changes. The Docker Redis path and the Prometheus/Grafana `monitoring` profile were not run in the build environment (no Docker); `docker-compose.yml` and the dashboard JSON are syntactically valid.
- **`grep -rn '\bactor\b' defenses` is empty.** No defense reads the ground-truth label; only the tools do.

---

## Bonus challenges

1. **Tie "act" to the cost, not the ratio.** `defenses/drift.py` uses the textbook PSI thresholds (0.1 / 0.2). Replace the "act" rule with one tied to the known-good false-positive rate. Does it fire earlier or later on week 3?
2. **Rotate the known-good token.** `allowlist.py` trusts one header value. Send it from the Round 5 farm (`--extra`) and watch it walk in. Then bind the token to a source range and alert when it arrives from anywhere else.
3. **Promote the canary.** After Round 3, run `tools/roles.py promote v3` and replay a week-4-style wave. Confirm the model now catches live what it only caught offline in shadow.
4. **A real retraining cadence.** `train.py` retrains on a week range you pass. Wire it to retrain whenever `alerts.py --drift` reports PSI > 0.2, and gate every candidate. What is the shortest safe loop?
