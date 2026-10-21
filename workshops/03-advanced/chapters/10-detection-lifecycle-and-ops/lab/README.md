# Chapter 10 Lab: Detection Signal Lifecycle & Ops

Starts from: `workshops/03-advanced/starter/` (contract 1.5). Adds: the sign-in stack an operator would be running (eight sensor layers, a correlation layer, one risk score and a response ladder with a proof of work and an emailed-code step-up, a deceptive block, a classifier as one more sensor in three roles) and the operations layer around it (hot operator config, a corpus with a date, a model registry, Prometheus metrics, a calendar replayer, the scoreboard, alerts, drift, gate, canary, labels, containment, snapshot and incident tools).

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `data/ops_world.json`
- `defenses/allowlist.py`
- `defenses/attempt.py`
- `defenses/campaign.py`
- `defenses/config.py`
- `defenses/containment.py`
- `defenses/corpus.py`
- `defenses/correlation.py`
- `defenses/features.py`
- `defenses/metrics.py`
- `defenses/mlfeatures.py`
- `defenses/model.py`
- `defenses/netinfo.py`
- `defenses/ops.py`
- `defenses/registry.py`
- `defenses/sensor_automation.py`
- `defenses/sensor_behavior.py`
- `defenses/sensor_fingerprint.py`
- `defenses/sensor_headers.py`
- `defenses/sensor_honeypot.py`
- `defenses/sensor_net.py`
- `defenses/sensor_tls.py`
- `defenses/sensor_velocity.py`
- `defenses/sensors.py`
- `demo_site/ext/ops.py`
- `demo_site/ext/risk.py`
- `demo_site/ext/templates/risk/collector.html`
- `demo_site/static/js/risk.js`
- `tools/alerts.py`
- `tools/canary.py`
- `tools/configure.py`
- `tools/contain.py`
- `tools/drift.py`
- `tools/gate.py`
- `tools/health.py`
- `tools/incident.py`
- `tools/label.py`
- `tools/labels.py`
- `tools/ops.py`
- `tools/ops_reset.py`
- `tools/personas_ch10.py`
- `tools/refresh_corpus.py`
- `tools/report.py`
- `tools/roles.py`
- `tools/rollback_watcher.py`
- `tools/shadow_report.py`
- `tools/signin.py`
- `tools/snapshot.py`
- `tools/sweep.py`
- `tools/train.py`
- `tools/weeks.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** pre-written (level-style) lab: Round 0 plus 4 attack ⚔️ defend rounds, one lab week each. See `../chapter_10_content.md`, §10.6.

The sign-in stack is **already written and already in production**: you read it, you do not build it. The store is the W3 starter (Kestrel Outfitters); `defenses/ladder.py` wires the stack onto the login at `DEFENSE_LEVEL=1` (`0` is the bare store, which is what `tools/verify.py --smoke` tests). The job is to **operate** it as the world moves: notice a signal going quiet, measure drift before it becomes a crisis, retrain and ship a model without hurting anyone, and run the incident when an attack finally slips through. What changes from round to round is **operational state** (a JSON file of overrides, a corpus refresh, a model registry, analyst labels), not code.

The lab compresses five weeks of production into a few minutes. A seeded replayer (`tools/weeks.py`) sends each week's 200 customers, 10 monitors and that week's bots through the live store, one at a time, stamped with a lab calendar so every tool can slice the decision log by week.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service URLs such as `REDIS_URL` and `DATABASE_URL` too) before a single request is sent. The store's edge accepts the lab headers only from loopback, and `app.run` binds `127.0.0.1`. Do not remove those checks.
- Every address is rented from `data/world.json` (documentation ranges, RFC 5737/3849, ASNs from RFC 5398), every account is a synthetic `*@example.test` seed user, and the five adversary profiles in `attacks/` are only as strong as they need to be to beat the previous round. The residential-proxy pool stands in for a product; no lab traffic ever goes through a real proxy, VPN or Tor node.
- The optional Prometheus and Grafana containers publish their ports on `127.0.0.1` only.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
demo_site/ext/ops.py        the calendar (Lab-Week / Lab-Clock), GET /metrics, POST /lab/ops/{new-week,reset}, GET /lab/ops/state
demo_site/ext/risk.py       the login collector (static/js/risk.js), challenges "pow" and "step_up", the deceptive block
defenses/                   sensor_*.py (8 layers) · sensors · correlation · campaign · model · containment      the stack
                            policy (weights, lines) · ladder (the wiring) · features · netinfo · attempt · mlfeatures
                            config (hot overrides) · corpus (data with a date) · registry (model roles) · allowlist · metrics · ops
attacks/                    week1_baseline … week5_humanized_farm  (one operator, five weeks; week 6 replays the farm)
tools/                      weeks (replayer) · ops (scoreboard) · alerts · health · drift · sweep · configure · refresh_corpus
                            train · gate · labels · roles · canary · rollback_watcher · shadow_report · label
                            contain · snapshot · incident · checkpoint · ops_reset · personas_ch10 · signin · report
data/ops_world.json         the chapter's week-0 snapshot: JA4 table, an old blocklist entry, built_week
monitoring/                 docker compose profile: Prometheus + Grafana with a provisioned dashboard (optional)
solutions/round1..2/data/   the operator-state files those rounds leave behind (--catch-up installs them)
solutions/round1..4/README.md  the answer key: the exact commands
```

**Why the simulated internet is the starter's.** `data/world.json` and `data/feeds/*` are the store's own (pools, ASNs, the synthetic feeds); the edge refuses an address outside them. What *drifts* in this chapter lives next to them in `data/ops_world.json` (the JA4 table captured in lab week 0, one old community-blocklist entry for a range that changed hands, `built_week`), and what the refresh learns lands in `data/world_updates.json`. The network sensor derives a network's kind from the feeds, as production does (`defenses/netinfo.py`).

**Why Python only.** Everything here is server-side: reading a decision log, computing drift, training and scoring a model, and flipping operational config. NumPy, scikit-learn and LightGBM are the standard tools, and PSI and the KS test are a few lines of NumPy (no SciPy). The browser-side collector that produces the telemetry was built in W2 Ch2 and Ch5; here the replayer sends its summaries directly, so no browser is needed (open `/login` in your own browser at level 1 and the same page script runs).

---

## Setup

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate       # one venv per chapter, see the root README
pip install -r requirements.txt
python tools/doctor.py                                  # READY?
DEFENSE_LEVEL=1 python demo_site/app.py                 # http://127.0.0.1:5000 (SQLite + in-process Redis)
```

Leave the store running for the whole chapter; the five weeks accumulate in one decision log. In a second terminal (same `.venv`), drive the weeks and read the scoreboard:

```bash
export DEMO_URL=http://127.0.0.1:5000
python tools/weeks.py --week 1                   # replay a week of traffic (about 15 seconds)
python tools/ops.py                              # the operations scoreboard (latest week)
python tools/ops.py --all                        # the five-week story, one row per week
python tools/checkpoint.py --round N             # rebuild a round's history from a clean slate and verify it
```

**Docker is optional, two reasons it exists.** The store keeps its shared counters in Redis and its rows in PostgreSQL in production; here it defaults to an in-process Redis and SQLite, and `docker compose up -d --wait` gives you the real thing (Redis 8.10 and PostgreSQL 18 on `127.0.0.1`; see the comment at the top of `docker-compose.yml` for the two environment variables). Separately, the capstone (W3 Ch12) asks for a Grafana dashboard: `docker compose --profile monitoring up -d --wait` adds Prometheus (3.15) scraping `/metrics` and Grafana (13.2) with a provisioned signal-health dashboard on `127.0.0.1:3000` (admin/admin); see **The monitoring profile** below. **The required path needs neither:** `/metrics` is readable with `curl`, and `tools/ops.py` and `tools/alerts.py` are a terminal dashboard over the same data.

**Troubleshooting**

| Problem | Fix |
|---|---|
| Port 5000 in use (macOS AirPlay) | `PORT=5050 DEFENSE_LEVEL=1 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:5050` |
| Every bot and customer gets through, nothing is logged as blocked | the store runs at `DEFENSE_LEVEL=0`, the bare store. Start it with `DEFENSE_LEVEL=1` (or `curl -X POST localhost:5000/lab/level -H 'Content-Type: application/json' -d '{"level": 1}'`) |
| You edited a file under `defenses/` and nothing changed | `defenses/*.py` hot-reloads on the next request (`LAB_RELOAD=1`); `demo_site/ext/*.py` does not, restart the store. State files (config, corpus, models, labels) are hot-reloaded too |
| Lost track of state | `python tools/ops_reset.py` wipes the log, counters, config, refresh, labels and models. The checkpoint does this for you |
| `Cannot reach Redis` / `PostgreSQL` | you set `REDIS_URL` / `DATABASE_URL` to a server you did not start; unset them for the in-process defaults, or `docker compose up -d --wait` |
| The tools print `Store not reachable` | start the store first and `export DEMO_URL=...` in the tools' shell |

---

## How to read a round

Each round is one lab week. You replay the week, read the scoreboard, and respond with the operator tools. The scoreboard shows **both sides**:

```
=== week 3: 370 logins (220 customers, 150 bots) ===

Detection (acting on a session = positive)
  precision    0%   recall    0%   TP 0  FP 14  FN 150
  bot outcomes: allow 150   (a proof-of-work is solved by the bot, so 'pow' is not a stop)
Bots that reached an account: 5   (of 5 that held a valid pair)

Real users hurt: 7 blocked, 7 challenged, of 220 (6.4%)
  typical          block 6
  vpn              pow 4
  autofill         block 1, pow 1 ...
```

- **Detection** treats "the stack acted" as the positive class, scored against ground truth (the lab's actor label, which production never has). A proof-of-work is counted as acting, but it does **not stop a bot**: the bot solves it. Watch "bots that reached an account" for the real loss.
- **Real users hurt** names every customer blocked or challenged, by persona. Each is a false positive with a cost.
- **Known-good cohort** is the ten monitors; the signals that fire on them are the only live false-positive rate you have, and a biased floor.
- **Defender cost** is the gate time per sign-in (`Server-Timing: gate`), the price of every check on the request path.

Finish every round with its checkpoint, which drives the whole round from a clean slate and verifies it:

```bash
python tools/checkpoint.py --round 3
```

**Fell behind?** `tools/checkpoint.py --round N` *is* the reference solution: it resets the store, replays weeks 1..N and applies every fix the rounds teach, so afterwards the live store stands where Round N ends and you can carry on by hand. Read `history()` in that file to see the exact operator commands; `solutions/roundN/README.md` is the same answer key in prose. `--catch-up` additionally installs the operator-state files of rounds 1..N (`data/ops_config.json`, `data/world_updates.json`) first. `--round N --level L` replays the same week with only the fixes of rounds 1..L in force: the "before" column. `--round N --no-reset` judges the store as you left it (your own hand-driven run).

---

## Round 0: Baseline — a stack that wins

🔵 Replay week 1 and record what "normal" looks like. The naive stuffer and the pre-stealth headless bot are exactly what this stack was built against.

```bash
python tools/weeks.py --week 1
python tools/ops.py --week 1
curl -s localhost:5000/metrics | grep signal_fired_total      # the same numbers Prometheus scrapes
python tools/checkpoint.py --round 0
```

Every bot is stopped; 7.7% of customers hit a challenge (the irreducible VPN/Tor privacy tax of the shipped policy). Those per-signal fire rates are the **baseline** every later week is compared against.

---

## Round 1: A signal goes quiet ⚔️ burned signals

🔴 Week 2: the operator read a week of 403s and upgraded half the fleet to a TLS-impersonation library and a stealth browser. The library User-Agent, the non-browser JA4 and the wrong header order **stop appearing**.

```bash
python tools/weeks.py --week 2
python tools/alerts.py --week 2          # 🟠 silent: headless_gpu -100%, webdriver_flag -100%, ...
python tools/ops.py --week 2             # bots stopped has fallen from 100% to ~71%
```

Nothing errored. Three signals just went silent, and the stop rate fell with them. 🔵 Demote the burned signal to intelligence-only (weight 0) and lift the behaviour signals the impersonator still trips, then prove with a replay of last week's log that it helps before you ship it:

```bash
python tools/sweep.py --weight mouse_too_straight=25 --weight timing_too_regular=25   # replay first
python tools/configure.py --weight header_order_mismatch=0 \
    --weight mouse_too_straight=25 --weight timing_too_regular=25
python tools/checkpoint.py --round 1     # stop rate back to 100%, customers hurt 4.5%
```

**Discuss:** you raised two weights to cover for one burned signal. Who did you borrow that detection from? (`tools/sweep.py --signal timing_too_regular`.)

---

## Round 2: The world moves under you ⚔️ drift

🔴 Week 3, two changes land at once. Chrome 146 ships (a new header order and a new JA4 the week-0 corpus has never seen), and Example Fiber buys an address range that your feeds still call a datacenter, with the first few addresses still on an old community blocklist. The same week, the bots switch to residential exits and a humanized mouse, so on week-3 signals they are **invisible**.

```bash
python tools/weeks.py --week 3
python tools/ops.py --week 3             # real users BLOCKED now, not just challenged
python tools/alerts.py --week 3 --drift  # 🔴 known_good: header_order_mismatch on 70% of monitors; corpus stale
```

Before you refresh, the scoreboard shows 6.4% of customers hurt (14 of 220), 7 of them real customers **blocked** by the stale blocklist and the stale datacenter label, and the monitors catch it. 🔵 Refresh the data the sensors depend on, then replay:

```bash
python tools/refresh_corpus.py --all --week 3
python tools/checkpoint.py --round 2     # blocked customers back to 0, hurt back to 2.7%
```

The drift report flags the bot behavioural shift (PSI > 0.2 on the score and the timing features) in the same run. 🔵 This is also where the team puts a **model** into production as another sensor; the checkpoint trains `v1` on the clean weeks (`tools/train.py`) and promotes it (`tools/roles.py promote v1`).

**Discuss:** the refresh fixed the false positives but caught **zero** of the new bots. Health and drift bought you the question a week early; they did not answer it. What answers it?

---

## Round 3: Retrain without poisoning yourself ⚔️ the feedback loop

🔴 Week 4: the evaders now sign in with the valid pairs they found. The weak-label rule — *signed in, so it is human* — labels every one of them human. A retrain on those labels learns that evader traffic is a customer.

```bash
python tools/weeks.py --week 4
python tools/train.py --weeks 2-4 --labels weak     # v2, the naive retrain
python tools/gate.py --candidate v2                 # ❌ REFUSE: no analyst-confirmed bots to judge on
```

🔵 The gate refuses to promote a model judged only on circular labels. So you label a sample a person actually looked at, retrain on it, and ship it the safe way:

```bash
python tools/label.py --queue --week 4                 # the sessions worth a human eye
python tools/label.py --cluster "<evader cluster>" --as bot --week 4
python tools/train.py --weeks 2-4 --labels weak+analyst   # v3
python tools/gate.py --candidate v3                    # ✅ PASS on the labelled set
python tools/roles.py shadow v3                        # score and log, act on no one
python tools/shadow_report.py --week 4                 # what v3 would newly catch, and the real users it would newly act on
python tools/roles.py canary v3 && python tools/canary.py --pct 50
python tools/rollback_watcher.py                       # 🟢 canary within budget
python tools/checkpoint.py --round 3
```

**Discuss:** the naive model `v2` looked perfect by every automatic metric (AUC 1.0). Why? What made the difference not a better model but a better *label*?

---

## Round 4: When one slips through ⚔️ incident response

🔴 Week 5: a farm with a fresh fingerprint per session, residential exits and a real hand's mouse timing. It shows **no signal** the stack has, the model included, and it reaches 42 accounts. You cannot re-weight your way out; there is nothing to weight.

```bash
python tools/weeks.py --week 5
python tools/ops.py --week 5                           # 42 accounts reached, almost nothing fired
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

In the containment window the farm reaches **0** accounts, at the cost of challenging **29% of all customers**. That is the trade an incident forces when the attack is signal-less. The lasting fix is not the step-up; it is the labelled sessions you preserved, which become the training data and the new signal the W3 capstone builds on.

---

## Debrief

```bash
python tools/ops.py --all
python tools/label.py --audit            # how wrong "obviously fine" labels were
```

- Walk the five-week scoreboard. Where did the stack lose, and was it a model problem or a label problem?
- Which measure warned you earliest each week: a silent signal, a known-good misfire, a drift score, or the business metric (failed logins, accounts reached)?
- The six false-positive archetypes (`chapter_10_content.md` §10.7). Which did you meet, and what did each exemption cost?
- Finish the `incident/incident_report.md` you generated. It is a capstone deliverable.

---

## The monitoring profile

`docker compose --profile monitoring up -d --wait` starts Prometheus and Grafana next to Redis and PostgreSQL. Prometheus scrapes the store at `host.docker.internal:5000/metrics` every 5 seconds (set `STORE_PORT` if you changed `PORT`); Grafana provisions the `Prometheus` data source and the dashboard **Bot Defense — Signal Health (W3 Ch10)** (uid `w3ch4-signal-health`) from `monitoring/`: signal fire rate, decisions by action, known-good false positives, login outcomes, corpus age, pipeline p95 and model score by role. Replay a week and the panels fill in; the same series are what `tools/alerts.py` computes from the log.

On Docker Desktop the store (bound to `127.0.0.1`, as always) sees the scrape arrive from loopback. On a native Linux engine `host.docker.internal` is the bridge gateway, which the store's edge refuses: read `/metrics` with `curl` there. Bring it down with `docker compose --profile monitoring down -v`.

---

## Expected results (self-check)

Verified end to end on Python 3.12 with the pinned `requirements.txt` (Flask 3.1, redis 8.1, numpy 2.5, scikit-learn 1.9, lightgbm 4.7, prometheus-client 0.26) and the default in-process Redis and SQLite; every round passes, every "before" column below is `--round N --level N-1`, and `python tools/verify.py --all --catch-up` run twice prints identical numbers. The population and the bots are seeded and play one at a time, so counts are exact; the millisecond figures vary with the machine. Each `checkpoint.py --round N` resets and replays weeks 1..N with every fix applied, so the numbers reproduce. The tables come from `python tools/verify.py --all --markdown` (and the `--level N-1` runs); do not edit them by hand.

Five-week scoreboard (`python tools/ops.py --all` after `checkpoint.py --round 4`):

| Week | Round | Bots | Bots stopped | Bots that reached an account | Real users hurt (acted on) |
|---|---|---|---|---|---|
| 1 | 0 baseline | 100 | 100% | 0 | 17 (7.7%) |
| 2 | 1 after re-weight | 150 | 100% | 0 | 10 (4.5%) |
| 3 | 2 after refresh | 150 | 0% | 5 | 6 (2.7%) |
| 4 | 3 | 160 | 0% | 41 | 12 (5.5%) |
| 5 | 4 incident | 120 | 0% | 42 | 16 (7.3%) |
| 6 | 4 containment window | 120 | 100% (step-up) | **0** | **64 (29.1%)** |

Per round, the "before" column (`--round N --level N-1`: the same week with only the earlier rounds' fixes in force) next to the "after" (`--round N`):

| Round | Signal it turns on | Before the fix | After the fix |
|---|---|---|---|
| 1 | silent-signal alert (`alerts.py`) | week 2: 71% of bots stopped; `silent` fires on `headless_gpu`, `webdriver_flag`, `tz_geo_mismatch`; 10 customers hurt (4.5%) | 100% stopped, still 10 hurt (4.5%) |
| 2 | drift + known-good (`alerts.py --drift`) | week 3: 14 hurt (6.4%), **7 blocked**; `known_good` fires (`header_order_mismatch` on 70% of the monitors); corpora 3 weeks stale | 6 hurt (2.7%), **0 blocked**; the 5 evaders that hold a valid pair still reach an account |
| 3 | the promotion gate (`gate.py`) | `v2` (weak labels) REFUSED: it catches 0% of the confirmed bots (AUC 1.0 on its own labels); 41 evaders reach an account | `v3` (weak+analyst) PASSED: 90% recall, 0% FP on the 72 labelled sessions; shadow would newly act on 132 of the 160 bots and on 1 of 220 customers |
| 4 | containment with a TTL (`contain.py`) | week 6 without it: the farm reaches 39 accounts, 11 customers hurt (5.0%) | containment window: the farm reaches 0, but 64 customers (29.1%) are challenged |

Things to watch for:

- **A proof-of-work is not a stop.** The scoreboard counts `pow` as "acted" for precision/recall, but the bot solves it. "Bots that reached an account" is the honest loss. Weeks 3 to 5 show high FN because the evaders are invisible to the rules and to `v1`.
- **The model's value is shown offline.** `v1` is prod through weeks 3 to 5 and never catches the signal-less evaders live. `tools/shadow_report.py` and `tools/gate.py` show what `v3` would do, which is the whole point of shadow mode.
- **Redis and PostgreSQL vs. the in-process defaults.** Counts are identical (verified through Round 2 against Redis 8.10 and PostgreSQL 18.6, with the store started by hand and `tools/checkpoint.py` attached to it); only the store line in `/lab/config` and the gate time (a real Redis adds round trips: median about 12 ms instead of 5) change.
- **`grep -rn "actor" defenses demo_site/ext` finds nothing.** No defense reads the ground-truth label; only the tools do (`check_labs.py` rule 11 and `tools/smoke.py` enforce it).
- **The numbers are exact.** The population and the bots are seeded, the customers and bots sign in one at a time, and the canary is assigned by a hash of the account, so every run reproduces the tables; only the millisecond figures move with the machine.

---

## Bonus challenges

1. **Tie "act" to the cost, not the ratio.** `tools/drift.py` uses the textbook PSI thresholds (0.1 / 0.2). Replace the "act" rule with one tied to the known-good false-positive rate. Does it fire earlier or later on week 3?
2. **Rotate the known-good token.** `defenses/allowlist.py` trusts one header value. Send it from the Round 4 farm (add the `X-Known-Good` header to `attacks/week5_humanized_farm.py`) and watch it walk in. Then bind the token to a source range and alert when it arrives from anywhere else.
3. **Promote the canary.** After Round 3, run `tools/roles.py promote v3` and replay a week-4-style wave. Confirm the model now catches live what it only caught offline in shadow.
4. **A real retraining cadence.** `tools/train.py` retrains on a week range you pass. Wire it to retrain whenever `tools/alerts.py --drift` reports PSI > 0.2, and gate every candidate. What is the shortest safe loop?
5. **Turn on the campaign layer.** `python tools/contain.py --campaign-stepup --for-weeks 1` switches on `defenses/campaign.py`. Replay week 3 and read `python tools/sweep.py --clusters` first: how many real customers share the farm's cluster key?
