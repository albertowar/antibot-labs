# Chapter 6 Lab: Account Takeover & Credential Stuffing

Five rounds of attack ⚔️ defend against the demo store's login endpoint. You play
both sides: run the attacker, read the defense, wire it in, run the attacker
again. Every round also runs ~145 simulated real users, so you see the cost of a
defense next to what it blocks. See `../chapter_06_content.md` §6.6.

> ⚠️ **Rules of engagement.** These scripts target **only** the local demo store
> you run yourself. Every attack refuses a non-loopback target in code
> (`attacks/_common.py:require_local_target`). Do not edit that out. All
> credentials, IPs, breach data and session cookies here are synthetic. Lab
> traffic never touches a third party, a public proxy, or anyone else's machine.

```
lab/
  demo_site/      the Flask store: login pipeline, routes, event log
  defenses/       the layers you implement (solutions/ holds the reference)
  attacks/        one stuffer/replay per round
  tools/          seed, legit-traffic simulator, scoreboard, checkpoint
  data/           synthetic combo list, breach corpus, users (seeded)
```

## Setup (before the session)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python tools/seed.py                       # builds data/ (users, combo list, corpus, ...)
DEFENSE_LEVEL=0 python demo_site/app.py     # terminal 1 — the store, on :5000
```

No Docker, no Redis server, no cloud: the store falls back to an in-process
`fakeredis` and a local SQLite file. (Want the production-shaped Redis + PostgreSQL
stack instead? `docker compose up -d` and set `REDIS_URL` / `DATABASE_URL` — see
`docker-compose.yml`.)

Each round runs at a fixed `DEFENSE_LEVEL` (0–4). Restart the store with the new
level at the start of each round. The port is `PORT` (default 5000); if it is
taken, use `PORT=5055 ... ` and `export DEMO_URL=http://127.0.0.1:5055` for the
tools.

**You implement the defenses.** The modules in `defenses/` are stubs with
`TODO (Round N)` markers; the working reference is in `defenses/solutions/`. Run
the store with `USE_SOLUTIONS=1` to use the reference (what the checkpoint and the
expected-results table assume). To catch up on a round:

```bash
USE_SOLUTIONS=1 DEFENSE_LEVEL=<N> python demo_site/app.py
python tools/checkpoint.py --round <N> --catch-up
```

## How to measure a round

In a second terminal, with the store running at the round's level:

```bash
python tools/checkpoint.py --round <N>
```

It resets the event log, runs this round's new attack **and** the previous
round's attack (to prove the old one is now dead), runs the 145 simulated humans,
and prints the scoreboard: accounts taken over, real users wrongly blocked,
step-up friction, and login latency (the defender's cost). You can also run any
piece on its own, e.g. `python attacks/round1_distributed_stuffer.py` or
`python tools/legit_traffic.py`.

---

## Round 0: Baseline — naive stuffer vs. an open door (DEFENSE_LEVEL=0)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round0_naive_stuffer.py` | ~40 accounts taken over |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | 40 ATO · 0 real users blocked |

**Discuss:** the combo list is 1000 pairs, 40 of them valid. The stuffer walks it
in seconds from one IP. Everything below is about raising that cost.

## Round 1: 🔵 login throttling ⚔️ 🔴 distributed stuffer (DEFENSE_LEVEL=1)

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | Implement `defenses/login_throttle.py` (per-IP velocity + per-account lockout) | – |
| 🗡️ Re-run naive | `python attacks/round0_naive_stuffer.py` | throttled to ~0–1 ATO |
| 🗡️ Attack | `python attacks/round1_distributed_stuffer.py` (one try per account, rotating IPs) | ~40 ATO again |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | naive ~0 · distributed ~40 · **5 CGNAT users wrongly blocked** |

**False-positive check:** the CGNAT cohort shares one IP; a naive per-IP limit
punishes ~5 of them every round from here on. That is the cost of the cheapest
defense — note it on the scoreboard and carry it forward.

## Round 2: 🔵 population signals ⚔️ 🔴 clean-list stuffer (DEFENSE_LEVEL=2)

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | Implement `defenses/population_signals.py` (per-cohort failure & unknown-account ratios) | – |
| 🗡️ Re-run distributed | `python attacks/round1_distributed_stuffer.py` | cohort flagged → ~0–1 ATO |
| 🗡️ Attack | `python attacks/round2_clean_list_stuffer.py` (prune via the oracle, spread across cohorts) | ~40 ATO |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | distributed ~1 · clean-list ~40 (pruned 1000 → 40) |

**Discuss:** the clean-list stuffer confirms which accounts exist through
`/forgot-password`, then gives each attempt its own /24. No cohort reaches the
sample floor, so no cohort can be challenged without challenging everyone.

## ☕ Break (10 min)

## Round 3: 🔵 breached-password screen + oracle hardening ⚔️ 🔴 stealer-log replay (DEFENSE_LEVEL=3)

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | Implement `defenses/breached_passwords.py` and `defenses/oracles.py` | – |
| 🗡️ Re-run clean-list | `python attacks/round2_clean_list_stuffer.py` | oracle closed + breach screen → **0 ATO** |
| 🗡️ Attack | `python attacks/round3_stealer_log_replay.py` (fresh, non-breached creds from malware) | 10/10 ATO |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | clean-list 0 · stealer 10/10 · **25 breached-password users see step-up** |

**False-positive check:** screening breached passwords is the single best control
against stuffing — but ~25 real users whose password is genuinely breached now hit
a step-up. They complete it (TOTP) and get in; count it as friction, not a block.

## ☕ Break (10 min)

## Round 4: 🔵 device/context risk + sensitive-action re-auth ⚔️ 🔴 session-cookie replay (DEFENSE_LEVEL=4)

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | Implement `defenses/risk_engine.py` (`assess`, `remember`, `needs_reauth`) | – |
| 🗡️ Re-run stealer | `python attacks/round3_stealer_log_replay.py` | new-network login → step-up → **0 ATO** |
| 🗡️ Attack | `python attacks/round4_session_replay.py` (replays a stolen session cookie) | reads 10/10, **0 sensitive actions** |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | stealer 0 · cookie reads 10, sensitive 0 · 125/145 real users in |

**Debrief:** the stolen cookie still reads the account — login-time defenses never
see it. Re-auth stops the *damage* (the email change), but stopping the read needs
device-bound sessions (DBSC), passkeys, or session-anomaly models. That is the
hand-off to W2 Ch7 (ML) and W4.

## Wrap-up: false positives and cost (debrief)

Pull the scoreboards together. For each round: accounts taken over, real users
blocked (false positives), step-up friction, and login latency. The arc is the
point — no single layer wins, and the cheapest layer (per-IP throttle) has the
bluntest false-positive profile (CGNAT), while the sharpest (breached-password
screen, device/context) cost recoverable friction instead of hard blocks.

## Instructor: expected results

Verified with the reference solutions (`USE_SOLUTIONS=1`) on Python 3.10,
`fakeredis` + SQLite, 1000-pair combo list, 145 simulated users. Small run-to-run
variation of ±1 ATO on the stuffers is normal (which valid pairs land before a
cohort trips). "ATO" = a session obtained through the front door.

| Round | Level | Attack this round | Accounts taken over | Real users blocked (FP) | Step-up friction |
|---|---|---|---|---|---|
| 0 | 0 | naive stuffer | **40** / 1000 | 0 | 0 |
| 1 | 1 | distributed stuffer | **~40** (naive now ~0–1) | **5** (CGNAT) | 0 |
| 2 | 2 | clean-list stuffer | **~40** (distributed now ~1) | 5 | 0 |
| 3 | 3 | stealer-log replay | **10 / 10** (clean-list now **0**) | 5 | **25** (breached pw) |
| 4 | 4 | session-cookie replay | reads **10 / 10**, sensitive **0** (stealer login now **0**) | 5 | **45** (breached + new device) |

Legitimate users logged in: 130/145 at L0 (15 are deliberate typos → rejected,
not a false positive), 125/145 from L1 on (15 typos + 5 CGNAT blocked).

## Troubleshooting

| Problem | Fix |
|---|---|
| `Port 5000 is in use` | `PORT=5055 DEFENSE_LEVEL=<N> python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:5055` |
| Checkpoint says the store is at the wrong level | Restart the store with the `DEFENSE_LEVEL` it prints |
| Checkpoint fails right after you edit a defense | You are running the stub. Restart the store with `USE_SOLUTIONS=1` (or finish the `TODO`) |
| Numbers look stale between rounds | The checkpoint calls `/lab/reset`; if you ran an attack by hand, re-run the checkpoint to reset first |
| Want a clean slate | Stop the store, `rm -f data/shop.db*`, `python tools/seed.py` |
| Use real Redis/PostgreSQL | `docker compose up -d` and set `REDIS_URL` / `DATABASE_URL` before seeding |
