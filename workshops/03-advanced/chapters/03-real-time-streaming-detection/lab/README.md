# Chapter 3 Lab: Real-Time Streaming Detection

**Format:** 5 rounds of attack ⚔️ defend, ~132 min. See `../chapter_03_content.md`, §3.6.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- Every IP is from a documentation range (RFC 5737). Usernames, sessions and timings are synthetic.
- By default the attacks write events straight to the local stream. `--live` sends them through the store instead, and is guarded like everything else.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

This lab is one Flask store that grows a streaming detector across five rounds. Every HTTP
request becomes one event on a **Redis Stream**; a consumer reads the stream and runs the
detectors turned on at the current `DEFENSE_LEVEL`. "Every defense is followed by the attack
that beats it, and every attack by the defense that catches it."

```
lab/
  README.md            this file
  requirements.txt     pinned deps (Python 3.12+)
  docker-compose.yml   OPTIONAL real Redis 8 (the default needs no Docker)
  demo_site/
    app.py             Flask store; after_request XADDs an event; a thread runs the consumer
    store.py           connect(): memory:// (fakeredis) or a real Redis URL
    stream.py          the event log + consumer-group helpers (XADD/XREADGROUP/XACK/XINFO)
    features.py        per-session state (Welford) + global sketches (CMS/HLL/Top-K)
    static/            placeholder assets so real browsers load JS/CSS/images
  defenses/
    window_rate.py     Round 1 — sliding-window per-IP/endpoint rate
    heavy_hitters.py   Round 2 — Count-Min velocity + HyperLogLog fan-out + Top-K
    regularity.py      Round 3 — Welford timing-regularity (CV)
    cross_key.py       Round 3 — distinct IPs per username (HyperLogLog)
    composite.py       Round 4 — weighted composite with a global campaign term
    consumer.py        the detector runner (checkpoint drain + live serve), level-gated
  attacks/
    _common.py         rules-of-engagement guard, synthetic helpers, event builder, --live
    round0_recon.py    the burst with no detector (the latency gap)
    round1_microburst.py
    round2_ip_rotation.py
    round3_low_and_slow.py
    round4_jittered_browser.py
  tools/
    lab.py             sets import paths + the localhost guard for tools
    legit_traffic.py   40 synthetic customers (the false-positive cohort)
    checkpoint.py      run one round end to end and score both sides
    scoreboard.py      bots flagged vs humans flagged, detection speed, defender cost
    lag.py             watch consumer lag grow when the consumer falls behind
```

## Setup (before the session)

```bash
cd lab
python -m venv .venv && . .venv/bin/activate      # one venv per chapter, see the root README
pip install -r requirements.txt
```

The default store is `memory://` (fakeredis), which implements Redis Streams **and** the
probabilistic commands (Count-Min, Top-K, HyperLogLog), so **no Docker is required**. To run
the identical code against a real Redis 8 instead:

```bash
docker compose up -d --wait        # redis:8.10.2-alpine on 127.0.0.1:6379
export REDIS_URL=redis://localhost:6379/0
```

Redis 8 is required for the real-server path because this chapter uses the probabilistic data
structures Redis 8 ships in core.

| Level | Adds | Module |
|---|---|---|
| L0 | nothing (batch baseline) | — |
| L1 | sliding-window rate | `window_rate.py` |
| L2 | + heavy hitters (sketches) | `heavy_hitters.py` |
| L3 | + regularity + cross-key fan-out | `regularity.py`, `cross_key.py` |
| L4 | + composite verdict | `composite.py` |

## How to measure a round

One command generates the round's attack and 40 legitimate customers, appends every event to
the stream in time order, drains it through the detectors enabled at that round's level, and
scores both sides:

```bash
REDIS_URL=memory:// python tools/checkpoint.py --round 1
```

```text
=== Checkpoint: Round 1 (DEFENSE_LEVEL=1, 563 events) ===

Bot traffic                         sessions flagged
  ✅ bot:microburst               1/1 (100%) (expected: ≥ 95%)

Real users (40 simulated customers) flagged
  ✅ 0/40 flagged   (budget: 0)

Detection speed
  streaming: first verdict a median 1.33s into the session
  batch:     a session-end scorer waits ~9.9s (session length)

Defender cost
  consumer: 563 events at ~760 events/s; backlog pending=0 lag=0

✅ Round 1 checkpoint passed.
```

A round passes when the attack is flagged at or above the expected rate **and no legitimate
customer is flagged**. Add `--slow` to any round to add 1 ms of processing per event and watch
the detection latency grow (a lagging consumer).

**Fell behind?** There is nothing to install. Every detector is pre-written, and the
checkpoint runs the whole pipeline in one process at the round's level, so run
`python tools/checkpoint.py --round N` for the round the class is on.

---

## Round 0: the latency gap (8 min)

- **Attack step:** `python tools/checkpoint.py --round 0`. The micro-burst runs with no
  streaming detector (L0).
- **Observe:** `0/1` flagged; a session-end scorer would wait ~9.9s. That gap is what the rest
  of the lab closes.
- **Checkpoint:** `python tools/checkpoint.py --round 0`.

## Round 1: micro-burst ⚔️ sliding-window detector (20 min)

- **Attack step:** 150 failed logins from one IP in ten seconds.
- **Defense step:** `defenses/window_rate.py` at L1 — trailing-60s count per `(IP, endpoint)`.
- **False-positive check:** the 40 customers, each on their own IP at a human rate, stay clear.
- **Checkpoint:** `python tools/checkpoint.py --round 1`.

## Round 2: IP rotation ⚔️ heavy hitters + distinct counts (24 min)

- **Attack step:** the same campaign across 40 IPs, 4 failed logins each — under any per-IP window.
- **Defense step:** `defenses/heavy_hitters.py` at L2 — Count-Min endpoint velocity, HyperLogLog
  distinct failing IPs, Top-K, gated on the per-session stuffing shape.
- **False-positive check:** humans never fail logins and load assets, so the shape gate spares them.
- **Checkpoint:** `python tools/checkpoint.py --round 2`.

## ☕ Break (10 min)

## Round 3: low-and-slow ⚔️ regularity + distinct-IP fan-out (24 min)

- **Attack step:** five accounts attacked from ~60 distinct IPs each, 1–2 tries per IP, slow.
- **Defense step:** `defenses/cross_key.py` (distinct IPs per username) and `defenses/regularity.py`
  at L3.
- **False-positive check:** each customer logs into their own account from one IP (fan-out = 1).
- **Observe:** the first ~20 attempts per account arrive before the fan-out crosses the threshold
  and get through — the latency cost of distinct-counting. Flagged ≈ `208/300`.
- **Checkpoint:** `python tools/checkpoint.py --round 3`.

## Round 4: jittered browser ⚔️ composite + lag honesty (22 min)

- **Attack step:** browser-like sessions (own IP, assets, jittered timing, rotated usernames);
  most fail 2 logins, a patient quarter fails 1.
- **Defense step:** `defenses/composite.py` at L4, plus `tools/lag.py`.
- **Observe:** no single detector fires; the composite's campaign term flags ≈ `56/80`; the
  patient quarter gets through (the residual). Then:
  ```bash
  python tools/lag.py --produce 160 --rate 160 --consume 60
  ```
  and watch the backlog grow — a slow consumer reopens the gap.
- **Checkpoint:** `python tools/checkpoint.py --round 4` (add `--slow` to see verdicts arrive late).

## Wrap-up: the scoreboard (13 min)

Every round reported humans flagged `0/40` next to the bots caught. Walk the scoreboard: which
detector caught each shape, where the residual survived, and why the next chapter (W3 Ch4) owns
the monitoring, drift and retraining that keep these signals honest over time.

## Instructor: expected results

Verified on Python 3.12.15 with Flask 3.1.3, redis 8.1.0, fakeredis 2.39.0 (`probabilistic` extra) and httpx 0.28.1 on the `memory://` store: checkpoints for rounds 0-4 pass with the numbers below, and the `--live` replay against the app at L2 works. The real Redis 8 path (`docker compose`) runs the identical code; the `docker compose` path is verified separately. Counts are deterministic (seeded).

| Round | Level | Attack | Bots flagged | Humans flagged | Catcher / note |
|---|---|---|---|---|---|
| 0 | 0 | micro-burst | 0 / 1 (none) | 0 / 40 | no detector; batch would wait ~9.9s |
| 1 | 1 | micro-burst | 1 / 1 (100%) | 0 / 40 | `window_rate`; detects ~1.3s in |
| 2 | 2 | IP rotation (40 IPs) | 40 / 40 (100%) | 0 / 40 | `heavy_hitters`; L1 alone misses it |
| 3 | 3 | low-and-slow (300 IPs) | ~208 / 300 (69%) | 0 / 40 | `cross_key`; first ~20 IPs/account get through |
| 4 | 4 | jittered browser (80) | ~56 / 80 (70%) | 0 / 40 | `composite`; patient ¼ is the residual |

Rounds 3 and 4 are intentionally not 100%: detection latency (Round 3) and a patient attacker
(Round 4) are real costs, and the hand-off to W3 Ch4 is explicit.

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: store` / `stream` | Run from `lab/` (e.g. `python tools/checkpoint.py`); `tools/lab.py` sets the import paths. |
| `Cannot reach Redis at redis://…` | Start it (`docker compose up -d --wait`) or use the default `REDIS_URL=memory://`. |
| CMS/TopK errors on a real server | You are on Redis < 8. Use Redis 8 (the compose file pins `8.10.2-alpine`) or the `memory://` store. |
| `--live`: verdicts don't appear | Start the app first: `DEFENSE_LEVEL=2 python demo_site/app.py`, then run an attack with `--live`. A separate app + consumer process needs real Redis, not `memory://`. |
| Port 5000 in use | `PORT=5055 DEMO_URL=http://localhost:5055 python demo_site/app.py` and pass `--live` with the same `DEMO_URL`. |

## Bonus challenges

- Rotate the sketch keys per tumbling window and compare the Count-Min estimate to an exact
  counter to see the over-count error.
- Add a second consumer to the group and confirm the Round 4 `--slow` backlog drains faster.
- Lower the `cross_key` fan-out threshold until a shared test account trips it; record the false
  positive.

## Why these tools

One primary language, Python 3.12+, because the whole series is Flask + Redis and Redis Streams
is the native event log — `XADD` to emit, consumer groups to read, and the probabilistic
commands in the same server. No secondary language, no broker, no per-detector worker. Kafka,
Faust, Bytewax and Flink are the scale-out answer discussed in §3.7; Redpanda is capable but not
open source, so it stays conceptual. `httpx` appears only for the optional `--live` replay.
