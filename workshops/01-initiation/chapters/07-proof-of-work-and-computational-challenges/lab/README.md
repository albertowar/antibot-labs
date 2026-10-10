# Chapter 7 Lab: The Price of a Page

**Format:** 6 rounds of attack ⚔️ defend (73 min) and a 10-min debrief. See `../chapter_07_content.md`, §7.7.

You play both sides. The scraper wants all 200 pages of the store's catalog. The defender puts a proof-of-work (PoW) gate in front of it, and each round tightens the gate.

PoW never really says "no". It says "that will cost you". So every round measures **price** as well as success:

- what the bot paid, in CPU-seconds and dollars per 1,000 pages
- what real users paid, as seconds of waiting on their device

> ⚠️ Run these scripts only against the local demo site. They refuse any target other than `localhost`.

```
lab/
  docker-compose.yml     Redis 8.10 for spent nonces, pass budgets and rate windows
  demo_site/app.py       Flask store; DEFENSE_LEVEL=0..4 picks the defense layers
  demo_site/static/      pow.js (page side) · pow-worker.js (pure-JS SHA-256 solver)
  defenses/              pow_core · challenge_naive · challenge_signed · passes · spend_store · adaptive
  attacks/               round0_bench … round5_playwright_browser, plus _common.py
  tools/                 checkpoint.py · legit_traffic.py
```

**Why Python, plus a little plain JavaScript?**

- Everything you run is Python, as in the rest of Workshop 1.
- The only browser code is the solver the store ships to its visitors: two small JS files with no build step. You read them; you don't have to write them.

---

## Setup (before the session)

```bash
cd lab
docker compose up -d --wait                 # Redis on 127.0.0.1:6379
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
playwright install chromium                 # Round 5 only
```

Python 3.10 or newer. Start the demo site, and restart it with a new `DEFENSE_LEVEL` each round:

```bash
cd demo_site
DEFENSE_LEVEL=0 python app.py               # http://localhost:5000
```

| Level | Adds | Module |
|---|---|---|
| 0 | Nothing. The catalog is open | – |
| 1 | PoW gate on `/api/products`, with a **naive** verifier that trusts the challenge the client sends back | `defenses/challenge_naive.py`, `defenses/passes.py` |
| 2 | Signed challenge: HMAC over nonce, difficulty, expiry and client IP | `defenses/challenge_signed.py` |
| 3 | Single-use challenges; a pass budget of 20 requests or 120 s; the pass bound to IP + User-Agent | `defenses/spend_store.py`, `defenses/passes.py` |
| 4 | Adaptive difficulty from the client's request rate: 16 → 20 → 22 bits | `defenses/adaptive.py` |

Each level includes every level below it.

**How the gate works:**

1. A catalog request without a valid pass gets a `403` with `{"error": "pow_required"}`.
2. The client calls `GET /pow/challenge`, solves the challenge, and `POST`s the answer to `/pow/verify`.
3. It gets back a `pow_pass` cookie.

**Debug endpoints**, never gated:

- `/pow-check` shows the IP the server sees, your rate, the difficulty you would get, and whether your pass is valid.
- `/pow-bench` benchmarks your browser's solver.
- `POST /lab/reset` clears all PoW state. The checkpoint calls it.

> The 403 responses include the reason that fired. That is for teaching only.
> In production, never tell a client which rule caught it.

**Simulated client IPs.** One laptop has to play a desktop user, a phone behind carrier NAT and a 10-IP bot farm at the same time. So every lab client sends `X-Sim-Client-IP`, and the server trusts that header only from loopback, which stands in for your edge proxy (Chapter 3). The addresses come from documentation ranges, so they are nobody's real IP:

| Range | Used for |
|---|---|
| `203.0.113.0/24` | bots |
| `198.51.100.0/24` | real users |
| `100.64.0.7` | the CGNAT household (RFC 6598 shared address space) |

No traffic ever leaves your machine. Don't swap in real proxies.

**Troubleshooting**

| Problem | Fix |
|---|---|
| Port 5000 already in use (macOS: the AirPlay Receiver uses it) | `PORT=5050 DEFENSE_LEVEL=… python app.py`, then `export DEMO_URL=http://localhost:5050` in the shell you run attacks and tools from |
| No Docker | `STORE=memory DEFENSE_LEVEL=… python app.py`. Same results, but the state lives in one process, so it is wrong for multi-worker production setups (see `spend_store.py`) |
| `❌ Redis not reachable` at startup | `docker compose ps`. The container must show as `healthy` |
| Every pass suddenly invalid | You restarted the app. The HMAC secret is random per start, so old passes die with it. Set `POW_SECRET=…` to keep them |
| Round 4 checkpoint is slow | It really solves 22-bit challenges on all your cores, so expect 20–60 s. That is the point of the round |

---

## How to measure a round

Finish every round with a **checkpoint**:

```bash
python tools/checkpoint.py --round <N>      # add --skip-browser to skip the Playwright attack
```

```
=== Checkpoint: Round 3 (server at DEFENSE_LEVEL=3, RedisStore) ===

Real users (simulated devices, desktop 4.0 MH/s, 5 s patience)
  ✅ desktop          16 bits · wait p50 0.01 s, p95 0.05 s · 0% would give up
  ✅ mid_phone        16 bits · wait p50 0.05 s, p95 0.20 s · 0% would give up
  ✅ low_end_phone    16 bits · wait p50 0.18 s, p95 0.79 s · 0% would give up
  ⚠️  no_js_reader     BLOCKED: ['[L3] no PoW pass: solve /pow/challenge first']  (the price of any JS-only gate)
  ✅ cgnat_neighbour  16 bits · wait p50 0.18 s, p95 0.79 s · 0% would give up

Bot traffic                          pages     solves  bits      price per 1,000 pages
  ✅ round1_naive_scraper              0/200       0   -         -
  ✅ round1_forge_difficulty           0/200       0   -         -
  ✅ round2_solve_once_replay         20/200       1   16          13.14 CPU-s  $0.000146
  ✅ round3_solver_pool              200/200      10   16          20.37 CPU-s  $0.000226
  ✅ round4_distributed              200/200      10   16          23.89 CPU-s  $0.000265
  ⏭️  round5_playwright_browser       skipped (--skip-browser)

Defender cost
  pass check: median 151 µs · verify: median 393 µs · store ops per page: 1
  (bot prices assume $0.04 per vCPU-hour)

✅ Round 3 checkpoint passed.
```

What it reports:

- **Real users.** `tools/legit_traffic.py` runs five simulated visitors, each with a device hash rate.
  - The server picks their difficulty. Their wait is hashes ÷ device rate, reported as p50/p95 plus the share who would give up after 5 s.
  - `no_js_reader` can't solve at all. Any `❌` here is a **false positive** you didn't expect.
  - Set `DESKTOP_MHS` to your own `/pow-bench` number. The phones are scaled from it (÷4 and ÷16, which are assumptions).
- **Bot traffic:** pages scraped, solves, the difficulties seen, and the price per 1,000 pages. CPU-seconds are measured with `time.process_time()` in every solver process. Dollars assume $0.04 per vCPU-hour.
- **Defender cost:** time spent checking passes and verifying solutions, from the `Server-Timing` header, plus store operations per page.

**Fell behind?** Every defense is already written, so catching up just means restarting the demo site with `DEFENSE_LEVEL=<N>`. The checkpoint tells you if you're on the wrong level.

---

## Round 0: What does a hash cost? (8 min)

**🔴 Attack (measure):**

```bash
python attacks/round0_bench.py              # 1 core and all cores, and what 16/20/22 bits cost
```

**🔵 Defend (measure):**

Open `http://localhost:5000/pow-bench` and click **Run benchmark**. Fill in:

| | Python, 1 core | Python, all cores | Browser, 1 worker | Browser, 4 workers |
|---|---|---|---|---|
| MH/s | | | | |
| 16 bits p95 | | | | |

Don't expose the demo site to your LAN to test a phone: it runs Flask's debug server, and its debugger executes code. The phone rates in `legit_traffic.py` are assumptions for that reason.

Then `export DESKTOP_MHS=<browser, 4 workers>` so the simulated users match your laptop.

**Checkpoint:** `python tools/checkpoint.py --round 0`. Everything gets through and nobody is challenged.

---

## Round 1: PoW gate ⚔️ forged difficulty (15 min)

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `defenses/pow_core.py` and `defenses/challenge_naive.py`, then restart with `DEFENSE_LEVEL=1` | – |
| 🔴 Attack | `python attacks/round1_naive_scraper.py` | `0/200`: `no PoW pass: solve /pow/challenge first` |
| 🔵 Look | Open `/` in your browser. Then disable JavaScript and reload | "Verified in … ms (16 bits)". Without JS: nothing, ever |
| 🔴 Attack | Read the `challenge_naive.verify` docstring, then run `python attacks/round1_forge_difficulty.py` | `200/200`, **0 hashes**. The bot sent `"difficulty": 0` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | forge gets through · no-JS reader blocked (⚠️) |

**Discuss:**

- Which field in the challenge should the client never control? (All of them.)
- This exact bug shipped in Anubis as CVE-2025-24369.
- The no-JS reader is blocked from now on, by design. Who are they? Text browsers, some accessibility setups, hardened privacy configs, and many legitimate API clients.

---

## Round 2: signed challenge ⚔️ solve once, replay (15 min)

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `defenses/challenge_signed.py` and `defenses/passes.py`, then restart with `DEFENSE_LEVEL=2` | – |
| 🔴 Re-run | `python attacks/round1_forge_difficulty.py` | `0/200`: `challenge signature invalid (was it edited?)` |
| 🔴 Attack | `python attacks/round2_solve_once_replay.py` | `200/200` for **one** solve: ~65k hashes, a fraction of a CPU-second |
| 🔴 Attack | `python attacks/round2_solve_once_replay.py --share` | `200/200`: the pass works from a second IP too |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | forge blocked · solve-once gets through |

**Discuss:** the challenge is now honest, but what did the solution *buy*? Chapter 5 said it: "solve once, replay a million times". What would you need to remember on the server to stop it?

---

## ☕ Break (10 min)

---

## Round 3: single use + pass budget ⚔️ solver pool (15 min)

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `defenses/spend_store.py` and the L3 parts of `check_pass()` and `pow_verify()` in `app.py`, then restart with `DEFENSE_LEVEL=3` | – |
| 🔴 Re-run | `python attacks/round2_solve_once_replay.py` | `20/200`: `PoW pass used up`, then `challenge already redeemed (replay)` |
| 🔴 Re-run | `python attacks/round2_solve_once_replay.py --share` | `1/200`: `PoW pass is bound to another client` |
| 🔴 Attack | `python attacks/round3_solver_pool.py` | `200/200`, 10 solves at 16 bits. Note the **price per 1,000 pages** |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | solve-once partial (20/200) · pool gets through · 0 JS users blocked |

**Exercise:** write the bot's price next to Chapter 6's CAPTCHA-farm price (about $1 per 1,000 solves). How many orders of magnitude apart are they? Now take Round 0's GPU figure (~20,000 MH/s of SHA-256) and redo the sum.

---

## Round 4: adaptive difficulty ⚔️ many small clients (15 min)

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `defenses/adaptive.py`, then restart with `DEFENSE_LEVEL=4` | – |
| 🔴 Re-run | `python attacks/round3_solver_pool.py` | `200/200`, but the solves climb to **20 and 22 bits**: the price goes up 25–35× |
| 🔵 Look | `curl -H 'X-Sim-Client-IP: 203.0.113.66' localhost:5000/pow-check` | `rate_last_60s` is high and `difficulty_now` is 22 |
| 🔴 Attack | `python attacks/round4_distributed.py` | `200/200`, every solve at **16 bits**: back to Round 3's price |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | pool climbs to ≥ 20 bits · distributed stays at 16 · **cgnat_neighbour ⚠️ 22 bits, ~74% would give up** |

**False positive:** `cgnat_neighbour` is one budget phone. It shares `100.64.0.7` with its neighbours (150 requests a minute), so it pays the 22-bit price: an 11 s median wait.

**Exercise:** do the `TODO (Round 4)` in `adaptive.py`, which keys the rate by /24 instead of by IP. Re-run the checkpoint.

- What happens to `round4_distributed`? All its IPs sit in `203.0.113.0/24`.
- What happens to everybody else in a /24? Chapter 3's IP reputation has the same trade-off.

---

## Round 5: the browser pays (5 min)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round5_playwright_browser.py` (still level 4) | `60/60`. The page's own Web Workers solve each challenge in about the time your `/pow-bench` predicted |
| ✅ Checkpoint | `python tools/checkpoint.py --round 5` | everything as in Round 4, plus the browser gets through |

The bot pays exactly what a human pays, and PoW has nothing left to say. PoW **prices** requests; it doesn't **identify** clients. Telling this browser apart from a person is the job of these chapters:

- automation artefacts: Workshop 2, Chapter 1
- behavior: Workshop 2, Chapter 3
- layering it all: Chapter 9

---

## Debrief: price, false positives and cost (10 min)

```bash
python tools/legit_traffic.py               # per-device wait at the current level
```

- Fill in the scoreboard on the slides. For each round, give the bot's price per 1,000 pages and the real users who were blocked or gave up.
- Which users did PoW hurt, even though it never "blocked" them?
- The defender's cost: a pass check is about 0.15 ms and one store op per page. What does replay protection add to the request path in production? (Hint: Redis round trips, and a fail-open or fail-closed decision.)

---

## Instructor: expected results

**Test setup:**

- **Verified on:** Python 3.10.12, Flask 3.1.3, httpx 0.28.1, Playwright 1.63.0 (Chromium), with both `STORE=memory` and a Redis-protocol server. The Redis runs used `fakeredis` 2.39 in TCP mode, because Docker wasn't available on the test machine. The `docker compose` path itself is not yet verified against a real Redis container.
- **Hardware:** a shared 6-core Xeon W-2133 under WSL2. It measured Python at ≈ 0.3 MH/s per core and the browser solver at ≈ 0.9 MH/s per worker (2.2 MH/s on 4 workers). An unloaded laptop is typically 2–4× faster in Python, so CPU-seconds will be lower and the ratios the same.

Pages scraped out of 200 (Round 5: out of 60). **Bold** marks the level where the attack stops:

| Attack ↓ / `DEFENSE_LEVEL` → | 0 | 1 | 2 | 3 | 4 | Reason / price |
|---|---|---|---|---|---|---|
| `round1_naive_scraper` | 200 | **0** | 0 | 0 | 0 | `[L1] no PoW pass` |
| `round1_forge_difficulty` | 200 | 200 | **0** | 0 | 0 | `[L2] challenge signature invalid` |
| `round2_solve_once_replay` | 200 | 200 | 200 | **20** | 20 | `[L3] PoW pass used up` → `challenge already redeemed (replay)` |
| `round3_solver_pool` | 200 | 200 | 200 | 200 | 200 | L3: 10 solves at 16 bits, ≈ 8–26 CPU-s/1k pages (≈ $0.0001–0.0003). L4: climbs to 20–22 bits, ≈ 210–850 CPU-s/1k (≈ $0.002–0.009), **25–35× the L3 price** |
| `round4_distributed` | 200 | 200 | 200 | 200 | 200 | L4: every solve at 16 bits, ≈ 11–26 CPU-s/1k (back to the L3 price) |
| `round5_playwright_browser` | 60 | 60 | 60 | 60 | 60 | 4 solves, 80–350 ms each at 16–20 bits |
| Real users with JS (4) | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | all solve in < 1 s at p95 at 16 bits |
| `no_js_reader` | ok | ⚠️ blocked | ⚠️ | ⚠️ | ⚠️ | the price of a JS-only gate |
| `cgnat_neighbour` | ok | ok | ok | ok | ⚠️ 22 bits | p50 11.6 s, p95 50 s, 74% would give up |

**Defender cost** (Flask dev server, memory store):

- pass check ≈ 0.15 ms
- verify ≈ 0.3–0.8 ms
- store ops per page: 0 at L1–L2, 1 at L3 (budget), 2 at L4 (budget + rate)

**Things to watch for:**

- **Checkpoint time.** It solves for real, so the Round 4 and 5 checkpoints take 20–60 s on a laptop. Start them before you start talking.
- **Re-running a single attack** right after the checkpoint (within 60 s) reuses the rate window for that IP, so the difficulties you see can be higher. `curl -X POST localhost:5000/lab/reset` gives you a clean slate.
- **Machine-to-machine variance.** CPU-seconds differ up to 4× between laptops. The checkpoint only checks outcomes and difficulty levels, so it doesn't fail on slow machines.

---

## Bonus challenges

1. **Memory-hard PoW.** Swap SHA-256 for Argon2id (`pip install argon2-cffi==25.1.0`) in `pow_core.digest`, with a small `memory_cost`. Then measure:
   - How many hashes per second do you get now?
   - What happens to the gap between your laptop and a GPU? Between your laptop and a phone?
   - Which side does this help?
2. **Pass budget by action.** Give `/login` its own pass (one solve per login attempt) and leave the catalog on the cheap budget. Which abuse does each budget price?
3. **Swap in ALTCHA.** Replace `challenge_signed.py` with the `altcha` Python library (2.3.0, MIT) and its widget. Which of our L2–L4 properties do you get for free, and which do you still have to build?
