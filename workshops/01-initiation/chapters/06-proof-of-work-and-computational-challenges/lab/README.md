# Chapter 6 Lab: The Price of a Page

Starts from: workshops/01-initiation/starter/ (contract 1.5). Adds: a `pow` challenge type, a three-scheme verifier (naive, signed, single-use), a pass budget and adaptive difficulty, the browser solver, six attack scripts and the Chapter 6 shoppers.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/challenge_naive.py`
- `defenses/challenge_signed.py`
- `defenses/pow_adaptive.py`
- `defenses/pow_budget.py`
- `defenses/pow_challenge.py`
- `defenses/pow_core.py`
- `defenses/pow_gate.py`
- `demo_site/ext/pow.py`
- `demo_site/ext/templates/pow/bench.html`
- `demo_site/ext/templates/pow/interstitial.html`
- `demo_site/ext/templates/pow/solver.html`
- `demo_site/static/js/pow-worker.js`
- `demo_site/static/js/pow.js`
- `tools/personas_ch6.py`
- `tools/pow_client.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** 6 rounds of attack and defense, two lessons on PoW in production and the people it hurts, and a debrief. See `../chapter_06_content.md`, section 6.7.

You play both sides. The scraper wants the whole catalog: all 120 product records. The defender puts a proof-of-work (PoW) gate in front of it, and each round tightens the gate.

PoW never really says "no". It says "that will cost you". So every round measures **price** as well as success:

- what the bot paid, in CPU-seconds and dollars per 1,000 products
- what real shoppers paid, as seconds of waiting on their device, and who gave up

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root (via `tools/labclient.py`), which refuses any target that is not this machine before a single request is sent, and any non-local `REDIS_URL` or `DATABASE_URL`. Do not remove that check.
- Simulated client addresses come from `data/world.json` and are sent in `X-Lab-Client-IP`, which the store's edge trusts only from loopback. The CPU cost is real, but it is your own CPU.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  demo_site/ext/pow.py            the feature: challenge type "pow", solver slot, /lab/pow/bench and /lab/pow/check
  demo_site/ext/templates/pow/    interstitial.html (the 403 page) · solver.html · bench.html
  demo_site/static/js/            pow.js (page side) · pow-worker.js (pure-JS SHA-256 solver)
  defenses/                       pow_core · challenge_naive · challenge_signed · pow_challenge (the scheme per level)
                                  pow_gate (L1) · pow_budget (L3) · pow_adaptive (L4) · ladder.py · policy.py
  attacks/                        round0_bench ... round5_playwright_browser
  tools/                          checkpoint.py · pow_client.py (Python solver + scrape loop) · personas_ch6.py (shoppers)
  solutions/round1..5/            reference ladder.py and policy.py per round (the catch-up files)
```

The rest of the store (catalog, cart, checkout, drops, accounts, the simulated edge, the decision log) is the Workshop 1
starter, unchanged. Its contract is `workshops/STORE_CONTRACT.md`.

**Why Python, plus a little plain JavaScript?**

- Everything you run is Python, as in the rest of Workshop 1.
- The only browser code is the solver the store ships to its visitors: two small JS files with no build step. You read them; you don't have to write them.

---

## Setup

Setup is covered once for the whole series in `onboarding/setup/PREWORK.md`. For this lab:

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-browser.txt                 # Round 5 only
python -m playwright install chromium                   # Round 5 only
python tools/doctor.py                                  # READY?
python demo_site/app.py                                 # http://127.0.0.1:5000
```

No Docker is needed (SQLite and an in-process Redis). With Docker, `docker compose up -d --wait` starts Redis 8.10 and
PostgreSQL 18 as in the starter README. Port 5000 busy (macOS AirPlay)? `PORT=8099 python demo_site/app.py`, then
`export DEMO_URL=http://127.0.0.1:8099` in the shell where you run attacks and tools.

You never restart the store between rounds. The checkpoint sets the level for you (`POST /lab/level`); to look around by
hand, set it yourself: `curl -X POST localhost:5000/lab/level -H 'content-type: application/json' -d '{"level": 2}'`, or start
the store with `DEFENSE_LEVEL=2`.

| Level | Adds | Module |
|---|---|---|
| 0 | Nothing. The catalog is open | none |
| 1 | PoW gate on the catalog, with a **naive** verifier that trusts the challenge the client sends back | `pow_gate.py`, `challenge_naive.py` |
| 2 | Signed challenge: HMAC over nonce, difficulty, expiry and client IP | `challenge_signed.py` |
| 3 | Single-use challenges; a pass worth 20 requests or 120 s, bound to IP + User-Agent | `pow_budget.py`, `pow_challenge.py` |
| 4 | Adaptive difficulty from the client's request rate: 16, 20 or 22 bits | `pow_adaptive.py` |

Each level includes every level below it. This lab ships its defenses **pre-written**: you read each round's module, then
switch levels. `defenses/ladder.py` shows what runs at each level (`LADDER[N]`); `python tools/checkpoint.py --round N
--catch-up` reinstalls the reference `ladder.py` and `policy.py` from `solutions/` if you edited them.

**How the gate works:**

1. A catalog request (`/products`, `/product/<sku>`, `/api/products...`) from a session without a pass gets a `403`: the
   interstitial page for browsers, `{"error": {"code": "challenge_required", "challenge": "pow", "payload": {...}}}` for JSON clients.
2. The client solves the payload (`GET /api/challenge?type=pow` returns a fresh one) and posts `{"type": "pow", "answer":
   {"challenge": payload, "counter": n}}` to `POST /api/challenge/verify`.
3. The session is cleared. The page's JavaScript then reloads the page it came from.

**Lab pages** (loopback only, never gated):

- `/lab/pow/bench`: benchmarks your browser's solver and posts the result to `/api/telemetry` as `kind: "pow_bench"`.
- `/lab/pow/check`: the IP the store sees, your request rate, the difficulty you would get now, and whether your session has a pass.
- `/lab/decisions?actor=bot:pow&limit=5`: every decision, with `extra.pow_reason` explaining a refused answer. The client only ever
  sees `challenge_failed`; in production never tell a client which rule caught it.
- `POST /lab/reset`: clears state. The checkpoint calls it.

**Simulated client IPs.** One laptop has to play a desktop shopper, a phone behind carrier NAT and a 10-IP bot farm at the
same time. Every lab client rents its source address from `data/world.json` and sends it in `X-Lab-Client-IP`; the store's edge
only honours addresses inside a pool. They are documentation ranges, so they are nobody's real IP. Bots rent from
`cloud_vm` (`203.0.113.0/26`), shoppers from the residential, mobile and VPN pools, and the CGNAT phones share two addresses
in `mobile_cgnat` (`198.51.100.0/30`). No traffic ever leaves your machine. Don't swap in real proxies.

**Troubleshooting**

| Problem | Fix |
|---|---|
| Port 5000 already in use | `PORT=5050 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:5050` for attacks and tools |
| A round's results look wrong | `curl -X POST localhost:5000/lab/reset`: re-running an attack within 60 s reuses its IP's rate window, so difficulties can be higher |
| Every pass suddenly invalid | You restarted the store. The HMAC secret is random per start, so old challenges die with it. Set `POW_SECRET=...` to keep them |
| `Executable doesn't exist` in Round 5 | `python -m playwright install chromium` |
| The Round 4 checkpoint is slow | It solves 22-bit challenges on all your cores, and the shoppers wait as long as a phone would. Expect up to a minute |

---

## How to measure a round

Finish every round with a **checkpoint**:

```bash
python tools/checkpoint.py --round <N>
python tools/scoreboard.py --markdown        # the store's own view: bots stopped vs shoppers hurt
```

It sets the level, resets the store, runs the round's attacks one after the other while 40 simulated shoppers browse and buy, and then prints:

- **The scoreboard.** Requests served and stopped per actor, with the gate's average cost in milliseconds. A shopper counts as
  "stopped" for every request that got a challenge, **including the first interstitial of a shopper who then solved it**. That is
  why the shoppers table below is the real measure of harm.
- **The bots table.** Products scraped, solves, difficulties, and the price per 1,000 products in CPU-seconds and dollars. CPU-seconds
  are measured with `time.process_time()` in every solver process. Dollars assume $0.04 per vCPU-hour.
- **The shoppers table.** Per persona: how many solved, how many gave up, how many have no JavaScript, the highest difficulty
  they met and their median wait. The wait is `hashes / device rate`: `tools/personas_ch6.py` really solves each challenge and
  then sleeps for what the person's device would have taken, and a shopper whose device needs more than 5 s leaves. Desktops run
  at `DESKTOP_MHS` (default 4.0 MH/s); iOS phones at 1/4 and Android phones at 1/16 of that, which are assumptions. Set
  `DESKTOP_MHS` to your Round 0 browser number.
- **PASS or FAIL**, against the round's thresholds in `tools/checkpoint.py`.

The scoreboard's `gate ms` column is the whole request's time on the server, not only the defenses. The cost of each check is in
the `Server-Timing` header of every response: `curl -si localhost:5000/api/products/p001 | grep -i server-timing`
(`pow_gate;dur=0.23` is the L1 gate's own cost).

**Fell behind?** Every defense is already written. `python tools/checkpoint.py --round N --catch-up` reinstalls the reference
`defenses/ladder.py` and `defenses/policy.py` for rounds 1..N (your files are kept as `.bak`).

---

## Round 0: What does a hash cost?

**Attack (measure):**

```bash
python attacks/round0_bench.py              # 1 core and all cores, and what 16/20/22 bits cost
```

**Defend (measure):**

Open `http://127.0.0.1:5000/lab/pow/bench` and click **Run benchmark**. Fill in:

| | Python, 1 core | Python, all cores | Browser, 1 worker | Browser, 4 workers |
|---|---|---|---|---|
| MH/s | | | | |
| 16 bits p95 | | | | |

Don't expose the store to your LAN to test a phone. The phone rates in `personas_ch6.py` are assumptions for that reason.

Then `export DESKTOP_MHS=<browser, 4 workers>` so the simulated shoppers match your laptop.

**Checkpoint:** `python tools/checkpoint.py --round 0`. The naive scraper gets all 120 products and nobody is challenged.

---

## Round 1: PoW gate vs forged difficulty

| Step | Do | Expected |
|---|---|---|
| Defend | Read `defenses/pow_gate.py`, `pow_challenge.py` and `challenge_naive.py`, then `curl -X POST localhost:5000/lab/level -H 'content-type: application/json' -d '{"level": 1}'` | |
| Attack | `python attacks/round1_naive_scraper.py` | `0/120`: `pow:no_pass` |
| Look | Open `/products` in your browser. Then disable JavaScript and reload | "Verified in ... ms (16 bits)", then the catalog. Without JS: the wall, forever |
| Attack | Read the `challenge_naive.verify` docstring, then run `python attacks/round1_forge_difficulty.py` | `120/120`, **0 hashes**. The bot sent `"difficulty": 0` |
| Checkpoint | `python tools/checkpoint.py --round 1` | forge gets through, naive scraper blocked, `no_js` shopper hurt |

**Discuss:**

- Which field in the challenge should the client never control? (All of them.)
- This exact bug shipped in Anubis as CVE-2025-24369.
- The no-JS shopper is blocked from now on, by design. Who are they? Text browsers, some accessibility setups, hardened privacy configs, and many legitimate API clients.

---

## Round 2: signed challenge vs solve once, replay

| Step | Do | Expected |
|---|---|---|
| Defend | Read `defenses/challenge_signed.py`, then set level 2 | |
| Re-run | `python attacks/round1_forge_difficulty.py` | `0/120`: pow_reason `challenge signature invalid (was it edited?)` |
| Attack | `python attacks/round2_solve_once_replay.py` | `120/120` for **one** solve: ~65k hashes, a fraction of a CPU-second |
| Attack | `python attacks/round2_solve_once_replay.py --share` | `120/120`: the cleared session works from a second IP too |
| Checkpoint | `python tools/checkpoint.py --round 2` | forge blocked, solve-once and shared pass get through |

**Discuss:** the challenge is now honest, but what did the solution *buy*? Chapter 8 said it: "solve once, replay a million times". What would you need to remember on the server to stop it?

---

## Round 3: single use + pass budget vs solver pool

| Step | Do | Expected |
|---|---|---|
| Defend | Read `defenses/pow_budget.py` and the L3 parts of `pow_challenge.verify`, then set level 3 | |
| Re-run | `python attacks/round2_solve_once_replay.py` | `20/120`: `pow:pass_used_up`, then `challenge already redeemed (replay)` |
| Re-run | `python attacks/round2_solve_once_replay.py --share` | `1/120`: `pow:pass_bound_elsewhere` |
| Attack | `python attacks/round3_solver_pool.py` | `120/120`, 6 solves at 16 bits. Note the **price per 1,000 products** |
| Checkpoint | `python tools/checkpoint.py --round 3` | solve-once partial (20/120), share stopped, pool gets through, only `no_js` hurt |

**Exercise:** write the bot's price next to Chapter 5's CAPTCHA-farm price (about $1 per 1,000 solves). How many orders of magnitude apart are they? Now take Round 0's GPU figure (~21,000 MH/s of SHA-256: an RTX 4090 in hashcat 6.2.6's mode 1400 benchmark) and redo the sum.

---

## Round 4: adaptive difficulty vs many small clients

| Step | Do | Expected |
|---|---|---|
| Defend | Read `defenses/pow_adaptive.py` and `policy.POW_ADAPTIVE`, then set level 4 | |
| Re-run | `python attacks/round3_solver_pool.py` | `120/120`, but the solves climb to **20 and 22 bits**: the price goes up 16-64x |
| Look | `curl -H 'X-Lab-Client-IP: 203.0.113.9' localhost:5000/lab/pow/check` | `rate_last_60s` is high and `difficulty_now` is 22 |
| Attack | `python attacks/round4_distributed.py` | `120/120`, every solve at **16 bits**: back to Round 3's price |
| Checkpoint | `python tools/checkpoint.py --round 4` | pool climbs to 20+ bits, distributed stays at 16, **`mobile_cgnat` shoppers pay 20-22 bits and the slow phones give up** |

**False positive:** the `mobile_cgnat` shoppers are budget phones that share two carrier-NAT addresses with their neighbours, so they pay the
price the neighbours' browsing set. An Android phone at 22 bits needs about 16 s on average and leaves.

**Exercise (discussion):** follow the `Exercise (Round 4, discussion)` note in `pow_adaptive.py`'s `rate_key`, which keys the rate by /24 instead of by IP. Re-run the checkpoint.

- What happens to `round4_distributed`? All its IPs sit in `203.0.113.0/24`.
- What happens to everybody else in a /24? Chapter 2's `prefix_limit` and Chapter 3's IP reputation made the same trade.

There is no reference file for this one: the Round 4 checkpoint expects the IP key, so with the /24 key it reports
`FAIL: round4_distributed: unexpected difficulty [22]`. That is the expected result. `--catch-up` does not undo the edit;
put `return ip` back before Round 5.

*Model answer (measured on the test machine):*

- **The distributed bot pays.** Its 10 addresses share one counter, so every solve climbs to 22 bits: 120/120 still,
  but about 900 CPU-s per 1,000 products instead of 10–16. That is the 64× of Round 4's pool.
- **So do the neighbours.** The 3 `consumer_vpn` shoppers (203.0.113.128/27) share the bot's /24 and pay 22 bits.
  The 24 `home` shoppers sit in two ISPs' /26s inside 192.0.2.0/24, so they now share one rate, and all of them meet
  22 bits instead of 16. The desktops still finish in about a second, so nobody new gave up in this run, but a phone in
  that /24 would. `mobile_cgnat` and `private_relay` share 198.51.100.0/24; 2 of the 8 CGNAT phones gave up, as before.
- **The lesson:** the bigger the key, the more strangers share a price. A /24 catches the farm and charges everyone
  near it — the trade-off you measured in Chapter 2 (`prefix_limit`'s loose /24 and tight /64 buckets) and met again
  in Chapter 3's reputation by prefix. The attacker's next move is addresses spread across many /24s: residential proxies.

---

## Round 5: the browser pays

| Step | Do | Expected |
|---|---|---|
| Attack | `python attacks/round5_playwright_browser.py` (still level 4) | `60/60`. The page's own Web Workers solve each challenge in about the time `/lab/pow/bench` predicted |
| Checkpoint | `python tools/checkpoint.py --round 5` | the browser gets through; shoppers as in Round 4 |

The bot pays exactly what a human pays, and PoW has nothing left to say. PoW **prices** requests; it doesn't **identify** clients. Telling this browser apart from a person is the job of these chapters:

- automation artefacts: Workshop 2, Chapter 1
- behavior: Workshop 2, Chapter 5
- layering it all: Chapter 9

---

## Debrief: price, false positives and cost

```bash
python tools/personas_ch6.py                 # the shoppers alone, at the current level
python tools/scoreboard.py                   # bots stopped vs shoppers hurt
```

- Fill in the scoreboard on the slides. For each round, give the bot's price per 1,000 products and the shoppers who were blocked or gave up.
- Which shoppers did PoW hurt, even though it never "blocked" them?
- The defender's cost: each check is under a millisecond (see `Server-Timing`), and L3 and L4 add Redis round trips per protected request. What does replay protection add to the request path in production? (Hint: Redis round trips, and a fail-open or fail-closed decision.)

---

## Expected results (self-check)

**Test setup**

- **Verified on:** Python 3.12.15, Flask 3.1.3, requests 2.34.2, fakeredis 2.39.0 (the store's default `memory://` Redis) with SQLite, and Playwright 1.63.0 (Chromium) for Round 5. The `docker compose` Redis 8.10 / PostgreSQL 18.6 path passes every round too (2026-10-17).
- **Hardware:** a shared 12-thread Xeon W-2133 under WSL2, busy with other jobs while this ran, so the CPU-seconds and the gate times below are pessimistic. An unloaded laptop is typically 2-4x faster in Python; the ratios stay the same.
- **Source:** `python tools/verify.py --round N` for every round at its own level (defended), the same attacks one level lower (undefended), and `--catch-up` for rounds 3 and 5. Shoppers: 40 (`DESKTOP_MHS=4.0`, 5 s patience).

**The attacks, one level lower and at the round's level.** Products scraped out of 120 (Round 5: out of 60), then the solves, the difficulties and the price per 1,000 products:

| Round | Attack | Level N-1 (undefended) | Level N (the round's defense) | Price at level N |
|---|---|---|---|---|
| 1 | `round1_naive_scraper` | 120/120 (L0) | **0/120**, `pow:no_pass` | none, it never pays |
| 1 | `round1_forge_difficulty` | 120/120 (L0) | 120/120, 0 hashes | 0 CPU-s: the verifier trusts the client's difficulty |
| 2 | `round1_forge_difficulty` | 120/120 (L1) | **0/120**, signature invalid | none |
| 2 | `round2_solve_once_replay` | 120/120 (L1) | 120/120 for 1 solve | 0.3-1.1 CPU-s per 1,000 (about $0.00001) |
| 2 | `round2_solve_once_replay --share` | 120/120 (L1) | 120/120 from a second IP | about the same |
| 3 | `round2_solve_once_replay` | 120/120 (L2) | **20/120**: `pass_used_up`, then replay refused | 1.5-2.9 CPU-s per 1,000 |
| 3 | `round2_solve_once_replay --share` | 120/120 (L2) | **1/120**: `pass_bound_elsewhere` | the thief gets nothing |
| 3 | `round3_solver_pool` | 120/120, 1 solve (L2) | 120/120, 6 solves at 16 bits | 7.2-11.2 CPU-s per 1,000 (about $0.0001) |
| 4 | `round3_solver_pool` | 6 solves, 16 bits (L3) | 120/120, solves at 16 and **22** bits | 343-503 CPU-s per 1,000 (about $0.004-0.006), 30-70x L3 |
| 4 | `round4_distributed` | 10 solves, 16 bits (L3) | 120/120, 10 solves, all **16** bits | 10.5-16 CPU-s per 1,000: back to the L3 price |
| 5 | `round5_playwright_browser` | 60/60 (L4) | 60/60, 3 solves at 16 and 22 bits | 42-111 CPU-s per 1,000 (4 workers x wall time) |

**The shoppers** (40 per run; the measure of harm). "Hurt" means the shopper never got the page:

| Level | `no_js` (1) | `mobile_cgnat` (8, two shared addresses) | everyone else (31) |
|---|---|---|---|
| 0 | buys | buy | buy |
| 1-3 | **hurt**: the interstitial is a wall | all solve at 16 bits, median wait under 0.2 s | all solve at 16 bits, median wait under 0.1 s |
| 4 | **hurt** | **1-3 of 8 give up** at 22 bits (4 runs: 1, 2, 2, 3; Round 5: 1, 2, 1, 0); the rest solve | all solve at 16 bits |

The scoreboard counts hurt **people** (the last thing that happened to them was a stop and they bought nothing), so it agrees with the table above: 1 of 40 at levels 1-3, 2-4 of 40 at level 4. The "requests stopped" figure next to it (40 of about 310) is every shopper's first interstitial before they solved it: the challenge working, not harm.

**Defender cost** (median per request, `Server-Timing`, Flask dev server, level 4, one cleared client): whole request 3.7 ms, `pow_gate` 0.23 ms, `pow_budget` 0.59 ms, `pow_adaptive` 0.52 ms. The scoreboard's `gate ms` column is the same defender cost (`Server-Timing: gate`); the whole request is `Server-Timing: app`.

**Things to watch for:**

- **Checkpoint time.** The shoppers wait as long as their phones would, and the solves are real. Round 0 takes about a minute (the benchmark), Rounds 4 and 5 up to a minute.
- **Re-running a single attack** right after the checkpoint (within 60 s) reuses that IP's rate window at level 4, so the difficulties you see can be higher. `curl -X POST localhost:5000/lab/reset` gives a clean slate.
- **Machine-to-machine variance.** CPU-seconds differ up to 4x between laptops. The checkpoint checks outcomes and difficulty levels, not seconds, so it does not fail on slow machines.
- **Round 4 is stochastic.** How many `mobile_cgnat` phones give up depends on the number of hashes each challenge happens to need. The checkpoint only requires that a CGNAT shopper met 20 or more bits.
- **`--share` at L2/L1** works because the pass *is* the session cookie. At L3 the pass is bound to IP + User-Agent, so the second IP is challenged.

<details><summary>The scoreboards, from <code>python tools/verify.py --all --markdown</code> (one run; the gate ms column is defender cost per request: Ctx build, enrichers and every check)</summary>

**Round 1: PoW gate with a naive verifier: naive scraper stopped, forged difficulty walks in (level 1)**

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:pow-forge | 122 | 121 | 0 | 1 | 0.3 | 0.94 |
| bot:pow-naive | 1 | 0 | 0 | 1 | 40.0 | 2.34 |
| human:autofill | 8 | 7 | 1 | 1 | 5.0 | 1.77 |
| human:consumer_vpn | 24 | 21 | 3 | 3 | 5.0 | 1.83 |
| human:home | 192 | 168 | 24 | 24 | 5.0 | 1.94 |
| human:mobile_cgnat | 64 | 56 | 8 | 8 | 5.0 | 1.78 |
| human:no_js | 2 | 1 | 0 | 1 | 20.0 | 2.62 |
| human:old_chrome | 8 | 7 | 1 | 1 | 5.0 | 1.69 |
| human:private_relay | 16 | 14 | 2 | 2 | 5.0 | 1.76 |

Bots stopped: **2/123** requests · shoppers hurt: **1/40** people (40/314 requests stopped, including challenges they then solved) · purchases: {'human': 39} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

**Round 2: signed challenge: forgery stopped, solve once and replay still works (level 2)**

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:pow-forge | 2 | 1 | 0 | 1 | 20.0 | 1.31 |
| bot:pow-replay | 244 | 242 | 0 | 2 | 0.3 | 0.96 |
| human:autofill | 8 | 7 | 1 | 1 | 5.0 | 2.19 |
| human:consumer_vpn | 24 | 21 | 3 | 3 | 5.0 | 1.29 |
| human:home | 192 | 168 | 24 | 24 | 5.0 | 1.65 |
| human:mobile_cgnat | 64 | 56 | 8 | 8 | 5.0 | 1.57 |
| human:no_js | 2 | 1 | 0 | 1 | 20.0 | 2.76 |
| human:old_chrome | 8 | 7 | 1 | 1 | 5.0 | 1.71 |
| human:private_relay | 16 | 14 | 2 | 2 | 5.0 | 1.61 |

Bots stopped: **3/246** requests · shoppers hurt: **1/40** people (40/314 requests stopped, including challenges they then solved) · purchases: {'human': 39} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

**Round 3: single use + pass budget + bound pass: replay and sharing stopped, the solver pool pays (level 3)**

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:pow-pool | 132 | 126 | 0 | 6 | 1.8 | 1.44 |
| bot:pow-replay | 28 | 24 | 0 | 4 | 5.7 | 2.17 |
| human:autofill | 8 | 7 | 1 | 1 | 5.0 | 2.39 |
| human:consumer_vpn | 24 | 21 | 3 | 3 | 5.0 | 1.88 |
| human:home | 192 | 168 | 24 | 24 | 5.0 | 1.86 |
| human:mobile_cgnat | 64 | 56 | 8 | 8 | 5.0 | 2.06 |
| human:no_js | 2 | 1 | 0 | 1 | 20.0 | 3.27 |
| human:old_chrome | 8 | 7 | 1 | 1 | 5.0 | 1.67 |
| human:private_relay | 16 | 14 | 2 | 2 | 5.0 | 2.01 |

Bots stopped: **10/160** requests · shoppers hurt: **1/40** people (40/314 requests stopped, including challenges they then solved) · purchases: {'human': 39} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

**Round 4: adaptive difficulty: the pool pays 16-64x, many small clients pay the base price (level 4)**

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:pow-farm | 140 | 130 | 0 | 10 | 2.9 | 1.77 |
| bot:pow-pool | 132 | 126 | 0 | 6 | 1.8 | 1.83 |
| human:autofill | 8 | 7 | 1 | 1 | 5.0 | 7.61 |
| human:consumer_vpn | 24 | 21 | 3 | 3 | 5.0 | 3.27 |
| human:home | 192 | 168 | 24 | 24 | 5.0 | 3.24 |
| human:mobile_cgnat | 46 | 38 | 5 | 8 | 7.0 | 2.9 |
| human:no_js | 2 | 1 | 0 | 1 | 20.0 | 3.41 |
| human:old_chrome | 8 | 7 | 1 | 1 | 5.0 | 2.23 |
| human:private_relay | 16 | 14 | 2 | 2 | 5.0 | 3.75 |

Bots stopped: **16/272** requests · shoppers hurt: **4/40** people (40/296 requests stopped, including challenges they then solved) · purchases: {'human': 36} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

**Round 5: the browser pays: a real Chromium solves with the page's own JavaScript (level 4)**

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:pow-browser | 67 | 64 | 0 | 3 | 1.8 | 1.83 |
| human:autofill | 8 | 7 | 1 | 1 | 5.0 | 5.67 |
| human:consumer_vpn | 24 | 21 | 3 | 3 | 5.0 | 2.92 |
| human:home | 192 | 168 | 24 | 24 | 5.0 | 3.16 |
| human:mobile_cgnat | 64 | 56 | 8 | 8 | 5.0 | 3.19 |
| human:no_js | 2 | 1 | 0 | 1 | 20.0 | 2.93 |
| human:old_chrome | 8 | 7 | 1 | 1 | 5.0 | 2.94 |
| human:private_relay | 16 | 14 | 2 | 2 | 5.0 | 5.67 |

Bots stopped: **3/67** requests · shoppers hurt: **1/40** people (40/314 requests stopped, including challenges they then solved) · purchases: {'human': 39} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

</details>

Regenerate these tables for your own machine with `python tools/verify.py --all --markdown` (about 6 minutes) rather than copying the numbers.

---

## Bonus challenges

1. **Memory-hard PoW.** Swap SHA-256 for Argon2id (`pip install argon2-cffi==25.1.0`) in `pow_core.digest`, with a small `memory_cost`. Then measure:
   - How many hashes per second do you get now?
   - What happens to the gap between your laptop and a GPU? Between your laptop and a phone?
   - Which side does this help?
2. **Pass budget by action.** Put the challenge on `action:login` too (`phases=("action:login",)` in a copy of `pow_gate.py`) and give it its own budget, leaving the catalog on the cheap one. Which abuse does each budget price?
3. **Swap in ALTCHA.** Replace `challenge_signed.py` with the `altcha` Python library (2.3.0, MIT) and its widget. Which of our L2-L4 properties do you get for free, and which do you still have to build?
