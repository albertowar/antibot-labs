# Chapter 2 Lab: JavaScript Challenges & Obfuscation

**Format:** 6 rounds of attack ⚔️ defend, ~112 min of hands-on time plus a 12-min debrief. See `../chapter_02_content.md`, §2.7.

The demo store sits behind a JavaScript challenge that gets stronger every round. You play both sides:

- The **attacker** climbs a ladder: skip the JavaScript, forge its output, port it, run it in an emulator, run it in a real browser, then harvest what the browser earned.
- The **defender** turns on the next layer and measures what it stops **and** what it costs: real users hurt, latency added, bytes shipped.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- The Node tools work on files in this lab. The jsdom solver only receives a URL the Python wrapper has already checked.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  docker-compose.yml   Redis 8.10 for single-use nonces and clearance budgets (optional)
  demo_site/app.py     Flask store; DEFENSE_LEVEL=0..5 picks the challenge
  defenses/            cookie_gate · tokens · variants · challenge_template.js · env_integrity · clearance
  attacks/             round1_requests_scraper … round5_resolve_loop, js/ (jsdom solver, webcrack)
  tools/               checkpoint · legit_traffic · build_variants · obfuscate.mjs · scoreboard
```

**Why two languages?**

- **Python** runs the store, the attacks and the measurements, as in every other chapter.
- **JavaScript (Node)** is used only where the chapter is about JavaScript: the obfuscator, the deobfuscator and the jsdom emulator.
- The challenge is plain JS, not TypeScript, so what you obfuscate and deobfuscate is exactly what the browser runs.

---

## Setup (before the session, ~10 min)

You need **Python 3.12+** and **Node 24 LTS (24.15 or later)**. Docker is optional.

```bash
cd lab
docker compose up -d --wait                 # optional: Redis on 127.0.0.1:6379
python -m venv .venv && source .venv/bin/activate      # one venv per chapter, see the root README
pip install -r requirements.txt
playwright install chromium firefox         # firefox is optional (one simulated user)
npm ci                                      # javascript-obfuscator, jsdom, webcrack
python tools/build_variants.py              # builds the Round 3+ obfuscated pool
```

Start the demo site, and restart it with a new `DEFENSE_LEVEL` each round:

```bash
cd demo_site
DEFENSE_LEVEL=0 python app.py               # http://localhost:5000
```

| Level | Challenge | Module |
|---|---|---|
| 0 | None | – |
| 1 | Inline JS sets a fixed cookie | `defenses/cookie_gate.py` |
| 2 | Signed, session-bound, single-use nonce; readable solver; clearance bound to session + UA | `defenses/tokens.py`, `defenses/variants.py` |
| 3 | + pool of polymorphic, obfuscated variants | `tools/build_variants.py`, `tools/obfuscate.mjs` |
| 4 | + the answer folds in layout, native-code and engine checks | `defenses/env_integrity.py`, `defenses/challenge_template.js` |
| 5 | + each clearance buys 30 requests / 10 min, then a fresh challenge | `defenses/clearance.py` |

The two gated paths are `/` (HTML; real users browse `/?page=N`) and `/api/products?page=N` (JSON; the scrapers target this). The catalog has 300 pages.

The debug endpoint `/challenge-check` is never gated. It shows your level, your session, your clearance status and the budget used.

> Teaching aids that you must **never** ship:
> - The challenge page and the 403 JSON say *why* you were challenged.
> - A failed verify at level 4+ even says *which* environment fact was wrong.
>
> In production, both turn your defense into a free oracle.

### No Docker?

Just skip `docker compose`. If Redis isn't reachable, the app falls back to an in-process **fakeredis** and says so on start-up. Everything works the same, except that state is lost when you restart.

### Troubleshooting

| Problem | Fix |
|---|---|
| Port 5000 in use (macOS AirPlay Receiver) | `PORT=5050 DEFENSE_LEVEL=… python app.py`, then `export DEMO_URL=http://localhost:5050` in every shell you run attacks or tools from |
| `No variant pool` on start at level ≥ 3 | `python tools/build_variants.py` from `lab/` (needs `npm ci`) |
| `npm warn EBADENGINE` for jsdom | Your Node is older than 24.15. It usually still works; upgrade if Round 3 fails |
| Firefox user skipped | `playwright install firefox`. Optional, but it's the user that catches engine-check mistakes |
| Checkpoint is slow | It drives real browsers (~30–60 s). `--skip-browser` is quicker but **doesn't measure false positives** |
| Everything fails right after a restart | Expected: each start uses a new signing key, so old cookies are invalid. Real browsers re-solve on their own |

---

## How to measure a round

Finish every round with a **checkpoint**:

```bash
python tools/checkpoint.py --round <N>
```

```
=== Checkpoint: Round 3 (server at DEFENSE_LEVEL=3) ===

Bot traffic
  ✅ round1_requests_scraper        0/300 pages in 0.0 s  (expected: stopped)
  ✅ round1_cookie_forge            0/300 pages in 0.0 s  (expected: stopped)
  ✅ round2_python_port             0/300 pages in 0.0 s, 1 solve(s)  (expected: stopped)
       verify failed: wrong answer
  ✅ round3_jsdom_solver          300/300 pages in 3.5 s, 1 solve(s)  (expected: gets through)

Real users (real browser engines)
  ✅ chromium-1     10/10 pages  challenges ok=1 failed=0  challenge->answer 153 ms, interstitial 368 ms
  …
  ✅ chromium-slow   5/5  pages  challenges ok=1 failed=0  challenge->answer 484 ms, interstitial 1105 ms
  ✅ firefox         5/5  pages  challenges ok=1 failed=0  challenge->answer 261 ms, interstitial 1198 ms
  ⚠️  no-js           0/3  pages  challenges ok=0 failed=0
  ⚠️  no-JS users are blocked by design: what do they get instead? (policy, not a bug)

Cost
  defender: gate 0.024 ms per cleared request (median, Server-Timing)
  client:   challenge script 21.2 KB
  attacker: round3_jsdom_solver            3.3 solves per 1,000 pages (2.02 s solving)

✅ Round 3 checkpoint passed.
```

- **Bot traffic:** every attack invented so far, compared with what should happen at this level.
- **Real users:** `tools/legit_traffic.py` drives real browser engines through the store:
  - three ordinary Chromium visitors,
  - one Chromium at **6× CPU throttling** (a budget phone),
  - **Firefox**,
  - a **power user** (60 pages),
  - a browser with **JavaScript off**.

  A JS-enabled user who misses a page or fails a challenge is a **false positive**.
  - *challenge→answer* is the browser-side time from asking for a challenge to sending the answer: script download, parse and run.
  - *interstitial* is what the person actually sat through.
- **Cost:**
  - server time per request (`Server-Timing`),
  - the challenge script's size,
  - and **browser solves per 1,000 pages**, the attacker's unit cost.

**Fell behind?** Every defense is already written, so catching up means restarting the demo site with `DEFENSE_LEVEL=<N>`. Levels 3+ also need the variant pool (`python tools/build_variants.py`). The checkpoint tells you if you're on the wrong level.

---

## Round 0: Baseline (8 min)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round1_requests_scraper.py` (level 0) | `300/300 pages` in ~2 s |
| 🔵 Look | Open `http://localhost:5000/` in your browser, click through a few pages, then open `/challenge-check` | the store, no challenge |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | scraper 300/300 · 0/6 real users hurt · no-JS user 3/3 |

Remember the last line: at level 0 even the no-JS user gets everything. It's the last time today that will be true.

---

## Round 1: JS cookie gate ⚔️ forged cookie (18 min)

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `defenses/cookie_gate.py`, restart with `DEFENSE_LEVEL=1`, then reload `/` in your browser | "Checking your browser…" flashes, then the store |
| 🔴 Re-run | `python attacks/round1_requests_scraper.py` | `0/300`, `no valid js_ok cookie` |
| 🔴 Attack | View the challenge page source (`curl -s localhost:5000/`). Read `attacks/round1_cookie_forge.py`, then run it | `300/300` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | scraper stopped · forge gets through · 0/6 hurt · **no-JS 0/3** |

**Discuss:**

- How long did the forge take to write? Real attackers don't keep the regex. They hard-code `ec0d7e1` (`FALLBACK`).
- The no-JS user is now locked out. Who is that in real life? Decide what they should get.
- **TODO (Round 1)** in `cookie_gate.py`: what would it take to give every visitor a different value?

---

## Round 2: Signed, bound, single-use challenge ⚔️ Python port (22 min)

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `defenses/tokens.py`, then restart with `DEFENSE_LEVEL=2` | – |
| 🔴 Re-run | `python attacks/round1_cookie_forge.py` | `0/300`, `no clearance cookie` |
| 🔴 Try replay | `python attacks/round2_python_port.py --replay` | `accepted` once, then `nonce already used`, `bound to a different session` and `bound to a different User-Agent` |
| 🔴 Attack | Read `/challenge/l2.js` in your browser. Read the port in `attacks/round2_python_port.py`, then run it | `300/300`, 1 solve |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | forge stopped · port gets through · 0/6 hurt |

**Exercises:**

1. Decode a `clr` cookie: `python -c "import base64,sys; print(base64.urlsafe_b64decode(sys.argv[1].split('.')[0] + '=='))" <value>`. What can the client read? What can it change?
2. **TODO (Round 2)** in `tokens.py`: swap `getdel()` for `get()`, restart, and re-run `--replay`. Which line changes?
3. The port solves in ~0.1 ms. The challenge did force the attacker to read 40 lines of JS, once. That's all it did.

---

## ☕ Break (10 min)

---

## Round 3: Polymorphic obfuscated variants ⚔️ run it in jsdom (25 min)

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `tools/build_variants.py` and `tools/obfuscate.mjs`. Look at one file in `demo_site/static/variants/`, then restart with `DEFENSE_LEVEL=3` | 12 variants, ~3.6 KB readable → ~20–30 KB obfuscated |
| 🔴 Re-run | `python attacks/round2_python_port.py` | `0/300`, `verify failed: wrong answer` |
| 🔴 Exercise (5 min timebox) | `npm run deobfuscate`, then open `attacks/out/<id>.deobf.js` | webcrack undoes it in ~0.6 s; the op chain is readable |
| 🔴 Attack | Read `attacks/js/jsdom_solve.mjs`, then run `python attacks/round3_jsdom_solver.py` | `300/300`, 1 solve (~2 s, mostly Node start-up) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | port stopped · jsdom gets through · 0/6 hurt · script ~21 KB |

**Discuss:**

- Obfuscation made the script 6× bigger and cost us ~240 ms per build. How long did it hold against webcrack?
- Polymorphism broke the *hand-written* port. Would it break a *script* that extracts the chain from each variant? (That's bonus challenge 1.)
- The jsdom attacker never read anything. What does that tell you about where to spend your effort?
- **TODO (Round 3)** in `tools/obfuscate.mjs`: turn off control-flow flattening and dead-code injection, then rebuild. Compare the size and the webcrack output.

---

## Round 4: Environment-bound answer ⚔️ real browser + clearance harvesting (22 min)

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `defenses/env_integrity.py` and the `if (ch.env)` block in `defenses/challenge_template.js`, then restart with `DEFENSE_LEVEL=4` | – |
| 🔴 Re-run | `python attacks/round3_jsdom_solver.py` | `0/300`, `offsetWidth was 0 (no layout engine); DOM methods are not native code` |
| 🔴 Attack | `python attacks/round4_playwright_harvest.py` | `300/300`: one headless-Chromium solve (~1.3 s), then 300 pages via `requests` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | jsdom stopped · harvest gets through · **0/6 hurt, Firefox included** |

**False-positive exercises.** Run each one, then restart without the variable:

| Restart with | Watch | Expected |
|---|---|---|
| `NAIVE_ENGINE_CHECK=1 DEFENSE_LEVEL=4 python app.py` | `firefox` | `0/5 pages`, `Error.stack style doesn't match the UA's engine`. Every Firefox and Safari user is gone |
| `MAX_SOLVE_MS=300 DEFENSE_LEVEL=4 python app.py` | `chromium-slow` | fails most challenges. Normal users answer in ~100 ms, the throttled one in ~500 ms |

**Discuss:**

- The harvester needed no stealth plugin: it *is* a real browser. What would catch it? (W2 Ch1 and W2 Ch3.)
- Why fold the checks into the hash instead of sending `{"layout_ok": true}`?
- **TODO (Round 4)** in `env_integrity.py`: does `expected_engine()` handle Edge, Samsung Internet, CriOS and FxiOS?

---

## Round 5: Clearance budget ⚔️ re-solve loop (17 min)

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `defenses/clearance.py`, then restart with `DEFENSE_LEVEL=5` | – |
| 🔴 Re-run | `python attacks/round4_playwright_harvest.py` | `29/300`, `clearance budget spent (30/30)` |
| 🔴 Attack | `python attacks/round5_resolve_loop.py` | `300/300`, ~11 solves, ~7 browser-seconds per 1,000 pages |
| ✅ Checkpoint | `python tools/checkpoint.py --round 5` | harvest stopped at 29 · resolve gets through · 0/6 hurt · power user: `challenges ok=2` |

**Discuss:**

- Nobody was blocked. What changed is the attacker's unit cost:
  - Round 4: one solve per scrape, however big.
  - Round 5: about 34 solves per 1,000 pages, growing linearly.
- How expensive is *one* solve? Here, a warm browser re-solves in ~0.1 s, which is why production challenges add PoW (W1 Ch7) or heavier probes.
- The power user was re-challenged once and never noticed. Would a screen-reader user notice? (Look at `role="status"` in `challenge.html`.)
- **TODO (Round 5)** in `clearance.py`: size the budget from real traffic.

---

## Debrief (12 min)

```bash
python tools/scoreboard.py                  # every level, every attack, real users (~5 min)
```

Run this before class if your machine is slow, and walk the table below. For each defense, ask three questions:

1. What did it stop?
2. Who did it hurt?
3. What did it cost to run?

---

## Instructor: expected results

Verified on 2026-10-11. Stack:

- Python 3.12.15 and Node 24.21.0 (`npm ci` from the committed lockfile).
- Flask 3.1.3, requests 2.34.2, Playwright 1.63.0 (Chromium 153.0.8010.12, Firefox 155.0).
- javascript-obfuscator 5.9.0, jsdom 30.1.2, webcrack 2.16.0.
- redis-py 8.1.0 with fakeredis 2.39.0 (the in-process fallback, as in the no-Docker path above).

Every round's checkpoint (0 to 5) passed with the numbers in the table below. The docker compose path (the Redis container) is verified separately.

Pages scraped out of 300 (blank = attack not invented yet):

| Attack ↓ / `DEFENSE_LEVEL` → | 0 | 1 | 2 | 3 | 4 | 5 | Reason at the first stop |
|---|---|---|---|---|---|---|---|
| `round1_requests_scraper` | 300 | **0** | 0 | 0 | 0 | 0 | `no valid js_ok cookie`, then `no clearance cookie` |
| `round1_cookie_forge` | | 300 | **0** | 0 | 0 | 0 | `no clearance cookie` |
| `round2_python_port` | | | 300 | **0** | 0 | 0 | `verify failed: wrong answer` |
| `round3_jsdom_solver` | | | | 300 | **0** | 0 | `offsetWidth was 0 (no layout engine); DOM methods are not native code` |
| `round4_playwright_harvest` | | | | | 300 | **29** | `clearance budget spent (30/30)` |
| `round5_resolve_loop` | | | | | | 300 | – (11 solves) |
| Real JS users hurt | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | – |
| No-JS user pages | 3/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | by design |
| Challenge script | – | inline | 3.6 KB | ~21–30 KB | ~21–30 KB | ~21–30 KB | variant sizes vary |

The other measurements:

- **Typical client numbers:**
  - Challenge→answer takes ~80–160 ms for normal Chromium, ~250–300 ms for Firefox and ~500–600 ms at 6× throttling.
  - The interstitial takes ~200–370 ms for normal Chromium and ~1.0–1.4 s for the throttled and Firefox users.
- **Server:** the gate costs ~0.02–0.05 ms per cleared request. Verify is well under 1 ms.
- **Pool build:** ~240 ms per variant to obfuscate.

Things to watch for:

- **Variance.** Variant sizes and the throttled user's timings vary run to run. `MAX_SOLVE_MS=300` is chosen to sit between the normal and the throttled users; re-check it on the classroom machines.
- **Version drift.** After a Playwright, jsdom or obfuscator upgrade, re-run `python tools/scoreboard.py`. Watch for two things:
  - a newer jsdom that implements layout or native-looking functions (it would break Round 4's story, not the lab);
  - a webcrack that stops handling a new obfuscator release.
- **Rotation.** `python tools/build_variants.py` while the site is running, then restart. In-flight challenges fail and real browsers simply re-solve. Use it to show what a rotation deploy looks like.

---

## Bonus challenges

1. **Automate the port.** Write a script that downloads a variant, runs webcrack, extracts the op chain from `step()` (with `@babel/parser`, or a regex over the `>>> 0` lines), and solves without executing anything. Does it beat level 3? Level 4? What would the defender change next?
2. **Patch the emulator.** Make `jsdom_solve.mjs` pass level 4:
   - give the probe a fake `offsetWidth`,
   - make `getBoundingClientRect.toString()` return `[native code]`.

   Then add one probe to the template that your patch doesn't cover. Who is winning, and at what cost?
3. **No-JS policy.** Give the `no-js` user something better than a dead end. Two options:
   - a read-only first page at a tight rate limit,
   - a `<noscript>` link to a CAPTCHA (W1 Ch6).

   Make the checkpoint report how many pages they can now read, and argue why that's acceptable.
4. **Proof of work.** Fold a small SHA-256 PoW (W1 Ch7) into the variant, then re-measure Round 5. How many browser-seconds per 1,000 pages now? What does the throttled user pay?
