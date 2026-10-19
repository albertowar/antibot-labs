# Chapter 4 Lab: JavaScript Challenges & Obfuscation

Starts from: `workshops/02-proficient/starter/` (contract 1.5). Adds: a registered `js` challenge type (cookie gate, signed single-use nonce, an obfuscated variant pool, an environment-bound answer, a clearance budget), the gate that serves it on the catalogue, the Node build of the variant pool, six bots and the shoppers' challenge solver.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/challenge_template.js`
- `defenses/clearance.py`
- `defenses/cookie_gate.py`
- `defenses/env_integrity.py`
- `defenses/js_challenge.py`
- `defenses/js_gate.py`
- `defenses/tokens.py`
- `defenses/variants.py`
- `demo_site/ext/jschallenge.py`
- `demo_site/ext/templates/js/interstitial.html`
- `tools/build_variants.py`
- `tools/obfuscate.mjs`
- `tools/personas_ch4.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** 6 rounds of attack ⚔️ defend plus a closing debrief. See `../chapter_04_content.md`, §4.7. **Style: pre-written.** Every defense ships complete; you read it, switch the level and measure. `solutions/round<N>/` holds only that round's `defenses/ladder.py` and `policy.py`. The `TODO (Round N, optional)` markers in `defenses/` and `tools/obfuscate.mjs` are tuning exercises, not steps: every defense already works, and the checkpoints pass without touching them.

The store's catalogue sits behind a JavaScript challenge that gets stronger every round. You play both sides:

- The **attacker** climbs a ladder: skip the JavaScript, forge its output, port it, run it in an emulator, run it in a real browser, then harvest what the browser earned.
- The **defender** turns on the next level and measures what it stops **and** what it costs: real users hurt, latency added, bytes shipped.

## Rules of engagement

- **Local only, enforced in code.** Every attack and tool reaches the store through `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine before a single request is sent. Browsers get the same guard (`labclient.browser_context`). The Node scripts check their target is localhost too, and the jsdom solver only receives a URL the Python wrapper took from `labclient`. Do not remove those checks.
- Simulated client addresses come from `data/world.json` and travel in `X-Lab-Client-IP`, which the store's edge trusts only from loopback. All shoppers and bots are synthetic.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages (`pip`, `npm ci`), browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  demo_site/ext/jschallenge.py        the feature: challenge type "js", /jsc/l2.js, /lab/jsc/check
  demo_site/ext/templates/js/         interstitial.html (the 403 page that runs the challenge)
  demo_site/static/js/variants/       the obfuscated pool (built by tools/build_variants.py; gitignored)
  defenses/                           js_gate · js_challenge · cookie_gate · tokens · variants · env_integrity · clearance
                                      challenge_template.js · secrets/ (the pool's answer key; gitignored) · ladder.py · policy.py
  attacks/                            round1_requests_scraper … round5_resolve_loop · js/ (jsdom solver, webcrack) · _common.py
  tools/                              checkpoint.py · personas_ch4.py (the shoppers' solver) · build_variants.py · obfuscate.mjs
  solutions/round1..5/                reference ladder.py and policy.py per round (the catch-up files)
```

The rest of the store (catalogue, product pages, cart, checkout, drops, accounts, the simulated edge, the decision log) is the W2 starter, unchanged. Its contract is `workshops/STORE_CONTRACT.md`.

**Why two languages?**

- **Python** runs the store, the attacks and the measurements, as in every other chapter.
- **JavaScript (Node)** is used only where the chapter is about JavaScript: the obfuscator, the deobfuscator and the jsdom emulator.
- The challenge is plain JS, not TypeScript, so what you obfuscate and deobfuscate is exactly what the browser runs.

---

## Setup

You need **Python 3.12+** and **Node 24 LTS (24.15 or later)**. Work through `onboarding/setup/PREWORK.md` first; this lab adds:

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # one venv per chapter, see the root README
pip install -r requirements.txt -r requirements-browser.txt
python -m playwright install chromium firefox             # Rounds 4-5, and the checkpoint's real browsers
npm ci                                                    # javascript-obfuscator, jsdom, webcrack
python tools/build_variants.py                            # the Round 3+ obfuscated pool
python demo_site/app.py                                   # http://127.0.0.1:5000/products
```

Docker is optional: the default is SQLite plus an in-process Redis. Switch levels without a restart (the checkpoint does it for you):

```bash
curl -s -X POST localhost:5000/lab/level -H 'Content-Type: application/json' -d '{"level": 3}'
```

| Level | Challenge | Module |
|---|---|---|
| 0 | None | – |
| 1 | Inline JS sets a fixed cookie | `defenses/js_gate.py`, `defenses/cookie_gate.py` |
| 2 | Signed, session-bound, single-use nonce; one readable solver (`/jsc/l2.js`); the pass is bound to the session and the User-Agent | `defenses/js_challenge.py`, `defenses/tokens.py`, `defenses/variants.py` |
| 3 | + a pool of polymorphic, obfuscated variants | `tools/build_variants.py`, `tools/obfuscate.mjs` |
| 4 | + the answer folds in layout, native-code and engine checks | `defenses/env_integrity.py`, `defenses/challenge_template.js` |
| 5 | + each pass buys 30 requests / 10 min, then a fresh challenge | `defenses/clearance.py` (enforced in `js_gate.py`) |

The gated paths are the catalogue: `/products` (HTML; shoppers browse it) and `/api/products` with every product record under it (JSON; the scrapers target this). A client without a pass gets the interstitial (HTML) or a 403 `challenge_required` carrying the challenge (JSON); the answer goes to the store's `POST /api/challenge/verify`, and the store keeps the pass server-side, in the session.

The debug page `/lab/jsc/check` is never gated. It shows your level, your session's pass, the pool size and the budget used.

> Teaching aids that you must **never** ship:
> - A failed verify says *why*, and at level 4+ even *which* environment fact was wrong (in the 403 body and in `/lab/decisions`).
>
> In production that turns your defense into a free oracle.

### Troubleshooting

| Problem | Fix |
|---|---|
| Port 5000 in use (macOS AirPlay Receiver) | `PORT=5050 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:5050` in every shell you run attacks or tools from |
| The interstitial says `no variant pool` at level 3+ | `python tools/build_variants.py` from `lab/` (needs `npm ci`). The checkpoint builds it if it is missing |
| `npm warn EBADENGINE` for jsdom | Your Node is older than 24.15. It usually still works; upgrade if Round 3 fails |
| Real-browser check fails to launch Firefox | `python -m playwright install firefox`: it's the browser that catches engine-check mistakes |
| Everything is challenged again after `POST /lab/reset` | Expected: the signing key lives in Redis and is replaced on reset, so outstanding challenges die with it. Real browsers re-solve on their own |

---

## How to measure a round

Finish every round with a **checkpoint**:

```bash
python tools/checkpoint.py --round <N>              # sets level N, runs the round's bots next to the 40 shoppers
python tools/checkpoint.py --round <N> --level <N-1>   # the same bots against the level before
```

- **Bots:** every attack invented so far, against what should happen at this level: `full` (the whole catalogue), `partial` (stopped part-way) or `blocked`.
- **Shoppers:** the store's 40 shoppers browse the catalogue (`tools/population.py`) and solve the challenge the way their browser would (`tools/personas_ch4.py`): the engine of the browser they claim, and a device time per solve (a budget Android phone is the slowest). A shopper stopped by the gate fails the round, except the no-JavaScript one from level 1 on: an accepted, measured cost.
- **Real browsers:** one real Chromium and one real Firefox load the catalogue through the interstitial. Either one stopped fails the round. They are the ground truth for the shoppers' model.
- **Cost:** the gate's time per cleared request (`Server-Timing`), the obfuscated script's size, and the bots' solves: the attacker's unit cost.

**Fell behind?** Every defense is already written, so catching up means switching to the round's level: the checkpoint does it, and `--catch-up` installs that round's `ladder.py` and `policy.py`. Levels 3+ also need the variant pool.

---

## Round 0: Baseline

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round1_requests_scraper.py` (level 0) | `125/125` records in about a second |
| 🔵 Look | Open `http://127.0.0.1:5000/products` in your browser, then `/lab/jsc/check` | the catalogue, no challenge |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | scraper 125/125 · 0 shoppers hurt, the no-JS one included |

Remember the last line: at level 0 even the no-JS shopper gets everything. It's the last time in this lab that will be true.

---

## Round 1: JS cookie gate ⚔️ forged cookie

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `defenses/js_gate.py` and `defenses/cookie_gate.py`, switch to level 1, then reload `/products` in your browser | "Checking your browser…" flashes, then the catalogue |
| 🔴 Re-run | `python attacks/round1_requests_scraper.py` | `0/125`, `challenge_required` |
| 🔴 Attack | View the challenge page's source (`curl -s -H 'Accept: text/html' localhost:5000/products`). Read `attacks/round1_cookie_forge.py`, then run it | `125/125` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | scraper stopped · forge gets through · **no-JS shopper hurt (accepted)** |

**Discuss:**

- How long did the forge take to write? Real attackers don't keep the regex. They hard-code `ec0d7e1` (`FALLBACK`).
- The no-JS shopper is now locked out. Who is that in real life? Decide what they should get.
- **TODO (Round 1, optional)** in `cookie_gate.py`: what would it take to give every visitor a different value?

---

## Round 2: Signed, bound, single-use challenge ⚔️ Python port

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `defenses/js_challenge.py` and `defenses/tokens.py`, then switch to level 2 | – |
| 🔴 Re-run | `python attacks/round1_cookie_forge.py` | `0/125`, `challenge_required` |
| 🔴 Try replay | `python attacks/round2_python_port.py --replay` | `accepted` once, then `nonce already used or expired`; another session is challenged; copied cookies with another User-Agent are challenged |
| 🔴 Attack | Read `/jsc/l2.js` in your browser. Read the port in `attacks/round2_python_port.py`, then run it | `125/125`, 1 solve |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | forge stopped · port gets through · only the no-JS shopper hurt |

**Exercises:**

1. Decode a challenge token from the 403 JSON: `python -c "import base64,sys; print(base64.urlsafe_b64decode(sys.argv[1].split('.')[0] + '=='))" <token>`. What can the client read? What can it change?
2. **TODO (Round 2, optional)** in `tokens.py`: swap `getdel()` for `get()`, save (the store reloads `defenses/`), and re-run `--replay`. Which line changes?
3. The port solves in ~0.1 ms. The challenge did force the attacker to read 40 lines of JS, once. That's all it did.

---

## Round 3: Polymorphic obfuscated variants ⚔️ run it in jsdom

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `tools/build_variants.py` and `tools/obfuscate.mjs`. Look at one file in `demo_site/static/js/variants/`, then switch to level 3 | 12 variants, ~3.8 KB readable → ~23 KB obfuscated |
| 🔴 Re-run | `python attacks/round2_python_port.py` | `0/125`, `verify failed: wrong answer` |
| 🔴 Exercise (5 min timebox) | `npm run deobfuscate`, then open `attacks/out/<id>.deobf.js` | webcrack undoes it in ~0.2 s; the op chain is readable |
| 🔴 Attack | Read `attacks/js/jsdom_solve.mjs`, then run `python attacks/round3_jsdom_solver.py` | `125/125`, 1 solve (~1.3 s, mostly Node start-up) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | port stopped · jsdom gets through · only the no-JS shopper hurt |

**Discuss:**

- Obfuscation made the script 6× bigger and costs ~150 ms per variant to build. How long did it hold against webcrack?
- Polymorphism broke the *hand-written* port. Would it break a *script* that extracts the chain from each variant? (That's bonus challenge 1.)
- The jsdom attacker never read anything. What does that tell you about where to spend your effort?
- **TODO (Round 3, optional)** in `tools/obfuscate.mjs`: turn off control-flow flattening and dead-code injection, then rebuild. Compare the size and the webcrack output.

---

## Round 4: Environment-bound answer ⚔️ real browser + clearance harvesting

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `defenses/env_integrity.py` and the `if (ch.env)` block in `defenses/challenge_template.js`, then switch to level 4 | – |
| 🔴 Re-run | `python attacks/round3_jsdom_solver.py` | `0/125`, `offsetWidth was 0 (no layout engine); DOM methods are not native code` |
| 🔴 Attack | `python attacks/round4_playwright_harvest.py` | `125/125`: one headless-Chromium solve (~1 s), then the catalogue via `requests` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | jsdom stopped · harvest gets through · **real Firefox and the Firefox/Safari shoppers pass** |

**False-positive exercises.** The variable belongs to the **store** (it is read when the store starts), so restart the store with it, run `python tools/checkpoint.py --round 4`, then restart without it. Or run `tools/verify.py`, which starts its own store and passes the variable on:

| Run | Watch | Expected (measured) |
|---|---|---|
| `NAIVE_ENGINE_CHECK=1 python tools/verify.py --round 4` | Firefox and Safari | the real Firefox and **all 16** Firefox/Safari shoppers are stopped: `Error.stack style doesn't match the UA's engine` |
| `MAX_SOLVE_MS=300 python tools/verify.py --round 4` | the phones | **7 of the 8** phone shoppers, 2 desktop shoppers and the real Firefox (headless, cold) are stopped: issue-to-answer takes longer than 300 ms |

(With a store you started yourself: `NAIVE_ENGINE_CHECK=1 python demo_site/app.py`, then the checkpoint.)

**Discuss:**

- The harvester needed no stealth plugin: it *is* a real browser. What would catch it? (Chapter 1 and Chapter 5.)
- Why fold the checks into the hash instead of sending `{"layout_ok": true}`?
- **TODO (Round 4, optional)** in `env_integrity.py`: does `expected_engine()` handle Edge, Samsung Internet, CriOS and FxiOS?

---

## Round 5: Clearance budget ⚔️ re-solve loop

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `defenses/clearance.py` and the level-5 branch of `js_gate.py`, then switch to level 5 | – |
| 🔴 Re-run | `python attacks/round4_playwright_harvest.py` | `29/125`, then `challenge_required`: the pass's 30 requests are spent |
| 🔴 Attack | `python attacks/round5_resolve_loop.py` | `125/125`, ~5 solves, ~10 browser-seconds per 1,000 records |
| ✅ Checkpoint | `python tools/checkpoint.py --round 5` | harvest stopped at 29 · resolve gets through · only the no-JS shopper hurt |

**Discuss:**

- Nobody new was blocked. What changed is the attacker's unit cost: Round 4 pays one solve per scrape, however big; Round 5 pays one per ~30 records, growing linearly.
- How expensive is *one* solve? A warm browser re-solves in a few hundred milliseconds, which is why production challenges add proof of work (W1 Ch6) or heavier probes.
- Would a screen-reader user notice a re-challenge? (Look at `role="status"` in `interstitial.html`.)
- **TODO (Round 5, optional)** in `clearance.py`: size the budget from real traffic.

---

## Debrief

For each level, ask three questions: what did it stop, who did it hurt, and what did it cost to run? `python tools/checkpoint.py --all` runs every round and gives you the table below.

---

## Expected results (self-check)

Verified on 2026-10-12 with Python 3.12 and Node 24.21 (`npm ci` from the committed lockfile), the W2 starter's pins (Flask 3.1.3, fakeredis 2.39.0 as the in-process Redis, SQLite), Playwright 1.63.0 (Chromium 153, Firefox 155), javascript-obfuscator 5.9.0, jsdom 30.1.2 and webcrack 2.16.0, on Linux. the Docker Redis 8.10 / PostgreSQL 18.6 compose path passes every round too (2026-10-17).

Generated from `python tools/verify.py --all --markdown`. Records scraped out of 125 (5 listing pages + 120 product records); blank = bot not introduced yet; **bold** = the first level that stops it; `(n)` = challenge solves.

| Bot ↓ / level → | 0 | 1 | 2 | 3 | 4 | 5 | Why it is stopped |
|---|---|---|---|---|---|---|---|
| `round1_requests_scraper` | 125 | **0** | 0 | 0 | 0 | 0 | `challenge_required`: no JavaScript, no pass |
| `round1_cookie_forge` |  | 125 | **0** | 0 | 0 | 0 | `challenge_required`: the cookie means nothing from level 2 |
| `round2_python_port` |  |  | 125 (1) | **0 (1)** | 0 (1) | 0 (1) | verify: `wrong answer` (each variant has its own op chain) |
| `round3_jsdom_solver` |  |  |  | 125 (1) | **0 (1)** | 0 (1) | verify: `offsetWidth was 0 (no layout engine); DOM methods are not native code` |
| `round4_playwright_harvest` |  |  |  |  | 125 (1) | **29 (1)** | challenged again after 29: the clearance budget (30) is spent |
| `round5_resolve_loop` |  |  |  |  |  | 125 (5) | never stopped: it pays a browser solve every ~30 records |
| Shoppers hurt (of 40) | 0 | 1 (no-JS) | 1 (no-JS) | 1 (no-JS) | 1 (no-JS) | 1 (no-JS) | the no-JS shopper, by design from level 1 |
| Real Chromium / Firefox | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ | through the interstitial, then the API |
| Gate ms per cleared request (median) | 0.520 | 0.600 | 0.920 | 1.000 | 1.280 | 1.900 | `Server-Timing` |
| Checkpoint | PASS | PASS | PASS | PASS | PASS | PASS | |

<details><summary>The scoreboards (one per round)</summary>

**Round 0** (level 0)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round1_requests_scraper | 125 | 125 | 0 | 0 | 0.0 | 0.62 |
| human:autofill | 6 | 6 | 1 | 0 | 0.0 | 1.08 |
| human:consumer_vpn | 18 | 18 | 3 | 0 | 0.0 | 1.36 |
| human:home | 144 | 144 | 24 | 0 | 0.0 | 1.2 |
| human:mobile_cgnat | 48 | 48 | 8 | 0 | 0.0 | 1.11 |
| human:no_js | 6 | 6 | 1 | 0 | 0.0 | 1.37 |
| human:old_chrome | 6 | 6 | 1 | 0 | 0.0 | 0.94 |
| human:private_relay | 12 | 12 | 2 | 0 | 0.0 | 1.11 |

Bots stopped: **0/125** requests · shoppers hurt: **0/40** people (0/240 requests stopped, including challenges they then solved) · purchases: {'human': 40} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

**Round 1** (level 1)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round1_cookie_forge | 126 | 125 | 0 | 1 | 0.3 | 0.65 |
| bot:round1_requests_scraper | 1 | 0 | 0 | 1 | 40.0 | 1.45 |
| human:autofill | 7 | 6 | 1 | 1 | 5.7 | 1.35 |
| human:consumer_vpn | 21 | 18 | 3 | 3 | 5.7 | 1.29 |
| human:home | 168 | 144 | 24 | 24 | 5.7 | 1.27 |
| human:mobile_cgnat | 56 | 48 | 8 | 8 | 5.7 | 1.33 |
| human:no_js | 2 | 1 | 0 | 1 | 20.0 | 1.68 |
| human:old_chrome | 7 | 6 | 1 | 1 | 5.7 | 1.51 |
| human:private_relay | 14 | 12 | 2 | 2 | 5.7 | 1.47 |

Bots stopped: **2/127** requests · shoppers hurt: **1/40** people (40/275 requests stopped, including challenges they then solved) · purchases: {'human': 39} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

**Round 2** (level 2)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round1_cookie_forge | 2 | 0 | 0 | 2 | 40.0 | 1.81 |
| bot:round1_requests_scraper | 1 | 0 | 0 | 1 | 40.0 | 1.89 |
| bot:round2_python_port | 127 | 126 | 0 | 1 | 0.3 | 1.04 |
| human:autofill | 8 | 7 | 1 | 1 | 5.0 | 1.43 |
| human:consumer_vpn | 24 | 21 | 3 | 3 | 5.0 | 1.29 |
| human:home | 192 | 168 | 24 | 24 | 5.0 | 1.56 |
| human:mobile_cgnat | 64 | 56 | 8 | 8 | 5.0 | 1.48 |
| human:no_js | 2 | 1 | 0 | 1 | 20.0 | 1.21 |
| human:old_chrome | 8 | 7 | 1 | 1 | 5.0 | 1.13 |
| human:private_relay | 16 | 14 | 2 | 2 | 5.0 | 1.44 |

Bots stopped: **4/130** requests · shoppers hurt: **1/40** people (40/314 requests stopped, including challenges they then solved) · purchases: {'human': 39} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

**Round 3** (level 3)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round1_cookie_forge | 2 | 0 | 0 | 2 | 40.0 | 2.08 |
| bot:round1_requests_scraper | 1 | 0 | 0 | 1 | 40.0 | 3.62 |
| bot:round2_python_port | 2 | 1 | 0 | 1 | 20.0 | 2.55 |
| bot:round3_jsdom_solver | 127 | 126 | 0 | 1 | 0.3 | 1.14 |
| human:autofill | 8 | 7 | 1 | 1 | 5.0 | 1.38 |
| human:consumer_vpn | 24 | 21 | 3 | 3 | 5.0 | 1.58 |
| human:home | 192 | 168 | 24 | 24 | 5.0 | 1.4 |
| human:mobile_cgnat | 64 | 56 | 8 | 8 | 5.0 | 1.48 |
| human:no_js | 2 | 1 | 0 | 1 | 20.0 | 2.27 |
| human:old_chrome | 8 | 7 | 1 | 1 | 5.0 | 1.36 |
| human:private_relay | 16 | 14 | 2 | 2 | 5.0 | 1.23 |

Bots stopped: **5/132** requests · shoppers hurt: **1/40** people (40/314 requests stopped, including challenges they then solved) · purchases: {'human': 39} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

**Round 4** (level 4)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round1_cookie_forge | 2 | 0 | 0 | 2 | 40.0 | 1.24 |
| bot:round1_requests_scraper | 1 | 0 | 0 | 1 | 40.0 | 3.07 |
| bot:round2_python_port | 2 | 1 | 0 | 1 | 20.0 | 1.46 |
| bot:round3_jsdom_solver | 2 | 1 | 0 | 1 | 20.0 | 1.1 |
| bot:round4_playwright_harvest | 128 | 127 | 0 | 1 | 0.3 | 1.36 |
| human:autofill | 8 | 7 | 1 | 1 | 5.0 | 1.29 |
| human:consumer_vpn | 24 | 21 | 3 | 3 | 5.0 | 1.4 |
| human:home | 192 | 168 | 24 | 24 | 5.0 | 1.43 |
| human:mobile_cgnat | 64 | 56 | 8 | 8 | 5.0 | 1.4 |
| human:no_js | 2 | 1 | 0 | 1 | 20.0 | 1.97 |
| human:old_chrome | 8 | 7 | 1 | 1 | 5.0 | 1.47 |
| human:private_relay | 16 | 14 | 2 | 2 | 5.0 | 1.46 |

Bots stopped: **6/135** requests · shoppers hurt: **1/40** people (40/314 requests stopped, including challenges they then solved) · purchases: {'human': 39} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

**Round 5** (level 5)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round1_cookie_forge | 2 | 0 | 0 | 2 | 40.0 | 2.03 |
| bot:round1_requests_scraper | 1 | 0 | 0 | 1 | 40.0 | 1.71 |
| bot:round2_python_port | 2 | 1 | 0 | 1 | 20.0 | 1.31 |
| bot:round3_jsdom_solver | 2 | 1 | 0 | 1 | 20.0 | 1.59 |
| bot:round4_playwright_harvest | 33 | 31 | 0 | 2 | 2.4 | 1.85 |
| bot:round5_resolve_loop | 144 | 135 | 0 | 9 | 2.5 | 1.31 |
| human:autofill | 8 | 7 | 1 | 1 | 5.0 | 1.32 |
| human:consumer_vpn | 24 | 21 | 3 | 3 | 5.0 | 1.45 |
| human:home | 192 | 168 | 24 | 24 | 5.0 | 1.58 |
| human:mobile_cgnat | 64 | 56 | 8 | 8 | 5.0 | 1.51 |
| human:no_js | 2 | 1 | 0 | 1 | 20.0 | 2.47 |
| human:old_chrome | 8 | 7 | 1 | 1 | 5.0 | 1.43 |
| human:private_relay | 16 | 14 | 2 | 2 | 5.0 | 1.66 |

Bots stopped: **16/184** requests · shoppers hurt: **1/40** people (40/314 requests stopped, including challenges they then solved) · purchases: {'human': 39} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

</details>

Things to watch for:

- **Variance.** Variant sizes and the shoppers' device times vary run to run. `MAX_SOLVE_MS=300` sits between the desktops and the phones; re-check it on your own machine against the real browsers.
- **Version drift.** After a Playwright, jsdom or obfuscator upgrade, re-run `python tools/checkpoint.py --all`. Watch for two things: a newer jsdom that implements layout or native-looking functions (it would break Round 4's story, not the lab), and a webcrack that stops handling a new obfuscator release.
- **Rotation.** Run `python tools/build_variants.py` while the store is running: `js_challenge.py` picks up the new pool on the next challenge, in-flight challenges fail and real browsers simply re-solve. Use it to show what a rotation deploy looks like.

---

## Bonus challenges

1. **Automate the port.** Write a script that downloads a variant, runs webcrack, extracts the op chain from `step()` (with `@babel/parser`, or a regex over the `>>> 0` lines), and solves without executing anything. Does it beat level 3? Level 4? What would the defender change next?
2. **Patch the emulator.** Make `jsdom_solve.mjs` pass level 4: give the probe a fake `offsetWidth`, and make `getBoundingClientRect.toString()` return `[native code]`. Then add one probe to the template that your patch doesn't cover. Who is winning, and at what cost?
3. **No-JS policy.** Give the no-JS shopper something better than a dead end: a read-only first page at a tight rate limit, or a `<noscript>` link to a CAPTCHA (W1 Ch5). Make the checkpoint report what they can now read, and argue why that's acceptable.
4. **Proof of work.** Fold W1 Ch6's puzzle into the variant (copy `solve()`/`meets_difficulty()` from its `lab/defenses/pow_core.py`; the puzzle and its cost model are taught there), then re-measure Round 5. How many browser-seconds per 1,000 records now? What does the slowest phone pay?
