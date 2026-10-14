# Chapter 4 Lab: Browser Fingerprinting

Starts from: `workshops/02-proficient/starter/` (contract 1.5). Adds: a fingerprint collector on the sign-up page (telemetry kind `fp`), five pre-written layers on the sign-up action, `/lab/fp/*` pages, four sign-up farms (Rounds 1–4) and nine real-browser profiles for the 40 shoppers.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/fields.py`
- `defenses/fingerprint.py`
- `defenses/fp_gate.py`
- `defenses/fuzzy_cluster.py`
- `defenses/lie_detector.py`
- `defenses/linking.py`
- `defenses/population_sample.json`
- `defenses/rarity.py`
- `defenses/render_stack.py`
- `defenses/stable_id.py`
- `demo_site/ext/fp.py`
- `demo_site/ext/templates/fp/check.html`
- `demo_site/ext/templates/fp/script.html`
- `demo_site/static/js/fp.js`
- `tools/personas_ch4.py`
- `tools/profiles/brave.json`
- `tools/profiles/chrome-mac.json`
- `tools/profiles/chrome-windows.json`
- `tools/profiles/corporate-fleet.json`
- `tools/profiles/firefox-fpp.json`
- `tools/profiles/iphone.json`
- `tools/profiles/privacy-extension.json`
- `tools/profiles/safari-mac.json`
- `tools/profiles/vdi.json`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** Round 0 plus 4 rounds of attack ⚔️ defend, then a debrief. See `../chapter_04_content.md`, §4.7–4.8. **Style: pre-written.** Every layer ships complete in `defenses/`: you read it, switch the level, and measure. `solutions/round<N>/` holds only that round's `defenses/ladder.py` and `policy.py`; catching up means running at the round's level (the checkpoint does it, and `--catch-up` installs those two files).

The store's sign-up page (`/register`) is what a farm wants: every account earns loyalty points and early access to drops, so a bot wants hundreds of them. You play both sides:

- The attacker runs a sign-up farm. Each account uses a fresh browser context and a different rented source address.
- The defender turns on the next fingerprinting layer and measures what it stops and what it costs: real users refused, and milliseconds spent.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service URLs such as `REDIS_URL` too). Browsers get the same guard: `labclient.browser_context` aborts every request that is not local. Do not remove that check.
- The farm's "rotating residential proxies" are addresses rented from `data/world.json` (documentation ranges) and sent in `X-Lab-Client-IP`, which the store's edge trusts only from loopback. No proxy is involved. Every account, e-mail address and fingerprint is synthetic, apart from the browser you capture yourself in Round 0.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, the browser and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  demo_site/ext/fp.py                the feature: collector slot, telemetry kind "fp", sign-up history, /lab/fp/*
  demo_site/ext/templates/fp/        script.html (the collector, with the session's nonce) · check.html
  demo_site/static/js/fp.js          the collector (plain JS, no build step): reports raw observations, judges nothing
  defenses/                          fingerprint (glue) · fields · fp_gate · render_stack · lie_detector
                                     stable_id · rarity (+ population_sample.json) · linking · fuzzy_cluster
                                     ladder.py · policy.py
  solutions/round1..4/               reference ladder.py and policy.py per round (the catch-up files)
  attacks/                           round0_recon … round4_noise_signup · _common.py · data/ (stealth patch, two harvested PCs)
  tools/                             checkpoint.py · personas_ch4.py (the shoppers) · profiles/*.json (the 9 cohorts)
```

The rest of the store (catalog, cart, checkout, drops, accounts, the simulated edge, the decision log) is the W2 starter, unchanged. Its contract is `workshops/STORE_CONTRACT.md`. The one visible change is the sign-up page: it loads the collector.

**Why Python only?** The collector is one plain JavaScript file, served as-is with no build step. It only *reports* what it observes. Every decision happens in the Python modules in `defenses/`, which are the files you read and edit, for two reasons:

- The collector runs on the attacker's machine, so anything it decides can be patched out.
- Keeping the judging server-side means you need no Node toolchain.

---

## Setup

Work through `onboarding/setup/PREWORK.md` first. This lab adds a browser:

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # one venv per chapter, see the root README
pip install -r requirements.txt -r requirements-browser.txt
python -m playwright install chromium                    # every attack drives Chromium
python tools/doctor.py
python demo_site/app.py                                   # http://127.0.0.1:5000/register
```

Docker is optional: the default is SQLite plus an in-process Redis. To run the production-shaped stack (Redis 8.10 holds the sign-up history L3 and L4 read; PostgreSQL 18 holds the store):

```bash
docker compose up -d --wait
REDIS_URL=redis://127.0.0.1:6379/0 DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop python demo_site/app.py
docker compose down -v                                    # when you are done
```

Switch levels without a restart (the checkpoint does it for you). A shell helper keeps the commands short:

```bash
level() { curl -s -X POST localhost:5000/lab/level -H 'Content-Type: application/json' -d "{\"level\": $1}"; }
level 2
```

| Level | Round | Adds | Module you read |
|---|---|---|---|
| 0 | 0 | Nothing: every sign-up is recorded with its fingerprint, none are refused | – |
| 1 | 1 | A fingerprint is required, and the render stack must be plausible | `defenses/fp_gate.py`, `defenses/render_stack.py` |
| 2 | 2 | Lie detection: page vs. worker vs. headers | `defenses/lie_detector.py` |
| 3 | 3 | Exact-ID linking, rarity-weighted | `defenses/stable_id.py`, `defenses/rarity.py`, `defenses/linking.py` |
| 4 | 4 | Fuzzy clustering on noise-resistant components | `defenses/fuzzy_cluster.py` |

Round N runs at level N. Each level includes every level below it. Every layer runs only on the **sign-up action** (`POST /register` and `POST /api/register`); the page that serves the collector stays open. `defenses/policy.py` (this lab's bands) turns the points into a verdict:

| Score | Verdict | What the client gets |
|---|---|---|
| ≥ 40 | `block` | 403, no account |
| ≥ 20 | `monitor` ("suspicious") | the account is created; the sign-up is logged |
| < 20 | `allow` ("clean") | the account is created |

`LINK_MODE` (in `defenses/policy.py`, or `LINK_MODE=naive` in the store's environment) turns off rarity weighting in L3 and L4. You use it once, in Round 3. Edit, save, and the store reloads `defenses/` on the next request.

Lab pages (loopback only, never scored):

| Endpoint | What it does |
|---|---|
| `/lab/fp/check` | Collects your browser's fingerprint and shows how every level judges it |
| `/lab/fp/profile` | Downloads your fingerprint as a real-user profile |
| `/lab/fp/dashboard` | Sign-ups by level and verdict, and the most-reused devices |
| `/lab/fp/logs` | The last sign-up decisions with the reasons the layers gave |
| `/lab/decisions` | The store's decision log: every request, with its signals |

> Every response carries `X-Lab-Verdict`, `X-Lab-Score` and `X-Lab-Signals`, and the bots print them. The reasons are in `/lab/fp/logs`. That is for teaching only.
> In production, never tell a client which rule caught it.

**Troubleshooting**

| Problem | Fix |
|---|---|
| Port 5000 is already in use (on macOS, the AirPlay Receiver takes it) | `PORT=5050 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:5050` in every shell you run attacks and tools from |
| `Executable doesn't exist` from Playwright | `python -m playwright install chromium` inside this lab's venv |
| An attack reports `refused 403` at level 0 | The store is at another level: `level 0` |
| A second attack run gets fewer accounts than the table says | Accounts from the earlier run count toward linking. The attack scripts reset the store when you run them by hand; if you passed `--no-reset`, run `python tools/reset.py` |
| Port 5432 or 6379 taken (another lab's containers) | `docker compose ls`, then `docker compose -p <name> down`, or stop your local PostgreSQL / Redis |
| The checkpoint is slow | Each run drives 40 browser sign-ups, about 20 s. `--signups` on an attack script shortens a hand run |

---

## How to measure a round

Finish every round with a **checkpoint**:

```bash
python tools/checkpoint.py --round <N>              # set level N, run every farm next to the 40 shoppers
python tools/checkpoint.py --round <N> --level <N-1>   # the same farms against the level before
python tools/checkpoint.py --round <N> --catch-up   # install solutions/round1..N (ladder.py, policy.py) first
python tools/checkpoint.py --restore                # put your own files back (*.bak)
```

It runs **every** farm of the chapter at the round's level, so you see both what the current layers stop and what still gets through (the next round's problem). At the same time the store's 40 shoppers (`tools/population.py`, with `tools/personas_ch4.py`) each sign up as one real-browser profile. It reports:

- **Bots.** Every farm, compared with what should happen at this level: accounts created out of 10. Each farm uses a fresh browser and a new address per attempt.
- **Real users.** A table per cohort. **Refused** is a false positive, and the checkpoint fails on it. **Flagged** means the gate scored the user 20–39 and still served them: friction you would take to a challenge in production. The cohorts are chosen to hurt:

| Cohort | n | Who | Why it is hard |
|---|---|---|---|
| chrome-windows | 7 | different Windows PCs | the easy majority |
| chrome-mac | 4 | identical MacBook Air M2s | one rare-looking class, many people |
| corporate-fleet | 4 | an office of identical laptops behind **one** address | identical fingerprint *and* one IP |
| iphone | 8 | identical iPhones behind carrier NAT (Safari 26, AFP noise) | the most common fingerprint on the web |
| safari-mac | 4 | Safari 26 with canvas noise | noise on by default |
| firefox-fpp | 4 | Firefox, canvas randomised per session | noise on by default |
| brave | 4 | Brave, canvas/audio farbled per session | noise on by default |
| vdi | 2 | Citrix desktops with a software renderer | look like a headless server |
| privacy-extension | 2 | Chrome + a canvas-noise extension | patched natives |
| no JavaScript | 1 | the `no_js` shopper | no fingerprint at all |

- **The no-JavaScript shopper** is refused from Round 1 on: with no fingerprint there is nothing to judge, and the gate treats "no fingerprint" as 40 points. The checkpoint counts that as an accepted, measured cost (`allowed_fp`) and fails if it is *not* refused. In production you send those users to a challenge (W1 Ch6).
- **Your own profiles** (`tools/profiles/you-*.json`, from Round 0) sign up as one more real user. The checkpoint fails if one is refused.
- **Defender cost.** The collector's run time and payload in a real Chromium, and for each check the milliseconds the gate spent on the sign-up (`Server-Timing`).

**The synthetic shoppers are a stand-in, not ground truth.** Every shipped profile is marked `synthesized`: built from real Chromium and Firefox captures plus each browser's documented behaviour, *not* captured on that exact device. Safari, Brave and a phone are the weakest. That is why Round 0 adds **your** browser, and why any refusal of a captured profile is a bug in the defense.

**Fell behind?** Every defense is already written, so catching up means running at the round's level: the checkpoint does it, and `--catch-up` installs that round's `ladder.py` and `policy.py`.

---

## Round 0: Recon

**🗡️ Attack (look):**

```bash
python attacks/round0_recon.py              # what does the store see from headless Chromium?
```

**🛡️ Defend (look):** open `http://127.0.0.1:5000/lab/fp/check` in your own browser, and in a second browser if you have one. Then fill in this table:

| | Headless Chromium | Your browser | Second browser |
|---|---|---|---|
| WebGL renderer | | | |
| `MAX_TEXTURE_SIZE` | | | |
| Fonts found | | | |
| Speech voices | | | |
| Screen | | | |
| `userAgentData` brands | | | |
| Collector time | | | |

Reload `/lab/fp/check` twice. Which values change? (Brave, Safari 26 and Firefox with fingerprinting protection will surprise you.)

**Add yourself to the real-user set:** click **Download as a real-user profile** and save the file as `tools/profiles/you-<browser>.json`. From now on, every checkpoint checks that *your* browser can still sign up.

**Checkpoint:** `python tools/checkpoint.py --round 0`. Every farm succeeds (10/10), every shopper registers, nobody is flagged.

---

## Round 1: Default headless ⚔️ Render-stack plausibility

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `level 0`, then `python attacks/round1_headless_signup.py` | 20/20 accounts created |
| 🛡️ Defend | Read `defenses/fp_gate.py` and `defenses/render_stack.py`, then `level 1` | – |
| 🗡️ Re-run | `python attacks/round1_headless_signup.py` | 0/20: `fp:render_stack` (SwiftShader WebGL renderer) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | farm 1 stopped · 0 refused of 39 · the no-JavaScript shopper refused |

**Exercises:**

1. Run `python -m defenses.render_stack`. Why does the Citrix user score 15, but the headless browser 40?
2. Why is a missing voice list worth nothing on Linux?
3. `TODO (Round 1)` in `render_stack.py` (optional tuning): Android.

---

## Round 2: Stealth patches ⚔️ Lie detection

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | Read `attacks/data/stealth_patch.js`, then `level 1` and `python attacks/round2_patched_signup.py` | 20/20: L1 now sees an NVIDIA GPU and three voices |
| 🛡️ Defend | Read `defenses/lie_detector.py`, then `level 2` | – |
| 🗡️ Re-run | `python attacks/round2_patched_signup.py` | 0/20, score 90: page vs. worker (platform, cores, memory), `MAX_TEXTURE_SIZE=8192` on an "RTX 3060", `userAgentData` brands vs. `Sec-CH-UA` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | farms 1–2 stopped · 0 refused of 39 · the 2 privacy-extension users flagged (25) |

**Exercises:**

1. None of the patched natives was flagged as patched. Why? (Look at `nativeShape()` in `demo_site/static/js/fp.js`, then at `spoofGetter` in the patch.)
2. The two privacy-extension users *were* flagged as patched, and only scored 25. Should tampering alone ever be worth 40?
3. `TODO (Round 2)` in `lie_detector.py` (optional tuning): compare `languages` and `timeZone` across contexts too. Then check that the checkpoint still passes.

---

## Round 3: Harvested fingerprint ⚔️ Linking with rarity

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `level 2`, then `python attacks/round3_replay_signup.py` | 20/20: L1 and L2 see an honest Windows PC |
| 🛡️ Defend (naive) | Read `defenses/stable_id.py` and `defenses/linking.py`. Set `LINK_MODE = "naive"` in `defenses/policy.py`, `level 3`, then `python tools/reset.py && python tools/personas_ch4.py` | **2 real users refused** (plus the no-JavaScript shopper): the 4th identical MacBook and the 4th office laptop |
| 🛡️ Defend | Read `defenses/rarity.py`, then set `LINK_MODE` back to `"rarity"` | – |
| 🗡️ Re-run | `python attacks/round3_replay_signup.py` | 3/20, then `fp:fingerprint_linked` (3 accounts today from device …) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | farms 1–3 stopped (farm 3 after 3 accounts) · farm 4 gets through · 0 refused of 39 |

**Exercises:**

1. Why does linking ignore the iPhones entirely? What does `python -m defenses.rarity` print for their class?
2. Replay *your own* fingerprint: `python attacks/round3_replay_signup.py --payload tools/profiles/you-<browser>.json`. How many accounts does it get, and why?
3. `TODO (Round 3)` in `linking.py` (optional tuning): one family, one laptop, three accounts. Count distinct source addresses.

**Discuss:** the attacker read `defenses/population_sample.json`. Which fingerprint will they replay next?

---

## Round 4: Noise ⚔️ Fuzzy clustering

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `level 3`, then `python attacks/round4_noise_signup.py` | 20/20: every `stable_id` is new |
| 🛡️ Defend | Read `defenses/fuzzy_cluster.py`, run `python -m defenses.fuzzy_cluster`, then `level 4` | – |
| 🗡️ Re-run | `python attacks/round4_noise_signup.py` | 3/20, then `fp:fingerprint_cluster` (3 accounts today from near-identical devices) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | farms 1–4 stopped (farms 3 and 4 after 3 accounts) · 0 refused of 39 |

**False-positive check:** set `LINK_MODE = "naive"`, keep `level 4`, and run `python tools/reset.py && python tools/personas_ch4.py`.

- Who gets refused now? 9 of the 39 shoppers with JavaScript: five identical iPhones, two office laptops, a MacBook and a Brave user.
- Why is fuzzy matching *more* dangerous to real users than exact matching?

**Exercises:**

1. `TODO (Round 4, attacker)` in `round4_noise_signup.py`: jitter the screen size as well. Does L4 still catch it?
2. `TODO (Round 4)` in `fuzzy_cluster.py` (optional tuning): weight the components instead of counting them, and re-run both the attack and `personas_ch4.py`.

**Why the checkpoint replays a second PC in Round 4.** It runs every farm against one store, and Round 3's three accounts (the first harvested PC) would count toward Round 4's cluster. The checkpoint passes `--payload attacks/data/harvested_fp_b.json`. By hand, with a reset between the two attacks, the first PC gives the same 3.

---

## Wrap-up: false positives and cost

```bash
python tools/reset.py && python tools/personas_ch4.py    # per-cohort verdicts and reasons
curl -s localhost:5000/lab/fp/dashboard | python -m json.tool
curl -s localhost:5000/lab/fp/logs | python -m json.tool | head -40
```

- Which rules would you only ever use for `monitor`, never for `block`?
- The collector costs 100–300 ms in headless Chromium, and much more on a cold page with a real GPU. Where in the page lifecycle would you run it in production, and what do you do with a sign-up that arrives before it finishes?
- The attacker's last move is to rotate **whole, coherent** fingerprints from a generator, or from a farm of real phones. Which signals are left?
  - **TLS and HTTP/2:** a "Windows Chrome" fingerprint arrives over Linux Python's TLS stack. That is W2 Ch5.
  - **Device binding and step-up on login:** W2 Ch6.
  - **Combining weak signals:** W2 Ch7.
  - **Making the collector itself hard to replay:** W2 Ch2.

---

## Expected results (self-check)

Generated from `python tools/verify.py --all --catch-up --markdown` (run `python tools/checkpoint.py --all --markdown` against your own store) on 2026-10-14 with Python 3.12.15, Flask 3.1.3, SQLAlchemy 2.1.4, Playwright 1.63.0 (Chromium 153), SQLite and the in-process Redis. Every round passed, and every `--level N-1` "before" run reported the round's farm succeeding where it should. The markdown output also holds one scoreboard per round. Numbers are accounts created out of 10 attempts (the checkpoint's default; by hand the scripts make 20). The checkpoint runs every farm on one store per round.

| Farm ↓ / `DEFENSE_LEVEL` → | 0 | 1 | 2 | 3 | 4 | Signal at the first stop |
|---|---|---|---|---|---|---|
| `round1_headless_signup` | 10 | **0** | 0 | 0 | 0 | `fp:render_stack` (SwiftShader, 40) |
| `round2_patched_signup` | 10 | 10 | **0** | 0 | 0 | `fp:fingerprint_mismatch` (worker 40 + texture limits 20 + brands 30 = 90) |
| `round3_replay_signup` | 10 | 10 | 10 | **3** | 3 | `fp:fingerprint_linked` (40; 80 at L4, with `fp:fingerprint_cluster`) |
| `round4_noise_signup` | 10 | 10 | 10 | 10 | **3** | `fp:fingerprint_cluster` (40) |
| Real users refused, of the 39 with JavaScript | 0 | 0 | 0 | 0 | 0 | |
| The no-JavaScript shopper refused | no | yes | yes | yes | yes | `fp:no_fingerprint` (40): the accepted cost |
| Real users flagged but served (20–39) | 0 | 0 | 2 | 2 | 2 | the 2 privacy-extension users, `fp:tampered` (25) |
| … refused with `LINK_MODE = "naive"` | | | | 2 | 9 | identical MacBooks, office fleet, iPhones, a Brave user |

Defender cost at level 4 (median, on the author's laptop; your numbers will differ):

| Item | Cost |
|---|---|
| Collector | about 110 ms in headless Chromium, about 2 s on a cold headed Chromium with a GPU; 3.9 KB payload |
| Gate on the sign-up | median 2.5 ms, p95 4.8 ms |
| … by check | `fp_gate` 0.4 ms · `render_stack` 0.03 ms · `lie_detector` 0.06 ms · `linking` 0.4 ms · `fuzzy_cluster` 0.4 ms |

`linking` is a key lookup (one sorted set per device) and stays flat as accounts pile up; `fuzzy_cluster` scans every account created today, so it is the cost that grows. The scan is fine for a lab and far too slow at scale (see §4.5).

Things to watch for:

- **Version drift.** When Chrome or Playwright updates, re-run every checkpoint. Then check `round0_recon.py`:
  - Does headless still report SwiftShader? (Chrome dropped the automatic SwiftShader fallback in 139. Playwright enables it explicitly.)
  - Is `MAX_TEXTURE_SIZE` still 8192?
- **Synthesized profiles.** See above. If you use Safari, Brave or a phone, add your capture in Round 0, and treat any refusal of a captured profile as a bug in the defense.
- **Where the history lives.** The accounts L3 and L4 count are in Redis (`lab:fp:acct:<stable_id>`, `lab:fp:cores`); `POST /lab/reset` flushes them. With `REDIS_URL=memory://` they vanish on a restart.

---

## Bonus challenges

1. **Coherent generator.** Install BrowserForge (`pip install browserforge`, Apache-2.0), a Python port of Apify's fingerprint-suite. Generate a different, internally consistent Windows/Chrome fingerprint for every sign-up and map it onto our payload format. How many accounts does it get at level 4? Which components would you still trust?
2. **FingerprintJS 5 (MIT).** Load the open-source FingerprintJS next to our collector and compare its `visitorId` with our `fp_id` across reloads, private windows and privacy browsers. Why should the server still recompute the ID from components?
3. **Headers meet fingerprints.** Combine this lab's `lie_detector` with W1 Ch4's header scoring. Which Round 3 shortcut (replaying the payload from `httpx` instead of a browser) does that close?
