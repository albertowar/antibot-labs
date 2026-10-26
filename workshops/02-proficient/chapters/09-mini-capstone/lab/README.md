# W2 Ch9 Lab: Stealth Browsers vs. the Stack

Starts from: `workshops/02-proficient/starter/` (contract 1.5). Adds: the capstone's own layers (`drop_guard`, `flow`, `session_model`, `token_binding`, `login_risk`), the `drop9` and `login9` extensions, `ladder.py`/`policy.py`, five scalper scripts, the Chapter 9 shoppers, and the finished modules of Chapters 1, 3, 4, 5 and 6 copied byte for byte (see `shared.json`).

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/automation_artifacts.py`
- `defenses/behavior.py`
- `defenses/behavior_features.py`
- `defenses/behavior_l1.py`
- `defenses/behavior_l2.py`
- `defenses/client_hints.py`
- `defenses/consistency.py`
- `defenses/drop_guard.py`
- `defenses/flow.py`
- `defenses/header_inspector.py`
- `defenses/header_order.py`
- `defenses/header_util.py`
- `defenses/interaction.py`
- `defenses/ja4.py`
- `defenses/ja4_denylist.py`
- `defenses/known_fingerprints.json`
- `defenses/lie_detection.py`
- `defenses/login_risk.py`
- `defenses/login_throttle.py`
- `defenses/ratelimit.py`
- `defenses/sensor.py`
- `defenses/sensor_gate.py`
- `defenses/session_model.py`
- `defenses/tls_family.py`
- `defenses/token_binding.py`
- `defenses/tokens.py`
- `defenses/ua_inspector.py`
- `demo_site/ext/ato.py`
- `demo_site/ext/behavior.py`
- `demo_site/ext/drop9.py`
- `demo_site/ext/login9.py`
- `demo_site/ext/sensor.py`
- `demo_site/ext/templates/behavior/view.html`
- `demo_site/ext/templates/drop.html`
- `demo_site/ext/templates/drop9/address.html`
- `demo_site/ext/templates/drop9/interstitial.html`
- `demo_site/ext/templates/drop9/proof_script.html`
- `demo_site/ext/templates/login9/token_field.html`
- `demo_site/ext/templates/sensor/capture.html`
- `demo_site/ext/templates/sensor/script.html`
- `demo_site/static/js/behavior.js`
- `demo_site/static/js/behavior_viewer.js`
- `demo_site/static/js/login9.js`
- `demo_site/static/js/proof.js`
- `demo_site/static/js/sensor.js`
- `tools/humans.py`
- `tools/mistype.py`
- `tools/personas_ch9.py`
- `tools/profile_replay.py`
- `tools/profiles/brave-153-linux.json`
- `tools/profiles/chrome-153-android-touch.json`
- `tools/profiles/chrome-153-macos.json`
- `tools/profiles/chrome-153-privacy-extension.json`
- `tools/profiles/chrome-153-vdi-swiftshader.json`
- `tools/profiles/chrome-153-windows-keyboard.json`
- `tools/profiles/chrome-153-windows-nojs.json`
- `tools/profiles/chrome-153-windows.json`
- `tools/profiles/chromium-153-linux.json`
- `tools/profiles/edge-153-windows.json`
- `tools/profiles/firefox-157-resistfingerprinting.json`
- `tools/profiles/firefox-157-windows.json`
- `tools/profiles/safari-26-macos.json`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** pre-written (level style), five rounds (0 to 4). See `workshops/02-proficient/chapters/09-mini-capstone/chapter_09_content.md` (slides repo), section 9.7.

A limited sneaker drop: **the "Lab Runner 9", one per account**. You are the scalper and the defender, round by round. Each round the attacker gets a better tool; you read and switch on the next layer of the Workshop 2 stack and measure two things: what it catches, and who it hurts. Forty simulated shoppers buy the same drop in the same minute as every scalper, and every round prints both columns.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service URLs such as `REDIS_URL` too). The store's edge accepts the lab headers only from loopback. Playwright, Patchright and Camoufox run through `labclient.browser_context`, which also aborts any request that leaves localhost. Do not remove those checks.
- **Everything is simulated.** Each actor rents an address from `data/world.json` (documentation ranges, RFC 5737 and RFC 3849) and sends it in `X-Lab-Client-IP`; the store's edge treats it as the client address, for requests from loopback only. The TLS fingerprint is **claimed** (`X-Lab-JA4`), not measured: there is no TLS edge in this lab. Every account, email, address, credential and "breach list" is synthetic. No proxy, VPN or Tor node is ever contacted.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, the three browsers (Chromium for Playwright and for Patchright, and Camoufox's Firefox, about 160 MB) and, if you use Docker, the container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

## How this lab is built

This lab is **pre-written** (level style): every defense ships complete, because you built each one in Chapters 1 to 6. You read them, switch `DEFENSE_LEVEL` and watch the scoreboard. `solutions/roundN/defenses/` holds only that round's `ladder.py` and `policy.py` (the wiring and the numbers as they stand after Round N), so catching up means restarting at the round's level: `python tools/checkpoint.py --round N --catch-up` installs them (your own are kept as `.bak`; `--restore` puts them back), and the checkpoint sets the level for you.

**This capstone copies the chapter modules; it does not rebuild them.** Every file marked "copy" below is the **finished version** from the chapter that built it (for a wire-it chapter, the file from its `solutions/`), listed in `shared.json`. `python scripts/lab_diff.py <this lab> --shared` from the repository root checks that they are still identical. Fix a bug in the chapter, then copy it here: do not edit the copy. The capstone's own code is the part no single chapter owns.

| Layer (round) | Source | What it does here |
|---|---|---|
| Header rules (0) | **copy** Ch1: `ua_inspector`, `header_inspector`, `client_hints`, `header_order`, `header_util` | the request phase, every request |
| TLS consistency (0) | **copy** Ch3: `ja4.py`, `known_fingerprints.json`, `ja4_denylist`, `tls_family` | a library's JA4 is a block; the User-Agent's engine must be consistent with the JA4 family |
| Sensor gate, automation artifacts (0) | **copy** Ch1: `sensor`, `sensor_gate`, `automation_artifacts`, `ext/sensor.py`, `sensor.js` | no JavaScript, no report, no pair; `webdriver` and driver globals |
| Fingerprint coherence (1) | **copy** Ch1: `consistency`, `lie_detection` (and `interaction.py`, which is not on the ladder: Ch1's `ext/sensor.py` imports it for `/lab/sensor/check`) | software GPU, headless window, JS vs HTTP identity, Worker and iframe realms |
| Behavior (2) | **copy** Ch5: `behavior`, `behavior_features`, `behavior_l1`, `behavior_l2`, `ext/behavior.py`, `drop.html`, `behavior.js`, `tools/humans.py` | the drop page's collector and the first two layers (not motor-control realism) |
| Flow (2) | **own**: `flow.py` | the SERVER's clock: dwell before the buy, a buy with no view of the page |
| Session and account model (3) | **own**: `session_model.py` | Chapter 7's idea on this store's features; Chapter 7's scorer needs a request log this store does not keep |
| Login throttle (0) | **copy** Ch6: `login_throttle`, `ratelimit`, `ext/ato.py` | per-IP velocity and per-account lock; `ato.py` also gives the `action:login_result` phase. It brings Ch6's `otp`/`reauth` challenge types and the `recover`/`email` routes along: unused here, and the recover oracle is Ch6's lesson, left open |
| Login token (4) | **own**: `token_binding.py` + `ext/login9.py` | a signed token bound to the session and the sensor's fingerprint hash, built on Ch4's `tokens.py` (**copy**) |
| Failures per fingerprint cluster (4) | **own**: `login_risk.py` | Ch6's idea keyed on JA4 a+b + fingerprint hash instead of the /24 |
| Glue | **own**: `drop_guard.py`, `ext/drop9.py`, `ladder.py`, `policy.py` | re-points Ch1's sensor checks at the buy; the `proof` challenge; the numbers |

Not copied, on purpose: Chapter 2's fingerprint checks fire on sign-up and Chapter 1's sensor already reads the fingerprint at the buy (copying both would count one root cause twice); Chapter 7's scorer; Chapter 8's sensors, which are deliberately small stand-ins for the layers above.

```
lab/
  defenses/ladder.py            which checks run at which level (read it first)
  defenses/policy.py            every number: bands, points, windows, the model's FP budget
  defenses/drop_guard.py        the glue: Chapter 1's sensor checks, re-pointed at the buy
  defenses/flow.py, session_model.py, token_binding.py, login_risk.py        the capstone's own layers
  defenses/<the Chapter 1, 3, 4, 5, 6 modules>   copies, see shared.json
  demo_site/ext/drop9.py        the "proof" challenge, the flow stamp, the address field
  demo_site/ext/login9.py       the login token endpoints and the login page's script
  demo_site/ext/sensor.py, behavior.py, ato.py (+ templates, static)           Chapters 1, 5, 6 (copies)
  attacks/round0_naive … round4_stuffing, round4_token_farm, _common.py, humanize.py (copy of Ch5's)
  tools/personas_ch9.py         the 40 shoppers · checkpoint.py · mistype.py (a real customer who mistypes) · profile_replay.py, humans.py, profiles/ (copies)
  solutions/roundN/defenses/    the ladder and policy after Round N (installed by --catch-up)
  data/                         world.json (the pretend network)
```

**Why Python:** every layer is server-side HTTP logic (Flask), the attackers are `curl_cffi`, Playwright, Patchright and Camoufox, and the only browser-side code is the copies of Chapter 1's sensor and Chapter 5's collector plus two short scripts of the capstone's own (`proof.js`, `login9.js`). A second language would add setup without teaching anything Workshop 2 needs.

### The claimed JA4

The store sits behind no TLS edge. Each client states in `X-Lab-JA4` what its real TLS stack would put on the wire (Python's OpenSSL, Chromium's BoringSSL, Firefox's NSS; the values come from Chapter 3's `known_fingerprints.json`), and Chapter 3's `ja4.py` reads it as a *claimed* fingerprint. That keeps the lesson (a perfect Chrome JA4 does not stop a browser or `curl_cffi`) without a fingerproxy process the harness cannot start. The measured version, with the handshake read off the wire, is Chapter 3.

### The levels, and one offset

| Level | Round | Adds | Beats |
|---|---|---|---|
| 0 | - | the bare store | - |
| 1 | 0 | request: headers (Ch1), TLS family (Ch3) · buy: sensor gate, automation artifacts (Ch1) · login: throttle (Ch6) | `requests`, `curl_cffi`, stock Chromium |
| 2 | 1 | buy: fingerprint coherence (Ch1 `consistency`, `lie_detection`) | headless Patchright |
| 3 | 2 | buy: behavior (Ch5 `l1`, `l2`) and flow | scripted Camoufox |
| 4 | 3 | buy: the session and account model | the humanized account farm |
| 5 | 4 | login: token binding, failures per fingerprint cluster | credential stuffing |

Round N runs at level N+1, because the W2 starter's level 0 is the bare store (by contract) and Round 0's layer therefore lives at level 1. Each level includes every level below it, so the "before" column of Round N is `--level N`. The decision per phase: the request phase judges every request; `action:drop_buy` judges the buy on its own signals; `action:login` judges the login. Points do not carry between phases. Bands: 15 monitor, 30 challenge (the `proof` challenge), 60 block (`defenses/policy.py`).

## Setup

Setup is covered once for the whole series in `PREWORK.md`. For this lab (one venv, inside `lab/`; the chapter pins Playwright 1.62 because Camoufox 0.5.8 needs it, so never share this venv):

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-browser.txt
python -m playwright install chromium                   # Round 0's stock-browser bot
python -m patchright install chromium                   # Round 1, and Round 4's token farm
python -m camoufox fetch                                # Rounds 2 and 3 (anti-detect Firefox, ~160 MB)
python tools/doctor.py                                  # READY?
python demo_site/app.py                                 # http://127.0.0.1:5000
```

No Docker is needed (SQLite and an in-process Redis). With Docker, `docker compose up -d --wait` starts Redis 8.10 and PostgreSQL 18 as in the starter README, and you run the store with `REDIS_URL=redis://127.0.0.1:6379/0 DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop python demo_site/app.py`; `docker compose down -v` wipes it. Port 5000 busy (macOS: the AirPlay Receiver)? `PORT=8099 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:8099` in the shell where you run tools.

You never restart the store between rounds: edits to `defenses/*.py` are picked up on the next request (`LAB_RELOAD=1` is the default), and the checkpoint sets the level with `POST /lab/level`. By hand: `curl -s -X POST localhost:5000/lab/level -H 'Content-Type: application/json' -d '{"level": 3}'`. Restart after editing `demo_site/ext/`. The story says 50 pairs; the checkpoint restocks to 200 for every run so that scalpers and shoppers never compete for stock (who gets the last pair is not this chapter's question).

Open `http://localhost:5000/` and `http://localhost:5000/whoami` in your browser: `/whoami` shows how the store sees *your* request. `/lab/status` lists the ladder at every level, and `/lab/capture` saves **your own browser** as a real-user profile (`tools/profiles/captured-<name>.json`): from then on it shops as customer `human:home:23` in every round, and you can check that you sail through every one.

## The commands

| Command | What it does |
|---|---|
| `python tools/checkpoint.py --round N` | Sets level N+1, runs **every** scalper next to the 40 shoppers, and checks the round's expectations. PASS/FAIL |
| `python tools/checkpoint.py --round N --level N` | The same scalpers against the previous round's level (the "before" column; reported, not judged) |
| `python tools/checkpoint.py --round N --catch-up` | Fell behind: installs the reference `ladder.py` and `policy.py` for Round N. Because the defenses are all here, this only restores the wiring. `--restore` puts yours back |
| `python tools/checkpoint.py --all --markdown` | Every round: the table below |
| `python attacks/round3_humanized_farm.py` | One scalper on its own (it needs the store running; `--sessions N`, `--tool NAME`, `--with-token`, `--rotate-fp` where they apply) |
| `python tools/scoreboard.py` | Bots stopped next to shoppers hurt, per actor |

Every round runs every scalper, so you see both what the current layers stop and what still gets through (the next round's problem). Read the shopper table too: it lists each behavior profile, how many bought, how many met the `proof` challenge and how many were blocked.

> The store's responses carry `X-Lab-Verdict`, `X-Lab-Score` and `X-Lab-Signals` headers. They are there for teaching only. A real defense never tells the client which rule fired (`LAB_HEADERS=0`).

---

## Round 0: Naive fleet ⚔️ headers, TLS consistency and the sensor gate (level 1)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python tools/checkpoint.py --round 0 --level 0` (the "before") | every Round 0 bot buys its pair: nothing is wired at level 0 |
| 🔵 Defend | Read level 1 in `defenses/ladder.py`: `ua_inspector`, `header_inspector`, `client_hints`, `header_order` (Ch1), `ja4_denylist`, `tls_family` (Ch3), `login_throttle` (Ch6), and Ch1's `sensor_gate` and `automation_artifacts` re-pointed at the buy by `drop_guard.at_drop()`. Then `python tools/checkpoint.py --round 0` | `requests` blocked at its first request (`ua:red_flag`, `ja4_denylist:library_ja4`, missing headers), `curl_cffi` blocked at the buy (`sensor_gate:no_sensor`), stock Chromium blocked at its first page (`client_hints:headless_brand`, `ua:red_flag`) · 39 of 40 shoppers buy · only `no_js` stopped |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | PASS |

Read `defenses/drop_guard.py` first: it is the one file that explains why the chapters' checks run where they do. Open `/whoami`, `/lab/status` and `/lab/sensor/check` in your browser. `curl_cffi` is the instructive bot: its JA4 and headers are exactly Chrome's, and what stops it is that it never ran the page.

## Round 1: Headless Patchright ⚔️ fingerprint coherence (level 2)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python tools/checkpoint.py --round 1 --level 1` | Patchright buys 2 of 2: `webdriver` false, no automation globals, the UA rewritten over CDP |
| 🔵 Defend | Read level 2: Ch1's `consistency` and `lie_detection` (`defenses/consistency.py` and the module docstring's false-positive list). `python tools/checkpoint.py --round 1` | Patchright blocked at the buy (`consistency:flagged`, `lie_detection:flagged`) · the privacy-extension shopper **challenged** (the extension wraps `navigator`; she solves the proof and buys) · VDI shoppers served at monitor (software renderer is 10 points) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | PASS (budget: 1 challenged shopper) |

**Exercise:** set `BANDS["challenge"]` to 10 in `defenses/policy.py` and rerun the shoppers (`python tools/population.py --scenario ch9_drop`, at level 2): five shoppers meet the proof challenge instead of one: the two VDI users (a software renderer, 10 points), the Firefox `resistFingerprinting` user (20), the old Chrome user (a stale version, 20, challenged on the home page itself and solved there) and the privacy-extension user (30). They all buy; only `no_js` is stopped. (Edit after the store has served its first gated request, or restart it: the reloader takes its first snapshot of `defenses/` at that request.) Put it back to 30.

## Round 2: Scripted Camoufox ⚔️ behavior and flow (level 3)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python tools/checkpoint.py --round 2 --level 2` | Camoufox buys 2 of 2: Round 1 has nothing to find in a native, coherent device |
| 🔵 Defend | Read level 3: Ch5's `behavior_l1`, `behavior_l2` and `flow.py`. Open the drop page in your browser, reserve a pair, and look at `/lab/behavior/view/latest`. `python tools/checkpoint.py --round 2` | Camoufox stopped (`behavior_l1:teleport`, `centre`, `text_without_keys`, `flow:short_dwell`) · keyboard, screen-reader, touch, tremor and trackpad shoppers all buy · challenged, then buy: the voice-control user (55 points) and the 1.5 s password-manager buyer |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | PASS (budget: 3 challenged shoppers) |

**Exercise:** raise `MIN_DWELL_MS` in `defenses/policy.py` from 4000 to 7000 and rerun the shoppers at level 3: 31 to 32 of the 40 shoppers (everyone whose form took under 7 s) now meet the challenge instead of 3, and the voice-control user, who scores 55 for the click and 30 more for the dwell, is blocked. A timing line has to sit below your fastest customer. Put it back.

## Round 3: Humanized farm ⚔️ the session and account model (level 4)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python tools/checkpoint.py --round 3 --level 3` | the farm buys 3 of 3: curved paths, a random click point and human keystrokes (Ch5's recipe, `attacks/humanize.py`) beat layers 1 and 2 |
| 🔵 Defend | Read `defenses/session_model.py` (the features, `MIN_SAMPLES_LEAF`, `pick_threshold`) and run `python -m defenses.session_model`. `python tools/checkpoint.py --round 3` | the farm blocked (`session_model:p_bot`: fresh accounts, three of them on one address) · the first-timer, whose account is as fresh, buys · gate median about 20 ms (the model) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | PASS |

**Exercise:** in `defenses/session_model.py` set `MIN_SAMPLES_LEAF = 20` (the library's default) and run `python -m defenses.session_model`: every held-out customer gets the same score, 0.233 (the base rate), and the farm and the first-timer both read 0.233: a model that looks trained and detects nothing. `--leaf 5` gives a threshold of 0.99, the farm at 1.000 and the first-timer at 0.000. At the shipped 1,400 rows the default 20 still works (threshold 0.82), so the failure needs a small training set. Put it back to 5.

## Round 4: Credential stuffing ⚔️ token binding and cluster risk (level 5)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python tools/checkpoint.py --round 4 --level 4` | the stuffer takes over 10 of 60 accounts, every victim who reused a password, with or without a token: nothing at the login looks at it |
| 🔵 Defend | Read `defenses/token_binding.py`, `login_risk.py` and `demo_site/ext/login9.py`. `python tools/checkpoint.py --round 4` | the bare stuffer: 0 takeovers (`token_binding:no_valid_token`) · the stuffer with a token: **0** takeovers: its first five attempts pass the check and fail, then its cluster is blocked before the password is read (55 of 60 attempts refused) · rotating its fingerprint: **5** takeovers, down from 10 — the family counter steps its later successes up to `otp` (`login_risk:campaign_stepup`); the first few slip through before the family is hot, and that residue is the W3 hand-off |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | PASS |

Open `http://localhost:5000/login` in your own browser at level 5 and sign in as `user031@example.test` (the password is `python -c "import demo_site.seed as s; print(s.password_for(31))"`): `login9.js` mints the token for you, in a blink. `attacks/round4_token_farm.py` is the cost line: a real Patchright browser per login takes about 0.8 s against 0.02 s (a bare login) to 0.1 s (a login with the token flow) for `curl_cffi`, and one browser build is one fingerprint, so the cluster check blocks it too.

**Exercise:** set `CLUSTER_MIN_FAILURES = 1` and `CLUSTER_MAX_FAILURE_RATIO = 0.2` and rerun the shoppers at level 5: no shopper is hurt (they sign in correctly the first time), so tighten, then run `python tools/mistype.py` followed by `python tools/population.py --scenario ch9_drop`: the customer's second attempt is already refused, the right password included, and four macOS Chrome shoppers (`home:10`, `11`, `12`, `18`) who share that customer's fingerprint are blocked after them. At the shipped numbers `python tools/mistype.py --typos 2` (or `--typos 4`) signs in without trouble. `POST /lab/reset` clears the counters between tries. Put them back.

**Exercise (the campaign counter):** the rotating stuffer loses 5 of its 10 takeovers to `CAMPAIGN_*` (`defenses/policy.py`), which steps up a first-seen-device success while its JA4 family is failing in a burst. Raise `CAMPAIGN_MIN_FAILURES` to 30 and rerun `python attacks/round4_stuffing.py --with-token --rotate-fp` at level 5: more pairs slip through, because the family needs longer to go hot. Lower it to 3 and rerun the shoppers: now real new-device Chrome customers meet the `otp` step-up during the campaign (they read the code and still buy — friction, not a block). That trade — oracle on one side, new-device collateral on the other — is why this is the last browser-side rung and Workshop 3 reaches for attestation. Put it back.

## Debrief

```bash
python tools/scoreboard.py                              # bots stopped next to shoppers hurt, per actor
curl -s 'localhost:5000/lab/decisions?actor=bot:round3_farm&limit=5' | python -m json.tool   # every gate decision: signals, outcome, extra
```

- Which layer stopped the most bot *requests*, and which the most bot *pairs*?
- Which shoppers did each round challenge, what did it cost them, and who would sign that off?
- Fingerprint rotation is only half-caught by the family step-up. What would catch the rest cleanly, and why is it not a browser-side value?


## Expected results (self-check)

Measured on 2026-10-14 on one laptop (WSL2, Python 3.12.15, Flask 3.1.3, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.1.4, redis 8.1.0, fakeredis[lua] 2.39.0, requests 2.34.2, curl_cffi 0.16.3, user-agents 2.2.0, scikit-learn 1.9.1, numpy 2.5.4, Playwright 1.62.0 with its bundled Chromium, Patchright 1.63.0 and Camoufox 0.5.8 with Firefox 156), with the default **in-process Redis and SQLite**. Each cell is the number of pairs (or, for the stuffers, accounts taken over) the scalper got when it ran during that round's checkpoint, from `python tools/verify.py --all --catch-up --markdown` (the matrix is compiled from the per-round output of that command; two runs in a row gave the same table, identical except the farm cell at Round 2). A bold cell is the round whose layer must stop that scalper, and the checkpoint fails if it does not. "Stopped" means at most 10 % got through, and below its round a scalper must still get at least one through. The "before" column of Round N (`--level N`) is the previous column of the same row. The `--rotate-fp` row was re-measured on 2026-10-18 when the family-level step-up was added (`login_risk.py`'s campaign counter): three consecutive `--round 4` runs each gave exactly 5 takeovers (down from 10), 1 shopper hurt (`no_js`), and 3 shoppers at the `proof` challenge — the step-up itself added no new shopper challenges, because the real customers sign in before their Chrome family goes hot.

| Scalper (attempts) ↓ / end of round → | 0 (level 1) | 1 (level 2) | 2 (level 3) | 3 (level 4) | 4 (level 5) |
|---|---|---|---|---|---|
| `round0_requests`, `round0_curl_cffi`, `round0_playwright` (1 each) | **0** | 0 | 0 | 0 | 0 |
| `round1_patchright` (2) | 2 | **0** | 0 | 0 | 0 |
| `round2_camoufox` (2) | 2 | 2 | **0** | 0 | 0 |
| `round3_farm` (3) | 3 | 3 | 3 (sometimes 2) | **0** | 0 |
| `round4_stuffing` (60 logins; takeovers) | 10 | 10 | 10 | 10 | **0** |
| `round4_stuffing --with-token` | 10 | 10 | 10 | 10 | **0** (55 refused) |
| `round4_stuffing --with-token --rotate-fp` | 10 | 10 | 10 | 10 | **5** (family step-up) |
| `round4_token_farm` (7 browser logins) | - | - | - | - | 0 (five failures, then refused) |
| **Shoppers who bought** (of 40) | 39 | 39 | 39 | 39 | 39 |
| **Shoppers blocked** | 1 (`no_js`) | 1 | 1 | 1 | 1 |
| **Shoppers who met the `proof` challenge** | 0 | 1 | 3 | 3 | 3 |
| Gate time on the drop POST, median / max (ms) | 4 / 11 | 4 / 16 | 9 / 23 | 18 / 120 | 18 / 51 |

Things to watch for:

- **Every cell is the same across runs except one.** The humanized farm sometimes loses a pair at level 3 (2 of 3), because Chapter 5's Bezier recipe is random and an unlucky run lands in the challenge band. Everything else, shoppers included, is deterministic: the personas are fixed, the breach list has a fixed order, and the model is trained from a fixed seed.
- **The challenged shoppers are the same three, by design.** From Round 1 the privacy-extension user (`lie_detection`, 30). From Round 2 also the voice-control user (`behavior_l1:centre`, `teleport`, `text_without_keys`, 55: Chapter 5's own cost) and the password-manager customer who buys in 1.2 to 1.6 s (`behavior_l1:bulk_fill` and `flow:short_dwell`, 35). They solve the proof and buy; the round fails above its budget (0, 1, 3, 3, 3). The no-JavaScript visitor is blocked from Round 0 (`sensor_gate:no_sensor`, 60) and again at the login in Round 4: the accepted cost of a JavaScript gate.
- **A challenge is a speed bump for a person and for a browser bot alike.** A script that does not run the interstitial's JavaScript stops there (the scalpers here are "challenged" or "blocked", not bought); a bot that drives a real browser solves it in a second. The stops that matter against a stealth browser are the ones that score it past 60: Patchright scores 100 at level 2, scripted Camoufox 85 at level 3.
- **The gate cost is pessimistic.** fakeredis emulates Redis's Lua inside the store's own process, so the median gate time is single-digit milliseconds until the model (about 18 ms at Rounds 3 and 4, mostly Python and scikit-learn inference). Present the numbers as relative, not absolute.
- **Camoufox is the slow part.** A fresh device per launch is 10 to 30 s: the farm's three sessions take about 90 s, and a full round (every scalper) three to four minutes.
- **Version drift.** The headers and sensor reports come from Chapter 1's profiles (Chrome 153); `MIN_CHROME_MAJOR` in `defenses/policy.py` is 140. Chapter 3's `known_fingerprints.json` is dated October 2026.

**Docker path** (Redis 8.10 and PostgreSQL 18.6 from `docker-compose.yml`): `docker compose up -d --wait`, then with `REDIS_URL=redis://127.0.0.1:6379/0` and `DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop` set, `python tools/doctor.py` reports READY, `python tools/verify.py --smoke` passes, and `python tools/verify.py --round 4` passes end to end with the same numbers as above (the gate median is 27 ms: every Redis call is now a round trip to a container). Then `docker compose down -v`.

## Troubleshooting

| Problem | Fix |
|---|---|
| Port 5000 already in use (macOS: AirPlay Receiver) | `PORT=8099 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:8099` in every terminal you run tools from |
| `Executable doesn't exist` from Playwright, Patchright or Camoufox | the matching install line in Setup; each of the three browsers is a separate download |
| `camoufox fetch` fails on a GitHub rate limit | wait a few minutes, or set `GITHUB_TOKEN`; it reads the public releases API |
| Camoufox attacks are slow | each launch builds a fresh device fingerprint; 10 to 30 s per session is normal (the farm's three sessions take about 90 s) |
| Headless browsers won't start on a server | install the system libraries Playwright lists, or run under `xvfb-run` |
| A round says a scalper "should be stopped" but the defense is wired | check the level: `curl -s localhost:5000/lab/status` shows it. A scalper run by hand uses whatever level the store is at; the checkpoint sets it |
| `connection refused` on 6379 or 5432 | Docker path only: `docker compose ps`, both containers must be `healthy`. Without Docker, unset `REDIS_URL` and `DATABASE_URL` |
| A shopper shows `error` | The store was stopped or too slow (30 s timeout). Check the store's terminal |
| Everything is stopped after you edited `policy.py` | A broken check fails open (a `<check>:error` signal with 0 points), but a bad number can block everyone. `python tools/checkpoint.py --round 4 --catch-up` restores the shipped numbers |
| Start completely fresh | `curl -s -X POST 'localhost:5000/lab/reset?mode=full'` reseeds the store; `docker compose down -v && docker compose up -d --wait` wipes the Docker path |

## Bonus challenges

1. **Capture yourself.** Save your browser at `/lab/capture`, run `python tools/checkpoint.py --round 4`, and confirm you buy at every round. Now hand your captured signals to the Round 4 stuffer in place of its own (`replay_signals()` in `attacks/round4_stuffing.py`). Why does a fingerprint shared with real customers make the cluster check hurt them?
2. **Shadow before you ship.** Start the store with `LAB_SHADOW=1 DEFENSE_LEVEL=1` and run the shoppers (`python tools/population.py --scenario ch9_drop`). Read the `shadow` field of `curl -s 'localhost:5000/lab/decisions?limit=50'`: which layers above level 1 would have touched the privacy-extension customer?
3. **Move the goalposts.** Lower `CLUSTER_MAX_FAILURE_RATIO` and `CLUSTER_MIN_FAILURES` in `defenses/policy.py` until a customer who mistypes twice from a shared laptop fingerprint is caught. Where is the line?
4. **Turn Chapter 5's third layer on.** Add `behavior_l3.CHECK` (copy it from Chapter 5, with `lab_diff`'s `shared.json` entry) to level 3. Does the humanized farm lose at Round 2 instead of Round 3, and who pays for it?
