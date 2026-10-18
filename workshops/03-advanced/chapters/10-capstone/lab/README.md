# W3 Ch10 Lab: Build & Break a Production-Grade Defense

Starts from: `workshops/03-advanced/starter/` (contract 1.5). Adds: the Workshop 2 layers as levels 1 to 4 (finished modules copied byte for byte from the W2 chapters, see `shared.json`), the three Workshop 3 layers (API hardening, streaming, supply chain), the `api9`, `stream9`, `supply9` and `metrics9` extensions, `ladder.py`/`policy.py`, six attack scripts, the API clients, a signal-health tool and an incident-report template.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/api_hardening.py`
- `defenses/api_token.py`
- `defenses/automation_artifacts.py`
- `defenses/behavior.py`
- `defenses/behavior_features.py`
- `defenses/behavior_l1.py`
- `defenses/behavior_l2.py`
- `defenses/client_hints.py`
- `defenses/consistency.py`
- `defenses/drop_guard.py`
- `defenses/flow.py`
- `defenses/graphql_cost.py`
- `defenses/header_inspector.py`
- `defenses/header_order.py`
- `defenses/header_util.py`
- `defenses/interaction.py`
- `defenses/ja4.py`
- `defenses/ja4_denylist.py`
- `defenses/known_fingerprints.json`
- `defenses/layers.py`
- `defenses/lie_detection.py`
- `defenses/login_risk.py`
- `defenses/login_throttle.py`
- `defenses/ratelimit.py`
- `defenses/sensor.py`
- `defenses/sensor_gate.py`
- `defenses/session_model.py`
- `defenses/stream_bus.py`
- `defenses/stream_detectors.py`
- `defenses/stream_layer.py`
- `defenses/supply_chain.py`
- `defenses/tls_family.py`
- `defenses/token_binding.py`
- `defenses/tokens.py`
- `defenses/ua_inspector.py`
- `defenses/ws_ratelimit.py`
- `demo_site/ext/api9.py`
- `demo_site/ext/ato.py`
- `demo_site/ext/behavior.py`
- `demo_site/ext/drop9.py`
- `demo_site/ext/login9.py`
- `demo_site/ext/metrics9.py`
- `demo_site/ext/sensor.py`
- `demo_site/ext/stream9.py`
- `demo_site/ext/supply9.py`
- `demo_site/ext/templates/behavior/view.html`
- `demo_site/ext/templates/drop.html`
- `demo_site/ext/templates/drop9/address.html`
- `demo_site/ext/templates/drop9/interstitial.html`
- `demo_site/ext/templates/drop9/proof_script.html`
- `demo_site/ext/templates/login9/token_field.html`
- `demo_site/ext/templates/sensor/capture.html`
- `demo_site/ext/templates/sensor/script.html`
- `demo_site/ext/templates/supply9/tags.html`
- `demo_site/static/js/analytics-helper.js`
- `demo_site/static/js/behavior.js`
- `demo_site/static/js/behavior_viewer.js`
- `demo_site/static/js/login9.js`
- `demo_site/static/js/proof.js`
- `demo_site/static/js/runtime_monitor.js`
- `demo_site/static/js/sensor.js`
- `demo_site/static/js/skimmer.js`
- `tools/humans.py`
- `tools/incident_report.md`
- `tools/personas_api.py`
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
- `tools/signalhealth.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** pre-written (level style), five rounds (0 to 4), with one small `TODO (Round N)` exercise in each of Rounds 1 to 3. See `../chapter_10_content.md`, section 10.7.

The store drops 50 pairs of the **Lab Runner 9**, one per account. You are the defender and the attacker, round by round: each round the attacker reaches for the next technique, you turn on the next layer and measure what it catches **and who it hurts**. Forty-three simulated people (the 40 shoppers of the W2 capstone, plus a mobile app, a second phone and a partner integration) use the store in the same minute as every attack, and every round prints both columns.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service URLs such as `REDIS_URL` and `DATABASE_URL` too). The store's edge accepts the lab headers only from loopback. The browsers run through `labclient.browser_context`, which also aborts any request that leaves localhost. Do not remove those checks.
- **Everything is simulated.** Each actor rents an address from `data/world.json` (documentation ranges, RFC 5737 and RFC 3849) and sends it in `X-Lab-Client-IP`. The TLS fingerprint is **claimed** (`X-Lab-JA4`), not measured: there is no TLS edge in this lab. Every account, email, address and credential is synthetic. The skimmer's collector (`collector.evil.example`) is fictional and is never contacted. No proxy, VPN or Tor node is ever contacted.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, Chromium and, if you use Docker, the container images.
- **The engagement runs under the rules of engagement you wrote in Chapter 8's Round 3** (`../../08-legal-ethical-and-future/lab/exercises/round3_roe_template.md`, filled in and scored by that lab's checkpoint). That document is this exercise's authorisation: scope, traffic limits, stop conditions, disclosure. In the versus-a-partner mode its referee, stop-word and disclosure sections apply as written — whoever found the most holes in Round 3 referees. Chapter 8 is this chapter's legal and ethical frame; do not point these scripts, or anything you build from them, at a site you do not own.

## How this lab is built

The lab is **pre-written** (level style): every layer ships complete, and a round is a `DEFENSE_LEVEL`. Rounds 1 to 3 each leave one small thing for you to set, marked `TODO (Round N)`, with the answer in `solutions/roundN/defenses/`: `python tools/checkpoint.py --round N --catch-up` installs the answers for rounds 1..N (your files are kept as `.bak`; `--restore` puts them back).

**The Workshop 2 layers are copies, not rebuilds.** The W3 starter store has no baseline (every workshop runs on its own), so this lab wires the W2 stack itself: every file marked "copy" below is the **finished version** from the W2 chapter that built it, or from the W2 capstone (`workshops/02-proficient/chapters/09-mini-capstone/lab`), listed in `shared.json`. `python scripts/lab_diff.py <this lab> --shared` from the repository root checks that they are still identical. Fix a bug in the chapter, then copy it here: do not edit a copy.

| Layer | Level | Source | What it does here |
|---|---|---|---|
| L0 request, TLS, sensor | 1 | **copy** W2 Ch1, Ch5, Ch6: `ua_inspector`, `header_inspector`, `client_hints`, `header_order`, `ja4`, `ja4_denylist`, `tls_family`, `sensor`, `sensor_gate`, `automation_artifacts`, `login_throttle` | headers, the claimed JA4 against the User-Agent, no JavaScript means no pair, `webdriver`, per-IP login velocity |
| L1 fingerprint coherence | 2 | **copy** W2 Ch1: `consistency`, `lie_detection` | software GPU, headless window, JS vs HTTP identity, Worker and iframe realms |
| L2 behavior and flow | 3 | **copy** W2 Ch3: `behavior_l1`, `behavior_l2` · **copy** W2 capstone: `flow` | how the hand got to the click, and the server's own clock |
| L3 session and account model | 4 | **copy** W2 capstone: `session_model` (trained from a seeded synthetic set at import: no browsers, no setup step) | a fresh account on a shared address buying in three seconds |
| L4 login token, cluster failures | 4 | **copy** W2 capstone: `token_binding`, `login_risk`, `ext/login9.py`, W2 Ch2's `tokens` | a login must prove the page's JavaScript ran in this session; failures are counted per fingerprint cluster |
| **L5 API hardening** | 5 | **own**: `api_hardening`, `graphql_cost`, `api_token`, `ws_ratelimit`, `ext/api9.py` | introspection off, GraphQL cost and depth, a JA4-bound bearer token, REST velocity per cluster, a WebSocket message bucket |
| **L6 streaming** | 6 | **own**: `stream_detectors`, `stream_bus`, `stream_layer`, `ext/stream9.py` | rate, regularity (Welford CV) and navigation, scored on the stream |
| **L7 supply chain** | 7 | **own**: `supply_chain`, `ext/supply9.py`, `static/js/` | an enforcing CSP, a violation sink, the runtime monitor |
| Glue | | **copy** `drop_guard`, `ext/drop9.py` · **own** `ladder.py`, `policy.py`, `layers.py`, `ext/metrics9.py` | re-points W2's sensor checks at the buy; the `proof` challenge; the numbers; layer names |

The module docstrings of the copies count levels the way the W2 capstone does (login token at 5, model at 4). Here the model and the login token share level 4; read `defenses/ladder.py` for the real map.

```
lab/
  defenses/ladder.py          which checks run at which level (read it first)
  defenses/policy.py          every number: bands, points, windows, budgets
  defenses/api_hardening.py   TODO (Round 1)      · graphql_cost.py, api_token.py, ws_ratelimit.py
  defenses/stream_detectors.py  TODO (Round 2)    · stream_bus.py, stream_layer.py
  defenses/supply_chain.py    TODO (Round 3)
  defenses/layers.py          check name -> layer (L0 to L7), used by the tools and /metrics
  defenses/<the W2 modules>   copies, see shared.json
  demo_site/ext/api9.py       /graphql, /api/v1/products, /api/token, the /ws/price socket
  demo_site/ext/stream9.py    publishes every request to the stream; /lab/stream/me and /lab/stream/all
  demo_site/ext/supply9.py    the vendor tag, the CSP header at level 7, the violation sink
  demo_site/ext/metrics9.py   GET /metrics (Prometheus text) for the `prod` profile
  attacks/round0_naive.py (copy) · round1_api.py · round2_streaming.py · round3_skimmer.py · round4_integrated.py
  tools/personas_api.py       the 43 people: the W2 shoppers plus the API clients
  tools/checkpoint.py         the rounds · signalhealth.py · incident_report.md
  solutions/roundN/defenses/  the answers to the Round 1 to 3 TODOs (installed by --catch-up)
  ops/                        Prometheus config and the Grafana board for the `prod` profile
```

**Why Python:** every layer is server-side HTTP logic (Flask), the attackers are `curl_cffi` and Playwright, and the only browser-side code is the W2 capstone's sensor, collector and proof scripts (copies) plus three small scripts of the capstone's own (the vendor tag, the runtime monitor, the skimmer payload). A second language would add setup without teaching anything this chapter needs.

### Levels and rounds

Level 0 is the bare store (the contract: `tools/verify.py --smoke` runs there), so the chapter's layers L0 to L7 sit on levels 1 to 7, and two of them share level 4. From level 5 the layer number and the level agree.

| Level | Layer | Round | Adds | Beats |
|---|---|---|---|---|
| 0 | - | - | the bare store | - |
| 1 to 4 | L0 to L4 | 0 | the inherited Workshop 2 stack | `requests`, `curl_cffi` without JavaScript, stock Chromium |
| 5 | L5 | 1 | API hardening | introspection, a batch scrape, the REST walk, a WebSocket flood |
| 6 | L6 | 2 | streaming | a micro-burst, a low-and-slow poll |
| 7 | L7 | 3 and 4 | supply chain | a form skimmer; then the integrated assault (every layer) |

Round 0 runs at level 4, Round 1 at 5, Round 2 at 6, Rounds 3 and 4 at 7. The "before" column of a round is the level below it (`--level N`: 0 for Round 0, 4 for Round 1, 5 for Round 2, 6 for Rounds 3 and 4). The decision per phase: the request phase judges every request, `action:drop_buy` judges the buy on its own signals, `action:login` judges the login. Points do not carry between phases. Bands: 15 monitor, 30 challenge (the `proof` challenge, a small proof of work), 60 block (`defenses/policy.py`).

## Setup

Setup is covered once for the whole series in `onboarding/setup/PREWORK.md`. For this lab (one venv, inside `lab/`; the chapter pins Playwright 1.62 because Camoufox 0.5.8, the optional browser of the bonus, needs it, so never share this venv):

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m playwright install chromium                   # Round 0's stock-browser bot and Round 3's browser proof
python tools/doctor.py                                  # READY?
python demo_site/app.py                                 # http://127.0.0.1:5000
```

**No Docker is needed**: the default is SQLite and an in-process Redis (`REDIS_URL=memory://`, the starter's), the streaming layer runs inline (`STREAM_BACKEND=inproc`), and the store seeds itself. You never restart the store between rounds: edits to `defenses/*.py` are picked up on the next request (`LAB_RELOAD=1`, the default) and the checkpoint sets the level with `POST /lab/level`. Restart after editing `demo_site/ext/`. Port 5000 busy (macOS: the AirPlay Receiver)? `PORT=8099 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:8099` in the shell where you run tools.

**With Docker** (the production-shaped base: Redis 8.10 and PostgreSQL 18):

```bash
docker compose up -d --wait
REDIS_URL=redis://127.0.0.1:6379/0 DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop python demo_site/app.py
docker compose down -v                                  # wipe it
```

**The optional `prod` profile** adds the production-like stack the capstone is about operating: Redpanda (the streaming layer's real backend), Prometheus and a provisioned Grafana signal-health board. No cloud account; every port is bound to `127.0.0.1`.

```bash
docker compose --profile prod up -d --wait              # + Redpanda :19092, Prometheus :9090, Grafana :3000 (admin/admin)
pip install confluent-kafka==2.12.0                     # the producer and the consumer (not in requirements.txt)
STREAM_BACKEND=kafka DEFENSE_LEVEL=6 python demo_site/app.py
docker compose --profile prod down -v
```

In `kafka` mode the same `observe()` runs out of band in a consumer thread, so the verdict trails the request by the consumer's lag (the price of moving detection off the request path). Prometheus scrapes the host store at `host.docker.internal:5000/metrics` (set `STORE_PORT` if you changed `PORT`); on Docker Desktop the scrape arrives from loopback, on a native Linux engine it arrives from the bridge gateway, which the store's edge refuses: there, read `/metrics` with `curl`. The default path (`tools/signalhealth.py`) needs none of this and is what the rounds below assume.

Open `http://localhost:5000/` and `http://localhost:5000/whoami` in your browser: `/whoami` shows how the store sees *your* request. `/lab/status` lists the ladder at every level, and `/lab/capture` saves **your own browser** as a real-user profile (`tools/profiles/captured-<name>.json`): from then on it shops as customer `human:home:23` in every round, and you can check that you sail through each one.

## The commands

| Command | What it does |
|---|---|
| `python tools/checkpoint.py --round N` | Sets round N's level, runs **every** attack next to the 43 people, and checks the round's expectations. PASS/FAIL |
| `python tools/checkpoint.py --round N --level L` | The same attacks against level L (the "before" column; reported, not judged) |
| `python tools/checkpoint.py --round N --catch-up` | Fell behind: installs the reference answers of Rounds 1..N. `--restore` puts yours back |
| `python tools/checkpoint.py --all --markdown` | Every round: the table below |
| `python tools/verify.py --round N` | The same, with a store started for you on a free port (build-time harness) |
| `python attacks/round2_streaming.py --pattern slow` | One attack on its own (the store must be running) |
| `python tools/signalhealth.py` | Which layer fired, which were silent, the CV of every session |
| `python tools/scoreboard.py` | Bots stopped next to shoppers hurt, per actor |
| `curl localhost:5000/lab/decisions?actor=bot:round1_batch` | Every gate decision: signals, outcome, extra |

Every round runs every attack, so you see both what the current layers stop and what still gets through (the next round's problem). Read the people table too: it lists each behavior profile, how many finished, how many met the `proof` challenge and how many were blocked.

> The store's responses carry `X-Lab-Verdict`, `X-Lab-Score` and `X-Lab-Signals` headers. They are there for teaching only. A real defense never tells the client which rule fired (`LAB_HEADERS=0`).

---

## Round 0: build and baseline (level 4) · 🔵

| Step | Do | Expected |
|---|---|---|
| 🛡️ Bring up | start the store; read `defenses/ladder.py` and `/lab/status` | levels 1 to 4 are the inherited stack |
| 📸 Capture | open `/lab/capture`, save the profile | you become customer `human:home:23` |
| 🗡️ Attack | `python tools/checkpoint.py --round 0 --level 0` (the "before") | every naive bot buys: nothing is wired at level 0 |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | the three naive bots stopped (`ua:red_flag`, `sensor_gate:no_sensor`, `client_hints:headless_brand`) · the W3 attacks still get through (they are the next rounds) · 39 of 43 people finish, the no-JavaScript visitor is the accepted cost |

`curl_cffi` is the instructive bot: its JA4 and headers are exactly Chrome's, and what stops it is that it never ran the page. The mobile app and the partner integration (the API clients) sign in through the same sensor and login token as everyone, because the layers compose.

## Round 1: API abuse ⚔️ API hardening (level 5) · 🔴🔵

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round1_api.py` at level 4 | 4 of 4: introspection, a batch scrape, the REST walk, a WebSocket flood. At level 5 with the starter numbers the REST walk (no token) and the flood (the bucket) are already stopped; introspection and the batch still get through |
| 🛡️ Defend | the three numbers in `defenses/api_hardening.py` (`INTROSPECTION_ENABLED`, `GRAPHQL_MAX_COST`, `GRAPHQL_MAX_DEPTH`); `python -m defenses.api_hardening` checks them | the honest page (cost 24) passes, the batch (200) and the catalogue (120) do not |
| 🗡️ Re-run | the same attack at level 5 | 0 of 4: introspection off, cost over budget, no API token, the socket cut after its 20-message burst |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | all four refused · the mobile app, the second phone and the partner integration finish |

**Discuss:** the legitimate mobile client pages the same REST endpoint and is *not* blocked. What makes it legitimate to the server (a token bound to its JA4) that the scraper cannot cheaply forge? Model answer: the token is minted at login for one TLS family and fails for another, so a token lifted out of the app and replayed from a script mismatches; but the scraper can log in with an account of its own and use its own matching handshake, so velocity per cluster is the second control, and neither identifies a *person*.

## Round 2: streaming evasion ⚔️ real-time detectors (level 6) · 🔴🔵

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round2_streaming.py` at level 6 with the starter | the burst is caught by the rate detector; the low-and-slow poll evades (CV about 0.02) |
| 🛡️ Defend | `REG_MAX_CV` in `defenses/stream_detectors.py`; `python tools/signalhealth.py` prints the CV of every session | a ceiling above every bot (0.02 to 0.17) and below every person (0.77 and up) |
| 🗡️ Re-run | the same attack | 0 of 2: the poll is caught by machine-even timing |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | both refused (`streaming:rate`, `streaming:regularity`) · nobody who is a person is flagged |

**Discuss:** the rate detector sees the burst before the buy is even scored: that is the latency gap closing. Why does the low-and-slow client, which stays under every rate limit, still stand out? Model answer: people pause to read and get distracted, so their gaps vary (CV near 1); a script sleeps a constant interval (CV near 0). And what breaks the detector: a status poller you wrote yourself is supposed to be regular. Allowlist it; do not raise the ceiling until it passes.

## Round 3: supply-chain skimmer ⚔️ CSP (level 7) · 🔴🔵

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round3_skimmer.py` at level 7 with the starter | the policy is Report-Only: the exfil to the collector would be allowed |
| 🛡️ Defend | `CSP_ENFORCE` and `CONNECT_SRC` in `defenses/supply_chain.py`: enforce, and lock `connect-src` to `'self'` | `python -m defenses.supply_chain` checks it |
| 🗡️ Re-run | the same attack | exfil refused by the browser, a violation reported; Chromium agrees (the proof) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | exfil 0 · the page's own same-origin telemetry still works under the policy · nobody blocked |

The enforcing policy also carries `worker-src 'self' blob:` and `style-src 'self' 'unsafe-inline'`: the first report-only week would have shown that W2's sensor reads the browser's identity from a `blob:` Worker, and that the drop page has inline styles. Drop either and watch the sensor report stop arriving.

**Discuss:** SRI would catch a *tampered* CDN file but not this runtime-injected skimmer. Why is `connect-src` the control that stops exfiltration, and what does the runtime monitor add? Model answer: SRI pins a file the page includes; a skimmer that arrives through an already-trusted script (or that injects another) is not that file. `connect-src` decides where the page may send data at all, whoever asks. The monitor cannot enforce (a script that loads first can unwrap it) but its reports are the early warning.

## Round 4: integrated assault ⚔️ the whole stack and its operation (level 7) · 🔴🔵

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round4_integrated.py` | 0 of 3 stages get through: recon is stopped by L5, the evade poll by L6, the purchase by L0 (it never ran the page's JavaScript) |
| 🩺 Operate | `python tools/signalhealth.py` | every layer an attack touched fires; a silent layer is a finding |
| 📝 Report | fill in `tools/incident_report.md` | the kill chain, the false positives, one improvement |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | PASS |

Each stage runs from its own session and address, the way a division of labour does. The purchase stage uses `curl_cffi` (always available); a stealth browser is the W2 capstone's territory. L3 and L4 are silent in this lab's attack set (the model and the login token have nothing to stop here): that is a real finding about a stack you cannot test, not a comfort.

## Debrief

```bash
python tools/scoreboard.py
python tools/signalhealth.py
```

- Walk the kill chain, then the false-positive budget: who was challenged and whether that is acceptable (the privacy-extension user, the voice-control user, the password-manager buyer; the no-JavaScript visitor is blocked, which is the price of a JavaScript gate).
- The one move this stack cannot stop, a farm of real devices rotating fingerprints, is the hand-off to W3 Ch1 (mobile attestation) and Workshop 4.

## Expected results (self-check)

Measured on 2026-10-15 on one laptop (WSL2, Python 3.12.15, Flask 3.1.3, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.1.4, redis 8.1.0, fakeredis[lua] 2.39.0, requests 2.34.2, curl_cffi 0.16.3, flask-sock 0.7.0, websockets 17.2, PyJWT 2.15.1, scikit-learn 1.9.1, numpy 2.5.4, Playwright 1.62.0 with its bundled Chromium), with the default **in-process Redis and SQLite**, from `python tools/verify.py --all --catch-up --markdown` (the matrix is compiled from the per-round output of that command). Each cell is how many of the attack's attempts got what they wanted when the attack ran during that round's checkpoint; a bold cell is the round whose layer must stop it, and the checkpoint fails if it does not. "Stopped" means at most 10 % got through, and below its round an attack must still get through at least once. The "before" column of Round N is the previous column of the same row (the `--level` runs, made without the answers installed, agree with it except where the answers matter, noted below).

| Attack (attempts) ↓ / end of round → | bare store (level 0) | 0 (level 4) | 1 (level 5) | 2 (level 6) | 3 (level 7) | 4 (level 7) |
|---|---|---|---|---|---|---|
| `round0_requests`, `round0_curl_cffi`, `round0_playwright` (1 each) | 3 of 3 | **0** | 0 | 0 | 0 | 0 |
| `round1_introspection` (1) | 1 | 1 | **0** | 0 | 0 | 0 |
| `round1_batch` (1 request, 200 aliases) | 1 | 1 | **0** | 0 | 0 | 0 |
| `round1_rest` (1 walk, 5 pages) | 1 | 1 | **0** | 0 | 0 | 0 |
| `round1_ws` (120 messages) | 1 | 1 | **0** (20 answered) | 0 | 0 | 0 |
| `round2_burst` (45 requests) | 1 | 1 | 1 | **0** | 0 | 0 |
| `round2_slow` (14 requests, 350 ms apart) | 1 | 1 | 1 | **0** | 0 | 0 |
| `round3_skimmer` (1) | 1 | 1 | 1 | 1 | **0** | 0 |
| `round4_integrated` (3 stages) | 3 | 2 | 1 | **0** | 0 | 0 |
| **People who finished** (of 43) | 43 | 42 | 42 | 42 | 42 | 42 |
| **People blocked** | 0 | 1 (`no_js`) | 1 | 1 | 1 | 1 |
| **People who met the `proof` challenge** | 0 | 3 | 3 | 3 | 3 | 3 |
| **API clients hurt** (of 3) | 0 | 0 | 0 | 0 | 0 | 0 |
| Gate time on the drop POST, median / max (ms) | - | 22 / 173 | 23 / 78 | 22 / 60 | 22 / 73 | 23 / 40 |

Things to watch for:

- **Every cell is the same across runs.** The personas are fixed, the attackers are deterministic, and the model is trained from a fixed seed. The one number that moves is the gate maximum (a thread scheduling effect).
- **Without the answers installed** (the lab as you first meet it): Round 1 at level 5 still lets introspection and the batch through (the REST walk and the flood are already stopped by the token and the bucket); Round 2 at level 6 stops the burst (`streaming:rate`) but the low-and-slow poll evades (CV about 0.02); Round 3 at level 7 lets the skimmer out (Report-Only). Each of those rounds then FAILS its checkpoint, which is the exercise.
- **The challenged are the same three, by design:** the privacy-extension user (`lie_detection`, 30), the voice-control user (`behavior_l1:centre`, `teleport`, `text_without_keys`, 55: Chapter 3's own cost) and the password-manager buyer (`behavior_l1:bulk_fill`, `flow:short_dwell`, 35). They solve the proof and buy. The no-JavaScript visitor is blocked (`sensor_gate:no_sensor`; at the login `token_binding:no_valid_token`): the accepted cost of a JavaScript gate. The W3 layers add no friction to anyone, and none of the three API clients is touched.
- **The streaming layer separates cleanly here.** `tools/signalhealth.py` after Round 2: bots' CV 0.016 to 0.168 (the burst is irregular, the polls are machine-even), people's CV 0.77 and up. A ceiling of 0.15 sits between them; it is not a general constant.
- **The kill chain** of Round 4: `recon -> L5`, `evade -> L6`, `purchase -> L0` (with L2's `no_telemetry` and `short_dwell` firing on the same bare purchase). Each stage runs from its own session, so one layer's verdict does not shadow the next.
- **The gate cost is pessimistic.** fakeredis emulates Redis inside the store's own process, so a median of 22 ms is mostly Python and scikit-learn inference (the W2 model), and the streaming layer adds under a millisecond inline. Present the numbers as relative, not absolute.

**Docker path** (Redis 8.10.2 and PostgreSQL 18.6 from `docker-compose.yml`): `docker compose up -d --wait`, then with `REDIS_URL=redis://127.0.0.1:6379/0` and `DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop` set, `python tools/doctor.py` reports READY, `python tools/verify.py --smoke` passes, and Rounds 2, 3 and 4 (`--catch-up`) pass with the same counts as above (1 of 43 people blocked, 3 challenged, 0 API clients hurt; the gate median is 41 to 48 ms: every Redis call is now a round trip to a container). Then `docker compose down -v`.

**`prod` profile** (Redpanda v26.2.4, Prometheus v3.15.0, Grafana 13.2.3): all three start healthy. With `confluent-kafka` 2.12.0 installed and `STREAM_BACKEND=kafka DEFENSE_LEVEL=6`, the consumer thread fills the same per-session state out of band (the burst is flagged `streaming:rate` after about 32 of its 45 requests, one more than inline: the lag), Prometheus scrapes the store's `/metrics` (target `up`; `STORE_PORT=<port>` when the store is not on 5000) and Grafana provisions the board "Capstone — Signal Health" (uid `capstone-signal-health`). Not measured: the Grafana panels rendered in a browser.


## Troubleshooting

| Problem | Fix |
|---|---|
| Port 5000 already in use | `PORT=8099 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:8099` in every terminal you run tools from |
| `Executable doesn't exist` from Playwright | `python -m playwright install chromium` (Round 0's stock-browser bot; Round 3's proof is skipped, and says so, without it) |
| A round says an attack "should be stopped" but the layer is wired | check the level: `curl -s localhost:5000/lab/status`. An attack run by hand uses whatever level the store is at; the checkpoint sets it |
| Round 1 passes before you edit anything | you are at level 5 with the answers installed (`--restore` puts yours back), or the numbers are already set |
| The WebSocket attack reports 0 answered | the store is below level 5, or flask-sock is not installed (`pip install -r requirements.txt`) |
| `connection refused` on 6379 or 5432 | Docker path only: `docker compose ps`, both containers must be `healthy`. Without Docker, unset `REDIS_URL` and `DATABASE_URL` |
| Everything is stopped after you edited `policy.py` | A broken check fails open (a `<check>:error` signal with 0 points), but a bad number can block everyone. `python tools/checkpoint.py --round 4 --catch-up` restores the shipped answers; `git checkout defenses/policy.py` the rest |
| Start completely fresh | `curl -s -X POST 'localhost:5000/lab/reset?mode=full'` reseeds the store |

## Bonus challenges

- **Versus a partner (black box).** Share your built stack as a container image and red-team each other's running store over its port, with no `--catch-up`. A Docker image does *not* hide your Python source: "black box" here means you attack the port and agree not to crack the container open. If you work alone, ask a model to play the other side from the decision log only.
- **Mobile frontier.** The one signal Round 4 cannot stop is a real device rotating its fingerprint. Sketch where device attestation (W3 Ch1) would plug into `defenses/ladder.py`, and what it would cost legitimate users on rooted or old devices.
- **Drift.** Raise `REG_MAX_CV` until a person trips it. Where is the line, and what would you watch in `tools/signalhealth.py` to catch that drift in production?
- **Shadow before you ship.** Start the store with `LAB_SHADOW=1 DEFENSE_LEVEL=4` and run the people (`python tools/population.py --scenario capstone`). Read the `shadow` field of `curl 'localhost:5000/lab/decisions?limit=50'`: which W3 layers would have touched a customer or an API client?
- **Replay the Workshop 2 fleet.** The W2 capstone's stealth-browser scalpers are not shipped here. Copy `round1_patchright.py`, `round2_camoufox.py` and `round3_humanized_farm.py` from that lab, point them at this store at level 7 and see which of L1 to L4 finally fire in `signalhealth.py`.
