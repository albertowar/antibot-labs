# Chapter 1 Lab: Browser Automation Detection

Starts from: `workshops/02-proficient/starter/` (contract 1.5). Adds: W1 Ch4's header rules as the Round 0 layer, a bot sensor on every store page (telemetry kind `sensor`), a sensor gate and four layer checks on `/api/products` and `/api/cart/add`, `/lab/sensor/*` and `/lab/capture`, eight bots and 13 real-browser profiles the shoppers replay.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/accept_ch.py`
- `defenses/automation_artifacts.py`
- `defenses/client_hints.py`
- `defenses/consistency.py`
- `defenses/header_inspector.py`
- `defenses/header_order.py`
- `defenses/header_util.py`
- `defenses/interaction.py`
- `defenses/lie_detection.py`
- `defenses/sensor.py`
- `defenses/sensor_gate.py`
- `defenses/ua_inspector.py`
- `demo_site/ext/headers.py`
- `demo_site/ext/sensor.py`
- `demo_site/ext/templates/home.html`
- `demo_site/ext/templates/sensor/capture.html`
- `demo_site/ext/templates/sensor/script.html`
- `demo_site/static/js/sensor.js`
- `tools/personas_ch1.py`
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

**Format:** Round 0 plus 4 attack ⚔️ defend rounds and a closing attack. See `workshops/02-proficient/chapters/01-browser-automation-detection/chapter_01_content.md` (slides repo), §1.6. **Style: wire-it.** Each round you finish one `TODO (Round N)` function in a layer module; `--catch-up` installs the reference versions from `solutions/round<N>/`.

You play both sides. The attacker drives a real browser at the store. The defender adds a layer to the bot sensor that runs inside the page, then measures two things: what the layer catches, and what it costs real users. Then the attacker works out what to try next.

## Rules of engagement

- **Local only, enforced in code.** Every attack and tool reaches the store through `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine before a single request is sent. Browsers get the same guard: `labclient.browser_context` aborts every request that is not local. Do not remove that check.
- Simulated client addresses come from `data/world.json` and travel in `X-Lab-Client-IP`, which the store's edge trusts only from loopback. All shoppers, carts and profiles are synthetic, apart from the browser you capture yourself.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images (and Selenium Manager fetching ChromeDriver for the optional Selenium bonus).
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  demo_site/ext/sensor.py           the feature: sensor nonce + telemetry kind "sensor", /lab/sensor/*, /lab/capture
  demo_site/ext/headers.py          W1 Ch4's Accept-CH negotiation (copied with the header checks)
  demo_site/ext/templates/          home.html (the store home + the Quick add panel) · sensor/script.html · sensor/capture.html
  demo_site/static/js/sensor.js     the in-page sensor (plain JS, no build step)
  defenses/                         ua_inspector · header_inspector · client_hints · header_order · accept_ch (W1 Ch4, level 1)
                                    sensor (glue) · sensor_gate · automation_artifacts · consistency · lie_detection · interaction
                                    ladder.py · policy.py
  solutions/round1..4/              reference versions of the four files you edit (installed by --catch-up)
  attacks/                          round0_* … round5_forged_sensor · bonus_* · _common.py
  tools/                            checkpoint.py · personas_ch1.py (the shoppers) · profile_replay.py · profiles/*.json
```

The rest of the store (catalog, product pages, cart, checkout, drops, accounts, the simulated edge, the decision log) is the W2 starter, unchanged. Its contract is `workshops/STORE_CONTRACT.md`. The one visible change is the home page: a **Quick add** panel waits for the sensor, then loads `/api/products` and offers Add to cart buttons that call `/api/cart/add` with the click evidence.

**Why this stack.** Python, the same as Workshop 1: the store, and Playwright, patchright and httpx for the attacks. The sensor is one plain JavaScript file with no build step, because it has to run unmodified in Chrome, Firefox and Safari, and you shouldn't need Node installed for one file.

---

## Setup

Work through `PREWORK.md` first. This lab adds browsers:

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # one venv per chapter, see the root README
pip install -r requirements.txt -r requirements-browser.txt
python -m playwright install chromium                    # Chromium + headless shell
python -m patchright install chromium                    # Round 4
python tools/doctor.py
python demo_site/app.py                                   # http://127.0.0.1:5000
```

Docker is optional: the default is SQLite plus an in-process Redis.

**One offset to remember: Round N runs at `DEFENSE_LEVEL` N+1.** Level 0 is the bare store (the contract's rule), so W1's header rules, which this chapter's attacker has already beaten, are level 1. The checkpoint switches levels for you; by hand:

```bash
curl -s -X POST localhost:5000/lab/level -H 'Content-Type: application/json' -d '{"level": 2}'
```

| Level | Round | Adds | Module you read (and finish) |
|---|---|---|---|
| 0 | – | Nothing: the bare store | – |
| 1 | 0 | W1 Ch4's header rules: User-Agent, header shape, Client Hints, header order, Accept-CH. The sensor runs and is recorded, nothing else is enforced | `defenses/ua_inspector.py` … `accept_ch.py` |
| 2 | 1 | **Sensor gate** (no sensor report = no API) and automation artifacts | `defenses/sensor_gate.py`, `defenses/automation_artifacts.py` |
| 3 | 2 | Consistency: JS vs. HTTP, headless window shape, self-contradictions | `defenses/consistency.py` |
| 4 | 3 | Lie detection: native-code integrity, Worker and iframe realms | `defenses/lie_detection.py` |
| 5 | 4, 5 | Interaction evidence on `POST /api/cart/add` | `defenses/interaction.py` |

Points from every enabled check add up (`defenses/policy.py`, W1 Ch4's bands):

- **≥ 40** → `block`: a 403.
- **≥ 20** → `monitor`: "suspicious", logged and served.
- **< 20** → allowed.

Lab pages (loopback only, never gated):

- `/lab/sensor/check` shows how your session's sensor report scores, layer by layer.
- `/lab/sensor/logs` shows the last 50 requests to the gated API with their reasons.
- `/lab/capture` saves your own browser as a real-user profile. Do this in Round 0.
- `/lab/headers/check` and `/lab/headers/logs` (from W1 Ch4) show what the header rules think of a request.

> Every response carries `X-Lab-Verdict`, `X-Lab-Score` and `X-Lab-Signals`, and the bots print them. That's for teaching only. In production, never tell a client which rule caught it. The sensor itself never learns its verdict.

**Troubleshooting**

| Problem | Fix |
|---|---|
| Port 5000 is in use (on macOS, AirPlay Receiver uses it) | `PORT=5050 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:5050` in the shell you run attacks and tools from |
| `Executable doesn't exist` from Playwright or patchright | Rerun the matching `install chromium` command above, inside this lab's venv |
| A browser attack hangs or times out | The store is not running on `DEMO_URL`, or something else listens on that port |
| You edited a defense and nothing changed | `defenses/` reloads on the next request; a syntax error shows in the store's terminal |

---

## How to measure a round

Finish every round with a **checkpoint**:

```bash
python tools/checkpoint.py --round <N>              # sets level N+1, runs every bot next to the 40 shoppers
python tools/checkpoint.py --round <N> --catch-up   # install the reference solutions up to round N first
python tools/checkpoint.py --restore                # put your own files back (*.bak)
```

Each checkpoint checks four things:

- **Your code.** The function you finished, and every earlier one, run against known inputs.
- **Bots.** Every bot of the chapter, with its two API calls: `full` (catalogue and cart), `partial` (the catalogue but not the cart) or `blocked`, compared with what should happen at this level.
- **Shoppers.** The store's 40 shoppers each replay one real-browser profile from `tools/profiles/` (`tools/personas_ch1.py`): its headers in wire order, its sensor report, its click. A blocked shopper fails the round, except the no-JavaScript one from Round 1 on, the one cost we accept and count. Shoppers whose score reaches 20–39 are listed as 🟡 suspicious.
- **Defender cost.** The gate's time on `/api/products` (from `Server-Timing`), the sensor's collection time in the browser (from the profiles) and its script size.

The 13 profiles are synthetic but grounded: header order and native-code strings come from a real Chromium 153 capture, and the identity values are edited per browser. Twelve of the thirteen are not real captures, so add yours with `/lab/capture`.

---

## Round 0: Where Workshop 1 left us

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round0_httpx_scraper.py` (level 1) | `403`: `ua:red_flag` on the python-httpx User-Agent, plus the headers no browser omits |
| 🔴 Attack | `python attacks/round0_playwright_default.py` | `403` on the page itself: `client_hints:headless_brand` (HeadlessChrome in the UA and the brands) |
| 🧪 Capture | Open `http://127.0.0.1:5000/lab/capture` in **your everyday browser**, then click the test button | `tools/profiles/captured-<name>.json` is saved. From now on a shopper replays you in every checkpoint |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | both Round 0 bots blocked · 0 shoppers blocked |

**Discuss:** Playwright's default headless is `chromium-headless-shell`, a separate build that says so in its User-Agent and brands. What is the *cheapest* change that gets an attacker past every Workshop 1 rule? (It is Round 1.)

---

## Round 1: CDP identity override ⚔️ the sensor gate + `navigator.webdriver`

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round1_playwright_cdp_override.py` (level 1) | `200` on `/api/products` and `/api/cart/add`: the header rules see a clean Chrome 153 |
| 🔵 Read | `demo_site/static/js/sensor.js`, `defenses/sensor.py`, `defenses/sensor_gate.py`, `defenses/automation_artifacts.py` | – |
| 🔵 Defend | Finish `TODO (Round 1)` in `check_webdriver()` | – |
| 🔴 Re-run | `python tools/checkpoint.py --round 1` (level 2) | the bot is blocked: `automation_artifacts` (navigator.webdriver is true) |
| ✅ Checkpoint | same command | 3 bots blocked · 1/40 shoppers blocked (no-JS, an accepted cost) |

**False-positive check:** open the store in your own browser, then `/lab/sensor/check`. It should show score 0.

**Discuss:**

- The gate blocks the no-JS shopper. How big is that population on *your* site, and who is in it? (Some corporate desktops, text-mode browsers, and people who block third-party scripts. A first-party sensor is less likely to be blocked.)
- `round4_patchright.py --vanilla` is caught by `__playwright__binding__` even with `webdriver` off. Why does `expose_function()` leave a global behind?

---

## Round 2: Automation flags off ⚔️ consistency

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round2_flags_off.py` (level 2) | `200`: `navigator.webdriver` is now `false` |
| 🔵 Read | `defenses/consistency.py` | – |
| 🔵 Defend | Finish `TODO (Round 2)` in `check_headless_shape()` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` (level 3) | 4 bots blocked; the round 2 bot fails five rules (`/lab/sensor/logs`) · the resistFingerprinting shoppers are 🟡 suspicious (20), not blocked |

**Exercise (5 min):** in `check_software_renderer()`, change the weight from 10 to 40 and rerun the checkpoint. Which shopper do you block? (`chrome-153-vdi-swiftshader`: someone on a Citrix desktop.) Put it back.

**Discuss:** the attack fails five rules. How many would still fire with new headless (`channel="chromium"`)? (Only the window shape and the WebGL renderer: 30 points, so it gets through as suspicious. New headless runs the real browser code.)

---

## Round 3: playwright-stealth ⚔️ lie detection

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round3_stealth_plugin.py` (level 3) | `200`: every value Layer 2 reads now looks plausible |
| 🔵 Read | `defenses/lie_detection.py` and `nativeReport()` / `workerReport()` in `sensor.js` | – |
| 🔵 Defend | Finish `TODO (Round 3)` in `check_realm_consistency()` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` (level 4) | 5 bots blocked: native code replaced + a Worker realm that disagrees · the privacy-extension shoppers are 🟡 suspicious (30), not blocked |

**Discuss:**

- The privacy extension tells the same kind of lie as the stealth plugin. Why is it 30 points and not 60? What is the difference between "modified" and "modified *and* inconsistent"?
- Try it in your own browser: install a fingerprint-protection extension, capture it again under a new name, and rerun the checkpoint.

---

## Round 4: patchright ⚔️ interaction evidence

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round4_patchright.py` (level 4) | `200` on both calls. Only the SwiftShader renderer (10 points) fires |
| 🔴 Compare | `python attacks/round4_patchright.py --vanilla` | `403`: plain Playwright leaves `__playwright__binding__` behind |
| 🔵 Read | `defenses/interaction.py` and `describeClick()` in `sensor.js` | – |
| 🔵 Defend | Finish `TODO (Round 4)` in `check_teleport()` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` (level 5) | `/api/products` **200**, `/api/cart/add` **403** (teleport + dead centre) · the keyboard-only and Android-touch shoppers stay ✅ |

**Discuss:**

- Scraping still works at this level. Why is that acceptable for a catalogue but not for a limited-edition drop?
- The keyboard rule accepts `detail == 0` without checks, so a bot can Tab and press Enter. Is that a bug? (No: it is an accessibility requirement. Close the gap with Chapter 5's keystroke and focus timing, not by blocking keyboard users.)

---

## Round 5 + debrief: Forge the sensor

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round5_forged_sensor.py` (level 5) | `200` on both calls, with no browser at all |
| 🔴 Bonus | `python attacks/bonus_humanized_cursor.py` | `200`: a curved path and a random landing point beat both Layer 4 rules |
| ✅ Checkpoint | `python tools/checkpoint.py --round 5` | passes: the forged sensor is *expected* to get through |

Read `round5_forged_sensor.py`: it is `tools/profile_replay.py`, the very module the shoppers use, with a different intent. Every layer in this chapter judges a payload the client wrote. That is what the rest of the workshop picks up:

| Gap | Picked up in |
|---|---|
| A sensor whose output cannot be forged without running it (challenge binding, obfuscation, signing) | Chapter 4 |
| Movement that is merely "not a teleport" | Chapter 5 |
| Device plausibility (canvas, audio, fonts) | Chapter 2 |
| The HTTP client underneath the forged sensor | Chapter 3 (TLS) |

---

## Expected results (self-check)

Verified on 2026-10-12 with Python 3.12, the W2 starter's pins (Flask 3.1.3, fakeredis 2.39.0 as the in-process Redis, SQLite), Playwright 1.63.0 (Chromium 153.0.8010.12), patchright 1.63.0 and playwright-stealth 2.0.3, on Linux. the Docker Redis 8.10 / PostgreSQL 18.6 compose path passes every round too (2026-10-17); the Selenium bonus was not re-run.

Generated from `python tools/verify.py --all --catch-up --markdown`. Each cell is `/api/products` / `/api/cart/add`; `–` means the bot never reached the cart. **Bold** marks the first block. Round N runs at level N+1 (Round 5 at level 5).

| Bot ↓ / Round (level) → | 0 (1) | 1 (2) | 2 (3) | 3 (4) | 4 (5) | 5 (5) | Why it is stopped |
|---|---|---|---|---|---|---|---|
| `round0_httpx_scraper` | **403 / –** | 403 / – | 403 / – | 403 / – | 403 / – | 403 / – | W1 header rules: `ua:red_flag` (python-httpx), missing browser headers |
| `round0_playwright_default` | **403 / –** | 403 / – | 403 / – | 403 / – | 403 / – | 403 / – | W1 header rules: `client_hints:headless_brand` (HeadlessChrome) |
| `round1_playwright_cdp_override` | 200 / 200 | **403 / –** | 403 / – | 403 / – | 403 / – | 403 / – | `automation_artifacts`: navigator.webdriver is true |
| `round2_flags_off` | 200 / 200 | 200 / 200 | **403 / –** | 403 / – | 403 / – | 403 / – | `consistency`: no browser UI, permission contradiction, 0 plugins, no window.chrome, SwiftShader |
| `round3_stealth_plugin` | 200 / 200 | 200 / 200 | 200 / 200 | **403 / –** | 403 / – | 403 / – | `lie_detection`: native code replaced, Worker realm disagrees |
| `round4_patchright` | 200 / 200 | 200 / 200 | 200 / 200 | 200 / 200 | **200 / 403** | 200 / 403 | `interaction` on the cart: teleport + dead centre (+ SwiftShader 10) |
| `round4_patchright --vanilla` | 200 / 200 | **403 / –** | 403 / – | 403 / – | 403 / – | 403 / – | `automation_artifacts`: `__playwright__binding__` global |
| `round5_forged_sensor` | 200 / 200 | 200 / 200 | 200 / 200 | 200 / 200 | 200 / 200 | 200 / 200 | never stopped here: a perfect replay (Chapter 4) |
| Shoppers blocked (of 40) | 0 | 1 (no-JS) | 1 (no-JS) | 1 (no-JS) | 1 (no-JS) | 1 (no-JS) | `sensor_gate:no_sensor`, an accepted cost |
| Shoppers 🟡 suspicious (20–39) | – | – | RFP Firefox (20) | privacy ext. (30), RFP Firefox (20) | privacy ext. (30), RFP Firefox (20) | privacy ext. (30), RFP Firefox (20) | served, one rule from a block |
| Gate ms on /api/products, median / max | 0.95 / 1.75 | 1.46 / 22.29 | 1.35 / 3.75 | 1.52 / 2.77 | 1.50 / 2.39 | 1.34 / 2.78 | `Server-Timing` |
| Checkpoint | PASS | PASS | PASS | PASS | PASS | PASS | |

<details><summary>The scoreboards (one per round)</summary>

**Round 0** (level 1)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round0_httpx_scraper | 1 | 0 | 0 | 1 | 90.0 | 2.46 |
| bot:round0_playwright_default | 1 | 0 | 0 | 1 | 95.0 | 2.92 |
| bot:round1_playwright_cdp_override | 4 | 4 | 0 | 0 | 0.0 | 1.16 |
| bot:round2_flags_off | 4 | 4 | 0 | 0 | 0.0 | 1.72 |
| bot:round3_stealth_plugin | 4 | 4 | 0 | 0 | 0.0 | 1.17 |
| bot:round4_patchright | 4 | 4 | 0 | 0 | 0.0 | 1.55 |
| bot:round4_patchright_vanilla | 4 | 4 | 0 | 0 | 0.0 | 1.35 |
| bot:round5_forged_sensor | 4 | 4 | 0 | 0 | 0.0 | 0.95 |
| human:autofill | 4 | 4 | 0 | 0 | 0.0 | 1.2 |
| human:consumer_vpn | 12 | 12 | 0 | 0 | 0.0 | 3.03 |
| human:home | 96 | 96 | 0 | 0 | 0.0 | 2.28 |
| human:mobile_cgnat | 32 | 32 | 0 | 0 | 0.0 | 2.03 |
| human:no_js | 3 | 3 | 0 | 0 | 0.0 | 1.57 |
| human:old_chrome | 4 | 4 | 0 | 0 | 0.0 | 1.98 |
| human:private_relay | 8 | 8 | 0 | 0 | 0.0 | 1.48 |

Bots stopped: **2/26** requests · shoppers hurt: **0/40** people (0/159 requests stopped, including challenges they then solved) · purchases: {} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

**Round 1** (level 2)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round0_httpx_scraper | 1 | 0 | 0 | 1 | 100.0 | 1.3 |
| bot:round0_playwright_default | 1 | 0 | 0 | 1 | 95.0 | 2.36 |
| bot:round1_playwright_cdp_override | 3 | 2 | 0 | 1 | 20.0 | 1.6 |
| bot:round2_flags_off | 4 | 4 | 0 | 0 | 0.0 | 1.54 |
| bot:round3_stealth_plugin | 4 | 4 | 0 | 0 | 0.0 | 1.49 |
| bot:round4_patchright | 4 | 4 | 0 | 0 | 0.0 | 1.38 |
| bot:round4_patchright_vanilla | 3 | 2 | 0 | 1 | 20.0 | 1.59 |
| bot:round5_forged_sensor | 4 | 4 | 0 | 0 | 0.0 | 1.0 |
| human:autofill | 4 | 4 | 0 | 0 | 0.0 | 1.4 |
| human:consumer_vpn | 12 | 12 | 0 | 0 | 0.0 | 1.71 |
| human:home | 96 | 96 | 0 | 0 | 0.0 | 2.73 |
| human:mobile_cgnat | 32 | 32 | 0 | 0 | 0.0 | 3.8 |
| human:no_js | 2 | 1 | 0 | 1 | 20.0 | 1.52 |
| human:old_chrome | 4 | 4 | 0 | 0 | 0.0 | 1.76 |
| human:private_relay | 8 | 8 | 0 | 0 | 0.0 | 3.81 |

Bots stopped: **4/24** requests · shoppers hurt: **1/40** people (1/158 requests stopped, including challenges they then solved) · purchases: {} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

**Round 2** (level 3)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round0_httpx_scraper | 1 | 0 | 0 | 1 | 100.0 | 1.22 |
| bot:round0_playwright_default | 1 | 0 | 0 | 1 | 95.0 | 1.38 |
| bot:round1_playwright_cdp_override | 3 | 2 | 0 | 1 | 33.3 | 2.51 |
| bot:round2_flags_off | 3 | 2 | 0 | 1 | 30.0 | 1.21 |
| bot:round3_stealth_plugin | 4 | 4 | 0 | 0 | 0.0 | 1.4 |
| bot:round4_patchright | 4 | 4 | 0 | 0 | 5.0 | 2.04 |
| bot:round4_patchright_vanilla | 3 | 2 | 0 | 1 | 23.3 | 1.48 |
| bot:round5_forged_sensor | 4 | 4 | 0 | 0 | 0.0 | 1.23 |
| human:autofill | 4 | 4 | 0 | 0 | 0.0 | 2.92 |
| human:consumer_vpn | 12 | 12 | 0 | 0 | 0.0 | 2.87 |
| human:home | 96 | 96 | 0 | 0 | 1.2 | 2.37 |
| human:mobile_cgnat | 32 | 32 | 0 | 0 | 1.9 | 2.44 |
| human:no_js | 2 | 1 | 0 | 1 | 20.0 | 1.84 |
| human:old_chrome | 4 | 4 | 0 | 0 | 0.0 | 1.78 |
| human:private_relay | 8 | 8 | 0 | 0 | 0.0 | 2.26 |

Bots stopped: **5/23** requests · shoppers hurt: **1/40** people (1/158 requests stopped, including challenges they then solved) · purchases: {} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

**Round 3** (level 4)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round0_httpx_scraper | 1 | 0 | 0 | 1 | 100.0 | 1.51 |
| bot:round0_playwright_default | 1 | 0 | 0 | 1 | 95.0 | 2.09 |
| bot:round1_playwright_cdp_override | 3 | 2 | 0 | 1 | 33.3 | 1.87 |
| bot:round2_flags_off | 3 | 2 | 0 | 1 | 33.3 | 1.98 |
| bot:round3_stealth_plugin | 3 | 2 | 0 | 1 | 23.3 | 1.52 |
| bot:round4_patchright | 4 | 4 | 0 | 0 | 5.0 | 1.45 |
| bot:round4_patchright_vanilla | 3 | 2 | 0 | 1 | 23.3 | 2.48 |
| bot:round5_forged_sensor | 4 | 4 | 0 | 0 | 0.0 | 1.08 |
| human:autofill | 4 | 4 | 0 | 0 | 0.0 | 4.54 |
| human:consumer_vpn | 12 | 12 | 0 | 0 | 5.0 | 3.4 |
| human:home | 96 | 96 | 0 | 0 | 2.5 | 2.42 |
| human:mobile_cgnat | 32 | 32 | 0 | 0 | 1.9 | 2.33 |
| human:no_js | 2 | 1 | 0 | 1 | 20.0 | 1.85 |
| human:old_chrome | 4 | 4 | 0 | 0 | 0.0 | 4.3 |
| human:private_relay | 8 | 8 | 0 | 0 | 0.0 | 2.91 |

Bots stopped: **6/22** requests · shoppers hurt: **1/40** people (1/158 requests stopped, including challenges they then solved) · purchases: {} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

**Round 4** (level 5)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round0_httpx_scraper | 1 | 0 | 0 | 1 | 100.0 | 1.54 |
| bot:round0_playwright_default | 1 | 0 | 0 | 1 | 95.0 | 1.48 |
| bot:round1_playwright_cdp_override | 3 | 2 | 0 | 1 | 33.3 | 1.16 |
| bot:round2_flags_off | 3 | 2 | 0 | 1 | 33.3 | 1.24 |
| bot:round3_stealth_plugin | 3 | 2 | 0 | 1 | 23.3 | 1.27 |
| bot:round4_patchright | 4 | 3 | 0 | 1 | 15.0 | 1.64 |
| bot:round4_patchright_vanilla | 3 | 2 | 0 | 1 | 23.3 | 2.37 |
| bot:round5_forged_sensor | 4 | 4 | 0 | 0 | 0.0 | 1.27 |
| human:autofill | 4 | 4 | 0 | 0 | 0.0 | 2.79 |
| human:consumer_vpn | 12 | 12 | 0 | 0 | 5.0 | 2.16 |
| human:home | 96 | 96 | 0 | 0 | 2.5 | 2.29 |
| human:mobile_cgnat | 32 | 32 | 0 | 0 | 1.9 | 2.54 |
| human:no_js | 2 | 1 | 0 | 1 | 20.0 | 1.93 |
| human:old_chrome | 4 | 4 | 0 | 0 | 0.0 | 2.93 |
| human:private_relay | 8 | 8 | 0 | 0 | 0.0 | 1.66 |

Bots stopped: **7/22** requests · shoppers hurt: **1/40** people (1/158 requests stopped, including challenges they then solved) · purchases: {} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

**Round 5** (level 5)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round0_httpx_scraper | 1 | 0 | 0 | 1 | 100.0 | 1.33 |
| bot:round0_playwright_default | 1 | 0 | 0 | 1 | 95.0 | 1.4 |
| bot:round1_playwright_cdp_override | 3 | 2 | 0 | 1 | 33.3 | 1.29 |
| bot:round2_flags_off | 3 | 2 | 0 | 1 | 33.3 | 1.16 |
| bot:round3_stealth_plugin | 3 | 2 | 0 | 1 | 23.3 | 1.17 |
| bot:round4_patchright | 4 | 3 | 0 | 1 | 15.0 | 2.5 |
| bot:round4_patchright_vanilla | 3 | 2 | 0 | 1 | 23.3 | 3.12 |
| bot:round5_forged_sensor | 4 | 4 | 0 | 0 | 0.0 | 1.57 |
| human:autofill | 4 | 4 | 0 | 0 | 0.0 | 5.5 |
| human:consumer_vpn | 12 | 12 | 0 | 0 | 5.0 | 1.42 |
| human:home | 96 | 96 | 0 | 0 | 2.5 | 2.18 |
| human:mobile_cgnat | 32 | 32 | 0 | 0 | 1.9 | 2.03 |
| human:no_js | 2 | 1 | 0 | 1 | 20.0 | 1.27 |
| human:old_chrome | 4 | 4 | 0 | 0 | 0.0 | 4.95 |
| human:private_relay | 8 | 8 | 0 | 0 | 0.0 | 1.43 |

Bots stopped: **7/22** requests · shoppers hurt: **1/40** people (1/158 requests stopped, including challenges they then solved) · purchases: {} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

</details>

Things to watch for:

- **Version drift is the whole game.** When Playwright, patchright or Chrome update, rerun `python tools/checkpoint.py --all --catch-up`. Then re-capture `tools/profiles/chromium-153-linux.json` with `/lab/capture`, and update the version strings in the synthetic profiles.
- **Synthetic profiles.** Twelve of the thirteen profiles are synthetic. The Firefox, Safari and resistFingerprinting values are representative, not captured. Add your own browsers with `/lab/capture` in Round 0: that's the best false-positive data you will get.
- **Collection time is user-visible latency.** The Quick add panel waits for the sensor before it loads products. The profiles report a median collection time of 140 ms (up to 2.2 s for the captured Chromium, where creating a GPU-backed WebGL context dominates). Production sensors defer expensive probes or run them off the critical path.
- **Headed attacks.** Every attack runs headless. If you run patchright headed on a real desktop, the SwiftShader signal disappears too.

---

## Bonus challenges

1. **Worker-side lies.** Extend `round3_stealth_plugin.py` so its patches also run inside Workers: wrap `window.Worker` and prepend the patch to the worker's script. The realm check goes quiet, but the native-code check still fires on the main thread. Why does it take both checks to catch a careful liar? Then make `workerReport()` report native-code integrity from inside the Worker too.
2. **Selenium.** Run `python attacks/bonus_selenium.py`. ChromeDriver still injects `cdc_adoQpoasnfa76pfcZLmcfl_*` globals in 2026. Which flag or patched driver removes them, and what does Layer 2 then see?
3. **Touch spoofing.** Make the Round 4 attack claim to be a touch device (`has_touch=True`, `page.tap()`). Which rule in `interaction.py` catches it, and what does that cost a real Windows laptop with a touchscreen? (Chapter 5, Round 5 goes further.)
4. **The CDP side-effect probe.** Add the classic `Runtime.enable` detector to `sensor.js`: a `console.debug` of an Error whose `stack` getter records being read. Run every attack. Why does it never fire on Chromium 153? (See §1.4: V8 fixed it in Chrome 137.)
