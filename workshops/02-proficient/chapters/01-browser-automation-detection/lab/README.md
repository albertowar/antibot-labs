# W2 Ch1 Lab: Browser Automation Detection

**Format:** Round 0 plus 4 attack ⚔️ defend rounds and a closing attack, ~126 min of hands-on time. See `../chapter_01_content.md`, §1.6.

You play both sides. The attacker drives a real browser at the demo store. The defender adds a layer to the bot sensor that runs inside the page, then measures two things: what the layer catches, and what it costs real users. Then the attacker works out what to try next.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- Lab traffic never goes through a proxy or anyone else's infrastructure. All users, carts and credentials here are synthetic.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  docker-compose.yml   PostgreSQL 16 (sensor verdicts, carts). Optional: SQLite works too
  demo_site/           Flask store · static/sensor.js (the in-page sensor) · templates/
  defenses/            automation_artifacts · consistency · lie_detection · interaction · scoring
    edge/              Workshop 1's header rules, always on
  solutions/roundN/    reference versions of the four files you edit (installed by --catch-up)
  attacks/             round0_* … round5_forged_sensor · bonus_* · _common (localhost guard)
  tools/               checkpoint.py · scoreboard.py · legit_traffic.py · profiles/*.json
```

**Why this stack.** The lab uses Python, the same as Workshop 1: Flask for the store, and Playwright, patchright and httpx for the attacks. The sensor is one plain JavaScript file with no build step, because it has to run unmodified in Chrome, Firefox and Safari, and students shouldn't need Node installed for one file. Docker is optional and only runs PostgreSQL.

---

## Setup (before the session, ~10 min)

You need Python 3.10 or newer. Docker is optional.

```bash
cd lab
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m playwright install chromium                   # Chromium + headless shell, ~250 MB
python -m patchright install chromium                   # Round 4
docker compose up -d --wait                             # PostgreSQL on 127.0.0.1:5432
#   no Docker?  export DATABASE_URL=sqlite:///sensor.db  (Windows: set DATABASE_URL=...)
```

Start the store, and restart it with a new `DEFENSE_LEVEL` each round:

```bash
cd demo_site
DEFENSE_LEVEL=0 python app.py                           # http://localhost:5000
```

| Level | Adds | Module you read (and finish) |
|---|---|---|
| 0 | Edge only: Workshop 1's header rules block bad headers. The sensor runs and is logged, but nothing else is enforced | `defenses/edge/` |
| 1 | **Sensor gate** (no sensor verdict = no API) and automation artifacts | `defenses/automation_artifacts.py` |
| 2 | Consistency: JS vs. HTTP, headless window shape, self-contradictions | `defenses/consistency.py` |
| 3 | Lie detection: native-code integrity, Worker and iframe realms | `defenses/lie_detection.py` |
| 4 | Interaction evidence on `POST /api/cart` | `defenses/interaction.py` |

`defenses/scoring.py` adds up the points from every layer at or below the level:

- **≥ 40** → `bot`: blocked with a 403.
- **≥ 20** → `suspicious`: logged but allowed.
- **< 20** → `clean`.

Three debug endpoints are never blocked:

- `/sensor-check` shows how your session was scored.
- `/sensor-logs` shows the last 50 verdicts.
- `/capture` saves your own browser as a real-user profile. Do this in Round 0.

> The 403 response lists the reasons that fired. That's for teaching only. In production, never tell a client which rule caught it.

**Troubleshooting**

| Problem | Fix |
|---|---|
| Port 5000 is in use (on macOS, AirPlay Receiver uses it) | Start with `PORT=5050 DEFENSE_LEVEL=… python app.py`. Then run `export DEMO_URL=http://localhost:5050` in the shell you run attacks and tools from |
| No Docker | `export DATABASE_URL=sqlite:///sensor.db` before starting the app. Everything else works the same |
| `connection refused` on 5432 | Run `docker compose ps`; the container must show as `healthy` |
| `Executable doesn't exist` from Playwright or patchright | Rerun the matching `install chromium` command above |
| A browser attack hangs or times out | Make sure the store is running on `DEMO_URL` and that nothing else is listening on that port |
| You edited a defense and nothing changed | The dev server reloads on save. If it crashed, the terminal shows the traceback |

---

## How to measure a round

Finish every round with a **checkpoint**:

```bash
python tools/checkpoint.py --round <N>          # --skip-browser skips the browser attacks
```

```
=== Checkpoint: Round 2 (server at DEFENSE_LEVEL=2) ===

Your code
  ✅ automation_artifacts.check_webdriver (Round 1)
  ✅ consistency.check_headless_shape (Round 2)

Bot traffic
  Attack                           /api/products  /api/cart
  ✅ httpx, default headers        403 ⛔          -
  ✅ Playwright defaults           403 ⛔          -
  ✅ Playwright + CDP identity     403 ⛔          -
  ✅ + automation flags off        403 ⛔          -

Real users (replayed profiles)
  ✅ 1/13 real-user profiles blocked
       chrome-153-windows-nojs: accepted cost: [gate] No sensor verdict for this session …
  🟡 firefox-157-resistfingerprinting scored suspicious (20): [L2] No browser UI: …

Defender cost
  sensor scoring (server): median 0.11 ms per payload
  sensor collection (client, from profiles): median 140 ms, max 2243 ms before the product list can load
  sensor.js: 8.8 KB (3.3 KB gzipped), +1 request (POST /api/sensor) per page view

✅ Round 2 checkpoint passed.
```

Each checkpoint checks four things:

- **Your code.** The function you finished this round is run against known inputs.
- **Bot traffic.** Every attack introduced so far is run and compared with the expected result.
- **Real users.** All 13 profiles in `tools/profiles/` are replayed. A blocked profile fails the checkpoint unless it carries an `expected_cost`: the no-JS user is the one cost we accept and count. 🟡 marks a profile that is allowed but scored `suspicious`.
- **Defender cost.** Server time to score a payload, client time to collect it, and the size of the script.

**Fell behind?** This command copies the reference solution for every round up to N into `defenses/` and saves your files as `*.bak`:

```bash
python tools/checkpoint.py --round <N> --catch-up
```

Then restart the store with `DEFENSE_LEVEL=<N>`.

---

## Round 0: Where Workshop 1 left us (10 min)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round0_httpx_scraper.py` | `403`: `[W1-UA] UA red flag: Raw HTTP library (Python httpx)` |
| 🔴 Attack | `python attacks/round0_playwright_default.py` | `403` on the page itself: `UA red flag: Headless Chrome`, `brand list contains HeadlessChrome` |
| 🧪 Capture | Open `http://localhost:5000/capture` in **your everyday browser**, then click the test button | `tools/profiles/captured-<name>.json` is saved. From now on every checkpoint replays you |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | both attacks blocked · 0 real users blocked |

**Discuss:** Playwright's default headless is `chromium-headless-shell`, a separate build that says so in its User-Agent and brands. What is the *cheapest* change that gets an attacker past every Workshop 1 rule? (It is Round 1.)

---

## Round 1: CDP identity override ⚔️ the sensor gate + `navigator.webdriver` (25 min)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round1_playwright_cdp_override.py` (level 0) | `200` on `/api/products` and `/api/cart`: the edge layer sees a clean Chrome 153 |
| 🔵 Read | `demo_site/static/sensor.js`, `require_sensor_verdict()` in `app.py`, `defenses/automation_artifacts.py` | – |
| 🔵 Defend | Finish `TODO (Round 1)` in `check_webdriver()`, then restart with `DEFENSE_LEVEL=1` | – |
| 🔴 Re-run | `python attacks/round1_playwright_cdp_override.py` | `403`: `[L1] navigator.webdriver is true` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | 3 attacks blocked · 1/13 real users blocked (no-JS, an accepted cost) |

**False-positive check:** open the store in your own browser, then check `/sensor-check`. It should show `clean`, score 0.

**Discuss:**

- The gate blocks the no-JS user. How big is that population on *your* site, and who is in it? (Some corporate desktops, text-mode browsers, and people who block third-party scripts. A first-party sensor is less likely to be blocked.)
- Run `python attacks/round4_patchright.py --vanilla`: it is caught by `__playwright__binding__` even with `webdriver` off. Why does `expose_function()` leave a global behind?

---

## Round 2: Automation flags off ⚔️ consistency (25 min)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round2_flags_off.py` (level 1) | `200`: `navigator.webdriver` is now `false` |
| 🔵 Read | `defenses/consistency.py` | – |
| 🔵 Defend | Finish `TODO (Round 2)` in `check_headless_shape()`, then restart with `DEFENSE_LEVEL=2` | – |
| 🔴 Re-run | `python attacks/round2_flags_off.py` | `403` with 5 reasons: `No browser UI`, `Notification.permission is 'denied' but permissions.query says 'prompt'`, `0 plugins`, `no window.chrome`, `Software WebGL renderer` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | 4 attacks blocked · the resistFingerprinting profile is 🟡 suspicious, not blocked |

**Exercise (5 min):** in `check_software_renderer()`, change the weight from 10 to 40 and rerun the checkpoint. Which real user do you block? (`chrome-153-vdi-swiftshader`: someone on a Citrix desktop.) Put it back.

**Discuss:** the attack fails five rules. How many of them would still fire if the attacker switched to new headless (`channel="chromium"`)? (Only the window shape and the WebGL renderer: 30 points, so it gets through as `suspicious`. New headless runs the real browser code: plugins, `window.chrome` and the permission APIs all behave like desktop Chrome.)

---

## ☕ Break (10 min)

---

## Round 3: playwright-stealth ⚔️ lie detection (25 min)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round3_stealth_plugin.py` (level 2) | `200`: every value Layer 2 reads now looks plausible |
| 🔵 Read | `defenses/lie_detection.py` and `nativeReport()` / `workerReport()` in `sensor.js` | – |
| 🔵 Defend | Finish `TODO (Round 3)` in `check_realm_consistency()`, then restart with `DEFENSE_LEVEL=3` | – |
| 🔴 Re-run | `python attacks/round3_stealth_plugin.py` | `403`: `Native code replaced by script: Navigator.plugins, window.outerWidth, …` and `Another JavaScript realm disagrees with the page: Worker languages` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | 5 attacks blocked · the privacy-extension profile is 🟡 suspicious (30), not blocked |

**Discuss:**

- The privacy extension tells the same kind of lie as the stealth plugin. Why is it 30 points and not 60? What is the difference between "modified" and "modified *and* inconsistent"?
- Try it in your own browser: install a fingerprint-protection extension, reload `/capture` with a new name, and rerun the checkpoint.

---

## ☕ Break (10 min)

---

## Round 4: patchright ⚔️ interaction evidence (25 min)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round4_patchright.py` (level 3) | `200` on both endpoints. Only `[L2] Software WebGL renderer` (10 points) fires |
| 🔴 Compare | `python attacks/round4_patchright.py --vanilla` | `403`: plain Playwright leaves `__playwright__binding__` behind |
| 🔵 Read | `defenses/interaction.py` and `describeClick()` in `sensor.js` | – |
| 🔵 Defend | Finish `TODO (Round 4)` in `check_teleport()`, then restart with `DEFENSE_LEVEL=4` | – |
| 🔴 Re-run | `python attacks/round4_patchright.py` | `/api/products` **200**, `/api/cart` **403**: `Pointer teleported: only 1 pointermove event(s)` and `Click landed within 1px of the exact centre` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | the keyboard-only and Android-touch profiles stay ✅ |

**Discuss:**

- Scraping still works at Level 4. Why is that acceptable for a catalogue but not for a limited-edition sneaker drop?
- The keyboard rule accepts `detail == 0` without checks, so a bot can Tab and press Enter. Is that a bug? (No: it is an accessibility requirement. Close the gap with W2 Ch3's keystroke and focus timing, not by blocking keyboard users.)

---

## Round 5 + debrief: Forge the sensor (16 min)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round5_forged_sensor.py` (level 4) | `200` on both endpoints, with no browser at all |
| 🔴 Bonus | `python attacks/bonus_humanized_cursor.py` | `200`: a curved path and a random landing point beat both Layer 4 rules |
| 💬 Scoreboard | `python tools/scoreboard.py --bonus` | the full picture below |
| ✅ Checkpoint | `python tools/checkpoint.py --round 5` | passes: the forged sensor is *expected* to get through |

Read `round5_forged_sensor.py`: it is `tools/legit_traffic.py` with a different intent. Every layer in this chapter judges a payload the client wrote. That is what the rest of the workshop picks up:

| Gap | Picked up in |
|---|---|
| A sensor whose output cannot be forged without running it (challenge binding, obfuscation, signing) | W2 Ch2 |
| Movement that is merely "not a teleport" | W2 Ch3 |
| Device plausibility (canvas, audio, fonts) | W2 Ch4 |
| The httpx client underneath the forged sensor | W2 Ch5 (TLS) |

---

## Instructor: expected results

Verified on 2026-10-10 with Playwright 1.63.0 (Chromium 153.0.8010.12), patchright 1.63.0, playwright-stealth 2.0.3, Selenium 4.51.0 and Python 3.10, against the store running on SQLite. Each cell shows `/api/products` / `/api/cart`. **Bold** marks the first block, and `–` means the attack never reached the cart.

| Attack ↓ / `DEFENSE_LEVEL` → | 0 | 1 | 2 | 3 | 4 | Reason at the first block |
|---|---|---|---|---|---|---|
| `round0_httpx_scraper` | **403** / – | 403 / – | 403 / – | 403 / – | 403 / – | `[W1-UA] UA red flag: Raw HTTP library (Python httpx)` |
| `round0_playwright_default` | **403** / – | 403 / – | 403 / – | 403 / – | 403 / – | `[W1-UA] … Headless Chrome`, `[W1-hints] … HeadlessChrome` |
| `round1_playwright_cdp_override` | 200 / 200 | **403** / – | 403 / – | 403 / – | 403 / – | `[L1] navigator.webdriver is true` |
| `round2_flags_off` | 200 / 200 | 200 / 200 | **403** / – | 403 / – | 403 / – | `[L2]` ×5, score 90 |
| `round3_stealth_plugin` | 200 / 200 | 200 / 200 | 200 / 200 | **403** / – | 403 / – | `[L3]` native code replaced (30) + Worker languages (40) |
| `round4_patchright` | 200 / 200 | 200 / 200 | 200 / 200 | 200 / 200 | 200 / **403** | `[L4]` teleport (25) + dead centre (25) + `[L2]` SwiftShader (10) |
| `round4_patchright --vanilla` | 200 / 200 | **403** / – | 403 / – | 403 / – | 403 / – | `[L1] Automation global found (… __playwright__binding__)` |
| `round5_forged_sensor` | 200 / 200 | 200 / 200 | 200 / 200 | 200 / 200 | 200 / 200 | – (by design) |
| `bonus_humanized_cursor` | 200 / 200 | 200 / 200 | 200 / 200 | 200 / 200 | 200 / 200 | – |
| `bonus_selenium` | 200 / 200 | **403** / – | 403 / – | 403 / – | 403 / – | `[L1]` webdriver + `cdc_adoQpoasnfa76pfcZLmcfl_*` globals |
| Real users blocked (of 13) | 0 | 1 (no-JS) | 1 | 1 | 1 | `[gate] No sensor verdict` |
| Real users 🟡 suspicious | 0 | 0 | 1 (RFP) | 2 (+ privacy ext.) | 2 | – |

**Defender cost** (measured on the same run):

- **Server scoring:** under 0.2 ms per sensor payload.
- **Script size:** `sensor.js` is 8.8 KB, or 3.3 KB gzipped.
- **Client collection time:**
  - 100–290 ms in headless Chromium, where most of the time goes to creating a WebGL context and starting the Worker.
  - 2.2 s in the captured `chromium-153-linux` profile (a GPU-backed WebGL context under WSLg).
- **Why collection time matters:** the store waits for the sensor before it loads products, so this is user-visible latency. Production sensors defer expensive probes or run them off the critical path.

Things to watch for:

- **Version drift is the whole game.** When Playwright, patchright or Chrome update, rerun `scoreboard.py --bonus` at every level before the session. Then re-capture `tools/profiles/chromium-153-linux.json` with `/capture`, and update the version strings in the synthetic profiles.
- **Synthetic profiles.** Twelve of the thirteen profiles are synthetic. Their header order and native-code strings come from the real Chromium capture, and the identity values (UA, brands, GPU, geometry) are edited per browser. The Firefox, Safari and resistFingerprinting values are representative, not captured. Ask students to add their own browsers with `/capture` in Round 0. That's the best false-positive data you will get in the room.
- **Headed attacks.** Every attack runs headless, so no display is needed. If a student runs patchright headed on a real desktop, the SwiftShader signal disappears too.
- **Docker.** The expected results above were verified on SQLite. The PostgreSQL path uses the same models and the same compose file as W1 Ch4.

---

## Bonus challenges

1. **Worker-side lies.** Extend `round3_stealth_plugin.py` so its patches also run inside Workers: wrap `window.Worker` and prepend the patch to the worker's script. The realm check goes quiet, but the native-code check still fires on the main thread. Why does it take both checks to catch a careful liar? Then make `workerReport()` report native-code integrity from inside the Worker too.
2. **Selenium.** Run `python attacks/bonus_selenium.py`. ChromeDriver still injects `cdc_adoQpoasnfa76pfcZLmcfl_*` globals in 2026. Which flag or patched driver removes them, and what does Layer 2 then see?
3. **Touch spoofing.** Make the Round 4 attack claim to be a touch device (`has_touch=True`, `page.tap()`). Which rule in `interaction.py` catches it, and what does that cost a real Windows laptop with a touchscreen?
4. **The CDP side-effect probe.** Add the classic `Runtime.enable` detector to `sensor.js`: a `console.debug` of an Error whose `stack` getter records being read. Run every attack. Why does it never fire on Chromium 153? (See §1.4: V8 fixed it in Chrome 137. We also tried the "inherited getter" variant reported in 2026; it did not fire either.)
