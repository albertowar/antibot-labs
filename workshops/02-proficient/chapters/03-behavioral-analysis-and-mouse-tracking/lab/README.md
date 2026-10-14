# Chapter 3 Lab: Behavioral Analysis & Mouse Tracking

Starts from: `workshops/02-proficient/starter/` (contract 1.4). Adds: a behavior collector on the drop page, five pre-written behavior layers on `POST /drop/<sku>`, `/lab/behavior/*` trace views, eight bots (Rounds 0–5) and behavior profiles for the 40 shoppers.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/behavior.py`
- `defenses/behavior_features.py`
- `defenses/behavior_l1.py`
- `defenses/behavior_l2.py`
- `defenses/behavior_l3.py`
- `defenses/behavior_l4.py`
- `defenses/behavior_l5.py`
- `demo_site/ext/behavior.py`
- `demo_site/ext/templates/behavior/view.html`
- `demo_site/ext/templates/drop.html`
- `demo_site/static/js/behavior.js`
- `demo_site/static/js/behavior_viewer.js`
- `tools/humans.py`
- `tools/personas_ch3.py`
- `tools/save_trace.py`
- `tools/score_trace.py`
- `tools/traces/corpus_01.json`
- `tools/traces/corpus_02.json`
- `tools/traces/corpus_03.json`
- `tools/traces/corpus_04.json`
- `tools/traces/corpus_05.json`
- `tools/traces/corpus_06.json`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** Round 0 recon plus 5 rounds of attack ⚔️ defend, then a debrief. See `../chapter_03_content.md`, Section 3.8. **Style: pre-written.** Every layer ships complete in `defenses/behavior_l1.py` … `behavior_l5.py`: you read it, switch the level, and measure. `solutions/round<N>/` holds only that round's `defenses/ladder.py` and `policy.py`.

The store is running a **limited drop**: the Lab Runner 9 shoe, one reservation form. Scalper bots want every pair.

The drop page carries a small collector script. It records *how* the form was filled in: pointer paths, clicks and taps, and the timing of each keystroke. Just before the form is sent, the page posts that record to the store's telemetry sink, and the behavior layers score it when the reservation arrives.

You play both sides. Every round follows the same loop:

1. The attacker runs a script.
2. The defender turns on the next layer and measures two things: the bots it stops, and the real users it stops by mistake.
3. The attacker works out what to try next.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service URLs such as `REDIS_URL` too). Browsers get the same guard: `labclient.browser_context` aborts every request that is not local. Do not remove that check.
- Simulated client addresses come from `data/world.json` (documentation ranges) and travel in `X-Lab-Client-IP`, which the store's edge trusts only from loopback. All names, emails and traces are synthetic, apart from the ones you record yourself.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, the browser and container images. Recording a phone trace (optional) uses a USB cable and `adb reverse`, so the phone reaches the store on this machine's loopback; nothing is exposed on your network.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  demo_site/ext/behavior.py          the feature: drop-page layout, telemetry kind "behavior", /lab/behavior/* views
  demo_site/ext/templates/           drop.html (the form at fixed positions) · behavior/view.html (the trace viewer)
  demo_site/static/js/               behavior.js (the collector) · behavior_viewer.js
  defenses/                          behavior (glue) · behavior_features · behavior_l1 … behavior_l5 · ladder.py · policy.py
  attacks/                           round0_recon … round5_touch_tap, humanize.py, demo_agent_style.py, _common.py
  tools/                             checkpoint.py · personas_ch3.py (the shoppers' profiles) · humans.py (their behavior)
                                     save_trace.py · score_trace.py · traces/ (corpus + your recordings)
  solutions/round1..5/               reference ladder.py and policy.py per round (the catch-up files)
```

The rest of the store (catalog, cart, checkout, drops, accounts, the simulated edge, the decision log) is the W2 starter, unchanged. Its contract is `workshops/STORE_CONTRACT.md`. The one visible change is the drop page: the lab's `drop.html` draws the order form at fixed positions (the server must know where every box is), adds a name field and asks for the size as text.

**Why this stack.** Python runs the store, the scoring, the attackers (Playwright) and the measurements; the two in-page scripts are plain JavaScript with `// @ts-check` and no build step. Feature extraction uses only the standard library. The machine-learning work belongs to W2 Ch7, which trains on these same features.

---

## Setup

Work through `onboarding/setup/PREWORK.md` first. This lab adds a browser:

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # one venv per chapter, see the root README
pip install -r requirements.txt -r requirements-browser.txt
python -m playwright install chromium
python tools/doctor.py
python demo_site/app.py                                   # http://127.0.0.1:5000/drop/lab-runner-9
```

Docker is optional. By default the store keeps its state in an in-process Redis (`REDIS_URL=memory://`) that forgets everything on restart; with `docker compose up -d --wait` and `REDIS_URL=redis://127.0.0.1:6379/0` it remembers sessions and replay signatures across restarts (this matters in Round 4).

Switch levels without a restart (the checkpoint does this for you):

```bash
curl -s -X POST localhost:5000/lab/level -H 'Content-Type: application/json' -d '{"level": 3}'
```

| Level | Adds | Module |
|---|---|---|
| 0 | Nothing. Every reservation is recorded and can be viewed, nobody is stopped | – |
| 1 | Presence & sanity: no telemetry, teleport clicks, text without keys, too fast | `defenses/behavior_l1.py` |
| 2 | Kinematics & keystroke dynamics: ruler paths, zero gaps between keys | `defenses/behavior_l2.py` |
| 3 | Motor-control realism: deceleration at the target, typing rhythm | `defenses/behavior_l3.py` |
| 4 | Layout jitter & replay signatures | `defenses/behavior_l4.py` + `new_layout()` in `defenses/behavior.py` |
| 5 | Touch realism: tap contact time, dead-centre taps | `defenses/behavior_l5.py` |

Each level includes every level below it. The store adds up the points of every enabled layer, and `defenses/policy.py` (this lab's bands) picks the verdict:

| Score | Verdict | What the client gets | In production |
|---|---|---|---|
| **≥ 60** | `block` | 403 | |
| **≥ 30** | `challenge` | 403, `X-Lab-Verdict: challenge` (no challenge type is registered in this lab) | a step-up: CAPTCHA or proof of work (W1 Ch6, Ch7) |
| **< 30** | `allow` | the order | |

Lab views (loopback only, never scored):

- `/lab/behavior/view/<sid>`: draws one session's path, clicks and taps, closing-speed profiles and keystrokes. `latest` works as the `<sid>`, and the drop page links to it.
- `/lab/behavior/sessions`: the last reservations, each with its level, verdict, signals, payload size and gate cost.
- `/lab/behavior/trace/<sid>`: the raw telemetry plus the extracted features, as JSON.
- `/lab/decisions`: the store's decision log, every request with its signals.

> Every response carries `X-Lab-Verdict`, `X-Lab-Score` and `X-Lab-Signals`, and the bots print them. That is for teaching only.
> In production, never tell a client which rule caught it.

### Troubleshooting

| Problem | Fix |
|---|---|
| Port 5000 is already in use (on macOS, the AirPlay Receiver takes it) | `PORT=5050 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:5050` in every shell you run attacks and tools from |
| `Executable doesn't exist … chrome-headless-shell` | `python -m playwright install chromium` inside this lab's venv |
| A bot reports `failed` | The store sent the form back (an invalid size or email): a bug in the bot, not a defense |
| You want a clean slate | `curl -X POST localhost:5000/lab/reset` (or restart the store) |

---

## How to measure a round

Finish every round with a **checkpoint**:

```bash
python tools/checkpoint.py --round <N>              # set level N, run every bot next to the 40 shoppers
python tools/checkpoint.py --round <N> --level <N-1>   # the same bots against the level before
```

It runs **every** bot of the chapter at the round's level, so you see both what the current layers stop and what still gets through (the next round's problem). At the same time the store's 40 shoppers (`tools/population.py`) buy the same drop, each with a behavior profile (`tools/personas_ch3.py`), and posting the telemetry their browser would have sent (`tools/humans.py`). It reports:

- **Bots.** Each bot's attempts and verdicts, against what should happen at this level. "Stopped" means challenged or blocked.
- **Shoppers.** A table per behavior profile. **Blocked** is a false positive, and the checkpoint fails on it. **Challenged** is friction: it is listed with its signals, and the round fails above its budget (3 from Level 1).
- **Your own traces** from Round 0, scored offline at the round's level. The checkpoint fails if one of them would be blocked.
- **Defender cost.** The gate's time on the drop `POST` (from `Server-Timing`) and the telemetry each shopper uploaded.

| Shopper profile | n | Who | Why it is hard |
|---|---|---|---|
| mouse | 18 | home, VPN, privacy relay, old Chrome | 125–1000 Hz mice, a range of skill, some slow typists |
| trackpad | 3 | home (macOS) | 60 Hz sampling, and the user lifts and re-places the finger |
| tremor | 3 | home | 4–6 Hz tremor of 2–4 px, slow movement, many corrections |
| keyboard | 2 | home | Tab through the form, Enter on the button. No pointer at all |
| screen_reader | 2 | home | Same as keyboard, but slower |
| touch | 8 | the phones (carrier NAT) | Taps with no hover path. A virtual keyboard that reports `Unidentified` with ~0 ms holds |
| password_mgr | 2 | autofill + one home | Name and email autofilled: text with no keystrokes |
| voice | 1 | home | Voice control: the cursor warps to each target's centre, and text is dictated |
| no telemetry | 1 | no_js | JavaScript off: the collector never runs |

**The synthetic shoppers are a stand-in, not ground truth.**
- Their movement is built from lognormal velocity strokes (Plamondon's Kinematic Theory), plus tremor and aperiodic jitter. Their typing uses log-normal hold and gap times, with natural rollover and typos.
- Every phone types like Android's Gboard. Nobody has checked the iPhone keyboard model against a real iPhone yet.
- That's why Round 0 adds **your** traces, and why you should record a phone too (below).

**Fell behind?** Every defense is already written, so catching up means switching to the round's level: the checkpoint does it, and `--catch-up` installs that round's `ladder.py` and `policy.py`.

---

## Round 0: Instrument & recon

**🛡️ Look at your own behavior:**

1. Open `http://127.0.0.1:5000/drop/lab-runner-9` in your normal browser. Read the page, then reserve a pair the way you normally would.
2. Click **view the last trace** under the form and study what the collector saw: the path, the closing speed of each approach, and the keystroke bars.
3. Save the session as a trace file:

   ```bash
   python tools/save_trace.py --name <you>     # → tools/traces/<you>.json
   ```

   From now on, every checkpoint scores your trace. Round 4's replay attack will also use it as its source.

4. Do it twice more, a little differently each time: Tab between fields, paste the email, or use a trackpad.

**🗡️ Look at the laziest bot:**

```bash
python attacks/round0_recon.py               # runs a page.fill()/page.click() bot, then compares it with you
```

It prints the bot's numbers next to yours (or next to a corpus trace until you have recorded one): pointer samples, mouse approaches, keystrokes, fields filled without keys, time to submit and payload size.

**Discuss:**

- Which of these differences could a scalper fix with one line of code? *(All of them, one at a time: that is this chapter.)*
- What does the collector *not* record, and why? *(Key values and `event.code`, and the form's text: a keystroke collector is one change away from a keylogger.)*

**Checkpoint:** `python tools/checkpoint.py --round 0`. Every bot reserves, every shopper buys, nobody is challenged.

---

## Round 1: `page.fill()` + `page.click()` ⚔️ L1 presence & sanity

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round1_click_fill.py` (level 0) | `reserved` |
| 🛡️ Defend | Read `defenses/behavior_l1.py`, then switch to level 1 | – |
| 🗡️ Re-run | `python attacks/round1_click_fill.py` | `blocked`: submitted in a fraction of a second, teleport click, pixel-perfect centre, text without keystrokes, first sample at (0, 0) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | round 1 bot stopped · shoppers: 0 blocked; voice (55) and no-JavaScript (30) challenged |

**Exercises:**

1. The keyboard exemption is one line in `click_features()` in `defenses/behavior_features.py` (`mouse = kind in MOUSE_KINDS and detail >= 1`). Change it to `mouse = kind in MOUSE_KINDS or detail == 0` so keyboard activations count as mouse clicks, save, and run the checkpoint. Who gets hurt? *(The keyboard and screen-reader shoppers: their clicks become teleports.)*
2. The voice-control shopper scores 55, a challenge. Why can't L1 tell them apart from the Round 1 bot? *(Teleport, centre and dictated text are the same signals; only speed separates them, and a bot can sleep.)*
3. `isTrusted` is in the collector, so why isn't it catching Playwright? *(CDP input events are trusted; only `el.click()` from page JS is not. Try `page.evaluate("document.getElementById('drop-buy').click()")`.)*

---

## Round 2: Ruler & metronome ⚔️ L2 kinematics & keystroke dynamics

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round2_linear_steps.py` (level 1) | `reserved`: it moves the mouse, presses real keys and takes ~6 s |
| 🛡️ Defend | Read `defenses/behavior_l2.py`, then switch to level 2 | – |
| 🗡️ Re-run | `python attacks/round2_linear_steps.py` | `blocked`: ruler-straight approach at constant speed and no gap between keys |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | rounds 1–2 stopped · shoppers: 0 blocked |

**Exercises:**

1. Open the bot's trace in `/lab/behavior/view/<sid>`. `keyboard.type(text, delay=100)` holds each key for 100 ms and releases it, and the next key goes down about 2 ms later. Compare the bars with yours.
2. The phone shoppers' virtual keyboards report holds of ~0–5 ms. Why don't they trip "zero-dwell typing"? *(Their keys have class `u`, counted as `ime_keys` and kept out of the dwell rules.)*
3. Run `python attacks/demo_agent_style.py` at levels 1 and 2. An agent that types `xdotool`-style is allowed at L1 and blocked at L2 for zero-dwell typing.

---

## Round 3: The humanizer ⚔️ L3 motor-control realism

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round3_humanizer.py --runs 3` and `--ease --runs 3` (level 2) | mostly `reserved` |
| 🛡️ Defend | Read `defenses/behavior_l3.py` and `closing_profile()` in `defenses/behavior_features.py`, then switch to level 3 | – |
| 🗡️ Re-run | Same commands | **no easing:** stopped (no deceleration at the target + Gaussian typing). **eased:** about half stopped |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | rounds 1–3 stopped (the eased humanizer ≥ 1 of 2) · shoppers: 0 blocked · your traces `allow` |

**Exercises:**

1. Compare the closing-speed curves in `/lab/behavior/view` for your trace and for both humanizer flavours. A human arrives at the target almost stopped (end ratio ≈ 0.05). A Bézier curve walked in uniform steps of t arrives at speed.
2. Why does L3 measure *closing* speed toward the click point rather than path speed? *(A hand oscillating in place has path speed but makes no progress; the first version measured path speed and blocked a tremor shopper.)*
3. **TODO (Round 3, optional)** in `behavior_l3.py`: add a "symmetric speed profile" rule using `asymmetry`, then count how many shoppers it challenges. We measured about 10% for a rule that catches eased Bézier curves. Would you ship it?

**Discuss:** the eased humanizer gets through some of the time. Tightening `WEAK_END` would catch more of it. What does each 0.05 cost in challenged shoppers? Change it, save (the store reloads `defenses/` on the next request) and rerun the checkpoint.

---

## Round 4: Replay a real human ⚔️ L4 layout jitter & signatures

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round4_replay.py --forge` (level 3) | `reserved`: a recorded human payload, sent over plain HTTP with no browser |
| 🗡️ Attack | `python attacks/round4_replay.py --runs 2` (level 3) | `reserved` ×2: your recording, warped onto the page in Chromium. L1–L3 have no memory |
| 🛡️ Defend | Read `defenses/behavior_l4.py` and `new_layout()` in `defenses/behavior.py`, then switch to level 4 | – |
| 🗡️ Re-run | `python attacks/round4_replay.py --forge` | `blocked` (70): click outside its target. The form moved, so the recorded click lands on empty page |
| 🗡️ Re-run | `python attacks/round4_replay.py --trace tools/traces/corpus_05.json --runs 2` | 1st `reserved` ("first use is free"), 2nd `blocked` (70): replayed typing |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | everything up to Round 4 stopped · shoppers: 0 blocked |

In the checkpoint the forged payload goes first, and the warped replays reuse the same recording, so even the first warped replay is a recording the store has already seen: all three are caught. On a long-running store, your own Round 0 session is caught on its **first** replay for the same reason. Restarting the store (or `POST /lab/reset`) forgets every signature unless you run Redis in Docker.

**Exercises:**

1. Run `python attacks/round4_replay.py --trace tools/traces/corpus_04.json --jitter-keys --runs 3`. This bot perturbs every key's hold and gap by about 20 ms, so only the path fingerprint is left. Why is the path so much weaker than typing? *(Playwright drops samples to 60 Hz, and smooth human paths look alike once normalised.)* What would you add?
2. Camoufox's `humanize` replays one of about 2,000 recorded human traces. How many reservations does a corpus that size buy if each trace works exactly once?

---

## Round 5: Be a phone ⚔️ L5 touch realism

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round5_touch_tap.py` (level 4) | `reserved` (score ~10): Pixel 7 emulation, `page.tap()`, Gboard-style keys over CDP. Every touch exemption applies |
| 🛡️ Defend | Read `defenses/behavior_l5.py`, then switch to level 5 | – |
| 🗡️ Re-run | `python attacks/round5_touch_tap.py` | `blocked` (65+): taps with < 1 ms of contact, each at the exact centre |
| 🗡️ Answer | `python attacks/round5_touch_tap.py --cdp` | `reserved`: `Input.dispatchTouchEvent` taps held 60–140 ms, off centre, with a finger-sized radius |
| ✅ Checkpoint | `python tools/checkpoint.py --round 5` | everything but `--cdp` stopped · the 8 phone shoppers: 0 blocked |

**Exercises:**

1. Open a phone shopper's trace and the bot's in `/lab/behavior/view`. The collector logs each tap's contact `width`, `height` and `pressure` (`telemetry.contact`): the scripted tap reports 2 × 2 px at pressure 1.0. Why does Layer 5 not score it? *(No real-phone capture to calibrate against, and Android and iOS report contact differently. Record yours, below.)*
2. The `--cdp` bot gets through. Which other layer of this workshop would you ask about a "Pixel 7" whose GPU, fonts and TLS fingerprint are a desktop Chromium's? *(Device coherence, W2 Ch4; the network stack, W2 Ch5.)*

### Record a phone trace (Android, optional)

The synthetic phone shoppers are a model. Your phone is not. The store stays on loopback: `adb reverse` makes the phone's `localhost:5000` this machine's `127.0.0.1:5000` over the USB cable, and nothing listens on your network.

1. Enable developer options and USB debugging on the phone, connect it, and accept the prompt.
2. On this machine (Android platform tools installed): `adb reverse tcp:5000 tcp:5000`
3. On the phone, in Chrome: open `http://localhost:5000/drop/lab-runner-9` and reserve a pair with your thumb and the on-screen keyboard.
4. Save it: `python tools/save_trace.py --name phone`. It prints your taps' contact times, centre offsets and contact geometry.
5. `python tools/score_trace.py tools/traces/phone.json` and the checkpoints now score it. A block of your phone is a false positive.
6. When you are done: `adb reverse --remove-all`.

An iPhone has no equivalent loopback tunnel, and we never bind the store to your network to reach one, so the lab has no iOS capture path.

---

## Wrap-up: false positives, cost, and where behavior stops (debrief)

```bash
python tools/population.py --scenario behavior_drop     # the shoppers once, at the current level
python tools/score_trace.py tools/traces/*.json
curl -s localhost:5000/lab/behavior/sessions | python -m json.tool | less
```

- Which shoppers were challenged at each level, and which rule caused it? Is the voice-control shopper's challenge acceptable? The no-JavaScript one?
- Your recorded traces are behavioral biometrics. What do you store, for how long, and who can see them? (GDPR Art. 9; see Section 3.9.)
- Scoring costs a few milliseconds per reservation in pure Python, more at Level 4 (a scan over up to 2,000 signatures), and the collector uploads ~10–15 KB per mouse shopper, more for a 1000 Hz mouse. What would you cap, sample or move client-side?
- Run `python attacks/demo_agent_style.py --dictate` at level 4. The "agent" is challenged for the same reasons as the voice-control shopper. What signal would tell them apart? (Hint: W4 Ch2, verified bot identity.)

---

## Expected results (self-check)

Verified on 2026-10-12 with Python 3.12, the W2 starter's pins (Flask 3.1.3, fakeredis 2.39.0 as the in-process Redis, SQLite) and Playwright 1.63.0 (Chromium 153.0.8010.12, headless) on Linux. The Docker Redis and PostgreSQL path has not been run for this lab.

Generated from `python tools/verify.py --all --markdown` (each round runs every bot next to the 40 shoppers). R = reserved · C = challenged · B = blocked; **bold** is the round that first stops the bot.

| Bot ↓ / level → | 0 | 1 | 2 | 3 | 4 | 5 | Signals at its round |
|---|---|---|---|---|---|---|---|
| `round1_click_fill` | R | **B** | B | B | B | B | `l1:centre`, `l1:teleport`, `l1:text_without_keys`, `l1:too_fast` |
| `round2_linear_steps` | R | R | **B** | B | B | B | `l2:instant_flight`, `l2:ruler_path` |
| `round3_humanizer` (×2) | 2 R | 2 R | 2 R | **1 C · 1 B** | 1 C · 1 B | 2 B | `l3:gaussian_typing`, `l3:no_deceleration` |
| `round3_humanizer --ease` (×2) | 2 R | 2 R | 2 R | **1 R · 1 C** | 2 C | 2 C | `l3:gaussian_typing`, `l3:weak_deceleration` |
| `round4_replay --forge` | R | R | R | R | **B** | B | `l4:click_outside` |
| `round4_replay` warped (×3) | 3 R | 3 R | 3 R | 3 R | **3 B** | 3 B | `l4:replayed_typing` |
| `round5_touch_tap` | R | R | R | R | R | **B** | `l5:centre_taps`, `l5:instant_taps` |
| `round5_touch_tap --cdp` | R | R | R | R | R | R | never stopped here: finger-like CDP taps (Section 3.7) |
| **40 shoppers** | 0 B · 0 C | 0 B · 2 C | 0 B · 2 C | 0 B · 2 C | 0 B · 2 C | 0 B · 2 C | C = voice control (55), no JavaScript (30) |
| gate ms, median / max | 1.53 / 2.85 | 5.67 / 44.10 | 7.18 / 27.95 | 7.35 / 26.70 | 10.07 / 28.11 | 8.91 / 69.56 | the drop POST, from `Server-Timing` |
| checkpoint | PASS | PASS | PASS | PASS | PASS | PASS | |

Telemetry: median 11.6 KB per mouse shopper, up to 60.3 KB (1000 Hz mice).

<details><summary>The scoreboards (one per round)</summary>

**Round 0** (level 0)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round1_click_fill | 3 | 3 | 1 | 0 | 0.0 | 1.3 |
| bot:round2_linear_steps | 3 | 3 | 1 | 0 | 0.0 | 1.38 |
| bot:round3_humanizer | 6 | 6 | 2 | 0 | 0.0 | 1.23 |
| bot:round3_humanizer_ease | 6 | 6 | 2 | 0 | 0.0 | 1.39 |
| bot:round4_forge | 3 | 3 | 1 | 0 | 0.0 | 0.93 |
| bot:round4_replay | 9 | 9 | 3 | 0 | 0.0 | 1.31 |
| bot:round5_touch_cdp | 3 | 3 | 1 | 0 | 0.0 | 1.21 |
| bot:round5_touch_tap | 3 | 3 | 1 | 0 | 0.0 | 1.28 |
| human:autofill | 4 | 4 | 1 | 0 | 0.0 | 2.84 |
| human:consumer_vpn | 12 | 12 | 3 | 0 | 0.0 | 2.03 |
| human:home | 96 | 96 | 24 | 0 | 0.0 | 1.87 |
| human:mobile_cgnat | 32 | 32 | 8 | 0 | 0.0 | 1.84 |
| human:no_js | 3 | 3 | 1 | 0 | 0.0 | 2.2 |
| human:old_chrome | 4 | 4 | 1 | 0 | 0.0 | 1.74 |
| human:private_relay | 8 | 8 | 2 | 0 | 0.0 | 1.68 |

Bots stopped: **0/36** requests · shoppers hurt: **0/40** people (0/159 requests stopped, including challenges they then solved) · purchases: {'bot': 12, 'human': 40} · drop stock left: {'lab-hoodie-1': 200, 'lab-runner-9': 148}

**Round 1** (level 1)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round1_click_fill | 3 | 2 | 0 | 1 | 33.3 | 1.0 |
| bot:round2_linear_steps | 3 | 3 | 1 | 0 | 0.0 | 3.45 |
| bot:round3_humanizer | 6 | 6 | 2 | 0 | 0.0 | 4.04 |
| bot:round3_humanizer_ease | 6 | 6 | 2 | 0 | 3.3 | 4.24 |
| bot:round4_forge | 3 | 3 | 1 | 0 | 0.0 | 4.22 |
| bot:round4_replay | 9 | 9 | 3 | 0 | 2.2 | 4.67 |
| bot:round5_touch_cdp | 3 | 3 | 1 | 0 | 3.3 | 1.81 |
| bot:round5_touch_tap | 3 | 3 | 1 | 0 | 3.3 | 1.8 |
| human:autofill | 4 | 4 | 1 | 0 | 1.2 | 12.46 |
| human:consumer_vpn | 12 | 12 | 3 | 0 | 0.0 | 4.63 |
| human:home | 96 | 95 | 23 | 1 | 0.6 | 4.2 |
| human:mobile_cgnat | 32 | 32 | 8 | 0 | 0.0 | 2.24 |
| human:no_js | 3 | 2 | 0 | 1 | 10.0 | 2.58 |
| human:old_chrome | 4 | 4 | 1 | 0 | 0.0 | 2.82 |
| human:private_relay | 8 | 8 | 2 | 0 | 0.0 | 4.03 |

Bots stopped: **1/36** requests · shoppers hurt: **2/40** people (2/159 requests stopped, including challenges they then solved) · purchases: {'bot': 11, 'human': 38} · drop stock left: {'lab-hoodie-1': 200, 'lab-runner-9': 151}

**Round 2** (level 2)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round1_click_fill | 3 | 2 | 0 | 1 | 33.3 | 0.94 |
| bot:round2_linear_steps | 3 | 2 | 0 | 1 | 26.7 | 3.5 |
| bot:round3_humanizer | 6 | 6 | 2 | 0 | 3.3 | 2.42 |
| bot:round3_humanizer_ease | 6 | 6 | 2 | 0 | 3.3 | 2.71 |
| bot:round4_forge | 3 | 3 | 1 | 0 | 0.0 | 4.18 |
| bot:round4_replay | 9 | 9 | 3 | 0 | 2.2 | 3.56 |
| bot:round5_touch_cdp | 3 | 3 | 1 | 0 | 0.0 | 2.28 |
| bot:round5_touch_tap | 3 | 3 | 1 | 0 | 0.0 | 1.98 |
| human:autofill | 4 | 4 | 1 | 0 | 1.2 | 9.27 |
| human:consumer_vpn | 12 | 12 | 3 | 0 | 0.0 | 4.44 |
| human:home | 96 | 95 | 23 | 1 | 0.6 | 3.87 |
| human:mobile_cgnat | 32 | 32 | 8 | 0 | 0.0 | 2.59 |
| human:no_js | 3 | 2 | 0 | 1 | 10.0 | 2.21 |
| human:old_chrome | 4 | 4 | 1 | 0 | 0.0 | 2.81 |
| human:private_relay | 8 | 8 | 2 | 0 | 0.0 | 2.27 |

Bots stopped: **2/36** requests · shoppers hurt: **2/40** people (2/159 requests stopped, including challenges they then solved) · purchases: {'bot': 10, 'human': 38} · drop stock left: {'lab-hoodie-1': 200, 'lab-runner-9': 152}

**Round 3** (level 3)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round1_click_fill | 3 | 2 | 0 | 1 | 33.3 | 1.04 |
| bot:round2_linear_steps | 3 | 2 | 0 | 1 | 33.3 | 2.76 |
| bot:round3_humanizer | 6 | 4 | 0 | 2 | 17.5 | 3.02 |
| bot:round3_humanizer_ease | 6 | 5 | 1 | 1 | 12.5 | 3.2 |
| bot:round4_forge | 3 | 3 | 1 | 0 | 0.0 | 3.54 |
| bot:round4_replay | 9 | 9 | 3 | 0 | 0.0 | 3.01 |
| bot:round5_touch_cdp | 3 | 3 | 1 | 0 | 3.3 | 1.51 |
| bot:round5_touch_tap | 3 | 3 | 1 | 0 | 0.0 | 1.73 |
| human:autofill | 4 | 4 | 1 | 0 | 1.2 | 8.85 |
| human:consumer_vpn | 12 | 12 | 3 | 0 | 0.0 | 3.83 |
| human:home | 96 | 95 | 23 | 1 | 0.8 | 3.63 |
| human:mobile_cgnat | 32 | 32 | 8 | 0 | 0.0 | 2.09 |
| human:no_js | 3 | 2 | 0 | 1 | 10.0 | 2.16 |
| human:old_chrome | 4 | 4 | 1 | 0 | 0.0 | 3.15 |
| human:private_relay | 8 | 8 | 2 | 0 | 0.0 | 5.48 |

Bots stopped: **5/36** requests · shoppers hurt: **2/40** people (2/159 requests stopped, including challenges they then solved) · purchases: {'bot': 7, 'human': 38} · drop stock left: {'lab-hoodie-1': 200, 'lab-runner-9': 155}

**Round 4** (level 4)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round1_click_fill | 3 | 2 | 0 | 1 | 33.3 | 1.02 |
| bot:round2_linear_steps | 3 | 2 | 0 | 1 | 33.3 | 3.0 |
| bot:round3_humanizer | 6 | 4 | 0 | 2 | 20.8 | 4.98 |
| bot:round3_humanizer_ease | 6 | 4 | 0 | 2 | 15.0 | 5.22 |
| bot:round4_forge | 3 | 2 | 0 | 1 | 23.3 | 6.91 |
| bot:round4_replay | 9 | 6 | 0 | 3 | 26.7 | 5.65 |
| bot:round5_touch_cdp | 3 | 3 | 1 | 0 | 0.0 | 3.19 |
| bot:round5_touch_tap | 3 | 3 | 1 | 0 | 0.0 | 2.8 |
| human:autofill | 4 | 4 | 1 | 0 | 1.2 | 8.99 |
| human:consumer_vpn | 12 | 12 | 3 | 0 | 0.0 | 4.88 |
| human:home | 96 | 95 | 23 | 1 | 0.9 | 5.0 |
| human:mobile_cgnat | 32 | 32 | 8 | 0 | 0.0 | 2.91 |
| human:no_js | 3 | 2 | 0 | 1 | 10.0 | 1.83 |
| human:old_chrome | 4 | 4 | 1 | 0 | 0.0 | 5.44 |
| human:private_relay | 8 | 8 | 2 | 0 | 0.0 | 4.86 |

Bots stopped: **10/36** requests · shoppers hurt: **2/40** people (2/159 requests stopped, including challenges they then solved) · purchases: {'bot': 2, 'human': 38} · drop stock left: {'lab-hoodie-1': 200, 'lab-runner-9': 160}192.0.2.10 - - [12/Oct/2026 16:23:51] "GET /lab/status HTTP/1.1" 200 -

**Round 5** (level 5)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:round1_click_fill | 3 | 2 | 0 | 1 | 33.3 | 1.67 |
| bot:round2_linear_steps | 3 | 2 | 0 | 1 | 33.3 | 2.72 |
| bot:round3_humanizer | 6 | 4 | 0 | 2 | 21.7 | 5.88 |
| bot:round3_humanizer_ease | 6 | 4 | 0 | 2 | 12.5 | 5.27 |
| bot:round4_forge | 3 | 2 | 0 | 1 | 23.3 | 3.92 |
| bot:round4_replay | 9 | 6 | 0 | 3 | 24.4 | 5.65 |
| bot:round5_touch_cdp | 3 | 3 | 1 | 0 | 0.0 | 3.07 |
| bot:round5_touch_tap | 3 | 2 | 0 | 1 | 25.0 | 3.08 |
| human:autofill | 4 | 4 | 1 | 0 | 1.2 | 6.95 |
| human:consumer_vpn | 12 | 12 | 3 | 0 | 0.0 | 4.7 |
| human:home | 96 | 95 | 23 | 1 | 0.6 | 4.77 |
| human:mobile_cgnat | 32 | 32 | 8 | 0 | 0.0 | 2.3 |
| human:no_js | 3 | 2 | 0 | 1 | 10.0 | 2.35 |
| human:old_chrome | 4 | 4 | 1 | 0 | 0.0 | 18.34 |
| human:private_relay | 8 | 8 | 2 | 0 | 0.0 | 3.15 |

Bots stopped: **11/36** requests · shoppers hurt: **2/40** people (2/159 requests stopped, including challenges they then solved) · purchases: {'bot': 1, 'human': 38} · drop stock left: {'lab-hoodie-1': 200, 'lab-runner-9': 161}

</details>

How to read it:

- **"Shoppers hurt" in the scoreboards counts challenges too.** The checkpoint is stricter about blocks and looser about challenges: it fails on any blocked shopper and allows up to 3 challenged ones from Level 1. In every run here, the two challenged shoppers are the voice-control user (teleport + centre + dictated text = 55) and the no-JavaScript user (no telemetry = 30).
- **Warped replays at Level 4.** The checkpoint runs the forged payload first, and both replays use `corpus_01.json`, so even the first warped replay is a recording the store has seen. On its own (`--trace tools/traces/corpus_05.json --runs 2` on a fresh store) the first replay reserves and the second is blocked: first use is free.
- **`l1:origin_start`** (one mouse sample at (0, 0), 10 points) shows up on most Playwright bots, the phone ones included: Playwright's emulation dispatches it before the page does anything. It is left out of the signal column because it never decides a verdict on its own.

Things to watch for:

- **Variance.** Rounds 3–5 use randomised bots. The thresholds ("stopped ≥ 1 of 2" for the eased humanizer, "≥ 2 of 3" for the warped replay, "gets through at least once" below a bot's round) sit below the observed rates, so a correct setup almost never fails by chance. In one run L2 challenged one of the two un-eased humanizer runs at Level 2 (a very flat Bézier looks ruler-straight). If a checkpoint fails once, run it again before you debug.
- **Synthetic shoppers.** The calibration comes from `tools/humans.py`, not from a labelled corpus of real users. Save 2–3 traces of your own in Round 0, record a phone if you can, and treat any block of a real trace as a bug in the rules.
- **Version drift.** Playwright changes how input is dispatched now and then (the stray (0, 0) sample, `page.tap()`'s timing). Re-run every checkpoint when you bump `playwright` in `requirements-browser.txt`.

---

## Bonus challenges

1. **Coalesced events.** The collector records every coalesced pointer sample. Playwright's CDP input arrives about one per frame (60 Hz), with no coalescing. Measure `moves_dispatched` against `len(pointer)` for your mouse and for each bot. Is "no coalesced samples" a signal? Who would it hurt? (60 Hz trackpads, Safari versions without `getCoalescedEvents`, remote desktops.) This is a hypothesis to measure, not an established vendor signal.
2. **Wheel and scroll.** Add `wheel` events (`deltaY`, `deltaMode`) to the collector, plus a feature that compares wheel steps with scroll jumps. What does `page.mouse.wheel()` look like next to a trackpad?
3. **Real data.** The Boğaziçi Mouse Dynamics dataset (CC BY 4.0, Mendeley Data) is real mouse movement you may download yourself. Convert a few sessions into the trace format and run `tools/score_trace.py` on them. How many would L3 challenge?
4. **Touch geometry.** Record two or three phone traces (above), then write a Layer 5 rule on `telemetry.contact` that blocks `page.tap()`'s 2 × 2 px contact without touching your phone. How confident are you with one phone model?
