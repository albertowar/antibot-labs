# Chapter 3 Lab: Behavioral Analysis & Mouse Tracking

**Format:** Round 0 recon plus 4 rounds of attack ⚔️ defend, 100 min of lab inside the 3-hour chapter. See `../chapter_03_content.md`, §3.7.

The demo store is running a **limited drop**: 50 pairs of a (fictional) shoe and one reservation form. Scalper bots want all 50.

Every page carries a small collector script. It records *how* the form was filled in: pointer paths, clicks, and the timing of each keystroke. The server scores that telemetry when the reservation arrives.

You play both sides. Every round follows the same loop:

1. The attacker runs a script.
2. The defender turns on the next layer and measures two things: the bots it stops, and the real users it stops by mistake.
3. The attacker works out what to try next.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- Lab traffic never goes through a proxy. All names, emails and traces are synthetic.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  docker-compose.yml   Redis 8 for drop sessions, traces and replay signatures
  demo_site/           app.py (DEFENSE_LEVEL=0..4), store.py, static/collector.js, static/viewer.js
  defenses/            features · l1_presence · l2_kinematics · l3_motor · l4_replay · scoring
  attacks/             round0_recon … round4_replay, humanize.py, demo_agent_style.py
  tools/               checkpoint · humans (synthetic users) · save_trace · score_trace · traces/
```

**Why this stack.** The lab is Python only, apart from the two in-page scripts, which are plain JavaScript with `// @ts-check` and no build step.
- **Python** runs the server, the scoring, the attackers (Playwright) and the measurements.
- **The browser-side code** is about 150 lines. A TypeScript toolchain would cost more setup time than it saves.
- **Feature extraction** uses only the standard library. The machine-learning work belongs to W2 Ch7, which trains on these same features.

---

## Setup (before the session, ~5 min)

```bash
cd lab
docker compose up -d --wait                 # Redis on 127.0.0.1:6379
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

You need Python 3.10 or newer. Docker is optional (see Troubleshooting).

Start the demo store, and restart it with a new `DEFENSE_LEVEL` each round:

```bash
DEFENSE_LEVEL=0 python demo_site/app.py     # http://localhost:5000/drop
```

| Level | Adds | Module |
|---|---|---|
| 0 | Nothing. Every reservation is scored and logged, but nobody is stopped | – |
| 1 | Presence & sanity: teleport clicks, text without keys, too fast | `defenses/l1_presence.py` |
| 2 | Kinematics & keystroke dynamics: ruler paths, zero gaps between keys | `defenses/l2_kinematics.py` |
| 3 | Motor-control realism: deceleration at the target, typing rhythm | `defenses/l3_motor.py` |
| 4 | Layout jitter & replay signatures | `defenses/l4_replay.py` + `new_layout()` in `app.py` |

Each level includes every level below it. `defenses/scoring.py` adds up the points and picks one of three verdicts:

| Score | Verdict | Response | In production |
|---|---|---|---|
| **≥ 60** | `block` | **403** | |
| **≥ 30** | `challenge` | **202** | step up to a CAPTCHA or proof of work (W1 Ch6, Ch7) |
| **< 30** | `allow` | **200** | reserved |

These debug endpoints are never scored:

- `/behavior/sessions`: the last decisions, each with its label, score, reasons, payload size and scoring time.
- `/behavior/view/<sid>`: draws one session's path, clicks, closing-speed profiles and keystrokes. `latest` works as the `<sid>`.
- `/behavior/trace/<sid>`: the raw telemetry plus the extracted features, as JSON.

> The response tells the client which rules fired. That is for teaching only.
> In production, never tell a client which rule caught it.

### Troubleshooting

| Problem | Fix |
|---|---|
| Port 5000 is already in use (on macOS, the AirPlay Receiver takes it) | Start the app with `PORT=5050 DEFENSE_LEVEL=… python demo_site/app.py`. Then `export DEMO_URL=http://localhost:5050` in every shell you run attacks and tools from |
| No Docker | Start the app with `STORE=memory`. Everything works the same, but the store forgets everything on restart (this matters in Round 4) |
| `Cannot reach Redis` | Run `docker compose ps`. The container must show `healthy` |
| You want a clean slate | `docker compose down -v && docker compose up -d --wait` |
| A Playwright attack hangs at `wait_for_selector` | The server isn't running, or `DEMO_URL` points to the wrong port |

---

## How to measure a round

Finish every round with a **checkpoint**, which takes about 90 seconds:

```bash
python tools/checkpoint.py --round <N>      # add --skip-browser to skip the Playwright attacks
```

```
=== Checkpoint: Round 3 (server at DEFENSE_LEVEL=3) ===

Bot traffic                         reserved  challenged  blocked   expected
  ✅ round1_click_fill                  0         0         1     stopped ≥ 1/1
  ✅ round2_linear_steps                0         0         1     stopped ≥ 1/1
  ✅ round3_humanizer                   0         0         2     stopped ≥ 2/2
  ✅ round3_humanizer --ease            0         1         1     stopped ≥ 1/2
  ✅ round4_replay --forge              1         0         0     gets through
  ✅ round4_replay (warped)             3         0         0     gets through

Real users: 40 synthetic humans
  ✅ blocked 0/40   challenged 1/40
       🟡 voice: [L1] Teleport click …; [L1] 4 click(s) within 1 px of the target's exact centre; [L1] Text without keystrokes …

Real users: your recorded traces (offline, Levels 1-3)
  ✅ alice.json               allow     score=0

Defender cost
  scoring:   median 4.58 ms, p95 12.41 ms per reservation
  telemetry: median 13.4 KB per mouse user, max 56.8 KB (1000 Hz mice)
             median 5.4 KB per Playwright bot (60 Hz, no coalescing)

✅ Round 3 checkpoint passed.
```

What the checkpoint reports:

- **Bot traffic.** Every attack script, compared with what should happen at this level. "Stopped" means challenged or blocked.
- **Real users.** Two kinds:
  - `tools/humans.py` builds 40 fresh synthetic visitors on every run. The population is in the table below.
  - **Your own traces** from Round 0, scored offline.

  **Blocked** is a false positive, and the checkpoint fails on it. **Challenged** is friction: it's listed with its reasons, so you can weigh it.
- **Defender cost.** The scoring time for each reservation, taken from `Server-Timing`, and the telemetry the browser uploads.

| Synthetic profile | n | Why it is hard |
|---|---|---|
| mouse | 24 | 125–1000 Hz mice, a range of skill, some slow typists |
| trackpad | 3 | 60 Hz sampling, and the user lifts and re-places the finger |
| tremor | 3 | 4–6 Hz tremor of 2–4 px, slow movement, many corrections |
| keyboard | 2 | Tab through the form, Enter on the button. No pointer at all |
| screen_reader | 2 | Same as keyboard, but slower |
| touch | 3 | Taps with no hover path. A virtual keyboard that reports `Unidentified` with ~0 ms holds |
| password_mgr | 2 | Name and email autofilled: text with no keystrokes |
| voice | 1 | Voice control: the cursor warps to each target's centre, and text is dictated |

**The synthetic users are a stand-in, not ground truth.**
- Their movement is built from lognormal velocity strokes (Plamondon's Kinematic Theory), plus tremor and aperiodic jitter.
- Their typing uses log-normal hold and gap times, with natural rollover and typos.
- That's why Round 0 adds **your** traces, and the checkpoint fails if any of them gets blocked.

**Fell behind?** Every defense is already written, so catching up just means restarting the store with `DEFENSE_LEVEL=<N>`. The checkpoint tells you if you're on the wrong level.

---

## Round 0: Instrument & recon (15 min)

**🛡️ Look at your own behavior:**

1. Open `http://localhost:5000/drop` in your normal browser. Read the page, then reserve a pair the way you normally would.
2. Click **view my trace** and study what the collector saw: the path, the closing speed of each approach, and the keystroke bars.
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

```
                                    bot          human
  pointer samples                     1            328
  mouse approaches                    0              2
  keystrokes                          0             41
  text without keys      email, name, size              -
  submitted after (ms)              165          17759
  payload (KB)                      0.4           11.5
```

**Discuss:**

- Which of these differences could a scalper fix with one line of code?
- What does the collector *not* record, and why? It never sends key values or `event.code`, and it stores form fields only as lengths.

**Checkpoint:** `python tools/checkpoint.py --round 0`. Everything gets through, and 0 humans are stopped.

---

## Round 1: `page.fill()` + `page.click()` ⚔️ L1 presence & sanity (20 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round1_click_fill.py` (level 0) | `reserved` |
| 🛡️ Defend | Read `defenses/l1_presence.py`, then restart with `DEFENSE_LEVEL=1` | – |
| 🗡️ Re-run | `python attacks/round1_click_fill.py` | `blocked`, score 95–105: submitted in ~0.2 s (40), teleport click (20), pixel-perfect centre (15), text without keystrokes (20), and sometimes first sample at (0, 0) (10) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | round 1 stopped · humans: 0 blocked, 1 challenged (voice) |

**Exercises:**

1. In `l1_presence.py`, comment out the keyboard exemption. A click with `detail == 0` is a keyboard activation. Treat it as a teleport click instead, then run the checkpoint. Who gets hurt?
2. The voice-control user scores 55, which is a challenge. Why can't L1 tell them apart from the Round 1 bot? (Only one rule separates them: speed.)
3. `isTrusted` is in the collector, so why isn't it catching Playwright? CDP input events are trusted, and only `el.click()` from page JS is not. Try `page.evaluate("document.getElementById('reserve').click()")`.

---

## Round 2: Ruler & metronome ⚔️ L2 kinematics & keystroke dynamics (20 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round2_linear_steps.py` (level 1) | `reserved`: it moves the mouse, presses real keys and takes ~6 s |
| 🛡️ Defend | Read `defenses/l2_kinematics.py`, then restart with `DEFENSE_LEVEL=2` | – |
| 🗡️ Re-run | `python attacks/round2_linear_steps.py` | `blocked`, score 70: ruler-straight approach at constant speed (straightness 1.0, step CV ≈ 0.002) and no gap between keys (100% within 8 ms) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | rounds 1–2 stopped · humans: 0 blocked, 1 challenged |

**Exercises:**

1. Open the bot's trace in `/behavior/view/<sid>`. `keyboard.type(text, delay=100)` holds each key for 100 ms and releases it, and the next key goes down about 2 ms later. Compare the bars with yours.
2. The touch users' virtual keyboards report holds of ~0–5 ms. Why don't they trip "zero-dwell typing"? Find the `ime_keys` exemption.
3. Run `python attacks/demo_agent_style.py` at levels 1 and 2. An agent that types `xdotool`-style is allowed at L1 (score 20) and blocked at L2 (score 70).

---

## ☕ Break (10 min)

---

## Round 3: The humanizer ⚔️ L3 motor-control realism (25 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round3_humanizer.py --runs 3` and `--ease --runs 3` (level 2) | mostly `reserved`. L2 occasionally challenges a very flat Bézier |
| 🛡️ Defend | Read `defenses/l3_motor.py` and `closing_profile()` in `features.py`, then restart with `DEFENSE_LEVEL=3` | – |
| 🗡️ Re-run | Same commands | **no easing:** `blocked` 5/5. No deceleration at the target (45; median end ratio 0.43–0.60) + Gaussian typing (15)<br>**eased:** about 2 blocked, 2 challenged, 1 reserved out of 5 |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | rounds 1–3 stopped · humans: 0 blocked, 1 challenged · your traces `allow` |

**Exercises:**

1. Compare the closing-speed curves in `/behavior/view` for your trace and for both humanizer flavours. A human arrives at the target almost stopped (end ratio ≈ 0.05). A Bézier curve walked in uniform steps of t arrives at speed.
2. Why does L3 measure *closing* speed toward the click point rather than path speed? The first version measured path speed, and it blocked a synthetic tremor user. A hand oscillating in place has path speed but no closing speed.
3. **TODO (Round 3, optional)** in `l3_motor.py`: add a "symmetric speed profile" rule using `asymmetry`. Then count how many synthetic humans it challenges. We measured about 10% for a rule that catches eased Bézier curves. Would you ship it?

**Discuss:** the eased humanizer gets through some of the time. Tightening `WEAK_END` would catch more of it. What does each 0.05 cost in challenged humans? Run `tools/humans.py` to find out.

---

## Round 4: Replay a real human ⚔️ L4 layout jitter & signatures (20 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round4_replay.py --forge` (level 3) | `reserved`: a recorded human payload, POSTed without a browser |
| 🗡️ Attack | `python attacks/round4_replay.py --runs 2` (level 3) | `reserved` ×2: your recording, warped onto the page in Chromium. L1–L3 have no memory |
| 🛡️ Defend | Read `defenses/l4_replay.py` and `new_layout()` in `app.py`, then restart with `DEFENSE_LEVEL=4` | – |
| 🗡️ Re-run | `python attacks/round4_replay.py --forge` | `blocked` (70): click outside its target. The form moved, so the recorded click lands on empty page |
| 🗡️ Re-run | `python attacks/round4_replay.py --trace tools/traces/corpus_05.json --runs 2` | 1st `reserved` ("first use is free"), 2nd `blocked` (70): replayed typing, every keystroke timed like an earlier session |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | everything stopped · humans: 0 blocked, 1 challenged |

With Redis, the store remembers sessions across restarts. A recording the server has already seen, including your own Round 0 session, is caught on its **first** replay. With `STORE=memory`, a restart forgets everything. The checkpoint accepts both.

**Exercises:**

1. Run `python attacks/round4_replay.py --trace tools/traces/corpus_04.json --jitter-keys --runs 3`. This bot perturbs every key's hold and gap by about 20 ms, so only the path fingerprint is left. In our runs, 1 of 3 replays was caught. Why is the path so much weaker than typing? Playwright drops samples to 60 Hz, and smooth human paths look alike once normalised. What would you add?
2. Camoufox's `humanize` replays one of about 2,000 recorded human traces. How many reservations does a corpus that size buy if each trace works exactly once?

---

## Wrap-up: false positives, cost, and where behavior stops (debrief)

```bash
python tools/humans.py                      # per-profile verdicts and reasons
python tools/score_trace.py tools/traces/*.json
curl -s localhost:5000/behavior/sessions | python -m json.tool | less
```

- Which synthetic users were challenged at each level, and which rule caused it? Is the voice-control user's challenge acceptable?
- Your recorded traces are behavioral biometrics. What do you store, for how long, and who can see them? (GDPR Art. 9; see §3.8.)
- Scoring costs ~5 ms in pure Python, and the collector uploads ~10–15 KB per user, up to ~95 KB for a 1000 Hz mouse. What would you cap, sample or move client-side?
- Run `python attacks/demo_agent_style.py --dictate` at level 4. The "agent" is challenged (score 40) for the same reasons as the voice-control user. What signal would tell them apart? (Hint: W4 Ch2, verified bot identity.)

---

## Instructor: expected results

Verified with Playwright 1.63 (Chromium 153.0.8010.12, headless) on Linux and Python 3.10, with `STORE=memory`. The Redis back end was **not** exercised in this verification run, because Docker wasn't available.

R = reserved · C = challenged · **B** = blocked. Bold marks the first level that stops the attack.

| Attack ↓ / `DEFENSE_LEVEL` → | 0 | 1 | 2 | 3 | 4 | Reason at the first stop |
|---|---|---|---|---|---|---|
| `round1_click_fill` | R | **B** | B | B | B | `[L1]` too fast + teleport + centre + text without keys, score 95–105 |
| `round2_linear_steps` | R | R | **B** | B | B | `[L2]` ruler-straight + no gap between keys, score 70 |
| `round3_humanizer` | R | R | R (rarely C) | **B** | B | `[L3]` no deceleration (45) + Gaussian typing (15) |
| `round3_humanizer --ease` | R | R | R | **~70% C/B** | ~70% C/B | `[L3]` no/weak deceleration + Gaussian typing |
| `round4_replay --forge` | R | R | R | R | **B** | `[L4]` click outside its target |
| `round4_replay` (warped) | R | R | R | R | **B** after first use | `[L4]` replayed typing |
| `round4_replay --jitter-keys` | R | R | R | R | mostly R (1/3 B) | `[L4]` replayed path, when it fires |
| `demo_agent_style.py` | R | R (20) | **B** (70) | B | B | `[L2]` zero-dwell typing |
| `demo_agent_style.py --dictate` | R | **C** (40) | C | C | C | `[L1]` teleport + text without keys |
| 40 synthetic humans | 0 B · 0 C | 0 B · 1 C | 0 B · 1 C | 0 B · 1 C | 0 B · 1 C | the C is the voice-control user (55) |

Over 200 synthetic humans per level, we saw 0 blocks after the closing-speed fix. A password-manager user is challenged occasionally (bulk fill 5 + weak deceleration 25 = 30).

Defender cost measured across these runs:
- **Scoring:** median 5–13 ms and p95 12–32 ms per reservation. That's pure-Python feature extraction; L4 adds a scan over up to 2,000 signatures.
- **Telemetry:** median 11–14 KB per mouse user, up to ~95 KB for a 1000 Hz mouse, and ~5 KB per Playwright bot.

Things to watch for:

- **Variance.** Round 3 and Round 4 bots are randomised. The checkpoint's thresholds ("stopped ≥ 1/2" for the eased humanizer) are set below the observed rates so that a correct setup almost never fails by chance. If a student's checkpoint fails once, run it again before you debug.
- **Synthetic humans.** Calibration came from `tools/humans.py`, not from a labelled corpus of real users. Ask students to save 2–3 traces each in Round 0, and treat any block of a real trace as a bug in the rules.
- **Version drift.** Playwright changes how input is dispatched now and then. The `(0, 0)` first sample, for example, appears in some runs and not others. Re-run all checkpoints when you bump `playwright` in `requirements.txt`.

---

## Bonus challenges

1. **Coalesced events.** The collector records every coalesced pointer sample. Playwright's CDP input arrives about one per frame (60 Hz), with no coalescing. Measure `moves_dispatched` against `len(pointer)` for your mouse and for each bot. Is "no coalesced samples" a signal? Who would it hurt? (60 Hz trackpads, Safari versions without `getCoalescedEvents`, remote desktops.) This is a hypothesis to measure, not an established vendor signal.
2. **Wheel and scroll.** Add `wheel` events (`deltaY`, `deltaMode`) to the collector, plus a feature that compares wheel steps with scroll jumps. What does `page.mouse.wheel()` look like next to a trackpad?
3. **Real data.** The Boğaziçi Mouse Dynamics dataset (CC BY 4.0, Mendeley Data) is real mouse movement you may download yourself. Convert a few sessions into the trace format and run `tools/score_trace.py` on them. How many would L3 challenge?
