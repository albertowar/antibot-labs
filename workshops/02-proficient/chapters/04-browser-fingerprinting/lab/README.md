# Chapter 4 Lab: Browser Fingerprinting

**Format:** Round 0 plus 4 rounds of attack ⚔️ defend, then a debrief. About 150 min of hands-on time, spread across the 4-hour chapter. See `../chapter_04_content.md`, §4.8.

The demo store gives every new account a €10 welcome credit, so a bot wants hundreds of accounts. You play both sides:

- The attacker runs a sign-up farm. It uses a fresh browser context and a new simulated IP for every account.
- The defender turns on the next fingerprinting layer. They measure what it stops and what it costs: real users refused, and milliseconds spent.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- The "rotating IPs" are RFC 5737 documentation addresses sent in `X-Lab-Client-IP`, a lab-only header the store trusts only from loopback. No proxy is involved, and every account and e-mail address is synthetic.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  docker-compose.yml       PostgreSQL 16 for fingerprints and sign-ups
  demo_site/app.py         Flask store; DEFENSE_LEVEL=0..4 picks the layers
  demo_site/static/fp_collector.js   the collector (reports raw observations, judges nothing)
  defenses/                render_stack · lie_detector · stable_id · population · linking · fuzzy_cluster · scoring
  attacks/                 round0_recon … round4_noise_signup, data/ (stealth patch, harvested fingerprint)
  tools/                   checkpoint.py · legit_traffic.py · profiles/*.json (40 simulated shoppers)
```

**Why Python only?** The collector is one plain JavaScript file, served as-is with no build step. It only *reports* what it observes. Every decision happens in the Python modules in `defenses/`, which are the files you read and edit, for two reasons:

- The collector runs on the attacker's machine, so anything it decides can be patched out.
- Keeping the judging server-side means you need no Node toolchain.

**Why Docker?** The demo store keeps its fingerprints and sign-ups in PostgreSQL, like the rest of the series. Docker is optional: the SQLite fallback below works the same.

---

## Setup (before the session)

```bash
cd lab
docker compose up -d --wait                 # PostgreSQL on 127.0.0.1:5432
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
playwright install chromium                 # every attack drives Chromium
```

Start the demo site, and restart it with a new `DEFENSE_LEVEL` each round:

```bash
cd demo_site
DEFENSE_LEVEL=0 python app.py               # http://localhost:5000
```

| Level | Adds | Module |
|---|---|---|
| 0 | Nothing. Every sign-up is scored and logged, none are refused | – |
| 1 | Render-stack plausibility, and a fingerprint is required | `defenses/render_stack.py` |
| 2 | Lie detection: page vs. worker vs. headers | `defenses/lie_detector.py` |
| 3 | Exact-ID linking, rarity-weighted | `defenses/stable_id.py`, `population.py`, `linking.py` |
| 4 | Fuzzy clustering on noise-resistant components | `defenses/fuzzy_cluster.py` |

Each level includes every level below it, and `defenses/scoring.py` adds up the points:

| Score | Verdict | What happens |
|---|---|---|
| ≥ 40 | `bot` | Sign-up refused with a 403 |
| ≥ 20 | `suspicious` | Logged, account created |
| < 20 | `clean` | Account created |

`LINK_MODE=naive` turns off rarity weighting in L3 and L4. You'll use it once, in Round 3.

The debug endpoints are never blocked:

| Endpoint | What it does |
|---|---|
| `/fp-check` | Shows your fingerprint and how every level judges it |
| `/fp-profile` | Downloads your fingerprint as a real-user profile |
| `/fp-dashboard` | Sign-ups by verdict, and the most-reused fingerprints |

> The 403 body lists the reasons it fired. That is for teaching only.
> In production, never tell a client which rule caught it.

**Troubleshooting**

| Problem | Fix |
|---|---|
| Port 5000 already in use (macOS: the AirPlay Receiver uses it) | `PORT=5050 DEFENSE_LEVEL=… python app.py`, then `export DEMO_URL=http://localhost:5050` in the shell you run attacks and tools from |
| No Docker | `export DATABASE_URL=sqlite:///fp_lab.db` before starting the app. Everything else works the same |
| Port 5432 taken (e.g. by the W1 Ch4 lab's database) | `docker compose -p w1-ch04-headers down`, or stop your local PostgreSQL |
| `Executable doesn't exist` from Playwright | `playwright install chromium` inside the venv |
| The checkpoint is slow | Each run drives 40 browser sessions, which takes about 45 s. `--signups 5` halves it |

---

## How to measure a round

Finish every round with a **checkpoint**:

```bash
python tools/checkpoint.py --round <N>
```

```
=== Checkpoint: Round 4 (server at DEFENSE_LEVEL=4, LINK_MODE=rarity) ===

Bot traffic (10 sign-ups per attack, fresh store each)
  ✅ round1_headless_signup      0/10 accounts created (expected 0)
  ✅ round2_patched_signup       0/10 accounts created (expected 0)
  ✅ round3_replay_signup        3/10 accounts created (expected 3)
  ✅ round4_noise_signup         3/10 accounts created (expected 3)

Real users (40 simulated shoppers, fresh store)
  ✅ 0/40 refused
       privacy-extension  0/2 refused, 2 suspicious

Defender cost
  collector (headless Chromium): median 214 ms, payload 3.9 KB
  server scoring:  median 0.76 ms, p95 2.97 ms
  linking queries: median 3.56 ms, p95 10.32 ms

✅ Round 4 checkpoint passed.
```

What it reports:

- **Bot traffic:** every attack, compared with what should happen at this level. Each attack starts from an empty store (`POST /lab/reset`), so the numbers don't depend on what you ran before.
- **Real users:** `tools/legit_traffic.py` signs up 40 simulated shoppers. Each one has a fingerprint and headers that match it. Any 403 here is a **false positive**. The cohorts are chosen to hurt: identical iPhones, an office of identical laptops behind one IP, privacy browsers that add noise, and Citrix desktops with no GPU.
- **Defender cost:**
  - collector run time and payload size, measured in a real Chromium;
  - the server's scoring time and linking time, read from the `Server-Timing` header.

**Fell behind?** Every defense is already written, so catching up just means restarting the demo site with `DEFENSE_LEVEL=<N>`. The checkpoint tells you if you're on the wrong level.

---

## Round 0: Recon (20 min)

**🗡️ Attack (look):**

```bash
python attacks/round0_recon.py              # what does the store see from headless Chromium?
```

**🛡️ Defend (look):** open `http://localhost:5000/fp-check` in your own browser, and in a second browser if you have one. Then fill in this table:

| | Headless Chromium | Your browser | Second browser |
|---|---|---|---|
| WebGL renderer | | | |
| `MAX_TEXTURE_SIZE` | | | |
| Fonts found | | | |
| Speech voices | | | |
| Screen | | | |
| `userAgentData` brands | | | |
| Collector time | | | |

Reload `/fp-check` twice. Which values change? (Brave, Safari 26 and Firefox with fingerprinting protection will surprise you.)

**Add yourself to the real-user set:** click **Download as a real-user profile** and save the file as `tools/profiles/you-<browser>.json`. From now on, every checkpoint checks that *your* browser can still sign up.

**Checkpoint:** `python tools/checkpoint.py --round 0`. Every attack should succeed.

---

## Round 1: Default headless ⚔️ Render-stack plausibility (25 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round1_headless_signup.py` (level 0) | 20/20 accounts created |
| 🛡️ Defend | Read `defenses/render_stack.py`, then restart with `DEFENSE_LEVEL=1` | – |
| 🗡️ Re-run | `python attacks/round1_headless_signup.py` | 0/20: `[L1] SwiftShader WebGL renderer` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | round 1 stopped · 0/40 real users refused |

**Exercises:**

1. Run `python defenses/render_stack.py`. Why does the Citrix user score 15, but the headless browser 40?
2. Why is a missing voice list worth nothing on Linux?
3. `TODO (Round 1)` in `render_stack.py`: Android.

---

## ☕ Break (10 min)

---

## Round 2: Stealth patches ⚔️ Lie detection (25 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | Read `attacks/data/stealth_patch.js`, then `python attacks/round2_patched_signup.py` (level 1) | 20/20: L1 now sees an NVIDIA GPU and three voices |
| 🛡️ Defend | Read `defenses/lie_detector.py`, then restart with `DEFENSE_LEVEL=2` | – |
| 🗡️ Re-run | `python attacks/round2_patched_signup.py` | 0/20, score 90: page vs. worker (platform, cores, memory), `MAX_TEXTURE_SIZE=8192` on an "RTX 3060", `userAgentData` brands vs. `Sec-CH-UA` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | rounds 1–2 stopped · 0/40 refused · 2 privacy-extension users `suspicious` |

**Exercises:**

1. None of the patched natives was flagged as patched. Why? (Look at `nativeShape()` in the collector, then at `spoofGetter` in the patch.)
2. The two privacy-extension users *were* flagged as patched, and only scored 25. Should tampering alone ever be worth 40?
3. `TODO (Round 2)` in `lie_detector.py`: compare `languages` and `timeZone` across contexts too. Then check that the checkpoint still passes.

---

## Round 3: Harvested fingerprint ⚔️ Linking with rarity (30 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round3_replay_signup.py` (level 2) | 20/20: L1 and L2 see an honest Windows PC |
| 🛡️ Defend (naive) | Read `defenses/stable_id.py` and `defenses/linking.py`. Restart with `DEFENSE_LEVEL=3 LINK_MODE=naive`, then run `python tools/legit_traffic.py` | **2/40 real users refused**: the 4th identical MacBook and the 4th office laptop |
| 🛡️ Defend | Read `defenses/population.py`, then restart with `DEFENSE_LEVEL=3` (rarity is the default) | – |
| 🗡️ Re-run | `python attacks/round3_replay_signup.py` | 3/20, then `[L3] fingerprint_linked: 3 accounts today from device …` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | rounds 1–3 stopped (round 3 after 3 accounts) · round 4 gets through · 0/40 refused |

**Exercises:**

1. Why does linking ignore the iPhones entirely? What does `python defenses/population.py` print for their class?
2. Replay *your own* fingerprint: `python attacks/round3_replay_signup.py --payload tools/profiles/you-<browser>.json`. How many accounts does it get, and why?
3. `TODO (Round 3)` in `linking.py`: one family, one laptop, three accounts.

**Discuss:** the attacker read `population_sample.json`. Which fingerprint will they replay next?

---

## ☕ Break (10 min)

---

## Round 4: Noise ⚔️ Fuzzy clustering (30 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round4_noise_signup.py` (level 3) | 20/20: every `stable_id` is new |
| 🛡️ Defend | Read `defenses/fuzzy_cluster.py`, run it, then restart with `DEFENSE_LEVEL=4` | – |
| 🗡️ Re-run | `python attacks/round4_noise_signup.py` | 3/20, then `[L4] fingerprint_cluster: 3 accounts today from near-identical devices` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | rounds 1–4 stopped · 0/40 refused |

**False-positive check:** restart with `DEFENSE_LEVEL=4 LINK_MODE=naive` and run `python tools/legit_traffic.py`.

- Who gets refused now? About 10/40: identical iPhones, the office fleet together with lookalike Windows PCs, and a privacy-extension user.
- Why is fuzzy matching *more* dangerous to real users than exact matching?

**Exercises:**

1. `TODO (Round 4, attacker)` in `round4_noise_signup.py`: jitter the screen size as well. Does L4 still catch it?
2. `TODO (Round 4)` in `fuzzy_cluster.py`: weight the components instead of counting them, and re-run both the attack and `legit_traffic.py`.

---

## Wrap-up: false positives and cost (20 min)

```bash
python tools/legit_traffic.py               # per-cohort verdicts and reasons
curl -s localhost:5000/fp-dashboard | python -m json.tool
docker compose exec postgres psql -U workshop -d shop \
  -c "SELECT level, verdict, status, count(*) FROM signup GROUP BY 1, 2, 3 ORDER BY 1, 2, 3;"
```

- Which rules would you only ever use for `suspicious`, never for `bot`?
- The collector costs 120–300 ms in headless Chromium, and much more on a cold page with a real GPU. Where in the page lifecycle would you run it in production?
- The attacker's last move is to rotate **whole, coherent** fingerprints from a generator, or from a farm of real phones. Which signals are left?
  - **TLS and HTTP/2:** a "Windows Chrome" fingerprint arrives over Linux Python's TLS stack. That is W2 Ch5.
  - **Device binding and step-up on login:** W2 Ch6.
  - **Combining weak signals:** W2 Ch7.
  - **Making the collector itself hard to replay:** W2 Ch2.

---

## Instructor: expected results

Verified with Playwright 1.63 (Chromium 153), Python 3.10, and the SQLite fallback. Numbers are accounts created out of 20 sign-ups (the scripts' default; the checkpoint uses 10). Each attack starts from an empty store.

| Attack ↓ / `DEFENSE_LEVEL` → | 0 | 1 | 2 | 3 | 4 | Reason at the first stop |
|---|---|---|---|---|---|---|
| `round1_headless_signup` | 20 | **0** | 0 | 0 | 0 | `[L1] SwiftShader WebGL renderer` (40) |
| `round2_patched_signup` | 20 | 20 | **0** | 0 | 0 | `[L2]` worker 40 + texture limits 20 + brands 30 = 90 |
| `round3_replay_signup` | 20 | 20 | 20 | **3** | 3 | `[L3] fingerprint_linked` (40; 80 at L4) |
| `round4_noise_signup` | 20 | 20 | 20 | 20 | **3** | `[L4] fingerprint_cluster` (40) |
| Real users refused (`legit_traffic.py`) | 0/40 | 0/40 | 0/40 | 0/40 | 0/40 | 2 privacy-extension users `suspicious` (25) from L2 |
| … with `LINK_MODE=naive` | | | | 2/40 | 10/40 | Identical MacBooks, office fleet, iPhones, a privacy extension |

Defender cost measured on the instructor laptop:

| Item | Cost |
|---|---|
| Collector | 120–300 ms in headless Chromium, about 2 s on a cold headed Chromium with a GPU; 3.9 KB payload |
| Scoring at level 4 | median 0.8 ms |
| Linking queries at level 4 | median 3.6 ms, p95 10 ms, on SQLite with a few dozen accounts |

Things to watch for:

- **Version drift.** When Chrome or Playwright updates, re-run every checkpoint. Then check `round0_recon.py`:
  - Does headless still report SwiftShader? (Chrome dropped the automatic SwiftShader fallback in 139. Playwright enables it explicitly.)
  - Is `MAX_TEXTURE_SIZE` still 8192?
- **Synthesized profiles.** Every shipped real-user profile is marked `synthesized`. They are built from real Chromium and Firefox captures plus each browser's documented behaviour, *not* captured on those exact devices. Ask students on Safari, Brave and phones to add their captures in Round 0, and treat any refusal of a captured profile as a bug in the defense.
- **PostgreSQL.** The lab was verified on the SQLite fallback. The queries are plain SQLAlchemy, but run one full checkpoint on PostgreSQL before teaching.

---

## Bonus challenges

1. **Coherent generator.** Install BrowserForge (`pip install browserforge`, Apache-2.0), a Python port of Apify's fingerprint-suite. Generate a different, internally consistent Windows/Chrome fingerprint for every sign-up and map it onto our payload format. How many accounts does it get at level 4? Which components would you still trust?
2. **FingerprintJS 5 (MIT).** Load the open-source FingerprintJS next to our collector and compare its `visitorId` with our `fp_id` across reloads, private windows and privacy browsers. Why should the server still recompute the ID from components?
3. **Headers meet fingerprints.** Combine this lab's `lie_detector` with W1 Ch4's header scoring. Which Round 3 shortcut (replaying the payload from `httpx` instead of a browser) does that close?
