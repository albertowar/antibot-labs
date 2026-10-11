# Chapter 6 Lab: Price the Puzzle

**Format:** Round 0 plus 4 rounds of attack ⚔️ defend, 77 min, then a 10-minute debrief. See `../chapter_06_content.md`, §6.6.

You play both sides. Each round, an attack script beats the store's current CAPTCHA setup. You fix one defense module (`TODO (Round N)` markers), and the checkpoint measures what the fix stops **and what it costs 40 simulated shoppers**.

> ⚠️ Run these scripts only against the local demo store, or other systems you own. Every attack script refuses non-`localhost` targets. Nothing in this lab contacts a real CAPTCHA provider or solving service.

```
lab/
  labkit.py                 shared settings: URLs, simulated time and IPs, ethics guard
  demo_site/app.py          the Chapter 5 store + CAPTCHAs; DEFENSE_LEVEL 0–4
  provider/mock_turnstile.py  offline provider with a Turnstile-compatible API (:5001)
  defenses/                 YOU EDIT THESE
    siteverify.py             Round 1: server-side token verification
    challenge_store.py        Round 2: where the answer lives
    captcha_generator.py      Round 3: the image (basic + your hardened style)
    solver_signals.py         Round 4: solve signals + serve on risk
  attacks/
    round0_mass_register.py   round1_bypass.py   round2_cookie_replay.py
    round3_ocr.py             round4_retry_ocr.py  round4_solver_farm.py
    ocr_solver.py             the targeted solver (segmentation + k-NN)
    farm.py                   a simulated human solving service
    common.py                 bot plumbing (Chrome UA, cookies, proxy IPs)
  solutions/roundN/         reference defenses, installed by --catch-up
  tools/
    checkpoint.py             end-of-round measurement (bots, humans, cost)
    legit_traffic.py          40 simulated shoppers
    scoreboard.py             solve-time histogram by actor (Round 4)
    fake_redis.py             no-Docker Redis
    reset.py                  clear Redis + provider state
```

**Why Python only:** everything in this chapter is server-side or an HTTP client: Flask, Redis, Pillow, scikit-learn. The browser widget is 20 lines of inline JavaScript in the mock provider. Students never edit it.

---

## Setup (before the session, < 10 min)

```bash
cd workshops/01-initiation/chapters/06-captchas-and-captcha-solving/lab
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

docker compose up -d --wait          # Redis 8 on 127.0.0.1:6379
#   no Docker?  python tools/fake_redis.py    (in its own terminal)
```

Then, in **three terminals** (each with the venv active):

```bash
python provider/mock_turnstile.py            # terminal 1: mock CAPTCHA provider on :5001
DEFENSE_LEVEL=0 python demo_site/app.py      # terminal 2: the store on :5000 (restart per round)
python tools/checkpoint.py 0                 # terminal 3: attacks + measurements
```

Open http://localhost:5000 in a browser: the store, the newsletter form, `/register` and `/promo` all work by hand.

| `DEFENSE_LEVEL` | Adds | You edit |
|---|---|---|
| 0 | nothing | — |
| 1 | provider token required on `/register` | `defenses/siteverify.py` |
| 2 | + image CAPTCHA on `/promo/redeem` | `defenses/challenge_store.py` |
| 3 | + the hardened generator style | `defenses/captcha_generator.py` |
| 4 | + solver signals and serve-on-risk | `defenses/solver_signals.py` |

The store runs with Flask's reloader: **saving a file under `defenses/` restarts it**. Changing `DEFENSE_LEVEL` needs a manual restart (Ctrl+C, then run again).

### Lab-only shortcuts (never ship these)

- **Simulated time:** `LAB_TIME_SCALE=5`, so one real second counts as five. A 40 s farm solve takes 8 s, and the 40-shopper simulation runs in about 5 s. Every threshold in `solver_signals.py` is in simulated seconds.
- **Simulated IPs:** the store trusts `X-Lab-Client-IP` from 127.0.0.1 only, standing in for the Chapter 3 edge proxy. Humans come from 198.51.100.0/24, bots from 203.0.113.0/24, farm workers from 192.0.2.0/24 (RFC 5737 documentation ranges).
- **Simulated eyes:** every challenge's answer is also written to `lab:eyes:<id>` in Redis, so simulated humans and the simulated farm can "read" the image the way a person would. Bot scripts (other than the farm) never read it.
- **Actor labels:** `X-Lab-Actor` (human/bot/farm) only colours the scoreboard. Defenses must never read it.
- **Verbose 403s:** the store tells the client which rule fired. In production that is a free oracle for the attacker.

### Troubleshooting

| Problem | Fix |
|---|---|
| Port 5000 busy (macOS AirPlay Receiver) | `PORT=5050 DEFENSE_LEVEL=0 python demo_site/app.py` and `export DEMO_URL=http://localhost:5050` in the other terminals |
| `ConnectionError` to Redis | Start Redis (`docker compose up -d --wait`) or `python tools/fake_redis.py` |
| No Docker | `python tools/fake_redis.py`. It is slower than real Redis (p95 check latency is higher), but the results are the same |
| Checkpoint says "Mock provider not reachable" | `python provider/mock_turnstile.py` in its own terminal |
| `Connection reset` in the middle of a checkpoint | You saved a defense file while it ran, and the reloader restarted the store. Run it again |
| Checkpoint says the store did not reload after `--catch-up` | Restart the store by hand, then re-run the checkpoint |
| Stale results | `python tools/reset.py` (the checkpoint resets state itself) |

---

## How to measure a round

```bash
python tools/checkpoint.py 3
```

```
=== Checkpoint: Round 3 (DEFENSE_LEVEL=3, generator=hardened) ===

Bot traffic
  ✅ round0_mass_register    0/20  succeeded  (expected: blocked)
  ✅ round1_bypass           0/20  succeeded  (expected: blocked)
  ✅ round2_cookie_replay    0/20  succeeded  (expected: blocked)
  ✅ round3_ocr              3/20  succeeded  (expected: ≤25% succeed)

Real users (40 simulated shoppers)
  completed 38/40 · challenged 40/40 · 43 CAPTCHAs shown · median journey 24 s
  ⚠️  user 15 lost: inaccessible: image-only CAPTCHA
  ⚠️  user 33 lost: inaccessible: image-only CAPTCHA

Defender cost (per request)
  captcha_check  median   2.50 ms · p95 293.33 ms
  captcha_gen    median 143.65 ms · p95 259.06 ms
  siteverify     median  13.37 ms · p95  57.30 ms

✅ Round 3 checkpoint passed.
```

It checks the store's `DEFENSE_LEVEL`, resets Redis and the provider, and then reports:
- every attack introduced so far against its expected result;
- the 40 shoppers: completed, challenged and lost, with the reason for each loss;
- defender cost from `Server-Timing`.

A shopper lost to a CAPTCHA is a ⚠️ cost, not a failure. A shopper who can't *register* fails the checkpoint.

**Fell behind?** `python tools/checkpoint.py N --catch-up` installs the reference solutions for rounds 1..N into `defenses/`, waits for the store to reload, and then runs the checkpoint. Your own files are backed up to `defenses/_backup/<timestamp>/`.

---

## Round 0: Baseline (5 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round0_mass_register.py` | `20/20` accounts in well under a second |
| 👥 Humans | `python tools/legit_traffic.py` | `completed 40/40 · challenged 0/40` |
| ✅ Checkpoint | `python tools/checkpoint.py 0` | passes |

**Write the scoreboard row:** bots 20/20, humans 40/40, challenged 0/40. Every later round is compared with it.

---

## Round 1: Naive verifier ⚔️ integration bypass (20 min)

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | Restart with `DEFENSE_LEVEL=1`. Sign up by hand at `/register` and watch the widget | form works |
| 🗡️ Attack | `python attacks/round0_mass_register.py` | still `20/20`: a missing token is "fine" |
| 🗡️ Attack | `python attacks/round1_bypass.py` | `20/20` via `missing`, `newsletter`, `laundered`, `outage` |
| 🛡️ Defend | Fix the five `TODO (Round 1)` in `defenses/siteverify.py`. Test with `python defenses/siteverify.py` | 1 accept, 3 rejects |
| 🗡️ Re-run | `python attacks/round1_bypass.py` | `0/20`, with a distinct reason per technique |
| ✅ Checkpoint | `python tools/checkpoint.py 1` | 0/20 · 40/40 shoppers · siteverify ~20 ms median |

**Rules of engagement:**
- A bot may mint tokens for non-interactive actions (`newsletter`), and for other hostnames (laundering through visitors to the attacker's page).
- An interactive token for *your* hostname costs money: it only comes from `attacks/farm.py`. The mock can't tell people from programs, so this rule stands in for the provider's risk engine.

**Discuss:** with all four bypasses closed, what does an attacker now have to buy? (A farm-solved token per account, about $2 per 1,000.) For a fake account worth $0.10, did the CAPTCHA change the economics?

---

## Round 2: Answer in a cookie ⚔️ server-side state (15 min)

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | Restart with `DEFENSE_LEVEL=2`. Try `/promo` in the browser | image CAPTCHA |
| 🗡️ Attack | `python attacks/round2_cookie_replay.py` | prints the cookie payload with the answer · `20/20` vouchers from one challenge |
| 🛡️ Defend | Fix the `TODO (Round 2)` in `defenses/challenge_store.py`. Test with `python defenses/challenge_store.py` | correct / used / other session |
| 🗡️ Re-run | `python attacks/round2_cookie_replay.py` | `0/20`: "no answer in any cookie" |
| ✅ Checkpoint | `python tools/checkpoint.py 2` | 0/20 · **38/40** shoppers |

**False-positive check:** the two screen-reader users (15 and 33) are lost the moment every redemption needs an image CAPTCHA. This lab has no audio or alternative path. Leave it for now; Round 4 comes back to it.

---

## ☕ Break (10 min)

---

## Round 3: Targeted solver ⚔️ hardened generator (20 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round3_ocr.py` (still at level 2) | trains in ~3–5 s · `20/20` (100%) |
| 🔍 Read | `attacks/ocr_solver.py`: binarize → segment → classify | list the assumptions |
| 🛡️ Defend | Restart with `DEFENSE_LEVEL=3`. Implement `generate_hardened()` and `text_length()`. Look at the samples: `python defenses/captcha_generator.py` | you can still read them |
| 🗡️ Re-run | `python attacks/round3_ocr.py` | `1–3/20` (5–15%) |
| ✅ Checkpoint | `python tools/checkpoint.py 3` | ≤25% · 38/40 shoppers, more CAPTCHAs shown |

**Optional:** `pip install pytesseract`, install the `tesseract` binary, then `python attacks/round3_ocr.py --tesseract`. A generic engine with no knowledge of your generator is a weak baseline. Real attackers on a self-hosted CAPTCHA write a targeted solver.

**Discuss:** did hardening hurt the solver or your readers more? Would a segmentation-free CNN care about touching glyphs?

---

## Round 4: Retry bot + solving farm ⚔️ solver signals (17 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round4_retry_ocr.py` (level 3) | `10/10` vouchers after ~50–100 challenges |
| 🗡️ Attack | `python attacks/round4_solver_farm.py` | `10/10` · ~$0.01 spent |
| 📊 Look | `python tools/legit_traffic.py`, then `python tools/scoreboard.py` | humans 3–15 s, bot < 1 s, farm 10–40 s |
| 🛡️ Defend | Restart with `DEFENSE_LEVEL=4`. Fix the `TODO (Round 4)` in `defenses/solver_signals.py` | — |
| 🗡️ Re-run | both Round 4 attacks | `0/10` and `0/10` |
| ✅ Checkpoint | `python tools/checkpoint.py 4` | **40/40 shoppers · 4/40 challenged** |

**Residual:** `python attacks/round4_solver_farm.py --sticky-ip` gets `10/10` again for ~$0.01. With one proxy per voucher there is no IP mismatch, and the farm's 10–40 s band alone is too weak to block on (slow humans live there too). That is the end of what a CAPTCHA can do. It has priced a $10 voucher at a tenth of a cent plus half a minute. The fix is a business rule (one voucher per verified account) and identity signals (W2 Ch6), not a harder puzzle.

---

## Debrief: scoreboard, false positives and cost (10 min)

Fill in the room's scoreboard:

| Round | Bots succeeded | Attacker cost | Shoppers completed | Shoppers challenged | Defender cost (p95) |
|---|---|---|---|---|---|
| 0 | 20/20 | $0 | 40/40 | 0/40 | — |
| 1 | 0/20 | needs a farm | 40/40 | 0/40 | siteverify |
| 2 | 0/20 | needs a solver | 38/40 | 40/40 | + generation, check |
| 3 | 1–3/20 | retries | 38/40 | 40/40 | hardened generation |
| 4 | 0/10, 0/10 | sticky farm: $0.01 / 10 | 40/40 | 4/40 | signals ~free |

Then use the discussion questions in the content doc (§6.6).

---

## Instructor: expected results

Measured on Python 3.10.12 (Linux, WSL2) with fakeredis 2.39 standing in for Redis, `LAB_TIME_SCALE=5`, and the reference solutions. **Before** means the shipped student files; **after** means the reference solutions (what `--catch-up` installs). Numbers vary slightly between runs (OCR accuracy, retries, timings); the ranges come from repeated runs.

| Attack ↓ / state → | L0 | L1 before | L1 after | L2 before | L2 after | L3 before | L3 after | L4 before | L4 after |
|---|---|---|---|---|---|---|---|---|---|
| `round0_mass_register` (20) | 20 | 20 | **0** | 0 | 0 | 0 | 0 | 0 | 0 |
| `round1_bypass` (20) | — | 20 | **0** | 0 | 0 | 0 | 0 | 0 | 0 |
| `round2_cookie_replay` (20) | — | 20 (no CAPTCHA) | 20 (no CAPTCHA) | 20 | **0** | 0 | 0 | 0 | 0 |
| `round3_ocr` (20) | — | — | — | — | 20 | 19–20 (stub = basic) | **1–3** | 4 | **0** |
| `round4_retry_ocr` (goal 10) | — | — | — | — | — | — | 10 (50–97 tries) | 10 (61–85 tries) | **0** (300 tries) |
| `round4_solver_farm` (goal 10) | — | — | — | — | — | — | 10, $0.011 | 10, $0.010 | **0**, $0.030 |
| `round4_solver_farm --sticky-ip` | — | — | — | — | — | — | — | — | 10, $0.010–0.012 (residual) |
| Shoppers completed / 40 | 40 | 40 | 40 | 38 | 38 | 37 | 38 | 36–37 | **40** |
| Shoppers challenged / 40 | 0 | 0 | 0 | 40 | 40 | 40 | 40 | 40 | **4** |

**Defender cost (median / p95, 40 concurrent shoppers on the Flask dev server):**
- siteverify: 13–23 ms / 44–100 ms against the local mock. Before switching to a pooled client it was 146 ms / 365 ms: a fresh client per call builds a TLS context.
- captcha_gen: basic 77–112 ms / 150–190 ms, hardened 13–150 ms / 130–260 ms. Under load this is mostly GIL contention; unloaded it is 8 ms (basic) and 17 ms (hardened).
- captcha_check: 1–7 ms median. The p95 is up to 300 ms with fakeredis and much lower with real Redis.

**Things to watch for:**
- **Run-to-run variance:** solver accuracy on the hardened style is 5–20% per attempt. If a room's hardened style is much weaker than the reference (say >25%), the Round 3 checkpoint fails. Show them the solver's assumptions again.
- **Student thresholds:** if students set `FAST_SOLVE_SIM_S` above ~3 s, the checkpoint flags real users. That's the lesson, so let it fail once.
- **Slow laptops:** the bot's solve time is real compute × `LAB_TIME_SCALE`. If OCR takes more than ~300 ms per image on a student machine, its "solve time" approaches the 2 s floor. Use `LAB_TIME_SCALE=3` everywhere on that machine.
- **Chrome version** in `attacks/common.py` and the simulator's UAs: update the major version each quarter.
- **Cloudflare dummy keys:** re-check them in Cloudflare's Turnstile testing docs the week you teach, if you run Bonus 3.

### Instructor prep checklist

- [ ] `pip install -r requirements.txt` on the lab image; `docker compose up -d --wait` (or `fake_redis.py`)
- [ ] Run `tools/checkpoint.py 0..4 --catch-up` once end to end (about 2 minutes), then `git checkout defenses/` to restore the student files
- [ ] Shared scoreboard (whiteboard or doc) ready for the debrief
- [ ] Optional: Tesseract installed on one machine for the generic-OCR comparison

---

## Bonus challenges

1. **Segmentation-free solver (take-home):** train a small CNN on 5,000 hardened samples and re-run Round 3. How long did your hardening last?
2. **Real provider, dummy keys:** set `SITEVERIFY_URL=https://challenges.cloudflare.com/turnstile/v0/siteverify` and `CAPTCHA_SECRET=1x0000000000000000000000000000000AA`, and use Cloudflare's widget with sitekey `1x00000000000000000000AA`. Which of your Round 1 checks still make sense with fixed dummy responses?
3. **Accessible path:** give screen-reader users a proof-of-work fallback (ALTCHA or Cap) instead of the image. What is that path's abuse cost? This previews Chapter 7.
4. **Evade your own Round 4:** make the retry bot visit `/`, wait 3 s and sleep before submitting. Which signals are left, and what did evasion cost it per voucher?
