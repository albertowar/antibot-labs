# Chapter 6 Lab: Price the Puzzle

Starts from: workshops/01-initiation/starter/ (contract 1.5). Adds: the `captcha` challenge type and widget templates, the Turnstile-style siteverify check, the self-hosted image CAPTCHA and its challenge store, the solver signals, the local mock provider, eight attack scripts (bypass, replay, OCR, farm) and the Chapter 6 shoppers.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/captcha_gate.py`
- `defenses/captcha_generator.py`
- `defenses/challenge_store.py`
- `defenses/siteverify.py`
- `defenses/solver_signals.py`
- `defenses/turnstile_check.py`
- `demo_site/ext/captcha.py`
- `demo_site/ext/templates/captcha/interstitial.html`
- `demo_site/ext/templates/captcha/promo.html`
- `demo_site/ext/templates/captcha/widget_footer.html`
- `demo_site/ext/templates/captcha/widget_register.html`
- `demo_site/static/js/captcha.js`
- `tools/captcha_kit.py`
- `tools/personas_ch6.py`
- `tools/solve_times.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** **wire-it.** Round 0 plus 4 rounds of attack ⚔️ defend, then a debrief. Each round's defense ships
as a stub with `TODO (Round N)` markers and a full version in `solutions/roundN/`;
`python tools/checkpoint.py --round N --catch-up` installs them if you fall behind. See `../chapter_06_content.md`, §6.6.

You play both sides. Each round, an attack script beats the store's current CAPTCHA setup. You fix one defense module (the `TODO (Round N)` markers), and the checkpoint measures what the fix stops **and what it costs 40 simulated shoppers**.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses any target that is not this machine before a single request is sent (side-service URLs such as `PROVIDER_URL` and `REDIS_URL` too). Do not remove that check.
- The CAPTCHA provider is the local mock in `provider/mock_turnstile.py`. Nothing in this lab contacts a real CAPTCHA provider or solving service; the "farm" is simulated people.
- Everything is synthetic. Simulated client addresses are rented from the pools in `data/world.json` (documentation ranges, IPv4 and IPv6), never invented, never real, and sent in `X-Lab-Client-IP`, which the store trusts only from loopback.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  labnet.py                 the localhost guard (byte-identical to scripts/labnet.py)
  demo_site/                the starter store + ext/captcha.py: the widget slots, the promo and the challenge type
  provider/mock_turnstile.py  offline provider with a Turnstile-compatible API (the store starts it itself)
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
  solutions/roundN/         reference defenses, installed by --catch-up
  tools/
    checkpoint.py             end-of-round measurement (bots, shoppers, cost)
    population.py             the 40 simulated shoppers (+ personas_ch6.py: this chapter's cast)
    scoreboard.py             served and stopped per actor, gate cost
    solve_times.py            solve-time histogram by actor (Round 4)
    labclient.py              every attack's HTTP client; runs the labnet guard on import
```

**Why Python only:** everything in this chapter is server-side or an HTTP client: Flask, Redis, Pillow, scikit-learn. The browser widget is a small piece of inline JavaScript served by the mock provider. Students never edit it.

---

## Setup (< 10 min)

```bash
cd workshops/01-initiation/chapters/06-captchas-and-captcha-solving/lab
python3.12 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate; one venv per chapter
pip install -r requirements.txt
python tools/doctor.py
```

One venv per chapter (`.venv` here); the root README explains why. No Docker needed: the store defaults to
`REDIS_URL=memory://` (in-process fakeredis). `docker compose up -d --wait` runs a real Redis instead
(`export REDIS_URL=redis://127.0.0.1:6379/0`).

Then start the store once and leave it running:

```bash
python demo_site/app.py        # 127.0.0.1:5000; starts the mock CAPTCHA provider on a thread (:5001)
```

Open http://localhost:5000 in a browser: the store, the newsletter form, `/register` and `/promo/` all work by hand.

**You never restart the store.** The checkpoint sets `DEFENSE_LEVEL` over `POST /lab/level`, and the store
re-reads your edits under `defenses/` on the next request (`LAB_RELOAD=1`, the default). Set a level by hand with:

```bash
curl -X POST localhost:5000/lab/level -H 'content-type: application/json' -d '{"level": 2}'
```

| Level | Adds | You edit |
|---|---|---|
| 0 | nothing | — |
| 1 | provider token required on `/register` | `defenses/siteverify.py` |
| 2 | + image CAPTCHA on `/promo/redeem` | `defenses/challenge_store.py` |
| 3 | + the hardened generator style | `defenses/captcha_generator.py` |
| 4 | + solver signals and serve-on-risk | `defenses/solver_signals.py` |

### Lab-only shortcuts (never ship these)

- **Simulated time:** `LAB_TIME_SCALE=5`, so one real second counts as five. A 40 s farm solve takes 8 s, and the 40-shopper simulation runs in seconds. Every threshold in `solver_signals.py` is in simulated seconds.
- **Simulated IPs:** actors rent addresses from the pools in `data/world.json` and send them in `X-Lab-Client-IP`, standing in for the Chapter 3 edge. Shoppers come from the home and mobile pools, bots from `cloud_vm`, farm workers from `home_broadband`, the rotating farm from `residential_proxy`.
- **Simulated eyes:** every challenge's answer is also written to `lab:eyes:<id>` in Redis, so simulated humans and the simulated farm can "read" the image the way a person would (`/lab/captcha/eyes/<id>`). Bot scripts (other than the farm) never read it.
- **Actor labels:** `X-Lab-Actor` (human/bot/farm) only colours the scoreboard. Defenses must never read it.
- **Verbose 403s:** the store tells the client which rule fired. In production that is a free oracle for the attacker.

### Troubleshooting

| Problem | Fix |
|---|---|
| Port 5000 busy (macOS AirPlay Receiver) | `PORT=5050 python demo_site/app.py` and `export DEMO_URL=http://localhost:5050` in the attack terminal |
| `Store not reachable on http://127.0.0.1:5000` | Start it: `python demo_site/app.py` |
| Want the provider in its own terminal | `python provider/mock_turnstile.py`, then start the store with `PROVIDER_AUTOSTART=0` |
| `ConnectionError` to Redis | You set `REDIS_URL` to a server that is not running. Start it (`docker compose up -d --wait`) or unset it (`memory://`) |
| Checkpoint FAILs with "store is at level X, expected N" | Let the checkpoint set the level (`--round N`), or set it by hand with the `curl` above |
| Stale results | `python tools/reset.py` (the checkpoint resets state itself) |

---

## How to measure a round

```bash
python tools/checkpoint.py --round N              # set level N, run the round's attacks next to the shoppers
python tools/checkpoint.py --round N --level N-1  # the same attacks against the previous level: the "before"
python tools/checkpoint.py --round N --catch-up   # install solutions/round1..N first
python tools/checkpoint.py --restore              # put your own files back (the .bak copies)
```

The checkpoint sets the level, resets the store and the provider, runs the round's attacks while the 40
shoppers sign up and claim the voucher, and prints:

- **The scoreboard**: requests served and stopped per actor, and the gate's cost per request (`Server-Timing` on every response has the per-check split).
- **The shoppers**: per persona, who signed up, who met a CAPTCHA and who was lost, with the reason for each loss. The two screen-reader users, the no-JavaScript visitor, the deep-linkers and the Wi-Fi → cellular hopper are named because a CAPTCHA's false positives are exactly those people.
- **The attacks**: accounts or vouchers obtained out of the attempts (and dollars spent on the farm), against the round's expectation.
- **Defender cost**: siteverify, image generation and answer checking in milliseconds, from the decision log.
- **PASS or FAIL** against the round's expectations in `tools/checkpoint.py`, including which personas the round is *allowed* to hurt (`allowed_fp`). That list is the price of the layer.

```
== Round 3: hardened images: the targeted solver drops from ~100% to a few percent (level 3)
...
Bots stopped: 21/102 requests · shoppers hurt: 3/40 people

attacks:
  cookie_replay    0% succeeded
  ocr              5% succeeded

  lost: human:screen_reader:00       image-only CAPTCHA, no audio or alternative path
  lost: human:screen_reader:01       image-only CAPTCHA, no audio or alternative path
  lost: human:no_js:00               no JavaScript: no widget, no token

defender cost (ms)         n   median      p95
gate (all requests)      374     4.09    26.62
siteverify                40     5.94    16.96
image generation          62    14.67    36.56
answer check              79     0.59     1.71

Round 3 at level 3: PASS
```

A shopper lost to a CAPTCHA is a cost the round owns up to (`allowed_fp`), not a silent pass. A shopper
who is hurt outside that list fails the checkpoint.

`tools/verify.py` runs the same thing with its own in-process store on a free port (used for the table below).

---

## Round 0: Baseline

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round0_mass_register.py` | `20/20` accounts in well under a second |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | PASS: bots 20/20 served · shoppers 40/40, 0 challenged |

**Write the scoreboard row:** bots 20/20, shoppers 40/40, challenged 0/40. Every later round is compared with it.

---

## Round 1: Naive verifier ⚔️ integration bypass

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | `python tools/checkpoint.py --round 1` sets level 1. Sign up by hand at `/register` and watch the widget | the form works; the checkpoint FAILs on the shipped verifier |
| 🗡️ Attack | `python attacks/round0_mass_register.py` | still `20/20`: a missing token is "fine" |
| 🗡️ Attack | `python attacks/round1_bypass.py` | `20/20` via `missing`, `newsletter`, `laundered`, `outage` |
| 🛡️ Defend | Fix the five `TODO (Round 1)` in `defenses/siteverify.py`. Test with `python defenses/siteverify.py` | 1 accept, 3 rejects |
| 🗡️ Re-run | `python attacks/round1_bypass.py` | `0/20`, with a distinct reason per technique |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | PASS: 0/20 · 39/40 shoppers · siteverify a few ms median |

**Rules of engagement:**
- A bot may mint tokens for non-interactive actions (`newsletter`), and for other hostnames (laundering through visitors to the attacker's page).
- An interactive token for *your* hostname costs money: it only comes from `attacks/farm.py`. The mock can't tell people from programs, so this rule stands in for the provider's risk engine.

**False-positive check:** the widget is JavaScript, so the no-JS visitor can't mint a token and is lost the moment the sign-up needs one. The round's `allowed_fp` names that persona; it stays lost for the rest of the lab.

**Discuss:** with all four bypasses closed, what does an attacker now have to buy? (A farm-solved token per account, about $2 per 1,000.) For a fake account worth $0.10, did the CAPTCHA change the economics?

---

## Round 2: Answer in a cookie ⚔️ server-side state

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | `python tools/checkpoint.py --round 2` sets level 2. Try `/promo/` in the browser | image CAPTCHA |
| 🗡️ Attack | `python attacks/round2_cookie_replay.py` | prints the cookie payload with the answer · `20/20` vouchers from one challenge |
| 🛡️ Defend | Fix the `TODO (Round 2)` in `defenses/challenge_store.py`. Test with `python defenses/challenge_store.py` | correct / used / other session |
| 🗡️ Re-run | `python attacks/round2_cookie_replay.py` | `0/20`: "no answer in any cookie" |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | PASS: 0/20 · **37/40** shoppers |

**False-positive check:** the two screen-reader users are lost the moment every redemption needs an image CAPTCHA. This lab has no audio or alternative path. Leave it for now; Round 4 comes back to it.

---

## Round 3: Targeted solver ⚔️ hardened generator

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round3_ocr.py` (still at level 2) | trains in a few seconds · `20/20` (100%) |
| 🔍 Read | `attacks/ocr_solver.py`: binarize → segment → classify | list the assumptions |
| 🛡️ Defend | `python tools/checkpoint.py --round 3` sets level 3 (the gate now draws the hardened style). Implement `generate_hardened()` and `text_length()`; look at the samples: `python defenses/captcha_generator.py` | you can still read them |
| 🗡️ Re-run | `python attacks/round3_ocr.py` | `1–3/20` (5–15%) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | PASS: ocr ≤35% · 37/40 shoppers, more CAPTCHAs shown |

**Optional:** `pip install pytesseract`, install the `tesseract` binary, then `python attacks/round3_ocr.py --tesseract`. A generic engine with no knowledge of your generator is a weak baseline. Real attackers on a self-hosted CAPTCHA write a targeted solver.

**Discuss:** did hardening hurt the solver or your readers more? Would a segmentation-free CNN care about touching glyphs?

---

## Round 4: Retry bot + solving farm ⚔️ solver signals

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round4_retry_ocr.py` (still at level 3) | `10/10` vouchers after ~50–100 challenges |
| 🗡️ Attack | `python attacks/round4_solver_farm.py` | `10/10` · ~$0.01 spent |
| 📊 Look | `python tools/solve_times.py` | humans 3–15 s, bot < 1 s, farm 10–40 s |
| 🛡️ Defend | `python tools/checkpoint.py --round 4` sets level 4. Fix the `TODO (Round 4)` in `defenses/solver_signals.py` | — |
| 🗡️ Re-run | both Round 4 attacks | `0/10` and `0/10` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | PASS: **39/40 shoppers · 8/40 challenged** · the screen readers are served again |

Serve-on-risk is the win hiding in the numbers: the CAPTCHA now appears only for risky sessions, so the two
screen-reader users (lost since Round 2) finish again, and the Wi-Fi → cellular hopper is stepped up once
(issuer ≠ submitter), solves it, and passes.

**Residual:** `python attacks/round4_solver_farm.py --sticky-ip` gets `10/10` again for ~$0.01. With one proxy per voucher there is no IP mismatch, and the farm's 10–40 s band alone is too weak to block on (slow humans live there too). That is the end of what a CAPTCHA can do. It has priced a $10 voucher at a tenth of a cent plus half a minute. The fix is a business rule (one voucher per verified account) and identity signals (W2 Ch6), not a harder puzzle.

---

## Debrief: scoreboard, false positives and cost

Fill in your scoreboard:

| Round | Bots succeeded | Attacker cost | Shoppers completed | Shoppers challenged | Defender cost (p95) |
|---|---|---|---|---|---|
| 0 | 20/20 | $0 | 40/40 | 0/40 | — |
| 1 | 0/20 | needs a farm | 39/40 | 0/40 | siteverify |
| 2 | 0/20 | needs a solver | 37/40 | 39/40 | + generation, check |
| 3 | 1–3/20 | retries | 37/40 | 39/40 | hardened generation |
| 4 | 0/10, 0/10 | sticky farm: $0.01 / 10 | 39/40 | 8/40 | signals ~free |

Then use the discussion questions in the content doc (§6.6).

---

## Expected results (self-check)

Measured October 2026 on Python 3.12 (Linux, WSL2) with the baseline pins (Flask 3.1, redis 8.1, fakeredis 2.39
on `memory://`, Pillow 12.3, numpy 2.5, scikit-learn 1.9) and `LAB_TIME_SCALE=5`. The `docker compose` path (Redis 8.10 / PostgreSQL 18.6) passes every round too (2026-10-17). **Before the fix** is the round run against its shipped stub (rounds 1..N−1
fixed): `python tools/verify.py --round N`. **After** is the reference solutions:
`python tools/verify.py --all --catch-up --markdown`, which regenerates this table's numbers; do not edit them
by hand. Numbers vary slightly between runs (OCR accuracy, retries, timings).

<!-- results:start -->
| Round | Attack | Before the fix (stub) | After (solution) | Shoppers hurt after |
|---|---|---|---|---|
| 1 | `register` | 20/20 accounts | 0/20 | `no_js` (39/40 finish): no JS, no token |
|  | `bypass` | 20/20 | 0/20 |  |
| 2 | `cookie_replay` | 20/20 vouchers from one challenge | 0/20 | + both `screen_reader` users (37/40 finish) |
| 3 | `ocr` | 20/20: the stub still draws the basic style | 1/20 (5%) | same 3/40 |
| 4 | `retry` | 10/10 (~50–100 tries) | 0/10 (gave up at 300) | back to `no_js` only (39/40 finish, 8/40 challenged) |
|  | `farm` | 10/10 · $0.01 | 0/10 · $0.03 |  |
|  | `farm_sticky` | 10/10 · $0.01 | **10/10 · $0.01 (the residual)** |  |
<!-- results:end -->

The "previous level" view (`--round N --level N-1`) reports without judging and tells the same story, with two
quirks worth knowing: Round 2 at level 1 nets the replay only 1/20, because with no CAPTCHA on the voucher the
one-per-session rule is the only thing left charging it; and Round 4 at level 3 prints FAIL because the two
screen-reader users are still being hurt there — which is exactly what Round 4 fixes.

**Defender cost (median / p95, from the decision log, 40 concurrent shoppers on the Flask dev server):**
- gate (all requests): 2–4 ms / 7–27 ms.
- siteverify: 3–7 ms / 17–21 ms against the in-process mock.
- image generation: 11–15 ms / 37–49 ms under load; unloaded it is ~8 ms (basic) and ~17 ms (hardened).
- answer check: 0.5–1 ms / 1–2 ms.

**Things to watch for:**
- **Run-to-run variance:** solver accuracy on the hardened style is 5–20% per attempt. If your hardened style is much weaker than the reference (say >35%), the Round 3 checkpoint fails. Re-read the solver's assumptions.
- **Your thresholds:** if you set `FAST_SOLVE_SIM_S` above ~3 s, the checkpoint flags real users. That's the lesson, so let it fail once.
- **Slow laptops:** the bot's solve time is real compute × `LAB_TIME_SCALE`. If OCR takes more than ~300 ms per image on your machine, its "solve time" approaches the 2 s floor. Use `LAB_TIME_SCALE=3` everywhere on that machine.
- **Chrome version** in `tools/captcha_kit.py` (`BOT_UA`) and the shoppers' UAs: update the major version each quarter.
- **Cloudflare dummy keys:** re-check them in Cloudflare's Turnstile testing docs before you run Bonus 2.

---

## Bonus challenges

1. **Segmentation-free solver (take-home):** train a small CNN on 5,000 hardened samples and re-run Round 3. How long did your hardening last?
2. **Real provider, dummy keys:** set `SITEVERIFY_URL=https://challenges.cloudflare.com/turnstile/v0/siteverify` and `CAPTCHA_SECRET=1x0000000000000000000000000000000AA`, and use Cloudflare's widget with sitekey `1x00000000000000000000AA`. Which of your Round 1 checks still make sense with fixed dummy responses?
3. **Accessible path:** give screen-reader users a proof-of-work fallback (ALTCHA or Cap) instead of the image. What is that path's abuse cost? This previews Chapter 7.
4. **Evade your own Round 4:** make the retry bot visit `/`, wait 3 s and sleep before submitting. Which signals are left, and what did evasion cost it per voucher?
