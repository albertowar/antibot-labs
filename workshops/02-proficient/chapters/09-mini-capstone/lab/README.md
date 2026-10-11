# Chapter 9 Mini-Capstone Lab: Stealth Browsers vs. the Stack

**Format:** 5 rounds of attack ⚔️ defend, ~110 min. See `../chapter_09_content.md`, §9.7.

A limited sneaker drop — **50 pairs of the "Lab Runner 9", one per account**. You are the scalper and the defender, round by round. Each round the attacker gets a better tool; you turn on the next layer of the Workshop 2 stack and measure two things: what it catches, and who it hurts.

Everything you built across W2 is here as one stack: automation flags (Ch1), JS challenges (Ch2), behavior (Ch3), fingerprinting (Ch4), TLS/JA4 (Ch5), account takeover (Ch6), an ML model (Ch7) and the layered risk engine (Ch8).

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- The accounts, credentials and "breach list" are synthetic. "Residential" egress IPs are a header claimed from a documentation range (RFC 5737); the lab never routes through a real proxy or a proxy list.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  docker-compose.yml   Redis 8.10 + PostgreSQL 18 (127.0.0.1 only)
  demo_site/           the store: app.py, the TLS+JA4 edge (edge.py, ja4.py), models, static JS
  defenses/            one module per layer; the risk engine fuses them
  attacks/             round0_naive … round4_stuffing, round4_token_farm
  solutions/           reference answers to each round's TODO (used by checkpoint --catch-up)
  tools/               doctor, seed, make_cert, legit_traffic, train_model, checkpoint, scoreboard
```

Why this stack: **Python** for the store, defenses and HTTP attackers; plain **JavaScript** (no build step) for the in-page collector and challenge, so setup stays under ten minutes; **Docker only** for Redis and PostgreSQL.

---

## Setup (before the session)

```bash
cd lab
docker compose up -d --wait                       # Redis + PostgreSQL on 127.0.0.1
python -m venv .venv && source .venv/bin/activate      # one venv per chapter, see the root README
pip install -r requirements.txt
playwright install chromium                        # Round 0/1/4 attacks
patchright install chromium                        # Round 1/4 (patched Chromium)
python -m camoufox fetch                           # Round 2/3 (anti-detect Firefox, ~160 MB)
python tools/make_cert.py                          # self-signed cert for the TLS edge
python tools/seed.py                               # accounts, past orders, combo list
python tools/doctor.py                             # confirm everything is in place
```

Start the store, and restart it with a new `DEFENSE_LEVEL` each round:

```bash
DEFENSE_LEVEL=0 python demo_site/app.py            # https://localhost:8443  (Ctrl-C to stop)
```

| Level | Adds | Modules | Beats |
|---|---|---|---|
| 0 | Headers, automation flags, TLS/JA4 consistency, per-egress rate limit | `request_checks`, `automation`, `tls_consistency` | naive scripts |
| 1 | Fingerprint coherence (software GPU, window, UA↔platform, Worker) | `fingerprint_coherence` | headless Patchright |
| 2 | Behavior & flow (pointer path, dwell, click origin) | `behavior_flow` | scripted Camoufox |
| 3 | Session + account model (sklearn) | `session_model` (`tools/train_model.py`) | humanized farm |
| 4 | Login token binding + per-cluster failure ratio + device step-up | `token_binding`, `login_risk` | credential stuffing |

Each level includes every level below it. `defenses/risk_engine.py` adds the points: **< 30 allow, 30–59 challenge, ≥ 60 block**. Layers above the current level run in **shadow mode** — their points are logged (`tools/scoreboard.py`) but don't act, so you can see what a layer *would* do before you turn it on.

> At `DEFENSE_LEVEL` 3 and 4 the store needs the trained model: run `python tools/train_model.py` once (it drives real browsers for a few minutes), then restart the store.

Debug endpoints, never gated: **`/whoami`** (how your current request scores, with its JA4) and **`/lab/capture`** (record your own browser as a legitimate-user profile — see Round 0).

> The blocked response lists the reasons it fired. That is for teaching only. In production, never tell a client which rule caught it.

**Ports and no-Docker options**

| Problem | Fix |
|---|---|
| Port 8443 in use | `PORT=8443` → pick another, e.g. `PORT=9443 DEFENSE_LEVEL=0 python demo_site/app.py`, then `export DEMO_URL=https://localhost:9443` in the shell you run attacks/tools from |
| No Docker | Run Redis and PostgreSQL yourself and set `REDIS_URL` / `DATABASE_URL`. SQLite also works: `export DATABASE_URL=sqlite:///$PWD/instance/shop.db` from `lab/`, in every terminal (use an absolute path: Flask resolves a relative one against a different `instance/` folder for the app and for `tools/seed.py`) |
| `connection refused` on 5432/6379 | `docker compose ps` — both must be `healthy` |
| Fresh slate | `python tools/seed.py` (also: `docker compose down -v && docker compose up -d --wait`) |

---

## How to measure a round

Finish every round with a **checkpoint**. It resets the drop, runs this round's attack and the 40 simulated customers, and reports both sides:

```bash
python tools/checkpoint.py --round <N>        # add --catch-up to apply the reference solution
```

```
=== Checkpoint: Round 1 (store at DEFENSE_LEVEL=1) ===

Bot traffic
  ✅ round1_patchright      0 pairs (stopped at level 1)
       - [L1] Software WebGL renderer: ANGLE (… SwiftShader …)
       - [L1] No window chrome: outer 1280x720 == inner 1280x720
       - [L1] Web Worker navigator differs from the page: platform
  attacker cost: 1.16 s wall per attempt (3.48 s total)

Legitimate users (40 simulated customers)
  ✅ 36/40 allowed, 4 challenged, 0 blocked, 0 errored
       ⚠️  challenged (friction): firefox-rfp, vdi-citrix

Defender cost: scoring median 10.3 ms, p95 19.6 ms per action

✅ Round 1 checkpoint passed.
```

A round **passes** when the attack is stopped at the level that should stop it **and** no legitimate customer is blocked. Challenged customers are friction, reported but not a failure. The 40 customers (`tools/personas.py`) are the people antibot defenses hurt in production — phone users, a screen-reader user, privacy browsers, a VDI session, 7 laptops behind one office IP, a brand-new customer — so watch that column as closely as the bot column.

**Fell behind?** Each round's fix is one `TODO (Round N)` in one defense file. `--catch-up` installs the reference solutions for rounds 1..N (keeping each of yours once as `.bak`); `python tools/checkpoint.py --restore` puts your files back. Then restart the store.

---

## Round 0: the naive fleet ⚔️ the end-of-Ch8 stack (15 min)

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | `DEFENSE_LEVEL=0 python demo_site/app.py` | the full L0 stack is on |
| 🧭 Recon | Open `https://localhost:8443/whoami` in your browser | see your JA4 and `tls_family` |
| 📸 Capture | Open `/lab/capture`, move around, click **Capture my profile**; save the JSON as `tools/profiles/mine.json` | you join the simulated customers |
| 🗡️ Attack | `python attacks/round0_naive.py` | `requests`, `curl_cffi` (no JS) and stock Playwright all blocked |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | bots 0/3 · 0 customers blocked |

**Discuss:** which layer caught each bot, and why `curl_cffi` — with a perfect Chrome JA4 — is still blocked (it never ran the page, so there's no telemetry).

## Round 1: headless Patchright ⚔️ fingerprint coherence (25 min)

Patchright removes the Ch1 automation tells (no `webdriver`, no `Runtime.enable` leak), so L0 lets it in. It is still a headless browser on a server.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | at L0: `python attacks/round1_patchright.py` | 3/3 pairs bought |
| 🛡️ Defend | edit the `TODO (Round 1)` in `defenses/fingerprint_coherence.py`, restart at `DEFENSE_LEVEL=1` | — |
| 🗡️ Re-run | `python attacks/round1_patchright.py` | 0/3 — software GPU, no window chrome, Worker navigator differs |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | bots 0/3 · 0 blocked · `vdi-citrix` & `firefox-rfp` challenged |

**Exercise:** the starter rule blocks the `vdi-citrix` user (real software rendering) outright. Tune the TODO so a software renderer *alone* only challenges, while a headless bot (software renderer **+** frameless window **+** Worker mismatch) still blocks. **Discuss:** is challenging the VDI user acceptable? Who signs off on that trade-off?

## Round 2: scripted Camoufox ⚔️ behavior & flow (20 min)

Camoufox spoofs the fingerprint natively, so every L1 check agrees. It still clicks Buy the instant the page loads.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | at L1: `python attacks/round2_camoufox.py` | 3/3 pairs bought |
| 🛡️ Defend | edit the `TODO (Round 2)` in `defenses/behavior_flow.py`, restart at `DEFENSE_LEVEL=2` | — |
| 🗡️ Re-run | `python attacks/round2_camoufox.py` | 0/3 — one move before the click, bought < 1 s after load |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | bots 0/3 · 0 blocked · `safari-ios` & `screen-reader` **not** flagged |

**Exercise:** the starter behavior rule flags the keyboard (screen-reader) and touch (iPhone) customers, who never move a mouse. Fix the TODO so the pointer-path checks apply only to sessions that actually use a pointer. **Discuss:** every accessibility exemption you add is a door the next bot will try — how do you keep it from becoming a free pass?

## ☕ Break (10 min)

## Round 3: humanized farm ⚔️ session & account model (25 min)

The scalper adds `humanize`, browses first, and dwells — beating L2. But one pair per account means one account per pair, so it bulk-registers fresh accounts that all ship to one reshipper.

| Step | Do | Expected |
|---|---|---|
| 🛠️ Train | at L1: `python tools/train_model.py` | model saved, 100% recall / 0% FPR on validation |
| 🗡️ Attack | at L2: `python attacks/round3_humanized_farm.py` | 3/3 pairs bought |
| 🛡️ Defend | edit the `TODO (Round 3)` in `defenses/session_model.py` (`pick_threshold`), retrain, restart at `DEFENSE_LEVEL=3` | — |
| 🗡️ Re-run | `python attacks/round3_humanized_farm.py` | 0/3 — `p(bot)` over threshold (fresh account, shared address) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | bots 0/3 · 0 blocked (the first-time buyer still gets through) |

**Exercise:** `pick_threshold` returns a flat 0.5. Make it return the lowest threshold whose false-positive rate on the validation humans is ≤ 1%. **Discuss:** the model learns *your lab's* bots. What happens the week the attacker changes tactics, and how would you notice?

## Round 4: credential stuffing ⚔️ token binding & login risk (22 min)

Fresh accounts are caught, so the farm pivots to aged accounts it doesn't own: a `curl_cffi` stuffer with a (synthetic) breach list over rotating egress.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | at L3: `python attacks/round4_stuffing.py` | ~10 takeovers (every reused password) |
| 🛡️ Defend | restart at `DEFENSE_LEVEL=4` | bare logins now need a page-minted token |
| 🗡️ Re-run | `python attacks/round4_stuffing.py` | 0 — `[L4] No valid login token` |
| 🗡️ Adapt | `python attacks/round4_stuffing.py --with-token` | the attacker reproduces the token in Python; with the starter rule, step-up **leaks** ~10 confirmations |
| 🛡️ Defend | edit the `TODO (Round 4)` in `defenses/login_risk.py`, restart | — |
| 🗡️ Re-run | `python attacks/round4_stuffing.py --with-token` | 0 confirmed — the fingerprint cluster is blocked after 5 failures |
| 💸 Cost | `python attacks/round4_token_farm.py` | a browser login costs ~5× a bare `curl_cffi` login |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | 0 confirmed · 0 blocked · `new-laptop` gets a device step-up |

**Exercise:** run `--with-token --rotate-fp` against the finished defense. It leaks confirmations again — a new fingerprint per attempt is a new cluster. **Discuss:** what would it take to count failures across clusters without blocking the office NAT? (That's device attestation — Workshop 3.)

## Wrap-up: the scoreboard (15 min)

```bash
python tools/scoreboard.py
```

Review it together: which layer caught the most, where the false positives landed (VDI, privacy browsers, the new-device customer), the attacker's cost per pair as it climbed each round, and what paid residential proxies, a CAPTCHA-solving service or a human click-farm would change. Then: W2 stops at "one machine, one stack." **Workshop 3** takes it to mobile, APIs and scale; **Workshop 4** to AI crawlers and agentic browsers.

---

## Instructor: expected results

Verified on 2026-10-11 with Python 3.12.15, Flask 3.1.3, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.1.4, redis-py 8.1.0 (served by fakeredis 2.39.0 over TCP, since no Redis server was installed), SQLite (no Docker; the `docker compose` path with Redis 8.10 and PostgreSQL 18 is verified separately), Playwright 1.62.0 / Patchright 1.63.0 (Chromium 153), Camoufox 0.5.8 (Firefox 156), curl_cffi 0.16.3, numpy 2.5.4 and scikit-learn 1.9.1. Each round ran with `--catch-up`; the model was retrained after the numpy/scikit-learn bump (threshold 0.5 at L1, 0.01 at L3). Pairs are out of 3 attacker sessions; "✅" means the round's checkpoint passes. Exact timings vary with hardware.

| Attack ↓ / `DEFENSE_LEVEL` → | 0 | 1 | 2 | 3 | 4 | First reason at the blocking level |
|---|---|---|---|---|---|---|
| `round0_naive` (3 bots) | **0 bought** | 0 | 0 | 0 | 0 | `[L0]` UA red flag / no telemetry / HeadlessChrome |
| `round1_patchright` | 3 bought | **0** | 0 | 0 | 0 | `[L1]` software GPU + no window chrome + Worker mismatch |
| `round2_camoufox` | 3 | 3 | **0** | 0 | 0 | `[L2]` 1 move before click, bought < 1000 ms |
| `round3_humanized_farm` | 3 | 3 | 3 | **0** | 0 | `[L3]` session model p(bot) ≈ 1.00 (fresh account, shared address) |
| `round4_stuffing` (default) | 10 taken | 10 | 10 | 10 | **0** | `[L4]` no valid login token |
| `round4_stuffing --with-token` (starter `login_risk`) | — | — | — | — | 10 confirmed | step-up reveals valid credentials |
| `round4_stuffing --with-token` (TODO done) | — | — | — | — | **0 confirmed** | `[L4]` cluster failing 5/5 ≥ 50% |
| `round4_stuffing --with-token --rotate-fp` (TODO done) | — | — | — | — | 10 confirmed | a new fingerprint per attempt = new cluster (W3 hand-off) |
| Legitimate users (`legit_traffic.py`, 40) | 0 blocked | 0 | 0 | 0 | 0 | — |

Legitimate-user friction (challenged, never blocked): `vdi-citrix` and `firefox-rfp` from L1 (software/generic WebGL), plus `new-laptop` from L4 (device step-up). The `first-timer` and `power-user` customers pass every level. Defender cost: scoring median ≈ 10 ms at L1, ≈ 24 ms at L3–4 (the model), p95 under ~90 ms.

Attacker cost per successful attempt climbs across rounds: `curl_cffi` ≈ 0.05–0.15 s, a Patchright browser ≈ 1 s, a fresh Camoufox launch ≈ 10–25 s. The point of Round 4 is that token binding forces the stuffer off 0.15 s HTTP logins and back onto ~1 s browser logins — and the per-cluster ratio then blocks them anyway.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `No TLS certificate` on startup | `python tools/make_cert.py` |
| Browser warns about the certificate | expected (self-signed): click Advanced → Proceed. Attack scripts skip verification for localhost only |
| Checkpoint says `DEFENSE_LEVEL=X expected` | restart the store at that level |
| Round 3/4: `model isn't loaded` | `python tools/train_model.py`, then restart the store |
| `camoufox fetch` fails on a GitHub rate limit | wait a few minutes, or set `GITHUB_TOKEN`; it reads the public releases API |
| Camoufox attacks are slow | each launch builds a fresh device fingerprint; 10–25 s per session is normal |
| Headless browsers won't start on a server | install the system libs Playwright lists, or run under `xvfb-run` |

## Bonus challenges

1. **Capture yourself.** Add `tools/profiles/mine.json` from `/lab/capture` and confirm you sail through every round. Now hand your JSON to the Round 3 farm as a replayed fingerprint — why doesn't one real fingerprint across 50 accounts help the scalper?
2. **Shadow before you ship.** Use `tools/scoreboard.py` to read the shadow scores of a layer before enabling it. Pick the weights so the VDI user is never blocked at any level.
3. **Move the goalposts.** The drop sells 50 pairs. Lower `MAX_FAILURE_RATIO` in `login_risk.py` until a legitimate office-NAT user who fat-fingers their password twice gets caught. Where's the line?
