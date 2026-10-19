# Chapter 9 Lab: The Drop (Mini-Capstone)

Starts from: workshops/01-initiation/starter/ (contract 1.5). Adds: the capstone's own glue (`drop_guard`, the `drop` ext, `policy.py`, `ladder.py`), the finished defenses of Chapters 2 to 8 copied byte for byte (see `shared.json`), five scalper scripts, the drop harness and the Chapter 9 shoppers.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/blocklists.py`
- `defenses/challenge_naive.py`
- `defenses/challenge_signed.py`
- `defenses/client_hints.py`
- `defenses/client_ip.py`
- `defenses/crawl_traps.py`
- `defenses/drop_guard.py`
- `defenses/feeds.py`
- `defenses/form_traps.py`
- `defenses/header_inspector.py`
- `defenses/header_order.py`
- `defenses/header_util.py`
- `defenses/ip_reputation.py`
- `defenses/pow_adaptive.py`
- `defenses/pow_budget.py`
- `defenses/pow_challenge.py`
- `defenses/pow_core.py`
- `defenses/pow_gate.py`
- `defenses/prefix_limit.py`
- `defenses/rate_limit.py`
- `defenses/responses.py`
- `defenses/session_guard.py`
- `defenses/trusted_proxy.py`
- `defenses/ua_inspector.py`
- `demo_site/ext/drop.py`
- `demo_site/ext/pow.py`
- `demo_site/ext/templates/drop/js_cookie.html`
- `demo_site/ext/templates/pow/bench.html`
- `demo_site/ext/templates/pow/interstitial.html`
- `demo_site/ext/templates/pow/solver.html`
- `demo_site/ext/templates/product.html`
- `demo_site/ext/templates/traps/archive.html`
- `demo_site/ext/templates/traps/fields.html`
- `demo_site/ext/templates/traps/footer.html`
- `demo_site/ext/templates/traps/head.html`
- `demo_site/ext/templates/traps/wp_login.html`
- `demo_site/ext/traps.py`
- `demo_site/static/css/traps.css`
- `demo_site/static/js/pow-worker.js`
- `demo_site/static/js/pow.js`
- `demo_site/static/js/traps.js`
- `tools/drop.py`
- `tools/personas_ch6.py`
- `tools/personas_ch9.py`
- `tools/pow_client.py`
- `tools/trapkit.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** Round 0 to 4 plus Drop Day. See `../chapter_09_content.md`, section 9.6.

Twenty limited-edition hoodies go on sale at once. Forty simulated shoppers want one each, and five waves of scalper bots want all of them. You compose the Workshop 1 defenses into one gate, round by round, and after every round you read both halves of the scoreboard: who got the hoodies, and what your defense cost the shoppers.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service URLs such as `REDIS_URL` too). The store's edge accepts the lab headers only from loopback. Playwright runs through `labclient.browser_context` (or `attacks/_drop.async_page`, which keeps the same guard), which also aborts any request that leaves localhost. Do not remove those checks.
- **Everything is simulated.** Each actor rents an address from `data/world.json` (documentation ranges, RFC 5737 and RFC 3849) and sends it in `X-Lab-Client-IP`; the store's edge treats it as the client address, for requests from loopback only. Every account, email and card is synthetic. No proxy, VPN or Tor node is ever contacted. The reputation feeds in `data/feeds/` are synthetic snapshots built from `data/world.json`; `data/feeds/manifest.json` records the real feed each one is shaped like. Nothing downloads them at run time.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, the Chromium that Playwright drives, and (optionally) the Redis and PostgreSQL container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

## What is in the folder, and how this lab is built

This lab is **pre-written** (level style): every defense ships complete, because you built each one in Chapters 2 to 8. You read them, switch `DEFENSE_LEVEL` and watch the scoreboard. `solutions/roundN/defenses/ladder.py` holds only the ladder as it stands after Round N, so catching up means restarting at the round's level: `python tools/checkpoint.py --round N --catch-up` installs the reference ladder (your own is kept as `ladder.py.bak`; `--restore` puts it back), and the checkpoint sets the level for you.

```
lab/
  defenses/ladder.py          which checks run at which level (L1 rate limits + headers, L2 IP reputation, L3 traps + session, L4 PoW + cap)
  defenses/policy.py          every number: bands, buckets, points, PoW bits. The ONLY file you edit on Drop Day
  defenses/drop_guard.py      the capstone's glue: points Chapter 2, 7 and 8's checks at the drop, and the one-per-customer cap
  defenses/rate_limit, client_ip, trusted_proxy, prefix_limit      Chapters 2/3   (copies, see shared.json)
  defenses/ip_reputation, feeds, blocklists                        Chapter 3
  defenses/ua_inspector, header_inspector, client_hints, header_order, header_util     Chapter 4
  defenses/session_guard                                           Chapter 8
  defenses/pow_core, pow_challenge, pow_gate, pow_budget, pow_adaptive, challenge_*    Chapter 6
  defenses/form_traps, crawl_traps, responses                      Chapter 7
  demo_site/ext/drop.py       the session plumbing session_guard reads, and the trap fields in the drop form
  demo_site/ext/pow.py, traps.py (+ templates, static)             Chapters 6 and 7
  attacks/round0_naive_scalper ... round4_full_browser, _drop.py
  tools/drop.py               run a drop and print the scoreboard · checkpoint.py · personas_ch9.py (the shoppers)
  data/                       world.json (the pretend network) · feeds/ (Chapter 3's snapshot)
  solutions/roundN/           the ladder after Round N (installed by --catch-up)
```

Every file marked "copy" is the **finished version** from the chapter that built it (for a wire-it chapter, the file from its `solutions/`), listed in `shared.json`. `python scripts/lab_diff.py <this lab> --shared` from the repository root checks that they are still identical. Fix a bug there, in the chapter, and copy it here: do not edit the copy.

**Why Python only:** every layer is server-side HTTP logic (Flask), the attackers are `requests` scripts and Playwright, and the only browser-side code is two short scripts in the store's pages (the JS cookie and the proof-of-work solver). A second language would add setup without teaching anything Workshop 1 needs.

### The levels, and one wrinkle

| Level | Round | Adds | From |
|---|---|---|---|
| 1 | rate limits + headers | `trusted_proxy`, `rate_limit`, `prefix_limit`, the drop's own bucket, then `ua_inspector`, `header_inspector`, `client_hints`, `header_order` | Ch2, Ch3, Ch4 |
| 2 | IP reputation | `ip_reputation` (Private Relay trusted) | Ch3 |
| 3 | traps + session | the drop form's honeypot and timing token, `crawl_traps`, `session_guard` | Ch7, Ch8 |
| 4 | proof of work + cap | `pow_gate` + `pow_budget` + `pow_adaptive`, one hoodie per customer, `session_binding`, `responses` | Ch6, Ch8, Ch7 |

Each level includes every level below it. Until level 4 nothing can be served in the challenge band, so `policy.decide()` enforces it as a block (the cost Round 2 makes visible); from level 4 the same score earns a proof of work. The wrinkle: the chapters' checks were written for the surface they taught (Chapter 2's checkout bucket meters `POST /checkout`, Chapter 8's session guard fires on the promo redeem, Chapter 7's traps sit on the signup form). The drop buys through `POST /drop/<sku>`, so `drop_guard.py` points them at it with the `action:drop_buy` phase instead of editing the copies. Read it first.

## Setup

Setup is covered once for the whole series in `onboarding/setup/PREWORK.md`. For this lab:

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-browser.txt      # one venv per chapter
python -m playwright install chromium                   # waves 3 and 4
python tools/doctor.py                                  # READY?
python demo_site/app.py                                 # http://127.0.0.1:5000
```

No Docker is needed (SQLite and an in-process Redis). With Docker, `docker compose up -d --wait` starts Redis 8.10 and PostgreSQL 18 as in the starter README, and you run the store with `REDIS_URL=redis://127.0.0.1:6379/0 DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop python demo_site/app.py`; `docker compose down -v` wipes it. Port 5000 busy (macOS: the AirPlay Receiver)? `PORT=8099 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:8099` in the shell where you run tools.

You never restart the store between rounds: edits to `defenses/*.py` are picked up on the next request, and the checkpoint (or `tools/drop.py --level N`) sets the level with `POST /lab/level`. By hand: `curl -s -X POST localhost:5000/lab/level -H 'Content-Type: application/json' -d '{"level": 2}'`. Restart only after editing `demo_site/ext/`. The drop is 20 hoodies: `tools/drop.py` restocks to 20 for every run, and `export DROP_STOCK=20` makes the store start that way for browsing by hand.

Open `http://localhost:5000/` and `http://localhost:5000/whoami` in your browser. `/whoami` shows how the store sees *your* request: your browser gets the world's `student_ip`, a home broadband address. `/lab/status` lists the ladder at every level.

## The three commands

| Command | What it does |
|---|---|
| `python tools/drop.py --waves 2` | Restocks, then releases the 40 shoppers and wave 2 at the same moment, and prints the scoreboard, at the store's current level. `--level N` sets the level first. `--waves 0,1,2,3,4` is Drop Day; `--waves none` is shoppers only; `--skip-browser` leaves out waves 3 and 4 |
| `python tools/checkpoint.py --round N` | Sets level N, runs the wave the round must stop and the wave that beats it (each in its own drop), and checks which shoppers a defense stopped. PASS/FAIL. `--level N-1` runs the same waves one level down (the "before"); `--all --markdown` is every round; `--all --full --markdown` runs every wave against every round (slow) |
| `python tools/checkpoint.py --round N --catch-up` | Fell behind: installs the reference ladder for Round N. Because the defenses are all here, this only restores the wiring. `--restore` puts yours back |

Reading the scoreboard:

```
Hoodies (20)   shoppers  8   bots 12 (r4_browser 12)   unsold 0           <- what the SERVER sold
Shoppers (40)  bought 8 · sold out 31 · stopped by a defense 1 (no_js x1)    <- false positives
               slowed >=1 s by proof of work: 1 (worst 1.2 s, 16 bits)       <- friction
bot:r4_browser sold 12 · believes 12 · 72 requests · blocked 0 · ... · 15 browser sessions
Gate cost      median 11.41 ms · p95 794.63 ms over 388 requests              <- defender latency
```

- **sold** vs. **believes**: trapped bots get fake order confirmations, so they believe they bought.
- **stopped by a defense**: a shopper who could not buy because of a defense (blocked, rate-limited, unable to solve a challenge, trapped). "Sold out" is not a false positive. A shopper behind a carrier-NAT address who then solved a proof of work and bought is not hurt either; the persona table in `tools/personas_ch9.py` says who is modelled and what hurts them.

> The store's responses carry `X-Lab-Verdict`, `X-Lab-Score` and `X-Lab-Signals` headers. They are there for teaching only. A real defense never tells the client which rule fired (`LAB_HEADERS=0`).

---

## Round 0: Baseline

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python tools/drop.py --level 0 --waves 0` | wave 0 sold **20**, shoppers 0 |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | wave 0 wins · 0 shoppers stopped |

Read `defenses/ladder.py` (level 0 is empty), `defenses/policy.py` and `defenses/drop_guard.py`, and open `/whoami` and `/lab/status` in your browser.

## Round 1: Rate limits + headers ⚔️ the cloud fleet

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read level 1 in `defenses/ladder.py`, then `rate_limit.py`, `trusted_proxy.py` and `ua_inspector.py`. `python tools/drop.py --level 1 --waves 0` | – |
| 🔴 Re-run | (the same command) | wave 0 sold **0**: blocked at its first request (`ua:red_flag` 40 + `headers:missing_accept_language` 15 + `headers:accept_any_on_navigation` 10 = 65: challenge, which is a block until Round 4) |
| 🔴 Attack | `python tools/drop.py --waves 1` | wave 1 sold **20**: copied Chrome headers, ≤5 requests per VM |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | wave 0 stopped · wave 1 wins · 0 shoppers stopped |

**Exercise:** set `"checkout_ip": (3, 0.05)` in `policy.py` and rerun wave 1 (no restart). The carrier-NAT shoppers (6 on one address) start getting `429`, and wave 1 does not notice. Put it back to `(12, 0.2)`.

## Round 2: IP reputation ⚔️ residential proxies

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | `python -m defenses.ip_reputation` (one address per pool), read `ip_reputation.py`. `python tools/drop.py --level 2 --waves 1` | – |
| 🔴 Re-run | (the same command) | wave 1 sold **0** (`datacenter` 40 + `hosting_asn` 25) · **3 VPN shoppers stopped** |
| 🔴 Attack | `python tools/drop.py --waves 2` | wave 2 sold **20**: residential addresses score 0 |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | wave 1 stopped · wave 2 wins · only `consumer_vpn` stopped |

**Discuss:** set `TRUST_PRIVACY_RELAYS = False` and run `python tools/drop.py --waves none`. Both Private Relay shoppers are now stopped: their egress ranges are on the community VPN list (`known_vpn` 40). Put it back.

## Round 3: Traps + session guard ⚔️ session minting

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read level 3 in `ladder.py`, `drop_guard.py` (the form check), `form_traps.py`, `crawl_traps.py` and `session_guard.py`. `python tools/drop.py --level 3 --waves 2` | – |
| 🔴 Re-run | (the same command) | wave 2 sold **0**, believes **60**, trapped 60 (fake successes) |
| 🔴 Attack | `python tools/drop.py --waves 3` | wave 3 sold **19–20** from 6 browser sessions |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` (`--skip-browser` without Chromium) | wave 2 stopped · wave 3 wins · only `consumer_vpn` stopped |

**Exercise:** set `MIN_FILL_SECONDS = 3.0`, then `python tools/drop.py --waves none`. The six shoppers whose form took less than 3 s (three `home`, a `private_relay`, the `autofill` shopper and one `mobile_cgnat`) are **trapped**: the page shows an order confirmation and nothing is bought, so the scoreboard's hoodie count and the shopper's own view disagree. A timing threshold must sit below your fastest customer. Put it back to `1.0`.

## Round 4: Proof of work + binding + one per customer ⚔️ a browser per hoodie

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read level 4 in `ladder.py`, `pow_gate.py`, `pow_budget.py`, `pow_adaptive.py` and `drop_guard.py` (the cap). `python tools/drop.py --level 4 --waves 3` | – |
| 🔴 Re-run | (the same command) | wave 3 sold **0**: challenged 18 times, its 12 proof-of-work solves bought nothing · VPN shoppers **slowed, not stopped** · only `no_js` stopped |
| 🔴 Attack | `python tools/drop.py --waves 4` | wave 4 sold **9** from 12 browser sessions, shoppers 11: every HTTP-level signal is genuine |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | wave 3 capped (≤ 6) · wave 4 gets a few · only `no_js` stopped |

Open `http://localhost:5000/drop/lab-hoodie-1` in your own browser at level 4 and buy a hoodie: the "Checking your browser…" page is `pow.js` solving the proof of work in Web Workers.

## Drop Day

```bash
python tools/drop.py --level 4 --waves 0,1,2,3,4        # ~1 min per run; --skip-browser leaves out 3 and 4
```

Edit **only** `defenses/policy.py`. The budget: **≤ 1** shopper stopped and **≤ 10** of 40 slowed ≥ 1 s. The goal: fewer bot hoodies than the reference run. The reference run (the shipped policy, seeds 7 to 9, identical each time): shoppers **11**, bots **9** (all of them wave 4), **1** shopper stopped (`no_js`), **0** slowed. Three things students try, measured on this lab:

| Change | Bots | Shoppers stopped | Slowed ≥ 1 s |
|---|---|---|---|
| nothing (reference) | 9 | 1 (`no_js`) | 0 |
| first row of `POW_ADAPTIVE` to 19 bits, then 20 | 9, then 10 | 2 (`no_js`, a budget phone gives up), 2 | 3, then 7 |
| `session_too_young` to 75 with `MIN_SESSION_SECONDS = 5.0` | 3 | 13 (`home` ×5, `mobile_cgnat` ×4, ...) | 0 |
| `asn_changed` to 75 | 9 | 1, or 2 when the phone that leaves its Wi-Fi mid-checkout reaches the buy before the stock is gone | 0 (wave 3 is already dead) |

Nothing here beats the reference *within the budget*: wave 4 is a real browser on a clean address, so anything that stops it stops people first. That is the point of the chapter.

## Debrief

```bash
python tools/scoreboard.py                              # bots stopped next to shoppers hurt, per actor
curl -s 'localhost:5000/lab/decisions?actor=bot:r2&limit=5' | python -m json.tool   # every gate decision: signals, outcome, extra
```

- Which layer stopped the most bot *requests*, and which the most bot *hoodies*?
- Which shoppers did your Drop Day policy hurt, and what would you change for them?
- Wave 2 "bought" 60 hoodies. Which dashboard would have shown you that, and which would have hidden it?


## Expected results (self-check)

Measured on 2026-10-14 on one laptop (WSL2, Python 3.12.15, Flask 3.1.3, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.1.4, redis 8.1.0, fakeredis[lua] 2.39.0 with lupa 2.8, requests 2.34.2, user-agents 2.2.0, Playwright 1.63.0 with its bundled Chromium 153), with the default **in-process Redis and SQLite**. The Redis 8.10 + PostgreSQL 18 `docker compose` path is verified separately (see the end of this section). Each cell is the number of hoodies (of 20) the bot's wave got when it ran alone against the 40 shoppers at the end of that round, from `CHECKPOINT_FULL=1 python tools/verify.py --all --catch-up --markdown` (the same table prints from `python tools/checkpoint.py --all --full --markdown`). The wave a round must **stop** and the wave that **beats** it are the checkpoint's expectations; "-" means not run in that round.

| Wave / end of round | 0 | 1 | 2 | 3 | 4 |
|---|---|---|---|---|---|
| wave 0 (naive scalper) | **20** | 0 | 0 | 0 | 0 |
| wave 1 (cloud fleet) | 20 | **20** | 0 | 0 | 0 |
| wave 2 (residential filler) | - | 20 | **20** | 0 (believes 60) | 0 |
| wave 3 (session minting) | - | - | 20 | **19-20** | 0 |
| wave 4 (a browser per hoodie) | - | - | - | 9 | **9** |
| **Shoppers stopped** | 0 | 0 | 3 (`consumer_vpn`) | 3 (`consumer_vpn`) | 1 (`no_js`) |
| **Shoppers slowed >= 1 s** | 0 | 0 | 0 | 0 | 0 |

Bold cells are the attack that beats the round (the checkpoint's "wins" expectation). The checkpoint's thresholds are: **wins** takes at least 10 of 20, **stopped** at most 4, **capped** (wave 3 at Round 4) at most 6, **some** (wave 4) at least 1, and no shopper outside the round's named personas may be stopped. The "before" column (`python tools/checkpoint.py --round N --level N-1`) is the previous column of the same row: for example Round 4's wave 3 at level 3 is 20, at level 4 it is 0.

Things to watch for:

- **Every cell but one is the same across runs and seeds.** The waves are faster than the shoppers (who arrive over six seconds and read the form for two to six), so a wave that beats a round takes the whole drop. Wave 3 sometimes loses one hoodie to a shopper (19-20). Wave 4 is the only race: it gets 9 and the shoppers 11 in every run (seeds 7 to 9), because its three browsers need about five seconds per hoodie.
- **Wave 1 and wave 2 at Round 4 are challenged, not blocked** (40 and 60 requests). They do not run JavaScript, so they never answer. A bot that could solve a 16-bit puzzle would get through the gate and meet the traps and the cap: Round 3's wave 2 row shows what the honeypot does to it.
- **The proof of work costs nobody a second at the shipped price.** A 16-bit puzzle is about 65,000 hashes: a few hundredths of a second on a desktop, a third of a second on the budget Android phone the shoppers model. Drop Day shows what happens when you raise it.
- **Gate cost with the in-process Redis is pessimistic.** fakeredis emulates Redis's Lua inside the store's own process (and its GIL), so the gate's median is 7 to 12 ms and its p95 40 to 750 ms in the combined Drop Day runs, against 1 to 2 ms for the bare store in Round 0. Present latency numbers as relative, not absolute.
- **Waves 3 and 4 need Chromium** and take 20 to 40 s each. `--skip-browser` leaves them out (the checkpoint skips their expectations too).
- **Version drift.** The headers come from `tools/browsers.py` (Chrome 153, Firefox 155, Safari 26). When Chrome stable moves on, bump the versions there and in `attacks/_drop.py` (`CHROME_MAJOR`), and `MIN_CHROME_MAJOR` in `defenses/policy.py`, as in W1 Ch4.

**Drop Day** (`python tools/drop.py --level 4 --waves 0,1,2,3,4`, the shipped policy, seeds 7 to 9, identical each time): shoppers **11** of 20, bots **9** (all of them wave 4, from 12 browser sessions), **1** shopper stopped (`no_js`), **0** slowed. Wave 0 is blocked at its first request, waves 1 and 2 are challenged (40 and 60 requests), wave 3 gets 18 challenges and 12 solves for nothing.

**Docker path** (Redis 8.10 and PostgreSQL 18.6 from `docker-compose.yml`): `docker compose up -d --wait`, then `REDIS_URL=redis://127.0.0.1:6379/0 DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop python tools/verify.py --smoke` passes, and Rounds 3 and 4 pass end to end with the same numbers as above (wave 3: 20 at level 3 and 0 at level 4; wave 4: 9, shoppers 11, 1 stopped). The gate's p95 drops to 50 to 110 ms (median 14 to 26 ms) because the Lua runs in a real Redis; the median is not lower because every Redis call is now a network round trip to a container. Then `docker compose down -v`.


## Troubleshooting

| Problem | Fix |
|---|---|
| Port 5000 already in use (macOS: AirPlay Receiver) | `PORT=8099 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:8099` in every terminal you run tools from |
| Checkpoint says a wave "should be stopped" but the defense is wired | Check the level: `curl -s localhost:5000/lab/status` shows it. A drop run by hand uses whatever level the store is at; `tools/drop.py --level N` sets it |
| `connection refused` on 6379 or 5432 | Docker path only: `docker compose ps`, both containers must be `healthy`. Without Docker, unset `REDIS_URL` and `DATABASE_URL` |
| `Executable doesn't exist` from Playwright | `python -m playwright install chromium`, or use `--skip-browser` |
| A shopper shows `error` | The store was stopped or too slow (30 s timeout). Check the store's terminal |
| Everything is stopped after you edited a defense | A broken check fails open (a `<check>:error` signal with 0 points), but a bad policy value can block everyone. `git diff defenses/policy.py`, or copy it back from the repository |
| Start completely fresh | `curl -s -X POST 'localhost:5000/lab/reset?mode=full'` reseeds the store; `docker compose down -v && docker compose up -d --wait` wipes the Docker path |

## Bonus challenges

1. **Rate-limit the customer, not the address.** Add a `checkout_session` bucket keyed on the session id in `drop_guard.py`, then tighten `checkout_ip` again. Does carrier NAT still hurt?
2. **A fallback for no-JS shoppers.** Serve a self-hosted CAPTCHA (Chapter 5) inside `<noscript>` when the proof of work cannot run. What does it cost the form filler?
3. **Tor.** Add a wave that rents from the world's `tor_exit` pool. Which layer catches it, and with how many points?
4. **Pin the workers.** Run wave 3 with its workers on the minter's own address for every request (a sticky proxy session): `python tools/reset.py --stock 20`, then `python attacks/round3_session_minting.py --pinned` against a store at level 4. It buys exactly 6 hoodies, one per minted session, with 12 refusals from the cap and no proof of work of its own (the minter's browser solved the pass the workers reuse). What stops it, and what does that tell you about the binding?
