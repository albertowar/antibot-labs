# Chapter 8 Lab: The Drop (Mini-Capstone)

**Format:** Round 0–4 plus Drop Day. See `../chapter_08_content.md`, §8.6.

Twenty limited-edition hoodies go on sale at once. Forty simulated shoppers want one each, and five waves of scalper bots want all of them. You wire the W1 defenses into one gate, round by round, and after every round you read both halves of the scoreboard: who got the hoodies, and what your defense cost the shoppers.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- The "IPs" are pretend: each actor names an address from `data/world.json`, and the store's lab edge treats it as the client address, for requests from loopback only. No proxy, VPN or Tor node is ever contacted.
- The reputation feeds in `data/feeds/` are shipped snapshots. Nothing downloads them at run time.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  docker-compose.yml   Redis 8 + PostgreSQL 18, bound to 127.0.0.1
  demo_site/           app.py (the store and its gate) · lab_edge.py (pretend CDN, W1 Ch2)
  defenses/            pipeline.py ← YOU WIRE IT · policy.py ← YOU TUNE IT · ladder.py
                       rate_limit · headers (+ the four W1 Ch3 modules) · ip_reputation
                       session_guard · traps · proof_of_work · store
  attacks/             wave0_naive_scalper … wave4_full_browser · browser_kit.py
  tools/               drop.py · checkpoint.py · humans.py · labclient.py · browsers.py
                       profiles/ (W1 Ch3 captures)
  data/                world.json (IP pools) · feeds/ (W1 Ch2 snapshot, trimmed)
  solutions/roundN/    defenses/pipeline.py as it stands after Round N (installed by --catch-up)
```

**Why Python only:** every layer is server-side HTTP logic (Flask), the attackers are `requests` scripts and Playwright, and the only browser-side code is two short inline scripts in the store's pages (the JS cookie and the proof-of-work solver). A second language would add setup without teaching anything W1 needs.

**Why Docker:** the gate needs Redis (token buckets, sessions, trap flags, used proof-of-work nonces) and the store keeps stock and orders in PostgreSQL. No Docker? See Troubleshooting: an in-process Redis and SQLite work too.

---

## Setup (~10 min)

```bash
cd workshops/01-initiation/chapters/08-mini-capstone/lab
docker compose up -d --wait                 # Redis on 127.0.0.1:6379, PostgreSQL on 127.0.0.1:5432
python -m venv .venv && source .venv/bin/activate      # one venv per chapter, see the root README
pip install -r requirements.txt
playwright install chromium                 # waves 3 and 4
```

Start the store and leave it running in its own terminal:

```bash
python demo_site/app.py                     # http://localhost:5000
```

**Restart the store after every edit** to `defenses/pipeline.py` or `defenses/policy.py` (Ctrl+C, then run it again).

Open `http://localhost:5000/` and `http://localhost:5000/whoami` in your browser. `/whoami` shows how the gate scored *your* request: your browser gets the world's `student_ip`, a home broadband address.

## The three commands

| Command | What it does |
|---|---|
| `python tools/drop.py --waves 2` | Restocks, then releases the 40 shoppers and wave 2 at the same moment, and prints the scoreboard. `--waves 0,1,2,3,4` for Drop Day, `--waves none` for shoppers only |
| `python tools/checkpoint.py --round N` | Checks your pipeline, runs the wave the round must stop and the wave that beats it, and checks which shoppers were stopped |
| `python tools/checkpoint.py --round N --catch-up` | Fell behind: installs the reference `defenses/pipeline.py` for Round N from `solutions/roundN/` (yours is kept as `pipeline.py.bak`; `--restore` puts it back). Restart the store afterwards |

Reading the scoreboard:

```
Hoodies (20)   shoppers 14   bots  6 (wave4 6)   unsold 0           ← what the SERVER sold
Shoppers (40)  bought 14 · sold out 25 · stopped by a defense 1 (no_js ×1)   ← false positives
               slowed ≥1 s by proof of work: 2 (worst 2.9 s, 17 bits)        ← friction
wave4          sold 6 · believes 6 · 18 requests · blocked 0 · rate-limited 0 · challenged 0 · trapped 0 · 9 browser sessions
Gate cost      median 5.54 ms · p95 19.00 ms over 148 requests                ← defender latency
```

- **sold** vs. **believes**: trapped bots get fake order confirmations, so they believe they bought.
- **stopped by a defense**: a shopper who couldn't buy because of a defense (blocked, rate-limited, unable to solve a challenge). "Sold out" is not a false positive.

> The store's responses carry `X-Lab-Verdict`, `X-Lab-Score` and `X-Lab-Signals` headers. They are there for teaching only. A real defense never tells the client which rule fired.

---

## Round 0: Baseline

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python tools/drop.py --waves 0` | wave 0 sold **20**, shoppers 0 |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | wave 0 wins · 0 shoppers stopped |

Read `defenses/pipeline.py` (empty `LAYERS`) and `defenses/ladder.py`.

## Round 1: Rate limits + headers ⚔️ the cloud fleet

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `defenses/rate_limit.py` and `defenses/headers.py`. In `pipeline.py`, follow `TODO (Round 1)`. Restart | – |
| 🔴 Re-run | `python tools/drop.py --waves 0` | wave 0 sold **0**: blocked at its first request (UA 40 + headers 25 = 65 → challenge → block) |
| 🔴 Attack | `python tools/drop.py --waves 1` | wave 1 sold **20**: copied Chrome headers, ≤3 requests per VM |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | wave 0 stopped · wave 1 wins · 0 shoppers stopped |

**Exercise:** set `"checkout_ip": (3, 0.05)` in `policy.py`, restart, and rerun wave 1. The carrier-NAT shoppers (6 on one IP) start getting `429`, and wave 1 doesn't notice. Put it back to `(12, 0.2)`.

## Round 2: IP reputation ⚔️ residential proxies

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | `python defenses/ip_reputation.py` (one IP per pool). Follow `TODO (Round 2)`. Restart | – |
| 🔴 Re-run | `python tools/drop.py --waves 1` | wave 1 sold **0** (`datacenter` 40 + `hosting_asn` 25) · **3 VPN shoppers stopped** |
| 🔴 Attack | `python tools/drop.py --waves 2` | wave 2 sold **20**: residential IPs score 0 |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | wave 1 stopped · wave 2 wins · only `consumer_vpn` stopped |

**Discuss:** set `TRUST_PRIVACY_RELAYS = False`, restart, and run `python tools/drop.py --waves none`. Both Private Relay shoppers are now stopped: their egress ranges are on the community VPN list (`known_vpn` 40). Put it back.

## Round 3: Session guard + traps ⚔️ session minting

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `defenses/session_guard.py` and `defenses/traps.py`. Follow `TODO (Round 3)`. Restart | – |
| 🔴 Re-run | `python tools/drop.py --waves 2` | wave 2 sold **0**, believes **60**, trapped 60 (fake successes) |
| 🔴 Attack | `python tools/drop.py --waves 3` | wave 3 sold **18–20** from 6 browser sessions |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` (`--skip-browser` without Chromium) | wave 2 stopped · wave 3 wins · only `consumer_vpn` stopped |

**Exercise:** set `MIN_FORM_SECONDS = 3.0`, restart, and run `python tools/humans.py`. The autofill shopper now scores `form_too_fast`. Put it back to `1.0`.

## Round 4: Proof of work + binding + one per customer ⚔️ a browser per hoodie

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Read `defenses/proof_of_work.py` and `session_guard.check_binding`. Follow `TODO (Round 4)`. Restart | – |
| 🔴 Re-run | `python tools/drop.py --waves 3` | wave 3 sold **1–6** (never more than one per minted session), challenged ~20–40 times · VPN shoppers **slowed, not stopped** · only `no_js` stopped |
| 🔴 Attack | `python tools/drop.py --waves 4` | wave 4 sold **4–8**: every HTTP-level signal is genuine |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | wave 3 capped (≤ 6) · wave 4 gets a few · only `no_js` stopped |

Open `/drop` in your own browser and buy a hoodie: the "Checking your browser…" message is the page solving the proof of work with WebCrypto.

## Drop Day

```bash
python tools/drop.py --waves 0,1,2,3,4        # ~40 s per run; --skip-browser leaves out 3 and 4
```

Edit **only** `defenses/policy.py`. Goal: fewer bot hoodies than the reference run, with **≤ 1** shopper stopped and **≤ 10** of 40 slowed ≥ 1 s.

## Debrief

```bash
python tools/humans.py                         # per-shopper outcome and proof-of-work cost
tail -n 5 logs/decisions.jsonl                 # every gate decision of the latest drop
```

- Which layer stopped the most bot *requests*, and which the most bot *hoodies*?
- Which shoppers did your Drop Day policy hurt, and what would you change for them?

---

## Expected results (self-check)

Measured on 2026-10-11 on one laptop (WSL2, Python 3.12.15, Flask 3.1.3, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.1.4, redis 8.1.0, fakeredis[lua] 2.39.0 with lupa 2.8, requests 2.34.2, user-agents 2.2.0, Playwright 1.63.0 / Chromium 153.0.8010.12 headless shell), with **`REDIS_URL=fakeredis://` and `DATABASE_URL=sqlite:///...`**. The Redis 8 + PostgreSQL 18 `docker compose` path is verified separately (see the notes below). Each cell shows the bot's hoodies out of 20 when it runs alone against the 40 shoppers, at the end of each round, with `tools/checkpoint.py --round N --all`.

| Wave ↓ / end of round → | 0 | 1 | 2 | 3 | 4 | First stopped by |
|---|---|---|---|---|---|---|
| wave 0 naive scalper | **20** | 0 | 0 | 0 | 0 | headers: UA 40 + consistency 25 |
| wave 1 cloud fleet | 20 | **20** | 0 | 0 | 0 | IP reputation: `datacenter` 40 + `hosting_asn` 25 |
| wave 2 residential filler | 20 | 20 | **20** | 0 (believes 60) | 0 (believes 60) | traps: `honeypot_field` 100 → fake success |
| wave 3 session minting | – | – | – | **18–20** | 1–6 | one per session + network-bound PoW |
| wave 4 full browser | – | – | – | – | **4–8** | nothing in W1 (Workshop 2) |
| **Shoppers stopped** | 0 | 0 | 3 VPN | 3 VPN | 1 no-JS | |
| **Shoppers slowed ≥ 1 s** | 0 | 0 | 0 | 0 | 1–3 (VPN, 17 bits) | |

Bold cells are the attack that beats the round (the checkpoint's "wins" expectation). "–" means not run in that round. Drop Day with the Round 4 policy, across seven runs: shoppers 11–16 of 20, bots 4–9 (wave 3: 2–4, wave 4: 2–6), 1 shopper stopped (no-JS), 2–3 slowed.

Things to watch for:

- **Gate cost with fakeredis is pessimistic.** fakeredis emulates Redis's Lua in-process (via `lupa`), about 2 ms per rate-limit check in isolation. Under 40 concurrent shoppers plus five waves and Chromium on one laptop, the gate's median rose to ~200 ms. Real Redis should be far cheaper, but this wasn't measured here. Present the latency numbers as relative, not absolute.
- **Wave 3 and 4 numbers depend on the laptop.** They race the shoppers, so a slow Chromium start gives the shoppers more hoodies. The checkpoint thresholds (wins ≥ 10, stopped ≤ 4, capped ≤ 6, some ≥ 1) leave room for that.
- **Wave 3 at Round 4 is capped, not zeroed.** Its workers rotate across a residential pool where AT&T and Comcast hold 55% of the addresses, so a retry sometimes lands on the network that minted the session and the bound proof of work verifies. Each of its 6 sessions can still buy one hoodie; the cap, not the binding, sets the ceiling.
- **Version drift.** The headers come from `tools/browsers.py` (Chrome 153, Firefox 155, Safari 26). When Chrome stable moves on, bump the versions there and in `attacks/browser_kit.py`, and `MIN_CHROME_MAJOR` in `defenses/ua_inspector.py`, as in W1 Ch3.
- **Proof-of-work speed was measured, not assumed.** The page's WebCrypto solver did ~80k SHA-256/s in headless Chromium 153 on the reference laptop, and the Python loop ~400k/s. `BROWSER_HASHES_PER_SECOND` in `tools/humans.py` uses the browser figure. On slower machines, students' own browsers take longer than the simulated shoppers.

## Troubleshooting

| Problem | Fix |
|---|---|
| Port 5000 already in use (macOS: AirPlay Receiver) | `PORT=5050 python demo_site/app.py`, then `export DEMO_URL=http://localhost:5050` in every terminal you run tools from |
| No Docker | `REDIS_URL=fakeredis:// DATABASE_URL=sqlite:///shop.db python demo_site/app.py`. The in-process Redis lives inside the store, so restarting the store wipes it. That's fine here: every drop starts with a reset |
| `connection refused` on 6379 or 5432 | `docker compose ps`: both containers must be `healthy` |
| Checkpoint says a layer is missing, but you added it | You didn't restart the store. `curl localhost:5000/admin/config` shows the live pipeline |
| `Executable doesn't exist` from Playwright | `playwright install chromium`, or use `--skip-browser` |
| A shopper shows `error` | The store was stopped or too slow (30 s timeout). Check the store's terminal |
| Start completely fresh | `docker compose down -v && docker compose up -d --wait`, then restart the store |

## Bonus challenges

1. **Rate-limit the customer, not the address.** Add a `checkout_session` bucket keyed on the session id, then tighten `checkout_ip` again. Does carrier NAT still hurt?
2. **A fallback for no-JS shoppers.** Serve a self-hosted CAPTCHA (W1 Ch5) inside `<noscript>` when a checkout fails the proof of work. What does it cost wave 2?
3. **Tor.** Add a wave that rents from the world's `tor` pool. Which layer catches it, and with how many points?
