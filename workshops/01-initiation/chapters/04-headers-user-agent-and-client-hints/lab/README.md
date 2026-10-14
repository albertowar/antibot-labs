# Chapter 4 Lab: Headers, User-Agent & Client Hints

Starts from: workshops/01-initiation/starter/ (contract 1.4). Adds: five header checks (`ua_inspector`, `header_inspector`, `client_hints`, `header_order`, `accept_ch`) wired into the ladder, the `headers` feature module, the browser-profile capture and replay tools, five attack scripts and the Chapter 4 shoppers.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/accept_ch.py`
- `defenses/client_hints.py`
- `defenses/header_inspector.py`
- `defenses/header_order.py`
- `defenses/header_util.py`
- `defenses/ua_inspector.py`
- `demo_site/ext/headers.py`
- `tools/capture_profiles.py`
- `tools/headers_client.py`
- `tools/personas_ch4.py`
- `tools/profiles/chrome-145-linux.json`
- `tools/profiles/firefox-155-linux.json`
- `tools/replay_profiles.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** 5 rounds (0–4) of attack ⚔️ defend. See `../chapter_04_content.md`, §4.7. **Lab style:** pre-written.
Every defense is written and already wired into `defenses/ladder.py`; each round you read one layer, the checkpoint
switches the store to that round's `DEFENSE_LEVEL`, and you re-run the attacks.

You play both sides. In each round, the attacker runs a script against the demo store. The defender then turns on the
next defense layer and measures two things: what it catches, and what it costs real shoppers. Then the attacker works
out what to try next.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`, which asks
  `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine. The store's edge accepts the
  lab headers only from loopback. Do not remove that check.
- **Everything is synthetic.** Scrapers and shoppers rent documentation addresses (RFC 5737) from `data/world.json` and
  send them in `X-Lab-Client-IP`; header checks ignore the address anyway. The browser profiles in `tools/profiles/` are
  header sets captured from real browsers on the author's machine, not people.
- **The real browser is yours.** The Round 3 Playwright attack drives a local headless Chromium against `127.0.0.1` only.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages and the Chromium build.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  defenses/ua_inspector.py      L1: the User-Agent on its own (libraries, headless markers, stale versions)
  defenses/header_inspector.py  L2: Accept*, Fetch Metadata and Referer tell one story
  defenses/client_hints.py      L3: Sec-CH-UA* against the User-Agent
  defenses/header_order.py      L3: Chromium's header order (weak: 15 points)
  defenses/accept_ch.py         L4: the high-entropy hints a real Chromium sends after Accept-CH
  defenses/ladder.py            which checks run at which level (pre-wired 0..4)
  defenses/policy.py            the bands (20 monitor, 40 block), MIN_CHROME_MAJOR, ACCEPT_CH_HINTS, CRITICAL_CH
  demo_site/ext/headers.py      Accept-CH on pages at level 4, /lab/headers/check, /lab/headers/logs
  attacks/                      round0_recon … round4_client_hints_spoof, round3_playwright_ua_override
  tools/                        checkpoint.py · replay_profiles.py · capture_profiles.py · profiles/*.json
                                personas_ch4.py (the shoppers' Accept-CH behaviour)
  solutions/round1..4/          the reference ladder.py per round (the catch-up files)
```

The rest of the store (catalog, cart, checkout, accounts, the simulated edge, the decision log) is the Workshop 1 starter,
unchanged. Its contract is `workshops/STORE_CONTRACT.md`.

---

## Setup

Setup is covered once for the whole series in `onboarding/setup/PREWORK.md`. For this lab:

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt                         # one venv per chapter
pip install -r requirements-browser.txt                 # Playwright, for the Round 3 browser attack
python -m playwright install chromium
python tools/doctor.py                                  # READY?
python demo_site/app.py                                 # http://127.0.0.1:5000
```

No Docker is needed (SQLite and an in-process Redis). With Docker, `docker compose up -d --wait` starts Redis 8.10 and
PostgreSQL 18 as in the starter README. Port 5000 busy (macOS AirPlay)? `PORT=8099 python demo_site/app.py`, then
`export DEMO_URL=http://127.0.0.1:8099` in the shell where you run attacks and tools. No browser? Every checkpoint takes
`SKIP_BROWSER=1` and leaves the two Playwright runs out.

You never restart the store between rounds: the checkpoint sets the level (`POST /lab/level`), and edits to
`defenses/*.py` are picked up on the next request. To set a level by hand:
`curl -X POST localhost:5000/lab/level -H 'content-type: application/json' -d '{"level": 2}'`.

| Level | Adds | Module |
|---|---|---|
| 0 | Nothing. No check runs; every request is still logged | – |
| 1 | User-Agent parsing | `defenses/ua_inspector.py` |
| 2 | Header presence and Fetch Metadata consistency | `defenses/header_inspector.py` |
| 3 | Client Hints consistency and header order | `defenses/client_hints.py`, `defenses/header_order.py` |
| 4 | `Accept-CH` negotiation for high-entropy hints | `defenses/accept_ch.py` |

Each level includes every level below it, and the gate adds up the points (`defenses/policy.py`, `BANDS`):

- **≥ 40** → block (`403`). Chapter 4 registers no challenge type, so the challenge band is a block too.
- **≥ 20** → monitor: served, logged as suspicious.
- **< 20** → allow.

**Fell behind?** `python tools/checkpoint.py --round N --catch-up` installs the reference `defenses/ladder.py` for round N
(your file is kept as `ladder.py.bak`; `python tools/checkpoint.py --restore` puts it back) and sets the level.

**Look around while you work** (lab pages, never gated, never in production):

```bash
curl -s localhost:5000/lab/headers/check | python -m json.tool    # how THIS request scores, check by check, level by level
curl -s localhost:5000/lab/headers/logs  | python -m json.tool    # the last 50 scored requests and their reasons
curl -s 'localhost:5000/lab/decisions?actor=bot:&limit=5' | python -m json.tool
python -m defenses.client_hints                                   # every check scores its own samples from the CLI
```

Every response carries `X-Lab-Verdict`, `X-Lab-Score`, `X-Lab-Signals` and `Server-Timing`. They tell the attacker
exactly what tripped: never send them in production (`LAB_HEADERS=0` turns them off).

---

## How to measure a round

```bash
python tools/checkpoint.py --round N              # level N: this round's layer on
python tools/checkpoint.py --round N --level N-1  # the same attacks one level lower: the "before"
```

The checkpoint sets the level, resets the store, runs **every** scraper (rounds 1–4, plus the Playwright browser with and
without its UA override) while the 40 shoppers browse, and prints:

- **The scoreboard**: requests served and stopped per actor, and the gate's cost in milliseconds.
- **The shoppers table**: per persona, how many finished and how many a defense stopped. Watch `old_chrome`: Chrome 138 is
  below `MIN_CHROME_MAJOR`, so it is *suspicious* (20 points) from level 1 on, served but logged.
- **The attacks**: each scraper's share of catalog pages fetched, against what this level should allow. A scraper is
  expected to get through until the level built to stop it, and to stay stopped after that.
- **Real browsers**: `tools/replay_profiles.py` replays the profiles in `tools/profiles/` byte for byte (same names, values
  and order). Any stopped request is a **false positive** and fails the round.
- **PASS or FAIL** against those expectations.

Trimmed output (the shoppers table, the attacks' JSON and the per-profile lines left out):

```text
$ python tools/checkpoint.py --round 3

== Round 3: Client Hints and header order: copied browser headers and a real browser with a UA override are stopped (level 3)
actor                          req  served  bought  stopped  score      ms
bot:devtools-copy                5       0       0        5   45.0    0.84
bot:fake-ua                      5       0       0        5   95.0    1.18
bot:headers-playwright          12       0       0       12   75.0    1.03
bot:hints-spoof                  6       6       0        0    0.0    0.98
bot:naive-requests               5       0       0        5   65.0    0.87
human:autofill                   6       6       1        0    0.0    1.54
human:consumer_vpn              18      18       3        0    0.0    1.51
human:home                     144     144      24        0    0.0    1.56
human:mobile_cgnat              48      48       8        0    0.0    1.67
human:no_js                      6       6       1        0    0.0    1.32
human:old_chrome                 6       6       1        0   20.0    1.78
human:private_relay             12      12       2        0    0.0    1.16

bots stopped 27/33 requests   shoppers hurt 0/40 people (0/240 requests stopped)   purchases {'human': 40}   drop stock {'lab-hoodie-1': 50, 'lab-runner-9': 50}

attacks:
  naive                            0% succeeded
  fake_ua                          0% succeeded
  copied                           0% succeeded
  spoof                            100% succeeded
  headless                         0% succeeded
  override                         0% succeeded

=== Real browsers (replayed profiles) ===

  Stopped: 0/6 requests across 2 profiles

  Defender cost on these requests: median 3.49 ms, p95 6.68 ms (the gate: Ctx build + every check)

  suspicious but served: human:old_chrome averaged score 20.0 over 6 requests

Round 3 at level 3: PASS
```

---

## Round 0: Recon

**🗡️ Attack (look):**

```bash
python attacks/round0_recon.py              # requests, urllib and curl hit /lab/headers/check
```

**🛡️ Defend (look):** open `http://127.0.0.1:5000/` and `/lab/headers/check` in **Chrome** and **Firefox**, then fill in:

| | requests | curl | Chrome | Firefox |
|---|---|---|---|---|
| Number of headers | | | | |
| `Accept` | | | | |
| `Accept-Language`? | | | | |
| `Sec-Fetch-*`? | | | | |
| `Sec-CH-UA*`? | | | | |
| Position of `User-Agent` | | | | |

Reference answer (counting `Host`), from `round0_recon.py` and the shipped profiles in `tools/profiles/` (Chrome 145 and
Firefox 155 on Linux, captured at level 4 after a page load):

| | requests | curl | Chrome | Firefox |
|---|---|---|---|---|
| Number of headers | 5 | 3 | 18 (14 on a first visit, before `Accept-CH` and the cookie) | 13 |
| `Accept` | `*/*` | `*/*` | `text/html,…` | `text/html,…` |
| `Accept-Language`? | no | no | yes | yes |
| `Sec-Fetch-*`? | no | no | yes | yes |
| `Sec-CH-UA*`? | no | no | yes (3 low-entropy, 3 negotiated) | no |
| Position of `User-Agent` | 2nd | 2nd | 10th, after the hints | 2nd |

**Add yourself to the real-user set:** at level 4 (so Chromium has negotiated its hints), save your browser's
`/lab/headers/check` output as `tools/profiles/<your-browser>.json`. From now on every checkpoint checks that *your*
browser isn't blocked. With a display, `python tools/capture_profiles.py` does the same for Chrome, Firefox and WebKit.

**Checkpoint:** `python tools/checkpoint.py --round 0`. Nothing is blocked; the checkpoint also checks that the shoppers'
header templates (`tools/browsers.py`) agree with the captured profiles.

---

## Round 1: Naive scraper ⚔️ User-Agent parsing

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round1_naive_requests.py` (level 0) | `200`, the whole catalog |
| 🛡️ Defend | Read `defenses/ua_inspector.py` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | level 1 · the naive scraper and headless Chrome blocked · 0 real users blocked |
| 🗡️ Re-run | `python attacks/round1_naive_requests.py` | `403`, `ua:red_flag` (Raw HTTP library) |

**Discuss:** how long does this defense survive? (About one line of attacker code.)

---

## Round 2: Chrome User-Agent ⚔️ presence & consistency

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round2_fake_ua.py` (level 1) | `200` |
| 🛡️ Defend | Read `defenses/header_inspector.py` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | level 2 · rounds 1–2 blocked · 0 real users blocked |
| 🗡️ Re-run | `python attacks/round2_fake_ua.py` | `403` (score 50): `headers:missing_accept_language`, `headers:no_sec_fetch`, `headers:accept_any_on_navigation` |

**Exercise:** check `/lab/headers/check` in Firefox, and in Safari if you have a Mac. Both send `Sec-Fetch-*`: Safari
since 16.4, Firefox since 90. The old rule "Safari + Sec-Fetch = forgery" would block every real Safari user.

---

## Round 3: Copied headers and a real browser ⚔️ Client Hints & order

Level 2 checks that the headers tell one story. The attacker tries two ways to tell it: copy a browser's headers, or
stop faking and drive a real Chromium with a UA override.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack 1 | `python attacks/round3_devtools_copy.py` (level 2) | `200`: every presence and Fetch Metadata check passes |
| 🗡️ Attack 2 | `python attacks/round3_playwright_ua_override.py` (level 2) | `200`: Playwright even rewrites `Sec-CH-UA-Platform` to `"Windows"`; the missing `Accept-Language` is only 15 points |
| 🛡️ Defend | Read `defenses/client_hints.py` and `defenses/header_order.py` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | level 3 · rounds 1–3 blocked · round 4 gets through · 0 real users blocked |
| 🗡️ Re-run 1 | `python attacks/round3_devtools_copy.py` | `403` (score 45): `client_hints:hints_absent` (30) + `header_order:unlike_chromium` (15) |
| 🗡️ Re-run 2 | `python attacks/round3_playwright_ua_override.py` | `403` (score 55): `client_hints:headless_brand` (40) + `headers:missing_accept_language` (15). The brand list still says `"HeadlessChrome";v="153"` |

The override changes the `User-Agent` string, not the brand list Chromium builds from the real binary. Without the
override (`--no-override`) the browser never got this far: `HeadlessChrome` in the UA is a level-1 red flag.

**Exercises:**

1. Run `python -m defenses.client_hints` and `python -m defenses.header_order`, and read each sample.
2. Find the GREASE brand in your Chrome's `sec-ch-ua`.
3. Header order alone scores only 15. Why so little? Think about proxies, CDNs and HTTP/2.

---

## Round 4: Spoofed Client Hints ⚔️ Accept-CH negotiation

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round4_client_hints_spoof.py` (level 3) | `200` on the navigation and every catalog page |
| 🛡️ Defend | Read `defenses/accept_ch.py` and `_offer_client_hints()` in `demo_site/ext/headers.py` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | level 4 · everything blocked · 0 real users blocked |
| 🗡️ Re-run | `python attacks/round4_client_hints_spoof.py` | navigation `200` (the store replies with `Accept-CH`), then each fetch `403`: `accept_ch:ignored` |

**False-positive check:** at level 4, open `/` in Chrome, then reload `/lab/headers/check`. You should see
`sec-ch-ua-full-version-list`, and a score of 0. The Chrome shoppers do the same (`tools/personas_ch4.py`).

**Discuss:**

- The bot throws away the `ch_offered` cookie every time. What happens? (Chapter 5)
- Which costs more, a cookie plus a response header, or blocking a real user?

---

## Wrap-up: where headers stop

The Playwright browser was caught by one leaked brand. Set the `userAgentMetadata` brands through the CDP command
`Emulation.setUserAgentOverride`, or run headed Chrome on a real Windows box, and **every header is genuine**. Header
inspection ends here; the next layers are:

- TLS and HTTP/2 fingerprints: W2 Ch5
- Automation artefacts: W2 Ch1
- JavaScript-side consistency (`userAgentData` vs. these headers, browser fingerprints): W2 Ch4
- Behaviour: W2 Ch3

Then look at the defender's side:

```bash
python tools/replay_profiles.py                                   # per-profile verdicts and reasons, at the current level
curl -s localhost:5000/lab/headers/logs | python -m json.tool     # which rule fired on which request
```

- Did any real-browser request score above 0? Which rule fired, and why?
- Which rules would you only ever use for `suspicious`, never for block? (`old_chrome` is your evidence.)
- The checkpoint prints the gate's cost per request. Which part of *this* store's request path costs more than every
  header check together? (Look at `app;dur` next to `gate;dur` in `Server-Timing`.)

---

## Expected results (self-check)

Generated by `python tools/verify.py --all --markdown` (the per-round scoreboards, then the attack-by-level matrix that
`tools/checkpoint.py` prints at the end: catalog products scraped out of 120); do not edit by hand. Verified on Linux with
Python 3.12.15, Flask 3.1.3, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.1.4,
redis 8.1.0 with fakeredis 2.39.0 (`memory://`), requests 2.34.2, user-agents 2.2.0
and Playwright 1.63.0 (Chromium 153 headless shell), on the zero-Docker path (SQLite); the `docker compose`
path has not been run for this lab. The shipped `tools/profiles/` come from real Chrome 145 and Firefox 155.

Round 0 runs without the browsers (`–`). The Playwright actor's 12 requests per round are the two runs' navigations and
catalog pages together.

- **Shoppers hurt: 0/40 at every level**, and the replayed real-browser profiles score 0 at every level.
- **`old_chrome`** (Chrome 138, below `MIN_CHROME_MAJOR`) averages score 20 from level 1 on: served, logged as
  suspicious. Set `STALE_VERSION_POINTS = 40` in `policy.py` and watch it become a false positive.
- **The gate's cost** is about 1–2 ms per request on a laptop, and level 0, with no check at all, already costs about 1 ms:
  most of it is building the request context (the session lookup in Redis), not the header checks. With the UA parser's
  cache warm, all five checks together cost about 0.1 ms (`Server-Timing` at level 4: `ua_inspector;dur=0.06,
  header_inspector;dur=0.04, client_hints;dur=0.01, header_order;dur=0.00, accept_ch;dur=0.01`). Under the checkpoint's load (40 shoppers next to six
  attacks in one Python process) the numbers move by a millisecond or two between runs.

Reasons at the first block:

| Attack | Stopped from | Signals |
|---|---|---|
| `round1_naive_requests` | L1 | `ua:red_flag` (Raw HTTP library) |
| `round2_fake_ua` | L2 | `headers:missing_accept_language`, `headers:no_sec_fetch`, `headers:accept_any_on_navigation` (score 50) |
| `round3_devtools_copy` | L3 | `client_hints:hints_absent`, `header_order:unlike_chromium` (score 45) |
| `round3_playwright_ua_override` | L3 | `client_hints:headless_brand`; at L4 also `accept_ch:bad_platform_version` |
| `… --no-override` | L1 | `ua:red_flag` (Headless Chrome) |
| `round4_client_hints_spoof` | L4 | `accept_ch:ignored` (the navigation is served; every catalog page after it is not) |

<!-- results:start -->
| Attack ↓ / level → | 0 | 1 | 2 | 3 | 4 |
|---|---|---|---|---|---|
| `round1_naive_requests` | 120/120 | 0/120 | 0/120 | 0/120 | 0/120 |
| `round2_fake_ua` | 120/120 | 120/120 | 0/120 | 0/120 | 0/120 |
| `round3_devtools_copy` | 120/120 | 120/120 | 120/120 | 0/120 | 0/120 |
| `round3_playwright_ua_override` | – | 120/120 | 120/120 | 0/120 | 0/120 |
| `round3_playwright_ua_override --no-override` | – | 0/120 | 0/120 | 0/120 | 0/120 |
| `round4_client_hints_spoof` | 120/120 | 120/120 | 120/120 | 120/120 | 0/120 |

<details><summary>Round 0 scoreboard (recon: nothing is wired, every scraper gets the catalog, level 0: PASS)</summary>

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:devtools-copy | 5 | 5 | 0 | 0 | 0.0 | 1.31 |
| bot:fake-ua | 5 | 5 | 0 | 0 | 0.0 | 1.39 |
| bot:hints-spoof | 6 | 6 | 0 | 0 | 0.0 | 0.95 |
| bot:naive-requests | 5 | 5 | 0 | 0 | 0.0 | 1.21 |
| human:autofill | 6 | 6 | 1 | 0 | 0.0 | 1.45 |
| human:consumer_vpn | 18 | 18 | 3 | 0 | 0.0 | 1.67 |
| human:home | 144 | 144 | 24 | 0 | 0.0 | 1.71 |
| human:mobile_cgnat | 48 | 48 | 8 | 0 | 0.0 | 1.66 |
| human:no_js | 6 | 6 | 1 | 0 | 0.0 | 2.9 |
| human:old_chrome | 6 | 6 | 1 | 0 | 0.0 | 2.12 |
| human:private_relay | 12 | 12 | 2 | 0 | 0.0 | 1.64 |
Bots stopped: **0/21** requests · shoppers hurt: **0/40** people (0/240 requests stopped, including challenges they then solved) · purchases: {'human': 40} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

</details>

<details><summary>Round 1 scoreboard (User-Agent parsing: the naive scraper and headless Chrome are stopped, level 1: PASS)</summary>

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:devtools-copy | 5 | 5 | 0 | 0 | 0.0 | 1.23 |
| bot:fake-ua | 5 | 5 | 0 | 0 | 0.0 | 1.96 |
| bot:headers-playwright | 12 | 6 | 0 | 6 | 20.0 | 0.85 |
| bot:hints-spoof | 6 | 6 | 0 | 0 | 0.0 | 1.69 |
| bot:naive-requests | 5 | 0 | 0 | 5 | 40.0 | 1.85 |
| human:autofill | 6 | 6 | 1 | 0 | 0.0 | 2.08 |
| human:consumer_vpn | 18 | 18 | 3 | 0 | 0.0 | 1.95 |
| human:home | 144 | 144 | 24 | 0 | 0.0 | 1.9 |
| human:mobile_cgnat | 48 | 48 | 8 | 0 | 0.0 | 2.08 |
| human:no_js | 6 | 6 | 1 | 0 | 0.0 | 2.21 |
| human:old_chrome | 6 | 6 | 1 | 0 | 20.0 | 1.99 |
| human:private_relay | 12 | 12 | 2 | 0 | 0.0 | 2.08 |
Bots stopped: **11/33** requests · shoppers hurt: **0/40** people (0/240 requests stopped, including challenges they then solved) · purchases: {'human': 40} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

</details>

<details><summary>Round 2 scoreboard (presence and Fetch Metadata: a Chrome UA on default headers is stopped, level 2: PASS)</summary>

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:devtools-copy | 5 | 5 | 0 | 0 | 0.0 | 1.55 |
| bot:fake-ua | 5 | 0 | 0 | 5 | 50.0 | 1.71 |
| bot:headers-playwright | 12 | 6 | 0 | 6 | 35.0 | 1.01 |
| bot:hints-spoof | 6 | 6 | 0 | 0 | 0.0 | 1.36 |
| bot:naive-requests | 5 | 0 | 0 | 5 | 65.0 | 0.83 |
| human:autofill | 6 | 6 | 1 | 0 | 0.0 | 1.65 |
| human:consumer_vpn | 18 | 18 | 3 | 0 | 0.0 | 1.84 |
| human:home | 144 | 144 | 24 | 0 | 0.0 | 2.03 |
| human:mobile_cgnat | 48 | 48 | 8 | 0 | 0.0 | 1.99 |
| human:no_js | 6 | 6 | 1 | 0 | 0.0 | 1.99 |
| human:old_chrome | 6 | 6 | 1 | 0 | 20.0 | 1.4 |
| human:private_relay | 12 | 12 | 2 | 0 | 0.0 | 1.96 |
Bots stopped: **16/33** requests · shoppers hurt: **0/40** people (0/240 requests stopped, including challenges they then solved) · purchases: {'human': 40} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

</details>

<details><summary>Round 3 scoreboard (Client Hints and header order: copied browser headers and a real browser with a UA override are stopped, level 3: PASS)</summary>

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:devtools-copy | 5 | 0 | 0 | 5 | 45.0 | 1.15 |
| bot:fake-ua | 5 | 0 | 0 | 5 | 95.0 | 1.55 |
| bot:headers-playwright | 12 | 0 | 0 | 12 | 75.0 | 1.19 |
| bot:hints-spoof | 6 | 6 | 0 | 0 | 0.0 | 1.54 |
| bot:naive-requests | 5 | 0 | 0 | 5 | 65.0 | 1.55 |
| human:autofill | 6 | 6 | 1 | 0 | 0.0 | 2.23 |
| human:consumer_vpn | 18 | 18 | 3 | 0 | 0.0 | 1.89 |
| human:home | 144 | 144 | 24 | 0 | 0.0 | 1.92 |
| human:mobile_cgnat | 48 | 48 | 8 | 0 | 0.0 | 1.97 |
| human:no_js | 6 | 6 | 1 | 0 | 0.0 | 1.78 |
| human:old_chrome | 6 | 6 | 1 | 0 | 20.0 | 2.13 |
| human:private_relay | 12 | 12 | 2 | 0 | 0.0 | 2.16 |
Bots stopped: **27/33** requests · shoppers hurt: **0/40** people (0/240 requests stopped, including challenges they then solved) · purchases: {'human': 40} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

</details>

<details><summary>Round 4 scoreboard (Accept-CH negotiation: consistent static hints are stopped, level 4: PASS)</summary>

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:devtools-copy | 5 | 0 | 0 | 5 | 45.0 | 1.8 |
| bot:fake-ua | 5 | 0 | 0 | 5 | 95.0 | 1.61 |
| bot:headers-playwright | 12 | 0 | 0 | 12 | 81.2 | 0.94 |
| bot:hints-spoof | 6 | 1 | 0 | 5 | 33.3 | 0.84 |
| bot:naive-requests | 5 | 0 | 0 | 5 | 65.0 | 0.91 |
| human:autofill | 6 | 6 | 1 | 0 | 0.0 | 1.71 |
| human:consumer_vpn | 18 | 18 | 3 | 0 | 0.0 | 1.86 |
| human:home | 144 | 144 | 24 | 0 | 0.0 | 1.67 |
| human:mobile_cgnat | 48 | 48 | 8 | 0 | 0.0 | 1.65 |
| human:no_js | 6 | 6 | 1 | 0 | 0.0 | 1.66 |
| human:old_chrome | 6 | 6 | 1 | 0 | 20.0 | 1.54 |
| human:private_relay | 12 | 12 | 2 | 0 | 0.0 | 1.75 |
Bots stopped: **32/33** requests · shoppers hurt: **0/40** people (0/240 requests stopped, including challenges they then solved) · purchases: {'human': 40} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

</details>
<!-- results:end -->

Things to watch for:

- **Version drift.** When Chrome or Playwright updates, re-run every checkpoint, re-capture `tools/profiles/`, and bump
  `MIN_CHROME_MAJOR` and `CHROME_MAJOR` in `tools/headers_client.py`.
- **WebKit capture on Linux** needs system libraries: `sudo playwright install-deps webkit`. The shipped profiles cover
  Chrome and Firefox only. On a Mac, add a Safari profile in Round 0.

---

## Bonus challenges

1. **Accept-Language vs. locale.** Flag `Accept-Language: zh-CN` paired with a UA or IP geolocation that suggests `en-US`.
   Mind the false positives: travellers, expats and VPN users. Add a profile that shows the problem.
2. **Firefox impersonation.** Write `attacks/bonus_firefox_spoof.py`: a Firefox UA with Firefox's headers, so there are no
   hints to check. Which of our rules still apply? Add a Firefox rule set to `header_order.py` and run the checkpoint.
3. **Critical-CH.** Set `CRITICAL_CH = True` in `defenses/policy.py`. Real Chrome (and the Chrome shoppers) then retry
   the *first* navigation with the hints, so the check no longer needs the cookie. What does this change for cookie-less
   bots?
