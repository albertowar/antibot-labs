# Chapter 4 Lab: Headers, User-Agent & Client Hints

Starts from: workshops/01-initiation/starter/ (contract 1.2). Adds: five header checks (`ua_inspector`, `header_inspector`, `client_hints`, `header_order`, `accept_ch`) wired into the ladder, the `headers` feature module, the browser-profile capture and replay tools, six attack scripts and the Chapter 4 shoppers.

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

**Format:** 6 rounds of attack ⚔️ defend, ~105 min. See `../chapter_04_content.md`, §4.7.

You play both sides. In each round, the attacker runs a script against the demo store. The defender then turns on the next defense layer and measures two things: what it catches, and what it costs. Then the attacker works out what to try next.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- Every request comes from your own machine; the browser profiles in `tools/profiles/` are header sets, not people.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  docker-compose.yml   PostgreSQL 18 for the header logs
  demo_site/app.py     Flask store; DEFENSE_LEVEL=0..4 picks the defense layers
  defenses/            ua_inspector · header_inspector · client_hints · header_order · accept_ch · scoring
  attacks/             round0_recon … round5_playwright_ua_override
  tools/               checkpoint.py · legit_traffic.py · capture_profiles.py · profiles/*.json
```

---

## Setup (before the session)

```bash
cd lab
docker compose up -d --wait                 # PostgreSQL on 127.0.0.1:5432
python -m venv .venv && source .venv/bin/activate      # one venv per chapter, see the root README
pip install -r requirements.txt
playwright install chromium                 # Round 5 attack
```

Start the demo site, and restart it with a new `DEFENSE_LEVEL` each round:

```bash
cd demo_site
DEFENSE_LEVEL=0 python app.py               # http://localhost:5000
```

| Level | Adds | Module |
|---|---|---|
| 0 | Nothing. Every request is scored and logged, but none are blocked | – |
| 1 | User-Agent parsing | `defenses/ua_inspector.py` |
| 2 | Header presence and Fetch Metadata consistency | `defenses/header_inspector.py` |
| 3 | Client Hints consistency and header order | `defenses/client_hints.py`, `defenses/header_order.py` |
| 4 | `Accept-CH` negotiation for high-entropy hints | `defenses/accept_ch.py` |

Each level includes every level below it, and `defenses/scoring.py` adds up the points:

- **≥ 40** → `bot`: the request is blocked with a 403.
- **≥ 20** → `suspicious`: logged but allowed through.
- **< 20** → `clean`.

Two debug endpoints are never blocked:

- `/header-check` shows how your current request is scored, and the headers in the order they arrived.
- `/header-logs` shows the last 50 scored requests.

> The 403 response includes the reasons it fired. That is for teaching only.
> In production, never tell a client which rule caught it.

**Troubleshooting**

| Problem | Fix |
|---|---|
| Port 5000 already in use (macOS: the AirPlay Receiver uses it) | `PORT=5050 DEFENSE_LEVEL=… python app.py`, then `export DEMO_URL=http://localhost:5050` in the shell you run attacks and tools from |
| No Docker | `export DATABASE_URL=sqlite:///header_logs.db` before starting the app. Everything else works the same |
| `connection refused` on 5432 | `docker compose ps`. The container must show as `healthy` |
| Fresh logs | `docker compose down -v && docker compose up -d --wait` |

---

## How to measure a round

Finish every round with a **checkpoint**:

```bash
python tools/checkpoint.py --round <N>      # add --skip-browser to skip the Playwright attack
```

```
=== Checkpoint: Round 3 (server at DEFENSE_LEVEL=3) ===

Bot traffic
  ✅ round1_naive_requests            1/1 blocked (expected: blocked)
  ✅ round2_fake_ua                   1/1 blocked (expected: blocked)
  ✅ round3_devtools_copy             1/1 blocked (expected: blocked)
  ✅ round4_client_hints_spoof        0/3 blocked (expected: gets through)
  ✅ round5_playwright_ua_override    2/2 blocked (expected: blocked)

Real users (replayed browser profiles)
  ✅ 0/4 requests blocked across 2 profiles

Defender cost
  header scoring: median 0.21 ms, p95 0.26 ms per request

✅ Round 3 checkpoint passed.
```

What it reports:

- **Bot traffic:** every attack script, compared with what should happen at this level.
- **Real users:** `tools/legit_traffic.py` replays header profiles captured from real browsers, with byte-identical values and order. Any 403 here is a **false positive**.
- **Defender cost:** the time spent scoring each request, read from the `Server-Timing` response header.

**Fell behind?** Every defense is already written, so catching up just means restarting the demo site with `DEFENSE_LEVEL=<N>`. The checkpoint tells you if you're on the wrong level.

---

## Round 0: Recon (15 min)

**🗡️ Attack (look):**

```bash
python attacks/round0_recon.py              # requests, urllib and curl hit /header-check
```

**🛡️ Defend (look):** open `http://localhost:5000/` and `/header-check` in **Chrome** and **Firefox**, then fill in:

| | requests | curl | Chrome | Firefox |
|---|---|---|---|---|
| Number of headers | | | | |
| `Accept` | | | | |
| `Accept-Language`? | | | | |
| `Sec-Fetch-*`? | | | | |
| `Sec-CH-UA*`? | | | | |
| Position of `User-Agent` | | | | |

**Add yourself to the real-user set:** save your browser's `/header-check` output as `tools/profiles/<your-browser>.json`.
From now on, every checkpoint checks that *your* browser isn't blocked.
If you have a display, `python tools/capture_profiles.py` does the same for Chrome, Firefox and WebKit.

**Checkpoint:** `python tools/checkpoint.py --round 0`. Nothing should be blocked.

---

## Round 1: Naive scraper ⚔️ User-Agent parsing (15 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round1_naive_requests.py` (level 0) | `200`, products scraped |
| 🛡️ Defend | Read `defenses/ua_inspector.py`, then restart with `DEFENSE_LEVEL=1` | – |
| 🗡️ Re-run | `python attacks/round1_naive_requests.py` | `403`, `[L1] UA red flag: Raw HTTP library (Python requests)` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | round 1 blocked · 0 real users blocked |

**Discuss:** how long does this defense survive? (About one line of attacker code.)

---

## Round 2: Chrome User-Agent ⚔️ presence & consistency (15 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round2_fake_ua.py` (level 1) | `200` |
| 🛡️ Defend | Read `defenses/header_inspector.py`, then restart with `DEFENSE_LEVEL=2` | – |
| 🗡️ Re-run | `python attacks/round2_fake_ua.py` | `403` (score 50): `Missing Accept-Language`, `Sec-Fetch-* headers are absent`, `Accept is */*` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | rounds 1–2 blocked · 0 real users blocked |

**Exercise:** check `/header-check` in Firefox, and in Safari if you have a Mac.
Both send `Sec-Fetch-*`: Safari since 16.4, Firefox since 90.
The old rule "Safari + Sec-Fetch = forgery" would block every real Safari user.

---

## ☕ Break (10 min)

---

## Round 3: Copied browser headers ⚔️ Client Hints & order (20 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round3_devtools_copy.py` (level 2) | `200`: every presence and Fetch Metadata check passes |
| 🛡️ Defend | Read `defenses/client_hints.py` and `defenses/header_order.py`, then restart with `DEFENSE_LEVEL=3` | – |
| 🗡️ Re-run | `python attacks/round3_devtools_copy.py` | `403` (score 45): `Sec-CH-UA is absent` (30) + `Header order unlike Chromium` (15) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | rounds 1–3 and 5 blocked · round 4 gets through · 0 real users blocked |

**Exercises:**

1. Run `python defenses/client_hints.py` and `python defenses/header_order.py`, and read each sample.
2. Find the GREASE brand in your Chrome's `sec-ch-ua`.
3. Header order alone scores only 15. Why so little? Think about proxies, CDNs and HTTP/2.

---

## Round 4: Spoofed Client Hints ⚔️ Accept-CH negotiation (20 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round4_client_hints_spoof.py` (level 3) | `200` on all four requests |
| 🛡️ Defend | Read `defenses/accept_ch.py` and `offer_client_hints()` in `app.py`, then restart with `DEFENSE_LEVEL=4` | – |
| 🗡️ Re-run | `python attacks/round4_client_hints_spoof.py` | navigation `200` (the server replies with `Accept-CH`), then each fetch `403`: `Accept-CH was offered but the client ignored it` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | everything blocked · 0 real users blocked |

**False-positive check:** open `/` in Chrome, then reload `/header-check`. You should see `sec-ch-ua-full-version-list`, and the verdict should be `clean`.

**Discuss:**

- The bot throws away the `ch_offered` cookie every time. What happens? (Chapter 5)
- Which costs more, a cookie plus a response header, or blocking a real user?

---

## Round 5: Real browser with a UA override (10 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round5_playwright_ua_override.py --no-override` | level ≥ 1: `403`, `UA red flag: Headless Chrome` |
| 🗡️ Attack | `python attacks/round5_playwright_ua_override.py` | level 2: `200` · level ≥ 3: `403`, `brand list contains HeadlessChrome` · level 4 adds `Platform-Version '10.0' is not in browser format` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 5` | everything blocked · 0 real users blocked |

Playwright rewrites the `User-Agent` and even the `Sec-CH-UA-Platform` hint. But the brand list still comes from the real binary, so it names `HeadlessChrome`. Headless mode also sends no `Accept-Language`.

**Debrief:** set the `userAgentMetadata` brands through the CDP command `Emulation.setUserAgentOverride`, or run headed Chrome on a real Windows box. At that point **every header is genuine**. Header inspection ends here; the next layers are:

- TLS and HTTP/2 fingerprints: W2 Ch5
- Automation artefacts: W2 Ch1
- JavaScript-side consistency (`userAgentData` vs. these headers, browser fingerprints): W2 Ch4
- Behaviour: W2 Ch3

---

## Wrap-up: false positives and cost (10 min)

```bash
python tools/legit_traffic.py               # per-profile verdicts and reasons
docker compose exec postgres psql -U workshop -d shop \
  -c "SELECT level, verdict, count(*) FROM header_log GROUP BY 1, 2 ORDER BY 1, 2;"
```

- Did any real-browser request score above 0? Which rule fired, and why?
- Which rules would you only ever use for `suspicious`, never for `bot`?
- Header scoring costs well under a millisecond. Which part of *this* app's request path costs more? (Hint: the log insert.)

---

## Instructor: expected results

Verified with Python 3.12.15, Flask 3.1.3, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.1.4, psycopg 3.3.6, requests 2.34.2, user-agents 2.2.0 and Playwright 1.63.0 (Chromium 153.0.8010.12 headless shell) on Linux, on the no-Docker path (`DATABASE_URL=sqlite:///...`); the shipped `tools/profiles/` come from real Chrome 145 and Firefox 155. The `docker compose` path has not been run for the migrated lab. "403" means every scraping request was blocked.

| Attack ↓ / `DEFENSE_LEVEL` → | 0 | 1 | 2 | 3 | 4 | Reason at the first block |
|---|---|---|---|---|---|---|
| `round1_naive_requests` | 200 | **403** | 403 | 403 | 403 | `[L1] UA red flag: Raw HTTP library` |
| `round2_fake_ua` | 200 | 200 | **403** | 403 | 403 | `[L2]` ×3, score 50 |
| `round3_devtools_copy` | 200 | 200 | 200 | **403** | 403 | `[L3] Sec-CH-UA is absent` + order, score 45 |
| `round4_client_hints_spoof` | 200 | 200 | 200 | 200 | **403** | `[L4] Accept-CH was offered but the client ignored it` |
| `round5_…` (UA override) | 200 | 200 | 200 | **403** | 403 | `[L3] brand list contains HeadlessChrome` |
| `round5_… --no-override` | 200 | **403** | 403 | 403 | 403 | `[L1] UA red flag: Headless Chrome` |
| Real users (`legit_traffic.py`) | 200 | 200 | 200 | 200 | 200 | – (score 0) |

Things to watch for:

- **Version drift.** When Chrome or Playwright updates, re-run every checkpoint, re-capture `tools/profiles/`, and bump `MIN_CHROME_MAJOR` and the Chrome version in the attack scripts.
- **WebKit capture on Linux** needs system libraries: `sudo playwright install-deps webkit`. The shipped profiles cover Chrome and Firefox only. Ask Mac users to add a Safari profile in Round 0.

---

## Bonus challenges

1. **Accept-Language vs. locale.** Flag `Accept-Language: zh-CN` paired with a UA or IP geolocation that suggests `en-US`.
   Mind the false positives: travellers, expats and VPN users. Add a profile that shows the problem.
2. **Firefox impersonation.** Write `round6_firefox_spoof.py`: a Firefox UA with Firefox's headers, so there are no hints to check.
   Which of our rules still apply? Add a Firefox rule set to `header_order.py` and run the checkpoint.
3. **Critical-CH.** Add `Critical-CH: Sec-CH-UA-Full-Version-List` to the responses.
   Real Chrome then retries the *first* navigation with the hints, so you no longer need the cookie.
   What does this change for cookie-less bots?
