# Chapter 5 Lab: The ClientHello Arms Race

**Format:** Round 0 recon plus 4 rounds of defend ⚔️ attack, 105 min plus a 13-min debrief. See `../chapter_05_content.md`, §5.8.

The W1 Ch4 attacker copies every header from DevTools, so nothing at the HTTP layer gives it away anymore. In this lab you move the defense one layer down, to the TLS ClientHello and the HTTP/2 connection preface. Each round you write a few lines of a new layer, run the attacker that beats it, and measure two things on simulated real users: what the layer catches, and what it costs.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- Scripts go through the local TLS edge on `https://localhost:8443`. `attacks/_lab.py` also refuses to skip the edge by targeting the Flask origin port directly.
- **Outbound network:** one setup-time download. `tools/get_fingerproxy.py` fetches the pinned fingerproxy release from GitHub and deletes it if the SHA-256 does not match. Nothing touches the network during the rounds.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  docker-compose.yml   PostgreSQL 18 for the request log (optional: SQLite works too)
  demo_site/app.py     Flask store behind the edge; DEFENSE_LEVEL=0..4 picks the layers
  defenses/            ja4 (parser) · edge_headers · ja4_denylist · tls_family · h2_fingerprint ·
                       browser_proof · scoring · known_fingerprints.json
  attacks/             round0_recon · round1_naive_requests · round1_cipher_tweak ·
                       round2_impit_chrome · round3_curl_cffi_chrome · round4_playwright_chromium
  tools/               edge.py · get_fingerproxy.py · make_cert.py · clienthello_dump.py ·
                       capture_fingerprints.py · checkpoint.py · legit_traffic.py · fingerprint_report.py
  solutions/roundN/    the reference defenses/ module for each round (installed by --catch-up)
```

```
 client ──TLS 1.3──▶ fingerproxy (Go)  :8443 ──HTTP + X-JA4-Fingerprint, X-HTTP2-Fingerprint──▶ Flask :5000
```

**Why two languages.** Python's `ssl` module never exposes the raw ClientHello or the HTTP/2 SETTINGS frame, so the TLS edge has to be something else. We use [fingerproxy](https://github.com/wi1dcard/fingerproxy) (Go, Apache-2.0) as a **prebuilt, checksum-pinned binary**: you never write or compile Go. Everything you edit is Python.

---

## Setup (before the session, about 10 min)

Requirements: Python ≥ 3.12. Docker is optional.

```bash
cd lab
python -m venv .venv && source .venv/bin/activate       # Windows: .venv\Scripts\activate; one venv per chapter
pip install -r requirements.txt
playwright install chromium firefox                   # + webkit if you want that persona
python tools/make_cert.py                              # certs/tls.crt, tls.key for https://localhost
python tools/get_fingerproxy.py                        # bin/fingerproxy v1.2.3, SHA-256 checked
docker compose up -d --wait                            # PostgreSQL on 127.0.0.1:5432 (or see "No Docker")
```

Keep three terminals open, all inside `lab/` with the venv active:

```bash
# terminal 1: the TLS edge. Leave it running all session
python tools/edge.py                                   # https://localhost:8443 → http://127.0.0.1:5000

# terminal 2: the demo site. Restart it every round with the next level
DEFENSE_LEVEL=0 python demo_site/app.py

# terminal 3: attacks and tools
python attacks/round0_recon.py
```

| Level | Adds | Module | Your TODO |
|---|---|---|---|
| 0 | Nothing. Every request is fingerprinted, scored and logged | – | – |
| 1 | Edge check plus a JA4 denylist of HTTP libraries | `defenses/ja4_denylist.py` | Round 1 |
| 2 | The UA's browser must match the TLS family (JA4 a+b) | `defenses/tls_family.py` | Round 2 |
| 3 | The HTTP/2 fingerprint must match the TLS family | `defenses/h2_fingerprint.py` | Round 3 |
| 4 | Browser TLS must come with a JS engine proof cookie | `defenses/browser_proof.py` | Round 4 |

Each level includes every level below it. `defenses/scoring.py` adds up the points:

- **≥ 40** → `bot`, blocked with a 403.
- **≥ 20** → `suspicious`, logged.

Each layer scores 50.

Debug endpoints, never blocked:

- `/tls-check`: what the edge saw for this request (JA4, JA3, HTTP/2, family) and how it scored.
- `/tls-logs`: the last 50 decisions.

> The 403 response includes the reasons. That's for teaching only: in production, never tell a client which rule caught it.

**Troubleshooting**

| Problem | Fix |
|---|---|
| Port 5000 taken (macOS AirPlay Receiver) | `PORT=5050` for **both** `tools/edge.py` and `demo_site/app.py` |
| No Docker | `export DATABASE_URL=sqlite:///tls_logs.db` in terminals 2 and 3. Everything else is the same |
| `connection refused` on 5432 | `docker compose ps`; the container must be `healthy` |
| `Edge not reachable` from the checkpoint | Terminal 1 must show `server listening on 127.0.0.1:8443` |
| `No X-JA4-Fingerprint: request bypassed the TLS edge` | You hit Flask on :5000 directly. Use https://localhost:8443 |
| No prebuilt fingerproxy for your platform | Go ≥ 1.21: see the `go install` line in `tools/get_fingerproxy.py` |
| `webkit-user skipped: missing system libraries` | Optional persona. `sudo playwright install-deps webkit`, or ignore it |
| Browser warns about the certificate | Expected: it's self-signed. Click through for `localhost` only |

---

## How to measure a round

Finish every round with a **checkpoint**:

```bash
python tools/checkpoint.py --round <N>        # --skip-browser skips Playwright (faster, fewer personas)
```

```
=== Checkpoint: Round 2 (server at DEFENSE_LEVEL=2) ===

Bot traffic                         blocked   expected        attacker req/s
  ✅ round1_naive_requests          10/10    blocked            33.1
  ✅ round1_cipher_tweak            10/10    blocked            32.3
  ✅ round2_impit_chrome             0/10    gets through       23.3
  ✅ round3_curl_cffi_chrome         0/10    gets through       25.1
  ✅ round4_playwright_chromium      0/10    gets through        6.8

Real users                          blocked
  ✅ partner-api                    0/3
  ⚠️  corporate-proxy                3/3  documented false positive: ['[L2] UA claims chromium but JA4 t13d1912h1_121de08f9505 matches no browser family']
  ✅ chromium-user                  0/3
  ✅ firefox-user                   0/3
  ⏭️  webkit-user                    skipped: missing system libraries (playwright install-deps webkit)
  ✅ noscript-firefox               0/1
  → real-user requests blocked: 3/13

Defender cost
  TLS scoring: median 0.14 ms, p95 0.58 ms per request

✅ Round 2 checkpoint passed.
```

What it reports:

- **Bot traffic:** every attack, compared with what should happen at this level, plus the attacker's throughput. Throughput is sequential and includes browser start-up, so compare the numbers with each other, not with production.
- **Real users:** the personas in `tools/legit_traffic.py`, which include real Chromium and Firefox through the same edge. Two personas are **documented false positives**: the checkpoint shows them with ⚠️ as the cost of the layer instead of failing. Any other 403 here fails the checkpoint.
- **Defender cost:** scoring time per request, from the `Server-Timing` response header.

**Fell behind?** `python tools/checkpoint.py --round N --catch-up` installs the reference solutions for rounds 1..N from `solutions/` over your files and keeps each of yours once as `.bak`. Restart the store at `DEFENSE_LEVEL=N`, then run the checkpoint again. `python tools/checkpoint.py --restore` puts your own files back.

---

## Round 0: Recon (25 min)

| Step | Do | Expected |
|---|---|---|
| 👀 Look | `python attacks/round0_recon.py` | One row per client: JA4, HTTP version, family, HTTP/2 fingerprint |
| 👀 Look | Open https://localhost:8443/ in **your own** Chrome and Firefox | The page prints your JA4 and HTTP/2 fingerprint |
| 🔁 Repeat | Run `round0_recon.py` again | `playwright chromium`'s JA4 part c **changed**. `curl_cffi chrome`'s didn't |
| 🔬 Dig | Terminal 3: `python tools/clienthello_dump.py`. Terminal 4: `python attacks/round0_recon.py --dump` | `captures/*.hex`, one raw ClientHello per client |
| 🧮 Compute | `python defenses/ja4.py captures/playwright-chromium.hex` | Our JA4 is `t13d1516h2_8daaf6152771_806a8c22fdea` on every run, and differs from the edge's part c |
| 🔁 Resume | Look at the `… resumed session` rows of the `--dump` output | Resumed Chromium is `t13d1517h2_8daaf6152771`: the same a+b as fresh Firefox |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | Nothing blocked, 0 real users blocked |

Fill in this table from the recon output:

| | python-requests | curl_cffi chrome | impit chrome | Playwright Chromium | Playwright Firefox |
|---|---|---|---|---|---|
| Cipher count (JA4_a) | 17 | 15 | | | |
| Extension count | | | | | |
| ALPN | | | | | |
| HTTP/2 SETTINGS | – | | | | |
| ClientHello bytes (`--dump`) | 517 | ~1,790 | | | |

**Discuss:**

1. Why does the edge's JA4_c for Chromium change, while our `ja4.py` gives the same value every time? Look at the first signature algorithm in `python defenses/ja4.py captures/playwright-chromium.hex`. Chromium puts a random GREASE value there. The JA4 spec says to ignore GREASE everywhere. fingerproxy v1.2.3 doesn't do that for signature algorithms, so its part c takes 16 values for one browser. That's why every layer in this lab keys on **JA4 a+b**.
2. `playwright page.request` claims to be HeadlessChrome. What sent it?
3. Why is Chromium's ClientHello three times the size of requests'? (Hint: `groups` contains `0x11ec`, X25519MLKEM768.)
4. A resumed Chrome connection adds `pre_shared_key`, so it has 17 extensions, just like a fresh Firefox 155. What does that mean for a rule that maps a JA4 to exactly one browser?

---

## Round 1: 🛡️ JA4 denylist ⚔️ 🗡️ change one cipher string (20 min)

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round1_naive_requests.py` (level 0) | `200`. Every header is Chrome's |
| 🛡️ Defend | `python tools/capture_fingerprints.py`, then fill in `TODO (Round 1)` in `defenses/ja4_denylist.py` | `local_fingerprints.json` holds *your* requests/httpx/urllib JA4s |
| 🛡️ Restart | `DEFENSE_LEVEL=1 python demo_site/app.py` | – |
| 🗡️ Re-run | `python attacks/round1_naive_requests.py` | `403`, `[L1] JA4 on library denylist: python-requests …` |
| 🗡️ Attack back | `python attacks/round1_cipher_tweak.py` | `200`: a new JA4 (`t13d0912h1_…`) the denylist has never seen |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | naive blocked, tweak gets through, 0 real users blocked |

**False-positive check:** comment out the `is_partner` lines and rerun the checkpoint. `partner-api` gets blocked: it uses python-requests too. Every library denylist needs an authenticated exception path for your own integrations.

**Discuss:** the attacker changed one string. How many JA4s would your denylist need to cover every `set_ciphers` value? What does that tell you about denylists?

---

## Round 2: 🛡️ UA ↔ TLS family ⚔️ 🗡️ a browser-shaped ClientHello (20 min)

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | Fill in `TODO (Round 2)` in `defenses/tls_family.py`; restart with `DEFENSE_LEVEL=2` | – |
| 🗡️ Re-run | `python attacks/round1_cipher_tweak.py` | `403`, `[L2] UA claims chromium but JA4 t13d0912h1_… matches no browser family` |
| ⚠️ Cost | `python tools/legit_traffic.py --no-browser` | `corporate-proxy` blocked: Chrome UA, but the TLS comes from a middlebox |
| 🗡️ Attack back | `python attacks/round2_impit_chrome.py` | `200`. impit's JA4 a+b is Chrome's exactly |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | tweak blocked, impit gets through, corporate-proxy ⚠️ documented |

**Discuss:**

1. From the server's side, how is `corporate-proxy` different from `round1_cipher_tweak`? (It isn't.) What would you do instead of a 403: challenge, step-up, or allow per network?
2. Why do Chrome, Firefox and Edge on iOS all map to `webkit`?
3. `tls_families()` can return two families for one JA4 (resumed Chrome = fresh Firefox). Why does the layer ask "is the TLS consistent with the claimed engine?" instead of "which browser is this?

## ☕ Break (10 min)

---

## Round 3: 🛡️ HTTP/2 fingerprint ⚔️ 🗡️ full impersonation (20 min)

| Step | Do | Expected |
|---|---|---|
| 👀 Look | Compare the impit and Chromium rows of `round0_recon.py`, HTTP/2 column | `2:0;4:6291456;5:16384;6:262144` vs `1:65536;2:0;4:6291456;6:262144` |
| 🛡️ Defend | Fill in `TODO (Round 3)` in `defenses/h2_fingerprint.py`; restart with `DEFENSE_LEVEL=3` | – |
| 🗡️ Re-run | `python attacks/round2_impit_chrome.py` | `403`, `[L3] HTTP/2 SETTINGS don't match chromium` |
| 🗡️ Attack back | `python attacks/round3_curl_cffi_chrome.py` | `200`: JA4 and HTTP/2 identical to real Chromium |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | impit blocked, curl_cffi gets through, no new false positives |

**Discuss:** `h2_core()` drops the PRIORITY section. Run `round0_recon.py` and look at Chromium's HTTP/2 value on a reused connection: why would an exact match break? curl_cffi's newest Chrome profile is 150 while stable is 156. Is that gap a detection rule, or a signal with a shelf life?

---

## Round 4: 🛡️ the browser claim needs browser proof ⚔️ 🗡️ a real browser (20 min)

| Step | Do | Expected |
|---|---|---|
| 👀 Look | View the source of https://localhost:8443/: the `engineSignals()` script | A TypeError message and `eval.toString().length` |
| 🛡️ Defend | Fill in `TODO (Round 4)` in `defenses/browser_proof.py`; restart with `DEFENSE_LEVEL=4` | – |
| 🗡️ Re-run | `python attacks/round3_curl_cffi_chrome.py` | `403`, `[L4] chromium TLS but no valid engine_proof cookie` |
| ⚠️ Cost | `python tools/legit_traffic.py` | `noscript-firefox` blocked on `/products` |
| 🗡️ Attack back | `python attacks/round4_playwright_chromium.py` | `200`: a real browser passes every network-layer check |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | everything but Playwright blocked; compare the req/s column |

**Discuss:** the attacker is now running a ~600 MB browser per worker instead of a ~40 MB script, and scrapes 5–7× slower. Is that a win? What catches the browser? (W2 Ch1 automation artifacts, W2 Ch3 behavior.)

---

## Debrief: fingerprints as an aggregation key (13 min)

```bash
python tools/fingerprint_report.py --minutes 120
```

```
JA4 a+b                   reqs  UAs  api%  page%  blocked%  HTTP/2 core
t13d1516h2_8daaf6152771    159    3   84%     8%        7%  1:65536;2:0;4:6291456;6:262144|15663105|m,a,s,p
t13d1812h1_85036bcba153     81    2  100%     0%       49%  http/1.1
t13d1516h2_8daaf6152771     60    1  100%     0%       33%  2:0;4:6291456;5:16384;6:262144|15597570|m,a,s,p
…
```

Real Chromium, curl_cffi and the Playwright bot all land in the first cluster. You can't block that JA4. You *can* see that it's 84% API calls and 8% page loads, and split it further by IP/ASN (W1 Ch3), session (W1 Ch5) or account (W2 Ch6). That's the idea behind Cloudflare's JA4 Signals.

**Scoreboard** (fill in with your checkpoint output):

| Level | Bots blocked (of 5) | Real-user requests blocked | Scoring p50 |
|---|---|---|---|
| 1 | 1 | 0/13 | |
| 2 | 2 | 3/13 (corporate-proxy) | |
| 3 | 3 | 3/13 | |
| 4 | 4 | 4/13 (+ noscript-firefox) | |

---

## Instructor: expected results

Verified on 2026-10-11 on Linux x86_64 (WSL2) with Python 3.12.15 (OpenSSL 3.5.9), Flask 3.1.3, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.1.4, requests 2.34.2, httpx 0.28.1, cryptography 50.0.2, fingerproxy v1.2.3, Playwright 1.63.0 (Chromium 153, Firefox 155.0), curl_cffi 0.16.3, impit 0.14.1 and the SQLite fallback. Every level was run with the reference solutions installed (`--catch-up`), after `tools/capture_fingerprints.py` (Round 1 step). The `docker compose` path is verified separately. The WebKit persona was not verified (missing system libraries).

| Attack ↓ / `DEFENSE_LEVEL` → | 0 | 1 | 2 | 3 | 4 | Reason at the first block |
|---|---|---|---|---|---|---|
| `round1_naive_requests` | 200 | **403** | 403 | 403 | 403 | `[L1] JA4 on library denylist: python-requests …` |
| `round1_cipher_tweak` | 200 | 200 | **403** | 403 | 403 | `[L2] UA claims chromium but JA4 t13d0912h1_f91f431d341e matches no browser family` |
| `round2_impit_chrome` | 200 | 200 | 200 | **403** | 403 | `[L3] HTTP/2 SETTINGS don't match chromium: 2:0;4:6291456;5:16384;6:262144\|15597570\|m,a,s,p` |
| `round3_curl_cffi_chrome` | 200 | 200 | 200 | 200 | **403** | `[L4] chromium TLS but no valid engine_proof cookie` |
| `round4_playwright_chromium` | 200 | 200 | 200 | 200 | 200 | – |
| `partner-api` | 200 | 200 | 200 | 200 | 200 | 403 from L1 if the `is_partner` exemption is missing |
| `corporate-proxy` ⚠️ | 200 | 200 | **403** | 403 | 403 | `[L2] UA claims chromium but JA4 t13d1912h1_121de08f9505 …` |
| `chromium-user`, `firefox-user` | 200 | 200 | 200 | 200 | 200 | – |
| `noscript-firefox` ⚠️ | 200 | 200 | 200 | 200 | **403** | `[L4] gecko TLS but no valid engine_proof cookie` |
| `webkit-user` | – | – | – | – | – | Not verified (needs `playwright install-deps webkit`). Expect a Safari UA on a non-Apple TLS stack, i.e. an L2 false positive |

Measured cost: scoring median 0.08–0.16 ms per request at every level. Attacker throughput varies run to run: 25–70 req/s for the HTTP clients and 5–10 req/s for Playwright including launch (sequential, Flask debug server), so the browser is 5–7× slower. Memory: ~600 MB RSS for a headless Chromium worker vs ~40 MB for curl_cffi.

TLS session resumption was verified with `tools/clienthello_dump.py` (resumed Chromium: `t13d1517h2_8daaf6152771`; resumed Firefox: unchanged a+b). It is not exercised through fingerproxy by the personas, because each persona opens a fresh browser.

**Things to watch for:**

- **Your OpenSSL ≠ ours.** On macOS or other distros, the library JA4s differ from the shipped list. That's why Round 1 starts with `tools/capture_fingerprints.py`. If `round1_naive_requests` isn't blocked at level 1, check `defenses/local_fingerprints.json`.
- **Browser updates.** When Playwright, Chrome or Firefox update, re-run `round0_recon.py` and compare JA4 a+b and the HTTP/2 core with `defenses/known_fingerprints.json`. A Firefox release that changes its cipher list breaks `firefox-user` at level 2. That's the lesson about allowlist maintenance, but fix the file before class.
- **impit and curl_cffi updates** change what they impersonate. The versions are pinned for a reason.
- **Students' own browsers** behind a corporate TLS-inspection proxy still show their real JA4 here, because localhost traffic doesn't go through the proxy.

## Bonus challenges

1. **Forge the proof.** Make `round3_curl_cffi_chrome.py` pass level 4 without a browser: fetch `/`, extract the nonce, POST the V8 signals to `/api/engine`. Then explain why W2 Ch2 obfuscates and rotates these challenges.
2. **Bypass the edge.** With `curl`, send `X-JA4-Fingerprint: t13d1516h2_8daaf6152771_806a8c22fdea` straight to `http://127.0.0.1:5000/api/products`. Why does this work? List three ways to make the origin trust only the edge (network isolation, mTLS, a signed header).
3. **Downgrade.** Run curl_cffi with `impersonate="chrome", http_version=CurlHttpVersion.V1_1`. Which layer catches it, and why? (Hint: compare JA4 part a.)
4. **JA4 is lossy.** `captures/impit-chrome.hex` has no `0x11ec` (ML-KEM) key share, while Chrome since 131 always sends one. JA4 doesn't hash supported groups. Sketch a Layer 2b that would need the raw ClientHello, and say where in the stack you'd compute it.
5. **Stale profiles.** Remove the Firefox 147 entry from `known_fingerprints.json` and run `round0_recon.py`. curl_cffi's firefox profile now fails Layer 2 while real Firefox 155 passes. How long would that difference last?
