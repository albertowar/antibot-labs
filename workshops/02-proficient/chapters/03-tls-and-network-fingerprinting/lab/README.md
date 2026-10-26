# Chapter 3 Lab: The ClientHello Arms Race

Starts from: `workshops/02-proficient/starter/` (contract 1.5). Adds: a TLS edge (fingerproxy) in front of the store, the JA4 module `defenses/ja4.py` and four TLS layers (Rounds 1 to 4), the `engine` collector, `/lab/tls/check`, five attackers and the real-client shoppers.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/browser_proof.py`
- `defenses/engine_signals.py`
- `defenses/h2_fingerprint.py`
- `defenses/ja4.py`
- `defenses/ja4_denylist.py`
- `defenses/known_fingerprints.json`
- `defenses/tls_family.py`
- `demo_site/ext/engine.py`
- `demo_site/ext/templates/tls/check.html`
- `demo_site/ext/templates/tls/engine.html`
- `demo_site/ext/tls_edge.py`
- `demo_site/static/js/tls_engine.js`
- `tools/capture_fingerprints.py`
- `tools/clienthello_dump.py`
- `tools/edge.py`
- `tools/fingerprint_report.py`
- `tools/get_fingerproxy.py`
- `tools/make_cert.py`
- `tools/personas_ch3.py`
- `tools/tls_edge.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** Round 0 plus 4 rounds of defend 🛡️ and attack 🗡️, then a debrief. See `workshops/02-proficient/chapters/03-tls-and-network-fingerprinting/chapter_03_content.md` (slides repo), §3.8. **Style: wire-it.** Each defense ships as a stub in `defenses/` with a `TODO (Round N)`; the finished version is in `solutions/roundN/`. `--catch-up` installs rounds 1..N (the check and `ladder.py`), and `--restore` puts your files back.

The W1 Ch4 attacker copies every header from DevTools, so nothing at the HTTP layer gives it away. In this lab you move the defense one layer down, to the TLS ClientHello and the HTTP/2 connection preface. Each round you write a few lines of a new layer, run the attacker that beats it, and measure two things: what the layer catches, and which real people it costs.

**This lab owns the series' TLS-fingerprinting module.** `defenses/ja4.py` (with `known_fingerprints.json`) is written here and copied unchanged by the W2 Ch9 capstone and by W3 Ch1, so it has no thresholds, point values or paths in it: those live in the four checks and in `defenses/policy.py`. `defenses/engine_signals.py` is the finished JavaScript half of Round 4.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool imports `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine. The TLS edge URL (`TLS_EDGE_URL`, default `https://localhost:8443`) and the ClientHello dump server (`DUMP_URL`) go through the same guard, and the attack scripts also refuse to skip the edge by targeting the store's own port. Do not remove those checks.
- Source addresses are rented from `data/world.json` (documentation ranges) and sent in `X-Lab-Client-IP`, which fingerproxy forwards like any other header. No proxy, no real address, no third-party site. Every shopper, key and account is synthetic.
- Disabling certificate verification (impit takes only a boolean) is acceptable only because the target is your own localhost edge with a self-signed certificate.
- **Outbound network:** one setup-time download. `tools/get_fingerproxy.py` fetches the pinned fingerproxy release (v1.2.3) from GitHub and deletes it if its SHA-256 does not match the checksum in the script. It is run by hand, once, and nothing touches the network during the rounds. Installing packages and browsers needs the internet too, as in every lab.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
 your own browser · attacks/*.py · the real-client shoppers
          │  TLS 1.3 (a real handshake)
          ▼
   fingerproxy :8443 ──HTTP + X-JA4-Fingerprint, X-HTTP2-Fingerprint──▶ the store :5000   ctx.edge.ja4_source == "measured"
                                                                         ▲
   the 40 Python shoppers ──────── X-Lab-JA4 (a claimed fingerprint) ────┘                 ctx.edge.ja4_source == "claimed"
```

```
lab/
  demo_site/ext/tls_edge.py          the bridge: fingerproxy's headers become ctx.edge.ja4 / ctx.edge.h2 (measured); /lab/tls/check
  demo_site/ext/engine.py            Round 4's collector: a script on every page + telemetry kind "engine"
  demo_site/static/js/tls_engine.js  the collector (plain JS): reports a TypeError message and eval's length, judges nothing
  defenses/                          ja4 (canonical, finished) · engine_signals (finished) · ja4_denylist · tls_family
                                     h2_fingerprint · browser_proof (your four stubs) · known_fingerprints.json · ladder.py · policy.py
  solutions/round1..4/defenses/      the finished check and the ladder as it stands after each round
  attacks/                           round0_recon · round1_naive_requests · round1_cipher_tweak · round2_impit_chrome
                                     round3_curl_cffi_chrome · round4_playwright_chromium · _common.py
  tools/                             edge.py · tls_edge.py · get_fingerproxy.py · make_cert.py · clienthello_dump.py
                                     capture_fingerprints.py · fingerprint_report.py · personas_ch3.py · checkpoint.py
```

The rest of the store (catalog, cart, checkout, accounts, the simulated edge, the decision log) is the W2 starter, unchanged. Its contract is `workshops/STORE_CONTRACT.md`.

**Why two languages.** Python's `ssl` module never exposes the raw ClientHello or the HTTP/2 SETTINGS frame, so the TLS edge has to be something else. We use [fingerproxy](https://github.com/wi1dcard/fingerproxy) (Go, Apache-2.0) as a **prebuilt, checksum-pinned binary**: you never write or compile Go. Everything you edit is Python.

**Measured and claimed fingerprints.** The contract keeps `X-Lab-JA4` as a *claimed* fingerprint until a TLS edge measures one. Here both exist, and the checks read `ctx.edge.ja4` either way:

- Everything with a real handshake (the five attackers, your browser, the real-client shoppers: a partner integration, a corporate proxy, a real Chromium and Firefox) goes through fingerproxy, and `tls_edge.py` turns what it measured into `ctx.edge.ja4`, `ctx.edge.h2` and `ctx.edge.ja4_source == "measured"`.
- The store's 40 shoppers are Python and cannot speak a browser's TLS, so each sends the fingerprint of the browser it plays as a claimed JA4 straight to the store (no HTTP/2 part: `h2_fingerprint` only judges measured fingerprints). They carry the chapter's false-positive accounting.

---

## Setup

Work through `PREWORK.md` first. This lab adds browsers, a certificate and the TLS edge binary:

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # one venv per chapter, see the root README
pip install -r requirements.txt -r requirements-browser.txt
python -m playwright install chromium firefox            # WebKit is optional, see Troubleshooting
python tools/make_cert.py                                # certs/tls.crt and tls.key for https://localhost (30 days)
python tools/get_fingerproxy.py                          # bin/fingerproxy v1.2.3, SHA-256 checked (the one download)
python tools/doctor.py
```

Keep three terminals open, all inside `lab/` with the venv active:

```bash
# terminal 1: the TLS edge. Leave it running all session
python tools/edge.py                                     # https://localhost:8443 -> http://127.0.0.1:5000

# terminal 2: the store. Rounds change the level live, no restarts
python demo_site/app.py

# terminal 3: attacks and tools
python attacks/round0_recon.py
```

Docker is optional: the default is SQLite plus an in-process Redis. To run the production-shaped stack (Redis 8.10 and PostgreSQL 18):

```bash
docker compose up -d --wait
REDIS_URL=redis://127.0.0.1:6379/0 DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop python demo_site/app.py
docker compose down -v                                   # when you are done
```

Switch levels without a restart (the checkpoint does it for you). A shell helper keeps the commands short:

```bash
level() { curl -s -X POST localhost:5000/lab/level -H 'Content-Type: application/json' -d "{\"level\": $1}"; }
level 2
```

| Level | Round | Adds | Module you finish |
|---|---|---|---|
| 0 | 0 | Nothing: every request is fingerprinted and logged, nobody is refused | – |
| 1 | 1 | A JA4 denylist of HTTP libraries (and: no fingerprint means the request skipped the edge) | `defenses/ja4_denylist.py` |
| 2 | 2 | The User-Agent's browser must match the TLS family | `defenses/tls_family.py` |
| 3 | 3 | The HTTP/2 preface must match the TLS family | `defenses/h2_fingerprint.py` |
| 4 | 4 | Browser TLS needs a JavaScript engine proof of the same family | `defenses/browser_proof.py` |

Round N runs at level N, and each level includes every level below it. Each layer scores 50 points (`policy.TLS_POINTS`), and `defenses/policy.py` maps the sum to a verdict:

| Score | Verdict | What the client gets |
|---|---|---|
| ≥ 40 | `block` | 403 |
| ≥ 20 | `monitor` | served, and logged |
| < 20 | `allow` | served |

From level 1 on, the store only serves requests that carry a TLS fingerprint. Browse it through **https://localhost:8443** (your browser warns about the self-signed certificate: click through for `localhost` only), not through port 5000.

Lab pages (loopback only, never scored):

| Endpoint | What it does |
|---|---|
| `/lab/tls/check` | What the edge measured for *your* connection: JA4, HTTP/2, families. `?format=json` for the data |
| `/whoami` | What the store resolved for you: address, `ja4`, `ja4_source` |
| `/lab/decisions` | The decision log: every request, with its signals and (in `extra`) its fingerprint |
| `/lab/scoreboard` | Bots stopped next to shoppers hurt |

> Every response carries `X-Lab-Verdict`, `X-Lab-Score` and `X-Lab-Signals` (for example `ja4_denylist:library_ja4`), and the attackers print them. That is for teaching only. In production, never tell a client which rule caught it.

**Troubleshooting**

| Problem | Fix |
|---|---|
| Port 5000 taken (macOS AirPlay Receiver) | `PORT=5050 python demo_site/app.py`; `PORT=5050 python tools/edge.py`; `export DEMO_URL=http://127.0.0.1:5050` in the shells that run tools |
| Port 8443 taken | `EDGE_PORT=8444 python tools/edge.py`, then `export TLS_EDGE_URL=https://localhost:8444` |
| `fingerproxy is not installed` | `python tools/get_fingerproxy.py` |
| No prebuilt fingerproxy for your platform | Go 1.21+: see the `go install` line in the docstring of `tools/get_fingerproxy.py` |
| `Refusing to target ...: these attacks go through the TLS edge` | `TLS_EDGE_URL` points at the store's port. Use `https://localhost:8443` (terminal 1) |
| Everything is a 403 `no_fingerprint` from level 1 | You are hitting the store directly (:5000). Use the edge (:8443) |
| `round1_naive_requests` is not blocked at level 1 | Your OpenSSL differs from ours: `python tools/capture_fingerprints.py` (Round 1), then retry |
| The certificate expired (it lasts 30 days) | `python tools/make_cert.py`, then restart the edge |
| `Executable doesn't exist` from Playwright | `python -m playwright install chromium firefox` inside this lab's venv |
| `webkit_user skipped` | Optional. `python -m playwright install webkit` (and `sudo python -m playwright install-deps webkit` on Linux), or ignore it |
| Browser warns about the certificate | Expected: it is self-signed. Click through for `localhost` only |
| Port 5432 or 6379 taken (another lab's containers) | `docker compose ls`, then `docker compose -p <name> down` |

---

## How to measure a round

Finish every round with a **checkpoint**:

```bash
python tools/checkpoint.py --round <N>                 # set level N, run every attacker next to the shoppers
python tools/checkpoint.py --round <N> --level <N-1>   # the same attackers against the level before
python tools/checkpoint.py --round <N> --catch-up      # install solutions/round1..N (the checks and ladder.py) first
python tools/checkpoint.py --restore                   # put your own files back (*.bak)
```

The checkpoint starts its own TLS edge on a free port, so it never collides with the one in terminal 1 (set `TLS_EDGE_URL` to make it use yours). It runs **every** attacker at the round's level, so you see what the current layers stop and what still gets through (the next round's problem), and it prints PASS or FAIL against explicit thresholds:

- **Attackers.** Each makes 10 requests to `/api/products`: `full` means at least 9 served, `blocked` at most 1. The table shows the first signal that stopped each one and its wall time.
- **The 40 shoppers** (claimed fingerprints, `tools/personas_ch3.py`). A refused shopper fails the round, except the `no_js` shopper from Round 4 on: it can never run the page's script, so it can never earn the engine proof. That is an accepted, measured cost, and the checkpoint fails if it is *not* refused.
- **The real clients** (real handshakes through the edge): `partner_api` (python-requests with a partner key), `corporate_proxy` (Python TLS behind a Chrome UA: a TLS-inspecting middlebox), `chromium_user` and `firefox_user` (real Playwright browsers) and, if installed, `webkit_user` (informational). Any refusal fails the round, except `corporate_proxy` from Round 2 on: it must show up as the layer's documented cost.
- **Defender cost.** The gate's time per request from the decision log (building `Ctx`, the enrichers, every check): the median must stay under 10 ms.

**Fell behind?** `python tools/checkpoint.py --round N --catch-up` installs `solutions/round1..N` over your files and keeps each of yours once as `.bak`. Run the checkpoint again; no restart is needed. `--restore` puts your files back.

---

## Round 0: Recon

| Step | Do | Expected |
|---|---|---|
| 👀 Look | `python attacks/round0_recon.py` | One row per client: JA4, HTTP version, family, HTTP/2 fingerprint |
| 👀 Look | Open https://localhost:8443/lab/tls/check in **your own** Chrome and Firefox | The page prints your JA4 and HTTP/2 fingerprint |
| 🔁 Repeat | Run `round0_recon.py` again | `playwright chromium`'s JA4 part c **changed**. `curl_cffi chrome`'s didn't |
| 🔬 Dig | Terminal 4: `python tools/clienthello_dump.py`. Terminal 3: `python attacks/round0_recon.py --dump` | `captures/*.hex`, one raw ClientHello per client |
| 🧮 Compute | `python -m defenses.ja4 captures/playwright-chromium.hex` | `t13d1516h2_8daaf6152771_806a8c22fdea` on every run, and it differs from the edge's part c |
| 🔁 Resume | Look at the `... resumed session` rows of the `--dump` output | Resumed Chromium is `t13d1517h2_8daaf6152771`: the same a+b as fresh Firefox |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | Every attacker served, 0 shoppers refused |

Fill in this table from the recon output (the reference answers follow):

| | python-requests | curl_cffi chrome | impit chrome | Playwright Chromium | Playwright Firefox |
|---|---|---|---|---|---|
| Cipher count (JA4_a) | | | | | |
| Extension count | | | | | |
| ALPN | | | | | |
| HTTP/2 SETTINGS | – | | | | |
| ClientHello bytes (`--dump`) | | | | | |

**Reference answers** (Python 3.12.15 on OpenSSL 3.5.9, Playwright 1.63 with Chromium 153 and Firefox 155, curl_cffi 0.16.3, impit 0.14.1):

| | python-requests | curl_cffi chrome | impit chrome | Playwright Chromium | Playwright Firefox |
|---|---|---|---|---|---|
| Cipher count (JA4_a) | 17 | 15 | 15 | 15 | 15 |
| Extension count | 12 | 16 | 16 | 16 | 17 |
| ALPN | `http/1.1` | `h2` | `h2` | `h2` | `h2` |
| HTTP/2 SETTINGS | – | `1:65536;2:0;4:6291456;6:262144` | `2:0;4:6291456;5:16384;6:262144` | `1:65536;2:0;4:6291456;6:262144` | `1:65536;2:0;4:131072;5:16384` |
| ClientHello bytes (`--dump`) | 1,531 | 1,725 | 782 | 1,823 | 1,891 |

Your numbers for `python-requests` depend on your OpenSSL (`python -c "import ssl; print(ssl.OPENSSL_VERSION)"`). On OpenSSL 3.0.2 the same script sends 18 ciphers, 12 extensions and **517** bytes (`t13d1812h1_85036bcba153_...`): OpenSSL 3.5 added the X25519MLKEM768 key share to its default ClientHello, which is most of the difference. Resumed sessions grow the ClientHello (Chromium 2,110 bytes, Firefox 2,462).

**Discuss:**

1. Why does the edge's JA4_c for Chromium change, while `defenses/ja4.py` gives the same value every time? *Look at the first signature algorithm in `python -m defenses.ja4 captures/playwright-chromium.hex`. Chromium puts a random GREASE value there. The JA4 spec says to ignore GREASE everywhere; fingerproxy v1.2.3 doesn't do that for signature algorithms, so its part c takes 16 values for one browser. That is why every layer in this lab keys on JA4 a+b.*
2. `playwright page.request` claims to be Chrome. What sent it? *Node.js, not the browser: Playwright's API client uses Node's TLS stack. Its JA4 (`t13d521100_...`, 52 ciphers, no ALPN) is the library signature of Node, and the table's last row of the recon shows it.*
3. Why is impit's ClientHello less than half the size of Chromium's? *Its `groups` extension has no `0x11ec` (X25519MLKEM768), the post-quantum key share that is over 1 KB. Compare `python-requests`: on OpenSSL 3.5 it sends that key share too, so it grew from 517 bytes (OpenSSL 3.0) to 1,531. Size is no longer a script signal; a missing key share on a "Chrome" is.*
4. A resumed Chrome connection adds `pre_shared_key`, so it has 17 extensions, just like a fresh Firefox. What does that mean for a rule that maps a JA4 to exactly one browser? *It breaks for every returning Chrome user. Ask whether the ClientHello is consistent with the claimed engine, not which browser sent it.*

---

## Round 1: 🛡️ JA4 denylist ⚔️ 🗡️ change one cipher string

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round1_naive_requests.py` (level 0) | 10/10 served. Every header is Chrome's |
| 🛡️ Defend | `python tools/capture_fingerprints.py`, then finish `TODO (Round 1)` in `defenses/ja4_denylist.py` and wire it in `defenses/ladder.py` | `local_fingerprints.json` holds *your* requests, httpx and urllib JA4s |
| 🛡️ Level | `level 1` | – |
| 🗡️ Re-run | `python attacks/round1_naive_requests.py` | 0/10: `ja4_denylist:library_ja4` |
| 🗡️ Attack back | `python attacks/round1_cipher_tweak.py` | 10/10: a new JA4 (`t13d0912h1_...`) the denylist has never seen |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | naive stopped, tweak served, 0 shoppers refused |

**False-positive check:** comment out the `is_partner` rule and rerun the checkpoint. `partner_api` is blocked: it uses python-requests too. Every library denylist needs an authenticated exception path for your own integrations.

**Discuss:** the attacker changed one string. How many JA4s would your denylist need to cover every `set_ciphers` value? What does that tell you about denylists? *Thousands (every subset and order of the cipher list), and the attacker picks the next one after you publish the last. A denylist is a record of what you have seen, never of what exists.*

---

## Round 2: 🛡️ UA ↔ TLS family ⚔️ 🗡️ a browser-shaped ClientHello

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | Finish `TODO (Round 2)` in `defenses/tls_family.py`, wire it in `ladder.py`, `level 2` | – |
| 🗡️ Re-run | `python attacks/round1_cipher_tweak.py` | 0/10: `tls_family:no_browser_family` (Chrome UA, a ClientHello no browser sends) |
| ⚠️ Cost | `python tools/checkpoint.py --round 2` | `corporate_proxy` blocked, with the same signal |
| 🗡️ Attack back | `python attacks/round2_impit_chrome.py` | 10/10. impit's JA4 a+b is Chrome's exactly |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | tweak stopped, impit served, `corporate_proxy` a documented cost |

**Discuss:**

1. From the server's side, how is `corporate_proxy` different from `round1_cipher_tweak`? *It isn't: a Chrome UA over a stack no browser uses. A 403 hurts an employee; a challenge, a lower rate limit or an allowance per authenticated enterprise network costs less.*
2. Why do Chrome, Firefox and Edge on iOS all map to `webkit`? *Apple requires every iOS browser to run WebKit and Apple's TLS. The UA says CriOS, FxiOS or EdgiOS, and a rule that expects BoringSSL behind "Chrome" blocks every iPhone.*
3. `ja4.tls_families()` can return two families for one JA4 (resumed Chrome = fresh Firefox). Why does the layer ask "is the TLS consistent with the claimed engine?" instead of "which browser is this?" *Because the second question has no answer for that JA4, and the first does.*

---

## Round 3: 🛡️ HTTP/2 fingerprint ⚔️ 🗡️ full impersonation

| Step | Do | Expected |
|---|---|---|
| 👀 Look | Compare the impit and Chromium rows of `round0_recon.py`, HTTP/2 column | `2:0;4:6291456;5:16384;6:262144` vs `1:65536;2:0;4:6291456;6:262144` |
| 🛡️ Defend | Finish `TODO (Round 3)` in `defenses/h2_fingerprint.py`, wire it, `level 3` | – |
| 🗡️ Re-run | `python attacks/round2_impit_chrome.py` | 0/10: `h2_fingerprint:h2_mismatch` |
| 🗡️ Attack back | `python attacks/round3_curl_cffi_chrome.py` | 10/10: JA4 and HTTP/2 identical to real Chromium |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | impit stopped, curl_cffi served, no new refusals |

**Discuss:** `ja4.h2_core()` drops the PRIORITY section. Why would an exact match break a reused Chromium connection? *fingerproxy appends every PRIORITY frame seen on the connection, so the string grows from `1:1:0:256` to `1:1:0:256,3:1:0:256`.* curl_cffi's newest Chrome profile is 150 while stable is 156. Is that gap a detection rule, or a signal with a shelf life? *A shelf life: it only helps while the profile differs on the wire from the current browser, until the profile updates, and a rule on it also catches real users who have not updated.*

---

## Round 4: 🛡️ the browser claim needs browser proof ⚔️ 🗡️ a real browser

| Step | Do | Expected |
|---|---|---|
| 👀 Look | View the source of https://localhost:8443/ and open `demo_site/static/js/tls_engine.js` | A TypeError message and `eval.toString().length`, posted to `/api/telemetry` |
| 🛡️ Defend | Finish `TODO (Round 4)` in `defenses/browser_proof.py`, wire it, `level 4` | – |
| 🗡️ Re-run | `python attacks/round3_curl_cffi_chrome.py` | 0/10: `browser_proof:no_proof` |
| ⚠️ Cost | `python tools/checkpoint.py --round 4` | The `no_js` shopper is refused on `/products` |
| 🗡️ Attack back | `python attacks/round4_playwright_chromium.py` | 10/10: a real browser passes every network-layer check |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | everything but Playwright stopped; compare the wall-time column |

**Discuss:** the attacker now runs a full browser per worker instead of a small script. Is that a win? What catches the browser? *It is a win in cost (memory, start-up, throughput) and nothing else. W2 Ch1's automation artifacts and W2 Ch5's behavior catch the browser; a TLS layer cannot.*

---

## Debrief: fingerprints as an aggregation key

```bash
python tools/fingerprint_report.py --minutes 120
```

```text
Last 120 min, 343 requests, 9 clusters

JA4 a+b                  src        reqs  UAs  api%  page%  blocked%  HTTP/2 core
t13d1516h2_8daaf6152771  claimed     161    3    0%    14%        0%  http/1.1
t13d2013h2_a09f3c656075  claimed      77    2    0%    14%        0%  http/1.1
t13d1517h2_8daaf6152771  claimed      37    1    0%    16%        3%  http/1.1
t13d1516h2_8daaf6152771  measured     27    2   81%     7%       37%  1:65536;2:0;4:6291456;6:262144|15663105|m,a,s,p
t13d1712h1_ab0a1bf427ad  measured     13    2  100%     0%       77%  http/1.1
t13d0912h1_f91f431d341e  measured     10    1  100%     0%      100%  http/1.1
t13d1516h2_8daaf6152771  measured     10    1  100%     0%      100%  2:0;4:6291456;5:16384;6:262144|15597570|m,a,s,p
t13d1517h2_8daaf6152771  measured      5    1   40%    20%        0%  1:65536;2:0;4:131072;5:16384|12517377|m,p,a,s
t13d1912h1_121de08f9505  measured      3    1  100%     0%      100%  http/1.1
```

The three `claimed` rows are the 40 Python shoppers (they never speak HTTP/2, hence `http/1.1`); the `measured` rows are real handshakes. Row 4 mixes real Chromium, curl_cffi and the Playwright bot: mostly API calls (81%), and a third of it blocked. Same JA4 a+b on rows 4 and 7, **different HTTP/2**: that is Round 3 in one line.

Real Chromium, curl_cffi and the Playwright bot land in the same JA4 a+b cluster. You can't block that JA4. You *can* see that one cluster is mostly API calls, and split it by IP/ASN (W1 Ch3), session (W1 Ch8) or account (W2 Ch6). That is the idea behind Cloudflare's JA4 Signals.

**Scoreboard** (fill in with your checkpoint output; ours is below):

| Level | Bots blocked (of 5 attackers) | People hurt (of 44) | Gate per request (median) |
|---|---|---|---|
| 1 | 1 | 0 | 1.4 ms |
| 2 | 2 | 1 (`corporate_proxy`) | 1.5 ms |
| 3 | 3 | 1 | 1.5 ms |
| 4 | 4 | 2 (+ `no_js`) | 1.6 ms |

---

## Expected results (self-check)

Generated from `python tools/verify.py --all --catch-up --markdown` (run `python tools/checkpoint.py --all --markdown` against your own store; the markdown output also holds one scoreboard per round) on 2026-10-14 on Linux x86_64 (WSL2) with Python 3.12.15 (OpenSSL 3.5.9), Flask 3.1.3, SQLAlchemy 2.1.4, requests 2.34.2, httpx 0.28.1, cryptography 50.0.2, fingerproxy v1.2.3, Playwright 1.63.0 (Chromium 153, Firefox 155.0), curl_cffi 0.16.3, impit 0.14.1, SQLite and the in-process Redis. Every round passed with the reference solutions installed, and every `--level N-1` "before" run reported the round's attacker getting through where it should. The Docker path (Redis 8.10, PostgreSQL 18) was run for the smoke test and Round 3: it passes, with the gate's median at 3.4 ms instead of 1.5 ms. The WebKit persona was **not** verified (this machine lacks WebKit's system libraries). Numbers are requests served out of 10 per attacker.

| Attacker ↓ / `DEFENSE_LEVEL` → | 0 | 1 | 2 | 3 | 4 | Signal at the first stop |
|---|---|---|---|---|---|---|
| `round1_naive_requests` | 10 | **0** | 0 | 0 | 0 | `ja4_denylist:library_ja4` (level 1) |
| `round1_cipher_tweak` | 10 | 10 | **0** | 0 | 0 | `tls_family:no_browser_family` (level 2) |
| `round2_impit_chrome` | 10 | 10 | 10 | **0** | 0 | `h2_fingerprint:h2_mismatch` (level 3) |
| `round3_curl_cffi_chrome` | 10 | 10 | 10 | 10 | **0** | `browser_proof:no_proof` (level 4) |
| `round4_playwright_chromium` | 10 | 10 | 10 | 10 | 10 | – |

People and cost, per level:

| | 0 | 1 | 2 | 3 | 4 | Reason |
|---|---|---|---|---|---|---|
| `corporate_proxy` blocked (of 3 requests) | 0/3 | 0/3 | 3/3 | 3/3 | 3/3 | `tls_family:no_browser_family`: the documented cost from Round 2 |
| `partner_api` blocked (of 3) | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | without the `is_partner` rule: 3/3 from level 1 |
| `chromium_user` blocked (of 4) | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |  |
| `firefox_user` blocked (of 4) | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |  |
| The 39 shoppers with JavaScript refused | 0 | 0 | 0 | 0 | 0 |  |
| The `no_js` shopper refused | no | no | no | no | yes | `browser_proof:no_proof` on `/products`: the accepted cost of Round 4 |
| **People hurt (of 44)** | 0 | 0 | 1 | 1 | 2 | `corporate_proxy` from level 2, + `no_js` at level 4 |
| Attacker requests stopped (of 52) | 0 | 10 | 20 | 30 | 40 | 10 per attacker, plus the browser's page load and proof POST |
| Gate per request, median / p95 (ms) | 1.28 / 3.37 | 1.44 / 3.61 | 1.54 / 3.81 | 1.51 / 3.70 | 1.55 / 3.82 | Ctx build + enrichers + every check, from the decision log |

Wall time per attacker (10 requests, Python start-up included): the four HTTP clients 0.2 to 0.4 s, Playwright Chromium 1.3 to 1.4 s (browser launch, page load and proof included), at every level. The browser is about four times slower per ten requests and holds a whole browser per worker (about 600 MB RSS against about 40 MB for curl_cffi in an earlier measurement, not repeated here).

**Things to watch for:**

- **Your OpenSSL is not ours.** On macOS, another distro or another Python build, `python-requests`, `httpx` and `urllib` have different JA4s from the shipped list (and OpenSSL 3.0 versus 3.5 is already two clients). That is why Round 1 starts with `tools/capture_fingerprints.py`. If `round1_naive_requests` is not stopped at level 1, check `defenses/local_fingerprints.json`: the checkpoint says so.
- **Browser updates.** When Playwright, Chrome or Firefox update, rerun `round0_recon.py` and compare JA4 a+b and the HTTP/2 core with `defenses/known_fingerprints.json`. A Firefox release that changes its cipher list fails `firefox_user` at level 2. That is the lesson about allowlist maintenance, but update the file before you publish the lab.
- **impit and curl_cffi updates** change what they impersonate. The versions are pinned for a reason.
- **TLS session resumption** was verified with `tools/clienthello_dump.py` (resumed Chromium: `t13d1517h2_8daaf6152771_a87ad97598a9`; resumed Firefox: unchanged a+b). The real-client shoppers open a fresh browser each, so they never resume through the edge.
- **Your own browser behind a TLS-inspecting proxy** still shows its real JA4 here, because localhost traffic does not go through the proxy.
- **Ports and the certificate.** Everything binds to 127.0.0.1; the self-signed certificate lasts 30 days.

## Bonus challenges

1. **Forge the proof.** Make `round3_curl_cffi_chrome.py` pass level 4 without a browser: fetch `/` with a cookie jar, read `data-nonce`, then POST `{"kind": "engine", "nonce": ..., "error_message": "Cannot read properties of null (reading 'f')", "eval_length": 33}` to `/api/telemetry` on the same session, then scrape. Why does it work, and why does W2 Ch4 obfuscate and rotate these challenges? *It works (verified: 403 `browser_proof:no_proof` before the POST, 200 after): the signals and the nonce are public, and curl_cffi's connection has Chromium's cipher hash, so the proof binds to it. A readable challenge is forgeable; W2 Ch4 makes the forgery expensive.*
2. **Bypass the edge.** With `curl`, send `X-JA4-Fingerprint: t13d1516h2_8daaf6152771_806a8c22fdea`, a matching `X-HTTP2-Fingerprint` (`1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:256|m,a,s,p`) and a Chrome UA straight to `http://127.0.0.1:5000/api/products`. Why does it pass level 3 (and fail level 4 until you add Bonus 1's proof)? The attack scripts refuse to do this; `curl` does not. List three ways to make the origin trust only the edge. *The origin cannot tell the edge's headers from yours. Fixes: network isolation (the origin listens only to the edge), mTLS between edge and origin, or a signed header the edge adds and the origin verifies. The store's claimed `X-Lab-JA4` has the same hole by design: it exists for the simulated shoppers.*
3. **Downgrade.** Run curl_cffi with `impersonate="chrome", http_version=CurlHttpVersion.V1_1`. Which layer catches it, and why? *Level 2, `tls_family:no_browser_family`: forcing HTTP/1.1 changes the ALPN it offers, so JA4 part a ends in `h1`, and no browser family lists that shape. Level 3's `http1_browser` rule is the backstop for a client that offers h2 and then falls back.*
4. **JA4 is lossy.** `captures/impit-chrome.hex` has no `0x11ec` (ML-KEM) key share, while Chrome since 131 always sends one. JA4 doesn't hash supported groups. Sketch a layer that would need the raw ClientHello, and say where in the stack you'd compute it. *At the TLS edge, which is the only place that sees the bytes: derive a feature such as `has_mlkem` and forward it as one more header, as fingerproxy does for JA4. Its shelf life is the same as any allowlist's.*
5. **Stale profiles.** Remove the Firefox 147 entry (`t13d1717h2_5b57614c22b0`) from `defenses/known_fingerprints.json` and run `round0_recon.py`. curl_cffi's firefox profile now fails Layer 2 while real Firefox 155 passes. How long would that difference last? *Until curl_cffi ships a newer Firefox profile, or the allowlist grows the old shape back; and the old shape stays valid for real users who have not updated.*
