# W4 Ch3 lab: Deterrence & Monetization for AI Crawlers

Starts from: `workshops/04-ai-era-bots/starter/` (contract 1.6). Adds: a published crawl policy, enforcement on crawlers you can name, a poisoned maze and an HTTP 402 pay-per-crawl exchange with a ledger, all on the Kestrel Outfitters store (`demo_site/ext/deterrence.py`, four defense modules you finish, W4 Ch2's Web Bot Auth verifier, two crawler operators and their key directories, seven crawler scripts, and nine clients a crawler defense must not hurt).

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/babble.py`
- `defenses/bot_identity.py`
- `defenses/crawl_policy.py`
- `defenses/crawler_registry.py`
- `defenses/enforce.py`
- `defenses/httpsig.py`
- `defenses/key_directory.py`
- `defenses/maze.py`
- `defenses/paywall.py`
- `defenses/web_bot_auth.py`
- `demo_site/ext/deterrence.py`
- `demo_site/ext/identity.py`
- `demo_site/ext/templates/crawl/entry.html`
- `tools/make_keys.py`
- `tools/mock_internet.py`
- `tools/personas_ch3.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** four rounds of defend 🔵 and attack 🔴, plus a bare-store Round 0. **Style: wire-it.** The four defense modules ship as stubs with `TODO (Round N)` markers and are wired into `defenses/ladder.py` already; an unfinished one is inert, so Round N's checkpoint fails until you finish it. Full versions are in `solutions/round1..4/`, and `--catch-up` installs rounds 1..N over your files (your own are kept as `.bak`; `--restore` puts them back). The chapter's content doc and deck are not written yet (`TODO.md`).

Every well-run crawler asks the same question of a site: *may I, and what does it cost?* This lab climbs the answers a site can give. Publish what you allow (Round 1). Refuse the crawlers that announce themselves and break the rules, or cannot prove who they are (Round 2). Make it expensive for the ones that do not announce themselves (Round 3). Charge the honest ones who will pay (Round 4). Each checkpoint measures what a rung stops **and** what it costs the people and services you want: 40 shoppers, five prefetching shoppers, three text-mode readers and the verified search crawler.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service URLs such as `REDIS_URL` and `MOCK_URL` too). The store's edge accepts the lab headers only from loopback.
- **Everything is simulated.** Source addresses are rented from `data/world.json` (RFC 5737 / 3849 documentation ranges) and sent in `X-Lab-Client-IP`, which the edge trusts only from loopback and only inside a pool. The two crawler operators, LabTrainBot and LabSearchBot, are synthetic. Their "published ranges" (`defenses/crawler_registry.py`) are slices of pools every lab already has (`cloud_vm`, `cloud_gcp`), so an operator's crawler is an ordinary cloud tenant exactly like the impostor who copies its User-Agent; the unpublished datacenter is `hosting_asn` and the stealth crawler rents `residential_proxy`. No real operator's endpoint, range or key is contacted or used.
- **The keys are yours.** The operators' Ed25519 keys are generated on your machine into `tools/fixtures/keys/` (gitignored) the first time anything asks for them (`python tools/make_keys.py`), and their key directories are served by `tools/mock_internet.py`, a side service the store starts on `127.0.0.1:5003` and `labnet` guards. A private key in git, even a synthetic one, trips secret scanners and teaches the wrong habit.
- The maze's drip delivery has a concurrency cap (`MAX_INFLIGHT` in `defenses/maze.py`). A tarpit with no cap is a denial-of-service amplifier against yourself; keep the cap if you change the maze.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages and, for the optional Docker path, container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

## Setup

Python 3.12+. Docker is optional: the default is SQLite plus an in-process Redis (fakeredis with Lua). One venv per chapter, inside `lab/`:

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python tools/doctor.py                                # READY?
python tools/make_keys.py                             # the operators' keys (also made on first use)
DEFENSE_LEVEL=1 python demo_site/app.py               # terminal 1: the store on 127.0.0.1:5000
python tools/checkpoint.py --round 1                  # terminal 2: both sides, one verdict
```

`PORT` changes the store's port; export `DEMO_URL=http://127.0.0.1:<port>` for the tools to match. Defense modules reload on change (`LAB_RELOAD=1`), so a saved edit takes effect on the next request. The extension in `demo_site/ext/` does not reload, and `DEFENSE_LEVEL` only changes live through the checkpoint (`POST /lab/level`), which sets the level for the round. No restart is needed between rounds.

`python tools/verify.py --round N` runs the same checkpoint with the store in-process on a free port, which is how the expected results below were produced.

**Fell behind?** `python tools/checkpoint.py --round N --catch-up` installs the reference modules for rounds 1..N over yours (each of yours is kept once as `.bak`). `python tools/checkpoint.py --restore` puts yours back.

## Rounds

| Round | `DEFENSE_LEVEL` | 🔴 Attack | 🔵 You edit | The question |
|---|---|---|---|---|
| 0 | 0 | `round1_compliant_crawler`, `round1_ignoring_crawler` | nothing | What does a bare store give a crawler? Everything, and nobody asks who it is |
| 1 | 1 | the same two | `defenses/crawl_policy.py`: `robots_lines()` and `response_headers()` (robots.txt groups, AIPREF `Content-Usage`, Content-Signal, the RSL licence) | Does a published preference govern anyone who does not read it? |
| 2 | 2 | `round1_ignoring_crawler`, then `round2_stealth_crawler` (Chrome UA, residential egress) | `defenses/enforce.py`: `evaluate()` | Why does the honest crawler get refused while the stealth one walks in? |
| 3 | 3 | `round3_stealth_crawler`, then `round3_maze_aware_crawler` | `defenses/maze.py`: `entry_link()` and `tagged()` | How much does a poisoned maze cost a crawler, and you? Who walks around it? |
| 4 | 4 | `round4_paying_crawler` and `round4_free_path_leak` | `defenses/paywall.py`: `evaluate()` (the 402 exchange) and `PAID_PATHS` | Who pays, and which route leaks the catalogue for free? |

A round passes when that round's crawler is held under its ceiling (or, in Round 4, is billed exactly what it took) **and** no shopper, prefetcher, reader or search-crawler request was refused, paywalled, billed or served a decoy. The checkpoint also prints the defender's cost: gate time per shopper request, and the maze's generation time, bytes and cap hits.

### What is given and what you write

| Round | Stub you finish (`defenses/`) | Given (do not edit) |
|---|---|---|
| 1 | `crawl_policy.py`: `robots_lines()`, `response_headers()` | `effective_rules()`, `signals()`, `rsl_xml()`, `is_disallowed()`, `exempt()` and the CHECK that logs violations |
| 2 | `enforce.py`: `evaluate()` | the CHECK that builds its inputs from the identity |
| 3 | `maze.py`: `entry_link()`, `tagged()` | `_token()`, `record_hit()`, `render()`, the CHECK; `babble.py` (the bigram generator) |
| 4 | `paywall.py`: `evaluate()`, `PAID_PATHS` | the CHECK, `Offer` helpers, `_parse()` |
| | | `bot_identity.py`, `crawler_registry.py`: who is this request really from |
| | | `web_bot_auth.py`, `httpsig.py`, `key_directory.py`: W4 Ch2's verifier, byte for byte (`shared.json`) |

### How a decoy page or a 402 gets out of a store whose verdicts are closed

The gate's verdict set is fixed: `allow`, `monitor`, `challenge`, `block`, `rate_limit`, `deceive`. A decoy page, a `402 Payment Required` and a "charged" 200 are none of them. So:

- `enforce` is a real `block` verdict from the ladder (a 403 the gate serves).
- `maze` and `paywall` are ordinary checks that record what they decided in `ctx.attrs` (`maze`, `paywall`) and return no verdict.
- `demo_site/ext/deterrence.py` registers a `before_request` **after** the gate's. It sees only what the gate allowed, reads `ctx.attrs`, and returns its own `Response`: the decoy page, or the 402 with `crawler-price`; or lets a charged page through and stamps `crawler-charged`, writes the ledger (`lab:ledger:*`, Redis) when the answer is a 200.
- It sets `g.outcome` to `mazed`, `paywalled` or `charged`. Since contract 1.6 the scoreboard gives each custom outcome its own column instead of folding it into `other`, so the table under the standard scoreboard reads: `requests · served · blocked · paywalled · charged · mazed`.

The identity the checks share (`bot_identity.identify(ctx)`) is computed once per request and cached in `ctx.attrs["identity"]`: a valid, trusted Web Bot Auth signature wins; otherwise a declared User-Agent from a published range is verified weakly; a declared User-Agent that proves nothing is *declared but unverified*.

## Round by round

**Round 0 (bare store).** `python tools/checkpoint.py --round 0`. Both LabTrainBot crawlers take the whole catalogue. This is the baseline every other row is compared with.

**Round 1: publish the policy.** Finish `robots_lines()` (a `Disallow` for the maze prefix in the catch-all group, the Content-Signal, Content-Usage and License lines, then one group per declared crawler) and `response_headers()` (`Content-Usage` and a `Link: <...>; rel="license"` header). Check by hand: `curl -s localhost:5000/robots.txt`, `curl -sI localhost:5000/`, `curl -s localhost:5000/license.xml`. The compliant crawler reads its group and leaves with nothing; the ignoring crawler (same User-Agent, from an unpublished datacenter, never reads robots.txt) still takes everything, and every request it makes is logged as `crawl_policy:robots_violation`. A preference is a contract for the crawlers that read it.

**Round 2: enforce on what you can name.** Finish `evaluate()`: refuse a declared crawler that cannot prove who it is, a verified one whose purpose the policy denies, and one in a Disallowed path; allow everyone else. The ignoring crawler is refused on its first request. The stealth crawler (a current Chrome User-Agent, a residential pool, no robots.txt) takes the catalogue: nothing in an identity-keyed policy can name it. Look at the readers: `Lynx` makes `ctx.ua.is_library` true (its `libwww` token), so a rule keyed on the UA family would have refused them. Keep `evaluate()` on the declared token.

**Round 3: make the careless pay.** Finish `entry_link()` (the hidden link, unique per client) and `tagged()` (an address that fetched `TAG_AFTER` decoy pages). The stealth crawler follows every `<a href>`, including the hidden one; each decoy page links to twenty more, and a tagged address gets decoys where the catalogue was. The maze-aware crawler never follows a hidden link, reads robots.txt as a list of trap hints, caps depth and bails on repetitive text. It takes the catalogue and is never tagged. Deterrence taxes the careless.

**Round 4: charge the honest.** Finish `evaluate()` (the 402 exchange, step by step in its docstring) and extend `PAID_PATHS`. Watch the leak first: `python attacks/round4_free_path_leak.py` rebuilds the catalogue for $0.00 from the JSON API, the bulk feed and the RSS feed because only the HTML pages were priced. Then add every carrier. The paying crawler is billed to the cent; the store's ledger (`curl -s localhost:5000/lab/crawl/stats`) must equal its own tally. Try `python attacks/round4_paying_crawler.py --max 0.005`: a crawler whose budget is below your price walks away, which is what most 402s meet in the wild.

## Expected results (self-check)

Generated from `python tools/verify.py --all --catch-up --markdown` (against your own store: `python tools/checkpoint.py --all --markdown`) and one `--round N --level N-1 --catch-up` run per round for the "before" column, on 2026-10-15 on Linux x86_64 (WSL2) with Python 3.12.15, Flask 3.1.3, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.1.4, redis 8.1.0, fakeredis 2.39.0, requests 2.34.2, httpx 0.28.1, cryptography 50.0.2, SQLite and the in-process Redis. Every round passed with the reference modules installed; the shoppers hurt were 0 of 40 and the clients you keep were hurt 0 times in every round. `--level` runs report numbers but do not judge (and so print no gate cost). "Products" are product *records* taken (a product page, a JSON item or a feed item) out of 120; a crawler is deterministic except for its request count, which varies by a request or two when its address order shifts.

### Before and after

| Round | Crawler | Before (level N-1): products / requests | After (level N): products / requests | What the scoreboard columns say at level N |
|---|---|---|---|---|
| 1 | compliant LabTrainBot | 120 / 142 | **0 / 1** (reads robots.txt and the licence, leaves) | served 2, blocked 0 |
| 1 | ignoring LabTrainBot | 120 / 141 | 120 / 141 (nothing stops it yet) | served 141; 140 robots violations logged |
| 2 | ignoring LabTrainBot | 120 / 141 | **0 / 1** | blocked 1 |
| 2 | stealth Chrome crawler | 120 / 141 | 120 / 141 (the limit of identity) | served 141 |
| 3 | stealth crawler, unchanged | 120 / 141 | **23 / 300** (15 pages served, the rest decoys) | **mazed 285** of 300 requests (95%) |
| 3 | maze-aware stealth crawler | 120 / 142 | 120 / 142 (the limit of deterrence) | served 142, mazed 0 |
| 4 | paying LabTrainBot (signed) | 0 / 3 (level 3 denies `ai-train`, so it reads robots.txt and leaves) | **120 / 283**, billed $1.39 | **paywalled 139, charged 139**, served 5 (the policy documents) |
| 4 | free-path leak (signed) | 0 / 24 (all 24 refused by `enforce`, which denies the purpose) | **0 / 24** (every carrier priced) | **paywalled 24** |

With `PAID_PATHS` left at `("/products", "/product/")` the leak rebuilds all 120 records for $0.00 in 24 requests (Round 4 then fails: "a carrier is not behind the paywall"). The ledger equals the paying crawler's own bill to the cent ($1.39 for 139 charged requests: 120 product pages and 19 listing pages).

Defender cost, from the decision log (median gate time of a shopper request while the crawlers run, in-process Redis, limit 25 ms): Round 0 1.42 ms (p95 3.30), Round 1 1.48 (3.42), Round 2 1.46 (3.38), Round 3 1.97 (3.93), Round 4 2.01 (3.86). The maze costs 0.67 ms to generate a decoy page and about 2.8 KB to send it (285 decoys, 784 KB; the concurrency cap was never hit because the crawler is serial).

#### Round 0: bare store: nobody asks who is crawling

| actor | requests | served | blocked | paywalled | charged | mazed |
|---|---|---|---|---|---|---|
| bot:compliant | 142 | 142 | 0 | 0 | 0 | 0 |
| bot:ignoring | 141 | 141 | 0 | 0 | 0 | 0 |
| 9 clients you keep (prefetch, readers, search) | 95 | 95 | 0 | 0 | 0 | 0 |
| shoppers (all) | 240 | 240 | 0 | 0 | 0 | 0 |

Bots stopped: **0/283** requests · shoppers hurt: **0/40** people (0/240 requests stopped, including challenges they then solved) · purchases: {'human': 40} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}


#### Round 1: L1 published policy: robots.txt, AIPREF, Content-Signal, RSL

| actor | requests | served | blocked | paywalled | charged | mazed |
|---|---|---|---|---|---|---|
| bot:compliant | 2 | 2 | 0 | 0 | 0 | 0 |
| bot:ignoring | 141 | 141 | 0 | 0 | 0 | 0 |
| 9 clients you keep (prefetch, readers, search) | 95 | 95 | 0 | 0 | 0 | 0 |
| shoppers (all) | 240 | 240 | 0 | 0 | 0 | 0 |

Bots stopped: **0/143** requests · shoppers hurt: **0/40** people (0/240 requests stopped, including challenges they then solved) · purchases: {'human': 40} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

- robots violations logged: ignoring crawler 140, compliant crawler 0

#### Round 2: L2 enforcement on crawlers you can name

| actor | requests | served | blocked | paywalled | charged | mazed |
|---|---|---|---|---|---|---|
| bot:ignoring | 1 | 0 | 1 | 0 | 0 | 0 |
| bot:stealth | 141 | 141 | 0 | 0 | 0 | 0 |
| 9 clients you keep (prefetch, readers, search) | 95 | 95 | 0 | 0 | 0 | 0 |
| shoppers (all) | 240 | 240 | 0 | 0 | 0 | 0 |

Bots stopped: **1/142** requests · shoppers hurt: **0/40** people (0/240 requests stopped, including challenges they then solved) · purchases: {'human': 40} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}


#### Round 3: L3 poisoned maze: hidden link, decoys, tagging, capped drip

| actor | requests | served | blocked | paywalled | charged | mazed |
|---|---|---|---|---|---|---|
| bot:aware | 142 | 142 | 0 | 0 | 0 | 0 |
| bot:naive | 300 | 15 | 0 | 0 | 0 | 285 |
| 9 clients you keep (prefetch, readers, search) | 95 | 95 | 0 | 0 | 0 | 0 |
| shoppers (all) | 240 | 240 | 0 | 0 | 0 | 0 |

Bots stopped: **0/442** requests · shoppers hurt: **0/40** people (0/240 requests stopped, including challenges they then solved) · purchases: {'human': 40} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

- maze: the naive crawler spent 95% of its 300 requests on decoys (285 in the scoreboard's mazed column); the maze-aware crawler got 100%
- cost  285 decoy pages, 0.67 ms/page to generate, 784 KB served, concurrency cap hit 0x

#### Round 4: L4 pay-per-crawl over HTTP 402, every carrier behind it

| actor | requests | served | blocked | paywalled | charged | mazed |
|---|---|---|---|---|---|---|
| bot:leak | 24 | 0 | 0 | 24 | 0 | 0 |
| bot:paying | 283 | 5 | 0 | 139 | 139 | 0 |
| 9 clients you keep (prefetch, readers, search) | 95 | 95 | 0 | 0 | 0 | 0 |
| shoppers (all) | 240 | 240 | 0 | 0 | 0 | 0 |

Bots stopped: **0/307** requests · shoppers hurt: **0/40** people (0/240 requests stopped, including challenges they then solved) · purchases: {'human': 40} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

- ledger: $1.39 for 139 charged requests against the crawler's own bill $1.39; 139 requests met a 402 first; ledger by operator {'total': 1.39, 'trainbot.example': 1.39}

## Run it in Docker (optional)

The default needs no Docker. To rehearse on the production-shaped stack (Redis 8.10 and PostgreSQL 18):

```bash
pip install 'psycopg[binary]==3.3.6'                  # the one dependency only this path needs (commented out in requirements.txt)
docker compose -p w4ch3 up -d --wait
REDIS_URL=redis://127.0.0.1:6379/0 DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop python demo_site/app.py
docker compose -p w4ch3 down -v                       # when you are done
```

**What ran on this path (2026-10-15):** Redis 8.10.2 and PostgreSQL 18.6 from `docker-compose.yml` (project `w4ch3`, ports bound to `127.0.0.1`), `python tools/verify.py --smoke`, then `--round 3 --catch-up` and `--round 4 --catch-up`: all pass with the same counts as above (naive crawler 23 of 120 products and 285 of 300 requests mazed; paying crawler 120 of 120, 139 charged, ledger $1.39 equal to its bill; 0 of 40 shoppers hurt). The gate figure rises to a median of 4.38 ms in Round 3 and 4.59 ms in Round 4 (p95 9.86 and 11.63 ms) because every request makes several Redis round trips (the nonce cache, the key-directory cache, the session); the checkpoint allows 250 ms against a real Redis instead of 25 ms. Round 1, Round 2 and the shoppers-only paths were not run on Docker.

## What this does not teach

- **The stealth crawler is depth-first.** It follows the most recently discovered link first, like a recursive scraper, so it meets the hidden link early. A breadth-first crawler with a big enough budget takes the whole catalogue before the maze can tag its addresses (measured here: 100% coverage, 55% of its 300 requests in the maze, with the same crawler and budget). The maze is a tax on careless crawlers, not a wall.
- **Tags are per address.** The stealth crawler rotates 24 addresses, so each earns its tag separately; a large rotating pool dilutes this, which is why the budget burn matters more than the tag and why production keys on fingerprints too (W2).
- **CSS-hidden links are not hidden from everyone.** A text-mode browser does not apply CSS, and `aria-hidden` is for screen readers; a Lynx user *can* see "Catalogue archive". The readers here do not click it (nobody mid-purchase does), but a maze link on a real shop needs a design review, not just `display:none`.
- **Coverage counts records, not names.** A product counts when the crawler holds its record: its page, a JSON item or a feed item. A listing or the sitemap names products; it does not hand them over. The footer's `/feed.xml` therefore gives any crawler 20 records before the maze can act, which is why Round 3 allows the naive crawler up to 25%.
- **The ledger is a toy.** It is one Redis counter per operator. Real pay-per-crawl needs signed receipts, settlement and dispute handling, and a verified identity strong enough to bill (that is why Round 2 sits in front of Round 4).
- The robots.txt this store prints begins with `Allow: /` in its catch-all group; first-match parsers such as Python's `urllib.robotparser` honour it before a later `Disallow`, RFC 9309 matches the longest rule. The crawler scripts read their own group, which has no such line.
- A real deployment would also use **TLS and behavior signals** against the stealth crawler (W2) and would not tell a client which check it failed; the decision log's reasons are for teaching.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Store not reachable on http://127.0.0.1:5000` | Start it: `python demo_site/app.py`, or use `python tools/verify.py --round N`, which starts its own |
| Round 1 `FAIL: compliant: expected blocked` | `robots_lines()` still returns `[]`: finish it, or `--catch-up` |
| A signed crawler is treated as unverified | The operators' websites must be up before the first signed request: a failed directory fetch is negative-cached for five minutes. Check `curl -s $MOCK_URL/stats` (the store prints `MOCK_URL` at start), then `curl -s -X POST localhost:5000/lab/reset` to clear the cache |
| `Address already in use` on 5003 | Another process holds the mock port; the store falls back to a free one and sets `MOCK_URL`, but a standalone `python tools/mock_internet.py` does not. Stop the old one, or set `MOCK_PORT` |
| `.bak` files after a run | `python tools/checkpoint.py --restore` puts your files back and removes them |
| Port 5000 busy | `PORT=8099 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:8099` |
