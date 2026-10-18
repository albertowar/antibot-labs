# W4 Ch2 Lab: Verified Bot Identity

Starts from: `workshops/04-ai-era-bots/starter/` (contract 1.6). Adds: the crawler gate and its identity layers (reverse DNS, published ranges, Web Bot Auth), the mock internet that plays DNS, operator range files and agent key directories, five attack scripts, and a cohort of eight genuine crawlers next to the starter's 40 shoppers.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/crawler_gate.py`
- `defenses/httpsig.py`
- `defenses/ip_ranges.py`
- `defenses/key_directory.py`
- `defenses/operators.py`
- `defenses/rdns.py`
- `defenses/resolver.py`
- `defenses/ua_claims.py`
- `defenses/web_bot_auth.py`
- `demo_site/ext/identity.py`
- `tools/fixtures/dns_zones.json`
- `tools/fixtures/ranges/anthropic/bots.json`
- `tools/fixtures/ranges/bing/bingbot.json`
- `tools/fixtures/ranges/google/common-crawlers.json`
- `tools/fixtures/ranges/google/user-triggered-fetchers.json`
- `tools/fixtures/ranges/openai/chatgpt-user.json`
- `tools/fixtures/ranges/openai/gptbot.json`
- `tools/fixtures/ranges/openai/searchbot.json`
- `tools/fixtures/ranges/perplexity/perplexitybot.json`
- `tools/make_keys.py`
- `tools/mock_internet.py`
- `tools/personas_ch2.py`
- `tools/verify_real.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** 5 rounds of defend 🔵 and attack 🔴 (one checkpoint each, `--round 1` to `--round 5`), plus two debriefs. **Style: wire-it.** Three defense modules ship as stubs with `TODO (Round N)`; the finished versions are in `solutions/roundN/`. `python tools/checkpoint.py --round N --catch-up` installs rounds 1..N and `--restore` puts your files back. See `../chapter_02_content.md`, §2.5.

You run a store that wants search engines and AI crawlers to index it, and that gives verified crawlers a *fast lane*: 600 requests a minute instead of the 30 every anonymous client gets. Scrapers want that lane. In every round you play the scraper that takes it, then the defender who closes the door, and you measure both what the impostor got and which genuine crawlers your new check wrongly throttled.

The store is the Workshop 4 starter, Kestrel Outfitters, unchanged: 120 products behind a catalog, a sitemap, a feed and a `robots.txt`. Everything this chapter adds sits in `defenses/`, `demo_site/ext/identity.py` and `tools/`.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine before a single request is sent. The mock internet (`MOCK_URL`) is a side service and goes through the same guard: `labnet.target("MOCK_URL", …)` in the defenses and attacks, `labnet.require_local_env("MOCK_URL")` in `tools/mock_internet.py`. It binds 127.0.0.1 and answers only loopback callers. Do not remove those checks.
- **Everything is simulated.** Source addresses are rented from `data/world.json` (RFC 5737 documentation ranges) and sent in `X-Lab-Client-IP`, which the store's edge trusts only from loopback and only inside a pool. The operators and the attacker rent from pools that already exist (`cloud_gcp`, `cloud_vm`, `hosting_asn`): a crawler operator is an ordinary tenant of an ordinary cloud, exactly like the attacker who impersonates it, so identity is proven by DNS, a published list or a signature, never by the pool. Hostnames are the real suffixes operators document (`googlebot.com`, `search.msn.com`) on synthetic addresses; the reverse zone and the range files are answered by the mock, from `tools/fixtures/`. No operator's real endpoint, range or key is contacted or used.
- **Keys are generated, not committed.** The Ed25519 keypairs (the synthetic `chatgpt.com` operator and the attacker's `attacker.example`) are created on first use by `tools/make_keys.py` into `tools/fixtures/keys/`, which is gitignored. They exist only on your disk and mean nothing anywhere else. In production the private key never leaves the operator's signing service.
- **Outbound network:** none during the rounds. The one exception is the optional bonus `tools/verify_real.py`, which is off unless you run it: it resolves an address from **your own** logs and downloads an operator's published range file. It sends nothing to the operator's crawler or to the address, and it is listed in `scripts/check_labs.py`'s outbound allowlist for that reason. Do not point it at addresses from logs you do not own. Setup also needs the internet to install packages and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  README.md              this file
  requirements.txt       pinned deps (Python 3.12+). Docker optional.
  defenses/              the gate and its identity layers; you implement the TODOs
    operators.py         what each operator documents: UA tokens, rDNS suffixes, range files (ships done)
    ua_claims.py         L0  User-Agent -> claimed operator (ships done: it is the hole)
    rdns.py              L1  PTR suffix check   L2  forward-confirmed rDNS + cache    (Rounds 1-2)
    ip_ranges.py         L3  published range files, TTL refresh, entitlement scoping  (Round 3)
    httpsig.py           RFC 9421 signer/verifier, JWK thumbprints, signed directory (ships done, shared)
    key_directory.py     bounded, cached, origin-bound fetch of an agent's key directory (ships done, shared)
    web_bot_auth.py      L4  verify a Web Bot Auth signature   L5  trust policy, window, nonce (Rounds 4-5)
    resolver.py          DNS client: the mock internet (ships done)
    crawler_gate.py      the one check at LADDER[0]; ties the layers together by DEFENSE_LEVEL (ships done)
    ladder.py            LADDER = {0: [crawler_gate.CHECK]}; policy.py  the lane budgets and the trust list
  demo_site/ext/identity.py   starts the mock internet, exposes the raw query string, X-Lane header
  attacks/               round*_*.py, one per attack step; _common.py holds the helpers
  solutions/round1..5/   the finished module each checkpoint installs (rdns, ip_ranges, web_bot_auth)
  tools/
    mock_internet.py     DNS zones, operator range files, agent key directories, the attacker's hosting panel
    personas_ch2.py      the cohort: the 40 shoppers plus 8 genuine crawlers (the false-positive set)
    checkpoint.py        ROUNDS and thresholds; --catch-up, --restore, --all --markdown
    make_keys.py         generates the lab's Ed25519 keypairs at setup (gitignored)
    verify_real.py       OPTIONAL, networked: FCrDNS + range check of an address from your own logs
    fixtures/            dns_zones.json, ranges/<operator>/*.json, keys/ (generated)
```

**Why Python only.** Everything here is server-side verification: DNS lookups, prefix matching, Ed25519 signatures. No browser, no JavaScript. `cryptography` does the signing; the RFC 9421 signature base is built by hand in `httpsig.py` so you can read the exact bytes an agent signs.

## Setup

Work through `onboarding/setup/PREWORK.md` first. This lab needs nothing beyond the starter's packages plus `cryptography` (and `dnspython` for the bonus tool):

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # one venv per chapter, see the root README
pip install -r requirements.txt
python tools/doctor.py
python demo_site/app.py                                  # terminal 1: the store on :5000; it starts the mock internet on :5001
python attacks/round1_ua_spoof.py                        # terminal 2: the honest scraper gets 30 pages, the Googlebot impostor 120
```

The store starts the mock internet on a thread. To run it in its own terminal instead (the two-process shape, and what a production verifier looks like), start `python tools/mock_internet.py` first and the store with `MOCK_AUTOSTART=0`. A busy port 5001 falls back to a free one; scripts in other terminals find it with `GET /lab/identity`.

Docker is optional: the default is SQLite plus an in-process Redis. To run the production-shaped stack (Redis 8.10 and PostgreSQL 18):

```bash
docker compose up -d --wait
REDIS_URL=redis://127.0.0.1:6379/0 DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop python demo_site/app.py
docker compose down -v                                   # when you are done
```

**Defense levels.** The checkpoint sets `DEFENSE_LEVEL` live (`POST /lab/level`), so the store never restarts between rounds. Each level includes every level below it, and you finish a stub, save (the store reloads `defenses/` on the next request), and measure.

| Level | Adds | Module | Beats |
|---|---|---|---|
| 0 | nothing: the User-Agent is believed | `ua_claims` | — |
| 1 | reverse DNS, PTR suffix only | `rdns` | Round 1 UA spoof |
| 2 | forward-confirmed reverse DNS + verdict cache | `rdns` | Round 2 forged PTR |
| 3 | operator range files with TTL refresh + entitlement scoping | `ip_ranges` | Round 3 shared-infra squat; admits GPTBot/ClaudeBot/PerplexityBot |
| 4 | Web Bot Auth signature verification | `web_bot_auth.verify` | nothing yet: admits the signed agent, and anyone with a key |
| 5 | trust policy, freshness window, nonce replay cache | `web_bot_auth.trust` | Round 4 self-signed agent and replay |

**Why one check, not one per level.** Every request must end in a budget decision, and that decision has to come after every proof the level can make. The ladder runs lower levels first, so a budget check cannot sit at one level; `crawler_gate.py` is one check at `LADDER[0]` that branches on the level, and what you write in each round are the layers it calls. Nothing to wire in `ladder.py`.

**Lanes** (`defenses/policy.py`, `RATE_LIMITS`): anonymous 30 requests, then 0.5 a second, per egress address; verified 600, then 10 a second, per identity. Over budget is a `429` and a forged, tampered or replayed signature is a `403`. The gate applies to clients that are not a mainstream browser (a library, a bot token, no User-Agent, signature headers) and to anyone claiming an operator: the starter's carrier-NAT shoppers share two addresses and would be hurt by a 30-a-minute budget for nothing. The price is W4 Ch1's lesson: a scraper dressed as Chrome never meets this gate. The responses carry `X-Lane: verified | anonymous`, and the decision log carries the reasons (`extra.reasons`); in production you never tell a client which check it failed.

## How to measure a round

Next to the attacks run the starter's 40 shoppers and eight genuine crawlers that are exactly what they say they are (`tools/personas_ch2.py`: Googlebot, bingbot, Applebot, GPTBot, a GPTBot on a prefix OpenAI added after your snapshot, ClaudeBot, PerplexityBot and the signed ChatGPT agent). The checkpoint prints:

- 🔴 **Impostors**: how many of the 120 product pages each took in one burst and how many of those came in the verified lane. *Held* means none from the fast lane and no more than the anonymous budget (30 plus the trickle that refills while it runs; the checkpoint allows 45).
- 🕷 **Genuine crawlers**: which of the eight got all 60 of their pages. A real crawler held to 30 is a *false positive*; the checkpoint lists, per level, the ones it expects to be throttled and fails if the set differs.
- 👤 **Shoppers hurt**: people (not requests) whose last request was a stop and who bought nothing. Must be 0 of 40.
- 💸 **Gate cost**: median and p95 gate time of every request that claimed an identity, from the decision log, and what the mock internet was asked (PTR and A lookups, range fetches, directory fetches). The mock adds ~15 ms per DNS query and ~30 ms per file fetch, like the real thing.

```bash
python tools/checkpoint.py --round N                 # your code
python tools/checkpoint.py --round N --catch-up      # the reference solutions for rounds 1..N (your files kept as .bak)
python tools/checkpoint.py --restore                 # put your own files back
python tools/checkpoint.py --round N --level N-1     # round N's impostors against the previous level: the "before"
python tools/scoreboard.py                           # the decision log by actor, after any run
```

## Round 1: UA spoof ⚔️ reverse DNS

The store is at level 0. The honest scraper (`python-httpx`) gets 30 pages and a wall of 429s. The same scraper with `User-Agent: … Googlebot/2.1 …` gets all 120 in the verified lane.

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round1_ua_spoof.py` (level 0) | honest `30/120`, UA = Googlebot `120/120`, `120` in the verified lane |
| 🔵 Defend | Implement `TODO (Round 1)` in `defenses/rdns.py`: `resolver.ptr(ip)`, then `name_matches()`. Level 1 | – |
| 🔴 Re-run | `python attacks/round1_ua_spoof.py` | `32/120`, none in the fast lane, first rejection `PTR static-203-0-113-66.attacker-hosting.example is not under ['.googlebot.com', '.google.com']` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | impostor held · crawlers **3/8** admitted · shoppers hurt 0 of 40 · gate median ≈ 5 ms, 300 PTR lookups |

**Discuss:** five genuine crawlers are now throttled: GPTBot, ClaudeBot, PerplexityBot and the signed ChatGPT agent publish no reverse DNS, so this check can never pass them. That is the price of Round 1, and Round 3 pays it back. Also look at the cost line: every claimant request now waits for a DNS round trip.

## Round 2: forged PTR ⚔️ forward confirmation

The attacker owns its hosting allocation's reverse zone (every hosting panel lets you set your PTR). First a substring trick, then an outright forgery.

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round2_ptr_spoof.py` (level 1) | substring PTR `32/120`; forged `crawl-198-51-100-97.googlebot.com` → `120/120`, all in the verified lane |
| 🔵 Defend | Implement `TODO (Round 2)` in `defenses/rdns.py`: `resolver.a(name)` must contain the IP; cache the verdict with `POSITIVE_TTL_S` / `NEGATIVE_TTL_S`. Level 2 | – |
| 🔴 Re-run | `python attacks/round2_ptr_spoof.py` | forged → `30/120`, `PTR crawl-198-51-100-97.googlebot.com does not resolve back to 203.0.113.68 (forged PTR)` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | impostors held · crawlers 3/8 (same five expected) · shoppers hurt 0 · gate median ≈ 3 ms, **6 PTR + 4 A lookups** |

**Exercise:** `name_matches()` is label-aware. Change it to `suffix in name` and re-run the substring attack. **Discuss:** the cache turned 300 lookups into 6. What TTL would you give a *negative* verdict, and what happens to Googlebot during a resolver outage?

### 💬 Debrief

`python tools/scoreboard.py`. Read the `claim` and `verified as` columns of `curl -s 'localhost:5000/lab/decisions?actor=bot:' | python -m json.tool` (`extra.claim`, `extra.identity`, `extra.method`, `extra.lane`): who said what, who could prove it, and who paid for the proof.

## Round 3: shared-infrastructure squat ⚔️ range files + scoping

Google's user-triggered fetchers run partly on App Engine. Their reverse DNS is `*.gae.googleusercontent.com`, a suffix Google's own verification page lists as valid, and the prefixes are in `user-triggered-fetchers.json`. Any App Engine tenant can send any request from those addresses. The attacker's scraper now lives there (a tenant VM on the lab's shared slice, 203.0.113.56) and calls itself `Google-Read-Aloud`. Forward-confirmed reverse DNS passes, honestly.

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round3_range_squat.py` (level 2) | `GPTBot from the hosting box 30/120` (no rDNS, nothing to check); `Google-Read-Aloud from GAE 120/120`, all in the verified lane |
| 🔵 Defend 3a | Implement `lookup()` in `defenses/ip_ranges.py` (walk `OPERATORS[*]["ranges"]`, `load()` each, `ipaddress`). Level 3, run `python tools/population.py --scenario lane_mix` | gptbot, claudebot, perplexitybot admitted; **gptbot-new 30/60**: the vendored snapshot lacks the prefix OpenAI added |
| 🔵 Defend 3b | Implement `load()`: fetch `f"{mock_url()}/ranges/{list_path}"`, cache for `RANGE_TTL_S`, keep a last-good copy. Re-run the cohort | gptbot-new 60/60 |
| 🔵 Defend 3c | Implement `lane_for()`: shared infrastructure and non-crawler categories get the anonymous lane | – |
| 🔴 Re-run | `python attacks/round3_range_squat.py` | squat → `30/120`, `google-fetcher verified via fcrdns, but on shared infrastructure: network proven, program not` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | impostors held (30 and 30) · crawlers **7/8** (chatgpt-agent expected) · shoppers hurt 0 · 8 range fetches, gate median ≈ 4 ms |

**Discuss:** the ChatGPT agent is still throttled. It is not in `chatgpt-user.json` (agents run from more places than crawlers), and even if it were, a user-triggered fetcher gets a person's budget under your own `lane_for()`. What would prove *this* request comes from OpenAI? Anthropic's single `bots.json` covers three bots: what can and can't you decide from it?

## Round 4: Web Bot Auth ⚔️ anyone with a key

The agent signs each request (RFC 9421, Ed25519) and points `Signature-Agent` at the origin that publishes its keys. Level 4 verifies the signature. Level 5 decides what a valid signature is worth. The three headers are plain request headers (not `X-Lab-*`), so they reach the check in `ctx.headers`; the signature base is built from `@authority` (`ctx.host`), `@path` and the **raw query string**. `ctx.args` is a parsed dict, so `demo_site/ext/identity.py` exposes `request.query_string` through an enricher as `ctx.attrs["raw_query"]`: the recon gap a verifier hits the first time a signed URL has `%20` or a repeated key in it. The genuine ChatGPT agent in the cohort signs `@query` and sends `tag=a%20b%2Bc` on purpose, so a verifier that rebuilds the query from `ctx.args` rejects it.

| Step | Do | Expected |
|---|---|---|
| 🔵 Look | `python -m defenses.httpsig` | the signature base, line by line, in both `Signature-Agent` wire forms; tamper → `False` |
| 🔵 Defend | Implement `verify()` in `defenses/web_bot_auth.py` (the docstring lists the six steps; `key_directory.fetch_directory()` and `message_context()` are given). Level 4 | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | crawlers **8/8** · shoppers hurt 0 · 2 directory fetches · `self_signed 120/120 in the verified lane (expected: it works at this level)` |

## Round 5: self-signed agent + replay ⚔️ trust policy

The attacks that beat verification, and the policy that stops them. (The attack scripts keep their `round4_*` filenames: both attack the level-4 verifier.)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack a | `python attacks/round4_self_signed_agent.py` (level 4) | publishes a valid signed directory for `attacker.example`, signs correctly → `120/120`, all in the verified lane |
| 🔴 Attack b | `python attacks/round4_replay.py` | stale leak (24 h window, signed 1 h ago) `120/120`; fresh leak (60 s window) replayed once per page → `120/120` |
| 🔵 Defend | Implement `trust()` in `defenses/web_bot_auth.py`: `policy.TRUSTED_AGENTS`, `policy.SIGNATURE_MAX_WINDOW_S`, nonce with `ctx.redis.set(key, "1", nx=True, ex=…)`. Level 5 | – |
| 🔴 Re-run | both attacks | self-signed `30/120` (`valid signature from untrusted origin`); stale `0/120` with 120 × 403 (`signature window 86400s exceeds policy 300s`); fresh `1/120`, 119 × 403 (`nonce already seen: replay`) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 5` | stale 0, fresh 1, self-signed held, spoof held · crawlers 8/8 · shoppers hurt 0 · gate median ≈ 4 ms |

**Discuss:** the attacker's signature in (a) was cryptographically perfect. Which line of the draft did your level-4 verifier violate? ("A verifier MUST NOT attribute a request to a Signature-Agent URL unless it made this association.") In (b) one replay still went through: why can no verifier distinguish the first replay from the original, and what could the *signer* cover to shrink the blast radius?

**The shared verifier.** `defenses/httpsig.py`, `defenses/key_directory.py` and the finished `solutions/round5/defenses/web_bot_auth.py` are the series' Web Bot Auth verifier: Chapters 3, 4 and 9 copy them byte for byte (`shared.json` lists them, and `python scripts/lab_diff.py <lab> --shared` confirms a copy still matches). The chapter-specific numbers are in `defenses/policy.py` (`TRUSTED_AGENTS`, `SIGNATURE_MAX_WINDOW_S`), which the verifier reads, so the module itself never changes.

## Wrap-up: the scoreboard

At level 5, run every attack and the cohort, then the scoreboard:

```bash
python tools/checkpoint.py --round 5 --catch-up
python tools/scoreboard.py
```

The checkpoint shows one of the impostors' 480 requests in the verified lane (the first replay of the fresh leak), genuine crawlers throttled 0 of 8, shoppers hurt 0 of 40. Walk the ladder backwards: at each level, which genuine crawler was the false positive, and which real-world check (not in this lab) would still have been missing? Then hand off to Chapter 3: now that you know who a crawler is, what do you charge it?

## Expected results (self-check)

Generated from `python tools/verify.py --all --catch-up --markdown` (against your own store: `python tools/checkpoint.py --all --markdown`), one `--round N --level N-1` run per round for the "before" column, and one run of every attack at every level for the matrix below, on 2026-10-15 on Linux x86_64 (WSL2) with Python 3.12.15, Flask 3.1.3, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.1.4, httpx 0.28.1, requests 2.34.2, cryptography 50.0.2, redis 8.1.0 and fakeredis 2.39.0 (`REDIS_URL=memory://`, SQLite), with the reference solutions applied cumulatively. Every checkpoint passed and shoppers hurt were **0 of 40** in every round. The Docker path (Redis 8.10.2 and PostgreSQL 18.6 from `docker-compose.yml`) was run for the smoke test and checkpoints 1, 3 and 5: it passes with the same page counts (30 to 32 for a held impostor, stale 0, fresh 1); the gate figure rises to about 30 ms median and 60 ms p95 for a claimant request (and 3.4 ms for a shopper), because every request makes several Redis round trips. A "page" is one of the 120 product pages. The anonymous lane is 30 pages plus the trickle refilled while an attack runs, so a held impostor shows 30 to 33, not exactly 30; the other numbers are deterministic.

**Per checkpoint** (before = the same impostors against the previous level):

| Checkpoint | Level | Impostors run | Product pages taken, before → after (in the verified lane) | Genuine crawlers admitted | Gate per claimant request, median / p95 | The mock internet was asked |
|---|---|---|---|---|---|---|
| 1 | 1 | UA spoof | 120 → **32** (120 → 0) | 3/8 | 5.1 / 41.7 ms | 300 PTR |
| 2 | 2 | UA spoof, forged PTR | forged PTR 120 → **30** (120 → 0); spoof 30 | 3/8 | 3.4 / 11.0 ms | 6 PTR + 4 A |
| 3 | 3 | forged PTR, GAE squat, GPTBot claim | squat 120 → **30** (120 → 0); GPTBot claim 30; forged PTR 30 | 7/8 | 3.7 / 9.8 ms | 6 PTR + 5 A + 8 range files |
| 4 | 4 | UA spoof, self-signed agent | self-signed 30 → **120** (0 → 120): the lesson; spoof 30 | 8/8 | 4.1 / 9.1 ms | + 2 directories |
| 5 | 5 | + stale and fresh replay | self-signed 120 → **30** (120 → 0); stale 120 → **0** (120 × 403); fresh 120 → **1** (119 × 403) | 8/8 | 3.8 / 10.1 ms | same |

Shoppers' own gate time stays at 1.4 ms median in every round (the gate ignores browsers).

**Pages scraped in one burst, out of 120, at each `DEFENSE_LEVEL`.** Bold marks the first level that holds the attack.

| Attack ↓ / `DEFENSE_LEVEL` → | 0 | 1 | 2 | 3 | 4 | 5 | Reason at the first catch |
|---|---|---|---|---|---|---|---|
| `round1_ua_spoof`, honest scraper | 30 | 30 | 30 | 30 | 30 | 30 | the anonymous lane |
| `round1_ua_spoof`, Googlebot UA from a hosting box | 120 | **32** | 30 | 30 | 30 | 30 | PTR not under `.googlebot.com` |
| `round2_ptr_spoof`, substring PTR | 120 | **32** | 30 | 30 | 30 | 30 | label-aware suffix match |
| `round2_ptr_spoof`, forged PTR | 120 | 120 | **30** | 30 | 30 | 30 | forward lookup does not return the IP |
| `round3_range_squat`, GPTBot claim | 120 | **30** | 30 | 30 | 30 | 30 | no PTR at L1-2; not in `openai/gptbot.json` at L3 |
| `round3_range_squat`, Google-Read-Aloud from GAE | 120 | 120 | 120 | **30** | 30 | 30 | shared infrastructure, no entitlement |
| `round4_self_signed_agent` | 30 | 30 | 30 | 30 | 120 | **30** | untrusted origin |
| `round4_replay --stale` (24 h window) | 120 | 30 | 30 | 30 | 120 | **0** (120 × 403) | window exceeds policy |
| `round4_replay --fresh` (60 s, once per page) | 120 | 30 | 30 | 30 | 120 | **1** (119 × 403) | nonce already seen |

The replay rows are 120 at level 0 because the leaked request is also a `ChatGPT-User` claim, which level 0 believes; at levels 1 to 3 the claim cannot be verified (no reverse DNS, not in the published range), and at level 4 the stolen signature is valid.

**Genuine crawlers admitted** (all 60 pages) and the shoppers:

| Cohort ↓ / level → | 0 | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| googlebot, bingbot, applebot (reverse DNS) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| gptbot, claudebot, perplexitybot (published ranges) | ✅ | ⛔ | ⛔ | ✅ | ✅ | ✅ |
| gptbot-new (prefix added after the snapshot) | ✅ | ⛔ | ⛔ | ✅ (live fetch) | ✅ | ✅ |
| chatgpt-agent (signed, in no range file) | ✅ | ⛔ | ⛔ | ⛔ | ✅ | ✅ |
| shoppers hurt | 0 of 40 | 0 | 0 | 0 | 0 | 0 |
| gate per claimant request, median | 2.8 ms | 5.3 ms | 3.3 ms | 3.9 ms | 3.9 ms | 3.3 ms |

Level 0 admits every impostor and every crawler: the ✅ column at level 0 is not a defense, it is the absence of one. With only the vendored snapshot (Round 3a, before you write `load()`), gptbot-new is also ⛔ at level 3: 30 of 60 pages.

Reading the table. Round 1 closes the cheapest lie and costs you five real operators. Round 2 closes the second cheapest, forging the PTR, and costs nothing more: the verdict cache turns 300 lookups into six. Round 3 pays back the operators that publish ranges instead of reverse DNS, and refuses to treat a network as a program. Round 4 admits the one agent that signs, and with it anyone who can publish a directory. Round 5 is the policy that no signature carries: whose key do we trust, for how long, once.

## Troubleshooting

| Problem | Fix |
|---|---|
| port 5000 or 5001 in use | `PORT=5050 python demo_site/app.py` and `export DEMO_URL=http://127.0.0.1:5050` in the other terminals; a busy 5001 falls back to a free port automatically (scripts find it with `GET /lab/identity`), or set `MOCK_PORT`/`MOCK_URL` yourself |
| the checkpoint says the store is at the wrong level | the checkpoint sets the level itself; if you changed it by hand, run the checkpoint again |
| crawlers still throttled after editing a defense | `defenses/` reloads on the next request; `demo_site/ext/identity.py` does not, restart the store after editing it |
| `Connection refused` mid-run on WSL or a loaded laptop | the dev server opens one socket per request and the OS keeps thousands in TIME-WAIT; restart the store |
| `rdns cache:` reasons after changing `rdns.py` | the verdict cache lives in Redis under `lab:ch2:rdns:`; `POST /lab/reset` (the checkpoint does it) or a restart clears it |
| Round 2 forgery still passes at level 2 | you cached the verdict before forward confirmation; cache only the final answer |
| Round 4 the genuine agent is `invalid` | check the signature base: the agent covers `@query`, so `message_context()` must use `ctx.attrs["raw_query"]`, not a query rebuilt from `ctx.args` |
| Round 4 `directory not bound` | the attacker's directory must be signed over `("@authority";req)` for `attacker.example`, see `httpsig.sign_directory` |
| `tools/fixtures/keys/` is missing | it is generated on first use; `python tools/make_keys.py` creates it, `--force` rotates the keys |
| want real Redis | `REDIS_URL=redis://127.0.0.1:6379/0` against any Redis you run (or the compose file); nothing else changes |
| port 5432 or 6379 taken (another lab's containers) | `docker compose ls`, then `docker compose -p <name> down` |

## Bonus challenges

1. **Dictionary form.** The working-group draft says signers MUST send `Signature-Agent: sig1="https://…"` and cover it as `"signature-agent";key="sig1"`; Cloudflare's verifier still requires the bare string. `httpsig.agent_headers(…, agent_form="dict")` produces the new form. Make the ChatGPT agent in `tools/personas_ch2.py` send it and confirm your `verify()` handles both.
2. **Narrow the blast radius.** Have the genuine agent cover `@method` and `@path` too, and show that a leaked signature now replays against exactly one URL.
3. **Your own logs.** `python tools/verify_real.py <ip> --claim googlebot` runs the real FCrDNS check and range match against an address from a server you operate (the only networked tool in the lab).
4. **IPv6.** Add `ipv6Prefix` entries and an IPv6 PTR to the fixtures (the `cloud_v6` pool). Where do `name_matches()` and the reverse-zone pattern need changing?
5. **mTLS, conceptually.** Sketch what a client-certificate allowlist would need from the operator and from your edge, and why no crawler operator offers it today.
