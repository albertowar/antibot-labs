# W4 Ch1 Lab: AI Crawlers, Landscape & Identification

Starts from: `workshops/04-ai-era-bots/starter/` (contract 1.6). Adds: the crawler layers and their label (`defenses/crawl.py` and four wire-it checks), the history recorders and the `robots.txt` policy hook (`demo_site/ext/crawl.py`), the reverse-DNS and published-range fixtures (shared with Chapter 2), four attack scripts and a 49-client cohort.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `data/crawl_policy.robots`
- `data/operators.json`
- `data/registry_extra.json`
- `data/robots.json`
- `defenses/crawl.py`
- `defenses/crawl_policy.py`
- `defenses/crawl_signature.py`
- `defenses/crawler_registry.py`
- `defenses/crawler_verify.py`
- `defenses/netdb.py`
- `demo_site/ext/crawl.py`
- `tools/fixtures/dns_zones.json`
- `tools/fixtures/ranges/anthropic/bots.json`
- `tools/fixtures/ranges/bing/bingbot.json`
- `tools/fixtures/ranges/commoncrawl/ccbot.json`
- `tools/fixtures/ranges/google/common-crawlers.json`
- `tools/fixtures/ranges/google/user-triggered-fetchers.json`
- `tools/fixtures/ranges/openai/chatgpt-user.json`
- `tools/fixtures/ranges/openai/gptbot.json`
- `tools/fixtures/ranges/openai/searchbot.json`
- `tools/fixtures/ranges/perplexity/perplexity-user.json`
- `tools/fixtures/ranges/perplexity/perplexitybot.json`
- `tools/personas_ch1.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `demo_site/templates/challenge.html`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** Round 0 plus 4 rounds of defend 🔵 and attack 🔴, then a debrief. **Style: wire-it.** Each defense ships as a stub in `defenses/` with a `TODO (Round N)`; the finished version is in `solutions/roundN/`. `python tools/checkpoint.py --round N --catch-up` installs rounds 1..N (the module, `defenses/ladder.py` and, for Round 1, your `robots.txt` policy), and `--restore` puts your files back. This README is the lab's reference; the chapter's content doc and deck are still to be written (`TODO.md` §5).

The demo store is the Workshop 4 starter state: Kestrel Outfitters, unchanged, with 120 products behind a catalog, a sitemap, an RSS feed, static files and a `robots.txt`. AI crawlers want the catalog. You build crawler identification in four rounds, and every checkpoint measures what each layer stops **and** what it costs: 40 shoppers browse and buy, and nine automated clients you want to keep (an RSS reader, a Slack link unfurler, an uptime monitor, a developer with curl, four verified crawlers and one small search engine that cannot prove who it is) run next to the crawlers.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool imports `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service URLs such as `REDIS_URL` too). Do not remove that check.
- **Everything is simulated.** Source addresses are rented from `data/world.json` (RFC 5737 documentation ranges) and sent in `X-Lab-Client-IP`, which the store's edge trusts only from loopback and only inside a pool. The operators' "published ranges" in `tools/fixtures/ranges/<operator>/` are lab snapshots: their prefixes are slices of pools that already exist in `world.json` (`cloud_vm`, `cloud_gcp`, `hosting_asn`), so an operator's crawler is a tenant of an ordinary cloud network, exactly like the attacker who impersonates it. Reverse and forward DNS are answered from `tools/fixtures/dns_zones.json` by `defenses/netdb.py`, never by a resolver. These fixtures are the same files Chapter 2's mock internet serves over HTTP (byte-identical copies, listed in `shared.json`); Chapter 2 adds the network and its cost, this chapter reads them locally. No crawler operator's real endpoint, range or key is contacted or used.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  defenses/        crawler_registry · crawler_verify · crawl_signature · crawl_policy   <- YOUR FOUR STUBS (one per round)
                   ladder.py                                                           <- yours too: wire one level per round
                   crawl.py (the label, the blunt mapping, history helpers) · netdb (rDNS) · netinfo (ASN type): finished
  data/            crawl_policy.robots   <- your Round 1 file, appended to /robots.txt from level 1
                   robots.json · registry_extra.json · operators.json
  tools/fixtures/  dns_zones.json · ranges/<operator>/<list>.json   <- the same files as Chapter 2
  demo_site/ext/   crawl.py: robots hook, the two history recorders, the placeholder challenge type
  attacks/         round0_declared_crawler · round1_impersonate_searchbot · round2_stealth_chrome
                   round3_polite_distributed · _common.py
  tools/           checkpoint.py (ROUNDS and thresholds) · personas_ch1.py (the cohort)
  solutions/roundN/  the finished module (and ladder.py) each round installs
```

The rest of the store (catalog, cart, checkout, the simulated edge, the decision log, `tools/population.py`, `tools/scoreboard.py`) is the W4 starter, unchanged. Its contract is `workshops/STORE_CONTRACT.md`.

---

## Setup

Work through `onboarding/setup/PREWORK.md` first. This lab needs nothing beyond the starter's packages (no browser, no Ollama):

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # one venv per chapter, see the root README
pip install -r requirements.txt
python tools/doctor.py
python demo_site/app.py                                  # terminal 1: the store, on :5000 (seeds itself)
python tools/checkpoint.py --round 0                     # terminal 2: crawlers and the cohort
```

Docker is optional: the default is SQLite plus an in-process Redis. To run the production-shaped stack (Redis 8.10 and PostgreSQL 18):

```bash
docker compose up -d --wait
REDIS_URL=redis://127.0.0.1:6379/0 DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop python demo_site/app.py
docker compose down -v                                   # when you are done
```

Round N runs at `DEFENSE_LEVEL` N and each level includes every level below it; the checkpoint changes the level live (`POST /lab/level`), so the store never restarts between rounds. You finish a stub, wire its `CHECK` in `defenses/ladder.py`, save (the store reloads `defenses/` on the next request), and measure:

```bash
python tools/checkpoint.py --round 1                    # your code
python tools/checkpoint.py --round 1 --catch-up         # the reference solutions for rounds 1..1 (your files kept as .bak)
python tools/checkpoint.py --restore                    # put your own files back
python tools/checkpoint.py --round 2 --level 1          # round 2's crawlers against Round 1's defenses: the "before"
```

Useful by hand: `python tools/population.py --scenario crawl_mix` runs the 49-client cohort alone; `python attacks/round2_stealth_chrome.py --assets` runs one crawler; `python tools/scoreboard.py` prints the decision log by actor; `curl -s 'localhost:5000/lab/decisions?actor=bot:' | python -m json.tool` shows each decision's label in `extra` (`crawl_identity`, `crawl_token`, `crawl_method`, `crawl_score`, `crawl_reasons`).

## How a client is judged

Four checks run in order on the catalog surface (`/`, `/products`, `/catalog`, `/product/<sku>`, `/search`). `/robots.txt`, `/sitemap.xml`, `/feed.xml`, the cart and account pages and `/api/*` are never judged: a crawler must be able to read the policy you want it to follow, and the JSON API is a leak Chapter 3 closes (API abuse in depth is W3 Ch2's territory).

1. **Claim** (L1, `crawler_registry`): which registry token is in the User-Agent, who runs it, for what purpose, and does your `robots.txt` allow this path for that token?
2. **Proof** (L2, `crawler_verify`): is the claim true? The operator's published address list, or forward-confirmed reverse DNS. Which network an address sits in proves nothing here: the operators and the impersonators rent from the same cloud pools.
3. **Behaviour** (L3, `crawl_signature`): a client that claims nobody is scored on how it fetches. Static files and images never reach the gate, so `demo_site/ext/crawl.py` records them (and every other request) per address under `lab:ch1:*`; the signature reads that history.
4. **Policy** (L4, `crawl_policy`): identity x purpose decides allow, limit, challenge or block.

The layers hand each other a label (`ctx.attrs["crawl"]`: identity, token, purpose, robots verdict, method, score). Until Round 4 `defenses/crawl.py` maps the label to allow-or-block, blunt on purpose. From Round 4 the earlier layers only label and `crawl_policy` decides, because a hard verdict from L1 to L3 would stop the pipeline before the policy ran.

## Rounds

| Round | Level | 🔴 Crawlers run | 🔵 You edit | The question |
|---|---|---|---|---|
| 0 | 0 | honest GPTBot (reads `robots.txt`, takes everything) | none | What does an honest AI crawler look like in the log? |
| 1 | 1 | + GPTBot ignoring `robots.txt`, OAI-SearchBot impersonator | `defenses/crawler_registry.py`, `data/crawl_policy.robots`, `defenses/ladder.py` | Who claims to be a crawler, and what does your policy say to them? |
| 2 | 2 | + Googlebot with a fake PTR, stealth Chrome from 4 cloud addresses | `defenses/crawler_verify.py` | Is the claim true? Published ranges and forward-confirmed reverse DNS |
| 3 | 3 | + a polite 30-address crawler, then the same with session cookies | `defenses/crawl_signature.py` | Does an unclaimed client behave like a crawler? |
| 4 | 4 | the same crawlers | `defenses/crawl_policy.py` | Identity x purpose: allow, limit, challenge or block |

A round passes when no shopper and no verified crawler is blocked, every verified crawler stays out of the rate limiter, each crawler lands where its row says (`blocked` takes at most 10% of the 120 product pages, `partial` between 10% and 90%, `full` 90% or more), and the gate stays cheap. Round 3 allows exactly one false positive, LocalSearchBot: it is a real search engine that cannot prove itself and behaves like a crawler, and the blunt mapping refuses it. Round 4 turns that refusal into a budget (the checkpoint requires "limited, never refused").

What the checkpoint cannot show you is the other end of Round 3: a polite, distributed crawler that keeps a session cookie scores like a crowd of shoppers and takes the whole catalog (`polite_cookies`, `full`). At the HTTP level that is the end of the road. W4 Ch2 makes the good crawlers prove who they are with signed requests, and W4 Ch3 makes the rest pay for every page.

**The cohort.** The starter's 40 shoppers (home broadband, carrier NAT, consumer VPNs, a privacy relay, an old Chrome, an autofill form, a no-JS browser) browse and buy; a hook in `tools/personas_ch1.py` makes them fetch the stylesheet, script and card images the way a browser does, otherwise the Round 3 signature would call every shopper "HTML only". Nine `legit:` clients run next to them: the scoreboard keeps them out of both "people hurt" and "bots stopped", and the checkpoint prints their own table (served, limited, refused). 403 is a stop, 429 is a budget (friction you chose).

**Trade-offs worth arguing about.** A User-Agent match is a claim, not evidence, and a stale range snapshot turns a real crawler into an "impersonator" the day its operator adds a prefix (the lab's Googlebot sits just outside its snapshot on purpose, so only reverse DNS saves it). Any rule on a VPN, relay or cloud address hurts real people first; the shoppers on those networks are in the cohort to show it. A "challenge" in this chapter cannot be solved (`crawl_proof`, registered by the ext), so it reads as a stop.

## Expected results (self-check)

Generated from `python tools/verify.py --all --catch-up --markdown` (against your own store: `python tools/checkpoint.py --all --markdown`) and one `--round N --level N-1` run per round for the "before" column, on 2026-10-15 (re-verified 2026-10-18 after the fixtures moved to Chapter 2's canonical set: every page count unchanged except the polite crawler, 59 → 60, within the one-or-two-page variance) on Linux x86_64 (WSL2) with Python 3.12.15, Flask 3.1.3, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.1.4, redis 8.1.0, fakeredis 2.39.0, requests 2.34.2, SQLite and the in-process Redis. Every round passed with the reference solutions installed (the final `--all --catch-up` run: 0 of 40 shoppers hurt in every round). The Docker path (Redis 8.10.2 and PostgreSQL 18.6 from `docker-compose.yml`) was run for the smoke test and Rounds 1, 3 and 4: it passes with the same page counts (the gate figure rises to about 3.5 ms median in Round 1 and 8 to 10 ms in Rounds 3 and 4, p95 about 90 to 100 ms, because every request makes several Redis round trips). A "page" is one of the 120 product pages; the polite crawler's count varies by one or two between runs (it depends on which addresses reach their fourth request first), the others are deterministic.

| Round | Level | Crawlers run | Product pages taken (before → after) | Shoppers hurt | Welcome clients | Gate per request, median / p95 |
|---|---|---|---|---|---|---|
| 0 | 0 | honest GPTBot | 120 | 0 of 40 | none refused | 1.5 / 3.5 ms |
| 1 | 1 | GPTBot, GPTBot ignoring `robots.txt`, OAI-SearchBot impersonator | GPTBot 120 → **0** (it obeys the policy) · ignoring 120 → **0** (blocked by token) · impersonator 120 → **120** | 0 of 40 | none refused | 1.5 / 3.5 ms |
| 2 | 2 | ignoring GPTBot, impersonator, fake-PTR Googlebot, stealth Chrome | ignoring 0 · impersonator 120 → **0** · fake PTR 120 → **0** · stealth 120 → **120** | 0 of 40 | none refused (Googlebot verified by reverse DNS alone) | 1.5 / 3.5 ms |
| 3 | 3 | impersonator, stealth Chrome, polite 30-address crawler, the same with cookies | impersonator 0 · stealth 120 → **11** · polite 120 → **60** · polite with cookies 120 → **120** | 0 of 40 | **LocalSearchBot refused** (1 page served, 11 refused): the documented false positive | 1.9 / 6.3 ms |
| 4 | 4 | the same four | impersonator 0 · stealth 11 · polite 60 · polite with cookies 120 | 0 of 40 | LocalSearchBot **limited** (10 served, 2 over its budget), none refused | 2.0 / 6.5 ms |

Reading the table. Round 1's policy only binds clients that claim a token and read the file; the impersonator wears the allowed badge and takes everything until Round 2 checks it. Round 2 verifies the badge, so the stealth crawler stops wearing one and takes everything until Round 3 scores how it fetches. Round 3's cost is real: LocalSearchBot behaves exactly like Googlebot and cannot prove it, so the blunt mapping refuses it; Round 4 gives it a budget instead, and the crawlers' numbers barely move because the policy changes what a stop means, not who gets stopped. The residual is the last column of Round 3 and 4: a polite, distributed, cookie-holding crawler on residential addresses takes the whole catalog. GPTBot and ClaudeBot are verified from Round 2 on and still skip every product page, because their documented token is a training token and your policy says no.

The gate figure is the median over the shoppers' catalog and checkout requests while the crawlers hammer the same store (the `Ctx` build, enrichers, history recording and every check, from the decision log). It is small here because the Redis is in-process; with the Docker stack every request pays a few Redis round trips, which is why the checkpoint allows 250 ms there instead of 25 ms.

## Troubleshooting

| Problem | Fix |
|---|---|
| Port 5000 taken (macOS AirPlay Receiver) | `PORT=5050 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:5050` in the shells that run tools |
| Round 1 fails with `gptbot: expected blocked, got 100%` | Your stub is not finished, or not wired in `defenses/ladder.py`, or `data/crawl_policy.robots` still says nothing. Finish the `TODO`, or `python tools/checkpoint.py --round 1 --catch-up` |
| The honest GPTBot still takes the catalog at Round 1 | `/robots.txt` is served from level 1 up only; check `curl -s localhost:5000/robots.txt` after the checkpoint set the level, and read the policy file's comment about groups and blank lines |
| Round 2 says a verified crawler was refused | Your `verify()` returns "impersonator" for a real operator: check that Googlebot (`198.51.100.108`) passes `fcrdns()` and that GPTBot (`203.0.113.7`) is inside the range file |
| Round 3 hurts shoppers | A weight is enough on its own to reach `THRESHOLD`. Read `X-Lab-Signals` and the `crawl_reasons` in `/lab/decisions?actor=human:` for the person that was refused |
| A round says `store is at level N` | The checkpoint sets the level itself; if you changed it by hand, run the checkpoint again |
| Numbers look stale between rounds | The checkpoint resets the store (`POST /lab/reset`, which also clears the recorded history); if you ran an attack by hand, run the checkpoint to reset first |
| `ModuleNotFoundError: demo_site` | Run scripts from `lab/` (`python attacks/...`), not from inside `attacks/` |
| Editing `demo_site/ext/crawl.py` has no effect | Ext modules are not reloaded: restart the store (`defenses/` and `data/crawl_policy.robots` do reload) |
| Want a clean slate | Stop the store, delete `instance/`, start it again |
| Port 5432 or 6379 taken (another lab's containers) | `docker compose ls`, then `docker compose -p <name> down` |
