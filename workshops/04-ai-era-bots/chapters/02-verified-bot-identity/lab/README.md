# Chapter 2 Lab: Verified Bot Identity

**Format:** 5 checkpoints in 4 rounds of defend 🔵 ⚔️ attack 🔴, plus two debriefs. See `../chapter_02_content.md`, §2.5.

You run a store that wants search engines and AI crawlers to index it, and that gives
verified crawlers a *fast lane*: 600 requests a minute instead of the 30 every anonymous
client gets. Scrapers want that lane. In every round you play the scraper that takes it,
then the defender who closes the door, and you measure both what the impostor got and
which genuine crawlers your new check wrongly throttled.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. It also refuses a non-local `MOCK_URL`. Do not remove that check.
- The "mock internet" (`tools/mock_internet.py`) answers the DNS and range-file lookups locally. Operator hostnames are real suffixes on synthetic addresses, every egress IP is an RFC 5737 address claimed in a header the store honours only from loopback, and every key is generated for this lab.
- **Outbound network:** none during the rounds. The optional bonus `tools/verify_real.py` resolves an IP from **your own** logs and downloads an operator's published range file; it sends nothing to the operator's crawler or to the address. Do not point it at addresses from logs you do not own.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  README.md              this file
  requirements.txt       pinned deps (Python 3.12+). No Docker.
  demo_site/
    app.py               the store: 200 products, two crawl budgets, the gate hook, /robots.txt
    store.py             fakeredis by default (REDIS_URL=memory://)
  defenses/              one module per rung of the ladder; you implement the TODOs
    operators.py         what each operator documents: UA tokens, rDNS suffixes, range files (ships done)
    ua_claims.py         L0  User-Agent -> claimed operator (ships done: it is the hole)
    rdns.py              L1  PTR suffix check   L2  forward-confirmed rDNS + cache    (Rounds 1–2)
    ip_ranges.py         L3  published range files, TTL refresh, entitlement scoping  (Round 3)
    httpsig.py           RFC 9421 signer/verifier, JWK thumbprints, signed directory (ships done)
    web_bot_auth.py      L4  verify a Web Bot Auth signature   L5  trust policy, window, nonce (Rounds 4–5)
    resolver.py          DNS client: the mock by default, the real resolver for the bonus tool
    crawler_gate.py      ties the layers together by DEFENSE_LEVEL (ships done)
  attacks/               round*_*.py, one per attack step; _common.py holds the loopback guard
  solutions/round1..5/   the reference defense for each checkpoint (used by --catch-up)
  tools/
    mock_internet.py     DNS zones, operator range files, agent key directories, the attacker's hosting panel
    legit_traffic.py     20 humans + 8 genuine crawlers (the false-positive cohort)
    checkpoint.py        run one checkpoint end to end; --catch-up applies the solution
    scoreboard.py        the decision log by actor: impostors admitted vs crawlers throttled vs humans blocked
    make_keys.py         regenerate the lab's Ed25519 keypairs
    verify_real.py       OPTIONAL, networked: FCrDNS + range check of an IP from your own logs
    fixtures/            dns_zones.json, ranges/<operator>/*.json, keys/*.json
```

**Why Python only.** Everything here is server-side verification: DNS lookups, prefix
matching, Ed25519 signatures. No browser, no JavaScript. `cryptography` does the
signing; the RFC 9421 signature base is built by hand in `httpsig.py` so you can read
the exact bytes an agent signs.

## Setup

```bash
cd lab
python -m venv .venv && source .venv/bin/activate      # one venv per chapter, see the root README
pip install -r requirements.txt
python tools/mock_internet.py                           # terminal 1: http://127.0.0.1:5001
DEFENSE_LEVEL=0 python demo_site/app.py                 # terminal 2: http://127.0.0.1:5000
python attacks/round1_ua_spoof.py                       # terminal 3: should print 200/200
```

Three terminals: the mock internet, the store, and one for attacks and tools. The store
and the mock stay up for the whole lab; you restart the store at each round's `DEFENSE_LEVEL`.

**Defense levels.** Each level includes every level below it.

| Level | Adds | Module | Beats |
|---|---|---|---|
| 0 | nothing: the User-Agent is believed | `ua_claims` | — |
| 1 | reverse DNS, PTR suffix only | `rdns` | Round 1 UA spoof |
| 2 | forward-confirmed reverse DNS + verdict cache | `rdns` | Round 2 forged PTR |
| 3 | operator range files with TTL refresh + entitlement scoping | `ip_ranges` | Round 3 shared-infra squat; admits GPTBot/ClaudeBot/PerplexityBot |
| 4 | Web Bot Auth signature verification | `web_bot_auth` | nothing yet: admits the signed agent, and anyone with a key |
| 5 | trust policy, freshness window, nonce replay cache | `web_bot_auth` | Round 4 self-signed agent and replay |

**Budgets** (`demo_site/app.py`): anonymous lane 30 requests/min per egress IP; verified
lane 600/min per identity. Over budget is a `429` with the gate's reasons in the body.
A forged or replayed signature is a `403`. The reasons are for teaching; in production
you never tell a client which check it failed.

## How to measure a round

Every round has the same three numbers, and the checkpoint prints them:

- 🔴 **Impostor**: how many of the 200 catalogue pages the attacker scraped in one burst.
  200/200 means it got the fast lane; 30/200 means it was held to the anonymous budget.
- 🕷 **Genuine crawlers**: how many of the 8 real crawlers in `tools/legit_traffic.py`
  got all 60 of their pages. A real crawler held to 30 is a *false positive*.
- 👤 **Humans**: 20 browser sessions that never claim an identity. Must stay 120/120.
- 💸 **Gate cost**: p50/p95 milliseconds per claimant request, and how many DNS, range
  and directory fetches the mock internet served. The mock adds ~15 ms per DNS query
  and ~30 ms per file fetch, like the real thing.

```bash
python tools/checkpoint.py --round N        # resets both servers, runs the attack and the cohorts
python tools/scoreboard.py                  # the decision log by actor, after any run
python tools/checkpoint.py --round N --catch-up   # fell behind? apply the reference solution, restart the store
```

## Round 1: UA spoof ⚔️ reverse DNS

The store is at level 0. The honest scraper gets 30 pages and a wall of 429s. The same
scraper with `User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; …)` gets all 200.

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round1_ua_spoof.py` (level 0) | honest `30/200`, `UA = Googlebot 200/200  lane=verified` |
| 🔵 Defend | Implement `TODO (Round 1)` in `defenses/rdns.py`: `resolver.ptr(ip)`, then `name_matches()`. Restart at `DEFENSE_LEVEL=1` | – |
| 🔴 Re-run | `python attacks/round1_ua_spoof.py` | `30/200`, first rejection `PTR static-192-0-2-77.attacker-hosting.example is not under ['.googlebot.com', '.google.com']` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | impostor 30/200 · crawlers **3/8** admitted · humans 0 blocked · p50 ≈ 17 ms, 380 PTR lookups |

**Discuss:** five genuine crawlers are now throttled: GPTBot, ClaudeBot, PerplexityBot
and the signed ChatGPT agent publish no reverse DNS, so this check can never pass them.
That is the price of Round 1, and Round 3 pays it back. Also look at the cost line: every
claimant request now waits for a DNS round trip.

## Round 2: forged PTR ⚔️ forward confirmation

The attacker owns 192.0.2.0/24's reverse zone (every hosting panel lets you set your
PTR). First a substring trick, then an outright forgery.

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round2_ptr_spoof.py` (level 1) | substring PTR `30/200`; forged `crawl-198-51-100-10.googlebot.com` → `200/200  lane=verified` |
| 🔵 Defend | Implement `TODO (Round 2)` in `defenses/rdns.py`: `resolver.a(name)` must contain the IP; cache the verdict with `POSITIVE_TTL_S` / `NEGATIVE_TTL_S`. Restart at `DEFENSE_LEVEL=2` | – |
| 🔴 Re-run | `python attacks/round2_ptr_spoof.py` | forged → `30/200`, `PTR crawl-198-51-100-10.googlebot.com does not resolve back to 192.0.2.77 (forged PTR)` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | impostor 30/200 · crawlers 3/8 (same five expected) · humans 0 · p50 ≈ 0.2 ms, **3 PTR + 3 A lookups** for 1,080 requests |

**Exercise:** `name_matches()` is label-aware. Change it to `suffix in name` and re-run
the substring attack. **Discuss:** the cache turned 380 lookups into 6. What TTL would you
give a *negative* verdict, and what happens to Googlebot during a resolver outage?

### 💬 Debrief

`python tools/scoreboard.py`. Read the `claim` and `verified as` columns side by side:
who said what, who could prove it, and who paid for the proof.

## Round 3: shared-infrastructure squat ⚔️ range files + scoping

Google's user-triggered fetchers run partly on App Engine. Their reverse DNS is
`*.gae.googleusercontent.com`, a suffix Google's own verification page lists as valid,
and the prefixes are in `user-triggered-fetchers.json`. Any App Engine tenant can send
any request from those addresses. The attacker's scraper now lives there (203.0.113.99)
and calls itself `Google-Read-Aloud`. Forward-confirmed reverse DNS passes, honestly.

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round3_range_squat.py` (level 2) | `GPTBot from 192.0.2.77 30/200` (no rDNS, nothing to check); `Google-Read-Aloud from GAE 200/200  lane=verified` |
| 🔵 Defend 3a | Implement `lookup()` in `defenses/ip_ranges.py` (walk `OPERATORS[*]["ranges"]`, `load()` each, `ipaddress`). Restart at `DEFENSE_LEVEL=3`, run `python tools/legit_traffic.py` | gptbot, claudebot, perplexitybot admitted; **gptbot-new 30/60**: the vendored snapshot lacks the prefix OpenAI added |
| 🔵 Defend 3b | Implement `load()`: fetch `f"{MOCK_URL}/ranges/{list_path}"`, cache for `RANGE_TTL_S`, keep a last-good copy. Restart, re-run `legit_traffic.py` | gptbot-new 60/60 |
| 🔵 Defend 3c | Implement `lane_for()`: shared infrastructure and non-crawler categories get the anonymous lane. Restart | – |
| 🔴 Re-run | `python attacks/round3_range_squat.py` | squat → `30/200`, `google-fetcher verified via fcrdns, but on shared infrastructure: network proven, program not` |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | impostors 30/200 + 30/200 · crawlers **7/8** (chatgpt-agent expected) · humans 0 · 8 range fetches, p50 ≈ 0.6 ms |

**Discuss:** the ChatGPT agent is still throttled. It is not in `chatgpt-user.json`
(agents run from more places than crawlers), and even if it were, a user-triggered
fetcher gets a person's budget under your own `lane_for()`. What would prove *this*
request comes from OpenAI? Anthropic's single `bots.json` covers three bots: what can and
can't you decide from it?

## Round 4: Web Bot Auth ⚔️ anyone with a key

The agent signs each request (RFC 9421, Ed25519) and points `Signature-Agent` at the
origin that publishes its keys. Level 4 verifies the signature. Level 5 decides what a
valid signature is worth.

**Checkpoint 4: verify.**

| Step | Do | Expected |
|---|---|---|
| 🔵 Look | `python defenses/httpsig.py` | the signature base, line by line, in both `Signature-Agent` wire forms; tamper → `False` |
| 🔵 Defend | Implement `verify()` in `defenses/web_bot_auth.py` (the docstring lists the six steps; `fetch_directory()` is given). Restart at `DEFENSE_LEVEL=4` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | crawlers **8/8** · humans 0 · 1 directory fetch · `ℹ L4 is naive on purpose: a self-signed agent got 200/200` |

**Checkpoint 5: the attacks that beat verification, and the policy that stops them.**

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack a | `python attacks/round4_self_signed_agent.py` (level 4) | publishes a valid signed directory for `attacker.example`, signs correctly → `200/200  lane=verified` |
| 🔴 Attack b | `python attacks/round4_replay.py` | stale leak (24 h window, signed 1 h ago) `200/200`; fresh leak (60 s window) replayed 200× → `200/200` |
| 🔵 Defend | Implement `policy()` in `defenses/web_bot_auth.py`: `TRUSTED_AGENTS`, `MAX_WINDOW_S`, nonce with `r.set(key, "1", nx=True, ex=…)`. Restart at `DEFENSE_LEVEL=5` | – |
| 🔴 Re-run | both attacks | self-signed `30/200` (`valid signature from untrusted origin`); stale `0/200` with 200 × 403 (`signature window 86400s exceeds policy 300s`); fresh `1/200`, 199 × 403 (`nonce already seen: replay`) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 5` | `stale replay 0/200, fresh replay 1/200` · crawlers 8/8 · humans 0 · p50 ≈ 1 ms |

**Discuss:** the attacker's signature in (a) was cryptographically perfect. Which line of
the draft did your level-4 verifier violate? ("A verifier MUST NOT attribute a request to
a Signature-Agent URL unless it made this association.") In (b) one replay still went
through: why can no verifier distinguish the first replay from the original, and what
could the *signer* cover to shrink the blast radius?

## Wrap-up: the scoreboard

At level 5, run every attack and the cohorts, then the scoreboard:

```bash
for a in round1_ua_spoof round2_ptr_spoof round3_range_squat round4_self_signed_agent round4_replay; do python attacks/$a.py; done
python tools/legit_traffic.py && python tools/scoreboard.py
```

The verified run shows `impostor requests in the verified lane: 1/1800`, `genuine-crawler
requests throttled: 0/960`, `humans blocked: 0/240`. Walk the ladder backwards: at each
level, which genuine crawler was the false positive, and which real-world check (not in
this lab) would still have been missing? Then hand off to Chapter 3: now that you know
who a crawler is, what do you charge it?

## Expected results (self-check)

Verified on 2026-10-11 with Python 3.12.15, Flask 3.1.3, httpx 0.28.1, cryptography 50.0.2, redis 8.1.0 and fakeredis 2.39.0 (`REDIS_URL=memory://`), with the reference solutions applied cumulatively; checkpoints 1–5 reproduce the numbers below.

Catalogue pages scraped in one burst, out of 200. Bold marks the first level that holds the attack.

| Attack ↓ / `DEFENSE_LEVEL` → | 0 | 1 | 2 | 3 | 4 | 5 | Reason at the first catch |
|---|---|---|---|---|---|---|---|
| `round1_ua_spoof` (Googlebot UA from 192.0.2.77) | 200 | **30** | 30 | 30 | 30 | 30 | PTR not under `.googlebot.com` |
| `round2_ptr_spoof` substring PTR | 200 | 30 | 30 | 30 | 30 | 30 | label-aware suffix match |
| `round2_ptr_spoof` forged PTR | 200 | 200 | **30** | 30 | 30 | 30 | forward lookup does not return the IP |
| `round3_range_squat` GPTBot claim | 200 | 30 | 30 | 30 | 30 | 30 | not in `openai/gptbot.json` |
| `round3_range_squat` Google-Read-Aloud from GAE | 200 | 200 | 200 | **30** | 30 | 30 | shared infrastructure, no entitlement |
| `round4_self_signed_agent` | 30 | 30 | 30 | 30 | 200 | **30** | untrusted origin |
| `round4_replay` stale (24 h window) | 30 | 30 | 30 | 30 | 200 | **0** (403) | window exceeds policy |
| `round4_replay` fresh (60 s, 200×) | 30 | 30 | 30 | 30 | 200 | **1** (199 × 403) | nonce already seen |

Genuine crawlers admitted (all 60 pages) and the human cohort:

| Cohort ↓ / level → | 0 | 1 | 2 | 3 (snapshot) | 3 (live) | 4 | 5 |
|---|---|---|---|---|---|---|---|
| googlebot, bingbot, applebot | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| gptbot, claudebot, perplexitybot | ✅ | ⛔ | ⛔ | ✅ | ✅ | ✅ | ✅ |
| gptbot-new (prefix added after the snapshot) | ✅ | ⛔ | ⛔ | ⛔ | ✅ | ✅ | ✅ |
| chatgpt-agent (signed, in no range file) | ✅ | ⛔ | ⛔ | ⛔ | ⛔ | ✅ | ✅ |
| humans, 120 requests | 120 | 120 | 120 | 120 | 120 | 120 | 120 |
| gate cost, p50 per claimant request | 0.01 ms | 17.5 ms | 0.24 ms | — | 0.6 ms | 0.95 ms | 0.96 ms |
| mock internet queries per checkpoint | 0 | 380 PTR | 3 PTR + 3 A | — | +8 range | +1 directory | same |

Level 0 admits every impostor and every crawler: the ✅ row at level 0 is not a defense,
it is the absence of one.

## Troubleshooting

| Problem | Fix |
|---|---|
| port 5000 or 5001 in use | `PORT=5050 python demo_site/app.py`, `MOCK_PORT=5051 python tools/mock_internet.py`, then `export DEMO_URL=http://127.0.0.1:5050 MOCK_URL=http://127.0.0.1:5051` in every other terminal (the store reads `MOCK_URL` too) |
| checkpoint says the store is at the wrong level | restart `demo_site/app.py` with the round's `DEFENSE_LEVEL`; the gate reads it at start-up |
| crawlers still throttled after editing a defense | the store imports defenses once; restart it |
| `Connection refused` mid-run on WSL or a loaded laptop | the clients retry with back-off; if it persists, restart the store. The dev server opens one socket per request and the OS keeps thousands in TIME-WAIT |
| `rdns cache:` reasons after changing `rdns.py` | the verdict cache lives in Redis; `curl -XPOST localhost:5000/admin/reset` or restart (fakeredis is in-process) |
| Round 2 forgery still passes at level 2 | you cached the verdict before forward confirmation; cache only the final answer |
| Round 4 `directory not bound` | the attacker's directory must be signed over `("@authority";req)` for `attacker.example`, see `httpsig.sign_directory` |
| want real Redis | `REDIS_URL=redis://127.0.0.1:6379/0` against any Redis you run; nothing else changes |

## Bonus challenges

1. **Dictionary form.** The working-group draft says signers MUST send
   `Signature-Agent: sig1="https://…"` and cover it as `"signature-agent";key="sig1"`;
   Cloudflare's verifier still requires the bare string. `httpsig.agent_headers(…,
   agent_form="dict")` produces the new form. Make `legit_traffic.py` send it and confirm
   your `verify()` handles both.
2. **Narrow the blast radius.** Have the genuine agent cover `@method` and `@path` too, and
   show that a leaked signature now replays against exactly one URL.
3. **Your own logs.** `python tools/verify_real.py <ip> --claim googlebot` runs the real
   FCrDNS check and range match against an address from a server you operate.
4. **IPv6.** Add `ipv6Prefix` entries and an IPv6 PTR to the fixtures. Where does
   `name_matches()` and the reverse-zone pattern need changing?
5. **mTLS, conceptually.** Sketch what a client-certificate allowlist would need from the
   operator and from your edge, and why no crawler operator offers it today.
