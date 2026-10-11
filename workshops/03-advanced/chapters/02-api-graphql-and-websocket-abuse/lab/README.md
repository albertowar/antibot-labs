# Chapter 2 Lab: API, GraphQL & WebSocket Abuse

**Format:** 5 rounds of attack ⚔️ defend, ~130 min of rounds plus debrief. See `../chapter_02_content.md`, §2.7.

You play both sides. Bots attack the data plane of the "Lab Runner 9" store — its
versioned REST API, its GraphQL endpoint and its WebSocket feed — and you add the
defense that catches each one, measuring the cost to real users at every step.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- All accounts, products, tokens and egress IPs here are synthetic. "Egress" IPs are claimed in a header the app honours only from loopback, drawn from RFC 5737 (192.0.2.0/24 is the attacker's datacenter).
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  README.md            this file
  requirements.txt     pinned deps (Python 3.12+)
  docker-compose.yml   OPTIONAL Redis + PostgreSQL; the lab runs without Docker
  demo_site/           the shared store, now behind three API surfaces
    app.py             Flask app; DEFENSE_LEVEL gate; Server-Timing cost header
    models.py          Product, User, Order, Decision (SQLAlchemy)
    store.py           fakeredis by default; REDIS_URL / DATABASE_URL to opt in
    schema.py          Strawberry GraphQL schema (circular Order↔User, cost counter)
  defenses/            one module per layer — you implement the TODO in each
    rate_cost.py       L1  cost-aware REST rate limiting          (Round 1)
    graphql_limits.py  L2  introspection off + depth/alias/token  (Round 2)
    persisted_queries.py L3 trusted-document allowlist            (Round 3)
    ws_guard.py        L4  WS origin + auth + per-connection rate  (Round 4)
    request_signing.py L5  HMAC request signing                    (Round 5)
    token_binding.py   L5  coarse bearer-token binding (ships done)
    response_deception.py L5 poison for detected bots (ships done)
    engine.py          fuses the layers by DEFENSE_LEVEL (allow/challenge/block)
  attacks/             roundN_*.py, one per attack step
  solutions/round1..5/ the reference defense for each round (used by --catch-up)
  tools/
    seed.py            create the catalogue, users and the persisted allowlist
    checkpoint.py      run one round end to end; --catch-up applies the solution
    legit_traffic.py   ~40 well-behaved clients across all three surfaces
    scoreboard.py      read the decision log: bots stopped vs real users caught
```

**Why Python only.** Every surface here — HTTP, GraphQL, WebSocket — has a first-class
Python client, and the defenses are server-side. No browser automation is needed, so
the lab stays light.

## Setup (before the session)

```bash
python -m venv .venv && source .venv/bin/activate      # one venv per chapter, see the root README
pip install -r requirements.txt
python tools/seed.py
DEFENSE_LEVEL=0 python demo_site/app.py        # http://127.0.0.1:5000
```

No Docker required: the app uses an in-process `fakeredis` and a local SQLite file by
default. To run the production-shaped backends instead:

```bash
docker compose up -d --wait
export REDIS_URL=redis://127.0.0.1:6379/0
export DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop
python tools/seed.py && DEFENSE_LEVEL=0 python demo_site/app.py
```

**Defense levels.** Each level includes every level below it. Start the server at the
level a round calls for, in a terminal of its own.

| Level | Adds | Module | Beats |
|---|---|---|---|
| 0 | nothing — the attacker's playground | — | — |
| 1 | cost-aware REST rate limiting | `rate_cost` | Round 1 scraping |
| 2 | introspection off + depth/alias/token limits | `graphql_limits` | Round 2 GraphQL |
| 3 | persisted-query allowlist (+ fragment-aware cost) | `persisted_queries` | Round 3 amplification |
| 4 | WS origin + auth + per-connection rate | `ws_guard` | Round 4 flood/CSWSH |
| 5 | HMAC signing + token binding + deception | `request_signing` … | Round 5 replay |

Score thresholds (defenses/engine.py): **< 30 allow, 30–59 challenge, ≥ 60 block.**

> A block reply lists the reasons it fired. That is for teaching only. In production,
> never tell a client which rule caught it.

## How to measure a round

Start the server at the round's level, then from a second terminal:

```bash
python tools/checkpoint.py --round 2         # with DEFENSE_LEVEL=2 running
```

```
── Round 2 checkpoint (DEFENSE_LEVEL=2) ──
🔴 Bot traffic:   introspection_blocked=True alias_batch_blocked=True
🔵 Real users:    40/40 served, 0 blocked (false positives)
💸 Defender cost: 8 scored, p50 0.78 ms/request

✅ PASS — attack stopped, no false positives
```

A round passes when the attack is **stopped** and **no legitimate client is blocked**.
The shipped `defenses/` are stubs with a `TODO (Round N)` — implement it, or, if you
fall behind, apply the reference and restart the server:

```bash
python tools/checkpoint.py --round 2 --catch-up   # copies solutions/round2 → defenses, saving .bak
```

`python tools/scoreboard.py` prints the decision log at any time: allow/challenge/block
per endpoint, the top reasons, per-request cost, and bots-stopped vs real-users-caught.

---

## Round 1: REST scraping ⚔️ cost-aware rate limiting (28 min)

An async client walks `/api/v2/products` with oversized pages and enumerates
`/api/v2/products/<id>` in order, draining the catalogue — and surfacing the internal
`hidden` SKUs that are never linked from the UI.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `DEFENSE_LEVEL=0 python demo_site/app.py`, then `python attacks/round1_scrape.py` | ~500 products, 11 hidden SKUs, 0 blocked |
| 🛡️ Defend | Implement the TODO in `defenses/rate_cost.py`; restart at `DEFENSE_LEVEL=1` | — |
| 🗡️ Re-run | `python attacks/round1_scrape.py` | scrape stops at ~100 products, the rest blocked |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | PASS, 0 false positives |

**Exercise:** spend each request's cost against a per-key budget, penalise oversized
pages, and block a sequential id walk. **Discuss:** which legitimate client is most at
risk from an IP-keyed budget? (CGNAT and corporate NAT — see §2.12.)

## Round 2: GraphQL introspection + alias batching ⚔️ query limits (28 min)

One introspection query downloads the whole schema; one aliased operation packs dozens
of `product` fetches into a single HTTP request.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | at `DEFENSE_LEVEL=1`, `python attacks/round2_graphql_batch.py` | introspection maps 8 types; 40 products via aliases |
| 🛡️ Defend | Implement the TODO in `defenses/graphql_limits.py`; restart at `DEFENSE_LEVEL=2` | — |
| 🗡️ Re-run | `python attacks/round2_graphql_batch.py` | introspection BLOCKED, alias batch BLOCKED |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | PASS, 0 false positives |

**Exercise:** reject introspection and enforce depth/alias/token caps. **Discuss:** why
is `__typename` left allowed? **Note:** the alias counter here does not follow fragment
spreads — remember that for Round 3.

## Round 3: fragment-spread amplification ⚔️ persisted queries (26 min)

Hide the aliases inside a fragment and spread it. Round 2's alias limiter counts the
surface aliases (zero) and waves it through — the shape of CVE-2026-47707.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | at `DEFENSE_LEVEL=2`, `python attacks/round3_fragment_amp.py` | bypass: 40 products at resolver cost 40 |
| 🛡️ Defend | Implement the TODO in `defenses/persisted_queries.py`; restart at `DEFENSE_LEVEL=3` | — |
| 🗡️ Re-run | `python attacks/round3_fragment_amp.py` | BLOCKED: query not in persisted allowlist |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | PASS, 0 false positives |

**Exercise:** enforce a trusted-document allowlist and count aliases *through* fragments.
**Discuss:** why does APQ-that-registers-on-first-use give you no security here?

## ☕ Break (10 min)

## Round 4: WebSocket flood + cross-site hijack ⚔️ connection guard (26 min)

One WebSocket, opened from a forged origin with no token, floods bid messages — invisible
to any HTTP rate limiter.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | at `DEFENSE_LEVEL=3`, `python attacks/round4_ws_flood.py` | connected; hundreds of bids/s accepted |
| 🛡️ Defend | Implement the TODO in `defenses/ws_guard.py`; restart at `DEFENSE_LEVEL=4` | — |
| 🗡️ Re-run | `python attacks/round4_ws_flood.py` | origin refused / bids rejected / connection closed |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | PASS, 0 false positives |

**Exercise:** check the Origin, require auth for state-changing messages, and meter
messages per connection. **Discuss:** why does the same-origin policy not save you here?

## Round 5: harvested-token replay ⚔️ request signing (21 min)

The attacker replays a captured bearer token from their datacenter, unsigned, against the
protected endpoints.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | at `DEFENSE_LEVEL=4`, `python attacks/round5_token_replay.py` | reads 2 victim orders; real price 220.00 |
| 🛡️ Defend | Implement the TODO in `defenses/request_signing.py`; restart at `DEFENSE_LEVEL=5` | — |
| 🗡️ Re-run | `python attacks/round5_token_replay.py` | orders 401; inventory poisoned (246.40) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 5` | PASS, 0 false positives |

**Exercise:** verify the HMAC signature and timestamp. **Discuss:** signing blocks the
orders read outright, but inventory is *deceived* instead — when is each the right call?

## Wrap-up: the scoreboard (debrief)

```bash
python tools/scoreboard.py
```

Read bots-stopped next to real-users-caught across all five rounds. Every round above
should show real users caught = 0. That is the number that justifies the defense.

---

## Instructor: expected results

Verified October 2026 with Python 3.12.15, Flask 3.1.3, SQLAlchemy 2.1.4, strawberry-graphql 0.333.0, flask-sock 0.7.0, websockets 17.2, PyJWT 2.15.1, redis 8.1.0, fakeredis 2.39.0, on the fakeredis + SQLite default (levels 1-5 pass `tools/checkpoint.py --catch-up` with 40/40 legitimate clients served; every attack run at level 0 reproduces the first column). The `docker compose` path is verified separately. A cell is the
attack's outcome at that cumulative `DEFENSE_LEVEL`; **bold** marks the level that first
stops it.

| Attack ↓ / DEFENSE_LEVEL → | 0 | 1 | 2 | 3 | 4 | 5 | First reason at the blocking level |
|---|---|---|---|---|---|---|---|
| R1 REST scrape | 500 scraped | **~100, rest blocked** | blocked | blocked | blocked | blocked | cost budget + sequential enumeration |
| R2 introspection + aliases | maps 8 types, 40 via aliases | pass | **blocked** | blocked | blocked | blocked | introspection off / alias cap |
| R3 fragment amplification | 40 @ cost 40 | 40 @ cost 40 | 40 @ cost 40 (naive count misses it) | **blocked** | blocked | blocked | query not in persisted allowlist |
| R4 WS flood + CSWSH | ~hundreds/s | floods | floods | floods | **blocked** | blocked | origin not allowed / bucket close |
| R5 token replay | reads orders, real price | reads | reads | reads | reads | **401 + poisoned** | missing signature / token binding |
| Legitimate users (40) | 40/40 | 40/40 | 40/40 | 40/40 | 40/40 | 40/40 | — (0 false positives at every level) |

**Things to watch for.** The Round 3 row is the teaching moment: DEFENSE_LEVEL=2 does
**not** stop fragment amplification — only the allowlist (L3) does. If a cohort sees R3
blocked at L2, their Round 2 alias counter is wrongly following fragments. Defender cost
(Server-Timing `score;dur`) stays around 1–3 ms per request on the default backend; it
rises slightly on the signed and rate-limited paths because those touch the store.

## Troubleshooting

| Problem | Fix |
|---|---|
| `Address already in use` / port 5000 taken | `PORT=8099 DEFENSE_LEVEL=0 python demo_site/app.py` and `export DEMO_URL=http://127.0.0.1:8099` for the attack/tool terminals |
| `connection refused` from a script | the server is not running at the level the round needs; start it first |
| Round blocks legit users | you are keying the limiter on something too coarse, or the mobile client's signature/persisted query does not match — re-run `tools/seed.py` |
| GraphQL query rejected after editing it | at L3 only the persisted (allowlisted) operations run; regenerate with `tools/seed.py` if you changed the client's queries |
| Fresh slate | `curl -X POST http://127.0.0.1:5000/admin/reset` clears the decision log and counters; `python tools/seed.py` rebuilds the catalogue |

## Bonus challenges

1. **Cursor pagination.** Replace page/`per_page` with opaque cursors and show how it
   changes the Round 1 enumeration signal — and what it does *not* fix.
2. **Fragment-aware cost on a public API.** You cannot allowlist a public GraphQL API.
   Keep L3's fragment-aware depth/alias/cost limits as the only control and find the
   query that still gets through.
3. **Redis-backed WS bucket.** Move the Round 4 per-connection bucket into Redis keyed on
   the subject, then show a flood spread across two server processes that the in-process
   bucket would miss.
