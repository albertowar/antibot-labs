# Chapter 2 Lab: API, GraphQL & WebSocket Abuse

Starts from: `workshops/03-advanced/starter/` (contract 1.5). Adds: three ext modules that open the store's data plane (the versioned REST API `/api/v2/*`, the GraphQL endpoint `/graphql` and the WebSocket drop feed `/ws/drop`), five defenses of the arms race (`rate_cost`, `graphql_limits`, `persisted_queries`, `ws_guard`, `request_signing`) with the two support layers `token_binding` and `response_deception`, the first-party API client the shoppers and the attackers share, and the 40 shoppers recast as API users.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `data/persisted_queries.json`
- `defenses/graphql_limits.py`
- `defenses/persisted_queries.py`
- `defenses/rate_cost.py`
- `defenses/request_signing.py`
- `defenses/response_deception.py`
- `defenses/token_binding.py`
- `defenses/ws_guard.py`
- `demo_site/ext/api_v2.py`
- `demo_site/ext/gql.py`
- `demo_site/ext/gql_schema.py`
- `demo_site/ext/ws_feed.py`
- `tools/api_sdk.py`
- `tools/personas_ch2.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** five rounds of attack 🔴 and defend 🔵, then a debrief. See `../chapter_02_content.md`, §2.8. **Style: wire-it.** Each defense ships as a stub with a `TODO (Round N)` and the finished file is in `solutions/roundN/`; `--catch-up` installs rounds 1..N and `--restore` puts your files back. The checks are already wired into `defenses/ladder.py`, so a round's work is one function.

You play both sides. Bots attack the data plane of the Kestrel Outfitters store (its REST API, its GraphQL endpoint and its WebSocket feed) and you add the defense that catches each one, measuring what it costs the real customers at every step.

This lab runs on the W3 starter's store and shows what **this lab adds**. Products, accounts, orders, reviews, the edge and the decision log are the starter, unchanged; the catalogue API is the starter's `/api/products` (this chapter does not ship a second one). The contract (`workshops/STORE_CONTRACT.md`) reserves `/api/v2/*` and `/graphql` for this chapter, and the three ext modules below mount there.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py` (the REST and GraphQL calls) or `tools/api_sdk.py` (the WebSocket client, which builds its URL from `labclient.BASE_URL`), and both ask `labnet.py` at the lab root for `DEMO_URL` and refuse anything that is not this machine (side-service URLs such as `REDIS_URL` too) before a single request is sent. The store's edge accepts the lab headers only from loopback. Do not remove that check.
- **Everything is synthetic.** Accounts are the starter's `user000..299@example.test` and the attacker's own `mallory@example.test`; tokens are signed by the store's lab secret; "source addresses" are rented from `data/world.json` (documentation ranges, RFC 5737 and RFC 3849) and sent in `X-Lab-Client-IP`. The lab never routes through a real proxy or a proxy list.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own. A GraphQL endpoint that allows introspection and a WebSocket that trusts `Origin` are findings in someone else's application, not a lab.

```
lab/
  README.md              this file
  requirements.txt       pinned versions (Python 3.12+; Strawberry, flask-sock, websockets, PyJWT on top of the starter's)
  demo_site/ext/
    api_v2.py            /api/v2/{auth/login, reviews, account/orders, inventory/<sku>}; the enricher that decodes the bearer token
    gql.py               POST /graphql (single or array-batched); gql_schema.py is the Strawberry schema (circular Order <-> User)
    ws_feed.py           /ws/drop (flask-sock): subscribe and bid frames; runs the ladder once per frame, phase ws:message
  defenses/
    rate_cost.py         Round 1 TODO: cost-aware rate limit + enumeration penalty (REST)
    graphql_limits.py    Round 2 TODO: introspection off, depth / alias / token caps
    persisted_queries.py Round 3 TODO: trusted-document allowlist, fragment-aware counting
    ws_guard.py          Round 4 TODO: Origin, auth for bids, per-connection bucket (handshake + every frame)
    request_signing.py   Round 5 TODO: verify the HMAC signature and timestamp
    token_binding.py     Round 5, ships done: coarse client binding (network class + UA family)
    response_deception.py Round 5, ships done: poison served instead of a refusal on the inventory read
    ladder.py            levels 1-5 wired (yours, but the stubs are already in it)
  data/persisted_queries.json   the three trusted documents of the first-party client
  attacks/               round1_scrape.py ... round5_token_replay.py (rounds 4 and 5 take flags for their variants); _common.py
  tools/
    api_sdk.py           the first-party client (login, signed reads, persisted GraphQL, the feed): shoppers AND attackers use it
    personas_ch2.py      the 40 shoppers as API users: browser, signed mobile app, feed watcher
    checkpoint.py        ROUNDS and thresholds
  solutions/round1..5/   reference files (applied by `checkpoint.py --catch-up`)
```

**Why Python only.** Every surface here (HTTP, GraphQL, WebSocket) has a first-class Python client, and the defenses are server-side. No browser automation is needed, so the lab stays light.

## Setup

```bash
python3.12 -m venv .venv && . .venv/bin/activate        # one venv per chapter, see the root README
pip install -r requirements.txt
python tools/doctor.py                                   # preflight
python demo_site/app.py                                  # http://127.0.0.1:5000, SQLite + in-process Redis, no Docker
```

Setup beyond the shared walkthrough (`onboarding/setup/PREWORK.md`) is the five lines for GraphQL, WebSockets and tokens in `requirements.txt`. Each round runs the store at a `DEFENSE_LEVEL`; the checkpoint sets it for you (`POST /lab/level`) and reloads the defenses on change, so you rarely restart anything. (Edits to `demo_site/ext/` need a restart; you should not need to make any.) To drive it by hand:

| DEFENSE_LEVEL | Adds | Module | Beats | Round |
|---|---|---|---|---|
| 0 | nothing: the attacker's playground | none | | |
| 1 | cost-aware REST rate limiting | `rate_cost` | the bulk export and the id walk | 1 |
| 2 | introspection off, depth / alias / token caps | `graphql_limits` | introspection, alias batching | 2 |
| 3 | persisted-query allowlist (+ fragment-aware counting) | `persisted_queries` | fragment amplification | 3 |
| 4 | WS Origin, auth for bids, per-connection bucket | `ws_guard` | flood and cross-site hijack | 4 |
| 5 | HMAC signing + token binding (+ deception on the inventory read) | `request_signing`, `token_binding`, `response_deception` | token replay | 5 |

The starter's bands turn the score into an outcome: `score < 20` allow, `20-39` monitor, `40-74` challenge, `>= 75` block. The checks here raise 80 points for a violation, or return a hard verdict (`rate_limit` for a spent cost budget, `block` or `rate_limit` for a refused WebSocket frame).

> A block reply is the same generic 403 at every level. The reason is in the lab-only `X-Lab-Signals` header (`LAB_HEADERS=1`). In production, never tell a client which rule caught it.

**How the gate sees each surface** (no contract change was needed):

| Surface | Phase the ladder runs in | What the check reads |
|---|---|---|
| REST `/api/products*`, `/api/v2/*` | `request` | path, arguments, the bearer subject (`ctx.attrs["bearer"]`) |
| GraphQL `POST /graphql` | `request` | the operations in `ctx.json` (one object, or an array when the client batches) |
| WebSocket handshake `GET /ws/drop` | `request` | the `Origin` header against `ctx.host` |
| WebSocket frames | `ws:message`, run by the route for every frame | `ctx.attrs["ws"]`: the frame, the subject, the connection's bucket |
| The two protected `/api/v2` reads | `action:api2_orders`, `action:api2_inventory`, run by the route | the signature headers, the exact request bytes, the binding claim |

The decision log gets one row per HTTP request and **one row per WebSocket connection** (its `ms` is the gate cost of an average frame, its `extra` the frame counts). That is the blind spot an HTTP rate limiter has: a flood is a single request.

### Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: strawberry` or `flask_sock` | `pip install -r requirements.txt` in the lab's own `.venv` |
| `unknown command 'hello'` from Redis | an old `fakeredis`; reinstall the requirements (needs `fakeredis[lua]==2.39.0`) |
| Checkpoint says it cannot reach the store | start it (`python demo_site/app.py`) or use `python tools/verify.py --round N`, which starts one on a free port |
| A round's attacker "succeeded" and you expected a block | restart is not needed (`LAB_RELOAD=1`); check that you saved the module and that its `CHECK` is the one in `defenses/ladder.py` |
| A shopper is refused after you edit a query | at Round 3 only the trusted documents in `data/persisted_queries.json` run; the shoppers send those exact strings through `tools/api_sdk.py` |
| Want a clean slate | `curl -X POST 'http://127.0.0.1:5000/lab/reset?mode=full'` |

## How to measure a round

```bash
python tools/checkpoint.py --round 2
```

It prints PASS or FAIL against explicit thresholds and measures **both sides**:

- **Bot traffic**: this round's attackers, and what they got (`expect`: `blocked` = at most 10 % of what they set out to get).
- **The shoppers**: 40 people through the store's three surfaces (`tools/personas_ch2.py`): 28 browse the REST API and send the storefront's persisted GraphQL query, 8 are the signed mobile app behind two carrier-NAT addresses, 4 watch the live feed from our own origin. A refusal of any kind fails the round.
- **Defender cost**: the median gate time over the shoppers' requests (`Server-Timing: gate`).

`--level N-1` runs the same attackers against the previous round's defense (the "before" column). Fell behind, or want the finished defense? `--catch-up` installs rounds 1..N (one `.bak` per file of yours), and `--restore` puts yours back:

```bash
python tools/checkpoint.py --round 3 --catch-up
python tools/checkpoint.py --restore
```

`python tools/verify.py --round N` does the same against a store it starts itself on a free port (used to build this lab; handy when you do not want a second terminal).

---

## Round 1: REST scraping ⚔️ cost-aware rate limiting (`DEFENSE_LEVEL=1`)

A script from a datacenter address walks `/api/products/p001`, `p002`, ... in order, one detail page at a time, then pulls the review corpus in oversized pages (`/api/v2/reviews?limit=200`). Undefended it drains 720 records in 124 requests.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python tools/checkpoint.py --round 1 --level 0` | the scrape gets 720/720 |
| 🛡️ Defend | implement `score_rest` in `defenses/rate_cost.py` | |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | PASS: 7/720, 0 shoppers hurt |

**Exercise:** spend each request's cost against a per-caller budget, refuse oversized pages, and block a sequential id walk. **Discuss:** which legitimate client is most at risk from an address-keyed budget? Eight phones behind two carrier addresses open the app on the anonymous catalogue first; change `personas_ch2.py` so that every one does it five times and watch the budget charge them as one.

## Round 2: GraphQL introspection + alias batching ⚔️ query limits (`DEFENSE_LEVEL=2`)

One introspection query downloads the whole schema; one aliased operation packs forty `product` fetches into a single HTTP request. Round 1's limiter never looks at `/graphql`.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python tools/checkpoint.py --round 2 --level 1` | introspection maps 8 types, 40 products via aliases |
| 🛡️ Defend | implement `score_query` in `defenses/graphql_limits.py` | |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | PASS: both refused (`graphql_limits:introspection`, `too_many_aliases`), 0 hurt |

**Exercise:** reject introspection and enforce depth, alias and token caps. **Discuss:** why is `__typename` left allowed? **Note:** the alias counter does not follow fragment spreads; remember that for Round 3.

## Round 3: fragment-spread amplification ⚔️ persisted queries (`DEFENSE_LEVEL=3`)

Hide the aliases inside a fragment and spread it. Round 2's alias limiter counts the surface aliases (zero) and waves it through: the shape of CVE-2026-47707.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python tools/checkpoint.py --round 3 --level 2` | bypass: 40 products at resolver cost 40 |
| 🛡️ Defend | implement `score_query` in `defenses/persisted_queries.py` | |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | PASS: `persisted_queries:not_allowlisted`, the shoppers' trusted documents still run |

**Exercise:** enforce a trusted-document allowlist (hash the text you were sent, never a hash the client claims) and count aliases *through* fragments. **Discuss:** why does APQ-that-registers-on-first-use give you no security here?

## Round 4: WebSocket flood + cross-site hijack ⚔️ connection guard (`DEFENSE_LEVEL=4`)

Three attackers on the live drop feed, each beating the control before it, all invisible to any HTTP rate limiter: a forged `Origin` and no token (`cswsh`), the right `Origin` but no token (`anon`), and a login of their own followed by a flood with a valid token (`authed`).

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python tools/checkpoint.py --round 4 --level 3` | all three land 200/200 bids at ~800-1400 frames/s |
| 🛡️ Defend | implement `check_origin`, `authorize` and `message_allowed` in `defenses/ws_guard.py` | |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | PASS: `cswsh` refused at the handshake, `anon` bids rejected, `authed` cut off after 10 bids |

**Exercise:** check the Origin, require auth for state-changing messages, and meter messages per connection. **Discuss:** why does the same-origin policy not save you here? Why is a per-connection bucket the right key when the address is the right key for Round 1?

## Round 5: harvested-token replay ⚔️ request signing (`DEFENSE_LEVEL=5`)

The attacker replays a captured bearer token, unsigned, against the two protected reads: once from their datacenter, once from a home address with the app's User-Agent copied.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python tools/checkpoint.py --round 5 --level 4` | both replays read the victim's orders and the real price, 220.00 |
| 🛡️ Defend | implement `verify` in `defenses/request_signing.py` | |
| ✅ Checkpoint | `python tools/checkpoint.py --round 5` | PASS: orders refused (403), inventory *deceived* (246.40, 12% over the real price) |

**Exercise:** verify the HMAC signature and timestamp. Run the round against the stub first: `token_binding` (already wired, shipped done) stops the naive replay by itself, and only the spoofed one gets through. That is why signing exists. **Discuss:** signing refuses the orders read outright, but inventory is *deceived*; when is each the right call?

## Wrap-up: the scoreboard (debrief)

```bash
python tools/scoreboard.py
```

Read bots stopped next to shoppers hurt across all five rounds. Every round should show **shoppers hurt 0/40**: that is the number that justifies the defense. (In Round 5 the scoreboard reports 41 people; the extra one is the victim, a customer whose token the attacker captured.)

---

## Expected results (self-check)

Generated by `python tools/verify.py --all --catch-up --markdown` (against your own store: `python tools/checkpoint.py --all --markdown`) with the reference solutions, on Linux x86_64 (WSL2), Python 3.12.15, Flask 3.1.3, SQLAlchemy 2.1.4, strawberry-graphql 0.333.0, flask-sock 0.7.0, websockets 17.2, PyJWT 2.15.1, redis 8.1.0, fakeredis 2.39.0, SQLite and the in-process Redis. The counts are deterministic and were identical across two runs; timings vary. A cell is `succeeded/attempted` for the attacker, "before" being `--round N --level N-1` and "after" the round at its own level.

| Round | Level | Attacker | Gets (before → after) | Bots stopped | Shoppers hurt | First signals | Gate per request, median / p95 |
|---|---|---|---|---|---|---|---|
| 1 | 1 | `round1_scrape` (id walk + bulk export) | 720/720 → **7/720** | 117 / 124 requests | 0 / 40 | `rate_cost:sequential_enumeration`, `oversized_page`, `cost_budget` | 3.1 / 5.0 ms |
| 2 | 2 | `round2_graphql_batch` (introspection) | 1/1 → **0/1** | 2 / 2 | 0 / 40 | `graphql_limits:introspection` | 3.1 / 4.9 ms |
| 2 | 2 | `round2_graphql_batch` (alias batch of 40) | 1/1 → **0/1** | (same run) | 0 / 40 | `graphql_limits:too_many_aliases` | |
| 3 | 3 | `round3_fragment_amp` | 40/40 → **0/40** | 1 / 1 | 0 / 40 | `persisted_queries:not_allowlisted` | 3.1 / 4.8 ms |
| 4 | 4 | `round4_ws_flood` (`cswsh`) | 200/200 → **0/200** | 3 / 4 connections and logins | 0 / 40 | `ws_guard:origin_not_allowed` | 3.2 / 5.0 ms |
| 4 | 4 | `round4_ws_flood --origin-ok` (`anon`) | 200/200 → **0/200** | (same run) | 0 / 40 | `ws_guard:unauthenticated`, `message_rate` | |
| 4 | 4 | `round4_ws_flood --login` (`authed`) | 200/200 → **10/200** | (same run) | 0 / 40 | `ws_guard:message_rate` (cut off after 14 frames) | |
| 5 | 5 | `round5_token_replay` (datacenter) | 2/2 → **0/2** (price 246.40) | 4 / 6 requests | 0 / 41 | `request_signing:missing_signature`, `token_binding:client_changed` | 3.2 / 4.9 ms |
| 5 | 5 | `round5_token_replay --spoof` (home address) | 2/2 → **0/2** (price 246.40) | (same run) | 0 / 41 | `request_signing:missing_signature` | |

Shoppers hurt is read from the scoreboard: a person whose last request was a refusal and who bought nothing (the shoppers here browse; they do not buy). Gate time is the decision log's `ms` over the 212 shopper requests (214 in Round 5); a WebSocket connection logs the cost of an average frame. With the Docker stack the gate time is higher (every check makes Redis round trips over TCP); the checkpoint allows 250 ms there instead of 25 ms.

**Things to watch for:**
- Until you implement a round's TODO, the attacker gets through. That is the point. `--catch-up` unblocks you if you fall behind.
- Round 3 is the teaching moment: `DEFENSE_LEVEL=2` does **not** stop fragment amplification, only the allowlist at level 3 does. If your Round 2 alias counter follows fragments, the "before" column for Round 3 shows `0/40`: you wrote the Round 3 fix one round early.
- Round 5 against the stub: the naive replay is already stopped (by `token_binding`) and the spoofed one is not. Both must be refused for the round to pass.
- Round 4's `authed` flood still gets its first 10 bids through: a bucket bounds a flood, it does not make it zero. Lower `BUCKET_CAPACITY` and watch what that does to a chatty legitimate client.

### What the lab leaves out

Real WebSocket servers run behind a load balancer, so the per-connection bucket would live in Redis keyed on the subject (see bonus 3). Real mobile clients get their signing secret from a hardware-backed keystore, not a JSON field (W3 Ch1). `users(first: 100)` in the GraphQL schema hands out e-mail addresses to anybody: the schema is deliberately over-exposed so that one query is worth amplifying. A production schema would put authorization on the field, which no amount of query limiting replaces.

## Bonus challenges

1. **Cursor pagination.** Replace `page` / `limit` on `/api/v2/reviews` with opaque cursors and show how it changes the Round 1 signal, and what it does *not* fix.
2. **Fragment-aware cost on a public API.** You cannot allowlist a public GraphQL API. Keep Round 3's fragment-aware depth / alias limits as the only control (drop the allowlist) and find the query that still gets through.
3. **Redis-backed WS bucket.** Move the Round 4 bucket into Redis keyed on the subject, then show a flood spread across two server processes that the in-process bucket would miss.
4. **Put the carrier NAT under pressure.** In `tools/personas_ch2.py`, make each of the eight phones open the anonymous catalogue five times before logging in. Which Round 1 number do you have to change to keep 0 shoppers hurt, and what does that do to the bulk export?
5. **The Docker path.** `docker compose up -d --wait`, then `REDIS_URL=redis://127.0.0.1:6379/0 DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop python tools/verify.py --round 3 --catch-up`. The counts should match; the gate cost will not. `docker compose down -v` when you are done.
