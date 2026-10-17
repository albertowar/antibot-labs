# The demo store contract

**Kestrel Outfitters** is the one e-commerce store every chapter of the series defends. This file is the
contract between the store, the chapter labs and the attack scripts: routes, data, headers, environment,
and the hook points a chapter uses to add a defense or a feature. The Demo Store deck
(`onboarding/demo-store/`) walks through the shop, the Lab Harness deck (`onboarding/lab-harness/`)
through the hook points; every starter and lab README points here.

Contract version: **1.7** (recorded in each starter's `STARTER.json`). Changing anything under
"Canonical surface" is a contract bump: rebuild the starters (`scripts/build_starter.py`) and rerun
`tools/smoke.py` in every lab.

| Version | Change |
|---|---|
| 1.0 | first version |
| 1.1 | backward-compatible hook additions from the W1 Ch7 pilot: per-type clearance TTL and uses, `revoke_clearance`, `verify` may return a reason, `PAGE_HOOKS` may replace the response, `personas_*.py` auto-load, multi-attack rounds with `expect`, `verify.py --level/--all` on a free port, `Server-Timing` split into `gate` and `app`, scoreboard counts hurt people instead of stopped requests |
| 1.2 | the series-wide guard: `labnet.py` at the lab root (a byte-identical copy of `scripts/labnet.py`) refuses non-local `DEMO_URL` and side-service URLs; the client moves from `tools/labnet.py` to `tools/labclient.py` (attacks import `labclient`); `checkpoint.py --restore`; `postgres:18.6-alpine` in compose |
| 1.3 | additive, for W1 Ch3: the edge keeps client `X-Forwarded-For` aside as a claimed chain (`ctx.edge.xff_claimed`, `/whoami`); `world.json` pool keys `spread`, `listed`, `feeds` and top-level `groups` (honoured by `build_world.py` and `labclient.world_pool`); pools `cloud_gcp`, `cloud_v6`, `free_proxy`, `bulletproof_host`, `resi_us`..`resi_in` (group `residential_proxy_net`); `private_relay` also on the VPN list; feeds `drop_v4.json`, `firehol_level1.netset`, `manifest.json`, `README.md` (provenance); `smoke.py` checks the world |
| 1.4 | two fixes: the baseline pins `fakeredis[lua]` so `ctx.bucket` (a Lua script) works on `REDIS_URL=memory://` instead of raising into a silent `<check>:error` allow, and `smoke.py` exercises it once; `LabClient.verdict()` returns the `X-Lab-Verdict`/`X-Lab-Score`/`X-Lab-Signals` of a blocked (4xx) response instead of `None` (the old guard treated a falsy `requests.Response` as "no response") |
| 1.5 | additive, for W1 Ch8 (and the W4 crawl-policy chapters): `/robots.txt` is extensible — an ext registers `hooks.robots(provider)` (a callable returning extra lines, called per request so lines may vary with the level) and `routes/seo.py` appends them to the base policy; the base body is byte-identical when nothing registers |
| 1.6 | additive, for the W4 chapters: (a) `hooks.on_action(name, fn)` now actually fires — the `review`, `checkout` and `drop_buy` routes (HTML and JSON) call it after a successful write with the row (`review=`/`order=`), and the handler may hold it (`status="pending"`), attribute it, or return a replacement response (e.g. a 202); nothing registered leaves the default behaviour byte-identical. (b) `hooks.on_reset(fn)` runs after `POST /lab/reset` so an ext can drop or reseed its own tables and keys. (c) the scoreboard gives a chapter-specific `outcome` (an ext setting `g.outcome`, e.g. `paywalled`/`charged`/`held`) its own column instead of folding it into `other` |
| 1.7 | the gaps the 29 lab migrations recorded (the old `TODO.md` §1.2). **Behaviour changes:** (a) `X-Lab-Verdict` and the log's `action` report the most severe decision of the request (allow < monitor < challenge < rate_limit < deceive < block, score as the tie-break), so a zero-score 429 no longer reads `allow`; checkpoints that want the HTTP result keep reading `outcome`. (b) `/api/challenge` and `/api/challenge/verify` are exempt from the challenge band (block and rate_limit still apply): a client whose every request scores into the band can now actually solve. (c) a soft `Verdict` with a score and no signals carries its points as one synthesized signal instead of summing to 0 and deciding `allow`. (d) a `deceive` verdict is honoured on login (byte-identical wrong-password 401, password never checked), register, review and newsletter (`routes/deceive.py`, called from `guard()`); checkout and drop keep their fakes in the route. (e) `robots.txt` drops its leading `Allow: /` (allow is the RFC 9309 default), so first-match parsers honour later `Disallow` lines, a chapter's bait entries included. (f) `tools/smoke.py` asserts 122 *visible* products (`/lab/status` `visible_products`), so hidden honeypot rows may sit in the catalogue; it requires no `X-Lab-*` headers on `/robots.txt` or ungated paths; and `tools/verify.py --smoke` sets `LAB_SMOKE=1` (the gate runs an empty ladder at every level), so a lab baseline at `LADDER[0]` passes smoke. (g) on `memory://` the token bucket runs in Python under one process lock (fakeredis serialized every thread for the whole Lua interpretation, ~10 ms per call under a 16-thread attack; real Redis keeps Lua). **Additive:** `hooks.ungate(prefix, session=True)` (Ctx, session cookie, enrichers and a log row, but no ladder); `hooks.on_response(fn)` (every response, gated or not, timed as gate cost); `hooks.stopped_outcome(*names)`; `on_action` also fires for `register` (after the account) and `login` (every attempt, `result={"user", "ok", "reason"}`); `Ctx.route/view_args/query_string/scheme`, `ctx.resumed`, `ctx.cleared(type)`, public `gate.spend_clearance`; `policy.decide` may declare `ctx=`; a challenge interstitial that interrupted a form POST carries the form in a hidden `#challenge-replay` resubmit (and `window.labReplay()`); held orders — the scoreboard counts only `status="paid"` orders as purchases, and `demo_site/orders.py cancel_order(order)` returns stock; a `legit:` actor kind (welcome automation) with its own scoreboard columns, added only when such actors exist, and judged by the checkpoint (`Round.legit_hurt_max`, default 0: a stopped verified crawler is a false positive that fails the round); `Round.setup(level, caught_up)/teardown(level)/people/threads` and `scenario=None`; `population.POST_HOOKS`; `labclient.browser_context(..., ja4=, user_agent=, headers=, headers_fn=)`; `defenses/netinfo.py` (network type from the feeds) joins the skeleton |

## 1. The store

A trail-sneaker and outdoor-gear outfitter with limited drops. The mix attracts every bot the series
teaches against: scalpers (drops), scrapers (120 priced SKUs, feeds, sitemap), credential stuffers
(accounts with loyalty points, saved cards, gift cards), review and sign-up spam (reviews, newsletter,
registration). Nothing is real: no payments are processed, every user is synthetic.

- Name and tagline: `demo_site/config.py` (`STORE_NAME`, one constant).
- Stack: Flask 3.1 + SQLAlchemy 2.1 + Redis. Zero-Docker default: SQLite (WAL) + in-process fakeredis.
  Compose path: `redis:8.10.2-alpine` + `postgres:18.6-alpine` (volume at `/var/lib/postgresql`), bound to 127.0.0.1.
- Python 3.12, one venv per chapter. Pins in `requirements.txt` are the series baseline.

## 2. Starters and the copy model

```
workshops/01-initiation/starter/     the skeleton (this contract, no defenses wired), written by hand
workshops/02-proficient/starter/     the skeleton + the W2 baseline (workshops/02-proficient/starter.manifest.json)
workshops/03-advanced/starter/       the skeleton + the W3 baseline
workshops/04-ai-era-bots/starter/    the skeleton + the W4 baseline
```

A chapter lab **copies** its workshop's starter (`labnet.py`, `demo_site/`, `defenses/`, `tools/`, `data/`, compose
and requirements) and adds its rounds on top. Labs never import across chapters and never edit starter
files; they add `defenses/<name>.py` checks and `demo_site/ext/<name>.py` modules. The W2-W4 starters
are never edited by hand: change the skeleton or the manifest, rebuild (`scripts/build_starter.py --all`),
and `scripts/starter_check.py` reports drift.

Every baseline is empty today (decision in `DECISIONS.md`). No starter is a previous workshop's end
state: each workshop runs on its own, and a chapter that needs an earlier control at its Round 0 (W1's
header rules, say) adds it in its own lab. A baseline that ever grows is listed in its starter's README,
with why each control is there.

Every lab README starts with: `Starts from: workshops/<NN>/starter/ (contract X.Y). Adds: …`, where
X.Y is the contract version the lab was built (or last re-based) against.

## 3. Canonical surface

### 3.1 HTML pages

| Route | Purpose | Bait for |
|---|---|---|
| `/` | home: hero, drops, top rated | crawlers |
| `/products` (`?page&category&q&sort`), alias `/catalog` | catalog, 24 per page | scrapers |
| `/product/<sku>` | product page, reviews, add to cart | scrapers, review spam |
| `/search?q=` | search results | scrapers |
| `/cart`, `POST /cart/add`, `POST /cart/remove` | cart (Redis, per session) | inventory hoarding |
| `/checkout` GET/POST | address + test card, atomic stock decrement | carding, fraud |
| `/drop/<sku>` GET/POST | limited drop: countdown, size, one unit per request | scalpers |
| `/login`, `/logout`, `/register` | account | credential stuffing, fake accounts |
| `/account`, `/orders` | profile, loyalty, saved card, orders | account takeover |
| `/gift-cards` GET/POST | balance check, redeem | gift-card cracking |
| `POST /review/<sku>` | post a review | review spam |
| `POST /newsletter` | sign-up | list bombing |
| `/robots.txt`, `/sitemap.xml`, `/feed.xml`, `/health` | hygiene | crawlers |
| `/img/<sku>.svg?w=` | product image (generated, cacheable) | asset fetch patterns |

HTML forms carry a hidden `csrf` field (session-bound). Every form works with JavaScript disabled.
Mind `/feed.xml` in a crawl-economics chapter: it hands any crawler the 20 newest records (name, blurb,
link) for free, so a lab that prices or gates the catalogue must include it in its paid or governed paths.

### 3.2 JSON API (`/api/*`)

`GET /api/products` (same filters as the page), `GET /api/products/<sku>` (with `stock`), `GET /api/search`,
`GET /api/reviews/<sku>`, `POST /api/reviews`, `GET /api/cart`, `POST /api/cart/add`, `POST /api/cart/remove`,
`POST /api/checkout`, `POST /api/buy` (drops: `{sku, size, email?}`), `POST /api/login`, `POST /api/register`,
`POST /api/logout`, `GET /api/account`, `GET /api/orders`, `POST /api/password-reset`,
`POST /api/password-reset/confirm`, `GET /api/gift-cards/balance?code=`, `POST /api/gift-cards/redeem`,
`POST /api/telemetry`, `GET /api/challenge?type=`, `POST /api/challenge/verify`.

Shapes: lists are `{items, page, pages, total}`; errors are `{"error": {"code", "message"}}` with the
HTTP status; money is `price_cents` plus a convenience `price`. JSON routes rely on the `SameSite=Lax`
session cookie, not on the csrf field.

`POST /api/telemetry {"kind": "...", ...}` is the **one sink** for every collector a chapter ships
(sensor, behavior, fp, pow_bench, …). The latest payload per kind is kept per session
(`ctx.telemetry(kind)`), the last 5000 per kind in `lab:telemetry:<kind>`.

Retired names (do not reintroduce): `/admin/*`, `/api/v0/*`, `/api/sensor`, `/api/session`, `/api/fp`,
`/telemetry`, `/products/<sku>`, `/signup`. `/api/v2/*` and `/graphql` are W3 Ch2 ext routes.
Retired request headers (the edge drops every `X-Lab-*` except the three in §3.6, so a chapter's own
header must not use that prefix): `X-Lab-Source-IP`, `X-Sim-Client-IP`, `X-Lab-Egress`, `X-Lab-Session`,
`X-Lab-FP`, `X-Lab-User`, `X-Lab-Round`, `X-Lab-Run`, `X-Lab-Admin`. The one client-IP header is
`X-Lab-Client-IP`; a session comes from the cookie, a round/run from the level, and scoring ground truth
travels only via `X-Lab-Actor` (moved to `environ["lab.actor"]`, unreadable by any defense).

### 3.3 Lab routes (loopback only, skipped by the gate, never "production")

| Route | Purpose |
|---|---|
| `GET /whoami` | what the edge resolved for you, session, user, level, last decision |
| `GET /lab/status` | level, ladder, loaded ext modules, challenge types, telemetry kinds, counts |
| `GET /lab/config` | the running `Config` |
| `GET /lab/decisions?actor=&since=&path=&limit=` | the decision log |
| `GET /lab/scoreboard?since=` | per-actor outcomes: bots stopped vs shoppers hurt, purchases, drop stock |
| `POST /lab/reset?mode=state\|full&stock=` | state: drop stock, lab rows, Redis, log; full: reseed |
| `POST /lab/level {"level": N}` | change `DEFENSE_LEVEL` live |
| `POST /lab/reload` | force a reload of `defenses/*` |
| `GET /lab/mailbox/<email>` | reset tokens and OTPs the store "emailed" |

### 3.4 Response headers (on every gated response, `LAB_HEADERS=1`)

`X-Lab-Verdict` (`allow|monitor|challenge|block|rate_limit|deceive`), `X-Lab-Score` (0-100),
`X-Lab-Signals` (`layer:name,…`), `X-Lab-Level`, `X-Lab-Shadow` (signals from shadow checks, when any),
`Server-Timing: gate;dur=…, app;dur=…, <check>;dur=…`. `gate` is the defender cost only (building the
`Ctx`, enrichers, every ladder pass of the request, `on_response` hooks); `app` is the whole request
including the route; one entry per check that ran. The decision log's `ms` is the `gate` figure;
`extra.total_ms` is `app`. When a request ran several ladder phases, the verdict and score reported are
the request's **most severe** decision (allow < monitor < challenge < rate_limit < deceive < block;
score breaks ties), not its highest-scoring one; `outcome` says what the client actually got.

### 3.5 Environment

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | 5000 | listen port (127.0.0.1 only) |
| `DATABASE_URL` | `sqlite:///instance/shop.db` | or `postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop` |
| `REDIS_URL` | `memory://` | in-process fakeredis; or `redis://127.0.0.1:6379/0` |
| `DEFENSE_LEVEL` | 0 | enforce `LADDER[k]` for `k <= level`; 0 = baseline only |
| `LAB_SEED` | 1337 | every seed derives from it |
| `LAB_HEADERS` | 1 | 0 hides the `X-Lab-*` oracle (what production looks like) |
| `LAB_SHADOW` | 0 | 1 runs above-level checks in shadow (logged, never enforced) |
| `LAB_SHADOW_CHECKS` | | checks forced to shadow regardless of level (W4 crawler labs) |
| `LAB_RELOAD` | 1 | reload `defenses/*.py` on change (no restarts between rounds) |
| `LAB_SMOKE` | 0 | 1: the gate runs an empty ladder at every level — the contract test's view of the bare store (`verify.py --smoke` sets it; set it yourself when running `tools/smoke.py` against a hand-started store whose lab wires `LADDER[0]`) |
| `DROP_STOCK` | 50 | units per drop at seed and reset (W1 Ch9 uses 20) |
| `LAB_HASH_ITERS` | 5000 | PBKDF2 iterations (lab speed) |
| `DEMO_URL` | `http://127.0.0.1:5000` | client side; `labnet.py` (via `tools/labclient.py`) refuses non-local hosts |

### 3.6 The simulated edge (`demo_site/lab_edge.py`, `data/world.json`)

- Loopback only; anything else is 403.
- **One** simulated-IP header: `X-Lab-Client-IP`. Honoured only if the address is inside a `world.json`
  pool; otherwise 421. No header means `student_ip` (a home broadband address).
- `X-Lab-Actor` is ground truth (`human:<persona>:<n>`, `bot:<name>`). It is moved to `environ["lab.actor"]`
  before the app runs; only the decision logger and the order record read it. `tools/smoke.py` fails
  any defense or ext that reads it.
- `X-Lab-JA4` is kept as a *claimed* fingerprint (`ctx.edge.ja4_source == "claimed"`) until a TLS edge
  (W2 Ch5) sets a measured one. Every other `X-Lab-*` request header is dropped — the prefix is
  **reserved for the edge**, so a chapter's own request header (a login token, a lab calendar stamp)
  must use another name or the edge eats it.
- A TLS edge reports a measurement through two WSGI environ keys the gate reads:
  `environ["lab.ja4_measured"]` (sets `ctx.edge.ja4` with `ja4_source == "measured"`, outranking any
  claim) and `environ["lab.h2"]` (the HTTP/2 fingerprint, `ctx.edge.h2`). Nothing in the starter sets
  them; W2 Ch5's `ext/tls_edge.py` middleware fills them from fingerproxy's headers (and strips the
  headers), and any lab that wants a measured JA4 reuses that shim.
- Client-supplied `X-Forwarded-For` is removed from the headers and never trusted by the edge. Like a CDN,
  the edge appends the peer and keeps the chain aside as `ctx.edge.xff_claimed` (`"<client value>, <ip>"`,
  or just `<ip>`): everything left of the last entry is attacker-controlled. Only W1 Ch3 reads it, to
  show the leftmost-entry bug; `ctx.edge.ip` is always the rented address.
- Defenses see `ctx.edge = EdgeInfo(ip, asn, org, country, pool, ja4, ja4_source, h2, xff_claimed)`. The
  pool's `type` is never exposed; infer it from `data/feeds/*` (`tools/build_world.py`), as production does.
- Addresses: RFC 5737 / RFC 3849 only, ASNs from RFC 5398 (64496-64511, 65536-65551); `build_world.py
  --check` rejects anything else. Allocation: `192.0.2.0/24` residential ISPs; `198.51.100.0/24` mobile
  CGNAT, corporate, university, privacy relay (.0-.95), `cloud_gcp`, `free_proxy`, `bulletproof_host`
  (.96-.223); `203.0.113.0/24` datacenter, hosting, VPN, Tor, open proxies (full); one `2001:db8:<x>::/48`
  (or /64) per pool that needs a large fleet. Add a pool to `world.json` (and rebuild feeds) rather than
  inventing addresses in a script. One consequence to design around: every home-broadband user lives in
  the same `192.0.2.0/24`, so a per-/24 cohort or reputation count is meaningless for them — count exact
  addresses (as W2 Ch7's features do, with a comment saying why).
- Pool keys beyond `cidr`/`hosts`/`asn`/`org`/`type`/`country`/`tz`: `spread: 64` enumerates one host per
  /64; `listed: 0.75` puts only the first 75 % of the hosts on a per-address feed (Tor, open proxies);
  `feeds: {"hosting_asns": false}` overrides the feeds a type lands in (the gaps of free feeds). Top-level
  `groups` names pools a client rotates over as one (`world_pool("residential_proxy_net")`: six countries,
  one address per /64).
- Feeds are synthetic. `data/feeds/manifest.json` and `README.md` (generated) record, per file, the real
  feed it is shaped like, that feed's URL, licence and production refresh cadence. No lab fetches a real feed.

### 3.7 Seed data (deterministic from `LAB_SEED`)

- 120 products `p001`..`p120`, six categories (shoes, packs, jackets, headlamps, poles, kitchen), 20 each,
  prices $19.99-$209.99, sizes per category, 500 in stock, ~600 reviews, ratings derived.
- Drops: `lab-runner-9` ($220, `max_per_account=1`) and `lab-hoodie-1` ($89), `DROP_STOCK` units each,
  live at seed time (set `drop_at` in an ext to stage a countdown).
- 300 users `user000..user299@example.test` (`demo_site/seed.py: username(i), password_for(i)`), users
  000-029 with a top-100 password (`data/wordlists/passwords_top.txt`, the stuffing subset,
  `weak_users()`), ~30 % with loyalty points, ~45 % with a saved card, 120 with an address, aged
  `created_at`; plus `mallory@example.test` / `mallory-owns-this-1`, the attacker's own account.
  PBKDF2-SHA256 at `LAB_HASH_ITERS`.
- 200 gift cards `GC-XXXX-XXXX` ($10-$100), ~800 historical orders.
- `hidden=True` products never appear in listings or the sitemap: the honeypot-SKU hook (W1 Ch8).
- Chapter-specific columns go in the `extra` JSON of each table, or in a chapter's own model.

### 3.8 Sessions and cookies

`sid` (HttpOnly, Lax, 7 days) is an opaque id for a Redis hash `lab:s:<sid>` holding `uid`, `csrf`,
`created_at`, `created_ip`, `created_asn`, flags and counters. `did` (Lax, 400 days) is a device cookie
for token-binding chapters. Per-defense session state uses `ctx.session.ns("<name>")` as a key prefix.

### 3.9 DOM contract (asserted by `tools/smoke.py`; attacks and shoppers may rely on these)

`.product-card[data-sku]`, `#cart-count`, `#add-to-cart`, `form.buy` with `input[name=sku|size|qty|csrf]`,
`#drop-buy[data-sku]`, `form#checkout`, `form#login-form`, `form#register-form`,
`input[name=email|password|code|csrf]`, `[data-testid="order-confirmed"]`. Changing one is a contract bump.

## 4. The gate and the hook points

Request path: `lab_edge` → `gate.before_request` (build `Ctx`, enrichers, `pipeline.run("request")`,
policy responder) → route (`guard("action:<name>")` before anything irreversible) →
`gate.after_request` (headers, decision log).

### 4.1 A defense (`defenses/<name>.py`)

```python
from .pipeline import Check, Signal, Verdict

def _check(ctx):                                   # ctx: defenses/context.py
    if ctx.ua.is_library:
        return [Signal("headers", "library_ua", 40, ctx.ua.raw[:40])]
    if not ctx.bucket("ip", ctx.ip):
        return Verdict("rate_limit", retry_after=5)
    return None

CHECK = Check("headers", _check, phases=("request",))   # or ("action:checkout",), ("action:*",), ("ws:*",)
```

Wire it in `defenses/ladder.py`: `LADDER = {0: [], 1: [headers.CHECK], 2: [ip_reputation.CHECK]}`. Round N
lives in `LADDER[N]`; `tools/checkpoint.py --round N` sets the level with `POST /lab/level`. Points sum to
a 0-100 score; `policy.decide()` maps it to a band (`monitor` 20, `challenge` 40, `block` 75); an override
that declares `ctx=` (or `**kwargs`) also receives the request's `Ctx`. A hard `Verdict` (`rate_limit`,
`block`, `deceive`) stops the gate. A soft `Verdict` with a bare score carries its points as one
synthesized signal, so `Verdict("challenge", 40, challenge="pow")` reaches the band. `challenge` with no
registered type is enforced as a block, so the cost of an unavailable challenge is visible. Tune numbers
in `policy.py`. A capstone that re-points a finished check at another surface rebinds it with
`dataclasses.replace(check, phases=("action:drop_buy",))` rather than editing the module.

`Ctx` offers: `method, path, args, form, json, cookies, headers` (ordered), `ua` (parsed), `edge`,
`session`, `user`, `redis`, `route` (the matched endpoint), `view_args`, `query_string` (raw, for
signature bases), `scheme`, `attrs` (from enrichers), `resumed` (a valid clearance existed when the Ctx
was built: the request is likely the retry after a solve, so per-attempt counters skip it),
`ctx.cleared(type=None)`, `ctx.header(name)`, `ctx.telemetry(kind)`, `ctx.bucket(name, key)`,
`ctx.note(**extra)` (into the log). There is no actor field. `ctx.bucket` is burst **plus** refill: a
`(30, 0.5)` bucket allows 30 up front and another one every 2 s while an attack runs, so "30 a minute"
is not 30 in any one minute — size checkpoint assertions accordingly.

### 4.2 A feature (`demo_site/ext/<name>.py`)

```python
from flask import Blueprint
from demo_site import hooks

def init(app):
    hooks.challenges.register("pow", issue=_issue, verify=_verify, render="pow/interstitial.html")
    hooks.slot("body_end", "pow/solver.html")           # also: head, nav, form:checkout, form:login,
    hooks.slot("form:checkout", "pow/fields.html")      #   form:register, form:drop, form:review,
    hooks.telemetry.register("pow_bench", _bench)       #   product:aside, challenge
    hooks.enricher(_tag_difficulty)                     # fn(ctx): fill ctx.attrs before the checks
    hooks.ungate("/lab/pow/")                           # paths the gate must skip
    hooks.ungate("/lab/fp/", session=True)              # skip the ladder but keep Ctx, cookie and log row
    hooks.robots(lambda: ["Disallow: /lab/pow/"])       # extra robots.txt lines (called per request)
    hooks.on_action("review", _hold)                    # fn(ctx, result, response) after a review/checkout/
                                                        #   drop_buy/register write, or any login attempt
    hooks.on_response(_observe)                         # fn(info) on every response, gated or ungated
    hooks.on_reset(_reseed)                             # fn(app) after POST /lab/reset: clear your tables
    hooks.stopped_outcome("paywalled")                  # count an ext outcome as a scoreboard stop
    app.register_blueprint(Blueprint("pow", __name__, url_prefix="/lab/pow"))
```

`init(app)` is also the ext's lifecycle hook: start a background worker there (keep its state under
`lab:…` keys so `POST /lab/reset` clears it, or register `on_reset`), and start a side service (a mock
provider, a TLS edge) there on a thread bound to a free loopback port — or lazily from the attack
callables that need it, as W2 Ch5 does; `tools/verify.py` itself starts nothing but the store.

Chapter templates go in `demo_site/ext/templates/<name>/` (searched first, so a chapter may override a
starter template) and chapter JS in `demo_site/static/js/<name>.js`. Ext modules load in name order.

Things that are easy to get wrong:

- **An ext that writes SQL per request opens its own engine.** The app's Flask-SQLAlchemy
  pool is sized for the routes (15 connections); an `on_response` or `on_action` handler that
  borrows it makes every request hold two of its connections at once, and 16 server threads
  then starve the pool — the store stalls for the 30 s pool timeout, not the disk. Create a
  separate engine on the same `DATABASE_URL` (W4 Ch7's `defenses/rule_store.py` is the model;
  on SQLite set WAL + `synchronous=NORMAL` so readers and the store's writer coexist).
- **Enrichers run at every level.** Per-round behaviour belongs in a check (which only runs at its level).
  A check may fill `ctx.attrs` for a later step of the same request (`issue()` of a challenge, a route):
  the gate and the route share one `Ctx` per request.
- **The reloader replaces `defenses/*` modules, not the references an ext holds.** Register through a
  lambda (`issue=lambda ctx: pow_challenge.issue(ctx)`) or edits to the defense are silently ignored
  until a restart. Ext modules themselves are not reloaded: restart after editing `demo_site/ext/`.
- **Run a defense module on its own with `python -m defenses.<name>`** from the lab folder (the package
  uses relative imports, so `python defenses/<name>.py` fails).

### 4.3 Challenges

`GET /api/challenge?type=<name>` issues, `POST /api/challenge/verify {"type", "answer"}` verifies and
grants a clearance. The two endpoints are exempt from the challenge **band** (a block or rate limit
still applies): a client whose every request scores into the band must still be able to fetch the
puzzle and deliver the answer. HTML clients get the type's `render` template (or
`templates/challenge.html`) with a 403; JSON clients get
`{"error": {"code": "challenge_required", "challenge", "payload"}}`. When the challenge interrupted a
form POST, the interstitial carries the submitted fields in a hidden `#challenge-replay` form (fresh
csrf, no JavaScript needed; a solver calls `window.labReplay()`), so the customer does not lose the
form — the fields, password included, are echoed only to the client that sent them.
`policy.DEFAULT_CHALLENGE` names the type served when a check does not.

```python
hooks.challenges.register("pow", issue, verify, render="pow/interstitial.html",
                          clearance_ttl=120,     # seconds one solve clears the session (default policy.CLEARANCE_TTL)
                          uses=20)               # challenge verdicts one solve absorbs (default: unlimited in the TTL)
def verify(ctx, answer):                         # bool, or (bool, reason)
    return False, "pass bound to another client" # reason -> the 403 message and decision extra.challenge_reason
```

**The downgrade rule.** While a session holds a valid clearance for the type a `challenge` verdict asks
for, the gate serves the request (as `monitor`) instead of challenging again, and spends one use. A
check that decides a pass is stolen, shared or over budget must call `gate.revoke_clearance(ctx, type)`
before returning its challenge verdict, or the verdict is absorbed. `gate.grant_clearance(ctx, type,
ttl=None, uses=None)`, `gate.clearance_valid(ctx, type)` and `gate.spend_clearance(ctx, type)` are the
other calls; a policy that wants to allow after a solve without a `challenge` verdict spends the
clearance itself. A check never reads the `lab:s:<sid>:clear:*` keys directly — `ctx.resumed` and
`ctx.cleared(type)` are the supported views.

### 4.4 Decision log and scoreboard

One `Decision` row per gated request: `ts, sid, user_id, actor, phase, method, path, ip, level, score,
action, enforced, outcome, status, signals, shadow, ms, extra`. `outcome` is what the client experienced:
`served | purchased | blocked | challenged | rate_limited | deceived | not_found | error`, or a
chapter-specific label an ext sets on `g.outcome` (e.g. `paywalled`, `charged`, `held`), which the
scoreboard reports in its own column rather than folding into `other`; `hooks.stopped_outcome(*names)`
makes such a label count in the `stopped` column and the hurt rule. The scoreboard groups actors by
`kind:persona` — the kinds are `human:`, `bot:` and `legit:` (welcome automation: verified crawlers,
uptime monitors, link unfurlers, whose stops are false positives, not bots stopped; its summary columns
`legit`, `legit_hurt`, `legit_requests`, `legit_requests_stopped` appear only when such actors exist) —
and reports bots stopped next to shoppers hurt, purchases by kind and drop stock. Chapter-specific
fields go in `extra` via `ctx.note()`.

A write route (`review`, `checkout`, `drop_buy`, `register`, HTML and JSON) fires
`hooks.on_action(name, fn)` after it commits, with the written row in `result` (`{"review": …}`,
`{"order": …}`, `{"user": …}`); the login routes fire it on **every** attempt with
`result={"user": …, "ok": bool, "reason": …}`. `fn(ctx, result, response)` may hold a row
(`review.status`/`order.status = "pending"`), attribute it, take the session back (delete `uid`), or
return a replacement response (a 202, a moderation notice). A held order keeps its stock reserved and
counts as neither a purchase nor a stop — only `status="paid"` orders reach `purchases` and the buyers
set — until review either marks it paid or calls `demo_site/orders.py cancel_order(order, reason)`,
which restocks its units. `hooks.on_reset(fn)` runs after `POST /lab/reset` clears the core store, so
an ext reseeds or drops the tables and Redis keys it owns.

Shoppers hurt are counted as **people**: an individual is hurt if the last thing that happened to them
was a stop and they bought nothing. A shopper who met a challenge, solved it and carried on is not hurt;
those requests still show in `human_requests_stopped`. `purchases` respects `since`.

## 5. Tools every lab ships (`tools/`)

| File | Purpose |
|---|---|
| `../labnet.py` | at the lab root, not in `tools/`: the one localhost guard (`target`, `require_local`, `require_local_env`) and the catch-up helper (`catch_up`, `restore`); a byte-identical copy of `scripts/labnet.py` |
| `labclient.py` | the lab client, guarded by `labnet` on import; `LabClient` (ordered headers, rented IP, actor label), `world_pool` (pools and groups), `group_members`, `admin`, `reset`, `set_level`, `scoreboard`, `browser_context` for Playwright |
| `browsers.py` | header templates of real browsers in wire order |
| `population.py` | the 40 shoppers (personas and scenarios); `PAGE_HOOKS` for chapter JS equivalents after a GET and `POST_HOOKS` after a form POST (a hook may return a replacement response); every `tools/personas_*.py` is auto-imported |
| `scoreboard.py` | table or markdown from `/lab/scoreboard` |
| `checkpoint_core.py`, `checkpoint.py` | `ROUNDS = {n: Round(...)}`; `--round N`, `--level L`, `--catch-up`, `--restore`, `--all`, `--markdown` |
| `verify.py` | in-process harness on a free port (or `$PORT`): `--smoke`, `--round N [--level L] [--catch-up]`, `--all --markdown` |
| `smoke.py` | this contract, as a test |
| `doctor.py`, `reset.py`, `build_world.py` | readiness check, reset, feeds (+ provenance manifest) from `world.json`. `doctor.py` is a starter file, so a lab with extra prerequisites (browser downloads, a side-service binary) ships its preflight as `tools/doctor_<ch>.py` next to it, named in the README's setup steps |

Solutions live in `solutions/round<N>/` mirroring the lab tree; `checkpoint.py --catch-up` installs rounds
1..N cumulatively, keeping one `.bak` per student file, and `--restore` puts them back. Attack scripts live in
`attacks/round<N>_<name>.py`, import `labclient` (which imports the `labnet` guard), and end by printing one JSON line with at least `{"attempted": n, "succeeded": k}`;
anything else they add (bits, CPU seconds, price) reaches `extra_checks`.

A round names its attacks and what each should achieve:

```python
3: Round(level=3, description="single-use passes",
         attacks={"replay": "attacks/round2_replay.py", "replay_share": "attacks/round2_replay.py --share",
                  "pool": "attacks/round3_solver_pool.py"},
         expect={"replay": "partial", "replay_share": "blocked", "pool": "full"},   # full >= 90 %, blocked <= 10 %
         allowed_fp=("no_js",),
         extra_checks=[lambda board, results, attacks: (max(attacks["pool"]["bits"]) >= 20, "pool must pay 20+ bits")]),
```

`scripts/new_lab.py <chapter folder>` copies the starter into `lab/` (no `.venv`, `instance/` or
`__pycache__`) and writes a README skeleton.
