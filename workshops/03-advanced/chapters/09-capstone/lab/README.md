# W3 Ch9 Capstone Lab — Build & Break a Production-Grade Defense

6 rounds of 🔴 attack ⚔️ 🔵 defend (Round 0 build + Rounds 1–4).
See `../chapter_09_content.md` §9.7 for the chapter notes.

You inherit the whole Workshop 1 + 2 stack (levels 0–4) already running. The
capstone adds the Workshop 3 "detection at scale" layers on top of it and runs
the W3 attacks against them:

| Level | Adds | Modules | Round |
|---|---|---|---|
| 0–4 | **inherited** W1+W2 stack: headers, JA4/TLS, rate, automation, fingerprint, behavior, session model, login token + cluster | `request_checks`, `tls_consistency`, `automation`, `fingerprint_coherence`, `behavior_flow`, `session_model`, `token_binding`, `login_risk` | 0 |
| 5 | **API hardening**: GraphQL cost/depth + introspection off, JWT↔JA4 binding, REST velocity, per-connection WS rate limit | `api_hardening`, `api_auth`, `ws_ratelimit` | 1 |
| 6 | **real-time streaming**: sliding-window rate, regularity (Welford CV), navigation, fed by the event bus | `streaming/` | 2 |
| 7 | **supply chain**: CSP (report-only→enforce) + SRI + runtime fetch monitor | `supply_chain` | 3 |

One scoring scale, inherited from W2 Ch8 and extended: each layer returns
`(points, reasons)`, the engine (`defenses/risk_engine.py`) adds them, and

```
score < 30    allow
30 ≤ score < 60   challenge   (step-up)
score ≥ 60    block
```

A layer above the current `DEFENSE_LEVEL` runs in **shadow mode**: its points are
logged (`decisions.shadow`, visible in `tools/scoreboard.py`) but don't act.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- "Egress IPs" are *claimed* with an `X-Lab-Egress` header drawn from RFC 5737 documentation ranges; no real proxy or proxy list is ever used.
- Accounts, addresses and the "stolen" PII are synthetic (`@mail.example`, `@customers.example`). The skimmer and its collector origin are local and fictional.
- Every container in `docker-compose.yml`, including the optional `prod` profile, publishes its ports on 127.0.0.1 only.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

## Scenario

The store drops 50 pairs of the Lab Runner 9, one per account. You play both
sides, round by round: the attacker reaches for the next technique, you turn on
the next layer and measure what it catches **and who it hurts**.

## Layout

```
demo_site/    the shared store + W3 surface: /graphql, /api/v1, a price WebSocket,
              a third-party script slot, /metrics; TLS edge computes JA4 (edge.py)
defenses/     inherited L0–L4 modules + api_hardening (L5), streaming/ (L6), supply_chain (L7)
              risk_engine.py fuses them; ws_ratelimit.py, api_auth.py
attacks/      round0_naive, round1_api, round2_streaming, round3_skimmer, round4_integrated
              inherited_* : the W2 browser bots, replayed by tools/train_model.py to fit L3
solutions/    reference answers for the Round 1–3 TODOs (used by --catch-up)
tools/        doctor, seed, make_cert, train_model, checkpoint, scoreboard,
              legit_traffic (+ api_traffic), signalhealth, personas, incident_report.md
ops/          prometheus.yml + grafana provisioning for the optional `prod` profile
```

## Setup (under 10 minutes)

```bash
cd lab
docker compose up -d --wait                 # Redis + PostgreSQL, bound to 127.0.0.1
python -m venv .venv && source .venv/bin/activate      # one venv per chapter, see the root README
pip install -r requirements.txt
playwright install chromium                 # for Round 0 and the Round 4 browser bonus
patchright install chromium                 # optional (Round 4 bonus)
python -m camoufox fetch                     # optional (Round 4 bonus), ~160 MB
python tools/make_cert.py                    # self-signed cert for the TLS edge
python tools/seed.py                         # accounts, past orders, the combo list
python tools/train_model.py                  # fit the inherited L3 model (drives browsers, a few min)
python tools/doctor.py                       # all green?
DEFENSE_LEVEL=4 python demo_site/app.py      # https://localhost:8443 ; raise the level each round
```

Each round runs the store at its own level, so restart with a new `DEFENSE_LEVEL`
when the round table says so (0→`4`, 1→`5`, 2→`6`, 3→`7`, 4→`7`).

**No-Docker fallback:** set `DATABASE_URL=sqlite:////absolute/path/to/lab/instance/shop.db`
(four slashes; a relative `sqlite:///instance/...` resolves under `demo_site/`, which
does not exist there). The store needs a Redis shared across processes: install a local
`redis-server`, keep the Redis container, or run fakeredis as a TCP server
(`pip install "fakeredis[lua]==2.39.0"`, then
`python -c "from fakeredis import TcpFakeServer as S; S(('127.0.0.1', 6379), server_type='redis').serve_forever()"`).

**Optional production-like stack** (`prod` profile): real Redpanda + Prometheus +
Grafana, locally, no cloud account.

```bash
docker compose --profile prod up -d --wait
STREAM_BACKEND=kafka DEFENSE_LEVEL=6 python demo_site/app.py
# Grafana signal-health board: http://localhost:3000  (anonymous view enabled)
```

The default path (`STREAM_BACKEND=inproc`, `tools/signalhealth.py`) needs none of
this and is what the rounds below assume.

## How to measure a round

```bash
python tools/checkpoint.py --round N        # runs the attack + the 40 customers + 3 API clients
python tools/checkpoint.py --round N --catch-up   # install the reference solutions up to round N
python tools/scoreboard.py                  # outcomes per action, incl. shadow-mode scores
python tools/signalhealth.py                # per-layer trigger rates (the Grafana stand-in)
```

A round **passes** when the attack is stopped at the round's level **and** no
legitimate customer or API client is blocked. Challenges are friction: reported,
not failed. Capture your own browser at `/lab/capture`, save it as
`tools/profiles/mine.json`, and you join the customers.

---

## Round 0 — build & baseline (L4) · 🔵

```bash
DEFENSE_LEVEL=4 python demo_site/app.py
python tools/checkpoint.py --round 0
```

| Step | Do | Expected |
|---|---|---|
| 🛡️ Bring up | start the store at `DEFENSE_LEVEL=4`, seed, train the model | inherited stack live |
| 📸 Capture | open `/lab/capture`, save `tools/profiles/mine.json` | you become customer 41 |
| 🗡️ Attack | `python attacks/round0_naive.py` | 0 pairs: `requests`/`curl_cffi`/stock Playwright all stopped |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | bots 0 · 0 customers blocked |

## Round 1 — API abuse ⚔️ API hardening (L5) · 🔴🔵

```bash
python attacks/round1_api.py                       # at L4: 4/4 techniques succeed
# edit TODO (Round 1) in defenses/api_hardening.py, then:
DEFENSE_LEVEL=5 python demo_site/app.py
python tools/checkpoint.py --round 1
```

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round1_api.py` at L4 | 4/4: introspection, batch scrape, REST paging, WS flood |
| 🛡️ Defend | TODO in `defenses/api_hardening.py`: disable introspection, set the GraphQL cost budget | — |
| 🗡️ Re-run | same attack at `DEFENSE_LEVEL=5` | 0/4: cost over budget, no API token, WS metered |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | bots 0/4 · 0 blocked · mobile/partner API clients allowed |

**Discuss:** the legit mobile client pages the same REST endpoint and is *not*
blocked. What makes it legitimate to the server (token bound to its JA4) that
the scraper cannot cheaply forge?

## Round 2 — streaming evasion ⚔️ real-time detectors (L6) · 🔴🔵

```bash
python attacks/round2_streaming.py                 # micro-burst caught by rate; low-and-slow evades
# edit TODO (Round 2) in defenses/streaming/detectors.py (the CV threshold), then:
DEFENSE_LEVEL=6 python demo_site/app.py
python tools/checkpoint.py --round 2
```

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round2_streaming.py` at L6 (starter) | burst blocked by rate; low-and-slow still evades (CV=0) |
| 🛡️ Defend | set `REG_MAX_CV` in `defenses/streaming/detectors.py` | — |
| 🗡️ Re-run | same attack | 0/2: low-and-slow now caught by machine-even CV |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | bots 0/2 · 0 blocked (humans' CV is high) |

**Discuss:** the rate detector sees the burst before the buy is even scored —
that is the latency gap closing. Why does the low-and-slow client, which stays
under every rate limit, still stand out?

## Round 3 — supply-chain skimmer ⚔️ CSP + SRI (L7) · 🔴🔵

```bash
python attacks/round3_skimmer.py                   # at L<7: exfil succeeds (report-only)
# edit TODO (Round 3) in defenses/supply_chain.py (enforce + connect-src 'self'), then:
DEFENSE_LEVEL=7 python demo_site/app.py
python tools/checkpoint.py --round 3
```

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round3_skimmer.py` at L7 (starter) | exfil to the collector would be allowed (report-only) |
| 🛡️ Defend | TODO in `defenses/supply_chain.py`: enforce CSP, lock `connect-src` to `'self'` | — |
| 🗡️ Re-run | same attack | exfil blocked by the browser; a violation is reported and scored |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | exfil 0 · 0 blocked · same-origin analytics still allowed |

**Discuss:** SRI would catch a *tampered* CDN file but not this runtime-injected
skimmer. Why is CSP `connect-src` the control that actually stops exfiltration,
and what does the runtime monitor add?

## Round 4 — integrated assault ⚔️ the whole stack + ops (L7) · 🔴🔵

```bash
DEFENSE_LEVEL=7 python demo_site/app.py            # all layers on, all solutions applied
python tools/checkpoint.py --round 4
python tools/signalhealth.py                       # which layer caught what
```

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round4_integrated.py` | 0 pairs: recon→L5, evade→L6, purchase→L0 |
| 🩺 Operate | `python tools/signalhealth.py` | every engaged layer fires; a silent one is a finding |
| 📝 Report | fill in `tools/incident_report.md` | the kill chain, false positives, one improvement |

## Wrap-up: the scoreboard (part of the debrief)

```bash
python tools/scoreboard.py
python tools/signalhealth.py
```

Walk the kill chain, the false-positive budget (who got challenged and whether
that is acceptable), and write the post-incident report. The one signal that
Round 4 could not have stopped — fingerprint rotation across real devices — is
the hand-off to W3 Ch1 (mobile attestation) and Workshop 4.

## Expected results (self-check)

Attack ↓ / `DEFENSE_LEVEL` →, with the first blocking level in **bold**:

| Attack | at its "before" level | at its round level | First reason at the blocking level |
|---|---|---|---|
| `round0_naive` | — | **L4**: 0 pairs | `[L0] HeadlessChrome` / `No telemetry` / UA·TLS mismatch |
| `round1_api` | L4: 4/4 succeed | **L5**: 0/4 | `[L5] introspection disabled` · `cost over budget` · `no API token` · WS metered 20/120 |
| `round2_streaming` | L5: 2/2 evade | **L6**: 0/2 | `[L6] N req in 10s` (burst) · `CV ≤ 0.15` (low-and-slow) |
| `round3_skimmer` | L≤6: exfil allowed | **L7**: blocked | `connect-src enforced` + CSP violation report |
| `round4_integrated` | — | **L7**: 0 pairs | recon `[L5] cost`, evade `[L6] CV`, purchase `[L0] no telemetry` |
| Legit (40 customers) | 0 blocked at every level | — | friction only: `firefox-rfp`, `vdi-citrix`, `new-laptop` challenged |
| Legit API (3 clients) | 0 blocked at every level | — | JA4-bound token valid, velocity under limit |

**Verified with** Python 3.12.15 on Linux, `requirements.txt` as pinned (Flask 3.1.3, SQLAlchemy 2.1.4, redis 8.1.0, PyJWT 2.15.1, websockets 17.2, numpy 2.5.4, scikit-learn 1.9.1, curl_cffi 0.16.3, playwright 1.62.0 with Chromium 151.0.7922.34, patchright 1.63.0 and camoufox 0.5.8 installed and importing), SQLite, the in-process stream backend, and fakeredis 2.39.0 served over TCP as the Redis (the Redis 8.10 image is exercised by the `docker compose` path, which is verified separately). `tools/train_model.py` was re-run after the numpy/scikit-learn bump (42 human + 11 bot sessions, threshold 0.010, bot recall 80%, human FPR 0% on validation). Rounds 0-4 each pass `tools/checkpoint.py` with the cumulative reference solutions applied and the store restarted at the round's level: 0 customers or API clients blocked, 5 of 49 challenged (`firefox-rfp`, `new-laptop`, `vdi-citrix`). The optional Round 4 browser bonus (patchright, camoufox) was not run end to end.

Defender cost in the default path: scoring median ~15 ms, p95 ~75 ms per action.
Attacker cost per attempt: `curl_cffi` API calls ~0.05 s; the low-and-slow poll
is slow *by design* (~0.35 s × 14).

## Troubleshooting

- **`store not reachable`** — start it, and check the round's `DEFENSE_LEVEL` matches.
- **`L3 model not loaded`** — `python tools/train_model.py` (needs the browsers), then restart. The W3 layers work without it; the inherited L3 just scores 0.
- **WS round "skipped"** — `pip install websockets`; the WS server binds `PORT+1` (8444).
- **Round 1 passes before you edit anything** — you are at L4, not L5; restart at `DEFENSE_LEVEL=5`.
- **Port in use** — `PORT=9443 python demo_site/app.py` and `export DEMO_URL=https://localhost:9443`.

## Bonus challenges

- **Versus a partner (black box).** Share your built stack as a container image
  (`docker save` → your partner's `docker load`, or push to a registry if you
  have an account) and red-team each other's running store over its port, with
  no `--catch-up`. **Note:** a Docker image does *not* hide your Python source —
  a partner can read every defense module out of the image layers. "Black box"
  here means they attack the port and agree not to crack the container open; it
  is not cryptographic secrecy.
- **Mobile frontier.** The one signal Round 4 can't stop is a real device
  rotating its fingerprint. Sketch where device attestation (W3 Ch1) would plug
  into `risk_engine.py`, and what it would cost legitimate users on rooted or
  old devices.
- **Drift.** Re-run `tools/train_model.py` with `--quick`, then raise the
  streaming `REG_MAX_CV` until a human persona trips it. Where is the line, and
  what would you watch in `signalhealth.py` to catch that drift in production?
