# W4 Ch5 Lab: The LLM Arms Race

Starts from: `workshops/04-ai-era-bots/starter/` (contract 1.6). Adds: the review, registration, catalogue and LLM surfaces this chapter attacks, one defense module per round and four LLM-powered attacks (the block below lists every file).

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `data/honeypots.json`
- `data/human_reviews.json`
- `defenses/challenge_gate.py`
- `defenses/challenge_policy.py`
- `defenses/content_heuristics.py`
- `defenses/extractor_traps.py`
- `defenses/honeypot_sku.py`
- `defenses/injection_regex.py`
- `defenses/llm_guard.py`
- `defenses/netintel.py`
- `defenses/review_signals.py`
- `demo_site/ext/llm_surfaces.py`
- `demo_site/ext/templates/llm/churn_css.html`
- `demo_site/ext/templates/llm/traps.html`
- `demo_site/ext/templates/partials/_card.html`
- `tools/llm.py`
- `tools/personas_ch5.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Lab style: wire-it.** Each round ships a stub in `defenses/` with a `TODO (Round N)`; the finished version is
in `solutions/roundN/` and `tools/checkpoint.py --round N --catch-up` installs rounds 1..N (your files are kept
as `.bak`, `--restore` puts them back).

Four LLM-powered attacks against one e-commerce store, each a short attack/defend round. The spine of the
chapter: **an LLM removes the brittle parts of an old attack (the parsing, the phrasing, the puzzle-solving)
but not the account it acts from, the purchase it hasn't made, the device and egress behind many "users," or
the fact that a text reader ingests what humans never see. The defense that works targets the signal the
model cannot rewrite, and prices the rest in the attacker's own currency: tokens and latency.**

| Round | Level | 🔴 LLM attack | 🔵 You wire (`defenses/`) | The signal |
|---|---|---|---|---|
| 1 | 1 | review farm: 40 unique, on-topic reviews from 40 new accounts | `review_signals.py` | account age + verified purchase + per-device/egress velocity |
| 2 | 2 | LLM/VLM challenge solver registering 40 accounts | `challenge_policy.py` | serve on risk, meter with proof-of-work, a solve is not a pass |
| 3 | 3 | LLM extraction, immune to layout churn | `extractor_traps.py` | text-only honeypots + a canary instruction + decoy tokens |
| 4 | 4 | indirect prompt injection via reviews | `llm_guard.py` | spotlighting + output validation + least privilege |

Round N runs at `DEFENSE_LEVEL=N`; level 0 is the store as it shipped. Level 1 also wires the pre-written
content heuristics (duplicates, templates, links, one-liners), the defense that stopped review spam before LLMs.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`, which
  asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine, before a single
  request is sent. It also refuses a non-local `LLM_URL` (and `REDIS_URL`, `DATABASE_URL`). The store's edge accepts
  the lab headers only from loopback. Do not remove that check.
- **What is synthetic.** Every account, review, device and address is synthetic: source addresses are rented from
  `data/world.json` (RFC 5737 / 3849 documentation ranges), never invented, never real. Round 4's injection payloads
  target this store's **own** LLM features, which is how a defender checks whether a feature can be steered; the "secret"
  the exfiltration payload chases is a made-up lab code. The nine accounts the injector works from are the store's
  seeded customers `user100..user108`.
- **The LLM is a deterministic in-process mock** by default (`tools/llm.py`): no model download, no GPU, no network and
  no API key, and the numbers below reproduce exactly. It models a known failure class; it is not a language model.
- **Outbound network:** none. No attack, tool or round reaches the internet. To try a real model, point `LLM_URL` at a
  server **on this machine** (for example Ollama on `http://127.0.0.1:11434/v1`): `labnet` refuses any other host, so
  prompts never leave the laptop. Only setup (packages, container images, an optional model pull) needs the internet.
- Do not point these scripts, or anything you build from them, at a site you do not own.

## What is in the store

The Kestrel Outfitters store of the W4 starter (`workshops/STORE_CONTRACT.md`), unchanged, plus one ext module,
`demo_site/ext/llm_surfaces.py`, that adds only what the chapter attacks:

| Surface | Where | Used by |
|---|---|---|
| reviews: `POST /api/reviews`, held ones answer `202` and show in the scoreboard's `held` column | the starter's route + `hooks.on_action("review")` (contract 1.6) | Rounds 1, 4 |
| registration behind a `puzzle` challenge: `POST /api/register` -> `403 challenge_required` -> `POST /api/challenge/verify` -> retry | the starter's routes + `hooks.challenges` | Round 2 |
| the listing `GET /products?page=N`: per-session class names (layout churn), a visible `SKU p001`, and a `body_end` slot for Round 3's traps | the starter's page + a `_card.html` override (the contract's `.product-card[data-sku]` is untouched) | Round 3 |
| `GET /api/products/<sku>/summary` and `POST /api/assist`: LLM features that read published reviews | the ext | Round 4 |

Four honeypot SKUs (`hp-101`..`hp-104`, `data/honeypots.json`) are not in the catalogue: nobody is ever shown them, and a
request for one is blocked on sight by the pre-wired `honeypot_sku.py`.

## Why this stack

**Python only.** The store (Flask), the attacks (`requests`), the LLM client and the scoring all live in Python, so there is
one toolchain. No Docker is required: the store runs on an in-process `fakeredis` and a SQLite file by default. The
challenge's image tiles are drawn with Pillow at request time, so there are no image fixtures to download. There is
deliberately **no Playwright** here: the agentic-browser loop is W4 Ch4; every attack in this chapter is `requests` plus a
model call.

## Setup (under 10 minutes)

One venv per chapter; see `onboarding/setup/PREWORK.md` for the toolchain.

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python tools/doctor.py                                # READY?
python demo_site/app.py                               # http://127.0.0.1:5000, level 0
```

Leave the store running and open a second terminal (activate the venv there too).

### Per round

```bash
# 1. Put the store at the round's level and run the attack; watch it beat the defense you have not written yet:
curl -s -X POST localhost:5000/lab/level -H 'content-type: application/json' -d '{"level": 1}'
python attacks/round1_review_farm.py

# 2. Open the round's module in defenses/, complete the TODO, save (the store reloads it on the next request).

# 3. The checkpoint resets the store, runs real customers AND the attacker, and reports both sides:
python tools/checkpoint.py --round 1

# Stuck? Install the reference solution, then go back to your own work:
python tools/checkpoint.py --round 1 --catch-up       # installs solutions/round1..1 (your files kept as .bak)
python tools/checkpoint.py --restore                  # puts your own files back
python tools/checkpoint.py --round 1 --level 0        # the same attack against the previous level (the "before")
```

At the end, review everything together: `python tools/checkpoint.py --all` (every round, with the `held` column),
and `python tools/scoreboard.py` for the bots-stopped-versus-shoppers-hurt table of the last run.

### The old attacks (run these first to see what the LLM changed)

Each round ships the pre-LLM attack that the store's existing defenses already beat, so the arms race is real and you
can see the brittleness the LLM removed (start the store at the level shown):

```bash
python attacks/round1_review_farm.py --scripted    # level 1: templated farm -> 39 of 40 held by shingle overlap
python attacks/round2_llm_solver.py --ocr          # level 2: arithmetic-only solver -> fails the tiles, 0 accounts
python attacks/round3_llm_extract.py --selectors   # any level: selector scraper -> 0 records against per-session churn
python attacks/round4_injector.py --list           # print the injection payloads
```

### Optional: a real local model instead of the mock

```bash
ollama pull qwen3:4b && ollama pull qwen2.5vl:3b
export LLM_URL=http://127.0.0.1:11434/v1 LLM_MODEL=qwen3:4b LLM_VISION_MODEL=qwen2.5vl:3b
python demo_site/app.py        # restart so the store picks up the backend
```

Off by default, loopback only (`labnet` refuses a non-local `LLM_URL`). With a real model the behaviour becomes genuine
and **non-deterministic**: the mock models a known failure class (it follows imperative instructions in untrusted
content unless the content is datamarked), while a real model's exact hits and misses vary from run to run. The verdicts
(PASS/FAIL) are robust; the exact counts are not. The mock's "vision" step reads a label embedded in each tile PNG, a
documented stand-in for a model's eyes; a real vision model sees the pixels. These instructions are checked against the
mock only: no real model was run to produce this README.

## Where your code runs

| Round | You edit | The plumbing around it (already written) |
|---|---|---|
| 1 | `CHECK`'s `_check` in `review_signals.py`: block on velocity, **hold** a new unverified account | `facts(ctx)` counts this review per device and per IP; `content_heuristics.py` runs first; the ext's `hooks.on_action("review")` parks a hold as `pending` and answers 202 |
| 2 | `serve(f)` and `verdict(f)` in `challenge_policy.py` | the `puzzle` challenge type and `challenge_gate.py`; the check serves it on `POST /api/register`, prices it with `serve()`'s bits, and on the retry after a solve asks `verdict()` |
| 3 | `decorate(ctx)` in `extractor_traps.py` | the check mints a per-session canary and hands it over; the ext renders your dict in an off-screen, `aria-hidden` block on `/products` |
| 4 | `ingest`, `build_prompt`, `validate` in `llm_guard.py` | from level 4 the ext's summary and assistant routes call your prompt builder and your output validator instead of plain concatenation |

## Expected results (self-check)

Verified on 2026-10-15 with Python 3.12.15, Flask 3.1.3, Flask-SQLAlchemy 3.1.1, redis 8.1.0, fakeredis 2.39.0, requests 2.34.2
and Pillow 12.3.0, on the default `fakeredis` + SQLite backend with the mock LLM, and again on the Docker path (Redis 8.10,
PostgreSQL 18). The numbers are deterministic. "Bare" is the attack against the previous level
(`checkpoint.py --round N --level N-1`), "Stub" is your starting file at level N, "Solution" is `--catch-up`
(`python tools/verify.py --all --catch-up --markdown` regenerates the scoreboards behind this table).

| Round | Metric | Bare (level N-1) | Stub (level N) | Solution | Shoppers hurt / friction |
|---|---|---|---|---|---|
| 1 Review farm | fake reviews published (of 40) | **40** | **40** | **0** (ceiling 3): 6 held, 34 refused | 0 hurt; 2 of 20 real reviews held (an exact duplicate and a one-liner, the honest friction) |
| 2 Challenge solver | bot accounts created (of 40) | **40** (no puzzle served) | **40** (everyone is challenged, the tiles are solved) | **0** (ceiling 2): 40 puzzles served and solved, none is a pass | 0 hurt; stub challenges **20 of 20** real sign-ups, solution **1** (a shared carrier address) |
| 3 LLM extraction | records harvested | 120 clean | 120 clean, 0 honeypot pages, no canary | **135 poisoned**: 4 honeypot pages fetched and blocked, the canary on every record, ~1.6x tokens (7040 vs 4404) | 0 of 40 shoppers hurt; the hidden block is `aria-hidden` |
| 4 Prompt injection | injections reaching a response (of 9) | **9** | **7** (the deny-list stops 2) | **0** | stub **3** real reviewers refused by the deny-list, solution **0** |

Every round reports 0 of its shoppers hurt in the solution column and a median gate time of about 1.5 to 4.5 ms per
shopper request on the in-process backend (printed by each checkpoint, limit 25 ms; 250 ms with a real Redis). Three
debrief points the table makes concrete:

- **Round 1** is the first false-positive lesson: the identity signals convert the farm to zero published, but two
  real reviewers are *held* for moderation (an exact-duplicate pair and a one-line "Love it!"). That is a real cost:
  name it, and ask how many held reviews a moderator would later approve. The scoreboard shows holds in their own
  `held` column because a hold is not one of the gate's verdicts.
- **Round 2** shows where human friction lives. The naive gate challenges *all 20* real sign-ups; serve-on-risk challenges
  one (a phone behind the shared carrier address) while the datacenter, device-clustered bot still gets a puzzle it can
  solve but not profit from.
- **Round 4** is the sharpest: the "obvious" regex deny-list both **misses 7 of 9** attacks and **refuses 3 real
  reviewers** who wrote everyday phrases ("ignore the instructions on the box"). The architectural guard publishes all
  three and stops all nine.

The toy AI-text detector in `content_heuristics.looks_generated` flags careful human prose just as happily as the bots'
(see its docstring): a reason to score the account, not the writing.

## Optional: production-shaped backend

```bash
docker compose up -d --wait
pip install "psycopg[binary]==3.3.6"
export REDIS_URL=redis://127.0.0.1:6379/0
export DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop
python demo_site/app.py
```

Redis and PostgreSQL are pinned and bound to `127.0.0.1`. Everything else is identical. This path is not required to
complete the lab; `docker compose down -v` when you are done.

## Troubleshooting

- **"Store not reachable"**: start it first (`python demo_site/app.py`) and run the checkpoint from the same `lab/` directory.
- **Port 5000 in use**: `PORT=8099 python demo_site/app.py` and `export DEMO_URL=http://127.0.0.1:8099` in the attack and checkpoint terminal.
- **A round won't pass after you edit it**: the checkpoint prints why: either the attack still gets through (wire the signal) or a
  real customer was refused (your rule is too broad). `--catch-up` shows the reference.
- **Round 3, if you edit `demo_site/ext/templates/llm/traps.html`**: the hidden block must stay `aria-hidden="true"`, or screen-reader users hear the decoys; the checkpoint asserts it.
- **Round 2 returns 403 `challenge_required` for every sign-up**: that is the stub (a puzzle for everyone); implement `serve()`.
- **Numbers drift with a real model** (`LLM_URL` set): expected. The mock is deterministic; a real model is not. The PASS/FAIL verdicts still hold.
