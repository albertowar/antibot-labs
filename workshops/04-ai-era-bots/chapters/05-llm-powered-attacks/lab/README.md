# W4 Ch5 Lab — The LLM Arms Race

Four LLM-powered attacks against one e-commerce store, each a short attack/defend
round. The spine of the chapter: **an LLM removes the brittle parts of an old
attack — the parsing, the phrasing, the puzzle-solving — but not the account it
acts from, the purchase it hasn't made, the device and egress behind many
"users," or the fact that a text reader ingests what humans never see. The
defense that works targets the signal the model cannot rewrite, and prices the
rest in the attacker's own currency: tokens and latency.**

| Round | 🔴 LLM attack | 🔵 You wire (`defenses/`) | The signal |
|---|---|---|---|
| 1 | review farm: 40 unique, on-topic reviews | `review_signals.py` | account age + verified purchase + per-device/egress velocity |
| 2 | LLM/VLM challenge solver | `challenge_policy.py` | serve on risk, meter with proof-of-work, a solve ≠ a pass |
| 3 | LLM extraction, immune to layout churn | `extractor_traps.py` | text-only honeypots + a canary instruction + decoy tokens |
| 4 | indirect prompt injection via reviews | `llm_guard.py` | spotlighting + output validation + least privilege |

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. It also refuses a non-local `LLM_URL`. Do not remove that check.
- Every account, review, device, IP and session in this lab is synthetic. The "source IPs" are RFC 5737 documentation ranges, honoured only from loopback.
- The LLM is a **deterministic in-process mock** by default (`tools/llm.py`): no model download, no GPU, no network and no API key, and the numbers below reproduce exactly. Round 4's injection payloads target this store's **own** LLM features, which is how a defender checks whether a feature can be steered. The "secret" the exfiltration payload chases is a made-up lab code.
- **Outbound network:** none. To try a real model, point `LLM_URL` at a server on this machine (for example Ollama on `http://127.0.0.1:11434/v1`). Prompts never leave the laptop.
- Do not point these scripts, or anything you build from them, at a site you do not own.

## Why this stack

**Python only.** The store (Flask), the attacks (`requests`), the LLM client and
the scoring all live in Python, so there is one toolchain. No Docker is required:
the store runs on an in-process `fakeredis` and a SQLite file by default. The
in-page challenge tiles are drawn with Pillow at request time, so there are no
image fixtures to download. There is deliberately **no Playwright** here — the
agentic-browser loop is W4 Ch4; every attack in this chapter is `requests` plus a
model call, which keeps the lab to one language.

## Setup (under 10 minutes)

```bash
cd lab
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python tools/seed.py                               # synthetic catalogue, users, cohorts
python demo_site/app.py                            # http://127.0.0.1:5000
```

Leave the store running and open a second terminal (activate the venv there too).

### Per round

```bash
# 1. Run the attack and watch it beat the pre-wired defense:
python attacks/round1_review_farm.py

# 2. Open the round's module in defenses/, complete the TODO, save.
#    (the store reloads it on the next request — no restart needed)

# 3. Re-run the checkpoint: it runs the real customers AND the attacker,
#    and reports both sides.
python tools/checkpoint.py --round 1

# Stuck? Install the reference solution, then go back to your own work:
python tools/checkpoint.py --round 1 --catch-up    # reference (saves your work to .bak)
python tools/checkpoint.py --round 1               # restores and tests your work
```

At the end, review everything together:

```bash
python tools/scoreboard.py
```

### The old attacks (run these first to see what the LLM changed)

Each round ships the pre-LLM attack that the store's existing defenses already
beat, so the arms race is real and you can see the brittleness the LLM removed:

```bash
python attacks/round1_review_farm.py --scripted    # templated farm → caught by shingle overlap
python attacks/round2_llm_solver.py --ocr          # arithmetic-only solver → fails the tiles
python attacks/round3_llm_extract.py --selectors   # selector scraper → 0 against per-session churn
python attacks/round4_injector.py --list           # print the injection payloads
```

### Optional: a real local model instead of the mock

```bash
ollama pull qwen3:4b && ollama pull qwen2.5vl:3b
export LLM_URL=http://127.0.0.1:11434/v1 LLM_MODEL=qwen3:4b LLM_VISION_MODEL=qwen2.5vl:3b
python demo_site/app.py        # restart so the client picks up the backend
```

With a real model the behaviour becomes genuine and **non-deterministic**: the
mock models a known failure class (it follows imperative instructions in
untrusted content unless the content is datamarked), while a real model's exact
hits and misses will vary run to run. The verdicts (PASS/FAIL) are robust; the
exact counts are not. The mock's "vision" step reads a label embedded in each
tile PNG — a documented stand-in for a model's eyes; a real vision model sees the
pixels.

## Instructor expected results

Measured on the default `fakeredis` + SQLite backend with the mock LLM (Python
3.12, `tools/seed.py` defaults). Numbers are deterministic.

| Round | Metric | Un-wired (stub) | Wired (solution) | Legit customers blocked |
|---|---|---|---|---|
| 1 Review farm | fake reviews published | **40** | **0** (ceiling 3) | 0 (2 held: a duplicate + a one-liner — the honest friction) |
| 2 Challenge solver | bot accounts created | **40** | **0** (ceiling 2) | 0 (stub challenges all 20 humans; solution challenges 0) |
| 3 LLM extraction | records harvested | 60 clean | **75 poisoned**: 4 honeypot pages fetched→blocked, canary in every record, ~2× tokens/page | 0 (15 shoppers, 65 views) |
| 4 Prompt injection | injections reaching a response | **7/9** | **0/9** | stub **3** (regex FPs) → solution **0** |

Median defender scoring cost is ~0.5–4 ms per decision (logged per decision,
shown by the scoreboard). Three debrief talking points the table makes concrete:

- **Round 1** is the first false-positive lesson: the identity signals convert the
  farm to zero published, but two real reviewers are *held* for moderation (an
  exact-duplicate pair and a one-line "Love it!"). That is a real cost — name it,
  and ask how many held reviews a moderator would later approve.
- **Round 2** shows where human friction lives. The naive gate challenges *all 20*
  real customers; serve-on-risk challenges *none* of them while the datacenter,
  device-clustered bot still gets a puzzle it can solve but not profit from.
- **Round 4** is the sharpest: the "obvious" regex deny-list both **misses 7 of 9**
  attacks and **blocks 3 real reviewers** who wrote everyday phrases ("ignore the
  instructions on the box"). The architectural guard publishes all three and
  stops all nine.

### Scoreboard snapshot (all defenses wired)

```text
=== Scoreboard ===
[1] Review farm       bots: block=34 challenge=6    humans: allow=18 challenge=2
[2] Challenge solver  bots: block=34 challenge=46    humans: allow=20
[3] LLM extraction    bots: allow=65 block=4         humans: allow=65
[aside] toy AI-text detector flagged 12/20 human reviews and 37/40 bot reviews
        as 'generated' — a reason to score the account, not the writing.
```

## Optional: production-shaped backend

```bash
docker compose up -d
pip install "psycopg[binary]==3.3.6"
export REDIS_URL=redis://127.0.0.1:6379/0
export DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop
python tools/seed.py && python demo_site/app.py
```

Redis and PostgreSQL are pinned and bound to `127.0.0.1`. Everything else is
identical. This path is not required to complete the lab.

## Troubleshooting

- **"Demo store not reachable"** — start it first: `python demo_site/app.py`, and
  run the checkpoint from the same `lab/` directory.
- **Port 5000 in use** — start the store with `PORT=8099 python demo_site/app.py`
  and export `DEMO_URL=http://127.0.0.1:8099` in the attack/checkpoint terminal.
- **A round won't pass after you edit it** — the checkpoint prints why: either the
  attack still gets through (wire the signal) or a real customer was blocked
  (your rule is too broad). `--catch-up` shows the reference.
- **Round 3 WARNING about aria-hidden** — your hidden block is only off-screen;
  add `aria-hidden="true"` or screen-reader users will hear the decoys.
- **Numbers drift with a real model** (`LLM_URL` set) — expected. The mock is
  deterministic; a real model is not. The PASS/FAIL verdicts still hold.
