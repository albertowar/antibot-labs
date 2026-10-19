# W4 Ch10 Capstone Lab — Govern the Agents

Starts from: `workshops/04-ai-era-bots/starter/` (contract 1.7). Adds: the whole Workshop 4 stack wired as one ladder — crawl governance, agent governance, deception within limits, the LLM guard and the decision-oracle guard (`defenses/`), a store extension that binds them to content, checkout, the LLM features and the policy surface (`demo_site/ext/capstone_store.py`), Web Bot Auth reused byte-for-byte from W4 Ch2 (`defenses/httpsig.py`, `defenses/web_bot_auth.py`), the agent/crawler-aware legitimate mix and the five rounds of attackers (`tools/`, `attacks/`), and the operate-and-audit tooling (`tools/approve.py`, `tools/audit.py`, `tools/make_keys.py`).

The last lab of the series. One store, the whole Workshop 4 stack, five rounds
of 🔴 attack ⚔️ 🔵 defend, run under the AI governance record you wrote in
W4 Ch8.

You do not build the store; it is here at its end-of-Workshop-4 shape. Each round
you switch on one more layer (`DEFENSE_LEVEL`) and complete the one module that
layer needs, then run the round's attack and the legitimate mix and read the
three-column scoreboard.

| Level | Adds | You edit | Round |
|---|---|---|---|
| 0 | W1 request checks only; every later layer runs in **shadow** | — (baseline) | 0 |
| 1 | crawl governance: identity × purpose → allow / 402 / charge / maze / block | `defenses/crawl_governance.py` | 1 |
| 2 | agent governance: your Ch8 policy, live at checkout | `defenses/agent_governance.py` + `policies/agent_policy.json` | 2 |
| 3 | deception within limits + the LLM guard | `defenses/deception_limits.py`, `defenses/llm_guard.py` | 3 |
| 4 | operate and audit: the decision-oracle guard, onboard a new vendor, run the audit | `defenses/oracle_guard.py` (+ `tools/approve.py`/`tools/audit.py`, run-only) | 4 |

Score scale is the series' usual: `score < 30` allow, `30–59` challenge, `≥ 60` block.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. It also refuses a non-local `LLM_URL`. Do not remove that check.
- "Egress IPs" are *claimed* with an `X-Lab-Egress` header drawn from RFC 5737 documentation ranges; no real proxy or proxy list is ever used.
- Accounts, addresses, keys and the "stolen" details are synthetic (`@mail.example`, `@customers.example`).
- Every LLM call goes through `tools/llm.py`, a deterministic local mock by default. A real model must run on this machine, so no API key is needed and nothing leaves your machine.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

## Setup (under 10 minutes)

Python 3.12+. No Docker, no browser.

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate; one venv per chapter
pip install -r requirements.txt
python tools/seed.py                               # 120 products + the drop + honeypots, 52 accounts, operator keys
python tools/doctor.py                             # preflight (packages, keys, seed)

# terminal 1 — the store at the round's level:
DEFENSE_LEVEL=0 PORT=8409 python demo_site/app.py
# terminal 2:
export DEMO_URL=http://127.0.0.1:8409
```

Optional real model: `ollama pull qwen3:4b` then `export LLM_URL=http://127.0.0.1:11434/v1` before starting the store.
Optional production stack: `docker compose up -d --wait` then set `REDIS_URL` / `DATABASE_URL` (see `docker-compose.yml`).

## How to measure a round

```bash
# edit the round's module, restart the store at the round's DEFENSE_LEVEL, then:
python tools/checkpoint.py --round N      # runs the attack + the legit mix, prints pass/fail + scoreboard
python tools/scoreboard.py                # the three-column governance scoreboard on its own
python tools/checkpoint.py --round N --catch-up   # fell behind? drop in the reference, then restart
```

A round passes when its attack targets are met **and** no legitimate user is
**blocked or mazed**. A challenge is friction, counted and weighted, not a failure.

## Round 0 — baseline · 🔵

```bash
DEFENSE_LEVEL=0 PORT=8409 python demo_site/app.py
python tools/checkpoint.py --round 0
```

| Step | Do | Expected |
|---|---|---|
| 🛡️ Bring up | start at L0, `seed.py`, `doctor.py` | store answers `/admin/status` |
| 🗡️ Attack | `python attacks/round0_naive.py` | crawler harvests 100%, the agent buys, the extractor reads |
| 📸 Read | `python tools/scoreboard.py` | three columns; 0 legit blocked; every later layer's shadow score visible |

**Discuss:** the whole W4 stack is running in shadow right now. What does it *say* about the agent that just bought, and why is none of it blocking yet?

## Round 1 — 🔴 the crawler fleet / 🔵 crawl governance

```bash
python attacks/round1_crawler_fleet.py          # at L1 with the stub: everything served
# edit TODO (Round 1) in defenses/crawl_governance.py, then:
DEFENSE_LEVEL=1 PORT=8409 python demo_site/app.py
python tools/checkpoint.py --round 1
```

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `round1_crawler_fleet.py` (stub) | all four crawlers harvest for free |
| 🛡️ Defend | wire `crawl_governance.evaluate`: verify → entitle → price → maze | — |
| 🗡️ Re-run | same attack at L1 | training crawler **402**, impostor **403**, stealth **mazed** (2nd pass 0), paying crawler **charged** |
| ✅ Checkpoint | `checkpoint.py --round 1` | leaks 0/3 · search 100% · readers/prefetch not mazed · 0 legit blocked |

**Discuss:** the paying crawler is the only one that gets the catalogue, and it is the only one you can send an invoice. Which is the defense — the 402 or the block?

## Round 2 — 🔴 the agent farm / 🔵 agent governance

```bash
python attacks/round2_agent_farm.py             # at L2 with the blunt policy: read who it refuses
# edit TODO (Round 2) in defenses/agent_governance.py AND rewrite policies/agent_policy.json
DEFENSE_LEVEL=2 PORT=8409 python demo_site/app.py
python tools/checkpoint.py --round 2
```

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `round2_agent_farm.py` vs the blunt policy | farm stopped, but signed agents and the a11y cohort blocked too |
| 🛡️ Defend | make the Ch8 reference policy live: declare-or-challenge, mandates, a non-visual challenge, caps | — |
| 🗡️ Re-run | same attack at L2 | farm ≤ 2 orders · forged signature 0 · a11y mimic 0 |
| ✅ Checkpoint | `checkpoint.py --round 2` | signed cloud agents buy · a11y cohort challenged only non-visually · 0 legit blocked |

**Discuss:** the shared fingerprint, not the "agent" label, is what caps the farm. Which legitimate cohort shares a fingerprint, and why is it spared?

## Round 3 — 🔴 extractor + injection / 🔵 deception limits + LLM guard

```bash
python attacks/round3_llm_extract.py ; python attacks/round3_injector.py
# edit TODO (Round 3) in defenses/deception_limits.py and defenses/llm_guard.py
DEFENSE_LEVEL=3 PORT=8409 python demo_site/app.py
python tools/checkpoint.py --round 3
```

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | extractor harvests; injector posts 9 payloads | harvest clean; 7/9 injections land (naive guard) |
| 🛡️ Defend | gate the traps on `would_block`; spotlight + validate the LLM output; add the Art 50 disclosure | — |
| 🗡️ Re-run | both attacks at L3 | extractor's harvest **poisoned** (honeypots + canary); injections **0/9** |
| ✅ Checkpoint | `checkpoint.py --round 3` | the honoured crawler and the a11y cohort get **0 decoys**; 0 legit blocked |

**Discuss:** the canary you stamp on the extractor is prompt injection you perform; Round 3's other attack is prompt injection performed on you. What makes one defensible?

## Round 4 — 🔴 integrated + adaptation / 🔵 operate & audit

```bash
python attacks/round4_integrated.py             # all of it + a score prober + a new vendor
# edit TODO (Round 4) in defenses/oracle_guard.py, then:
DEFENSE_LEVEL=4 PORT=8409 python demo_site/app.py
# operate: a person onboards the new vendor (the drift the ops round is about)
python tools/approve.py onboard-operator --origin https://agents.newvendor.test --by <you>
python tools/audit.py --record exercises/<your-record>.md   # the 7 live cards + the 12-item record
python tools/checkpoint.py --round 4
```

Drafting and approving a *detection rule* — triage proposing one, the gate testing it
against the shopper cohorts, a person signing it — is W4 Ch7's subject and is not
repeated here; the capstone's human-in-the-loop action is onboarding the vendor.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `round4_integrated.py` at L4 | every earlier target holds; prober reads **no** score; new vendor blocked |
| 🩺 Operate | `approve.py onboard-operator` | the vendor is trusted by a named person; it now buys |
| 📝 Audit | `audit.py` (7 cards) + `--record` | 7/7 cards; record ≥ 12/12 |
| ✅ Checkpoint | `checkpoint.py --round 4` | caps hold, oracle hides the score, audit passes, 0 legit blocked |

**Discuss:** the oracle guard turns a 200-request probe into a 2,000-account one. It did not stop the attacker. What did it buy you, and what finishes the job?

## Wrap-up: the scoreboard

`python tools/scoreboard.py` at L4, next to the L0 baseline. Read the three
columns aloud: bots through, legitimate users blocked (target 0), legitimate
users challenged (weighted). Name the cohort in column three with the highest
weighted friction and decide whether it is worth it.

## Expected results (self-check)

Verified on 2026-10-16 with Python 3.12, Flask 3.1, Flask-SQLAlchemy 3.1,
SQLAlchemy 2.1, redis 8.1, fakeredis 2.39, cryptography 50.0, requests 2.34 and
httpx 0.28, on fakeredis + SQLite with the deterministic mock LLM, through
`tools/verify.py --round N --catch-up` (reference solutions applied cumulatively).
Regenerate this table with `tools/verify.py --all --catch-up --markdown`.

| Round (level) | Attack result | Legit |
|---|---|---|
| 0 (L0) | crawler 120/120 free · agent buys · extractor 24 records/page | 0 blocked |
| 1 (L1) | training **402** (0 free) · impostor **403** (0) · stealth 2nd pass **0** · paying **charged** 120/120 · leaks **0/3** | 0 blocked/mazed (readers & prefetch served) |
| 2 (L2) | farm **1/36** drop orders · forged signature **0** · dark cloud agent **0** · a11y mimic **0** | signed agents buy · a11y challenged non-visually · 0 blocked |
| 3 (L3) | extractor poisoned (3 honeypots, canary in every record) · injections **0/9** · 3 real reviewers published | honoured crawler & a11y: **0** decoys · 0 blocked |
| 4 (L4) | caps hold · score **not recoverable** · new vendor **0** until onboarded, then buys · audit **7/7** · record **12/12** | 0 blocked |

Attacker cost: a mock-LLM round runs in well under a minute; a full `checkpoint.py`
is ~60–90 s. Defender cost: checkout scoring median a few ms; the maze costs bytes.

## Troubleshooting

- **`store not reachable`** — start it: `DEFENSE_LEVEL=N PORT=8409 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:8409`.
- **`This round needs DEFENSE_LEVEL=N`** — restart the store at the round's level; changing the level needs a restart (editing a defense module does not).
- **Round passes before you edit anything** — you are already at that level with the reference in place; `git`-reset the module or re-read the stub.
- **`409 account exists` / stale drop caps** — `checkpoint.py` resets for you; to reset by hand, `POST /admin/reset?decisions=1&fresh_accounts=1` with the admin key, or re-run `tools/seed.py`.
- **Port in use** — `PORT=9409 python demo_site/app.py` and `export DEMO_URL=http://127.0.0.1:9409`.
- **`database is locked` under load (SQLite)** — rare; re-run the checkpoint, or use the Docker PostgreSQL path.

## Bonus challenges

1. **Rotating pool.** Give the Round 1 stealth crawler a pool of datacenter IPs. The per-IP maze tag dilutes. What keys the deterrence now? (W2 Ch2 fingerprint clustering; streaming detection across the whole pool.)
2. **A real model.** `export LLM_URL=…` and re-run Round 3. Which injection variants does a real model resist that the mock follows, and which does it fall for?
3. **A browser agent.** `attacks/bonus_playwright_agent.py` drives a real Chromium agent against checkout (needs `pip install playwright==1.63.0 && python -m playwright install chromium`). Does the HTTP-level story hold?
4. **Pay-per-use.** Extend the ledger so a crawl is billed only when the page is later served in an answer, not on fetch (Cloudflare's 2026 shift). Where does the accounting move?

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/agent_behavior.py`
- `defenses/agent_governance.py`
- `defenses/agent_identity.py`
- `defenses/agent_policy.py`
- `defenses/automation.py`
- `defenses/babble.py`
- `defenses/behavior_flow.py`
- `defenses/capstone.py`
- `defenses/challenges.py`
- `defenses/content_heuristics.py`
- `defenses/crawl_governance.py`
- `defenses/crawl_policy.py`
- `defenses/crawler_identity.py`
- `defenses/crawler_registry.py`
- `defenses/deception_limits.py`
- `defenses/decision.py`
- `defenses/extractor_traps.py`
- `defenses/fingerprint_coherence.py`
- `defenses/httpsig.py`
- `defenses/injection_regex.py`
- `defenses/key_directory.py`
- `defenses/llm_guard.py`
- `defenses/mandates.py`
- `defenses/maze.py`
- `defenses/oracle_guard.py`
- `defenses/paywall.py`
- `defenses/policy_engine.py`
- `defenses/request_checks.py`
- `defenses/risk_engine.py`
- `defenses/rules.py`
- `defenses/signals.py`
- `defenses/web_bot_auth.py`
- `demo_site/ext/capstone_store.py`
- `demo_site/ext/templates/capstone/traps.html`
- `demo_site/ext/templates/partials/_card.html`
- `demo_site/static/collector.js`
- `demo_site/static/js/capstone.js`
- `demo_site/static/shop.js`
- `tools/approve.py`
- `tools/audit.py`
- `tools/crawl.py`
- `tools/lab.py`
- `tools/legit_traffic.py`
- `tools/llm.py`
- `tools/make_keys.py`
- `tools/personas.py`
- `tools/profiles/brave-win.json`
- `tools/profiles/chrome-mac.json`
- `tools/profiles/chrome-win.json`
- `tools/profiles/firefox-linux.json`
- `tools/profiles/firefox-rfp.json`
- `tools/profiles/office-win.json`
- `tools/profiles/safari-ios.json`
- `tools/profiles/vdi-citrix.json`
- `tools/record_checklist.py`
- `tools/seed.py`
- `tools/synthetic_input.py`
- `tools/triage.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->
