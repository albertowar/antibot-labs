# W4 Ch7 Lab — LLMs for Defense

**Format:** Round 0 plus 3 rounds. This is a minimal README: the chapter's content doc, timings, measured expected results and the checkpoint's pass/fail thresholds are still to be written (see the chapter's entry in the root `TODO.md`).

It is drop day at the store from W2 Ch7, minus the ML scoring. A rule engine at checkout enforces `rules/active.json`. An LLM analyst reads the request log **offline**, triages sessions and proposes rules. The attacker writes to that log too, through every header it sends. Each round you harden the analyst, and the scoreboard measures triage quality, injection success, real customers blocked, and what the model costs in tokens, dollars and latency.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- Simulated client addresses are sent in `X-Lab-Client-IP`, which the store trusts only from 127.0.0.1. Customers, sessions and the bait bot's VPN identity are synthetic.
- The LLM is a deterministic mock by default (`defenses/llm_mock.py`). `LLM_BACKEND=ollama` uses a local model instead; `OLLAMA_HOST` must point at this machine, so prompts and log data never leave the laptop.
- No model sits in the request path. A rule reaches the edge only after `defenses/gate.py` replayed it against verified customers and a person approved it with `tools/approve.py`.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  labnet.py            the localhost guard and catch-up helper (shared by every lab)
  demo_site/           app.py (the store and its rule engine, DEFENSE_LEVEL 0–2) · static/
  defenses/            sanitize · triage · gate · cluster  ← YOU EDIT THESE
                       llm · llm_mock · rulesmith · rules · sessionize · schemas · fields · store (given)
  attacks/             round0_baseline · round1_injected_ua · round2_stitched · round3_token_flood
  tools/               simulate (real users) · approve (the only writer of rules/active.json) ·
                       scoreboard · checkpoint · shopper · labclient
  rules/               active.json (what the edge enforces) · audit.jsonl (who approved what)
  solutions/roundN/    reference defenses, installed by --catch-up
```

## Setup

Python 3.12+. No Docker: SQLite by default (`DATABASE_URL=sqlite:///llm_lab.db`); run every command from `lab/` so they share the file.

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
DEFENSE_LEVEL=0 python demo_site/app.py           # terminal 1: the store on 127.0.0.1:5000
python tools/simulate.py                          # terminal 2: 600 real users + baseline bots
python tools/checkpoint.py --round 0              # triages the run, then scores it vs ground truth
```

`DEFENSE_LEVEL=1` records rule matches in shadow; `DEFENSE_LEVEL=2` enforces them at checkout.

**Fell behind?** `python tools/checkpoint.py --round N --catch-up` installs the reference solutions for rounds 1..N from `solutions/` over your files and keeps each of yours once as `.bak`. Restart the store, re-run `tools/simulate.py` and the round's attack, then the checkpoint. `python tools/checkpoint.py --restore` puts your own files back.

## Rounds

| Round | 🔴 Attack | 🔵 You edit | Scoreboard view |
|---|---|---|---|
| 0 | `round0_baseline`: the usual scalpers | – | `--triage`: heuristic and LLM side by side |
| 1 | `round1_injected_ua --variant both`: instructions in the User-Agent and Referer | – (watch the naive prompt fail) | `--triage`: injection success |
| 2 | `round2_stitched --mode stitch`, then `--mode bait` | `defenses/sanitize.py` (input caps, phrase redaction, output validation) and `defenses/triage.py` (the fenced prompt) | `--triage`: injection success after hardening |
| 3 | `round3_token_flood --n 400` | `defenses/cluster.py` (pre-filter and clustering) and `defenses/gate.py` (replay candidate rules against verified customers) | `--live`: real users blocked per cohort and bots blocked, at the edge |

`python tools/checkpoint.py --round N` triages the round's run (`defenses/triage.py`) and scores it with `tools/scoreboard.py`; for Round 3 it prints the operations steps and the live view. Read the numbers by cohort: an injection that drops to a few percent is a result, and a residual that never reaches zero is the lesson.
