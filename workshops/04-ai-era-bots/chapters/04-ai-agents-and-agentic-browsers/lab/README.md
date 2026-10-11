# W4 Ch4 Lab — AI Agents & Agentic Browsers

**Format:** 4 rounds of attack ⚔️ defend. This is a minimal README: the chapter's content doc and measured expected results are still to be written (see the chapter's entry in the root `TODO.md`).

The store is the end-of-Workshop-2 stack plus an agent policy, selling one limited drop ("Lab Runner 9", one per account). Shoppers now arrive through AI agents as well as browsers. Some are honest and declared, some hide, some forge an identity, and one runs a fleet. Each round you add the layer that sorts them, and the checkpoint measures what it stops **and** what happens to the 40 human customers and the legitimate agents.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- The agents drive the local store with Playwright and Chromium. Egress addresses are RFC 5737 documentation ranges claimed in `X-Lab-Egress`, which the store honours only from loopback. Accounts, payment mandates and the step-up inbox (`/lab/mailbox/<email>`) are synthetic.
- The agent's decisions come from a scripted policy by default. `AGENT_POLICY=ollama` swaps in a local model; `OLLAMA_URL` must point at this machine, and `labnet.py` refuses anything else, so prompts never leave the laptop.
- Operator signing keys are generated on your machine by `tools/make_keys.py`, and the store's `instance/` secrets are gitignored.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  labnet.py            the localhost guard and catch-up helper (shared by every lab)
  demo_site/           app.py (the store, DEFENSE_LEVEL 0–4, http://127.0.0.1:8404) · models.py · static/
  defenses/            agent_policy · agent_behavior · agent_identity · checkout_gate  ← YOU EDIT THESE
                       request_checks · automation · fingerprint_coherence · behavior_flow ·
                       risk_engine · httpsig (given: the W1–W2 stack, in shadow)
  attacks/             round1_honest_agent · round1_undeclared_agent … round4_fleet · agent/ (the agent loop)
  tools/               doctor · seed · make_keys · checkpoint · legit_traffic · scoreboard · personas · profiles/
  solutions/roundN/    reference defenses, installed by --catch-up
```

## Setup

Python 3.12+ and Chromium. No Docker: the store uses SQLite and an in-memory Redis by default.

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
python tools/seed.py                              # accounts, past orders, operator keys
python tools/doctor.py                            # preflight: packages, Chromium, keys, store
DEFENSE_LEVEL=1 python demo_site/app.py           # terminal 1: the store on 127.0.0.1:8404
python tools/checkpoint.py --round 1              # terminal 2 (HEADLESS=1 with no display)
```

`PORT` changes the store's port; export `DEMO_URL=http://127.0.0.1:<port>` for the tools to match. With the in-memory Redis, restart the store after `tools/seed.py`. Debug endpoints that are never blocked: `/whoami` and `/agent-policy`.

**Fell behind?** `python tools/checkpoint.py --round N --catch-up` installs the reference solutions for rounds 1..N from `solutions/` over your files and keeps each of yours once as `.bak`. Restart the store at `DEFENSE_LEVEL=N`, then run the checkpoint again. `python tools/checkpoint.py --restore` puts your own files back.

## Rounds

| Round | `DEFENSE_LEVEL` | 🔴 Attack | 🔵 You edit | What the checkpoint expects of the attack |
|---|---|---|---|---|
| 1 | 1 | `round1_undeclared_agent` (and `round1_honest_agent` for contrast) | `defenses/agent_policy.py`: declared agents may browse, not buy | Gets through: the policy only sorts honest agents. Round 2 closes this |
| 2 | 2 | `round2_humanized_agent` | `defenses/agent_behavior.py`: teleport clicks, paste-like fills, metronome timing | Gets through: it clears the behaviour score. Round 4's gate caps it |
| 3 | 3 | `round3_forged_agent` (and `round3_verified_agent`, the happy path) | `defenses/agent_identity.py`: Web Bot Auth signatures from trusted operators | Stopped: every forged identity is refused, the verified agent buys |
| 4 | 4 | `round4_fleet` | `defenses/checkout_gate.py`: mandates, human step-up, per-account and per-device caps | Capped at the per-device limit (≤ 2) despite passing the step-up |

A round passes when the round's attack meets that expectation **and** no human customer is blocked. Challenges count as friction, not failure. The checkpoint also prints the W2 stack's shadow score, so you can see what the older layers would have done.
