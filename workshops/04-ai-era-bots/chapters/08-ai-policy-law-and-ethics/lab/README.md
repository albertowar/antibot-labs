# Chapter 8 Lab: Reservation, Agent Policy, Governance Record

**Format:** 3 rounds, 45 min, plus a 10 min debrief. See `../chapter_08_content.md`, §8.4.

This chapter's attacker is three different things. In Round 1 it is a fleet of AI crawlers, honest and otherwise, reading the signals you publish. In Round 2 it is a scalping farm that has learned that, since *Amazon v. Perplexity* (9th Cir., August 2026), a shopper's own agent is legally the shopper, and hides behind that. In Round 3 it is the other team, reading your AI governance record the way an auditor would. Each round still has a 🔵 defense, a 🔴 attack that beats it, a checkpoint and a number.

## Rules of engagement

Nothing in this lab touches a network. The crawler fleet and the agent farm are models that read your local policy files; the session log is generated from the documentation address ranges in `data/world.json` (RFC 5737 / RFC 3849); every vendor, crawler token, account and case fact in the exercises is invented unless it carries a citation. Nothing here is legal advice. Case law and regulation are current to October 2026; check before teaching.

```
lab/
  requirements.txt            Python 3.12+ standard library only. No Docker, no demo-site process.
  data/world.json             the simulated internet from W2 Ch8 (documentation ranges, ASNs)
  data/agent_sessions.jsonl   3,000 sessions: 2,000 real people in six cohorts, 4 bot campaigns of 250
  defenses/reservation/       your Round 1 stack: robots.txt · headers.json · terms.json · logging.json
  defenses/reservation_naive/ the day-one stack · reservation_reference/ the instructor's
  policies/                   agent_policy_blunt (day one) · agent_policy_naive (the first fix) · agent_policy (yours) · agent_policy_reference
  attacks/                    round1_crawler_fleet · round2_agent_farm
  exercises/                  round1 fleet key · round3 governance record template + audit cards · AI ethics checklist
  tools/                      make_log · reservation_audit · agent_audit · checkpoint
```

**Why Python and no server:** the chapter is about the policy and the paperwork *over* the stack you built in W4 Ch1–7, not the stack. Shipped, deterministic inputs let everyone audit the same six crawlers and 3,000 sessions in seconds, and make the numbers below reproducible. `tools/make_log.py` regenerates the session log byte-for-byte from seed 2026.

---

## Setup (before the session)

```bash
cd workshops/04-ai-era-bots/chapters/08-ai-policy-law-and-ethics/lab
python3 --version                                                  # 3.12 or newer
python3 tools/reservation_audit.py --stack defenses/reservation    # Round 1 scoreboard
python3 tools/agent_audit.py --policy policies/agent_policy.json   # Round 2 scoreboard
```

If both commands print a scoreboard, you are ready. Print or open `exercises/round3_governance_record_template.md` and `exercises/round3_audit_cards.md`; Round 3 is a paper exercise.

**Troubleshooting**

- `ModuleNotFoundError`: you are running an old Python. Use 3.12+ (the series floor); nothing needs installing.
- `data/agent_sessions.jsonl` missing or edited: `python3 tools/make_log.py` rebuilds it.
- You broke `defenses/reservation/` or `policies/agent_policy.json`: `cp defenses/reservation_naive/* defenses/reservation/` or `cp policies/agent_policy_blunt.json policies/agent_policy.json` to start over.
- Windows: use `python` instead of `python3`. Paths in this README are relative to `lab/`.

---

## How to measure a round

Every round reports three things, and the instructor table at the bottom is in the same shape.

- **Attacker success.** Round 1: crawlers that *ingested* your catalogue. Round 2: farm sessions that reached the shop. Round 3: audit cards the record does not answer.
- **Real users hurt.** Round 1: search visibility lost, and the lawful research crawler you turned away. Round 2: blocked and challenged rate **per cohort** against a 2 % blocked budget, with agent shoppers and assistive agents as separate rows. Round 3: the cohort the record forgets to measure.
- **Defender cost.** Round 1: the logging you must keep (and justify) to make any lever work. Round 2: friction (challenges and human confirmations served to real people) and the exposure notes. Round 3: the clauses you had to add.

**Fell behind?** `python3 tools/checkpoint.py --round N` prints the round's key, reference scoreboard or checklist.

---

## Round 1: A reservation that holds ⚔️ the crawler fleet (15 min)

You inherit `defenses/reservation_naive/`, already copied into `defenses/reservation/`: a `robots.txt` that disallows one vendor's token, no usage signals, a browsewrap clause saying "no bots", and 7 days of user-agent logs. Three declared crawlers visit by default; the full fleet adds the ones that do not announce themselves.

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend (look) | `python3 tools/reservation_audit.py --stack defenses/reservation` | **Machine-readable reservation: NO.** The signatory, the search crawler and the research crawler all ingest; 8 exposure notes |
| 🔵 Defend (edit) | Edit the four files in `defenses/reservation/` until the reservation is machine-readable and the declared crawlers honour it. Re-run after each change. | Most teams write `User-agent: *` / `Disallow: /`: honoured 3/3, **search visibility: LOST** |
| 🔴 Attack | `python3 attacks/round1_crawler_fleet.py --stack defenses/reservation --fleet all` then `python3 tools/reservation_audit.py --stack defenses/reservation --fleet all` | Against the blanket Disallow: stealth crawler, intermediary and mirror ingest anyway; **evidence sufficient 0/2**; the only thing you lost was search |
| 🔵 Re-run | Separate access from usage: `Allow: /` for `*` with `Content-Signal: search=yes, ai-input=no, ai-train=no` and `Content-Usage: train-ai=n, ai-use=n`; the same `Content-Usage`, `TDM-Reservation: 1` and an RSL `Link` in `headers.json`; `clickwrap` in `terms.json`; every logging field on and `retention_days` 90 | Reference: honoured 2/6 (signatory; search for training), ingested 5/6, **search kept, evidence 2/2**, exposure notes: none |
| ✅ Checkpoint | `python3 tools/checkpoint.py --round 1` then `cp defenses/reservation_reference/* defenses/reservation/` | prints `exercises/round1_fleet_key.md` and the reference scoreboard |

What the scoreboard reports:

```
=== Reservation stack: reservation_reference   fleet: gpai_signatory, ... pirate_mirror ===
Machine-readable reservation: YES   channels: robots.txt Content-Signal ai-train=no, ..., Link rel=license (RSL), ...

  crawler                robots   saw reservation  honoured    ingested  lever / evidence
  gpai_signatory         fetched  yes              yes         no        -
  search_answers         fetched  yes              train only  YES       none reliable: ai-input=no is read but not honoured; ...
  research_tdm           fetched  no               -           YES       none: research TDM (DSM Art 3) is lawful ...
  stealth_crawler        skipped  no               -           YES       AI Act Art 53 complaint ...; DMCA 1201 ...  [evidence: sufficient]
  scraping_intermediary  fetched  yes              NO          YES       DMCA 1201 (Reddit v. SerpApi, S.D.N.Y. 2026) ...  [evidence: sufficient]
  pirate_mirror          -        n/a              -           YES       copyright against the ingestor (Bartz v. Anthropic ...). Your signals never reached it

Honoured 2/6 · Ingested 5/6 · Search visibility: kept · Reachable ignorers with sufficient evidence: 2/2
Exposure notes: none.
```

- **Honoured / ingested:** a crawler that read a machine-readable reservation and left, versus one that took the catalogue. "Train only" means the search crawler will not train on you but still uses your pages for AI answers; the `ai-input` signal is a request, not a control.
- **Lever / evidence:** for each ingesting crawler, the legal route that reaches it (AI Act Art 53 complaint, DMCA §1201, contract, GDPR, copyright, or none) and whether `logging.json` would carry it. A lever with missing evidence is a letter nobody has to answer.
- **Exposure notes:** facts about the stack that change what the outcome costs you: a natural-language-only reservation (OLG Hamburg, *Kneschke v. LAION*, December 2025), a named-token list, browsewrap terms, each logging field that is off, retention too short to answer a letter or too long to justify.

**The lesson in the numbers:** signals stop the honest, logs convict the rest, and nothing you emit reaches the mirror. Five of six still ingest under the reference stack: the search crawler for answers under a signal it does not act on, the research crawler lawfully, two with your evidence against them, one out of reach.

**Exercise (if time):** delete the `ScrapeFeed-Bot` group from the reference `robots.txt` and re-run with `--fleet all`. The intermediary's row changes from "saw reservation: yes, honoured: NO" to "no". Which version is the better evidence?

---

## Round 2: An agent policy ⚔️ the shopper's own agent (17 min)

You inherit `policies/agent_policy_blunt.json`, copied into `agent_policy.json`: hard blocks on every agent signal, "no bots" in browsewrap terms, an image CAPTCHA, no appeal path, a year of logs. It stopped last month's scalping wave. Run it and read who else it stopped.

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend (look) | `python3 tools/agent_audit.py --policy policies/agent_policy.json` | scalper 100 % caught; **agent_shopper 98.3 %, cloud_signed 100 %, cloud_undeclared 100 %, a11y_agent 100 % blocked**; 4 cohorts over budget; 10 exposure notes |
| 🔵 Defend (edit) | Edit `agent_policy.json` until every cohort is at or under 2 % blocked with the scalper still ≥ 85 % caught. Levers: delete the hard rules, exempt the agent and screen-reader signals, lower weights. Re-run after each change. | Most teams land near `agent_policy_naive.json`: no rules, `agent_ua` / `signature_agent` / `no_pointer` / `screen_reader_api` exempted with `"max_action": "allow"`. Scalper still 100 % caught, nobody blocked |
| 🔴 Attack | `python3 attacks/round2_agent_farm.py --policy policies/agent_policy.json` (try `agent_policy_naive.json` too) | Against the naive fix: **750 of 750 hidden sessions reached the shop, 0 % caught.** The farm looks like an agent shopper per session; the mimic lives inside the assistive-technology exemption |
| 🔵 Re-run | Change every `"max_action": "allow"` to `"challenge"` and drop the `no_pointer` exemption (weight 5 never blocks anyone alone); set `declaration.required` true with `undeclared_agent_action` `challenge`; `account_velocity` 4 orders/hour → `block`; `checkout_step_up` `human_confirm`; `challenge_type` `pow`; terms `clickwrap` + `declared_only`; `appeal_path` true; `retention_days` 90. Run `--campaigns all` | Reference: **96.7 % caught** (646 blocked, 321 stopped at the human step-up), 0 cohorts blocked, exposure notes: none. Cost: agent_shopper 38.9 % challenged + 39.3 % step-ups, cloud_undeclared 70.8 % challenged, a11y_agent 53.2 % challenged |
| ✅ Checkpoint | `python3 tools/checkpoint.py --round 2` then `cp policies/agent_policy_reference.json policies/agent_policy.json` | reference scoreboard |

What the scoreboard reports:

```
=== Agent policy: reference   campaigns: scalper_headless, local_agent_farm, declared_then_undeclared, a11y_mimic ===
Bots: 1000   caught 967 (96.7%)   blocked 646   challenged 0   stopped at step-up 321   allowed 0 (0.0%)
  scalper_headless           caught 100.0%   (block 250, ...)
  local_agent_farm           caught 100.0%   (block 250, ...)              <- velocity per account
  declared_then_undeclared   caught  94.0%   (block 146, ..., step-up  89)
  a11y_mimic                 caught  92.8%   (block   0, ..., step-up 232) <- the exemption held; the step-up caught it

Real people:
  cohort                n   blocked  challenged   step-up   allowed   budget
  shopper            1452      0.0%        0.0%     25.5%     74.5%   ok
  agent_shopper       229      0.0%       38.9%     39.3%     21.8%   ok
  cloud_signed        122      0.0%       10.7%     44.3%     45.1%   ok
  cloud_undeclared     65      0.0%       70.8%     29.2%      0.0%   ok
  a11y_agent           47      0.0%       53.2%     36.2%     10.6%   ok
  ...
FP budget (2% blocked per cohort): 0 cohort(s) over budget.   Bot target (85% caught): met.
Exposure notes: none.
```

- **Bots:** blocked, challenged, stopped at the human step-up, allowed, per campaign. "Caught" is the first three. A farm session that a human operator confirmed counts as allowed: the step-up is a cost to the farm, not a verdict.
- **Real people:** blocked (a false positive), challenged (friction), step-up (a confirmation the person answered), allowed, per cohort, with the 2 % budget flag. A screen-reader session served an image CAPTCHA is counted as blocked.
- **Exposure notes:** the hard block on agents after *Amazon v. Perplexity*, blocking signed agents while unsigned ones pass, assistive-technology blocks, `allow` exemptions, terms that prohibit agents or say nothing, no human step at the money step, inaccessible challenge, no appeal path, long retention.

**False-positive check:** the reference policy blocks nobody, but it challenges 71 % of undeclared cloud agents and 53 % of assistive agents, and hands a confirmation back to a quarter of all shoppers at checkout. That is where the cost went. The challenge is a proof of work (non-visual); the confirmation is the thing a shopper's agent exists to hand back. Is it acceptable? Write down, for Round 3, who gets to decide that and which number they watch.

**Exercise (if time):** set `checkout_step_up` back to `none` and run `--campaigns all`. Everything is still "caught", but the a11y mimic is now 250 proof-of-work challenges and no blocks: the screen-reader exemption caps velocity at a challenge, and a proof of work is a cost a farm can pay. Which number would you report to the board? Then set `undeclared_agent_action` to `block` and read the `agent_shopper` and `cloud_undeclared` rows.

---

## Round 3: The AI governance record ⚔️ the auditor's cards (13 min)

The detection stack now contains an adversarially trained classifier (W4 Ch6) and an LLM in the triage and appeal path (W4 Ch7). Nothing yet says who is its provider, what it was trained on, whether the appeal assistant admits it is a machine, or who switches it off. You write that now. It is also the charter the Capstone runs under.

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | 5 min: fill `exercises/round3_governance_record_template.md` for your team, with names and numbers in the blanks | `python3 tools/checkpoint.py --round 3 --record <file>` ≥ 10/12 (the blank template scores 11: retention needs a number) |
| 🔴 Attack | 5 min: swap records; the other team answers `exercises/round3_audit_cards.md` against yours: answered / vague / **doesn't say** | Typical first drafts have no lawful basis for *training* on session logs, no Art 50 wording for the appeal assistant, and nothing about who the labyrinth may be served to |
| 🔵 Re-run | 3 min: patch every "doesn't say" with a concrete rule | 0 unanswered cards |
| ✅ Checkpoint | `python3 tools/checkpoint.py --round 3` | the 12-item checklist |

**Discuss:** which of the twelve items would you have skipped if the other team had not been reading? That one is the paragraph that gets written after the regulator's letter.

---

## Debrief (10 min)

Fill in the scoreboard on the slide: Round 1 honoured / ingested / evidence on your final stack, Round 2 bots caught and cohorts over budget on your final policy, Round 3 cards unanswered. Then the two questions that carry into the Capstone:

1. Your Round 2 policy challenges 71 % of undeclared cloud agents and hands a confirmation to a quarter of shoppers. The Capstone rubric scores blocked legitimate users. What should it say about *challenged* ones, and about agents whose owner never sees the challenge?
2. Which sections of your governance record would also be the right answer to a customer who asks "does the store use AI to decide who gets in?"

---

## Instructor: expected results

Verified on 2026-10-11 with Python 3.12.15 on Linux (standard library only; all three checkpoints run clean); the fleet is deterministic and the session log is seeded (2026), so these numbers do not drift.

**Round 1** (`tools/reservation_audit.py --fleet all`)

| Stack | Machine-readable | Honoured | Ingested | Search | Evidence (reachable ignorers) | Exposure notes |
|---|---|---|---|---|---|---|
| `reservation_naive` | **no** (one named token) | 0/6 | 6/6 | kept | 0/2 | 8 |
| blanket `User-agent: *` / `Disallow: /`, nothing else changed | yes | 3/6 | 3/6 | **lost** | 0/2 | 6 + the search-lost note |
| `reservation_reference` | yes, 6 channels | 2/6 | 5/6 | kept | **2/2** | 0 (one informational note on `ai-input`) |

**Round 2** (`tools/agent_audit.py --campaigns all`)

| Policy | `scalper_headless` | hidden (`local_agent_farm`, `declared_then_undeclared`, `a11y_mimic`) | Cohorts blocked (budget 2 %) | Challenged / step-up | Exposure notes |
|---|---|---|---|---|---|
| `agent_policy_blunt` | 100 % | 100 % (all blocked) | **4 over**: agent_shopper 98.3, cloud_signed 100, cloud_undeclared 100, a11y_agent 100; shopper 1.0 | vpn 100 challenged | 10 |
| `agent_policy_naive` | 100 % | **0 %, 750 allowed** | 0 over | none | 6 (four `allow` exemptions) |
| `agent_policy_reference` | 100 % | 95.6 % (396 blocked, 321 stopped at step-up, 33 allowed) | 0 over | agent_shopper 38.9 / 39.3; cloud_signed 10.7 / 44.3; cloud_undeclared 70.8 / 29.2; a11y_agent 53.2 / 36.2; shopper 0 / 25.5 | none |
| Real people, all cohorts | 2,000 people: blunt blocks 23.7 %, naive 0 %, reference 0 % (challenges 4.2 % / 0 % / 9.0 %; step-ups 0 / 0 / 28.6 %) | | | | |

| Round | Metric | Target |
|---|---|---|
| 1 | Final stack with `--fleet all` | machine-readable yes, search kept, evidence 2/2, 0 exposure notes |
| 2 | Final policy with `--campaigns all` | bots ≥ 85 % caught, 0 cohorts over budget, 0 exposure notes |
| 3 | `checkpoint.py --round 3 --record` and audit cards | ≥ 10/12 covered, 0 cards unanswered after the patch |

Things to watch for:

- Round 1 teams that "fix" the stack by adding more vendor tokens to `robots.txt`: the signatory in the fleet uses a token they have not listed, and the `robots.txt names ...` note stays. Reserve by usage.
- Round 1 teams that set `retention_days` to 365 to be safe: the retention note flips from "too short" to "write down why". Both are findings.
- Round 2 teams that set `undeclared_agent_action` to `block`: 52 % of agent shoppers and 100 % of undeclared cloud agents are blocked, two cohorts over budget. Assistive agents survive only because the `screen_reader_api` exemption caps the action at a challenge.
- Round 2 teams that rely on the step-up alone (naive weights plus `human_confirm`): about 89 % caught, because 10–25 % of farm sessions are routed to a human operator who answers the confirmation. Velocity per account is what blocks the farm.
- Round 3 records that say "we comply with the AI Act" under every heading score well with the grep and lose every card. Say so out loud before the swap.
- Case law is current to October 2026. *Amazon v. Perplexity* was a Ninth Circuit panel opinion (rehearing denied September 2026) with the CFAA claims back in the district court; *NYT v. OpenAI* was at summary judgment; the Third Circuit's *Thomson Reuters v. Ross* outcome and the Official Journal publication of the Digital Omnibus were unconfirmed at build time. Check all four before teaching and say which way they went.

---

## Bonus challenges

1. **Verified-agent lane.** Add an `if_signature_valid` rule type to `agent_audit.py` so a valid Web Bot Auth signature (W4 Ch2) can *lower* the action for cloud agents, and measure what that does to `declared_then_undeclared` phase 1. Then write the one-paragraph terms clause that lane depends on.
2. **Appeal path as a number.** Extend the Round 2 scoreboard with an "appealed and reinstated" column driven by `appeal_path`, assuming 30 % of blocked real people appeal and all are reinstated, and 0 % of agents' owners ever see the block page. What does that say about where the appeal link has to be?
3. **Reservation drift.** Write the 20-line check that fetches your *own* `robots.txt` and headers daily (against `localhost` only) and alerts when a channel disappears. The reservation that was there in January is the one a court asks about in June.
