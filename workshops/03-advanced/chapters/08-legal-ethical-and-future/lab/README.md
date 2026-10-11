# Chapter 8 Lab: Counsel, Auditor, Referee

**Format:** 3 rounds, 45 min, plus a 10 min debrief. See `../chapter_08_content.md`, §8.4.

This chapter's attacker is not a script. In Round 1 it is the scraper's lawyer, in Round 2 it is a bot campaign that has learned to look like the people your policy protects, and in Round 3 it is the other team reading your rules of engagement for the hole they will use this afternoon. Each round still has a 🔵 defense, a 🔴 attack that beats it, a checkpoint and a number.

> ⚠️ Nothing in this lab touches a network. The decision log is generated from the documentation address ranges in `data/world.json` (RFC 5737 / RFC 3849), the people in it are the W2 Ch8 synthetic population, and every name, account and case in the exercises is invented. Nothing here is legal advice.

```
lab/
  requirements.txt       Python 3.10+ standard library only. No Docker, no demo-site process.
  data/world.json        the simulated internet from W2 Ch8 (documentation ranges, ASNs)
  data/decisions.jsonl   3,500 scored requests: 2,000 real people in eight cohorts, 5 bot campaigns of 300
  policies/              policy_blunt (day one) · policy_naive (the first fix) · policy (yours) · policy_reference
  exercises/             round1_cases + answer key · round3 RoE template + loophole cards · ethics checklist · disclosure template
  tools/                 make_log · fp_audit · checkpoint
```

**Why Python and no server:** the chapter is about the policy *over* a pipeline you already built (W2 Ch8, W3 Ch3–4), not the pipeline. A shipped log lets everyone audit the same 3,500 decisions in seconds and makes the numbers below reproducible. `tools/make_log.py` regenerates it byte-for-byte from seed 2026.

---

## Setup (before the session)

```bash
cd workshops/03-advanced/chapters/07-legal-ethical-and-future/lab
python3 --version                                   # 3.10 or newer
python3 tools/fp_audit.py --policy policies/policy_blunt.json
```

If the last command prints a scoreboard, you are ready. Print or open `exercises/round1_cases.md` and `exercises/round3_roe_template.md`; Rounds 1 and 3 are paper exercises.

**Troubleshooting**

- `ModuleNotFoundError`: you are running an old Python. Anything 3.10+ works; nothing needs installing.
- `data/decisions.jsonl` missing or edited: `python3 tools/make_log.py` rebuilds it.
- Windows: use `python` instead of `python3`. Paths in this README are relative to `lab/`.

---

## How to measure a round

Every round reports three things, and the instructor table at the bottom is in the same shape.

- **Attacker success.** Round 1: claims the scraper's counsel defeats. Round 2: bots *allowed* through. Round 3: loophole cards the draft does not answer.
- **Real users hurt.** Round 1: the customers whose data was in the log. Round 2: blocked and challenged rate **per cohort**, against a 2% blocked budget (the Capstone rubric). Round 3: the cohort the rules forget to protect.
- **Defender cost.** Round 1: what the logs would have had to contain. Round 2: friction (challenges served to real people) and the exposure notes. Round 3: the clauses you had to add.

**Fell behind?** `python3 tools/checkpoint.py N` prints the round's answer key, reference scoreboard or checklist.

---

## Round 1: Three cease-and-desists ⚔️ the scraper's counsel (17 min)

Pairs: one 🔵 store's counsel, one 🔴 scraper's counsel. Three fact patterns in `exercises/round1_cases.md`: public listings scraped after a letter (US), logged-in GraphQL scraping by 400 fake accounts (US), and a people-search startup scraping EU customers' reviews.

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Store's counsel lists the claims that survive per case (CFAA, contract, DMCA §1201, trespass, fraud, GDPR) | Most teams over-claim CFAA on public pages |
| 🔴 Attack | Scraper's counsel answers each with the case that kills it (*Van Buren*, *hiQ*, *Meta v. Bright Data*, *Ryanair*, *Feist*) | Case A collapses to a narrow §1201 claim at best; Case C flips: the store is exposed, not just the scraper |
| 🔵 Re-run | Fill the verdict sheet; 5 min reveal against the key | Net score out of +6 |
| ✅ Checkpoint | `python3 tools/checkpoint.py 1` | prints `exercises/round1_answer_key.md` |

**Discuss:** for each surviving claim, what would the detection log have needed to contain? (The key's last section.) That question is the bridge to Round 2: the evidence that convicts a scraper is a store of personal data about every customer you scored.

---

## Round 2: The proportionality audit ⚔️ the campaign that hides among the protected (18 min)

You inherit `policies/policy_blunt.json`: hard blocks on Tor exits, datacenter ASNs and library user agents, a score ladder, no exemptions, a third-party CAPTCHA, no appeal path, a year of logs. It stops every scraper. Run it and read who else it stops.

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend (look) | `python3 tools/fp_audit.py --policy policies/policy_blunt.json` | bots 100% caught; **vpn 100%, tor 100%, a11y 66.7%, privacy 45.6% blocked**; 6 cohorts over the 2% budget; 6 exposure notes |
| 🔵 Defend (edit) | Copy `policy_blunt.json` over `policy.json` and edit it until every cohort is at or under 2% blocked with bots still ≥ 85% caught. Levers: delete hard rules, lower the weights that single cohorts trip alone, add `exemptions`. Re-run after each change. | Most teams land near `policy_naive.json`: no rules, `tor_exit`/`no_pointer`/`ip_elevated` exempted with `"max_action": "allow"`. Default scrapers still 100% caught |
| 🔴 Attack | `python3 tools/fp_audit.py --policy policies/policy.json --campaigns cgnat_burst,tor_hidden,a11y_mimic` (try it on `policy_naive.json` too) | Against the naive fix: **0% caught, 900 of 900 allowed**. The exemptions are the hole: a bot over Tor, or sending no pointer events, is never even challenged |
| 🔵 Re-run | Change every `"max_action": "allow"` to `"challenge"`, move Tor and datacenter from rules to small weights, put the weight on automation evidence (`headless_gpu`, `cdp_artifacts`, `fp_reuse`, `timing_too_regular`), switch `challenge_type` to `pow`, set `appeal_path` true and `retention_days` to 30. Run with `--campaigns all` | Reference: bots 100% caught (802 blocked, 698 challenged); 0 cohorts blocked; **tor 100% and a11y 61% challenged**; exposure notes: none |
| ✅ Checkpoint | `python3 tools/checkpoint.py 2` then `cp policies/policy_reference.json policies/policy.json` | reference scoreboard |

What the scoreboard reports:

```
=== Policy: reference   campaigns: scraper_dc, scraper_resi, cgnat_burst, tor_hidden, a11y_mimic ===
Bots: 1500   caught 1500 (100.0%)   blocked 802   challenged 698   allowed 0 (0.0%)
  ...
Real users:
  cohort          n   blocked  challenged   allowed   budget
  typical      1529      0.0%        0.0%    100.0%   ok
  vpn            64      0.0%       14.1%     85.9%   ok
  a11y           18      0.0%       61.1%     38.9%   ok
  tor            24      0.0%      100.0%      0.0%   ok
  ...
FP budget (2% blocked per cohort): 0 cohort(s) over budget.   Bot target (85% caught): met.
Exposure notes: none.
```

- **Bots:** blocked, challenged, allowed, per campaign. "Caught" is blocked plus challenged; a challenge is a cost, not a verdict.
- **Real users:** blocked (a false positive), challenged (friction), allowed, per cohort, with the 2% budget flag.
- **Exposure notes:** the facts about the deployment that change what a block costs you: hard rules on Tor or datacenters, `allow` exemptions, a third-party CAPTCHA, no appeal path, long retention, keyboard-only users over budget.

**False-positive check:** the reference policy blocks nobody, but it challenges every Tor user and 61% of keyboard-only users. That is where the cost went. Is it acceptable? Only if the challenge has an accessible, non-visual path and the people behind it can get through. A proof-of-work challenge does; an image CAPTCHA does not. Write that down for Round 3.

**Exercise (if time):** try `"max_action": "allow"` for `no_pointer` only and run `--campaigns a11y_mimic`. Then try blocking `fp_randomized` at 40 again and look at the `privacy` row. Every lever has a cohort on the other end.

---

## Round 3: Rules of engagement for the Capstone ⚔️ the loophole hunt (10 min)

This afternoon each team attacks another team's deployment. Nothing in the Capstone brief says who authorised that, what is in scope, or how a blocked legitimate cohort is scored. You write it now.

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | 4 min: fill `exercises/round3_roe_template.md` for your team, with numbers in the blanks | `python3 tools/checkpoint.py 3 --roe <file>` ≥ 10/12 (the blank template scores 11: traffic limits need a number) |
| 🔴 Attack | 4 min: swap drafts; the other team answers `exercises/round3_loophole_cards.md` against yours: allowed / forbidden / **doesn't say** | Typical first drafts miss the opponent's Redis, the CAPTCHA-solving service, and what happens to captured logs after the workshop |
| 🔵 Re-run | 2 min: patch every "doesn't say" with a concrete rule | 0 unanswered cards |
| ✅ Checkpoint | `python3 tools/checkpoint.py 3` | the 12-item checklist |

**Discuss:** which of the twelve items would you have skipped if the other team had not been reading? That one is the clause that gets written after an incident in production.

---

## Debrief (10 min)

Fill in the scoreboard on the slide: Round 1 net score, Round 2 bots caught and cohorts over budget on your final policy, Round 3 cards unanswered. Then the two questions that carry into the Capstone:

1. Your Round 2 policy challenges 100% of Tor users and 61% of keyboard-only users. What does the Capstone rubric need to say about *challenged* legitimate users, not just blocked ones?
2. Which clauses of your rules of engagement would also be the right clauses for a production bug-bounty scope?

---

## Instructor: expected results

Verified with Python 3.10 on Linux; the log is deterministic (seed 2026), so these numbers do not drift.

| Policy ↓ / campaigns → | default (`scraper_dc`, `scraper_resi`) | hidden (`cgnat_burst`, `tor_hidden`, `a11y_mimic`) | Cohorts blocked (budget 2%) | Challenged | Exposure notes |
|---|---|---|---|---|---|
| `policy_blunt` | 100% caught (600 blocked) | 100% caught (900 blocked) | **6 over**: vpn 100, tor 100, a11y 66.7, privacy 45.6, old_device 6.2, cgnat 2.6 | cgnat 29.1, privacy 54.4, a11y 33.3 | 6 |
| `policy_naive` | 100% caught | **0% caught, 900 allowed** | **2 over**: privacy 45.6, vpn 17.2 | vpn 53.1, privacy 54.4 | 6 (three `allow` exemptions) |
| `policy_reference` | 100% caught | 100% caught (202 blocked, 698 challenged) | 0 over | tor 100, a11y 61.1, vpn 14.1, cgnat 1.7 | none |
| Real users, all cohorts | 2,000 people: blunt blocks 6.5%, naive 1.9%, reference 0% (challenges 3.6% / 3.4% / 2.3%) | | | | |

| Round | Metric | Target |
|---|---|---|
| 1 | Net verdict score (max +6) | ≥ +3; every pair marks Case C "store has no exposure" as **No** |
| 2 | Final policy with `--campaigns all` | bots ≥ 85% caught, 0 cohorts over budget, 0 exposure notes |
| 3 | `checkpoint.py 3 --roe` and loophole cards | ≥ 10/12 covered, 0 cards unanswered after the patch |

Things to watch for:

- Teams that "fix" Round 2 by setting `challenge_at` and `block_at` very high: bots drop below 85% caught, which the scoreboard flags as `MISSED`.
- Teams that exempt `fp_reuse` or `timing_too_regular`: those are automation evidence that no real cohort trips alone; the hidden campaigns walk through.
- In Round 3, a draft that says "be reasonable" for traffic limits scores a red point; the checklist wants a number.
- Case law in the answer key is current to October 2026. *Ryanair v. Booking.com* was on appeal to the Third Circuit and *Reddit v. SerpApi* was a district-court ruling at build time; check both before teaching and say which way they went.

---

## Bonus challenges

1. **Country block.** Add `{"if_country": "DE", "action": "block"}` support to `fp_audit.py` and measure what it does to the `tor` cohort (Tor exits in `world.json` are in Germany). Then write the one-paragraph justification a regulator would ask for. Most people cannot.
2. **Appeal path as a number.** Extend the scoreboard with an "appealed and reinstated" column driven by `appeal_path`, assuming 30% of blocked real people appeal and all of them are reinstated. How does that change the per-cohort block rate, and what does it cost in support time?
3. **Retention.** Write the 10-line deletion job the `retention_days` field implies, against `decisions.jsonl`. Then list which fields you would drop *before* 30 days to keep the log useful for Case B's evidence while holding less personal data.
