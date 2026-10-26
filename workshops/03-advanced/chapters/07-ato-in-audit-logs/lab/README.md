# W3 Ch7 Lab — Investigating Account Takeover in Audit Logs

**Format:** Round 0 explore + five detection rounds + reveal. See `workshops/03-advanced/chapters/07-ato-in-audit-logs/chapter_07_content.md` (slides repo), §7.4.

This chapter's attacker is not a script you run. It already ran: nine account-takeover campaigns are buried in 90 days of a store's account audit log, next to every legitimate behaviour that looks like one. Each round is still a 🔵 defense (a detection family you build in a notebook), a 🔴 attack (the tier of campaigns built to evade the previous round's family), a checkpoint and a number. The answer key stays sealed until the reveal; the scorer tells you how you are doing without telling you why.

## Rules of engagement

Nothing in this lab touches a network. Every address is non-routable (198.18.0.0/15 benchmark space for residential, mobile and datacenter pools; 100.64.0.0/10 for carrier NAT; the RFC 5737 /24s for VPN, Tor and hosting; 2001:db8::/32 for IPv6), every ASN is private (RFC 6996), and every account, agent, device and city centroid is invented. The companies named in the data do not exist.

```
lab/
  requirements.txt       pandas, numpy, scikit-learn, networkx, matplotlib, jupyterlab. Python 3.12+. One venv per chapter.
  data/                  account_activity.jsonl.gz is GENERATED (python tools/make_log.py, ~1 min, ~24 MB) and gitignored.
                         world.json (the simulated internet), sample.jsonl (the first 2,000 events, for a look at the schema)
  notebooks/             00_explore · 01_rules · 02_graph · 03_ml · 04_invariant · 05_session_queue · 06_reveal  (one per round; each starts from the previous round's suspects)
  tools/                 make_log (generator) · atolab (helpers) · score (the checkpoint) · checkpoint (reference rounds, catch-up) · doctor
  solutions/             answer_key.json · round1_rules.py · round2_graph.py · round3_anomaly.py · round4_invariant.py · round5_session_queue.py · checkpoints/suspects_r{1..5}.csv · walkthrough.md
  tests/                 test_make_log.py: golden digest (determinism) and the tier-integrity assertions the README table rests on
```

**Why a notebook and no server:** the chapter is about the *analysis* over a log the W2 Ch6 login pipeline and the W3 Ch3 stream already produced, not about producing it. A generated log lets everyone investigate the same 335,000 events, makes the scoreboard reproducible, and keeps a 3-hour chapter off server setup. `tools/make_log.py` regenerates it byte for byte from seed 2026 on any Python 3.12+.

---

## Setup (5 minutes plus a 1-minute generation)

```bash
cd workshops/03-advanced/chapters/07-ato-in-audit-logs/lab
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python tools/make_log.py                                # writes data/account_activity.jsonl.gz, about a minute
python tools/doctor.py                                  # versions, data present, digest matches the answer key
jupyter lab notebooks/
```

**Troubleshooting**

- `doctor.py` says the digest does not match: you generated with a different seed or scale, or edited the generator. Run `python tools/make_log.py` with no flags.
- `ModuleNotFoundError: atolab`: the notebooks add `../tools` to `sys.path` in their first cell; run that cell, and start JupyterLab from `lab/` or `lab/notebooks/`.
- Memory: the full log loads into about 1.5 GB as a DataFrame. On a small laptop, `load_events(nrows=150000)` is enough for Rounds 0 and 1.
- Windows: use `python` instead of `python3`. Paths in this README are relative to `lab/`.

---

## The data

One JSON object per line, 24 fields. `details` is a per-type object; `atolab.load_events()` flattens the common keys into `d_*` columns.

| Field | What it is |
|---|---|
| `event_id`, `ts`, `ingested_at` | Stable id; when the client said it happened; when the log received it. They differ, sometimes by hours, occasionally in the wrong direction. |
| `account_id`, `event_type`, `outcome`, `actor` | Who, what, success/failure, and whether the user, a support agent (`details.agent_id`) or the system did it. |
| `client`, `session_id`, `auth_method`, `mfa_method` | web / ios / android / api; the session; password / passkey / oauth:provider / magic_link / **session_resume**; the MFA method used, if any. |
| `ip`, `asn`, `asn_type`, `country`, `city` | Where from, as the geo-IP provider reported it (residential / mobile / cgnat / datacenter / vpn / tor / internal). City centroids are in `data/world.json`. |
| `device_id`, `fp_hash`, `ja4`, `user_agent` | The browser's cookie, its canvas fingerprint, its TLS fingerprint, its UA. Any of them can be missing for a non-browser client. |
| `accept_language`, `tz_offset` | The client's locale and its clock's offset from UTC, in minutes. |
| `request_id`, `details` | Retries share a `request_id`; `details` carries reason codes, ticket and agent ids, provider ids, amounts, ship-to flags, old/new email domains, `alerts_enabled`. |

About forty event types; the content doc §7.1.1 groups them. There is **no label column**: production logs never have one.

---

## How to measure a round

Every round produces `suspects_rN.csv` (an `account_id` column; optional `score` for ranking and `first_event_id` as your time-to-detect claim) and runs

```bash
python tools/score.py suspects_r2.csv --prev suspects_r1.csv
```

which prints the series' three numbers (for Rounds 2-5 pass the previous file as `--prev` to see what the round added):

- **Attacker success:** confirmed takeovers found per campaign (shown as `campaign A-1 … D-9` until the reveal), per tier, and per compromise level (`access_only` / `persisted` / `monetized`).
- **Real users hurt:** accounts flagged per legitimate cohort against a budget of 2% (or one account), worst first, with each red-herring cohort's one-line story. Rounds 1 and 2 are block-grade findings and must stay within budget. Rounds 3-5 are review queues: a queue entry is friction, not an action, so they are judged on precision at 25/50/100, and Rounds 4 and 5 on what they **add** to the previous round (the scorer's "This round added N accounts, M of them takeovers" line, from `--prev`).
- **Defender cost:** precision, precision at the queue sizes an analyst can open, and analyst-hours at five minutes a review.

Names, misses and the red herrings' stories appear with `--reveal` (after Round 5). **Fell behind?** `python tools/checkpoint.py --round N --catch-up` runs the reference detector for round N and writes its suspects to `lab/suspects_rN.csv` so the next notebook can start from it.

---

## Round 0: Explore · `notebooks/00_explore.ipynb`

Load the log, look at the event mix, the share of `session_resume` logins, a few account timelines. Find the four data-quality traps before anyone names them: duplicate lines, retries, late arrivals and clock skew, and one address block that changes country for three days. Write three hypotheses with numbers in them. Nothing to submit.

## Round 1: Rules ⚔️ tier A · `01_rules.ipynb`

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Write five rules: impossible travel · new context + high-risk change · stuffed then entered · MFA fatigue · reset from nowhere. Each needs a **known-history clause** (novelty is relative to history the log contains). | A first draft without the clause flags ~180 accounts and puts email migrants, password-manager migrants and dormant returners far over budget |
| 🔴 Attack | Score it. The campaigns that stay at 0/N are the ones built to beat per-account rules: no high-risk change, correct credentials, a shared identity, a complicit agent. | Tier A found, tier B and C at or near zero |
| 🔵 Re-run | Add the clause; try `MIN_HISTORY` of 3 and 10. Then the exercise: widen the target set to medium-risk events (`address_added`, `payment_method_added`, `order_placed`). | Reference: 29 flagged, tier A 24/26, tier B 0/46, tier C 0/18, precision 83%, 0 cohorts over budget. Wide: a few phishing-kit victims, and new-phone upgraders and gift buyers over budget |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1 --catch-up` | the reference `suspects_r1.csv` |

**Discuss:** the only rule that found access-only takeovers is "failure from datacenter space, then a password login from datacenter space". What in the login pipeline (W2 Ch6) would have made the log unnecessary for them?

## Round 2: Graph ⚔️ tier B · `02_graph.ipynb`

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack (look) | Build the account–identifier graph on `ja4` and `ip` and read the largest components. | A 4,000-account component (the top Chrome JA4), carrier NAT hubs of hundreds, the VPN exit, the QA team's shared browser |
| 🔵 Defend | **Seed expansion** from your Round 1 accounts: identifiers that first appeared on them at or after the compromise, from *user* events, seen on at most a dozen accounts. Then **young, thin components** on `device_id`, `fp_hash`, `provider_sub_hash`: 2–12 accounts per identifier, every edge first seen on or after day 25, few events per edge, and no old thick identifier shared by the same accounts. | Expansion: ~35 accounts. Components: ~11 of 2–8 accounts, ~16 of which are a fake-account cluster (no history before the shared id): abuse, not takeover, kept out |
| 🔴 Attack (why it is hard) | Drop any guard and re-score: without the user-actor guard, the store's own policy engine links all 295 force-reset accounts; without the same-person guard, duplicate-account owners go over budget; with a degree threshold instead of components, the kit (cookie rotated every 4–6 victims) is missed or households are flagged. | Each guard is worth a cohort |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2 --catch-up` | Reference (cumulative): 68 flagged, tier A 25/26, **tier B 36/46**, tier C 0/18, precision 90%, 0 cohorts over budget |

**Discuss:** one tier is still at zero and its victims share nothing with each other. What is left to compare them against?

## Round 3: Models ⚔️ tier C · `03_ml.ipynb`

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Weekly `window_features()` (14-day windows, leak-free, successful events only for every behavioural feature), an IsolationForest on the deviation features, each account's worst week, a top-100 queue of accounts Round 2 did not contain. | Reference (cumulative): 168 flagged, tier A 25/26, tier B 39/46, **tier C 11/18**, precision at 100 of the ranked list 75% |
| 🔴 Attack (the queue's cost) | Read the queue's composition: travellers, relocators, the MFA-migration batch, forced resets. Each is a single feature doing honest work on the wrong person. | 5 cohorts "over budget" in a 100-account review queue; that is what review is for. Three tier D accounts are in it by accident |
| 🔵 Contrast | Train the supervised model on Rounds 1+2 and submit its queue instead. | More tier A and B, almost no tier C: a model trained on your detections finds your detections |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3 --catch-up` | the reference `suspects_r3.csv` |

## Round 4: Invariant ⚔️ tier D · `04_invariant.ipynb`

Campaign D (pre-hijack) is a sequence that should be impossible, not an anomaly: the attacker signs up with the victim's email first and never verifies it; the real person later "recovers" the account with a reset, verifies and adds a card; the attacker's session survives. Round 4 is judged on what it **adds** to Round 3.

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack (the textbook rule) | Test "a reset must end every other session" on the log: how many resets are followed by `sessions_revoked_all`? | 857 accounts complete a user reset; 36 have a revoke of any kind. The textbook rule would flag ~820 owners. Revocation is not logged by the flows you are auditing: a finding for the product team, not a detector |
| 🔵 Defend | Build the invariant from what is logged: a user-initiated `password_reset_completed` on an account created inside the window, **no `email_verified` before the reset**, from a device other than the creating one. **No `n_prior` clause**: tier D accounts are new by construction. | 6 flagged, 6/6 tier D, 0 innocent. Adds 3 over Round 3 (the model had 3 by accident): 100% delta precision |
| 🔴 Attack (why P2 alone is a disaster) | Take the symptom (reset, then a `session_resume` on a pre-reset device) as a rule across all accounts and score it. | `python solutions/round4_invariant.py --p2`: 473 flagged, 13 cohorts over budget (forgetful owners, support recoveries, forced resets). Use it to rank inside the invariant, never alone |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4 --catch-up` | Reference (cumulative): 171 flagged, tier D **6/6**, adds 3 accounts, 3 takeovers; no cohort newly over budget |

Time to detect is poor by construction: the first compromise is the attacker's login, days to weeks before the owner shows up and the invariant can fire. The scorer's time-to-detect line says so; the fix for this campaign is in the reset flow (revoke, and log it), not in the detector.

## Round 5: Session queue ⚔️ the ones that got away · `05_session_queue.ipynb`

By now five phishing-kit victims, most of the low-and-slow victims and a few others are unflagged. They share nothing, but each one **monetized**: inside a session on a browser the account only just started using, an `address_added` and an order to the new address. A per-session rule with a top-100 queue, judged on its delta.

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Sessionize the user's events. Candidate = a login, an `address_added` and an order with `ship_to_new_address` in one session, on a device first seen by this account at most 14 days earlier, on an account with at least `MIN_HISTORY` earlier events. Rank by order amount over the account's earlier median (+ a new-ASN bonus). Take the top 100 not already flagged. | The queue holds 19 accounts: 12 takeovers (5 phishing kit, 6 low and slow, 1 session replay), 7 honest accounts. Delta precision 63% |
| 🔴 Attack (the first mistake) | Require the device to be brand new *at the order session*. | Reaches 1 or 2 of the five kit victims: the kit spends its first session on a new cookie only reading cards and orders from the same cookie days later. The 14-day "young device" clause is what reaches them |
| 🔵 Re-run (the history trade) | `python solutions/round5_session_queue.py --min-history 10`, then `5`, then `3`. | 10: 15 queued, 10 takeovers, **3 of the 5 kit victims** (the thin accounts fall under the clause). **5 (reference): 19 queued, 12 takeovers, all 5.** 3: 21 queued, 13 takeovers, all 5 and one more thin low-and-slow victim, with one more honest account. Round 1's free clause now costs recall; the cost curve is flat below 5 |
| 🔴 Attack (the budget is cumulative) | Read the cohort table. | Every cohort's own delta is inside its budget (the most is 2 accounts), but `stuffing_target` goes from 17 of 17 to 19: Round 3's queue had already spent its allowance, so any further honest hit tips it over |
| ✅ Checkpoint | `python tools/checkpoint.py --round 5 --catch-up` | Reference (cumulative): 190 flagged, tier A 25/26, **tier B 45/46**, **tier C 17/18**, tier D 6/6, precision 49% |

**Discuss:** three victims are still missing after Round 5. What do they have in common, and what would the next attacker change?

## Reveal · `06_reveal.ipynb`

`python tools/checkpoint.py --reveal` (or `score.py suspects_r5.csv --reveal`), then `solutions/walkthrough.md`: each campaign's log signature, which method found it, which red herring it hid behind, and the six-victim pre-hijack campaign that is a sequence invariant, not an anomaly.

---

## Expected results (self-check)

Produced by `python tests/test_make_log.py --tiers` (which runs the five reference detectors and asserts the bounds below). The log is deterministic (seed 2026, same digest on Python 3.12+), so these numbers do not drift. 96 victims: 26 tier A, 46 tier B, 18 tier C, 6 tier D; 26 legitimate cohorts.

| Round (cumulative) | Tier A (26) | Tier B (46) | Tier C (18) | Tier D (6) | Flagged | Precision | Cohorts over 2% budget |
|---|---|---|---|---|---|---|---|
| 1 · rules | **24** | 0 | 0 | 0 | 29 | 83% | 0 |
| 2 · + graph | 25 | **36** | 0 | 0 | 68 | 90% | 0 |
| 3 · + model queue | 25 | 39 | **11** | 3 | 168 | 46% (p@100 75%) | 5, all inside the review queue |
| 4 · + invariant | 25 | 39 | 11 | **6** | 171 | 47% (delta 3/3, 100%) | 5, none newly over |
| 5 · + session queue | 25 | **45** | **17** | 6 | 190 | 49% (delta 12/19, 63%) | 6 (`stuffing_target` tips over: 17 of 17 becomes 19) |

| Campaign | Tier | Victims | R1 | R2 | R3 | R4 | R5 | What finds it |
|---|---|---|---|---|---|---|---|---|
| A1 datacenter stuffing | A | 14 | 14 | 14 | 14 | 14 | 14 | stuffed-then-entered (incl. 4 access-only), new context + high-risk |
| A2 reset abuse / MFA fatigue | A | 6 | 5 | 5 | 5 | 5 | 5 | MFA fatigue (3), reset from nowhere (2); one SMS victim with too little history for the clause |
| A3 impossible travel | A | 6 | 5 | 6 | 6 | 6 | 6 | impossible travel; the sixth via seed expansion (shares the kit's fingerprint) |
| B1 phishing kit | B | 20 | 0 | 12 | 15 | 15 | **20** | young thin components + seed expansion; the model adds 3; the session queue the last 5 |
| B2 session replay | B | 10 | 0 | 9 | 9 | 9 | 10 | one cookie-buyer device across victims; the session queue the tenth |
| B3 OAuth hijack | B | 8 | 0 | 7 | 7 | 7 | 7 | provider identity + device, after the same-person guard |
| B4 support ring | B | 8 | 0 | 8 | 8 | 8 | 8 | tickets opened from one browser profile |
| C1 low and slow | C | 18 | 0 | 0 | 11 | 11 | 17 | joint deviation from the account's own baseline; the session queue adds 6 |
| D pre-hijack | D | 6 | 0 | 0 | 3 | **6** | 6 | the invariant: user reset on a window-born account, no verified email before it |

Assertions in the test: R1 tier A ≥ 80%, tier B ≤ 25%, tier C ≤ 10%; R2 tier B ≥ 75%, tier C ≤ 15%; R3 tier C in [45%, 75%], precision@100 ≥ 25% and tier D ≤ 60%; R4 tier D ≥ 5/6, delta precision 100% and no cohort newly over budget; R5 reaches ≥ 4 of the 5 phishing-kit victims missed so far, delta precision ≥ 50% and no cohort over budget on its own delta; no cohort over budget in Rounds 1 and 2.

Three victims are still missing after Round 5: the SMS-swap victim with too little history for the Round 1 clause, an OAuth-hijack victim on an account born in the window that never ordered, and a dormant returner whose few earlier events sit under the history clause. Each is one clause short of a detector the earlier round already had.

Things to watch for:

- Teams that skip the known-history clause: ~180 flagged, three to six cohorts over budget. The fix is one line; the lesson is that the log has a start date.
- Teams that flag every stuffing target: 900 accounts, precision 2%. The failures are the attacker's; the account is still the owner's.
- Teams whose graph round returns the farm: it *is* a young, thin cluster. Ask what the accounts did before the shared fingerprint appeared.
- Teams whose Round 3 queue is all travellers and relocators: a single feature (country share) is doing the work. Ask for the joint.
- Teams that write the textbook invariant in Round 4 ("every reset must be followed by a revoke"): ~820 flagged. Count first; the log does not record the revoke the rule assumes.
- Teams whose Round 5 rule requires a brand-new device at the order session: 1 or 2 of the five kit victims. The kit reads cards in the first session and orders from the same cookie days later.
- Timing: `load_events()` ~10 s; Round 3's weekly features ~60 s; the reference rounds take 20 / 40 / 90 / 20 / 40 s.

---

## Bonus challenges

1. **Campaign D without the verified-email clause.** Round 4 gives you the invariant. Rebuild it from the surviving session alone (reset, then a `session_resume` on the creating device) and compare the cohorts it costs with `--p2`.
2. **Time to detect as the ranking.** Re-rank your Round 3 queue by first suspicious event. What does the ordering change for the owners?
3. **Temporal split.** Train the supervised model on days 1–60, evaluate on 61–90. Report what the in-sample number was hiding.
4. **Another seed.** `python tools/make_log.py --seed 7 --out-dir /tmp/other` regenerates the world with the same campaigns in different places; the key is written next to it. Do your rules still hold?
