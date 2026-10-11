# W3 Ch7 Lab — Investigating Account Takeover in Audit Logs

**Format:** Round 0 explore + three detection rounds + reveal, 110 min, plus a 15 min debrief. See `../chapter_07_content.md`, §7.4.

This chapter's attacker is not a script you run. It already ran: eight account-takeover campaigns are buried in 90 days of a store's account audit log, next to every legitimate behaviour that looks like one. Each round is still a 🔵 defense (a detection family you build in a notebook), a 🔴 attack (the tier of campaigns built to evade the previous round's family), a checkpoint and a number. The answer key stays sealed until the reveal; the scorer tells you how you are doing without telling you why.

## Rules of engagement

Nothing in this lab touches a network. Every address is non-routable (198.18.0.0/15 benchmark space for residential, mobile and datacenter pools; 100.64.0.0/10 for carrier NAT; the RFC 5737 /24s for VPN, Tor and hosting; 2001:db8::/32 for IPv6), every ASN is private (RFC 6996), and every account, agent, device and city centroid is invented. The companies named in the data do not exist.

```
lab/
  requirements.txt       pandas, numpy, scikit-learn, networkx, matplotlib, jupyterlab. Python 3.10+. One venv per chapter.
  data/                  account_activity.jsonl.gz is GENERATED (python tools/make_log.py, ~1 min, ~24 MB) and gitignored.
                         world.json (the simulated internet), sample.jsonl (the first 2,000 events, for a look at the schema)
  notebooks/             00_explore · 01_rules · 02_graph · 03_ml · 04_reveal  (one per round; each starts from the previous round's suspects)
  tools/                 make_log (generator) · atolab (helpers) · score (the checkpoint) · checkpoint (reference rounds, catch-up) · doctor
  solutions/             answer_key.json · round1_rules.py · round2_graph.py · round3_anomaly.py · checkpoints/suspects_r{1,2,3}.csv · walkthrough.md
  tests/                 test_make_log.py: golden digest (determinism) and the tier-integrity assertions the README table rests on
```

**Why a notebook and no server:** the chapter is about the *analysis* over a log the W2 Ch6 login pipeline and the W3 Ch3 stream already produced, not about producing it. A generated log lets everyone investigate the same 335,000 events, makes the scoreboard reproducible, and keeps a 3-hour chapter off server setup. `tools/make_log.py` regenerates it byte for byte from seed 2026 on any Python 3.10+.

---

## Setup (before the session, 5 minutes plus a 1-minute generation)

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

which prints the series' three numbers:

- **Attacker success:** confirmed takeovers found per campaign (shown as `campaign A-1 … C-8` until the reveal), per tier, and per compromise level (`access_only` / `persisted` / `monetized`).
- **Real users hurt:** accounts flagged per legitimate cohort against a budget of 2% (or one account), worst first, with each red-herring cohort's one-line story. Rounds 1 and 2 are block-grade findings and must stay within budget. Round 3 is a review queue: a queue entry is friction, not an action, so it is judged on precision at 25/50/100.
- **Defender cost:** precision, precision at the queue sizes an analyst can open, and analyst-hours at five minutes a review.

Names, misses and the red herrings' stories appear with `--reveal`. **Fell behind?** `python tools/checkpoint.py --round N --catch-up` runs the reference detector for round N and writes its suspects to `lab/suspects_rN.csv` so the next notebook can start from it.

---

## Round 0: Explore (25 min) · `notebooks/00_explore.ipynb`

Load the log, look at the event mix, the share of `session_resume` logins, a few account timelines. Find the four data-quality traps before anyone names them: duplicate lines, retries, late arrivals and clock skew, and one address block that changes country for three days. Write three hypotheses with numbers in them. Nothing to submit.

## Round 1: Rules ⚔️ tier A (30 min) · `01_rules.ipynb`

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Write five rules: impossible travel · new context + high-risk change · stuffed then entered · MFA fatigue · reset from nowhere. Each needs a **known-history clause** (novelty is relative to history the log contains). | A first draft without the clause flags ~180 accounts and puts email migrants, password-manager migrants and dormant returners far over budget |
| 🔴 Attack | Score it. The campaigns that stay at 0/N are the ones built to beat per-account rules: no high-risk change, correct credentials, a shared identity, a complicit agent. | Tier A found, tier B and C at or near zero |
| 🔵 Re-run | Add the clause; try `MIN_HISTORY` of 3 and 10. Then the exercise: widen the target set to medium-risk events (`address_added`, `payment_method_added`, `order_placed`). | Reference: 29 flagged, tier A 24/26, tier B 0/46, tier C 0/18, precision 83%, 0 cohorts over budget. Wide: a few phishing-kit victims, and new-phone upgraders and gift buyers over budget |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1 --catch-up` | the reference `suspects_r1.csv` |

**Discuss:** the only rule that found access-only takeovers is "failure from datacenter space, then a password login from datacenter space". What in the login pipeline (W2 Ch6) would have made the log unnecessary for them?

## ☕ Break (10 min)

## Round 2: Graph ⚔️ tier B (30 min) · `02_graph.ipynb`

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack (look) | Build the account–identifier graph on `ja4` and `ip` and read the largest components. | A 4,000-account component (the top Chrome JA4), carrier NAT hubs of hundreds, the VPN exit, the QA team's shared browser |
| 🔵 Defend | **Seed expansion** from your Round 1 accounts: identifiers that first appeared on them at or after the compromise, from *user* events, seen on at most a dozen accounts. Then **young, thin components** on `device_id`, `fp_hash`, `provider_sub_hash`: 2–12 accounts per identifier, every edge first seen on or after day 25, few events per edge, and no old thick identifier shared by the same accounts. | Expansion: ~35 accounts. Components: ~11 of 2–8 accounts, ~16 of which are a fake-account cluster (no history before the shared id): abuse, not takeover, kept out |
| 🔴 Attack (why it is hard) | Drop any guard and re-score: without the user-actor guard, the store's own policy engine links all 295 force-reset accounts; without the same-person guard, duplicate-account owners go over budget; with a degree threshold instead of components, the kit (cookie rotated every 4–6 victims) is missed or households are flagged. | Each guard is worth a cohort |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2 --catch-up` | Reference (cumulative): 68 flagged, tier A 25/26, **tier B 36/46**, tier C 0/18, precision 90%, 0 cohorts over budget |

**Discuss:** one tier is still at zero and its victims share nothing with each other. What is left to compare them against?

## Round 3: Models ⚔️ tier C (25 min) · `03_ml.ipynb`

| Step | Do | Expected |
|---|---|---|
| 🔵 Defend | Weekly `window_features()` (14-day windows, leak-free, successful events only for every behavioural feature), an IsolationForest on the deviation features, each account's worst week, a top-100 queue of accounts Round 2 did not contain. | Reference (cumulative): 168 flagged, tier A 25/26, tier B 39/46, **tier C 12/18**, precision at 100 of the ranked list 72% |
| 🔴 Attack (the queue's cost) | Read the queue's composition: travellers, relocators, the MFA-migration batch, forced resets. Each is a single feature doing honest work on the wrong person. | 6 cohorts "over budget" in a 100-account review queue; that is what review is for |
| 🔵 Contrast | Train the supervised model on Rounds 1+2 and submit its queue instead. | More tier A and B, almost no tier C: a model trained on your detections finds your detections |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3 --catch-up` | the reference `suspects_r3.csv` |

## Reveal (15 min) · `04_reveal.ipynb`

`python tools/checkpoint.py --reveal` (or `score.py suspects_r3.csv --reveal`), then `solutions/walkthrough.md`: each campaign's log signature, which method found it, which red herring it hid behind, and the six-victim bonus campaign (pre-hijack) that is a sequence invariant, not an anomaly.

---

## Instructor: expected results

Produced by `python tests/test_make_log.py --tiers` (which runs the three reference detectors and asserts the bounds below). The log is deterministic (seed 2026, same digest on Python 3.10 and 3.12), so these numbers do not drift.

| Round (cumulative) | Tier A (26) | Tier B (46) | Tier C (18) | Flagged | Precision | Cohorts over 2% budget |
|---|---|---|---|---|---|---|
| 1 · rules | **24** | 0 | 0 | 29 | 83% | 0 |
| 2 · + graph | 25 | **36** | 0 | 68 | 90% | 0 |
| 3 · + model queue | 25 | 39 | **12** | 168 | 45% (p@100 72%) | 6, all inside the review queue |

| Campaign | Tier | Victims | R1 | R2 | R3 | What finds it |
|---|---|---|---|---|---|---|
| A1 datacenter stuffing | A | 14 | 14 | 14 | 14 | stuffed-then-entered (incl. 4 access-only), new context + high-risk |
| A2 reset abuse / MFA fatigue | A | 6 | 5 | 5 | 5 | MFA fatigue (3), reset from nowhere (2); one SMS victim with too little history for the clause |
| A3 impossible travel | A | 6 | 5 | 6 | 6 | impossible travel; the sixth via seed expansion (shares the kit's fingerprint) |
| B1 phishing kit | B | 20 | 0 | 12 | 15 | young thin components + seed expansion; the model adds 3 |
| B2 session replay | B | 10 | 0 | 9 | 9 | one cookie-buyer device across victims |
| B3 OAuth hijack | B | 8 | 0 | 7 | 7 | provider identity + device, after the same-person guard |
| B4 support ring | B | 8 | 0 | 8 | 8 | tickets opened from one browser profile |
| C1 low and slow | C | 18 | 0 | 0 | 12 | joint deviation from the account's own baseline |
| D pre-hijack (bonus, unscored) | – | 6 | 0 | 0 | 3 | the sequence invariant "reset must revoke sessions" |

Assertions in the test: R1 tier A ≥ 80%, tier B ≤ 25%, tier C ≤ 10%; R2 tier B ≥ 75%, tier C ≤ 15%; R3 tier C in [45%, 75%] and precision@100 ≥ 25%; no cohort over budget in Rounds 1 and 2.

Things to watch for:

- Teams that skip the known-history clause: ~180 flagged, three to six cohorts over budget. The fix is one line; the lesson is that the log has a start date.
- Teams that flag every stuffing target: 900 accounts, precision 2%. The failures are the attacker's; the account is still the owner's.
- Teams whose graph round returns the farm: it *is* a young, thin cluster. Ask what the accounts did before the shared fingerprint appeared.
- Teams whose Round 3 queue is all travellers and relocators: a single feature (country share) is doing the work. Ask for the joint.
- Timing: `load_events()` ~10 s; Round 3's weekly features ~60 s; the reference rounds take 20 / 40 / 90 s.

---

## Bonus challenges

1. **Campaign D.** Six accounts were created by the attacker with the victim's email (`email_verification_sent`, never `email_verified`), later "recovered" by the real person with a reset that revoked no sessions. Write the invariant as a rule and submit it: the scorer reports the bonus line.
2. **Time to detect as the ranking.** Re-rank your Round 3 queue by first suspicious event. What does the ordering change for the owners?
3. **Temporal split.** Train the supervised model on days 1–60, evaluate on 61–90. Report what the in-sample number was hiding.
4. **Another seed.** `python tools/make_log.py --seed 7 --out-dir /tmp/other` regenerates the world with the same campaigns in different places; the key is written next to it. Do your rules still hold?
