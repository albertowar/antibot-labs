# W4 Ch6 Lab: Trailmates — Finding the Crews in a Community's Log

Starts from: no store. This is an analyst-side lab with no `demo_site/`, no server and no `attacks/`. A deterministic generator writes the log, and you work in notebooks.

**Format:** Round 0 explore, four defense rounds, reveal. See `../chapter_06_content.md`, §6.6.
**Lab style:** analyst notebooks. The reference detectors in `solutions/` are complete. Catching up installs their output as your round file.

Trailmates is Kestrel Outfitters' hobby community. Members message each other about trips, sell used gear on a swap board, and pay through the community wallet. You are its trust-and-safety team, and you have ninety days of its records. Four crews are working members for money in them. **The lab is defense only.** You never run, write or read a scam. The crews exist as the traces their operations leave: accounts, message metadata, payments and reports. Each round is still a 🔵 defense, followed by a 🔴 campaign tier built to slip past the previous round's detector family. Each round also has a checkpoint and a number.

## Rules of engagement

- **No network.** Nothing in this lab opens a socket. **Outbound network: none.** That includes no model API and no lookups.
- **No message text, by design.** A message is a row of metadata: sender, recipient, time, a length bucket, and flags for a link, a payout reference or an "add me on another app" handle. It also carries a structure hash. The generator cannot produce message text, and no file in this lab contains a lure, a script or a persona. The chapter teaches how scam operations are built at block-diagram level only (§6.3). The lab measures what a defender would measure.
- **Everything is synthetic.** Every member, device, photo hash and payout handle is invented. Every address is non-routable: 198.18.0.0/15 residential, 100.64.0.0/10 mobile, 203.0.113.0/24 hosting and 198.51.100.0/24 VPN. Every ASN is private (RFC 6996). Every domain ends in `.example`.
- **Round 3's outcomes are simulated.** Each scam payment carries a sealed coin flip for whether a warning, or a hold, would have stopped it. The money "prevented" is measured in this simulation, not in the field.

```
lab/
  requirements.txt     pandas, numpy, networkx, matplotlib, jupyterlab (notebooks only). Python 3.12+. One venv per chapter.
  data/                world.json and sample_dm_events.jsonl are committed; the rest is GENERATED (~15 s, ~12 MB) and gitignored
  notebooks/           00_explore · 01_profile · 02_shape · 03_interventions · 04_network · 05_reveal
  tools/               make_trailmates (generator) · trailmates (loaders, features) · score (the scorer) · checkpoint (PASS/FAIL, catch-up)
  solutions/           answer_key.json (sealed) · round1_profile · round2_shape · round3_interventions · round4_network · walkthrough.md
  tests/               test_make_trailmates.py: golden digest (determinism) and the tier and trap assertions this README rests on
  out/                 your round files (suspects_r1/r2/r4.csv, actions_r3.csv) and out/reference/ (gitignored)
```

**Why notebooks and no server.** The chapter's question is what a platform can see and what each control costs. It does not ask how to stand up a community site. A generated log lets everyone investigate the same 217,000 message events and makes the scoreboard reproducible. The generator, scorer, checkpoint and reference detectors use only the standard library, and `tools/make_trailmates.py` regenerates the log byte for byte on any Python 3.12+.

## Setup

```bash
cd workshops/04-ai-era-bots/chapters/06-ai-social-engineering/lab
python -m venv .venv && source .venv/bin/activate      # one venv per chapter (Windows: .venv\Scripts\activate)
pip install -r requirements.txt
python tools/make_trailmates.py                         # ~15 s: writes data/ and checks it against the sealed key
python tests/test_make_trailmates.py                    # determinism: your data matches everyone else's
jupyter lab notebooks/
```

This lab needs nothing beyond the toolchain in `onboarding/setup/PREWORK.md`. It needs no Docker, no browser and no model.

## The data

| File | One row per | Columns you will use |
|---|---|---|
| `members.jsonl` | member | `joined_at`, `signup_asn` (kind in `world.json`), `device_id`, `photo`, `declared_region`, `login_regions` |
| `dm_events.jsonl.gz` | message | `ts`, `thread`, `sender`, `recipient`, `first_contact`, `len`, `link`, `payout_ref`, `offplatform`, `translated`, `shape` |
| `payments.jsonl` | wallet payment | `payer`, `payee`, `amount`, and what the platform knew at that moment: `first_to_payee`, `payee_age_days`, `offplatform_contact`, `offplatform_contact_days`, `offplatform_contact_msgs`, `payee_is_offplatform_contact` |
| `reports.jsonl` | member report | `reporter`, `reported`, `reason` |
| `partner_intel.json` | indicator | payout handles and domains a partner bank's customers complained about (a lead, not a verdict) |

`tools/trailmates.py` computes the per-member features every round uses (`member_features()`) and loads everything as pandas DataFrames (`frames()`).

## Rounds

| Round | 🔴 In the data | Why it slips past the previous round | 🔵 You build | Checkpoint passes when |
|---|---|---|---|---|
| 0 | four crews and nine genuine cohorts | — | nothing; explore and form hunches | — |
| 1 | **A, the farm:** new accounts, reused photos, hosting or VPN egress, bursts of templated first contacts | there is no earlier round | account and profile rules | tier A ≥ 80%, no cohort over budget, ≤ 5% of members flagged |
| 2 | **B, the LLM crew:** bought aged accounts, unique photos and wording, translated, one shift of operators, many threads moved to another app within days | nothing about the account is new or reused | conversation-shape rules (cumulative) | tier B ≥ 75% as well |
| 3 | **C, the closer:** few targets, human pace and hours, an early move to another app, then high-value payment chains | too few conversations to have a shape | warn or hold at the payment moment | ≥ 60% of scam money prevented (simulated), holds ≤ 2% and warnings ≤ 10% of each payer cohort's genuine payments |
| 4 | **D, the dispersed crew:** one or two targets per account, ordinary hours, half never post a link | no single account looks wrong | reports, partner intel, clustering on devices and money (cumulative) | tier D ≥ 75%, overall recall ≥ 85%, precision@25 ≥ 90% |

Each round, from its notebook:

```bash
python tools/checkpoint.py --round 1            # judges out/suspects_r1.csv (Round 3 judges out/actions_r3.csv)
python tools/checkpoint.py --round 2 --catch-up # behind? installs the reference results for rounds 1..2 as your files (.bak kept)
python tools/checkpoint.py --restore            # put your own files back
python tools/checkpoint.py --round 4 --reference  # judge the reference detector instead of your file
```

**Scoring.**
- **Recall per campaign and tier.** This is how you see each round catch one tier and miss the next.
- **False positives per cohort.** Each cohort has a 2% budget, at least one person. Victims are members too, so flagging a victim counts.
- **precision@k.** This is the queue an analyst works top-down, at about 5 minutes per account.
- **Round 3's money prevented against genuine friction.** It is counted per payer cohort and is simulated.

`python tools/score.py <file> --reveal` names the campaigns you missed, and says why every cohort you touched was a trap.

## Expected results (self-check)

Generated by `python tools/checkpoint.py --all --write-readme` from the reference detectors (seed 2026, full scale):

<!-- results:start -->
| Round | You add | Tier A | Tier B | Tier C | Tier D | Flagged | Over budget | Also |
|---|---|---|---|---|---|---|---|---|
| 1 | account and profile rules | 75/75 | 0/36 | 0/12 | 0/30 | 78 (3 genuine) | none | precision@25 100% |
| 2 | conversation shape | 75/75 | 35/36 | 0/12 | 0/30 | 114 (4 genuine) | none | precision@25 100% |
| 3 | interventions at the payment moment | 50% | 83% | 88% | 43% | 7 held, 30 warned | none | scam money prevented 83% (simulated) |
| 4 | reports, partner intel, clustering | 75/75 | 36/36 | 12/12 | 30/30 | 159 (6 genuine) | none | precision@25 100% |

Round 3's tier columns are the share of each tier's scam money a hold or warning stopped. The genuine members each round touched, against their cohort's budget (the honest cost):

- Round 1: newcomer 3 of 5
- Round 2: guide 1 of 1; newcomer 3 of 5
- Round 3: long_distance_couple 3 held of 3; newcomer 2 held of 6; regular 2 held of 69; newcomer 30 warned of 34
- Round 4: guide 1 of 1; newcomer 3 of 5; seller 2 of 2
<!-- results:end -->

**The honest costs, named.** Each one below is within budget and is a cost of the round, not a failure:
- **Round 1.** Newcomers who signed up on the festival's cloud-hosted Wi-Fi. They are new, they burst, and their egress is hosting.
- **Round 2.** The guide who runs the summer trip's group chat on another app and invites people from announcements sent in office hours.
- **Round 3, holds.** Three long-distance couples who met this summer. Their first gift looks like a scam's first payment. Also held: two buyers who chatted with a seller for weeks, and were asked to text, before their first purchase. So were two newcomers whose festival friend asked them to switch apps, just before they moved money to their own new bank handle.
- **Round 3, warnings.** Newcomers moving festival-sale money to their own new bank handle. One field, knowing that the handle is the payer's own, would remove that friction.
- **Round 4.** The seller with two dispute reports and the seller whose handle a bank listed after a chargeback.

## Things to watch for

- **Scoring the pieces.** Score each piece of a rule on its own before you combine them, and read which cohort it hurts.
- **Photo reuse.** Shared default avatars are not photo reuse.
- **Translation.** It is how non-native members talk, and it is never a signal on its own.
- **Off-platform moves.** "Text me" from a seller within a day of the first message is commerce. The scam shape is a bonded contact, days in.
- **Clustering.** A cluster around no seed is a household, not a crew. A cluster bigger than any crew is an association chain gone wrong.
- **Intel.** It is a lead, not a verdict. Read the bank's note on every indicator.

## Troubleshooting

- **`WARNING: data/ does not match the answer key`.** Re-run `python tools/make_trailmates.py`. Do not edit the files in `data/`, and do not regenerate with `--scale`, which writes only to another `--out-dir`.
- **A notebook says `out/suspects_r1.csv does not exist yet`.** Run the previous round's notebook, or `--catch-up`.
- **Checking the tiers yourself.** `python tests/test_make_trailmates.py --tiers` re-proves every claim in the table above.
