# Chapter 9 Lab: Fair Drops

Starts from: `workshops/03-advanced/starter/` (contract 1.8). Adds: the raffle (`demo_site/ext/raffle.py`) and the cast of 110 fans and four crews (`demo_site/ext/raffle_world.py`), four allocation defenses (Rounds 1 to 4), Chapter 4's funnel as Round 0, six crews and the 110 fans recast for a raffle.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `data/reshippers.txt`
- `defenses/eligibility.py`
- `defenses/entity_resolution.py`
- `defenses/raffle_basics.py`
- `defenses/scalping_funnel.py`
- `defenses/weak_link_graph.py`
- `demo_site/ext/raffle.py`
- `demo_site/ext/raffle_world.py`
- `demo_site/ext/templates/raffle/page.html`
- `tools/personas_ch9.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** five rounds of defend 🔵 and attack 🔴, then a debrief. See `../chapter_09_content.md`. **Style: wire-it.** Each defense ships as a stub in `defenses/` with a `TODO (Round N)`; the finished version is in `solutions/roundN/`. `--catch-up` installs rounds 1..N (the check and `ladder.py`), and `--restore` puts your files back. Round 0 is finished: it is Chapter 4's funnel, copied byte for byte.

The spine of the chapter: **a raffle moves the decision from one request to the whole list of entries, and the defender's job is to make "one entry per person" true, without dropping the people who merely look like a farm.** You play defender against four crews that each buy a different thing (speed, tickets, a trusted history, a spread-out identity) and a fifth that buys nothing the data can see (a crowd of paid people). Each round you finish one check, run the crews that beat the previous step, and read two numbers side by side: the share of the 50 pairs that reached real fans, and the real fans each rule hurt.

This lab runs the **whole** Kestrel store; it is not a slice. The raffle is one ext (`raffle.py`) on top of the store's drop; the account, card and ship-to routes it uses are the starter's contract 1.8.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool imports `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service URLs such as `REDIS_URL` too). The store's edge accepts the lab headers only from loopback. Do not remove that check.
- **Everything is synthetic.** The 110 fans and the crews' kits come from `demo_site/ext/raffle_world.py`: invented names, emails on RFC 2606 domains (`example.com`, `*.example`; `gmail.example` plays Gmail), card numbers made of a synthetic prefix and hash digits, addresses on invented streets. The "package forwarders" in `data/reshippers.txt` are invented; none is a real business. No retailer, brand or product is a target here.
- Source addresses are rented from `data/world.json` (documentation ranges): `home_*` pools for the fans, `residential_proxy_net` for the crews that pay for a fleet, rotating on every request. No proxy, no real address, no third-party site.
- **Ground truth never reaches a defense.** Who is a fan and who is a crew is read only by `GET /lab/raffle/report`, which joins entries to the decision log the way the scoreboard does; no check sees it (`scripts/check_labs.py` rule 11).
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  demo_site/ext/raffle.py          the raffle: tables, routes, the draw, claim, expire and re-score, the
                                   otp_session challenge, the lab clock-free state machine (see the docstring)
  demo_site/ext/raffle_world.py    the cast: 110 fans in nine cohorts, four crews' kits (shared by the store,
                                   the personas and the attacks; a script reads only its own crew's kit)
  defenses/                        scalping_funnel (Round 0, finished) · raffle_basics · eligibility ·
                                   entity_resolution · weak_link_graph (your four stubs) · ladder.py (yours)
  solutions/round1..4/defenses/    the finished check and the ladder as it stands after each round
  attacks/                         round0_patient_farm · round1_account_farm · round2_aged_farm ·
                                   round3_jig_farm (--spread) · round4_crowd_entrants · _common.py
  tools/                           personas_ch9.py (the fans' scenarios) · checkpoint.py (ROUNDS, thresholds)
  data/reshippers.txt              the synthetic forwarder list Round 4 reads
  shared.json                      the one file this lab shares byte for byte with another (Chapter 4's funnel)
```

The rest of the store (catalogue, cart, checkout, the simulated edge, the decision log) is the W3 starter, unchanged. Its contract is `workshops/STORE_CONTRACT.md`.

**Round 0.** The W3 starter's baseline is empty, so this lab starts from Chapter 4's Round 2 check, `defenses/scalping_funnel.py` (a view before the buy, a second between view and buy, one attempt per device), wired at `LADDER[0]` and byte-identical to `../04-specialized-attack-scenarios/lab/solutions/round2/defenses/scalping_funnel.py` (`python scripts/lab_diff.py <lab> --shared` proves it). At level 0 the store sells the drop first come, first served; from level 1 it raffles it and refuses the first-come buy (`409 raffle_only`).

**How a round runs.** `tools/checkpoint.py` drives one whole event, so every round is the same sequence whatever your defenses decide:

```
reset -> open the event (seed the cast) -> [110 fans and the crews ENTER] -> draw -> [winners CLAIM]
      -> expire the unclaimed -> [promoted CLAIM] -> re-score -> [promoted CLAIM] -> re-score -> report
```

The draw, the claim waves, the expiry and the re-scores are lab routes (`/lab/raffle/{open,draw,expire,rescore}`, `GET /lab/raffle/report`; loopback only). The draw and the re-score are **batch phases**: the lab runs your checks once, with the whole list in `ctx.attrs["entries"]`, and your checks change the entries (`weight`, `excluded`, `cluster`, `verdict`). The decision log gets one row per call. A first-come round (level 0) has no draw. Verification (the email link) and the claim step-up code are simulated with the lab mailbox: the store's only outbox, `GET /lab/mailbox/<email>`.

---

## Setup

Work through `onboarding/setup/PREWORK.md` first. This lab needs nothing beyond the starter's packages:

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # one venv per chapter, see the root README
pip install -r requirements.txt                          # (or: uv venv -p 3.12 .venv && uv pip install -r requirements.txt)
python tools/doctor.py
python demo_site/app.py                                  # terminal 1: the store, on :5000 (seeds itself)
python tools/verify.py --smoke                           # terminal 2: the contract, as a test (optional)
```

Docker is optional: the default is SQLite plus an in-process Redis. To run the production-shaped stack (Redis 8.10 and PostgreSQL 18):

```bash
docker compose up -d --wait
REDIS_URL=redis://127.0.0.1:6379/0 DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop python demo_site/app.py
docker compose down -v                                   # when you are done
```

Round N runs at `DEFENSE_LEVEL` N and each level includes every level below it; the checkpoint changes the level live (`POST /lab/level`), so the store never restarts between rounds. You finish a stub, wire it in `defenses/ladder.py`, save (the store reloads `defenses/` on the next request), and measure:

```bash
python tools/checkpoint.py --round 1                    # your code
python tools/checkpoint.py --round 1 --catch-up         # the reference solutions for rounds 1..1 (your files kept as .bak)
python tools/checkpoint.py --restore                    # put your own files back
python tools/checkpoint.py --round 1 --level 0          # the round's crews against the PREVIOUS level (the "before")
python tools/checkpoint.py --all --markdown             # every round (the expected-results table below)
```

(`python tools/verify.py --round N` does the same against a store it starts in-process on a free port, which is how the numbers below were produced. The harness runs the store and about 170 client threads in one process, so a round takes a minute or two and every request waits its turn; the per-request gate time it prints includes that queueing, and only the batch phases are judged.)

| Level | Round | Adds | Module you finish |
|---|---|---|---|
| 0 | 0 | First come, first served behind Chapter 4's funnel | – (`scalping_funnel.py`, finished, shared) |
| 1 | 1 | A raffle: guests out, one entry per account, one ticket each | `defenses/raffle_basics.py` |
| 2 | 2 | A verified email at entry, trust-weighted tickets at the draw | `defenses/eligibility.py` |
| 3 | 3 | Normalize, link, one entry per cluster | `defenses/entity_resolution.py` |
| 4 | 4 | An evidence graph, a claim step-up and holds, a re-score and a redraw | `defenses/weak_link_graph.py` |

Each check scores on the starter's 0 to 100 scale (`defenses/policy.py`): 40 and up is a `challenge`, 75 and up a `block`. The batch checks do not return a verdict; they change the entries. The one challenge with a solver is `otp_session` (the lab mailbox); any other challenge band score is **enforced as a block**.

> Every response carries `X-Lab-Verdict`, `X-Lab-Score` and `X-Lab-Signals` (for example `eligibility:unverified_email`). That is for teaching only: here it stands in for the page telling a fan to verify their email. In production, never tell a client which rule caught it.

## The people

Every round runs the same 110 fans (`tools/personas_ch9.py`) next to the crews:

| Cohort | n | Why they are here | Where they pay |
|---|---|---|---|
| `loyal` | 52 | the easy majority: aged, orders, a card, an address | nowhere: they must never be hurt |
| `household` | 9 | three households of three people: one address, three accounts, three cards | Round 3: one entry per household |
| `apartment` | 5 | five strangers in 10 Harbour Street, five unit numbers | Round 3: merged with each other |
| `shared_card` | 4 | two couples who each pay with one card at two addresses | Round 3: merged by the card |
| `new_real_fan` | 12 | accounts 1 to 5 days old; two never verified their email | Round 2: a quarter ticket; two follow the mail's link |
| `power_user` | 8 | aged, six to twelve orders | nowhere |
| `gift_buyer` | 6 | the pair ships to someone else's door | Round 4: held for review |
| `traveller` | 6 | consumer-VPN and privacy-relay addresses | nowhere: no check here reads the IP |
| `no_saved_card` | 8 | no card on file: they add one when they win | Round 4: a code at the claim |

**Hurt** means a fan ended excluded by a rule, merged away with another person, or with a win that never became a pair. **Lost** (not selected) is a fair loss, not harm. **Stepped up** means the fan followed a verification link or entered a claim code: friction. **Held** is a claim waiting in review; the re-score releases it. The crews are labelled `bot:<crew>` for the scoreboard; the paid `crowd` is real people and counts as a bot only because the scoreboard counts who the reseller gets.

---

## Round 0: 🔵 first come, first served ⚔️ 🔴 a patient farm (`DEFENSE_LEVEL=0`)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round0_patient_farm.py` (60 accounts registered ahead, one device cookie each, the drop page viewed, then every buy at the opening second) | the farm buys 43 to 46 of the 50 pairs in the runs we made, because the opening second is a race |
| 🔵 Defend | nothing to write: Chapter 4's funnel is wired at `LADDER[0]` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 0` | the farm holds 20 to 50 pairs · fans hold at most 60% · **fan odds against a fair lottery well under 1** |

The funnel did what it says: nobody skipped the page, nobody clicked faster than a second, nobody used a device twice. What it counts is the problem. A first-come sale makes speed and parallelism the scarce resource, and the crew has both.

## Round 1: 🔵 a raffle ⚔️ 🔴 two hundred fresh accounts (`DEFENSE_LEVEL=1`)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round1_account_farm.py` (200 accounts, registered and verified on the spot, one drop address, a virtual card each; each tries to enter twice) | before (level 0, first come): the same crew **stages and buys**, 45 to 48 pairs · after the raffle, unwired: 400 entries from 200 accounts |
| 🔵 Defend | Finish `defenses/raffle_basics.py` (guest → block, a second entry from one account → block, every ticket weight 1.0), wire `1: [raffle_basics.CHECK]` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | 200 entries refused (the second try) · the crew holds about **34 of 50**, its share of the tickets · fans hold 32% |

**Discuss:** the raffle took the speed away and left the numbers. Entries per identity is 2.8: one crew holds 200 of 310 tickets.

## Round 2: 🔵 eligibility ⚔️ 🔴 bought aged accounts (`DEFENSE_LEVEL=2`)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round1_account_farm.py` (again) and `python attacks/round2_aged_farm.py` (100 bought accounts: aged, verified, one old paid order, every pair to one drop address) | before (level 1): the fresh farm 25, the aged farm 6 |
| 🔵 Defend | Finish `defenses/eligibility.py` (an unverified email → block at entry; at the draw an unverified entry is excluded and a new account with no order weighs 0.25), wire `2: [eligibility.CHECK]` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | the fresh farm falls to **11** · the aged farm rises to **13** (it is the survivor) · **2 new fans stepped up** (the unverified ones) · fans hold 52% |

**False-positive check:** the twelve genuinely new fans have a quarter of everyone's odds. And the crew that buys accounts is not stopped, only priced.

## Round 3: 🔵 entity resolution ⚔️ 🔴 jigged addresses and virtual cards (`DEFENSE_LEVEL=3`)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round2_aged_farm.py` and `python attacks/round3_jig_farm.py` (80 aged accounts, one building written 80 ways, five mailboxes written 80 ways, virtual cards from one BIN) | before (level 2): aged 16, jig 19 |
| 🔵 Defend | Finish `defenses/entity_resolution.py` (fold the email, split the address into building and unit, link on a shared email, building or card, one entry per cluster), wire `3: [entity_resolution.CHECK]` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | aged **1** · jig **1** · fans hold 96% · fan odds 0.98 · **12 fans hurt: apartment 4, household 6, shared_card 2** |

**False-positive check:** the twelve are real people. The rule that collapsed 180 crew entries into two also collapsed four neighbours, six family members and two spouses. Say which you would ship.

## Round 4: 🔵 an evidence graph, claim holds and a re-score ⚔️ 🔴 a spread-out crew and a paid crowd (`DEFENSE_LEVEL=4`)

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round3_jig_farm.py` (again), `python attacks/round3_jig_farm.py --spread` (48 aged accounts from one creation batch, distinct clean addresses, slow entries; the pairs that win go to forwarders) and `python attacks/round4_crowd_entrants.py` (24 paid people, each with their own account, card and home) | before (level 3): jig 1, spread **13**, crowd 8 · 12 fans hurt |
| 🔵 Defend | Finish `defenses/weak_link_graph.py` (points per pair, merge at 100; at the claim a code for a card that is not the entry's, a hold for a forwarder or a new ship-to; at the re-score cancel convergent forwarder claims, burn their BINs, release the rest), wire `4: [weak_link_graph.CHECK]` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | jig **0** (the graph merges it) · spread **0** (19 cancelled at the re-score, 29 waitlist entries burned) · crowd **6** · **0 fans hurt** · 6 stepped up (2 verifications, 4 claim codes) · 1 gift held, then released |

**The honest residual:** the crowd holds about its share of the entries (6 of 50) with every control in place, and its entries per identity is 1.0.

## Wrap-up: the cross-round debrief

`python tools/checkpoint.py --all --markdown` prints every round's scoreboard. The arc is the point: a first-come sale rewards speed, a raffle rewards tickets, trust weights price accounts, a single-link merge collapses the crews and 12 real fans with them, and an evidence graph keeps the fans while the claim and the re-score close the gap the graph leaves on purpose. What is left, the crowd, is intent, which no allocation rule sees.

## Expected results (self-check)

<!-- results:start -->
Generated by `python tools/verify.py --write-readme --catch-up` (every round judged with the reference solutions installed, each followed by its `--level N-1` "before" run; against your own store: `python tools/checkpoint.py --all --markdown`).

| Round | Attack | Before (level N-1) | After (level N) | Shoppers stopped after |
|---|---|---|---|---|
| 0 | `patient_farm` | — | 46/60 | none |
| 1 | `account_farm` | 48/200 | 34/200 | none |
| 2 | `account_farm` | 25/200 | 11/200 | none |
|  | `aged_farm` | 6/100 | 13/100 |  |
| 3 | `aged_farm` | 16/100 | 1/100 | apartment 4, household 6, shared_card 2 |
|  | `jig_farm` | 19/80 | 1/80 |  |
| 4 | `jig_farm` | 1/80 | 0/80 | none |
|  | `spread_farm` | 13/48 | 0/48 |  |
|  | `crowd` | 8/24 | 6/24 |  |
<!-- results:end -->

## Troubleshooting

| Problem | Fix |
|---|---|
| Port 5000 taken (macOS AirPlay Receiver) | `PORT=5050 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:5050` in the shells that run tools |
| A round says `account_farm: got 34, expected ...` or fans hurt where there should be none | Your stub is not finished, or not wired in `defenses/ladder.py`. Finish the `TODO`, or `python tools/checkpoint.py --round N --catch-up` |
| Round 0 numbers move from run to run | They are a race for the opening second (the checkpoint allows the whole range it measured). Rounds 1 to 4 are seeded and repeat exactly |
| `409 raffle_only` from `/api/buy` | At level 1 and up the drop is a raffle; enter at `/api/raffle/lab-runner-9/enter` |
| An entry is refused with `eligibility:unverified_email` | Follow the `verify_url` in `GET /lab/mailbox/<email>`, then enter again |
| `ModuleNotFoundError: demo_site` | Run scripts from `lab/` (`python attacks/...`), not from inside `attacks/` |
| Want a clean slate | Stop the store, delete `instance/`, start it again |
| Port 5432 or 6379 taken (another lab's containers) | `docker compose ls`, then `docker compose -p <name> down` |
