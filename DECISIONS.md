# Antibot Workshop Labs: Decisions

Settled maintainer choices for the labs, the starters and the store contract. Each line records a
decision that was made on purpose and the reason it holds. **Follow them; do not reopen the
question.** This is not a backlog: open work lives in `TODO.md`, which lists only what is still
wrong. When a `TODO.md` item is closed by a deliberate choice rather than by being fixed, the choice
moves here and a one-line pointer to this file is left on whatever still references it.

Decisions about the curriculum, the chapter docs, the decks and the industry-figure ledger live in
the slides repo's `DECISIONS.md` (`~/github/antibot-workshop-slides`). The per-gap history behind
the migration decisions is in that repo's git: the pre-closure `TODO.md` is
`git show c624e58e^:TODO.md` there (it still carries §1.2, the per-migration contract-gap lists).

## Two repos

**Decision** (2026-10-26): **the labs live in their own repo, the docs and decks in the slides repo,
and both keep the same chapter paths.** `workshops/<NN>/chapters/<slug>/` holds `lab/` here and
`chapter_NN_content.md` + `slides.md` there; the starters, the contract and the lab scripts moved
here with their history (`git filter-repo`), the slides repo kept its history unrewritten. Why: the
labs were 29 of the 38 MB tracked and 213 of the 224 MB packed, and every search across the 39
store copies drowned doc work; the docs and decks stay together because the lesson cut
(`check_lessons.py`) and the review books both read the content doc. What crosses the seam, and
how, is in `AGENTS.md` → "The slides repo, and what crosses between the two": repo-rooted paths
plus "(slides repo)", one shared `check_links.py` that resolves against `ANTIBOT_SIBLING_ROOT`,
and the slides repo's `table_of_contents.md` staying the single status tracker (its Lab column is
the one cross-repo chore). The student `PREWORK.md` moved here because it is the lab setup; the
onboarding decks that narrate it stayed with the theme. A three-way split (docs, decks, labs) was
assessed and declined.

## Starters and lab migration

The store migration is complete: every lab that ships a store runs its workshop's starter, and
§1.2 (the per-migration contract-gap lists) closed with contract **1.7** (2026-10-16). The
behaviour changes and additions are the 1.7 changelog in `workshops/STORE_CONTRACT.md`; the
workarounds that stayed by choice are below.

**Decision** (2026-10-12): the W2, W3 and W4 starters are the skeleton with an **empty baseline**
(`workshops/<NN>/starter.manifest.json`, built by `scripts/build_starter.py --workshop N`), not the
previous capstone's end state. A chapter that needs an earlier control at its Round 0 (W2 Ch1,
W3 Ch1/Ch4/Ch10, W4 Ch4 and the capstones assume W1's header rules or rate limit) adds it in its
own lab.

**Decision** (2026-10-16, closing the former §1.2): contract 1.7 shipped the behaviour changes and
additions the migrations needed (`STORE_CONTRACT.md` changelog). The gaps below stayed as lab-side
workarounds by decision — the per-gap detail is in the slides repo's `git show c624e58e^:TODO.md`.

- **Teaches the gap** — the gap *is* the chapter's lesson, so the contract keeps it: W2 Ch3's claimed-vs-measured HTTP/2 and loopback-edge trust (Bonus 2), W2 Ch6's OTP/recovery routes and typeless-challenge-as-block, W2 Ch7's `BANDS["challenge"]` tuning, W4 Ch3's Python-shopper decoy blind spot, and W4 Ch4's pre-write checkout `block` (2026-10-18: kept as the teaching shape through the 1.7 re-base; 1.7's held orders are discussed in the chapter's §4.5 as the post-write alternative, not used).
- **Single consumer** — one lab needs it, so an ext or wrapper is simpler than a new contract surface; revisit on a second consumer: W4 Ch2's post-ladder finalizer (the `LADDER[0]` orchestrator is the teaching shape), W4 Ch3's `Verdict(response=…)` (only the maze/paywall ext and its Ch9 copy), W4 Ch4's per-page telemetry accumulation (~10 lab-side lines).
- **Lab-owned** — belongs in the lab, not the skeleton: the capstones re-point the finished checks' surface in a glue module (W1 Ch9, W2 Ch9, W3 Ch12), and W3 Ch12 keeps its layer-name tags for the debrief.
- **Layering / cost** — W4 Ch1 reads `robots.txt` through its own mirror and fetches assets in a `PAGE_HOOK`, rather than make every lab's shoppers pull stylesheets and images.
- **Documented pattern** — the workaround is now a named convention: side services start from the ext thread and a per-lab `tools/doctor_<ch>.py` preflights binaries (`STORE_CONTRACT.md` §4.2/§5); `defenses/reloader.py` reloads flat modules only (W2 Ch8 flattened its subpackage).
- **Lab-side env** — `DROP_STOCK` sets the drop day's stock from the lab, not a contract default (W1 Ch9, W2 Ch7).
- **`/catalog` kept** — the starter's canonical alias of `/products` (`AGENTS.md` "Retired names").

**Decision** (2026-10-17): W3 Ch11 and W4 Ch10 keep their purpose-built 8-pool `world.json` rather
than adopt the starter's 25 pools. `vpn` typed as `datacenter` is Round 2's lesson — a blunt "block
datacenter ASNs" policy catches work-VPN users as collateral — which the canonical pools (where
`consumer_vpn` is type `vpn`) would un-teach; the files' `_comment` now records why. Neither lab
needs the `labnet.py` guard: both are offline, their `attacks/` are stdlib policy models that read
local files, and `scripts/check_labs.py` confirms it (the former TODO item's "W4 Ch10 has `attacks/`
→ needs the guard" premise was wrong).

**Decision** (2026-10-20): the store gained canonical account-management routes in contract 1.8
because three labs (W2 Ch6, W4 Ch4, W3 Ch6) each needed them; the raffle (W3 Ch9) stays a
chapter-local ext until a second chapter needs it.

## Solutions and catch-up conventions

**Decision**: level-style labs (defenses pre-written, students switch `DEFENSE_LEVEL`) are an
accepted alternative to stub + solutions; they are documented, not converted. The conventions are
in `AGENTS.md` and enforced by `make check`: the `labnet.py` guard, `solutions/roundN/` with
`--catch-up`/`--restore`, and a "Rules of engagement" section in every README.

**Decision:** attacks within a round stay serial. Attacks share one store, and global defenses
(honeypots, adaptive PoW, telemetry thresholds) make interleaved results non-deterministic; a lab
that needs to be faster divides its shoppers' pauses by a `SPEEDUP` constant instead
(`AGENTS.md` → "Pacing").

## Lab shapes settled per chapter

**Decision** (2026-10-20): **account-takeover labs write real attack scripts; a script an
automated safety check refuses becomes a scored crew profile.** It applies to W3 Ch5, W3 Ch6 and
any later lab whose attacker replays stolen credentials or sessions or reads a victim's code. Try
the script first: it runs only against the learner's own loopback store, with synthetic accounts
from the lab's seeded world. If a check stops it, keep the round and score the crew the way W2 Ch8
does: a profile of what the crew holds (password, device cookie, webmail, session, phone) and what
it tries, scored against the live policy, with the real-customer cohort as the measured half of
the round. Record each such fallback in the chapter's own `TODO.md`. Scalper and farm scripts
(registration, entry, purchase) are ordinary attack scripts, as in W3 Ch4.

**Decision** (2026-10-17): **W2 Ch8 keeps its Round 4 campaign layer.** The old TODO wanted it moved
to Ch9 "which runs live traffic". Scoping showed a move is a rewrite (Ch8 is contract 1.7, Ch9 is 1.5,
different ctx/features/persona stacks) that would tear out a verified round (ladder level 4,
`campaign_probe`, `sweep --clusters`, solutions, README results). Instead the item was split: Ch8 kept
Round 4 and gained the scoring-dialects recap in its doc and deck, and Ch9 Round 4 gained the
live-traffic campaign rule the TODO really wanted — a family-level counter in `login_risk.py` whose
hot state steps up first-seen-device successes to the `otp` challenge, closing the documented
`--rotate-fp` gap. Do not reopen the move.

**Decision** (2026-10-21): **W3 Ch10 keeps its PSI bands at 0.1 / 0.2** (`lab/tools/drift.py`:
`PSI_WARN, PSI_ACT = 0.10, 0.20`). A bot signal's reference window is days rather than a quarter,
and crossing the line costs an analyst a look rather than a model rebuild. Do not move the lab's
threshold to the literature's 0.25; it would change what Round 2's drift report flags and force a
re-run of the expected-results table. The chapter doc records the literature's figure.

**Decision** (2026-10-21): **W4 Ch6 (AI Social Engineering & Romance Scams) has a defense-only
lab** in the W3 Ch7 analyst shape: a seeded generator writes a **feature log** of a synthetic
community (accounts, message events as metadata, payments, reports), never message text, and
there is no `attacks/`. Each round's "attack" is a campaign tier in the data, built to slip past
the previous round's detector family, so the attack/defend rhythm holds without anyone writing a
scam. No prompts, persona scripts, sample lure messages, pacing recipes or operator tooling in the
lab. This settles the old P0 ("lab's attacker side blocked by a safety check").

**Decision** (2026-10-17): **Private Access Tokens stay theory in W3 Ch1.** The lab cannot ship
Apple's issuer, and a PAT is an anonymous "some real device" rate signal rather than a per-session
binding, so there is no honest localhost analogue to build. W3 Ch1 Round 5's **device-bound session**
(a DBSC-style key signed per sensitive call) is the lab-buildable analogue instead.
