# Antibot Workshop Labs: TODO

*The lab backlog, split out of the series `TODO.md` on 2026-10-26 when the labs moved to this repo. Doc and deck findings, the sourcing residue and the extension ideas stay in the slides repo's `TODO.md` (`~/github/antibot-workshop-slides`). Only open work is listed; see `AGENTS.md` "Work tracking".*

## How to use this file

- **P0** — wrong, missing or contradictory; a lab cannot be run as-is.
- **P1** — cohesion across chapters: stale hand-offs, duplicated material, broken promises between labs.
- **P2** — consistency and polish: pins, naming, format.
- **P3** — extensions.

When an item is done, delete it from this file **and** update the chapter row (Lab mark, Notes) and the Progress table in the slides repo's `table_of_contents.md`.

Five chapters keep residue lists next to their doc and deck in the slides repo, because they mix doc and lab items: W2 Ch1 (`workshops/02-proficient/chapters/01-browser-automation-detection/TODO.md`), W2 Ch8 (`workshops/02-proficient/chapters/08-multi-layered-defense/TODO.md`), W3 Ch5 (`workshops/03-advanced/chapters/05-risk-based-authentication/TODO.md`), W3 Ch6 (`workshops/03-advanced/chapters/06-session-trust-and-sensitive-actions/TODO.md`) and W3 Ch9 (`workshops/03-advanced/chapters/09-fair-drops-raffles-and-allocation/TODO.md`), all paths in the slides repo. W4 Ch8's list is lab-only and lives here: `workshops/04-ai-era-bots/chapters/08-adversarial-ml-and-synthetic-data/lab/TODO.md`.

---

## 1. Series-wide

- [ ] **P2 · The W3 capstone's copies drifted from the W2 capstone.** `workshops/03-advanced/chapters/12-capstone/lab/defenses/login_risk.py` and `tools/personas_ch9.py` differ from the W2 Ch9 sources named in its `shared.json` (`python scripts/lab_diff.py <lab> --shared`). Re-copy them, or record the fork on purpose and drop them from `shared.json`.
- [ ] **P2 · Contract 1.8 follow-ups (2026-10-21).** When W2 Ch6 and the W3 capstone are next re-based, drop their lab-side `POST /api/account/email` (`ext/ato.py`) in favour of the canonical route, which keeps the same path and action name. The account page's screenshot in the slides repo's onboarding deck also needs regenerating there (`scripts/capture_store_shots.py`, which boots this repo's W1 starter through `ANTIBOT_SIBLING_ROOT`).
- [ ] **P2 · The W2 Ch4 lab's `package.json` is still named `w2-ch02-…`** from before the renumber. Rename it to match the chapter.

---

## 3. Workshop 2 · Proficient

### Ch1 Browser Automation Detection
- [ ] **P1 · 12 of 13 "real-user" profiles are synthetic**, so the false-positive numbers rest on made-up users (W2 Ch2 has the same problem). The capture drive (Windows Chrome, Edge, Firefox, Brave), the re-baseline and the prose updates are in the chapter's residue list in the slides repo (see the top of this file), together with what stays synthetic afterwards (Safari, a phone).

### Ch2 Browser Fingerprinting
- [ ] **P2 · The 9 real-user profiles are synthetic.** Add captured Safari, Brave and phone profiles.

### Ch3 TLS & Network Fingerprinting
- [ ] **P2 · The optional WebKit persona is unverified.** Playwright's WebKit downloads but needs system libraries this machine lacks (`sudo python -m playwright install-deps webkit`); `tools/personas_ch3.py` reports it as skipped. Run it once on a machine that has them and confirm the informational row (expected: a Safari UA on a non-Apple TLS stack, an L2 false positive), then drop this item.

### Ch5 Behavioral Analysis & Mouse Tracking
- [ ] **P3 · Record real-phone reference traces.** Round 5's touch bot and Layer 5 are in, but the 8 phone shoppers are synthetic (`lab/tools/humans.py`), and every phone types like Android's Gboard (`lab/README.md:164`). `lab/tools/traces/` holds only `corpus_01..06.json`.
  - Record an Android trace with the README's `adb reverse` path ("Record a phone trace", `lab/README.md:292`).
  - Commit it as `lab/tools/traces/phone.json`, so every checkpoint scores it.
  - Check the iPhone keyboard model against a real iPhone; the lab has no loopback path for iOS.
  - Then decide whether contact geometry earns points in `defenses/behavior_l5.py`. Today `telemetry.contact` is logged but not scored (`behavior_l5.py:28`).

### Ch8 Multi-Layered Defense Architecture
- Residue list in the slides repo (see the top of this file): the in-page JS untested outside headless Chromium (Firefox/Safari), `sweep.py` human-axis only.

---

## 4. Workshop 3 · Advanced

### Ch5 Risk-Based Authentication — 🟡
Content doc and deck in the slides repo quote round outcomes predicted from the lab's measured calibration until the lab runs. The open items (the blocked attack-script and passkey decisions, the checkpoint rounds, the README, replacing the predictions with measurements) are in the chapter's residue list in the slides repo (see the top of this file).

### Ch6 Session Trust & Sensitive Actions — 🟡
The lab's store side, cohort, defenses and a cohort-only checkpoint exist; an automated safety check stopped the build before the attacker side (`DECISIONS.md` → "Lab shapes settled per chapter" says what to do). The blocked and open items are in the chapter's residue list in the slides repo (see the top of this file).

### Ch7 Investigating Account Takeover in Audit Logs
- [ ] **P2 · Real-user capture.** All 26 cohorts and 9 campaigns are synthetic (a stdlib generator). An anonymised capture from a real audit log would validate the base rates that the tier-integrity bounds assume: 55% `session_resume`, 0.9% prevalence and the cohort sizes.
- [ ] **P3 · Three victims survive Round 5.** `acc_006341` (A2 SMS swap, excluded by Round 1's history clause), `acc_002663` (C1 dormant returner, below Round 5's `MIN_HISTORY=5`; the session queue finds it at history 3) and `acc_010052` (B3, a marketing-burst account that linked a provider and never ordered, so there is nothing to monetise in the window). Two are a history-clause trade, one is access-only.

### Ch9 Fair Drops: Raffles & Risk-Scored Allocation
Open lab work (a forwarder customer in the cast, the Docker path, the capstone question) is in the chapter's residue list in the slides repo (see the top of this file).

---

## 5. Workshop 4 · AI-Era Bots

### Ch6 AI Social Engineering & Romance Scams
- [ ] **P3 · Lab extensions (README Bonus Challenges, not yet built).** LLM triage of the Round 4 queue behind a human gate (Chapter 9's pattern) and a fifth tier that keeps personal hours. The lab also deliberately omits a "payout handle belongs to the payer" field (discussion question 3); add it only with a matching change to Round 3's reference and the README's expected results.

### Ch7 Agentic Reverse Engineering — ⬜ (content done; lab open)
The chapter's doc and deck exist in the slides repo and pass their checks; the deck's "Your turn" lesson hands off to the lab without a repo path, because no `lab/` is on disk yet. Design and tooling spike: REA (`morluto/rea`, npm `rea-agents`, MIT).
- [ ] **P0 · Blocked by a safety check: the lab's attacker side (2026-10-21, twice).** An automated safety check stopped the agent both times it started designing the attack scripts (the beacon forge, the capture replay, the re-analyse loop); nothing from those steps was saved. Same situation as W3 Ch5. W4 Ch6 settled its version with a defense-only analyst lab (campaign tiers in a generated log, no attack scripts; `DECISIONS.md`), which is a third option here. Decide, then record the choice in `DECISIONS.md`: (a) the W2 Ch8 shape: no attack scripts; each attacker is a scored signal profile replayed by the checkpoint, and the measured part of every round is the shopper cohort (stale tab, privacy extension, prefetcher, no-JS); or (b) a human writes the attack scripts from the design below. The defenses, the guard ext, the variant builder, the persona hook, the surface-audit tool and the fixtures are not blocked and can be built first either way.
- [ ] **P1 · Build the lab** (wire-it, W4 starter, contract **1.8**: copy the current starter). Spike proved the shape: a signed guard beacon gating checkout; attacker pipeline = webcrack 2.16 → `rea-agents` 6.7 `--json` → rule-based porter, **shipped as captured fixtures** (`REA_LIVE=1` re-runs live; add to `check_labs.py` outbound allowlist). Rounds: R1 obfuscated embedded key + source map + hidden route ⚔️ pipeline; R2 surface audit (`tools/surface_audit.py`) ⚔️ HAR replay; R3 variant pool (data-driven per-variant JSON) + watermark + single-use nonce ⚔️ re-analyse/cache (cost × N); R4 canary decoy key/route ⚔️ runtime-only port → W2 hand-off. Persona hook computes the beacon from the server's variant manifest (like `personas_ch2.py`); `no_js` = accepted FP. Pins to add to the AGENTS.md dependency table: rea-agents 6.7, webcrack 2.16, javascript-obfuscator 5.9, esbuild 0.25; lab `package.json` `engines.node >=24.15`. When the lab lands: flip the TOC Lab mark to ✅ in the slides repo, regenerate the README `Starts from:`/results blocks, and re-add the `lab/` path to the deck's hand-off slide there.

### Ch8 Adversarial ML & Synthetic Data — 🟡
- Residue list: `workshops/04-ai-era-bots/chapters/08-adversarial-ml-and-synthetic-data/lab/TODO.md`: the rounds 3–4 fresh-environment P1 (shared lineage with the W2 Ch7 defect) and a README/checkpoint metric-naming P2. A defended membership-inference round, and a positive control for `attacks/demo_membership.py`, wait on that P1.

---

## 8. Verification checklist (run after each item)

```bash
# guard, loopback binds, solutions layout, README sections (every lab and starter), paths, starter drift
make check

# every round of the touched lab, from a clean venv using only the README's commands
python tools/verify.py --all --with-before --markdown   # every round + its "before" run, one process; then --smoke
python -m py_compile $(git ls-files 'workshops/**/lab/**/*.py')

# no committed artefacts or keys
git ls-files | grep -E "__pycache__|\.pyc$|\.pem$|\.venv/"
```

Then: update the chapter row, Notes and Progress table in the slides repo's `table_of_contents.md`, and delete the item here.

## Future

- [University Course] The two-day in-person course is designed in the slides repo (`university/table_of_contents.md`, `university/match.md`). What remains on the lab side is the match tooling, none of which exists:
  - **Container bind (contract question, needs a maintainer call).** No lab has a Dockerfile, and `demo_site/app.py` binds `host="127.0.0.1"`, which a container port map cannot reach. Options: `--network host` (not portable to Docker Desktop), or an env-gated in-container bind published only as `127.0.0.1:<port>:<port>`; the second edits a starter file (contract bump) and needs a `scripts/check_labs.py` allowlist entry with the reason.
  - **Team image** for W3 Ch12 and W2 Ch9: a Dockerfile plus `make team-image` that layers only `defenses/policy.py`, `defenses/ladder.py` and at most one new `defenses/<name>.py` onto the stock lab, runs on `memory://` + SQLite with `LAB_HEADERS=0`, and rejects any defense reading `X-Lab-Actor`. In match mode the image must also pin `DEFENSE_LEVEL`, refuse `POST /lab/level` and `POST /lab/reset`, and serve `GET /lab/decisions` and `/lab/scoreboard` only to the runner (a token); today every `/lab/*` route is open on loopback and no env var protects them (`workshops/STORE_CONTRACT.md` §3.3), so this is a contract change too.
  - **Match runner:** starts an image on loopback, runs the seeded shopper population next to each attack (`tools/population.py` takes a seed internally but its CLI does not expose one), enforces a per-attack request budget, records each attack's claimed `X-Lab-JA4` with its client library, refuses browser imports in Match 1, and writes one JSON scorecard from the decision log (not from the `X-Lab-*` headers `LAB_HEADERS=0` hides) plus a decision-log export for replay.
  - **House image and house fleet** per match, with reference scores for the solo variant, and a leaderboard.
- [Lab surfaces for extension ideas in the slides repo's `TODO.md` §7] a mock MCP server driving the agent (W4 Ch4); a verified Docker run of the Prometheus/Grafana profile (W3 Ch10); a real-user capture drive for the W2 Ch1/Ch2 profiles.
