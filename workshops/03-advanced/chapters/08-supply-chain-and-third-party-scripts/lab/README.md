# Chapter 8 Lab: Supply Chain & Third-Party Scripts

Starts from: `workshops/03-advanced/starter/` (contract 1.5). Adds: a vendor script include and a first-party bundle on the store's pages, the compromise that is already in them (`demo_site/ext/supply.py`), the browser-enforced controls as ladder checks (`defenses/`), four skimmer attacks, a local exfil collector, and browser-driven shoppers.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/csp_policies.py`
- `defenses/generate_sri.py`
- `defenses/inventory.py`
- `defenses/inventory_scripts.py`
- `defenses/page_controls.py`
- `defenses/runtime_monitor.py`
- `defenses/script_monitor.py`
- `demo_site/ext/assets/analytics-helper.baseline.js`
- `demo_site/ext/assets/analytics-helper.js`
- `demo_site/ext/assets/shop-bundle.js`
- `demo_site/ext/assets/shop-bundle.poisoned.js`
- `demo_site/ext/supply.py`
- `demo_site/ext/templates/supply/body_end.html`
- `demo_site/ext/templates/supply/head.html`
- `demo_site/static/js/runtime-monitor.js`
- `tools/cdn_bump.py`
- `tools/personas_ch8.py`
- `tools/slice_check.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** four rounds of defend 🔵 and attack 🔴, then a debrief. See `../chapter_08_content.md`, §8.6. **Style: pre-written.** Every control ships complete; you read it, switch `DEFENSE_LEVEL`, and watch what the next skimmer does to it. `solutions/roundN/defenses/ladder.py` is the ladder as it stands after Round N, and `--catch-up` installs it (your own `ladder.py` is kept as `.bak`; `--restore` puts it back). Catching up also just means running the round at its level, which the checkpoint does for you.

**This lab works on a slice of the store, on purpose.** A client-side skimmer lives in the browser, so the store here is the starter's, unchanged, but the lab exercises only the two forms a skimmer targets: the checkout (`form#checkout`, with a card field) and the login (`form#login-form`, with a password), plus the path that reaches them (a product, the cart) and a third-party script include the store hosts. The include and the controls ride every HTML page (the slots are site-wide); the catalogue, the drops, the JSON API and the bot-facing machinery of other chapters are not part of this lab and are not measured. Nothing in the starter is edited.

A third-party include your store hosts has been swapped to carry a skimmer. Each round you switch on one more control the browser enforces and watch what it does, and does not, stop. The skimmer is not yours to write: it is already in place, and the attacker's only job each round is to pick the exfil technique that beats the last control.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine. Its browser context also aborts every request that is not to this machine, so a page that tried to load something remote would fail rather than reach out. The store's edge accepts the lab headers only from loopback.
- **The collector is loopback too.** The attacker's sink (`collector/collector.py`) binds `127.0.0.1` only, takes its address from `COLLECTOR_URL` through `labnet.target()` / `require_local_env()` (a non-local value ends the process), and the store, the attacks and the checkpoint all read the same variable through the same guard.
- **Everything is synthetic.** The victims type the synthetic test card `4242424242424242` and the seed accounts' passwords (`demo_site/seed.py`). Source addresses are rented from `data/world.json` (documentation ranges). The skimmer is a lab artefact that sends only to the local collector. No proxy, no real address, no third-party site.
- **Outbound network:** none during the rounds (the collector is on loopback and the browser refuses anything else). Only setup needs the internet: installing packages, the Chromium that Playwright downloads, and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

## What is in the slice

```
demo_site/ext/supply.py      the include, the compromise and the response side of the controls:
                             GET /static/vendor/analytics-helper.js   the third-party include (clean | compromised | updated)
                             GET /static/js/shop-bundle.js            the first-party bundle (clean, or the poisoned build)
                             POST /lab/supply/scenario {"variant", "vendor", "report_only"}    which technique, which file
                             GET  /lab/supply/status                  the controls live at this level, the collector
                             POST /lab/supply/csp-report              the CSP report-uri; GET /lab/supply/csp-reports to read it
                             telemetry kind "script_violation"        the runtime monitor's reports; GET /lab/supply/violations
demo_site/ext/assets/        analytics-helper.baseline.js (the known-good release) and .js (the swapped one), shop-bundle[.poisoned].js
demo_site/static/js/runtime-monitor.js    Round 4's monitor
defenses/
  inventory.py               Round 1 (level 1): the inventory is out-of-band, the check marks the level
  inventory_scripts.py       a Playwright crawl of the slice: every script the pages load
  script_monitor.py          SHA-256 of each one, diffed against a baseline (instance/script_baseline.json)
  csp_policies.py            Round 2 (level 2) weak(): host allowlist · Round 3 (level 3) strict(): nonce + strict-dynamic
  generate_sri.py            Round 3 (level 3): the integrity pin on the vendor tag
  runtime_monitor.py         Round 4 (level 4): the monitor, loaded first
  page_controls.py           what a check sets (the "page" phase); ladder.py is the wiring
collector/collector.py       the attacker's sink on 127.0.0.1 (counts what the skimmer sends)
attacks/round1..4_*.py       two browser victims (one at the card field, one at the password field) and the collector's tally
tools/                       checkpoint.py (ROUNDS), personas_ch8.py (the browser shoppers), slice_check.py, cdn_bump.py
```

**The ladder.** Level k is on when k <= `DEFENSE_LEVEL`, and a higher level's check may replace a lower one's:

| Level | Round | Adds | Where it lands |
|---|---|---|---|
| 0 | - | nothing: the vendor include skims freely | - |
| 1 | 1 | script inventory + change detection | out-of-band: the store's responses are identical to level 0 |
| 2 | 2 | CSP, host allowlist (`'unsafe-inline'`, permissive `img-src`) | `Content-Security-Policy` header (Report-Only for the first half of the round) |
| 3 | 3 | CSP nonce + `strict-dynamic`, SRI | header; a nonce on every `<script>`; `integrity=` on the vendor tag |
| 4 | 4 | runtime monitor | a `<script>` first in `<head>`; reports to `POST /api/telemetry` |

These checks run in a "page" phase (see `defenses/page_controls.py`): they decide what an HTML response carries to the browser, not whether a request is served, so the gate never refuses anyone because of them. `python tools/slice_check.py` prints what `/login` carries at the store's current level. Switch levels without a restart: `curl -X POST localhost:5000/lab/level -d '{"level": 3}' -H 'Content-Type: application/json'` (or start the store with `DEFENSE_LEVEL=3`); the checkpoint does it for you.

**Techniques.** The attacker's technique is a request to the store, not a restart: `curl -X POST localhost:5000/lab/supply/scenario -d '{"variant":"allowlisted"}' -H 'Content-Type: application/json'`. The attack scripts do it for you. `beacon` (Round 1), `dynamic` (Round 2), `allowlisted` (Round 3) live in the vendor file; `firstparty` (Round 4) lives in the store's own bundle. In Round 4 the strict policy allows one analytics origin in `connect-src` (a real store's analytics vendor); the lab models it with the collector's origin: the attacker holds a tenant on that shared endpoint.

**The nonce middleware.** At level 3 the store tags every `<script>` its templates render with the response's nonce, with a regular expression over the finished HTML. That is what an edge or a framework helper does, and it is safe here only because Jinja escapes user input; a response that echoed attacker markup would hand the attacker the nonce too. In production add the nonce in the template engine, not afterwards.

## Setup

Work through `onboarding/setup/PREWORK.md` first. This lab adds a real browser, because the controls are enforced by one:

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # one venv per chapter, see the root README
pip install -r requirements.txt -r requirements-browser.txt
python -m playwright install chromium                    # Chromium 153 with Playwright 1.63
python tools/doctor.py
python demo_site/app.py                                  # terminal 1: the store, on :5000
python collector/collector.py                            # terminal 2: the attacker's sink, on :5001
python tools/verify.py --smoke                           # optional: the contract, as a test (starts its own store)
```

`tools/checkpoint.py` starts the collector for you (on loopback, at the address the store reports) if nothing is listening, so terminal 2 is optional. Port 5000 or 5001 busy? `PORT=8099 python demo_site/app.py` and `export DEMO_URL=http://127.0.0.1:8099`; `export COLLECTOR_URL=http://127.0.0.1:8098` before starting the store, the collector and every tool (all of them read it through the guard, and it must be loopback).

The default store is SQLite plus an in-process Redis (`memory://`), so **no Docker is required**: the chapter is about code running in the browser, and the browser and the collector run on your machine either way. To run the production-shaped store (Redis 8.10 and PostgreSQL 18) under the same lab:

```bash
docker compose up -d --wait
export REDIS_URL=redis://127.0.0.1:6379/0
export DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop
python demo_site/app.py
```

Bring it down with `docker compose down -v`. The browser-driven rounds run unchanged against it (the store is a host process; only Redis and PostgreSQL are containers). Expect the gate median to rise from about 1 ms to about 3 ms: every gate step is now a network round trip.

## How to measure a round

```bash
python tools/checkpoint.py --round 2              # level 2: the round's skimmer, and 6 browser shoppers next to it
python tools/checkpoint.py --round 3 --level 2    # the same skimmer against Round 2's defense (the "before")
python tools/checkpoint.py --all --markdown       # every round (the table below)
```

Each run drives two victims through the store in Chromium (one pays with the test card, one signs in) and asks the collector whether the data arrived; at the same time six browser shoppers (`tools/personas_ch8.py`) pay as guests and sign in. A round passes when the skimmer's numbers are the expected ones **and no shopper was stopped** **and none of the store's own files was refused by the policy** **and the page carries exactly what the level promises** (`slice_check.py`). Besides the scoreboard each run prints the costs:

```text
the shoppers: 6 browsers · first-party files refused by the policy: 0 · add-on pixel/script refused (report noise): 10 · vendor file refused by SRI: 30 · skimmer calls refused: 0
defender cost: gate time of the shoppers' 52 requests: median 1.06 ms (the controls ride the response, not the gate)
```

Two of the shoppers run a privacy add-on that injects a tracker pixel and an inline script into every page. Nobody is hurt, but under the strict policy the browser refuses both and files CSP reports: the report stream fills with traffic that is not an attack, which is what running CSP costs. The shoppers all run in Chromium; Firefox and Safari enforce the same policies with differences (Trusted Types in particular), so test the engines your customers use.

---

## Round 1: 🔴 vendor skimmer ⚔️ 🔵 inventory and change detection (`DEFENSE_LEVEL=1`)

- **Attack step:** `python attacks/round1_vendor_skimmer.py`. The vendor's analytics file has been swapped (think Polyfill.io, 2024): on submit it `sendBeacon`s every field to the attacker. The victim pays, the victim signs in, and the collector holds the card and the password.
- **Defense step:** read `defenses/inventory_scripts.py` (a crawl of the slice that records every script the pages load, with a cart so `/checkout` renders the payment form) and `defenses/script_monitor.py` (SHA-256 of each script, diffed against a baseline). The checkpoint builds the baseline from the clean release (`curl -X POST localhost:5000/lab/supply/scenario -d '{"vendor":"clean"}' -H 'Content-Type: application/json'`, crawl, `python defenses/script_monitor.py --create-baseline`), lets the vendor swap the file (`"vendor":"compromised"`), crawls again and expects `CHANGED .../analytics-helper.js` and nothing else.
- **Observe:** the swap is flagged, and the card still left on the first checkout. Detection buys time to respond (PCI DSS 11.6.1 asks for it at least weekly: a window of days); it does not stop the next victim.
- **Checkpoint:** `python tools/checkpoint.py --round 1`.

## Round 2: 🔴 checkout-only dynamic skimmer ⚔️ 🔵 CSP, Report-Only first (`DEFENSE_LEVEL=2`)

- **Attack step:** `python attacks/round2_checkout_only.py`. A one-shot crawl of the home page never sees this skimmer: it arms itself only on `/checkout` and `/login`, injects a script and sends the fields with `fetch`.
- **Defense step:** read `defenses/csp_policies.py:weak`: a host allowlist with `connect-src 'self'`. Ship it Report-Only first (`python attacks/round2_checkout_only.py --report-only`, which asks the store to send the header as `Content-Security-Policy-Report-Only`): the skimmer still wins, and `GET /lab/supply/csp-reports` lists exactly what enforcement would break. Then enforce.
- **Observe:** under Report-Only both victims are skimmed and the reports name `connect-src` and the collector; enforced, the injected script runs and the data has nowhere to go.
- **False-positive check:** none for the six shoppers. The policy's cost is the report endpoint and the week of Report-Only before you enforce it.
- **Checkpoint:** `python tools/checkpoint.py --round 2`.

## Round 3: 🔴 allowlist bypass ⚔️ 🔵 nonce + `strict-dynamic`, and SRI (`DEFENSE_LEVEL=3`)

- **Attack step:** `python attacks/round3_allowlist_bypass.py`. `connect-src 'self'` stops `fetch` and `sendBeacon`, so the skimmer injects an inline script (allowed by the allowlist's `'unsafe-inline'`) and exfils through an `<img>` pixel (allowed by the permissive `img-src`).
- **Defense step:** read `csp_policies.py:strict` (no `'unsafe-inline'`, only nonced scripts, `img-src 'self' data:`, Trusted Types) and `generate_sri.py` (the integrity pin on the vendor tag, from the known-good release). Run `python -m defenses.generate_sri` to see the tag.
- **Observe:** the browser refuses the swapped vendor file (`Failed to find a valid digest`), so the skimmer never runs. Each control alone is enough against this technique (measured once by editing the ladder to `[csp_policies.STRICT]` and to `[generate_sri.CHECK]`: both stopped the Round 2 and Round 3 techniques, both lost to Round 4's); together they are two independent reasons.
- **False-positive check:** `python tools/cdn_bump.py`. SRI fails closed: a legitimate vendor release (`"vendor":"updated"`) is refused for every visitor until you re-pin and redeploy. The shoppers' pages also show the vendor file refused 30 times in a round, because the vendor file in the lab is the swapped one.
- **Checkpoint:** `python tools/checkpoint.py --round 3`.

## Round 4: 🔴 poisoned first-party bundle ⚔️ 🔵 runtime monitor (`DEFENSE_LEVEL=4`)

- **Attack step:** `python attacks/round4_poisoned_bundle.py`. A build-time dependency (think the Shai-Hulud npm worm, September 2025) put the skim inside the store's own bundle. It ships from your origin: SRI matches your own build, the strict CSP nonces it, and its beacon goes to the one analytics origin `connect-src` must allow.
- **Defense step:** read `demo_site/static/js/runtime-monitor.js`: it loads first, wraps `fetch`, `XMLHttpRequest` and `sendBeacon`, reports a call to any other origin to `POST /api/telemetry` (`script_violation`), and refuses the beacon.
- **Observe:** the monitor's report (`GET /lab/supply/violations`) names `sendBeacon` and the collector; the collector gets nothing. The monitor is a detection layer with a blocking lever, not a wall: a script that runs before it keeps the originals, and `Image().src` and form posts are not wrapped.
- **Checkpoint:** `python tools/checkpoint.py --round 4`.

## Debrief: false positives and cost

Run `python tools/slice_check.py` and `python tools/cdn_bump.py` after each round. Across all four rounds the controls stop no shopper: the skimmer is parasitic, and none of these controls touch your own checkout code. The cost is operational: the Report-Only week, the report noise from add-ons and extensions, re-pinning SRI on every vendor release, and keeping the monitor's allowlist current. And the controls have seams: each attack in the table beats the control before it.

## Expected results (self-check)

Verified on Linux with Python 3.12.15, Flask 3.1.3, Playwright 1.63.0 (Chromium 153.0.8010.12), on the no-Docker path (SQLite and the in-process Redis), and again on the Docker path (Redis 8.10 and PostgreSQL 18, containers from `docker-compose.yml`): `tools/verify.py --smoke` and `--all` pass on both. "Skimmed" counts victims whose data reached the collector, of 2 (one at the card field, one at the password field). The "before" column is the same skimmer against the previous level (`--round N --level N-1`). Report counts vary a little between runs (the add-on noise and the order of the shoppers); the other numbers are stable.

| Round | Level | Skimmer | Before (level N-1) | After | Detection signal | Shoppers hurt (of 8 people) | Gate median |
|---|---|---|---|---|---|---|---|
| 1 | 1 | `beacon` | skimmed 2/2 | skimmed 2/2 | `CHANGED .../analytics-helper.js` from the crawl and hash diff | 0 | about 1 ms |
| 2 | 2 | `dynamic` | skimmed 2/2 | Report-Only: 2/2; enforced: 0/2 | CSP reports naming `connect-src` and the collector (6 and 10 in one run) | 0 | about 1 ms |
| 3 | 3 | `allowlisted` | skimmed 2/2 | 0/2 | the browser refuses the vendor file (digest) and the pixel (`img-src`) | 0 | about 1 ms |
| 4 | 4 | `firstparty` | skimmed 2/2 | 0/2 | runtime monitor reports `sendBeacon` to the collector (a few per victim page, and every shopper page the poisoned bundle loads on) | 0 | about 1 ms |

Negative controls: every "before" cell is the skimmer beating the control above it (`--round 3 --level 2` is the pixel getting through Round 2's `connect-src 'self'`; `--round 4 --level 3` is the poisoned bundle getting through nonce, `strict-dynamic` and SRI). Costs measured in the same runs: first-party files refused by the policy: 0 in every round; the add-on shoppers' pixel and script refused at level 3 and 4: 10 per round (2 shoppers, 5 pages each) with the matching CSP reports; a legitimate vendor release refused by SRI at level 3 and 4 (`tools/cdn_bump.py`); gate time of the shoppers' requests, 1 to 1.5 ms on SQLite and about 2.4 to 3.3 ms on Redis 8.10 and PostgreSQL 18.

Regenerate the scoreboard tables with `python tools/checkpoint.py --all --markdown` (the store running), or `python tools/verify.py --all --markdown` (it starts its own).

## Troubleshooting

| Problem | Fix |
|---|---|
| `Executable doesn't exist` from Playwright | `python -m playwright install chromium` inside the venv |
| `Address already in use` on 5000 or 5001 | See Setup: `PORT` for the store, `COLLECTOR_URL` for the sink, the same value for every process |
| `Refusing to run against non-local ...` | `DEMO_URL` or `COLLECTOR_URL` points off this machine; that is the guard working |
| The checkpoint says "page carries ..." | The store is not at the round's level, or the ladder in `defenses/ladder.py` was edited; `POST /lab/level` or `--catch-up` |
| A victim shows `error: TimeoutError` | The machine was busy; the script retries a victim once, and the checkpoint fails a round with unfinished victims instead of reporting a false "blocked" |
| Round 1 reports no `CHANGED` | The crawl wrote no inventory (the store was down, or Chromium could not start); run `python defenses/inventory_scripts.py` by hand and read it |

## Bonus challenges

1. **Tighten `connect-src` with reporting.** Put the store at level 3 with a real `report-uri` pipeline and prove you could detect Round 4's exfil attempt even while allowing the analytics origin.
2. **Harden the monitor.** It can be unwrapped by a script that loads first. Add a check that detects whether `fetch` and `sendBeacon` were reassigned after it ran, and report the tampering.
3. **SRI in CI.** Wire `python -m defenses.generate_sri` into a pre-commit hook that fails if the served vendor file no longer matches the pinned hash.
