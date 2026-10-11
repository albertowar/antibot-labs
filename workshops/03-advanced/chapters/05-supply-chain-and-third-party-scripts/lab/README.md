# Chapter 5 Lab: Supply Chain & Third-Party Scripts

**Format:** 4 rounds of attack ⚔️ defend. See `../chapter_05_content.md`, §5.6.

A third-party include your store hosts has been swapped to carry a skimmer. Each
round you add one browser-enforced control and watch what it does — and does not
— stop. The store is a small slice of the workshop shop: just a checkout page
with a card field and a login page, the two forms a skimmer cares about.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. It also refuses a non-local `COLLECTOR_URL`. Do not remove that check.
- The store and the skimmer's collector both bind `127.0.0.1`.
- Use only the synthetic data already in the forms, never a real card number. `TRUSTED_ANALYTICS` only adds an origin to the store's CSP; the store never fetches it.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  README.md              this file
  requirements.txt       pinned (Flask, Playwright, httpx)
  demo_site/             the store — CSP/SRI/monitor are all env-driven
    app.py
    templates/           base, index, product, checkout, login
    static/js/           shop.js (first-party bundle), runtime-monitor.js (defense)
    static/vendor/       analytics-helper.js (compromised) + .baseline.js (known-good)
  collector/collector.py the attacker's exfil sink (127.0.0.1:5001)
  defenses/
    inventory_scripts.py Playwright script inventory          (Round 1)
    script_monitor.py    hash change-detection                (Round 1)
    csp_policies.py      the weak vs. strict CSP strings       (Rounds 2-3)
    generate_sri.py      SHA-384 SRI pin generator            (Round 3)
    solutions/roundN/    the exact commands for each round
  attacks/               round1..4 drivers (+ _common.py)
  tools/
    checkpoint.py        verify a round (both sides)
    legit_traffic.py     simulated shoppers + the SRI re-pin cost
    scoreboard.py        did data get out, and did we block anyone
```

## Setup

No Docker, no database. You need Python 3.12+ and a Chromium for Playwright.

```bash
cd lab
python -m venv .venv && source .venv/bin/activate      # one venv per chapter, see the root README
pip install -r requirements.txt
playwright install chromium
```

Open **two terminals** (both with the venv active):

```bash
# Terminal A — the attacker's collector (leave it running all session)
python collector/collector.py            # http://127.0.0.1:5001

# Terminal B — the store (you restart this each round with new flags)
cd demo_site && CSP_MODE=off python app.py   # http://127.0.0.1:5000
```

The store is driven entirely by environment variables, so a round is a restart,
not a code edit. Read the defense module, set the flags, re-run the attack.

| Variable | Values | Meaning |
|---|---|---|
| `CSP_MODE` | `off` · `report-only` · `enforce` · `strict` | which CSP header is sent |
| `SRI` | `off` · `on` | pin the vendor `<script>` to the known-good hash |
| `MONITOR` | `off` · `on` | load `runtime-monitor.js` first and wrap the network APIs |
| `SKIMMER_VARIANT` | `beacon` · `dynamic` · `allowlisted` · `firstparty` | the exfil technique (one per round) |
| `VENDOR` | `compromised` (default) · `clean` | serve the skimmer file or the benign baseline |
| `TRUSTED_ANALYTICS` | a URL | a third-party beacon origin the store must allow (Round 4) |

Debug endpoints: `/status`, `/csp-report/log`, `/api/script-violation/log`, and
the collector's `/captured`.

**Troubleshooting**

| Problem | Fix |
|---|---|
| `Address already in use` on 5000/5001 | Another app holds the port. Set `PORT=5055 python app.py` (store) / `PORT=5056 python collector.py`, and export `DEMO_URL`/`COLLECTOR_URL` to match. |
| Playwright `Executable doesn't exist` | Run `playwright install chromium` inside the venv. |
| Checkpoint says "not in this round's state" | Restart the store with the flags it prints. |
| Round 1 "did you build the baseline?" | Build it from the clean release first — see `solutions/round1/README.md`. |

## How to measure a round

```bash
python tools/checkpoint.py --round 2
```

It reads `/status`, re-runs the round's attack, and checks **both** sides: did
the skimmer get card data out, and did any of 5 simulated shoppers get blocked.
Round 1 is the exception — there it confirms the change-monitor fired *and* that
the card still got out, because detection is not prevention.

Fell behind? `python tools/checkpoint.py --round N --catch-up` prints the exact
commands, and each `solutions/roundN/README.md` has them too. This lab is configured,
not coded, so there are no files to install.

## Round 1: Inventory & change detection

Know every script that runs, and get told when one changes. PCI DSS v4.0 req
6.4.3 makes this mandatory on payment pages.

| Step | Do | Expected |
|---|---|---|
| 🛡️ Baseline | Start the store `VENDOR=clean`, then `inventory_scripts.py` + `script_monitor.py --create-baseline` | 2 scripts baselined |
| 🗡️ Swap | Restart the store at its default (`VENDOR=compromised CSP_MODE=off SKIMMER_VARIANT=beacon`) | — |
| 🛡️ Detect | `python defenses/inventory_scripts.py` then `python defenses/script_monitor.py` | `CHANGED  …/analytics-helper.js` |
| 🗡️ Attack | `python attacks/round1_vendor_skimmer.py` | 🔴 EXFIL SUCCEEDED (1 capture) |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | change flagged · card still out · 0/5 shoppers blocked |

**Discuss:** you detected the swap in minutes. The card still left on the first
checkout. What does detection buy you, and what does it not?

## Round 2: CSP report-only → enforce

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | Restart `CSP_MODE=report-only SKIMMER_VARIANT=dynamic`, run `round2_checkout_only.py` | still exfils; `/csp-report/log` fills |
| 🛡️ Defend | Restart `CSP_MODE=enforce SKIMMER_VARIANT=dynamic` (read `defenses/csp_policies.py:weak`) | — |
| 🗡️ Re-run | `python attacks/round2_checkout_only.py` | 🟢 nothing sensitive gets out |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | exfil blocked · CSP reports logged · 0/5 blocked |

**Discuss:** report-only changed nothing for users but told you exactly what
enforce would break. Why always run report-only first?

## Round 3: Nonce + strict-dynamic, and SRI

The host-allowlist of Round 2 ships two routine holes: `'unsafe-inline'` and a
permissive `img-src`. This round's skimmer uses both — an injected inline script
and an `<img>` pixel — to sidestep `connect-src 'self'`.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | Restart `CSP_MODE=enforce SKIMMER_VARIANT=allowlisted`, run `round3_allowlist_bypass.py` | 🔴 EXFIL SUCCEEDED (via pixel) |
| 🛡️ Defend | Restart `CSP_MODE=strict SRI=on SKIMMER_VARIANT=allowlisted` (read `csp_policies.py:strict`, run `generate_sri.py`) | — |
| 🗡️ Re-run | `python attacks/round3_allowlist_bypass.py` | 🟢 nothing sensitive gets out |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | exfil blocked · 0/5 blocked |

**False-positive check:** `python tools/legit_traffic.py --cdn-bump`. SRI fails
closed when a vendor legitimately updates its file — budget for re-pinning.

## Round 4: Runtime monitor + dependency hygiene

A poisoned build ships the skim inside your own first-party bundle. CSP nonces
it, SRI matches your own build, and it rides the one analytics origin your
`connect-src` must allow. Only the runtime monitor sees it.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | Restart `CSP_MODE=strict SRI=on MONITOR=off SKIMMER_VARIANT=firstparty TRUSTED_ANALYTICS=http://127.0.0.1:5001`, run `round4_poisoned_bundle.py` | 🔴 EXFIL SUCCEEDED |
| 🛡️ Defend | Restart the same but `MONITOR=on` (read `demo_site/static/js/runtime-monitor.js`) | — |
| 🗡️ Re-run | `python attacks/round4_poisoned_bundle.py` | 🟢 blocked; `/api/script-violation/log` has it |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | exfil blocked · runtime report · 0/5 blocked |

**Discuss:** the monitor is a detection layer that can be unwrapped by a script
that runs before it. Why is it still worth deploying, and what is it *not*?

## Wrap-up: false positives and cost (debrief)

Run `python tools/scoreboard.py` after each round. Across all four rounds, the
correct controls block **0** of the simulated shoppers — the skimmer is
parasitic, and none of these controls touch your own checkout code. Their cost
is operational, not user-facing: re-pinning SRI on every CDN bump, tuning the
policy out of report-only, and keeping the monitor's allowlist current.

## Expected results (self-check)

Verified on Linux with Python 3.12.15, Flask 3.1.3, httpx 0.28.1, Playwright 1.63.0
(Chromium 153.0.8010.12), on the no-Docker path (no Redis or database in this lab).
Rounds 1-4 each pass `tools/checkpoint.py` with the store restarted at that round's
flags, and the numbers match the table below. The `docker compose` path is verified
separately. Each round below is the *solved* end state; the negative
control shows the prior defense genuinely failing.

| Round | End state | Attack result | Detection signal | Shoppers blocked |
|---|---|---|---|---|
| 1 | `CSP=off` | 🔴 exfil succeeds (1) | `CHANGED` on the vendor file | 0/5 |
| 2 | `CSP=enforce` | 🟢 blocked (0) | CSP `connect-src` report | 0/5 |
| 3 | `CSP=strict SRI=on` | 🟢 blocked (0) | inline refused / pixel blocked | 0/5 |
| 4 | `CSP=strict SRI=on MONITOR=on` + allowed analytics | 🟢 blocked (0) | runtime `sendBeacon` report (1) | 0/5 |

Negative controls (the attack beating the prior round's defense):

| Control | State | Result |
|---|---|---|
| Round 3 attack vs. Round 2 defense | `CSP=enforce SKIMMER_VARIANT=allowlisted` | 🔴 pixel exfil succeeds |
| Round 4 attack vs. Round 3 defense | `CSP=strict SRI=on MONITOR=off TRUSTED_ANALYTICS=…` | 🔴 first-party exfil succeeds |

## Bonus challenges

1. **Tighten connect-src with reporting.** Put the store in `strict` with a real
   `report-uri` pipeline and prove you could detect Round 4's exfil attempt even
   while allowing the analytics origin.
2. **Harden the monitor.** The monitor can be unwrapped by a script that loads
   first. Add a check that detects whether `fetch`/`sendBeacon` were reassigned
   after it ran, and report tampering.
3. **SRI in CI.** Wire `generate_sri.py` into a pre-commit hook that fails if the
   served vendor file no longer matches the pinned hash.
