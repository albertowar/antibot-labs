# W4 Ch4 lab: AI Agents & Agentic Browsers

Starts from: `workshops/04-ai-era-bots/starter/` (contract 1.6). Adds: an agent-aware drop on the Kestrel Outfitters store (`demo_site/ext/agents.py`: a step-up challenge, account mandates, an `/agent-policy` document, a Markdown catalogue for declared agents), four defense modules you finish, W4 Ch2's Web Bot Auth verifier, two agent operators and their key directories, a small observe-decide-act browser agent that drives a real Chromium, six agent scripts, and the people and welcome agents a defense must not hurt.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/agent_behavior.py`
- `defenses/agent_identity.py`
- `defenses/agent_policy.py`
- `defenses/agent_session.py`
- `defenses/automation.py`
- `defenses/behavior_flow.py`
- `defenses/checkout_gate.py`
- `defenses/fingerprint_coherence.py`
- `defenses/httpsig.py`
- `defenses/key_directory.py`
- `defenses/mandates.py`
- `defenses/principal.py`
- `defenses/request_checks.py`
- `defenses/w2_shadow.py`
- `defenses/web_bot_auth.py`
- `demo_site/ext/agents.py`
- `demo_site/ext/templates/agents/collector.html`
- `demo_site/ext/templates/agents/mandate_field.html`
- `demo_site/ext/templates/agents/stepup.html`
- `demo_site/static/js/agent.js`
- `tools/doctor_ch4.py`
- `tools/make_keys.py`
- `tools/mock_internet.py`
- `tools/personas_ch4.py`
- `tools/profiles/brave-win.json`
- `tools/profiles/chrome-mac.json`
- `tools/profiles/chrome-win.json`
- `tools/profiles/firefox-linux.json`
- `tools/profiles/firefox-rfp.json`
- `tools/profiles/office-win.json`
- `tools/profiles/safari-ios.json`
- `tools/profiles/vdi-citrix.json`
- `tools/synthetic_input.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** four rounds of defend 🔵 and attack 🔴. **Style: wire-it.** The four defense modules ship as stubs with `TODO (Round N)` markers and are wired into `defenses/ladder.py` already; an unfinished one is inert, so Round N's checkpoint fails until you finish it. Full versions are in `solutions/round1..4/`, and `--catch-up` installs rounds 1..N over your files (your own are kept as `.bak`; `--restore` puts them back). The chapter's content doc and deck are not written yet (`TODO.md`).

Shoppers now arrive through AI agents as well as browsers. Some are honest and declared, some hide, some forge an identity, and one runs a fleet. The store sells one limited drop, the Lab Runner 9 (`/drop/lab-runner-9`, one unit per account), and every agent in this lab tries to buy it in a real Chromium. Each round adds the layer that sorts them, and the checkpoint measures what it stops **and** what happens to the 45 people and the two legitimate agents who run beside it.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service URLs such as `REDIS_URL`, `MOCK_URL` and `OLLAMA_URL` too). Every browser the agents use is a context from `labclient.browser_context`, which also aborts any request whose URL is not local. The store's edge accepts the lab headers only from loopback.
- **Everything is simulated.** Source addresses are rented from `data/world.json` (RFC 5737 / 3849 documentation ranges) and sent in `X-Lab-Client-IP`: a user-directed agent runs from a `home_fiber` address, the welcome agents from the operator's `cloud_vm`, the fleet from `residential_proxy` exits. No new pool, no real proxy. Accounts are the seeded `userNNN@example.test` users; the "emailed" step-up code is the lab mailbox (`GET /lab/mailbox/<email>`). The two agent operators, `agents.lab-provider.test` (trusted) and `agents.evil.test` (valid but unknown to the store), are `.test` names (RFC 6761). No real operator, key, endpoint or hosted LLM is contacted or used.
- **The keys are yours.** The operators' Ed25519 keys are generated on your machine into `tools/fixtures/keys/` (gitignored) the first time anything asks for them (`python tools/make_keys.py`), and their key directories are served by `tools/mock_internet.py`, a side service the store starts on `127.0.0.1:5004` and `labnet` guards. A private key in git, even a synthetic one, trips secret scanners and teaches the wrong habit.
- The agent's decisions come from a scripted policy by default. `AGENT_POLICY=ollama` swaps in a local model; `OLLAMA_URL` must point at this machine, and `labnet.py` refuses anything else, so prompts never leave the laptop. Nothing in the checkpoints depends on it.
- **Outbound network:** none during the rounds. The agents drive Playwright's Chromium on this machine against the local store. Only setup needs the internet: installing packages, `python -m playwright install chromium` and, for the optional Docker path, container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

## Setup

Python 3.12+ and Chromium. Docker is optional: the default is SQLite plus an in-process Redis (fakeredis with Lua). One venv per chapter, inside `lab/`:

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-browser.txt
python -m playwright install chromium             # Chromium 153, the browser every agent drives
python tools/doctor.py                            # packages, URLs; then: python tools/doctor_ch4.py (browser, keys)
python tools/make_keys.py                         # the operators' keys (also made on first use)
DEFENSE_LEVEL=1 python demo_site/app.py           # terminal 1: the store on 127.0.0.1:5000
HEADLESS=1 python tools/checkpoint.py --round 1   # terminal 2: both sides, one verdict (drop HEADLESS=1 to watch)
```

`PORT` changes the store's port; export `DEMO_URL=http://127.0.0.1:<port>` for the tools to match. Defense modules reload on change (`LAB_RELOAD=1`), so a saved edit takes effect on the next request. The extension in `demo_site/ext/` does not reload, and `DEFENSE_LEVEL` only changes live through the checkpoint (`POST /lab/level`), which sets the level for the round. No restart is needed between rounds.

`python tools/verify.py --round N` runs the same checkpoint with the store in-process on a free port, which is how the expected results below were produced. With no `DISPLAY` the agents run headless on their own; `HEADLESS=1` forces it anywhere and `HEADLESS=0` shows the browser.

**Fell behind?** `python tools/checkpoint.py --round N --catch-up` installs the reference modules for rounds 1..N over yours (each of yours is kept once as `.bak`). `python tools/checkpoint.py --restore` puts yours back.

## Rounds

| Round | `DEFENSE_LEVEL` | 🔴 Attack | 🔵 You edit | The question |
|---|---|---|---|---|
| 1 | 1 | `round1_undeclared_agent`, and `round1_honest_agent` for contrast | `defenses/agent_policy.py`: `classify()` and `score_checkout()` | Declared agents may browse, not buy. What does that sort, and what does it miss? |
| 2 | 2 | `round1_undeclared_agent` again, then `round2_humanized_agent` | `defenses/agent_behavior.py`: `score()` | Can a session's hands tell an agent from a person, and who pays when they cannot? |
| 3 | 3 | `round3_forged_agent` (claim, replay, vouch) and `round3_verified_agent`, the happy path | `defenses/agent_identity.py`: `verify()` | Which signatures does the store believe, and why is a valid one not enough? |
| 4 | 4 | `round4_fleet` | `defenses/checkout_gate.py`: `evaluate()` | May this purchase happen, and who stands behind it? |

A round passes when its agents meet their expectation **and** no shopper is blocked. A step-up that a person answers is friction, reported but not a failure. The checkpoint also prints the W2 browser stack's shadow score, so you can see what the older layers would have done, and the defender's cost: gate time per shopper purchase.

### What is given and what you write

| Round | Stub you finish (`defenses/`) | Given (do not edit) |
|---|---|---|
| 1 | `agent_policy.py`: `classify()`, `score_checkout()` | the CHECK that runs them on the drop purchase; `wants_markdown()` and `markdown_catalog()`; `principal.py` (combines Rounds 1 and 3) |
| 2 | `agent_behavior.py`: `score()` | `features()` (the five tells), the CHECK; `agent_session.py` (what the collector and the flow log recorded) |
| 3 | `agent_identity.py`: `verify()` | `score()`, the CHECK; `web_bot_auth.py`, `httpsig.py`, `key_directory.py`: W4 Ch2's verifier, byte for byte (`shared.json`) |
| 4 | `checkout_gate.py`: `evaluate()` | `mandate_problems()`, the lookups, the CHECK; `mandates.py` (storage) |
| | | `request_checks.py` (W1) and `w2_shadow.py` (W2), in shadow at every level |

| Round | What the stub does | What the reference does |
|---|---|---|
| 1 | `classify()` finds nobody: every client is a human, so the honest agent buys | reads the `LabAgent` User-Agent token or a `Signature-Agent` claim; `score_checkout()` gives a declared agent 60 points (a block) |
| 2 | `score()` is 0: the stock agent buys | teleport clicks +20, keystroke-free fills +15, metronome cadence +15, programmatic scrolls +10, injected overlay +30, capped at 59 (a challenge, never a block) |
| 3 | `verify()` says `none`: a signature is treated as absent, so the verified agent is still refused by Round 1 | maps the shared verifier's two answers to `verified`, `untrusted`, `replayed`, `invalid`, `unverified`; anything but `none` and `verified` scores 60 |
| 4 | `evaluate()` allows everything: the fleet wins every unit | a verified agent needs a valid mandate; anyone else gets a step-up when the session is robotic or the account is new; a device that already bought `PER_DEVICE_CAP` units is blocked |

### How a step-up and a refusal come out of a closed verdict set

The gate's verdicts are fixed: `allow`, `monitor`, `challenge`, `block`, `rate_limit`, `deceive`. This chapter needs a hand-off to a person, an attribution and a cap, and gets all three without a new verdict:

- All four checks run in the `action:drop_buy` phase (`POST /drop/<sku>` and `POST /api/buy`) and return **signals** on the scale of `policy.py`: under 30 allow, 30-59 challenge, 60 and over block. `policy.DEFAULT_CHALLENGE` is `step_up`.
- `step_up` is a registered **challenge type** (`demo_site/ext/agents.py`): a six-digit code goes to the account's lab mailbox, and the interstitial asks for it. One solve absorbs one challenge verdict (`uses=1`, the gate's downgrade rule), so the second press of Buy goes through. An agent with no inbox access stops there and hands the order back to its user.
- A **refusal is a pre-write verdict**, not a post-write hold. The brief for this migration pointed at `hooks.on_action` for holding an order; that hook fires after the order is committed, the stock is decremented and the scoreboard has counted a purchase, so it cannot refuse. Mandate and device-cap failures are `block` verdicts from `checkout_gate`; `hooks.on_action("drop_buy", ...)` only **attributes** (`order.extra` gets `placed_by`, `operator` and the mandate id), spends the mandate and counts the unit against the device.
- Who the principal is (`human`, `declared_agent`, `verified_agent`) and the identity record are computed once per request by `defenses/principal.py` and cached in `ctx.attrs`, because the shared verifier spends the signature's nonce: verifying twice would call a genuine request a replay. Identity is only consulted from level 3 up.
- A mandate is a Redis record (`lab:mandate:<id>`), granted through `POST /api/account/mandates` from the account holder's **own** session; an agent session cannot grant one. The agent presents it in the drop form's `mandate` field or an `X-Agent-Mandate` header.

## Round by round

**Round 1: declared agents may browse, not buy.** Finish `classify()` (a `ChatGPT-User`/`Claude-User`/`Perplexity-User`/`LabAgent` token in the User-Agent, or a `Signature-Agent` claim, makes a client a *declared agent*) and `score_checkout()` (60 points: a block). Check by hand: `curl -s localhost:5000/agent-policy`, and `curl -s -H 'Accept: text/markdown' localhost:5000/products` (a declared agent is served the catalogue as Markdown, a fraction of the tokens). The honest agent reads the refusal and stops; the **undeclared** agent, the same loop in a stock Chrome with no token and no claim, is a customer as far as the store can tell, and buys. Declaration is a convenience for honest operators, not a control.

**Round 2: how a session acts.** Finish `score()`. The stock agent resolves an element and acts on it: its clicks have no pointer path, its fills have no keystrokes, its think time is a metronome, it scrolls with `scrollIntoView()` and draws highlight boxes over the page. Those five tells sum to a challenge (capped at 59), the stock agent meets the step-up and cannot answer it, and it is stopped. The **humanized** agent (a Bezier cursor, wheel ticks, per-character typing, jittered think time, no overlay) passes. Read the cohort afterwards: the RPA macro (teleport clicks, instant fills) is challenged and answers, and the two screen-reader users and the voice-control user, whose clicks arrive with `detail` 0, are exempt on purpose. Every exemption is a door the next agent will try.

**Round 3: who signed it?** Finish `verify()`. The verifier (W4 Ch2's) answers two questions, and you decide what the store does with the answers: did the holder of a key the `Signature-Agent` origin publishes sign *this* request, and should we act on it (a trusted origin, a window under `policy.SIGNATURE_MAX_WINDOW_S`, a nonce not seen)? `round3_forged_agent.py` tries three shortcuts: **claim** (an origin in `Signature-Agent`, no signature), **replay** (a header set that leaked into a log: signed by the trusted operator an hour ago with a 24 h window) and **vouch** (a perfect signature by `agents.evil.test`, an operator the store has never heard of). They land as `unverified`, `replayed` and `untrusted`. The **verified** agent, signed by `agents.lab-provider.test`, buys with no behavior score and no step-up. A directory outage is an `unverified` too: the lab fails closed, and the docstring says what that costs honest agents.

**Round 4: the checkout gate.** Finish `evaluate()`. A verified agent needs a **mandate**: the account holder's single-use, time-boxed approval for this operator and this SKU. Check by hand with two `curl` sessions: log in as `user110@example.test` (its password is `demo_site.seed.password_for(110)`), `POST /api/account/mandates {"operator": "agents.lab-provider.test", "sku": "lab-runner-9"}`, and put the id in the drop form's `mandate` field. Everyone else gets a **step-up** when the session looks robotic (behavior points at or above `SUSPECT_AT`) or the account is under a day old with no orders, and a **device cap** on the drop. The fleet (fresh accounts, one Chromium, rented residential exits) reads its own inboxes, so the step-up is friction, not a wall; the cap counts units per *browser fingerprint*, which a fleet of fresh contexts on one machine does not rotate for free, so it stops at `PER_DEVICE_CAP`. Beating the cap costs a different real device per unit (W2 Ch4) and the plain cost of owning that many devices. The per-*account* cap is the store's own (`max_per_account=1`).

## Expected results (self-check)

Generated from `python tools/verify.py --all --catch-up --markdown` (against your own store: `python tools/checkpoint.py --all --markdown`) and one `--round N --level N-1 --catch-up` run per round for the "before" column, on 2026-10-15 on Linux x86_64 (WSL2) with Python 3.12.15, Flask 3.1.3, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.1.4, redis 8.1.0, fakeredis 2.39.0, requests 2.34.2, httpx 0.28.1, cryptography 50.0.2, Playwright 1.63.0 (its bundled headless Chromium), SQLite and the in-process Redis. Every round passed with the reference modules installed; the shoppers hurt were 0 of 45 in every round, and every `--level` run also passed. `--level` runs report numbers but do not judge. An agent "buys" when its session ends on the order-confirmed page. The agents are deterministic except for the humanized one's cursor jitter, so its wall time varies by seconds; the counts were identical in the separate per-round runs and in the `--all` run.

### Before and after

| Round | Agent | Before (level N-1) | After (level N) | What the scoreboard and logs say at level N |
|---|---|---|---|---|
| 1 | honest agent (`LabAgent` token) | 4 / 4 buy (bare store) | **0 / 4** | refused on the first press of Buy: `agent_policy:declared_agent` |
| 1 | undeclared agent (stock Chrome, highlight boxes on) | 4 / 4 buy | 4 / 4 buy (the limit of a policy) | `purchased 4`, nothing stopped |
| 2 | undeclared agent | 4 / 4 buy (level 1) | **0 / 4** | met the step-up, no inbox to read: `stopped 4`, outcome `challenge` |
| 2 | humanized agent | 4 / 4 buy (level 1) | 4 / 4 buy (the limit of behavior) | `purchased 4`, 72 s wall against 20 s for the stock agent |
| 3 | forged agent: claim, replay, vouch (2 each) | 0 / 6 (level 2: declared agents are already refused) | **0 / 6** | `agent_identity:unverified` (claim), `:replayed` (leaked set, 24 h window), `:untrusted` (valid, unknown operator) |
| 3 | verified agent (trusted operator) | 0 / 4 (level 2: still a declared agent) | **4 / 4 buy** | no behavior score, no step-up |
| 4 | fleet (6 fresh accounts, one Chromium, rented residential exits) | 6 / 6 buy (level 3) | **2 / 6** (`PER_DEVICE_CAP`) | the first two answer the step-up and win; the other four are blocked on their first press by `checkout_gate:cap` (the gate checks the cap before it asks anyone for a code) |

| Round | Welcome agents (`legit:agent_user`, signed, with a mandate) | People who met the step-up and answered it | Median / p95 gate time of a shopper's purchase | W2 stack in shadow, median points at the purchase |
|---|---|---|---|---|
| 1 | 0 / 2 bought (declared, so refused) | 0 / 45 | 8.5 / 18.4 ms | agents 205, welcome agents 65, people 0 |
| 2 | 0 / 2 | 1 / 45 (the RPA macro) | 9.6 / 19.3 ms | agents 182, welcome agents 65, people 0 |
| 3 | **2 / 2** (verified: no behavior score) | 1 / 45 (the RPA macro) | 9.4 / 17.5 ms | agents 205, welcome agents 65, people 0 |
| 4 | **2 / 2** (verified and mandated) | 2 / 45 (the RPA macro, the first-timer's brand-new account) | 11.0 / 22.7 ms | agents 160, welcome agents 65, people 0 |

The W2 line needs care. It is what the older layers would have said, never what they decided, and it is **not** a measurement of real agents: here the agents are Playwright's headless Chromium, which the W2 stack was built to flag (software GL, no window chrome, no pointer path). A real agentic browser drives the person's own headful Chrome and would not look like this. The agents were not run headful: the machine behind these numbers has no display.

Five things the table says out loud:

- **A policy sorts the cooperative.** Round 1 refuses the agent that tells you what it is and welcomes the one that does not.
- **Behavior is a tax, and the humanized agent pays it once.** 72 s against 20 s of wall clock for four sessions, and the RPA macro pays too (it is challenged and answers).
- **A valid signature is not trust.** The `vouch` forgery is cryptographically perfect; only the operator allow-list refuses it.
- **A challenge is only friction for someone who can read the inbox.** The fleet owns its inboxes and answers the step-up; the cap, not the step-up, is what stops it.
- **The cap is a cost, not a wall.** Two units per fingerprint is the price of two fingerprints; a fleet that can rotate real device fingerprints walks past it.

#### Round 1: declared agents may browse, not buy (`DEFENSE_LEVEL` 1)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:undeclared_agent | 36 | 36 | 4 | 0 | 0.0 | 4.27 |
| human:autofill | 7 | 7 | 1 | 0 | 0.0 | 5.37 |
| human:consumer_vpn | 21 | 21 | 3 | 0 | 0.0 | 5.02 |
| human:first_timer | 7 | 7 | 1 | 0 | 0.0 | 6.19 |
| human:home | 168 | 168 | 24 | 0 | 0.0 | 5.95 |
| human:mobile_cgnat | 56 | 56 | 8 | 0 | 0.0 | 5.73 |
| human:no_js | 5 | 5 | 1 | 0 | 0.0 | 5.59 |
| human:old_chrome | 7 | 7 | 1 | 0 | 0.0 | 4.7 |
| human:private_relay | 14 | 14 | 2 | 0 | 0.0 | 4.26 |
| human:rpa_macro | 7 | 7 | 1 | 0 | 0.0 | 4.99 |
| human:screen_reader | 14 | 14 | 2 | 0 | 0.0 | 4.56 |
| human:voice_control | 7 | 7 | 1 | 0 | 0.0 | 4.75 |


Bots stopped: **0/36** requests · shoppers hurt: **0/45** people (0/313 requests stopped, including challenges they then solved) · purchases: {'bot': 4, 'human': 45} · drop stock left: {'lab-hoodie-1': 5, 'lab-runner-9': 46}

#### Round 2: robotic sessions get the step-up (`DEFENSE_LEVEL` 2)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:humanized_agent | 36 | 36 | 4 | 0 | 0.0 | 4.06 |
| bot:undeclared_agent | 36 | 32 | 0 | 4 | 6.6 | 5.26 |
| human:autofill | 7 | 7 | 1 | 0 | 2.1 | 5.44 |
| human:consumer_vpn | 21 | 21 | 3 | 0 | 0.0 | 5.86 |
| human:first_timer | 7 | 7 | 1 | 0 | 0.0 | 4.47 |
| human:home | 168 | 168 | 24 | 0 | 0.0 | 5.69 |
| human:mobile_cgnat | 56 | 56 | 8 | 0 | 0.0 | 4.88 |
| human:no_js | 5 | 5 | 1 | 0 | 0.0 | 5.01 |
| human:old_chrome | 7 | 7 | 1 | 0 | 0.0 | 3.41 |
| human:private_relay | 14 | 14 | 2 | 0 | 0.0 | 5.07 |
| human:rpa_macro | 9 | 8 | 1 | 1 | 7.8 | 5.51 |
| human:screen_reader | 14 | 14 | 2 | 0 | 0.0 | 5.52 |
| human:voice_control | 7 | 7 | 1 | 0 | 0.0 | 4.88 |


Bots stopped: **4/72** requests · shoppers hurt: **0/45** people (1/315 requests stopped, including challenges they then solved) · purchases: {'bot': 4, 'human': 45} · drop stock left: {'lab-hoodie-1': 5, 'lab-runner-9': 46}

#### Round 3: verified identity (`DEFENSE_LEVEL` 3)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:forged_agent | 54 | 48 | 0 | 6 | 11.1 | 6.86 |
| human:autofill | 7 | 7 | 1 | 0 | 2.1 | 6.86 |
| human:consumer_vpn | 21 | 21 | 3 | 0 | 0.0 | 4.52 |
| human:first_timer | 7 | 7 | 1 | 0 | 0.0 | 5.1 |
| human:home | 168 | 168 | 24 | 0 | 0.0 | 5.59 |
| human:mobile_cgnat | 56 | 56 | 8 | 0 | 0.0 | 5.29 |
| human:no_js | 5 | 5 | 1 | 0 | 0.0 | 5.91 |
| human:old_chrome | 7 | 7 | 1 | 0 | 0.0 | 6.24 |
| human:private_relay | 14 | 14 | 2 | 0 | 0.0 | 5.02 |
| human:rpa_macro | 9 | 8 | 1 | 1 | 7.8 | 7.0 |
| human:screen_reader | 14 | 14 | 2 | 0 | 0.0 | 5.84 |
| human:voice_control | 7 | 7 | 1 | 0 | 0.0 | 5.63 |


Bots stopped: **6/54** requests · shoppers hurt: **0/45** people (1/315 requests stopped, including challenges they then solved) · purchases: {'human': 45, 'legit': 6} · drop stock left: {'lab-hoodie-1': 5, 'lab-runner-9': 44}

#### Round 4: the checkout gate (`DEFENSE_LEVEL` 4)

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:fleet | 68 | 62 | 2 | 6 | 7.1 | 4.71 |
| human:autofill | 7 | 7 | 1 | 0 | 0.0 | 5.77 |
| human:consumer_vpn | 21 | 21 | 3 | 0 | 0.0 | 5.75 |
| human:first_timer | 9 | 8 | 1 | 1 | 6.7 | 8.12 |
| human:home | 168 | 168 | 24 | 0 | 0.0 | 6.46 |
| human:mobile_cgnat | 56 | 56 | 8 | 0 | 0.0 | 6.06 |
| human:no_js | 5 | 5 | 1 | 0 | 0.0 | 5.09 |
| human:old_chrome | 7 | 7 | 1 | 0 | 0.0 | 4.93 |
| human:private_relay | 14 | 14 | 2 | 0 | 0.0 | 5.84 |
| human:rpa_macro | 9 | 8 | 1 | 1 | 6.7 | 7.48 |
| human:screen_reader | 14 | 14 | 2 | 0 | 0.0 | 7.59 |
| human:voice_control | 7 | 7 | 1 | 0 | 0.0 | 6.26 |


Bots stopped: **6/68** requests · shoppers hurt: **0/45** people (2/317 requests stopped, including challenges they then solved) · purchases: {'bot': 2, 'human': 45, 'legit': 2} · drop stock left: {'lab-hoodie-1': 5, 'lab-runner-9': 46}

The rows `legit:honest_agent`, `legit:verified_agent`, `legit:agent_user` and `legit:agent_owner` (the welcome agents and the people who grant their mandates) are not in these tables: the scoreboard lists humans and bots, and the checkpoint reports the others from their responses. Shoppers are the starter's 40 (`home` 24, `mobile_cgnat` 8, `consumer_vpn` 3, `private_relay` 2, `old_chrome`, `autofill`, `no_js`) plus two screen-reader users, a voice-control user, an RPA macro and a first-timer who registers during the drop; the hoodie (50 units) is theirs, the Lab Runner 9 is the agents'.

## Docker (optional)

The default needs none. To run the production-shaped stack the series uses everywhere else:

```bash
pip install 'psycopg[binary]==3.3.6'
docker compose -p w4ch4 up -d --wait
REDIS_URL=redis://127.0.0.1:6379/0 DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop python demo_site/app.py
docker compose -p w4ch4 down -v
```

Redis is `redis:8.10.2-alpine`, PostgreSQL `postgres:18.6-alpine` (volume at `/var/lib/postgresql`), both bound to `127.0.0.1`. Mandates, the step-up codes, nonces and device counters are Redis keys under `lab:`, so a reset clears them on either backend.

## What this does not teach

- **A real agentic browser.** The agent is an observe-decide-act loop in a headless Chromium with a scripted planner. Real products drive the person's own Chrome, change their request shape between releases and ship vendor-specific identity signals; none of that is modelled. `AGENT_POLICY=ollama` swaps in a local model for the planner, which changes how the agent thinks, not how the store scores it (not exercised in the checkpoints).
- **Interop with a real Web Bot Auth signer.** The verifier is W4 Ch2's and the signer is this lab's own; both speak RFC 9421 and the web-bot-auth draft, and neither has been tested against a vendor's.
- **Real card-network agentic payments.** The mandate is a sketch in the spirit of AP2: scoped, time-boxed, single-use, bound to an operator and a SKU. It moves no money and is not an AP2 implementation.
- **Cart checkout.** The gate acts on the drop purchase (`POST /drop/<sku>`, `POST /api/buy`); a verified agent that buys an ordinary product through the cart is not gated. Extending the phase list to `action:checkout` needs the order's SKU, which the cart route does not put in the notes.
- **Held orders.** A step-up here is a challenge before the order exists. Holding an order that is already paid and restocking it on a timeout is a different design, and this lab's store (pre-1.7) has no cancel path. Contract 1.7 later added held orders and `demo_site/orders.py cancel_order` (`STORE_CONTRACT.md` changelog); this lab keeps its pre-write `block`.

## Troubleshooting

- `playwright._impl._errors.Error: Executable doesn't exist`: `python -m playwright install chromium`, inside the lab's venv. `python tools/doctor_ch4.py` says so too.
- The agents hang on a display error: `HEADLESS=1`.
- Every round says the store is unreachable: `python demo_site/app.py` in another terminal, or use `python tools/verify.py --round N`, which starts its own.
- A forged-agent run shows `unverified` for the trusted operator: the store could not fetch the directory (the mock failed to start, or `MOCK_URL` points elsewhere). A failed fetch is cached for five minutes; reset with `POST /lab/reset` or wait.
- Round 4's fleet wins more than the cap: the page's telemetry did not reach the store before the Buy press (the device is the browser fingerprint), so the gate fell back to the cookie. Check `X-Lab-Signals` and `/lab/decisions?actor=bot:fleet`.
- Stale `.bak` files after an interrupted catch-up: `python tools/checkpoint.py --restore`.
