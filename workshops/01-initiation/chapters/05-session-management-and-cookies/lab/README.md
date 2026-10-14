# Chapter 5 Lab: Replay, Harden, Detect

Starts from: `workshops/01-initiation/starter/` (contract 1.5). Adds: a promo voucher whose "unlocked"
flag rides in a signed client-side cookie, four session defenses (`promo_state`, `session_velocity`,
`session_guard` with a binding check), four attack scripts on one shared helper, and the Chapter 5 shoppers.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/promo_state.py`
- `defenses/session_guard.py`
- `defenses/session_velocity.py`
- `demo_site/ext/promo.py`
- `demo_site/ext/templates/promo/js_cookie.html`
- `demo_site/ext/templates/promo/offer.html`
- `demo_site/static/js/promo.js`
- `tools/personas_ch5.py`
- `tools/promokit.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** **pre-written.** The defenses ship complete; each round you read one, wire it into `defenses/ladder.py`,
run the attack, then read the attack that beats it. `solutions/roundN/` holds the finished `ladder.py` (and, for
Round 3, the tuned `policy.py`). `python tools/checkpoint.py --round N --catch-up` installs them if you fall
behind. See `../chapter_05_content.md`, section 5.8.

You play both sides. The store sells a promo voucher at `/promo/`: answer a one-line quiz to unlock, then
redeem once. The bug is that the "unlocked" flag lives in a signed cookie, so the bot tries to turn one unlock
into many vouchers. Every round you add one session layer and measure two numbers:

- how many vouchers the bot got from a single unlock;
- which of the 40 simulated shoppers your layer stopped. No-JS visitors, autofill users and a phone that moves
  networks mid-visit all look a little like a bot to a session defense; the scoreboard shows them next to the
  bots stopped.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`,
  which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service
  URLs such as `REDIS_URL` too). The store's edge accepts the lab headers only from loopback.
- Everything is synthetic. Source addresses are rented from `data/world.json` (documentation ranges), never
  invented, never real. The "browser" in Round 4 is a real Chromium, but it only ever talks to localhost. No
  public proxy lists, no third-party sites, no real users or credentials.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages and the
  Chromium build for Round 4.

## Setup

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
# Round 4 drives a real browser:
pip install -r requirements-browser.txt && python -m playwright install chromium
python tools/doctor.py
```

One venv per chapter (`.venv` here); the root README explains why. The store runs in-process during the
checkpoints, so you do not start it by hand to run a round.

## How to measure a round

```bash
python tools/checkpoint.py --round N              # level N: your defenses
python tools/checkpoint.py --round N --level N-1  # the same attacks against the previous level: the "before"
python tools/checkpoint.py --round N --catch-up   # install solutions/round1..N first
```

The checkpoint sets the level, resets the store, runs the round's attacks one after the other while the 40
shoppers run the `promo` scenario, and prints:

- **The scoreboard**: requests served and stopped per actor, and the gate's cost in milliseconds
  (`Server-Timing` on every response has the per-check split).
- **The shoppers table**: per persona, how many finished and how many a defense stopped.
- **The attacks**: vouchers obtained out of the attempts, and the top `X-Lab-Signals` that fired.
- **PASS or FAIL** against the round's expectations in `tools/checkpoint.py`, including which personas the round
  is *allowed* to hurt (`allowed_fp`). That list is the price of the layer.

`tools/verify.py` runs the same thing with its own in-process store on a free port (used for the table below).

---

## Round 1: cookie replay vs server-side state

| Step | Do | Expected |
|---|---|---|
| Before | `python tools/checkpoint.py --round 1 --level 0` | 20/20 vouchers from one unlock |
| Defend | Read `defenses/promo_state.py`; wire `1: [promo_state.CHECK]` in `ladder.py` | |
| After | `python tools/checkpoint.py --round 1` | 0/20: `promo_state:promo_not_unlocked` |
| Red | `python attacks/round1_cookie_replay.py --share` | 0/20: sharing the solved cookie across IPs does not help |

The attack decodes the `promo` cookie with no key and prints the flag in plain view: a signature proves the
server wrote the cookie once, not that it is the latest copy. **Discuss:** the store also keeps the session in
Redis already (the `sid` cookie). Why was *this* flag replayable when the cart is not? (The cart lives in Redis
under the session; the promo flag lived in the cookie. Keep decisions on the server.)

## Round 2: session reset vs creation velocity

| Step | Do | Expected |
|---|---|---|
| Before | `python tools/checkpoint.py --round 2 --level 1` | 30/30: a fresh session each time, each unlocked once |
| Defend | Read `defenses/session_velocity.py`; wire `2: [session_velocity.CHECK]` | |
| After | `python tools/checkpoint.py --round 2` | ~10/30: the first ~10 new sessions a minute get through |
| Red | `python attacks/round2_session_reset.py --rotate` | 30/30: one new session per residential IP looks like one new customer |

A per-session limit resets for free when the session does, so we limit session *creation* per IP. **Discuss
(blue stretch):** lower `MAX_NEW_SESSIONS_PER_MIN` to 3 and re-run. Watch the `mobile_cgnat` phones that share
one carrier address get caught. A limit sized for one person throttles a neighbourhood.

## Round 3: straight-to-redeem vs session signals

| Step | Do | Expected |
|---|---|---|
| Before | `python tools/checkpoint.py --round 3 --level 2` | 12/12: nothing reads the session yet |
| Defend | Read `defenses/session_guard.py`; wire `3: [session_guard.CHECK]` | |
| After | `python tools/checkpoint.py --round 3` | **FAIL**: the bot gets 0/12, but the `no_js` shopper is blocked too |
| Blue | `defenses/policy.py`: set `SESSION_POINTS["no_js_cookie"] = 25`; rerun | PASS: the no-JS human is monitored, the bot still 0/12 |
| Red | `python attacks/round3_straight_to_redeem.py --reimplement-js` | 12/12: beats each signal on its own |

The first run fails on purpose. A missing JS cookie weighted as a block (40) stops the one shopper who runs no
JavaScript. Drop it to 25 and it becomes "monitor": logged, not blocked. That is the business decision the signal
forces. **Discuss:** the re-implementer reads the nonce and waits 3.3 s. Which later chapter makes the JS
expensive to re-run (Chapter 7), and which makes it hard to re-implement (W2 Ch2)?

## Round 4: session minting vs identity binding

| Step | Do | Expected |
|---|---|---|
| Before | `python tools/checkpoint.py --round 4 --level 3` | 8/8: a minted session looks completely human |
| Defend | Read `session_guard.BINDING_CHECK`; wire `4: [session_guard.BINDING_CHECK]` | |
| After | `python tools/checkpoint.py --round 4` | 0/8: `session:ua_changed` on the hand-off |
| Red | `python attacks/round4_session_mint.py --copy-hints` | 8/8: copy the Client Hints and the identity hash stops moving |

Round 4 is the one to remember. The attacker drives a real browser to mint a clean session (landing, JavaScript,
age — every Round 3 signal genuine), then hands the cookies to a cheap HTTP client to redeem. The hand-off
forgets the browser's Client Hints, and the binding check sees the identity move. Copy the hints and it passes —
but note `launches_per_voucher` stays at 1: binding means **every** voucher now costs a full browser mint.
**Discuss:** the copy-hints hand-off scores 0 at the session layer. Name two signals from later chapters that
still tell it apart from Chrome (W2 Ch5 TLS/JA4; W2 Ch3 behavior; Chapter 7 makes each mint cost CPU).

## Debrief

1. Round 4's copy-hints hand-off wins. What did we actually win by forcing it? (The attacker's cost: one real
   browser per voucher instead of one line of Python.)
2. Which session signal has the highest false-positive risk for your own users, and who in your company decides
   whether to block or monitor it?
3. Every signal here is cheap and none is conclusive. Why is a weighted score with a logged reason better than
   any single rule?
4. The promo flag was replayable; the cart was not. State the one-sentence rule that separates them.

---

## Expected results (self-check)

Generated by `python tools/verify.py --all --catch-up --markdown`; do not edit by hand. Your numbers may differ
by a voucher or two depending on timing. The tables run every round on the reference solutions (Round 3 with
`no_js_cookie = 25`). Round 3 with the shipped policy (`python tools/checkpoint.py --round 3` before the blue
step) blocks the bot just as well but FAILs: the `no_js` shopper is stopped.

<!-- results:start -->
| Round | Attack | Before (level N-1) | After (level N) | Shoppers stopped after |
|---|---|---|---|---|
| 1 | `replay` | 20/20 vouchers | 0/20 | none |
|  | `replay_share` | 20/20 | 0/20 |  |
| 2 | `reset` | 30/30 | ~10/30 | none |
|  | `reset_rotate` | 30/30 | 30/30 |  |
| 3 | `straight` | 12/12 | 0/12 | none (with the blue step) |
|  | `reimplement_js` | 12/12 | 12/12 |  |
| 4 | `mint` | 8/8 | 0/8 | none |
|  | `mint_copy_hints` | 8/8 | 8/8 |  |

The number is vouchers the attack turned one unlock into. All 40 shoppers redeem in every round; no persona is
stopped on the reference solutions. The gate adds about 2 ms per request (`Server-Timing: gate;dur=…`): one Redis
`INCR` for velocity, one `HGET`/`HDEL` for the session. Round 4's numbers come from a real Chromium mint, so they
move by a browser launch or two between runs.

**Round 3, shipped policy** (`no_js_cookie = 40`, before the blue step): the bot is still stopped (`straight` 0/12),
but the `no_js` shopper is blocked too, so the round **FAILs** (`1 shoppers stopped who should not be:
human:no_js:00`). Setting `no_js_cookie = 25` makes it `monitor`: the no-JS human is logged and served, and the
round PASSes. That trade — catch one more kind of bot, or serve every human — is the lesson, not a bug.
<!-- results:end -->
