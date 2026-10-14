# Chapter 2 Lab: Make Volume Cost Something

Starts from: workshops/01-initiation/starter/ (contract 1.3). Adds: seven rate-limiting checks (`flood_monitor`, `fixed_window`, `sliding_window`, `rate_limit`, `endpoint_limit`, `account_limit`, `trusted_proxy`, `prefix_limit`) wired one round at a time, a trusted-proxy client-IP helper shared byte-for-byte with Chapter 3, five attack scripts on one shared scraper and a login helper, an offline limiter comparator, and the Chapter 2 shoppers.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/account_limit.py`
- `defenses/client_ip.py`
- `defenses/endpoint_limit.py`
- `defenses/fixed_window.py`
- `defenses/flood_monitor.py`
- `defenses/prefix_limit.py`
- `defenses/rate_limit.py`
- `defenses/sliding_window.py`
- `defenses/trusted_proxy.py`
- `tools/ipkit.py`
- `tools/limiter_lab.py`
- `tools/personas_ch2.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** setup, 5 rounds of attack and defense, then a debrief. See `../chapter_02_content.md`, section 2.14.

**This lab is wire-it.** Each round you read one defense module (its docstring says what it catches, what it misses and
who it hurts), fill in its short `TODO (Round N)`, wire it into `defenses/ladder.py`, and run the checkpoint. The reference
version of every file lives in `solutions/roundN/`. **Fell behind?** `python tools/checkpoint.py --round N --catch-up`
installs the reference files for rounds 1..N (your files are kept as `.bak`); `python tools/checkpoint.py --restore` puts
yours back.

You play both sides. The attacker wants the catalog (`GET /api/products/<sku>`, all 120) or a working login, and every round
it changes *how fast* or *from where* it comes: a flat flood, a boundary burst, a patient trickle, a rotating fleet, a
forged header, a residential proxy network. Every round you add one rate-limiting layer and measure two numbers:

- how much the attacker still got;
- which of the 40 simulated shoppers your layer stopped. Phones behind carrier NAT look suspicious to any per-IP limit, and
  the scoreboard shows them next to the bots.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`, which asks
  `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service URLs such as
  `REDIS_URL` too). The store's edge accepts the lab headers only from loopback. Do not remove that check.
- **Everything is synthetic.** Every source address is a documentation address (RFC 5737, RFC 3849) rented from
  `data/world.json` and sent in `X-Lab-Client-IP`; every account and password is seeded by `demo_site/seed.py`. No proxy,
  VPN or real credential is ever used. The "cloud fleet", "IPv6 VPS" and "residential proxy network" are addresses the store
  *pretends* to see.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  defenses/flood_monitor.py   Round 1: count per IP, tag the monitor band, block nothing
  defenses/fixed_window.py    Round 2: INCR + EXPIRE per (IP, clock window)
  defenses/sliding_window.py  Round 3 (alternative): two blended windows, no boundary
  defenses/rate_limit.py      Round 3: per-IP token bucket (shared with Chapter 3)
  defenses/endpoint_limit.py  Round 4: a tight login_ip bucket on POST /login
  defenses/account_limit.py   Round 4: attempts per target account, any address
  defenses/client_ip.py       which IP? naive until trusted_proxy is wired, then from the right (shared with Chapter 3)
  defenses/trusted_proxy.py   Round 5: read X-Forwarded-For from the right (shared with Chapter 3)
  defenses/prefix_limit.py    Round 5: per-/24 and per-/64 buckets (shared with Chapter 3)
  defenses/ladder.py          YOUR FILE: wire one round at a time
  defenses/policy.py          the numbers: RATE_LIMITS, FIXED_WINDOW, ACCOUNT_LIMIT, XFF_POINTS, ...
  attacks/                    round1_flood ... round5_residential (scrapes on tools/ipkit.py, logins on attacks/_common.py)
  tools/                      checkpoint.py · ipkit.py (shared scraper) · limiter_lab.py (offline comparator) · personas_ch2.py
  solutions/round1..5/        reference check modules + ladder.py per round (the catch-up files)
```

The rest of the store (catalog, cart, checkout, accounts, the simulated edge, the decision log) is the Workshop 1 starter,
unchanged. Its contract is `workshops/STORE_CONTRACT.md`.

---

## Setup

Setup is covered once for the whole series in `onboarding/setup/PREWORK.md`. For this lab:

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt                         # one venv per chapter
python tools/doctor.py                                  # READY?
python demo_site/app.py                                 # http://127.0.0.1:5000
```

No Docker is needed (SQLite and an in-process Redis; this lab's `requirements.txt` adds fakeredis's `[lua]` extra because
the token bucket is a Lua script). With Docker, `docker compose up -d --wait` starts Redis 8.10 and PostgreSQL 18 as in the
starter README. Port 5000 busy? `PORT=8099 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:8099` in the
shell where you run attacks and tools.

You never restart the store between rounds: edits to `defenses/*.py` are picked up on the next request, and the checkpoint
sets the level (`POST /lab/level`). Restart only after editing `demo_site/ext/`.

**Look around while you work:**

```bash
python tools/limiter_lab.py                                               # the four algorithms on one trace, no waiting
curl -s localhost:5000/whoami | python -m json.tool                       # what the edge says about you (xff_claimed too)
curl -s 'localhost:5000/lab/decisions?actor=bot:&limit=5' | python -m json.tool
```

Every response carries `X-Lab-Verdict`, `X-Lab-Score`, `X-Lab-Signals`, `Retry-After` (on a 429) and `Server-Timing` (the
per-check gate cost). They tell the attacker exactly what tripped: never send them in production (`LAB_HEADERS=0`).

**There is no challenge type in this chapter.** CAPTCHAs arrive in Chapter 6 and proof of work in Chapter 7. The rate limits
answer `429`; the monitor in Round 1 answers nothing at all.

## How to measure a round

```bash
python tools/checkpoint.py --round N              # level N: your defenses
python tools/checkpoint.py --round N --level N-1  # the same attacks against the previous level: the "before"
python tools/checkpoint.py --round N --catch-up   # install solutions/round1..N first
```

The checkpoint sets the level, resets the store, runs the round's attacks one after another while the 40 shoppers shop (the
`rush` scenario, and `rush_login` once logins matter — the starter's journey with every pause cut to a fifth, so the phones
sharing one CGNAT address really meet the per-IP limit), and prints PASS/FAIL against the thresholds, with the shoppers your
layer stopped shown next to the bots.

## Rounds

| Round | Defense (level) | Attack | Expected at its level |
|---|---|---|---|
| 1 | `flood_monitor` (watch only) | `round1_flood.py` · `--login` | both full; flood tagged, nothing blocked |
| 2 | `fixed_window` | `round1_flood.py` (flood) · `round2_boundary.py` | flood capped (~16%), boundary ~2× the limit |
| 3 | `rate_limit` token bucket | `round2_boundary.py` · `round3_paced_login.py` | boundary capped, patient client full (slow) |
| 4 | `endpoint_limit` + `account_limit` | `round1_flood.py --login` · `round4_rotate.py` (`--brute`, `--xff`, `--pool cloud_v6`) | login flood partial, brute blocked, rotate/xff/v6 full |
| 5 | `trusted_proxy` + `prefix_limit` | `round4_rotate.py --xff` · `--pool cloud_v6` · `round4_rotate.py` · `round5_residential.py` | xff capped at burst, v6 bitten, fleet & residential full → Chapter 3 |

---

## Expected results (self-check)

Generated by `python tools/verify.py --all --catch-up --markdown`; do not edit by hand. Your numbers may differ by a few
requests depending on timing — the CGNAT count in particular moves by one or two between runs with how the phones' requests
overlap.

The `gate ms` column grows from ~1 ms in Round 1 to 100-200 ms in Round 5. That is almost all queueing: the store, its
in-process Redis and the 40 shoppers share one Python process while several attacks run eight threads each. On its own, one
request through all of Round 5's checks costs about 2 ms (`Server-Timing`); the token buckets are the expensive part,
because each is a Redis round trip.

<!-- results:start -->
| Round | Attack | Before (level N-1) | After (level N) | Shoppers stopped after |
|---|---|---|---|---|
| 1 | `flood` | 120/120 | 120/120 | none (monitor blocks nothing) |
|   | `login_flood` | 30/30 | 30/30 |  |
| 2 | `flood` | 120/120 | 19/120 | none |
|   | `boundary` | 40/40 | 40/40 |  |
| 3 | `boundary` | 40/40 | 21/40 | mobile_cgnat 4 |
|   | `paced_login` | 30/30 | 30/30 |  |
| 4 | `login_flood` | 19/30 | 10/30 | mobile_cgnat 2 |
|   | `brute` | 59/60 | 4/60 |  |
|   | `rotate` | 29/30 | 30/30 |  |
|   | `xff` | 120/120 | 120/120 |  |
|   | `v6` (`--pool cloud_v6`) | 120/120 | 120/120 |  |
| 5 | `xff` | 120/120 | 19/120 | mobile_cgnat 2 |
|   | `v6` (`--pool cloud_v6`) | 120/120 | 16/120 |  |
|   | `fleet` (`round4_rotate.py`) | 30/30 | 30/30 |  |
|   | `residential` | 120/120 | 120/120 |  |

`mobile_cgnat` is the round's accepted false positive from Round 2 on: a per-IP limit cannot tell six phones behind one
carrier-NAT address from one busy client. No other shopper is ever stopped. `rotate`, `xff` (at Round 4), `fleet` and
`residential` staying full is the point, not a failure: rate limiting has run out of road, and Chapter 3 picks them up.

<details><summary>Round 1 scoreboard (naive flood vs a monitor, level 1: PASS)</summary>

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:r1_flood | 121 | 121 | 0 | 0 | 10.1 | 1.18 |
| bot:r1_login_flood | 31 | 31 | 0 | 0 | 20.0 | 3.93 |
| human:autofill | 6 | 6 | 1 | 0 | 0.0 | 3.53 |
| human:consumer_vpn | 18 | 18 | 3 | 0 | 0.0 | 3.12 |
| human:home | 144 | 144 | 24 | 0 | 0.0 | 2.78 |
| human:mobile_cgnat | 48 | 48 | 8 | 0 | 0.0 | 2.69 |
| human:no_js | 6 | 6 | 1 | 0 | 0.0 | 3.23 |
| human:old_chrome | 6 | 6 | 1 | 0 | 0.0 | 2.09 |
| human:private_relay | 12 | 12 | 2 | 0 | 0.0 | 3.78 |
Bots stopped: **0/152** requests · shoppers hurt: **0/40** people · purchases: {'human': 40}

</details>

<details><summary>Round 2 scoreboard (boundary burst vs a fixed window, level 2: PASS)</summary>

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:r1_flood | 121 | 20 | 0 | 101 | 0.0 | 1.41 |
| bot:r2_boundary | 41 | 40 | 0 | 1 | 0.0 | 2.59 |
| human:mobile_cgnat | 48 | 48 | 8 | 0 | 0.0 | 3.44 |
| human:home | 144 | 144 | 24 | 0 | 0.0 | 3.58 |
Bots stopped: **102/162** requests · shoppers hurt: **0/40** people · purchases: {'human': 40}

</details>

<details><summary>Round 3 scoreboard (patient client vs a token bucket, level 3: PASS)</summary>

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:r2_boundary | 23 | 21 | 0 | 2 | 0.0 | 3.13 |
| bot:r3_paced_login | 40 | 31 | 0 | 9 | 0.0 | 7.73 |
| human:mobile_cgnat | 36 | 32 | 4 | 4 | 0.0 | 7.62 |
| human:home | 144 | 144 | 24 | 0 | 0.0 | 6.57 |
Bots stopped: **11/63** requests · shoppers hurt: **4/40** people (all mobile_cgnat) · purchases: {'human': 36}

</details>

<details><summary>Round 4 scoreboard (rotation & brute force vs endpoint & account keys, level 4: PASS)</summary>

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:r1_login_flood | 31 | 11 | 0 | 20 | 0.0 | 8.79 |
| bot:r4_brute | 61 | 4 | 0 | 57 | 0.0 | 18.13 |
| bot:r4_cloud_v6 | 120 | 120 | 0 | 0 | 0.0 | 104.52 |
| bot:r4_rotate | 31 | 30 | 0 | 1 | 0.0 | 9.01 |
| bot:r4_xff | 121 | 121 | 0 | 0 | 0.0 | 47.02 |
| human:mobile_cgnat | 34 | 32 | 0 | 2 | 0.0 | 9.34 |
| human:home | 120 | 120 | 0 | 0 | 0.0 | 29.43 |
Bots stopped: **78/364** requests · shoppers hurt: **2/40** people (mobile_cgnat) · purchases: {}

</details>

<details><summary>Round 5 scoreboard (spoofed headers & rotation vs trusted proxy & prefix keys, level 5: PASS)</summary>

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:r4_cloud_v6 | 120 | 16 | 0 | 104 | 0.0 | 213.02 |
| bot:r4_rotate | 31 | 31 | 0 | 0 | 1.3 | 17.82 |
| bot:r4_xff | 121 | 20 | 0 | 101 | 1.6 | 97.4 |
| bot:r5_residential | 120 | 120 | 0 | 0 | 0.0 | 186.84 |
| human:mobile_cgnat | 35 | 33 | 0 | 2 | 0.0 | 107.54 |
| human:home | 120 | 120 | 0 | 0 | 0.0 | 125.14 |
Bots stopped: **205/392** requests · shoppers hurt: **2/40** people (mobile_cgnat) · purchases: {}

</details>
<!-- results:end -->

## Troubleshooting

- **`unknown command 'EVALSHA'`** — the token bucket is a Lua script and your fakeredis is missing the `[lua]` extra.
  `pip install -r requirements.txt` installs `fakeredis[lua]`.
- **A round FAILs with "expected blocked, got 16%"** — a limiter lets its burst through, so a 120-request scrape against a
  burst of 20 floors at ~17%. That is `partial`, not `blocked`; it is the expected shape, not a bug.
- **Everything passes at level 0** — you have not wired the round into `defenses/ladder.py`, or the store did not reload.
  Edits to `defenses/*.py` load on the next request; restart only after editing `demo_site/ext/`.
