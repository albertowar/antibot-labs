# W2 Ch8 Lab: Multi-Layered Defense Architecture

Starts from: `workshops/02-proficient/starter/` (contract 1.7). Adds: the eight sensor layers, the veto chain, the risk score and response ladder, the correlation and campaign layers, a login collector with two challenge types, and the 200 customers the engines are measured on (see the block below).

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/attempt.py`
- `defenses/campaign.py`
- `defenses/correlation.py`
- `defenses/features.py`
- `defenses/netinfo_ch8.py`
- `defenses/sensor_automation.py`
- `defenses/sensor_behavior.py`
- `defenses/sensor_fingerprint.py`
- `defenses/sensor_headers.py`
- `defenses/sensor_honeypot.py`
- `defenses/sensor_net.py`
- `defenses/sensor_tls.py`
- `defenses/sensor_velocity.py`
- `defenses/sensors.py`
- `defenses/veto.py`
- `demo_site/ext/risk.py`
- `demo_site/ext/templates/risk/collector.html`
- `demo_site/static/js/risk.js`
- `tools/layer_report.py`
- `tools/personas_ch8.py`
- `tools/report.py`
- `tools/sweep.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** pre-written (level-style) lab, shadow mode plus 4 rounds. See `workshops/02-proficient/chapters/08-multi-layered-defense/chapter_08_content.md` (slides repo), section 8.5.

In W1 and the earlier W2 chapters you built one defense at a time. This lab puts eight of them in front of one login form and asks the question every production team eventually faces: **how do the layers decide together, and who pays when they get it wrong?**

You play the defender. Every defense is **pre-written**: you read it, switch the decision engine (`DEFENSE_LEVEL`), send the store's 200 simulated customers through the login, and read the bill: customers blocked, customers challenged, and the signals they paid for. Then you look at what the round's attacker shows the defender, score that profile against the engine you just deployed, and see why the previous engine missed it.

## Rules of engagement

- **Local only, enforced in code.** `tools/labclient.py` asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service URLs such as `REDIS_URL` and `DATABASE_URL` too). The store's edge accepts the lab headers only from loopback, and `app.run` binds `127.0.0.1`. Do not remove those checks.
- The lab ships **no attack scripts**: attackers are described by the signals they show, and `tools/sweep.py --signals` scores those profiles against your policy. Everything is synthetic: source addresses come from `data/world.json` (documentation ranges), the feeds in `data/feeds/` describe no real network, and the 200 customers are seed users (`user000@example.test` ...).
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

## Setup

```bash
python3.12 -m venv .venv && . .venv/bin/activate        # one venv per chapter, see the root README
pip install -r requirements.txt
python tools/doctor.py                                   # READY?
DEFENSE_LEVEL=0 python demo_site/app.py                  # http://127.0.0.1:5000 (SQLite + in-process Redis)
```

Port 5000 busy? `PORT=5050 python demo_site/app.py` and `export DEMO_URL=http://127.0.0.1:5050` in the shell you run tools from. The tools talk to the running store: leave it running in one terminal and use a second one for the commands below.

You do not restart the store between rounds. Every checkpoint sets its own level (`POST /lab/level`), and a change to a file in `defenses/` is picked up on the next request. To switch by hand: `curl -X POST localhost:5000/lab/level -H 'Content-Type: application/json' -d '{"level": 3}'`.

| Level | Decision engine | Where |
|---|---|---|
| 0 | **Shadow mode.** Every sensor reports and logs. Nothing is enforced | `defenses/sensors.py`, `policy.decide` |
| 1 | **Veto chain.** Any layer over its own line blocks | `defenses/veto.py` |
| 2 | **Risk score + response ladder.** One score; allow / proof of work / block. Refusals explain themselves | `defenses/policy.py` |
| 3 | + **Correlation layer**, and a block becomes indistinguishable from a wrong password | `defenses/correlation.py`, `policy.block_action` |
| 4 | + **Campaign layer**: a cluster that fails logins like a stuffing run gets a step-up code | `defenses/campaign.py` |

The eight sensors (`defenses/sensor_*.py`) run at every level. Each one is a small stand-in for a chapter you have already done (W1 Ch2-4 and Ch8; W2 Ch1-5), and each docstring starts with who it hurts by mistake. They only **report**: signals with points. What the signals mean is decided in `policy.decide()`, which is why the same sensors serve a veto chain, a score and a campaign rule. `defenses/ladder.py` wires the layers by level; every check runs only on the login action (`POST /login`, `POST /api/login`).

```
demo_site/ext/risk.py        collector slot, telemetry kind "risk", challenges "pow" and "step_up", refusal shaping
demo_site/static/js/risk.js  the page's collector and challenge handling (runs in your own browser)
defenses/                    sensors.py + sensor_*.py · veto.py · policy.py · correlation.py · campaign.py
                             features.py (telemetry -> features) · netinfo_ch8.py (feeds -> network kind) · attempt.py
tools/                       checkpoint.py · sweep.py · layer_report.py · personas_ch8.py · report.py
solutions/roundN/defenses/   the reference ladder.py and policy.py after Round N
```

Open `http://127.0.0.1:5000/login` in your own browser at any level: the page runs a tiny collector, solves the proof of work with WebCrypto, and asks for the code (read it at `/lab/mailbox/<email>`) when stepped up. Sign in as `user000@example.test`; the password is `python -c "import demo_site.seed as s; print(s.password_for(0))"`. (A real browser trips layers a simulated customer does not: a headless or automated one is refused at level 2, and the refusal tells you why.)

## How to measure a round

Finish every round with a **checkpoint**:

```bash
python tools/checkpoint.py --round <N>
```

```
Real customers (200 logins, level 2)
  blocked        1    0.5%
  challenged     4    2.0%   pow 4, step-up 0   (all solved: True)

  Who paid
    vpn+a11y+autofill        1/1   blocked 1
    tor+autofill             1/1   pow 1
    cgnat                    1/10  pow 1
    ...
  Signals they paid for: no_keystrokes 3, datacenter_asn 3, no_pointer 1, ...

Defender cost
  gate per login: median 2.66 ms, p95 4.97 ms over 200 logins
  proof-of-work: median 64 ms per challenged customer (Python; a browser's WebCrypto is faster)

Round 2 at level 2: PASS
```

What it reports:

- **Real customers:** `tools/personas_ch8.py` plays 200 seeded customers, **one at a time** so the per-address counters see the same order on every run: the numbers below are exact. Most are ordinary; the minorities each trip one weak signal for a legitimate reason: VPN, mobile CGNAT, privacy browser, Tor Browser, keyboard-only, password-manager autofill, an old device, a typo. Anyone blocked or challenged is a **false positive with a cost**, and the checkpoint names them. A customer who solves a challenge is *friction*, counted separately from *blocked*.
- **Defender cost:** the gate time of each customer's first sign-in (`Server-Timing`), and the proof-of-work solve time on the customer's side.
- **Pass/fail:** each level has a false-positive budget. Round 1 is *expected* to blow it (it must block between 5% and 25%). From Round 3 the checkpoint also proves that a block answers byte-for-byte like a wrong password, and Round 4 makes one cluster hot with a burst of failed logins and signs a real customer in through the step-up.
- `python tools/checkpoint.py --round N --level N-1` runs the same customers against the previous engine: the "before" column. It reports the numbers and then fails the shoppers-hurt check at Round 2, which is the point of the comparison, not a problem.

**Fell behind?** Every defense is already written, so catching up means running the round at its level: `python tools/checkpoint.py --round <N>` does that. `--catch-up` additionally installs `solutions/round1..N/defenses/ladder.py` and `policy.py` (your own copies are kept as `.bak`), which undoes your experiments with weights and thresholds; `python tools/checkpoint.py --restore` puts yours back.

---

## Round 0: Shadow mode

**Defend (look):** run the checkpoint at level 0 and read what each layer says about real customers.

```bash
python tools/checkpoint.py --round 0        # nothing blocked, nothing challenged
python tools/layer_report.py                # which layer fires on which customers
```

The report is the preview of Round 1: what each layer would block if it were allowed to decide alone.

**What the attacker shows you:** the naive credential stuffer from W2 Ch6, replayed in your head. An HTTP library's User-Agent and TLS stack, no `Accept-Language`, no page JavaScript, a cloud address, six attempts a minute. Score it:

```bash
python tools/sweep.py --signals http_library_ua,missing_browser_headers,ja4_non_browser,datacenter_asn,no_telemetry,ip_burst
```

Several layers would each veto it on their own. In shadow mode it is allowed and logged; that is what shadow mode is for.

---

## Round 1: The veto chain, then the attacker who stays under every line

| Step | Do | Expected |
|---|---|---|
| Defend | Read `defenses/veto.py` and the `level == 1` branch of `policy.decide` | - |
| Checkpoint | `python tools/checkpoint.py --round 1` | **16/200 real customers blocked (8.0%)**: every VPN user, every privacy browser, every keyboard-only user, the Tor user. Vetoed by `net` 9, `behavior` 3, `fingerprint` 3, `velocity` 1 |
| Attacker | `python tools/sweep.py --signals ja4_ua_mismatch,header_order_mismatch,outdated_browser,ip_elevated,timing_too_regular` | `veto chain: allow` / `risk score: 80 points -> block` |

The attacker's operator never saw your code. They saw 403s, fixed one thing at a time, and stopped the moment the 403s stopped: a mismatched TLS stack *just* under the TLS line, header oddities *just* under the headers line, a timer-driven pointer *just* under the behaviour line. Five weak signals at once, and no layer is allowed to add them up.

**Discuss:** the layers' false positives barely overlap, so the union is close to their sum. Which customers are over two layers' lines at once? (`python tools/layer_report.py` after a Round 0 run lists each layer's signals and who carries them.)

*Model answer.* Two of the 16: the VPN user who is also keyboard-only (`net` and `behavior`) and the Tor user with a password manager (`net` and `fingerprint`); the "Vetoed by" line credits each to the first layer in the chain only. Layers overlap little because each is tuned on its own slice of "odd": that is why a chain of independent vetoes costs roughly the sum of what each one costs.

---

## Round 2: Risk score and response ladder, then the leaky verdict

| Step | Do | Expected |
|---|---|---|
| Defend | Read `defenses/policy.py`, then `python tools/checkpoint.py --round 2` | blocked **1** (0.5%), challenged **4** (2.0%, all proof of work) |
| Attacker, before | `python tools/sweep.py --signals ja4_ua_mismatch,header_order_mismatch,outdated_browser,ip_elevated,timing_too_regular` | `80 points -> block`, and the 403 body lists the reasons with their points |
| Attacker, after | `python tools/sweep.py --signals ip_elevated,timing_too_regular` | `30 points -> challenge (pow)`: the solver costs the bot CPU, then it is in |

Round 1's bot is caught: the score adds up what no layer could. Then read the 403 the way its operator does: at levels 1 and 2 a refusal explains itself (`score`, `layer`, `reasons`; the lab does this on purpose, never do it in production). It names the cheap fixes, leaves two signals worth 30, and the ladder's middle rung is a *cost*, not a verdict. A proof of work stops the lazy and taxes the determined; that is all it is for.

**Exercises** (`TODO (Round 2)` in `policy.py`; run a checkpoint first so the sweep has a log):

1. After a Round 4 checkpoint, `python tools/sweep.py` prints the blocked/challenged grid for other thresholds. Find the cell that blocks nobody and challenges at most 2%. What do you give up?
2. `python tools/sweep.py --signal tor_exit`: one customer carries it. `--weight tor_exit=40` shows what the grid does to them. Why does the shipped policy use 30?
3. The one customer still blocked is a VPN user who is also keyboard-only with a password manager (25 + 25 + 10). Is that the right call for a login form? For a checkout?

*Model answers.* (1) Challenge at 40 or 50 and block at 80 or 100 blocks nobody and challenges 2.0% or 1.5%, but nothing under 80 points is stopped any more, and the narrow band left for challenges is what made Round 2's attacker pay. (2) The Tor customer carries `tor_exit` (30) + `fp_randomized` (15) + `no_keystrokes` (10) = 55, a challenge; at 40 it is 65, a block. Every Tor Browser user randomizes the canvas, so 40 would block all of them, which is a policy choice you should make on purpose and not by tuning one number. (3) On a login a challenge or a step-up is the better answer than a block; on a checkout, where the unit is money and the account may be new, a harder rung is defensible. What you cannot defend is not knowing the person exists: log who was blocked.

---

## Round 3: Opaque responses and correlation, then the clean-looking session

| Step | Do | Expected |
|---|---|---|
| Defend | Read `shape_refusal()` in `demo_site/ext/risk.py` and `defenses/correlation.py`, then `python tools/checkpoint.py --round 3` | blocked **1** (0.5%, shown as *Wrong email or password*), challenged **9** (4.5%): every VPN user now carries `tz_geo_mismatch` (+10) and lands on the proof of work |
| Attacker | `python tools/sweep.py --signals telemetry_replay` and `--signals fp_reuse` | `60 -> block` and `30 -> challenge (pow)`, from sessions that show **no per-request signal at all** |

Two changes. First, a block now returns the exact bytes of a wrong password: the operator's probe loop learns nothing from it. (The gate lets the route run, `shape_refusal()` turns whatever it returned into the 401 and takes any session back. The checkpoint proves the bodies are identical.) Second, the correlation layer asks what no sensor can: has this *exact* behaviour trace been seen before (a captured "good" sensor blob, replayed), has this device fingerprint come from four IPs in ten minutes, does the browser's time zone sit on the IP's continent?

**Discuss:** the VPN customers' rate of being stopped went from 3 of 8 (1 blocked, 2 challenged) to all 8 (7 challenged, 1 blocked) for a +10 signal. Is `tz_geo_mismatch` worth it? What would you need to log to answer that with data instead of opinion?

*Model answer.* On its own it never changes an outcome; it matters when it tips a borderline score, and here it does so for every VPN customer. Keep it only if the log shows it also tipped bots: log the final action for requests where removing the signal would change the band, and the bot or human label from your later review (chargebacks, takedowns). If it only ever tips people, drop it to 0.

**What this round still misses:** a session that is fresh everywhere, with a new trace, new fingerprint and new address every time, shows zero signals. Per-request scoring has nothing left to score.

---

## Round 4: Campaign layer, then low and slow

| Step | Do | Expected |
|---|---|---|
| Defend | Read `defenses/campaign.py`, then `python tools/checkpoint.py --round 4` | same bill as Round 3: blocked 1, challenged 9, **step-up 0**. Real customers fail about one login in ten, so no cluster goes hot. The hot-cluster probe at the end signs a customer in through the emailed code |
| Collateral | `python tools/sweep.py --clusters` | 40 clusters; the largest holds **19** real customers (11% failing). If it went hot, all 19 would be stepped up |
| Attacker | `python tools/sweep.py --signals campaign_cluster` | `challenge (step_up)`: the operator does not own the victims' inboxes, and the response is identical for unknown accounts |

A stuffing run fails most of its logins, because most of its list are not your customers. The campaign layer stops judging requests and judges the thing the operator's tooling holds constant while it rotates everything else: TLS stack, device family, provider ASN. Over `MIN_ATTEMPTS` attempts with a failure ratio over `FAIL_RATIO`, and every login in that cluster is stepped up. Counting failures means checking the password for requests you are about to challenge or block, so this level pays one more password hash per login: watch the gate cost double in the checkpoint.

**Exercises** (`TODO (Round 4)` in `campaign.py` and `policy.py`):

1. Lower `MIN_ATTEMPTS` to 4 and rerun the checkpoint. Still zero step-ups? Now also set `FAIL_RATIO = 0.2`. How many customers are stepped up, and who are they?
2. Set `CAMPAIGN_ACTION = "block"` and reason it through: what does the largest cluster's 19 customers see during an attack?

*Model answers.* (1) With `MIN_ATTEMPTS = 4` alone: still zero, because no cluster reaches a 50% failure ratio once it has four attempts. With 4 and 0.2, **19 customers** are stepped up, 15 of them *typical* customers with a clean score, and 14.0% of the population is now challenged: a threshold tight enough to catch a slow run is tight enough to tax the people who mistype. (2) They see "Wrong email or password" for as long as the window lasts and cannot tell why; a support ticket cannot be answered from what they know. Block only if you can afford that for the largest cluster, which is why the default is a step-up.

**What this round still misses:** a run that keeps each cluster under `MIN_ATTEMPTS`, at a human's pace, spread across many providers and device families, is below the floor of this stack. That residual is real. It is why W2 Ch6's account-side controls (breached-password checks, passkeys, MFA by default) exist, why W3 Ch3 moves detection to streams over longer windows, and what the Chapter 9 capstone throws at you with real browsers.

---

## Debrief

```bash
python tools/checkpoint.py --round 4
python tools/sweep.py --signal no_keystrokes       # the largest minority you nearly charged for a password manager
```

- Fill in the scoreboard: for each level, real customers blocked and challenged, and the attacker profile that the level catches.
- Which signal cost real customers the most across all rounds? Was it ever decisive on its own?
- The gate costs a few milliseconds. Which part of *this* app's login costs more? (The password hash, which runs even for requests you block. Why?)

---

## Expected results (self-check)

Verified on 2026-10-15 (re-based onto contract 1.7) with Python 3.12, Flask 3.1.3 and the `memory://` store; the same counts came out of the compose path (Redis 8.10, PostgreSQL 18.6). The counts are unchanged from the 1.5 build; the gate medians dropped a little (the 1.7 starter's `memory://` token bucket no longer serializes threads in Lua). The population is seeded and runs one customer at a time, so the counts are exact; gate timings vary with the machine. Regenerate the lines with `python tools/checkpoint.py --all --markdown` (each round ends in a `README row:` line).

| `DEFENSE_LEVEL` | Real customers blocked | Challenged | Who | Gate median (memory / Redis + PostgreSQL) |
|---|---|---|---|---|
| 0 | 0 | 0 | - | 2.6 / 4.2 ms |
| 1 | **16 (8.0%)** | 0 | all 8 VPN customers, 3 more keyboard-only, all 3 privacy browsers, the Tor user, 1 CGNAT | 2.3 / 3.4 ms |
| 2 | 1 (0.5%) | 4 (2.0%, all proof of work) | blocked: vpn + keyboard-only + autofill · PoW: tor, CGNAT, vpn x2 | 2.3 / 3.4 ms |
| 3 | 1 (0.5%, deceptive) | 9 (4.5%, all proof of work) | + every VPN user (`tz_geo_mismatch`) | 3.0 / 4.3 ms |
| 4 | 1 (0.5%, deceptive) | 9 (4.5%), step-up 0 | unchanged; no cluster is hot | 7.6 / 11.6 ms |

Attacker profiles, as scored by `tools/sweep.py --signals`:

| Round | Profile the defender sees | Veto chain | Score |
|---|---|---|---|
| 0 | `http_library_ua, missing_browser_headers, ja4_non_browser, datacenter_asn, no_telemetry, ip_burst` | block (net) | 235 -> block |
| 1 | `ja4_ua_mismatch, header_order_mismatch, outdated_browser, ip_elevated, timing_too_regular` | **allow** | 80 -> block |
| 2 | `ip_elevated, timing_too_regular` | allow | 30 -> **challenge (pow)** (solved) |
| 3 | `telemetry_replay` / `fp_reuse` | allow | 60 -> block / 30 -> challenge (pow) |
| 4 | `campaign_cluster` | allow | -> **challenge (step_up)** |

Things to watch for:

- **The step-up never fires on the population.** That is correct: real customers do not fail half their logins. The checkpoint exercises it with a probe (a burst of failed logins from one cluster, then a real customer in that cluster who completes the emailed code); the exercise above shows what a tighter threshold costs.
- **Round 2 "before".** `--round 2 --level 1` fails the shoppers-hurt check on purpose: those are the 16 customers Round 1 blocked.
- **Redis vs. memory.** The counts are identical; the gate cost is higher on a real Redis (a few round trips per login), and the checkpoint's cost ceiling is 20 ms in memory, 250 ms on Redis.
- If someone edits a weight and the checkpoint fails, `tools/sweep.py` replays the log against the shipped thresholds without restarting anything.

## Docker path (optional)

```bash
docker compose up -d --wait        # Redis 8.10 + PostgreSQL 18.6 on 127.0.0.1
export REDIS_URL=redis://127.0.0.1:6379/0 DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop
python demo_site/app.py
docker compose down -v             # stop and wipe
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `Store not reachable on http://127.0.0.1:5000` | Start it: `python demo_site/app.py` (leave it running; use a second terminal for the tools) |
| Port 5000 already in use (macOS: the AirPlay Receiver uses it) | `PORT=5050 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:5050` in the shell you run tools from |
| No Docker | Nothing to do: the default `REDIS_URL=memory://` works in one process. The point of Redis is that two app servers would share the counters |
| The sweep says "No logged human logins" | Run a checkpoint first: the sweep replays its log. `curl -X POST localhost:5000/lab/reset` wipes it |
| `sweep --clusters` says there are no cluster keys | They exist from level 4: run `python tools/checkpoint.py --round 4` |
| A round fails after you edited a file | `python tools/checkpoint.py --restore` puts the shipped files back if `--catch-up` replaced them; otherwise compare with `solutions/round<N>/defenses/` |
| `python tools/verify.py` | The in-process harness the repo's CI uses (`--round N`, `--smoke`, `--all`): same store, free port, no second terminal |

## Bonus challenges

1. **Per-endpoint policy.** `policy.decide()` has one set of thresholds. Give `/login` and a hypothetical `/checkout` different ones, and argue which should be stricter.
2. **Positive signals.** Add a `trusted_device` signal that *subtracts* points when the fingerprint hash matches the account's last successful login. What does `--clusters` look like once most customers carry it?
3. **Fail-open or fail-closed?** Stop Redis while the app runs. Decide per layer what should happen, implement it, and write the one-line justification each choice deserves.
