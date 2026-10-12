# Chapter 8 Lab: Multi-Layered Defense Architecture

**Format:** shadow mode plus 4 rounds. See `../chapter_08_content.md`, §8.5.

In W1 and the earlier W2 chapters you built one defense at a time. This lab puts eight of them in front of one login form and asks the question every production team eventually faces: **how do the layers decide together, and who pays when they get it wrong?**

You play the defender. Each round you switch the decision engine (`DEFENSE_LEVEL`), send the store's 200 simulated customers through the login, and read the bill: customers blocked, customers challenged, and the signals they paid for. Then you look at what the round's attacker shows the defender, score that profile against the engine you just deployed, and see why the previous engine missed it.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- The lab ships **no attack scripts**: attackers are described by the signals they show, and `tools/sweep.py --signals` scores those profiles against your policy. Every address, name and password here is synthetic.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  docker-compose.yml   Redis 8 for the shared counters (optional; REDIS_URL=memory:// works too)
  world.json           the simulated internet: documentation IP ranges, ASNs, JA4 values
  demo_site/           app.py (login + pipeline), edge.py (simulated CDN edge), users.py (300 customers)
  defenses/sensors/    net · headers · tls · velocity · honeypot · automation · fingerprint · behavior
  defenses/            veto (R1) · policy + ladder (R2) · correlation (R3) · campaign (R4) · pipeline · store
  tools/               checkpoint · layer_report · sweep · population · labclient
```

---

## Setup

```bash
cd lab
docker compose up -d --wait                 # Redis on 127.0.0.1:6379 (skip: see troubleshooting)
python -m venv .venv && source .venv/bin/activate      # one venv per chapter, see the root README
pip install -r requirements.txt
```

Start the demo site, and restart it with a new `DEFENSE_LEVEL` each round:

```bash
cd demo_site
DEFENSE_LEVEL=0 python app.py               # http://localhost:5000
```

| Level | Decision engine | Module |
|---|---|---|
| 0 | **Shadow mode.** Every sensor scores and logs. Nothing is enforced | `defenses/pipeline.py` |
| 1 | **Veto chain.** Any layer over its own line blocks | `defenses/veto.py` |
| 2 | **Risk score + response ladder.** One score; allow / proof-of-work / block. Blocks explain themselves | `defenses/policy.py`, `defenses/ladder.py` |
| 3 | + **Correlation layer**, and blocks become indistinguishable from a wrong password | `defenses/correlation.py` |
| 4 | + **Campaign layer**: a cluster that fails logins like a stuffing run gets a step-up code | `defenses/campaign.py` |

The eight sensors in `defenses/sensors/` run at every level. Each one is a small stand-in for a chapter you have already done (W1 Ch1–3, Ch7; W2 Ch1–5), and each docstring starts with who it hurts by mistake.

Open `http://localhost:5000/login` in your own browser at any level: the page runs a tiny collector, solves the proof-of-work with WebCrypto, and asks for the code (read it at `/lab/mailbox/<email>`) when stepped up. Sign in as `user000@example.test` with the password that `python -c "import demo_site.users as u; print(u.password(0))"` prints.

**Troubleshooting**

| Problem | Fix |
|---|---|
| Port 5000 already in use (macOS: the AirPlay Receiver uses it) | `PORT=5050 DEFENSE_LEVEL=… python app.py`, then `export DEMO_URL=http://localhost:5050` in the shell you run tools from |
| No Docker | `export REDIS_URL=memory://` before starting the app. Everything works the same in one process; the point of Redis is that two app servers would not |
| `Cannot reach Redis` | `docker compose ps` must show the container as `healthy` |
| Fresh counters and log | `curl -X POST localhost:5000/lab/reset` (the checkpoint does this for you) |

---

## How to measure a round

Finish every round with a **checkpoint**:

```bash
python tools/checkpoint.py --round <N>
```

```
=== Checkpoint: Round 2 (server at DEFENSE_LEVEL=2, store redis) ===

Real customers (200 logins)
  blocked        1    0.5%
  challenged     6    3.0%   pow 6, step-up 0
  what they saw: blocked 1, invalid 8, ok 191

  Who paid
    vpn                      2/7   pow 2
    tor+a11y                 1/1   block 1
    …
  Signals they paid for: tor_exit 3, fp_randomized 3, no_keystrokes 3, datacenter_asn 3, …

Defender cost
  pipeline: median 0.10 ms, p95 0.18 ms per login
  proof-of-work: median 51 ms per challenged customer

✅ Round 2 checkpoint passed.
```

What it reports:

- **Real customers:** `tools/population.py` plays 200 seeded customers. Most are ordinary; the minorities each trip one weak signal for a legitimate reason: VPN, mobile CGNAT, privacy browser, Tor Browser, keyboard-only, password-manager autofill, an old device, a typo. Anyone blocked or challenged is a **false positive with a cost**, and the checkpoint names them.
- **Defender cost:** pipeline time per login (from `Server-Timing`), and the proof-of-work solve time on the customer's side.
- **Pass/fail:** each level has a false-positive budget. Round 1 is *expected* to blow it.

**Fell behind?** Every defense is already written. Catching up means restarting the demo site with `DEFENSE_LEVEL=<N>`.

---

## Round 0: Shadow mode

**🛡️ Defend (look):** start at `DEFENSE_LEVEL=0`, then:

```bash
python tools/checkpoint.py --round 0        # nothing blocked, nothing challenged
python tools/layer_report.py                # what each layer says about real customers
```

The report's second table is the preview of Round 1: what each layer would block if it were allowed to decide alone, the sum of those slices, and their union.

**🗡️ What the attacker shows you:** the naive credential stuffer from W2 Ch6, replayed in your head. An HTTP library's User-Agent and TLS stack, no `Accept-Language`, no page JavaScript, a cloud address, six attempts a minute. Score it:

```bash
python tools/sweep.py --signals http_library_ua,missing_browser_headers,ja4_non_browser,datacenter_asn,no_telemetry,ip_burst
```

Five layers would each veto it on their own. In shadow mode it is allowed and logged; that is what shadow mode is for.

**Checkpoint:** `python tools/checkpoint.py --round 0`.

---

## Round 1: The veto chain ⚔️ staying under every line

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | Read `defenses/veto.py`, then restart with `DEFENSE_LEVEL=1` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | **21/200 real customers blocked (10.5%)**: every VPN user, every privacy browser, every Tor user, the keyboard-only user. Vetoed by `net` 12, `fingerprint` 8, `behavior` 1 |
| 🗡️ Attacker | `python tools/sweep.py --signals ja4_ua_mismatch,header_order_mismatch,outdated_browser,ip_elevated,timing_too_regular` | `veto chain: allow` · `risk score: 80 points -> block` |

The attacker's operator never saw your code. They saw 403s, fixed one thing at a time, and stopped the moment the 403s stopped: a mismatched TLS stack *just* under the TLS line, header oddities *just* under the headers line, a timer-driven pointer *just* under the behaviour line. Five weak signals at once, and no layer is allowed to add them up.

**Discuss:** the union of the layers' false positives was 10.5%. Why is it less than the 12.5% sum? Which customers tripped two layers?

---

## Round 2: Risk score + ladder ⚔️ the leaky verdict

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | Read `defenses/policy.py` and `defenses/ladder.py`, then restart with `DEFENSE_LEVEL=2` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | blocked **1** (0.5%), challenged **6** (3.0%) · pipeline p95 ≈ 0.2 ms · PoW ≈ 50 ms |
| 🗡️ Attacker, before | `python tools/sweep.py --signals ja4_ua_mismatch,header_order_mismatch,outdated_browser,ip_elevated,timing_too_regular` | `block`, and the 403 body lists all five reasons with their points |
| 🗡️ Attacker, after | `python tools/sweep.py --signals ip_elevated,timing_too_regular` | `30 points -> pow`: the browser-side solver costs the bot 50 ms of CPU, then it is in |

Round 1's bot is caught: the score adds up what no layer could. Then read the 403 the way its operator does. It names the three cheap fixes (a current browser's header set, a matching TLS stack), leaves two signals worth 30, and the ladder's middle rung is a *cost*, not a verdict. A proof-of-work stops the lazy and taxes the determined; that is all it is for.

**Exercises** (`TODO (Round 2)` in `policy.py`):

1. `python tools/sweep.py` prints the blocked/challenged grid for other thresholds. Find the cell that challenges fewer than 2% and blocks nobody. What do you give up?
2. `python tools/sweep.py --signal tor_exit`: three customers carry it. Raise its weight to 40 (`--weight tor_exit=40`) and see what the grid does to them. Why does the shipped policy use 30?
3. The one customer still blocked is a keyboard-only Tor Browser user (30 + 15 + 25). Is that the right call for a login form? For a checkout?

---

## Round 3: Opaque responses + correlation ⚔️ the clean-looking session

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | Read `respond()` in `demo_site/app.py` and `defenses/correlation.py`, then restart with `DEFENSE_LEVEL=3` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | blocked **1** (0.5%, shown as *Invalid credentials*), challenged **12** (6.0%): every VPN user now carries `tz_geo_mismatch` (+10) and lands on the PoW rung |
| 🗡️ Attacker | `python tools/sweep.py --signals telemetry_replay` and `--signals fp_reuse` | `60 -> block` and `30 -> pow`, from sessions that show **no per-request signal at all** |

Two changes. First, a block now returns the exact bytes of a wrong password: the operator's probe loop learns nothing from it. Second, the correlation layer asks what no sensor can: has this *exact* behaviour trace been seen before (a captured "good" sensor blob, replayed), has this device fingerprint come from four IPs in ten minutes, does the browser's time zone sit on the IP's continent?

**Discuss:** the VPN users' challenge rate doubled for a +10 signal. Is `tz_geo_mismatch` worth it? What would you need to log to answer that with data instead of opinion?

**What this round still misses:** a session that is fresh everywhere, with a new trace, new fingerprint and new address every time, shows zero signals. Per-request scoring has nothing left to score.

---

## Round 4: Campaign layer ⚔️ low and slow

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | Read `defenses/campaign.py`, then restart with `DEFENSE_LEVEL=4` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | same bill as Round 3: blocked 1, challenged 12, **step-up 0**. Real customers fail about one login in ten, so no cluster goes hot |
| 🛡️ Collateral | `python tools/sweep.py --clusters` | 51 clusters; the largest holds **15** real customers. If it went hot, all 15 would be stepped up |
| 🗡️ Attacker | `python tools/sweep.py --signals campaign_cluster` | `step_up`: the operator does not own the victims' inboxes, and the response is identical for unknown accounts |

A stuffing run fails most of its logins, because most of its list are not your customers. The campaign layer stops judging requests and judges the thing the operator's tooling holds constant while it rotates everything else: TLS stack, device family, provider ASN. Over `MIN_ATTEMPTS` attempts with a failure ratio over `FAIL_RATIO`, and every login in that cluster is stepped up.

**Exercises** (`TODO (Round 4)` in `campaign.py` and `policy.py`):

1. Lower `MIN_ATTEMPTS` to 4 and rerun the checkpoint. Still zero step-ups? Now look at the 29%-failure cluster in `--clusters`. How many typos away is it from going hot?
2. Set `CAMPAIGN_ACTION = "block"` and reason it through: what does the largest cluster's 15 customers see during an attack?

**What this round still misses:** a run that keeps each cluster under `MIN_ATTEMPTS`, at a human's pace, spread across many providers and device families, is below the floor of this stack. That residual is real. It is why W2 Ch6's account-side controls (breached-password checks, passkeys, MFA by default) exist, why W3 Ch3 moves detection to streams over longer windows, and what the Ch9 capstone throws at you with real browsers.

---

## Debrief

```bash
python tools/checkpoint.py --round 4
python tools/sweep.py --signal no_keystrokes       # the largest minority you nearly charged for a password manager
```

- Fill in the scoreboard: for each level, real customers blocked and challenged, and the attacker profile that the level catches.
- Which signal cost real customers the most across all rounds? Was it ever decisive on its own?
- The pipeline costs well under a millisecond. Which part of *this* app's login costs more? (The password hash, which runs even for requests you block. Why?)

---

## Expected results (self-check)

Verified on 2026-10-11 with Python 3.12.15, Flask 3.1.3, requests 2.34.2 and the `memory://` store (no Docker). Rounds 2 and 4 were also run through the redis-py 8.1.0 client against fakeredis 2.39.0 served over TCP, with the same counts. The `docker compose` path (real Redis 8) is verified separately. The population is seeded, so the counts are exact; pipeline timings vary with the machine.

| `DEFENSE_LEVEL` | Real customers blocked | Challenged | Who | Pipeline p50 / p95 |
|---|---|---|---|---|
| 0 | 0 | 0 | – | 0.05 / 0.15 ms |
| 1 | **21 (10.5%)** | 0 | vpn 9, privacy 8, tor 3, a11y 1 (two overlap) | 0.07 / 0.17 ms |
| 2 | 1 (0.5%) | 6 (3.0%, all PoW) | blocked: tor+a11y · PoW: vpn 3, tor 2, a11y 1 | 0.06 / 0.16 ms |
| 3 | 1 (0.5%) | 12 (6.0%, all PoW) | + every VPN user (`tz_geo_mismatch`) | 0.09 / 0.22 ms |
| 4 | 1 (0.5%) | 12 (6.0%), step-up 0 | unchanged; no cluster is hot | 0.08 / 0.19 ms |

Attacker profiles, as scored by `tools/sweep.py --signals`:

| Round | Profile the defender sees | Veto chain | Score |
|---|---|---|---|
| 0 | `http_library_ua, missing_browser_headers, ja4_non_browser, datacenter_asn, no_telemetry, ip_burst` | block (headers) | 235 → block |
| 1 | `ja4_ua_mismatch, header_order_mismatch, outdated_browser, ip_elevated, timing_too_regular` | **allow** | 80 → block |
| 2 | `ip_elevated, timing_too_regular` | allow | 30 → **pow** (solved) |
| 3 | `telemetry_replay` / `fp_reuse` | allow | 60 → block / 30 → pow |
| 4 | `campaign_cluster` | allow | → **step_up** |

Things to watch for:

- **The step-up never fires on the population.** That is correct: real customers do not fail half their logins. The hot-cluster path (202 → `/lab/mailbox` → `/login/verify`, single-use codes, identical response for unknown users) was verified separately with the Flask test client.
- **The in-page JavaScript** (collector, WebCrypto proof-of-work, step-up prompt) is for learners who want to log in from their own browser. It was not exercised by the automated verification.
- **Redis vs. memory.** The counts are identical; only the `store` line in the checkpoint header changes.
- If someone edits a weight and the checkpoint fails, `tools/sweep.py` replays the log against the shipped thresholds without restarting anything.

---

## Bonus challenges

1. **Per-endpoint policy.** `policy.decide()` has one set of thresholds. Give `/login` and a hypothetical `/checkout` different ones, and argue which should be stricter.
2. **Positive signals.** Add a `trusted_device` signal that *subtracts* points when the fingerprint hash matches the account's last successful login. What does `--clusters` look like once most customers carry it?
3. **Fail-open or fail-closed?** Stop Redis while the app runs. Decide per layer what should happen, implement it in `store.py`, and write the one-line justification each choice deserves.
