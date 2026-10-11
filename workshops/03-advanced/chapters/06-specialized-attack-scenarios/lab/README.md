# W3 Ch6 Lab — Five Economies, Five Signatures

Five specialized attacker economies against one e-commerce store, each a short
attack/defend round. The spine of the chapter: **an attack's economics force a
signature it cannot hide, and the defense that works targets that signature, not a
generic "is this a bot" score.** The generic layers you built in Workshops 1–2
(per-IP rate limiting, datacenter detection) are already wired into the store; each
round shows where they fall short and what catches the rest.

| Round | Economy | You wire (`defenses/`) | The signature |
|---|---|---|---|
| 1 | Credential stuffing | `breached_passwords.py` | hits are, by definition, breached passwords |
| 2 | Scalping a drop | `scalping_funnel.py` | machine-speed funnel + units per device |
| 3 | Adversarial scraping | `scrape_defense.py` | catalogue **coverage** + honeypot SKUs |
| 4 | Fake-account farming | `account_cluster.py` | registration velocity + device cluster |
| 5 | Click / ad fraud | `ivt_scoring.py` | GIVT hard filters + SIVT engagement funnel |

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- Every credential, email, IP, fingerprint and session in this lab is synthetic. The "source IPs" are RFC 5737 documentation ranges, honoured only from loopback.
- **Outbound network:** none by default. The Round 1 breach check reads an offline k-anonymity fixture. With `HIBP_LIVE=1` it queries the real Pwned Passwords range API instead, sending only the first five hex characters of a SHA-1 hash. Leave it off in class.
- Do not point these scripts, or anything you build from them, at a site you do not own.

## Setup (under 10 minutes)

**Python only.** HTTP attackers (`requests`), the Flask store, and the scoring all
live in Python, so there is one toolchain to install. No Docker is required: the
store runs on an in-process `fakeredis` and a SQLite file by default.

```bash
cd lab
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python tools/seed.py                               # synthetic catalogue, users, fixtures
python demo_site/app.py                            # http://127.0.0.1:5000
```

Leave the store running and open a second terminal (activate the venv there too).

### Per round

```bash
# 1. Run the attack and watch it win against the un-wired defense:
python attacks/round2_scalper.py

# 2. Open the round's module in defenses/, complete the TODO, save.
#    (the store reloads it on the next request — no restart needed)

# 3. Re-run the checkpoint: it runs the real customers AND the attacker,
#    and reports both sides.
python tools/checkpoint.py --round 2

# Stuck? Install the reference solution, then go back to your own work:
python tools/checkpoint.py --round 2 --catch-up    # reference (saves your work to .bak)
python tools/checkpoint.py --round 2               # restores and tests your work
```

At the end, review everything together:

```bash
python tools/scoreboard.py
```

### Evolved attacks (try after the defense is wired)

Each round ships the attack that beats the previous step, so the arms race is real:

```bash
python attacks/round2_scalper.py --skip-view       # skip the funnel entirely
python attacks/round4_account_farm.py --clean-emails   # dodge the disposable blocklist
python attacks/round5_click_fraud.py --sivt        # sophisticated invalid traffic
```

## Instructor expected results

Measured on the default fakeredis + SQLite backend (`DROP_STOCK=50`, 1000-row combo
list, 10 real hits). Numbers are deterministic up to small timing jitter.

| Round | Metric | Un-wired (stub) | Wired (solution) | Legit customers blocked |
|---|---|---|---|---|
| 1 Stuffing | account takeovers | **10** | **0** (10 → forced reset) | 0 (2 reused-pw users *challenged* — the honest FP) |
| 2 Scalping | pairs won of 50 | **50** | **0** (80 challenged); `--skip-view` → 0 | 0 (40 real buyers all served) |
| 3 Scraping | catalogue items harvested | **70** | **25** (blocked at item 26) | 0 (15 shoppers, ~98 views) |
| 4 Fake accounts | accounts created | **20** | **0**; `--clean-emails` → **3** then blocked | 0 (10 first-timers served) |
| 5 Click fraud | fraudulent clicks counted | **60** | **0**; GIVT=60 / SIVT=60 both blocked | 0 (15 real click-throughs) |

Median defender scoring cost is ~1–2 ms per decision (`Server-Timing`-style, printed
by the scoreboard). Two debrief talking points the table makes concrete:

- **Round 1** is the clearest false-positive lesson: the breach gate converts every
  stuffing hit to a forced reset, but it also prompts 2 real users who reused a
  breached password. That is a real cost, not a bug — name it.
- **Round 4** `--clean-emails` leaks exactly 3 accounts before the per-egress
  velocity cap (`IP_CAP=3`) bites. The blocklist was evaded; the cluster signal was
  not. No single signal is sufficient.

## Optional: production-shaped backend

```bash
docker compose up -d
export REDIS_URL=redis://127.0.0.1:6379/0
export DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop
python tools/seed.py && python demo_site/app.py
```

Redis and PostgreSQL are pinned and bound to `127.0.0.1`. Everything else is
identical. This path is not required to complete the lab.

## Troubleshooting

- **"Demo store not reachable"** — start it first: `python demo_site/app.py`, and
  run the checkpoint from the same `lab/` directory.
- **Round 1 is slow / no hits** — the offline breach fixture lives in
  `data/breach_ranges/`; re-run `python tools/seed.py` if you deleted `data/`.
- **A round won't pass after you edit it** — the checkpoint prints why: either the
  attack still gets through (wire the signature) or real customers were blocked
  (your rule is too broad). `--catch-up` shows the reference.
- **Numbers drift by one or two** — timing jitter on the dwell gates. The verdict
  (PASS/FAIL) is robust; the exact counts are not.
