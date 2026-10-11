# W4 Ch1 Lab — AI Crawlers: Landscape & Identification

**Format:** Round 0 plus 4 rounds of attack ⚔️ defend. This is a minimal README: the chapter's content doc, timings and measured expected results are still to be written (see the chapter's entry in the root `TODO.md`).

The demo store is the Workshop 4 starter state: an HTML catalogue of 120 products with a sitemap, an RSS feed, static assets and a `robots.txt`. AI crawlers want the catalogue. You build crawler identification in four rounds, and every checkpoint measures what each layer stops **and** what it costs the 14 legitimate personas: people, feed readers, link previewers and verified search crawlers.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- Source addresses come from `data/world.json` (RFC 5737 documentation ranges) and are sent in `X-Lab-Source-IP`, which the store honours only from loopback. No proxy or crawler infrastructure is ever contacted.
- The operators' published IP ranges in `data/published_ranges/` are shipped snapshots. Reverse and forward DNS go through `defenses/netdb.py`, which answers from `data/world.json`, not from a real resolver.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  labnet.py            the localhost guard and catch-up helper (shared by every lab)
  demo_site/           app.py (the store, DEFENSE_LEVEL 0–4) · lab_edge.py · store.py · robots.txt
  defenses/            crawler_registry · crawler_verify · crawl_signature · policy  ← YOU EDIT THESE
                       netdb (DNS and ASN lookups against the lab world, given)
  attacks/             round0_declared_crawler … round3_polite_distributed · _common.py
  tools/               checkpoint · legit_traffic · scoreboard · traffic_mix · personas · build_world
  data/                world.json · operators.json · robots.json · published_ranges/
  solutions/roundN/    reference defenses (and Round 1's robots.txt), installed by --catch-up
```

## Setup

Python 3.10+. No Docker, no browser: the store falls back to an in-process `fakeredis` and SQLite.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
DEFENSE_LEVEL=0 python demo_site/app.py          # terminal 1: the store on 127.0.0.1:5000
python tools/checkpoint.py --round 0             # terminal 2: both sides, one verdict
```

`PORT` changes the store's port; export `DEMO_URL=http://127.0.0.1:<port>` for the tools to match. Defense modules reload on save. Only a new `DEFENSE_LEVEL` needs a restart. `docker compose up -d` gives the Redis and PostgreSQL backends instead (set `REDIS_URL` / `DATABASE_URL`).

**Fell behind?** `python tools/checkpoint.py --round N --catch-up` installs the reference solutions for rounds 1..N from `solutions/` over your files and keeps each of yours once as `.bak`. Restart the store at `DEFENSE_LEVEL=N`, then run the checkpoint again. `python tools/checkpoint.py --restore` puts your own files back.

## Rounds

| Round | `DEFENSE_LEVEL` | 🔴 Attack | 🔵 You edit | The question |
|---|---|---|---|---|
| 0 | 0 | `round0_declared_crawler`: GPTBot that honours `robots.txt` | – | What does an honest AI crawler look like in the log? |
| 1 | 1 | `round1_impersonate_searchbot`: claims to be OAI-SearchBot | `defenses/crawler_registry.py`, `demo_site/robots.txt` | Who claims to be a crawler, and what does your policy say to them? |
| 2 | 2 | `round2_stealth_chrome`: Chrome UA from 4 cloud IPs | `defenses/crawler_verify.py` | Is the claim true? Published ranges and forward-confirmed reverse DNS |
| 3 | 3 | `round3_polite_distributed`: slow, 30 ISP addresses | `defenses/crawl_signature.py` | Does an unclaimed client behave like a crawler? |
| 4 | 4 | every earlier crawler | `defenses/policy.py` | Identity × purpose → allow, limit, challenge or block |

A round passes when no person and no verified crawler is blocked or challenged, and every attack from earlier rounds stays under its ceiling. The current round's attack is shown but not judged: it is supposed to get through, and that is the next round.

`python tools/legit_traffic.py` runs the legitimate cohort on its own. `python tools/scoreboard.py` prints the decision log by actor.
