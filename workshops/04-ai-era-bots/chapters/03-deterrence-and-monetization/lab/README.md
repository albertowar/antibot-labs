# W4 Ch3 Lab — Deterrence & Monetization for AI Crawlers

**Format:** 4 rounds of attack ⚔️ defend. This is a minimal README: the chapter's content doc and measured expected results are still to be written (see the chapter's entry in the root `TODO.md`).

The shop every AI crawler in this chapter wants: 300 products served the way a real shop serves them, through HTML, search, a JSON API and a sitemap. Each round climbs one rung of crawler governance: publish a policy, enforce it on crawlers you can verify, deter the ones you can't, and charge the ones who will pay. Every checkpoint measures what each rung stops **and** what it costs real users, readers, prefetchers and the verified search crawler.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- Simulated client addresses are RFC 5737 documentation ranges sent in `X-Lab-Client-IP`, which the store honours only from loopback. The crawler operators' signing keys are generated on your machine by `tools/seed.py` into the gitignored `attacks/keys/`.
- The maze's drip delivery has a concurrency cap (`MAX_INFLIGHT` in `defenses/maze.py`). A tarpit with no cap is a denial-of-service amplifier against yourself; keep the cap if you change the maze.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  labnet.py            the localhost guard and catch-up helper (shared by every lab)
  demo_site/           app.py (the store, DEFENSE_LEVEL 0–4) · store.py
  defenses/            crawl_policy · enforce · maze · paywall  ← YOU EDIT THESE
                       bot_identity · crawler_registry · babble (given, from W4 Ch1–2)
  attacks/             round1_compliant_crawler … round4_free_path_leak · _common.py
  tools/               seed · make_keys · checkpoint · legit_traffic · scoreboard
  solutions/roundN/    reference defenses, installed by --catch-up
```

## Setup

Python 3.10+. No Docker: the store falls back to an in-process `fakeredis` and SQLite.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python tools/seed.py                              # catalogue + operator keys (deterministic)
DEFENSE_LEVEL=1 python demo_site/app.py           # terminal 1: the store on 127.0.0.1:5000
python tools/checkpoint.py --round 1              # terminal 2: both sides, one verdict
```

`PORT` changes the store's port; export `DEMO_URL=http://127.0.0.1:<port>` for the tools to match. Defense modules are re-imported on every request, so a saved edit takes effect at once. Only a new `DEFENSE_LEVEL` needs a restart.

**Fell behind?** `python tools/checkpoint.py --round N --catch-up` installs the reference solutions for rounds 1..N from `solutions/` over your files and keeps each of yours once as `.bak`. Restart the store at `DEFENSE_LEVEL=N`, then run the checkpoint again. `python tools/checkpoint.py --restore` puts your own files back.

## Rounds

| Round | `DEFENSE_LEVEL` | 🔴 Attack | 🔵 You edit | The question |
|---|---|---|---|---|
| 1 | 1 | `round1_compliant_crawler` vs `round1_ignoring_crawler` | `defenses/crawl_policy.py`: `robots.txt`, AIPREF `Content-Usage`, Content Signals, RSL licence | Does a published preference govern anyone who doesn't read it? |
| 2 | 2 | `round1_ignoring_crawler`, then `round2_stealth_crawler` (Chrome UA, residential egress) | `defenses/enforce.py`: refuse verified crawlers that break the policy, and unverifiable claims | Why does the honest crawler get refused while the stealth one walks in? |
| 3 | 3 | `round3_stealth_crawler`, then `round3_maze_aware_crawler` | `defenses/maze.py`: hidden entry link and tagging | How much does a poisoned maze cost a crawler, and you? |
| 4 | 4 | `round4_paying_crawler` and `round4_free_path_leak` | `defenses/paywall.py`: the HTTP 402 exchange, and every catalogue carrier behind it | Who pays, and which route leaks the catalogue for free? |

A round passes when that round's crawler is held under its ceiling **and** no legitimate request was blocked, paywalled, charged or mazed. The checkpoint also prints the defender's cost: maze generation time, bytes served and cap hits.
