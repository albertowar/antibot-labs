# Chapter 8 Lab: Honeypots & Trap Techniques

**Format:** Round 0 plus 4 rounds of attack ⚔️ defend, followed by a debrief. See `../chapter_08_content.md`, §8.5.

You play both sides. Each round, the defender turns on the next trap and the attacker runs the script that walks into it. Then the attacker runs the script that walks around it. Every checkpoint measures two things: the bots a trap catches, and the real people it catches by mistake. The second number is the one honeypot tutorials leave out.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- All traffic stays on your machine, and every user, email and IP address is synthetic.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  docker-compose.yml   Redis 8 for trap events, sanctions, accounts and reviews
  demo_site/app.py     the store; DEFENSE_LEVEL=0..4 picks the traps
  defenses/            form_traps · crawl_traps · responses · trap_store
  solutions/           reference fixes for the Round 2 and Round 3 TODOs
  attacks/             round0_recon … round4_verify_signup
  tools/               checkpoint.py · legit_traffic.py · scoreboard.py
```

**Why this stack:** the whole lab is Python, because every trap here lives on the server or in plain HTML and CSS. Playwright drives the "attackers who render the page" and the simulated real users. Redis holds what the traps produce: short-lived sanctions with a TTL, event logs, and the store's accounts. This chapter has no use for PostgreSQL, so it isn't required. Docker is optional (see Setup).

---

## Setup

```bash
cd lab
docker compose up -d --wait                 # Redis on 127.0.0.1:6379 (optional, see below)
python -m venv .venv && source .venv/bin/activate      # one venv per chapter, see the root README
pip install -r requirements.txt
playwright install chromium                 # Round 2 and 3 attacks, and the simulated users
```

**No Docker?** Start the demo store with `REDIS_URL=memory://`. It then keeps everything in process (fakeredis) and forgets it on every restart, which is fine for this lab.

Start the demo store, and restart it with a new `DEFENSE_LEVEL` each round:

```bash
cd demo_site
DEFENSE_LEVEL=0 python app.py               # http://localhost:5000
```

| Level | Adds | Module |
|---|---|---|
| 0 | Nothing. Requests are counted, nothing is trapped | – |
| 1 | The textbook honeypot: a field called `website` inside `<div style="display:none">` | `defenses/form_traps.py` |
| 2 | Honeypot hidden by a class in `store.css`, per-session opaque field names, a signed timing token | `defenses/form_traps.py` |
| 3 | Hidden trap link, honey product, decoy endpoints, `robots.txt` | `defenses/crawl_traps.py` |
| 4 | Sanctions, set by `RESPONSE_MODE=block\|fake\|quarantine` and `SANCTION_KEY=ip\|session` | `defenses/responses.py` |

Each level includes every level below it. Levels 1 to 3 only **detect**: a trapped signup gets the same "Welcome aboard!" page as a real one and is quietly dropped. Level 4 also **sanctions** the client for 15 minutes.

**Simulated network.** Every script sends `X-Forwarded-For` with a TEST-NET address (RFC 5737). The store trusts that header only from `127.0.0.1`, the same "trusted edge" idea as W1 Ch3. That lets one laptop play a bot farm, a dozen shoppers and a mobile carrier's CGNAT.

**Debug endpoints** (never trapped or sanctioned):

- `/trap-check`: how the store sees *you* (simulated IP, session, sanction, current honeypot config)
- `/trap-logs`: the last 50 trap hits
- `/lab/summary` and `POST /lab/reset`: the scoreboard's raw data, and a wipe

> At level 4, `RESPONSE_MODE=block` puts the trap's name on the 403 page. That's for teaching only.
> In production, never tell a client which trap caught it.

**Troubleshooting**

| Problem | Fix |
|---|---|
| Port 5000 already in use (macOS: the AirPlay Receiver uses it) | `PORT=5050 DEFENSE_LEVEL=… python app.py`, then `export DEMO_URL=http://localhost:5050` in the shell you run attacks and tools from |
| `redis.exceptions.ConnectionError` | Start Redis (`docker compose up -d --wait`) or use `REDIS_URL=memory://` |
| Old results in the scoreboard | `curl -X POST http://localhost:5000/lab/reset` (the checkpoint does this for you) |
| `Executable doesn't exist` from Playwright | `playwright install chromium` inside the venv |

---

## How to measure a round

Finish every round with a **checkpoint**:

```bash
python tools/checkpoint.py --round <N>      # add --skip-browser to skip the Playwright scripts
```

```
=== Checkpoint: Round 3 (server at DEFENSE_LEVEL=3) ===

Bot traffic
  ✅ round0_recon             0/1 signups created (bot believes 1/1) (expected: trapped)
  ✅ round1_form_spammer      0/10 signups created (bot believes 10/10) (expected: trapped)
  ✅ round1b_markup_aware     0/10 signups created (bot believes 10/10) (expected: trapped)
  ✅ round2_playwright_form   3/3 signups created (bot believes 3/3) (expected: gets through)
  ✅ round3_crawler           24 trap hits, scraped 12/12 + honey product (expected: trapped)
  ✅ round3b_polite_crawler   0 trap hits, scraped 12/12 (expected: gets through)

Real users (simulated personas)
  ✅ mouse_shopper          ok
  ✅ screenreader_shopper   ok
  ✅ autofill_shopper       ok
  ✅ cgnat_shopper          ok
  ✅ search_crawler         ok
  → 0/5 personas hurt

Defender cost
  trap checks: median 0.031 ms, p95 7.188 ms per request (159 requests)

✅ Round 3 checkpoint passed.
```

What it reports:

- **Bot traffic:** every attack introduced so far. "Bot believes" is what the script printed. "Signups created" is what the server actually saved.
- **Real users:** `tools/legit_traffic.py` runs five personas (below). A trap hit, a block, a dropped or quarantined signup, or a hidden review all count as a **false positive**.
- **Defender cost:** the time spent in trap checks per request, from the `Server-Timing` header. The median is pattern matching. The p95 is the Redis writes that log a hit.

| Persona | Models | A trap hurts them if… |
|---|---|---|
| `mouse_shopper` | a sighted user with a mouse | it's visible (none of ours are) |
| `screenreader_shopper` | a keyboard or screen-reader user who fills whatever Tab lands on | the honeypot can take focus |
| `autofill_shopper` | browser autofill or a password manager filling the fields it recognises | the honeypot has a layout box and a name or label like `phone` or `email` |
| `search_crawler` | a search engine crawler that obeys `robots.txt` and reads raw HTML | a trap URL isn't in `robots.txt` |
| `cgnat_shopper` | a customer on a mobile carrier, sharing `203.0.113.77` with the Round 4 bot | sanctions are keyed on IP |

The autofill and screen-reader personas are **models**. Real autofill heuristics differ by browser and version. In Round 2, also try the form in your own browser with its autofill and password manager on.

`python tools/scoreboard.py` prints the server's view at any time.

**Fell behind?** `python tools/checkpoint.py --round <N> --catch-up` copies the reference fix for every TODO up to round N into `defenses/` and keeps your version as a `.bak`. The demo store reloads by itself. Restart it with the round's level if you haven't yet.

---

## Round 0: Recon

**🗡️ Look like a bot:**

```bash
python attacks/round0_recon.py              # the form's inputs and robots.txt, as raw HTML shows them
```

**🛡️ Look like a defender:** open `http://localhost:5000/`, create an account in your browser, then open `/trap-check` and `/trap-logs`. Note your session id and simulated IP.

**Checkpoint:** `python tools/checkpoint.py --round 0`. Expected: one account created, 0/5 personas hurt.

**Discuss:** the store has no defenses yet. Which of its pages would a spammer want? Which would a scraper want?

---

## Round 1: Naive spammer ⚔️ the textbook honeypot

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round1_form_spammer.py` (level 0) | 10/10 signups created |
| 🛡️ Defend | Read `_honeypot_html()` and `check_submission()` in `defenses/form_traps.py`, then restart with `DEFENSE_LEVEL=1` | – |
| 🗡️ Re-run | `python attacks/round1_form_spammer.py`, then `python tools/scoreboard.py` | the bot prints 10/10 successes; the server shows 0/10 created, `honeypot×10` |
| 🗡️ Adapt | `python attacks/round1b_markup_aware.py` | `skipping 'website': inline style`, 10/10 created |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | spammer trapped · markup-aware gets through · 0/5 personas hurt |

**Discuss:**

- Why does the trapped bot still print "succeeded"? What would a 400 response have taught it?
- The markup-aware bot needed about 15 lines. What gave the trap away?

---

## Round 2: CSS-hidden honeypot + timing token ⚔️ a real browser

| Step | Do | Expected |
|---|---|---|
| 🛡️ Defend | Read the level 2 parts of `defenses/form_traps.py` and `.hp-offscreen` in `demo_site/static/store.css`. Restart with `DEFENSE_LEVEL=2` and view the form's source | opaque field names, a `ts` token, a field labelled "Phone" |
| ✅ Measure | `python tools/checkpoint.py --round 2` | both spammers trapped, **but** `screenreader_shopper` and `autofill_shopper` ❌ (2/5 personas hurt), and the Playwright bot is trapped too |
| 🛡️ Fix | The `TODO (Round 2)` in `defenses/form_traps.py`: make the honeypot unreachable for humans | – |
| 🗡️ Attack | `python attacks/round2_playwright_form.py` | `skipping invisible field 'f_…'`, 3/3 created |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | spammers trapped (`honeypot` + `too-fast`) · Playwright bot gets through · 0/5 personas hurt |

**Exercises:**

1. Before the fix, why did the Playwright bot get caught? (`is_visible()` is true for an off-screen element.) After the fix, why doesn't it? The change that protects real users is the same change that lets a rendering bot through.
2. Remove `store.css` from the page (DevTools → Network → block request URL) and look at the form. What does a user see now, and why is the label "Leave this field empty" there?
3. The cheapest attack that beats level 2 without a browser: what would you add to `round1b_markup_aware.py`? (There are two parts.)

---

## Round 3: Crawl traps ⚔️ the polite crawler

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round3_crawler.py` (level 2) | 12 products, nothing trapped |
| 🛡️ Defend | Read `defenses/crawl_traps.py`, `trap_link_html()` in the footer and `/static/store.js`. Restart with `DEFENSE_LEVEL=3` | – |
| 🗡️ Re-run | `python attacks/round3_crawler.py` | `/catalog/archive` on the first page, then 20 archive pages; `401 /api/internal/export`; the **Seafoam Glaze Espresso Cup** (id 13) in its results |
| ✅ Measure | `python tools/checkpoint.py --round 3` | crawler trapped, **but** `search_crawler` ❌ `trap:trap_link×4` |
| 🛡️ Fix | The `TODO (Round 3)` in `defenses/crawl_traps.py`: tell good crawlers where not to go | – |
| 🗡️ Adapt | `python attacks/round3b_polite_crawler.py` | `Visited 16 pages, scraped 12 products`, 0 trap hits. It never even sees the trap link: `a:visible` skips it before `robots.txt` is consulted |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | crawler trapped · polite crawler gets through · 0/5 personas hurt |

**Discuss:**

- The naive crawler was trapped 24 times and still got the whole catalog. What did the traps buy you? (Attribution, a canary in its dataset, and crawl budget wasted in the archive maze.)
- Listing traps in `robots.txt` tells the polite crawler exactly where not to go. Is that a problem? Who is still caught?
- Your performance team adds Speculation Rules that prefetch every same-origin link. What happens to the trap link?

---

## Round 4: Responding to a hit ⚔️ the bot that checks its work

Run the same experiment under four configurations. For each one, restart the store, run the bot, **then** the CGNAT customer who shares its IP, then read the scoreboard:

```bash
cd demo_site && DEFENSE_LEVEL=4 RESPONSE_MODE=block SANCTION_KEY=ip python app.py
python attacks/round4_verify_signup.py
python tools/legit_traffic.py cgnat_shopper
python tools/scoreboard.py
```

| `RESPONSE_MODE` / `SANCTION_KEY` | What the bot concludes | `cgnat_shopper` |
|---|---|---|
| `block` / `ip` | `blocked` ×3: the 403 told it exactly which request failed | ❌ blocked with a 403 |
| `fake` / `ip` | `shadow-banned` ×3: "Welcome aboard!", then the login fails | ❌ signup silently dropped, can't log in |
| `quarantine` / `ip` | `success` ×3: login works, and it can see its own review | ❌ looks fine to them, but the account is quarantined and the review hidden. **The worst kind of false positive: nobody complains.** |
| `quarantine` / `session` | `success` ×3; reviews published: 0 | ✅ |

**Checkpoint:** restart with `RESPONSE_MODE=quarantine SANCTION_KEY=session`, then `python tools/checkpoint.py --round 4`. Expected: every trapped bot stays trapped, the Round 4 bot concludes `success` while 0 reviews are published, and 0/5 personas are hurt.

**Discuss:**

- How would the Round 4 bot detect the shadow ban? (Look for its review from a second, clean session.) What would you do next?
- The bot drops its cookie and comes back clean. Why is that acceptable here, and when isn't it?
- Why isn't tarpitting (`time.sleep(5)` before responding) one of the modes? Whose thread is sleeping?

---

## Debrief: false positives and cost

```bash
python tools/scoreboard.py
curl -s localhost:5000/trap-logs | python -m json.tool | head -40
```

- Two scripts got through every trap: the Playwright form bot and the polite crawler. What do they have in common?
- Count the false positives you caused in this lab and the TODO that fixed each one. Which would you have noticed in production without the personas?
- What does a trap check cost per request? What does a sanction lookup add? (Compare the level 3 and level 4 medians.)
- Next, in Chapter 9: combine this chapter's traps with rate limits (Ch2), IP reputation (Ch3), header scoring (Ch4), sessions (Ch5), CAPTCHAs (Ch6) and proof of work (Ch7) into one layered defense.

---

## Expected results (self-check)

Verified with Python 3.12.15, Flask 3.1.3, redis 8.1.0, fakeredis 2.39.0 (`REDIS_URL=memory://`), httpx 0.28.1 and Playwright 1.63.0 (Chromium 153.0.8010.12 headless shell). The `docker compose` path (Redis 8 container) is verified separately. Levels 2–4 assume the Round 2 and Round 3 fixes are in. Level 4 is `quarantine` / `session`.

| Attack ↓ / `DEFENSE_LEVEL` → | 0 | 1 | 2 | 3 | 4 | Trap at the first catch |
|---|---|---|---|---|---|---|
| `round1_form_spammer` (10) | 10 created | **0** | 0 | 0 | 0 quarantined ×10 | `honeypot_field` |
| `round1b_markup_aware` (10) | 10 | 10 | **0** | 0 | 0 | `honeypot_field` + `too_fast` |
| `round2_playwright_form` (3) | 3 | 3 | 3 | 3 | 3 | – (before the Round 2 fix: 0, `honeypot_field`) |
| `round3_crawler` | 12 products, 0 hits | same | same | **24 hits**, 12 + honey | same | `trap_link` ×20, `decoy_endpoint` ×3, `honey_record` ×1 |
| `round3b_polite_crawler` | 12, 0 hits | same | same | same | same | – |
| `round4_verify_signup` (3) | – | – | – | – | concludes `success`, 0 published | `honeypot_field` + `too_fast` |
| Personas hurt | 0/5 | 0/5 | 0/5 (2/5 before the fix) | 0/5 (1/5 before the fix) | 0/5 | – |

A full checkpoint takes about 20 s at Round 0 and about 40 s at Round 4. Most of that is the Playwright personas.

Things to watch for:

- **Port 5000 taken:** see Troubleshooting. Everything reads `DEMO_URL`.
- **If you edit `form_traps.py` without the debug reloader** (e.g. `flask run` without `--debug`) you must restart the store to pick up the fix.
- **"too_fast" on a real person:** `MIN_FILL_SECONDS` is 1.5 s. The autofill persona takes about 2 s. If your own autofill-plus-generated-password signup gets trapped, that's a real finding. Discuss it; don't hide it.
- **Docker path:** the store connects to `redis://localhost:6379/0` by default. Check with `docker compose up` before you start.

---

## Bonus challenges

1. **Detect the shadow-ban check.** Write `round4b_second_session.py`: post the review with one session, then look for it from a fresh one. Then decide: is this worth defending against, or is the bot's cost now high enough?
2. **Watermark the catalog.** Give each session a slightly different honey product name (derived from an HMAC of the session id, like the field names). Write `tools/attribute.py` that takes a scraped product list and names the session, IP and time it came from.
3. **Speculation Rules.** Add `<script type="speculationrules">` with an eager document rule for `/catalog/*` to the layout, and visit the store in Chrome. Does the trap fire? Exclude the trap with a `not` / `selector_matches` clause and check again.
4. **The cheapest level 2 bypass.** Add a 2-second sleep and a label check ("leave", "empty") to `round1b_markup_aware.py`. What does the trap still have? What would you add next?
