# Chapter 3 Lab: Who Is Knocking?

Starts from: workshops/01-initiation/starter/ (contract 1.5). Adds: six IP checks (`rate_limit`, `blocklists`, `ip_reputation`, `trusted_proxy`, `prefix_limit`, `geo_velocity`) on a shared feed index and client-IP helper, the `/lab/ip-check/<ip>` page, five attack scripts on one shared scraper and the Chapter 3 shoppers.

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/blocklists.py`
- `defenses/client_ip.py`
- `defenses/feeds.py`
- `defenses/geo_velocity.py`
- `defenses/ip_reputation.py`
- `defenses/prefix_limit.py`
- `defenses/rate_limit.py`
- `defenses/trusted_proxy.py`
- `demo_site/ext/ip_check.py`
- `tools/ipkit.py`
- `tools/personas_ch3.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** setup, 5 rounds of attack and defense, then a debrief. See `workshops/01-initiation/chapters/03-ip-reputation-and-proxy-detection/chapter_03_content.md` (slides repo), section 3.6.

You play both sides. The scraper wants the whole catalog: all 120 product records from `/api/products/<sku>`. Every round
it changes **where its traffic comes from**: one cloud VM, free proxies, a fleet of fresh VMs, a forged `X-Forwarded-For`,
a residential proxy network. Every round you add one IP-based layer and measure two numbers:

- how much of the catalog the scraper still got;
- which of the 40 simulated shoppers your layer stopped. Phones behind carrier NAT, VPN users and privacy relay users all
  look suspicious to an IP defense, and the scoreboard shows them next to the bots stopped.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`, which asks
  `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service URLs such as
  `REDIS_URL` too). The store's edge accepts the lab headers only from loopback. Do not remove that check.
- **Everything is synthetic.** Every source address is a documentation address (RFC 5737, RFC 3849) rented from
  `data/world.json` and sent in `X-Lab-Client-IP`; every ASN is a documentation ASN (RFC 5398). The "proxies", "Tor exits"
  and "residential proxy network" are addresses the store *pretends* to see. No proxy, VPN or Tor node is ever contacted.
- **The feeds are synthetic too.** `data/feeds/` is generated from `world.json` by `tools/build_world.py`, shaped like
  the real free feeds; `data/feeds/README.md` (and `manifest.json`) lists, for every file, the real feed it stands in for,
  its URL, licence and production refresh cadence. **No feed is fetched live**: TheSpeedX/PROXY-List and the other real
  lists are discussed in the chapter and never contacted by any script here.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  defenses/feeds.py           data/feeds/* loaded into a CidrIndex / RangeTable (IPv4 and IPv6), reloaded on change
  defenses/client_ip.py       which IP? naive (leftmost X-Forwarded-For) until trusted_proxy is wired, then trusted
  defenses/rate_limit.py      Round 1: per-IP token bucket (30 a minute, burst 20)
  defenses/blocklists.py      Round 2: Tor, open proxies, DROP, FireHOL -> block
  defenses/ip_reputation.py   Round 3: datacenter, hosting ASN, VPN, privacy relay -> score and band
  defenses/trusted_proxy.py   Round 4: read X-Forwarded-For from the right
  defenses/prefix_limit.py    Round 5: per-/24 and per-/64 buckets
  defenses/geo_velocity.py    Round 5: IP churn and country hops within one session
  defenses/ladder.py          YOUR FILE: wire one round at a time
  defenses/policy.py          the numbers: RATE_LIMITS, IP_POINTS, TRUST_PRIVACY_RELAYS, XFF_POINTS, GEO_*
  demo_site/ext/ip_check.py   /lab/ip-check/<ip>: the full breakdown for any address
  attacks/                    round1_single_ip ... round5_residential (all on tools/ipkit.py)
  tools/                      checkpoint.py · ipkit.py (the shared scraper) · personas_ch3.py (the `rush` shoppers)
  solutions/round1..5/        reference ladder.py per round, plus Round 3's policy.py (the catch-up files)
```

The rest of the store (catalog, cart, checkout, accounts, the simulated edge, the decision log) is the Workshop 1 starter,
unchanged. Its contract is `workshops/STORE_CONTRACT.md`.

---

## Setup (5 min)

Setup is covered once for the whole series in `PREWORK.md`. For this lab:

```bash
cd lab
python3.12 -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt                         # one venv per chapter
python tools/doctor.py                                  # READY?
python demo_site/app.py                                 # http://127.0.0.1:5000
```

No Docker is needed (SQLite and an in-process Redis; this lab's `requirements.txt` adds fakeredis's `[lua]` extra because
the token buckets are a Lua script). With Docker, `docker compose up -d --wait` starts Redis 8.10 and PostgreSQL 18 as in
the starter README. Port 5000 busy? `PORT=8099 python demo_site/app.py`, then `export DEMO_URL=http://127.0.0.1:8099` in
the shell where you run attacks and tools.

You never restart the store between rounds: edits to `defenses/*.py` are picked up on the next request, and the checkpoint
sets the level (`POST /lab/level`). Restart only after editing `demo_site/ext/`.

**This lab ships its defenses pre-written.** Each round you read one module (its docstring says what it catches, what it
misses and who it hurts), wire it into `defenses/ladder.py`, and run the checkpoint. **Fell behind?**
`python tools/checkpoint.py --round N --catch-up` installs the reference `ladder.py` (and Round 3's `policy.py`) for rounds
1..N; your files are kept as `.bak`, and `python tools/checkpoint.py --restore` puts them back.

**Look around while you work** (lab pages, never gated, never in production):

```bash
curl -s localhost:5000/lab/ip-check/203.0.113.5 | python -m json.tool     # network, signals, blocklists, score, band
python -m defenses.ip_reputation                                          # one address from every pool, scored
python -m defenses.feeds                                                  # linear scan vs CidrIndex
curl -s localhost:5000/whoami | python -m json.tool                       # what the edge says about you (xff_claimed too)
curl -s 'localhost:5000/lab/decisions?actor=bot:&limit=5' | python -m json.tool
```

Every response carries `X-Lab-Verdict`, `X-Lab-Score` and `X-Lab-Signals`. They tell the attacker exactly what tripped:
never send them in production (`LAB_HEADERS=0` turns them off).

**There is no challenge type yet.** CAPTCHAs arrive in Chapter 5 and proof of work in Chapter 6. Until then the `challenge`
band (score 40-74) is enforced as a block (`challenge_unavailable`), so a "challenged" shopper is a lost shopper.

## The simulated network

On a laptop every request comes from `127.0.0.1`, so the store's edge (`demo_site/lab_edge.py`, in-process) treats the
address in `X-Lab-Client-IP` as the TCP peer, but only if it falls inside a `world.json` pool: you may rent an address,
never invent one (anything else is a 421). Like a CDN, the edge appends that peer to whatever `X-Forwarded-For` the client
sent and passes the chain on as `ctx.edge.xff_claimed`; it never trusts it itself.

| Pool | Used by | What it is | What the feeds say |
|---|---|---|---|
| `cloud_vm`, `cloud_gcp` | bot | 80 VMs on two cloud providers | both in cloud ranges; only `cloud_vm`'s ASN is on the hosting list |
| `cloud_v6` | bot | one IPv6 VPS /64, a new address per request | nothing: the provider publishes no ranges |
| `free_proxy` | bot | 60 public proxies, 40 % dead | 75 % on the open proxy list, 25 % fresher than your copy |
| `tor_exit` | bot | 12 Tor exits | all on the Tor exit list and FireHOL |
| `bulletproof_host` | bot | a criminal netblock | on DROP and FireHOL |
| `residential_proxy_net` | bot | 384 home connections, six ISPs, six countries, one per /64 | residential ISPs, like your customers |
| `home_*` | 27 shoppers | home broadband, one address each | residential ISPs |
| `mobile_cgnat` | 8 shoppers | two carrier-NAT addresses shared by every phone | a mobile carrier |
| `consumer_vpn` | 3 shoppers | a commercial VPN | on the VPN list |
| `private_relay` | 2 shoppers | Safari with a privacy relay | relay list, **and** the community VPN list |

`python -m defenses.ip_reputation` prints what every pool scores right now.

---

## How to measure a round

```bash
python tools/checkpoint.py --round N              # level N: your defenses
python tools/checkpoint.py --round N --level N-1  # the same attacks against the previous level: the "before"
```

The checkpoint sets the level, resets the store, runs the round's attacks one after the other while the 40 shoppers shop
(the `rush` scenario in `tools/personas_ch3.py`: the starter's journey with every pause cut to a fifth, so the phones
sharing one CGNAT address really meet the per-IP limit), and prints:

- **The scoreboard**: requests served and stopped per actor, and the gate's cost in milliseconds (`Server-Timing` on every
  response has the per-check split).
- **The shoppers table**: per persona, how many finished and how many a defense stopped.
- **The attacks**: products scraped out of 120, what stopped the rest, and the top `X-Lab-Signals`.
- **PASS or FAIL** against the round's expectations in `tools/checkpoint.py`, including which personas the round is
  *allowed* to hurt (`allowed_fp`). That list is the price of the layer.

---

## Round 1: one cloud VM vs a per-IP rate limit

| Step | Do | Expected |
|---|---|---|
| Before | `python tools/checkpoint.py --round 1 --level 0` | the VM scrapes 120/120 |
| Defend | Read `defenses/rate_limit.py`; wire `1: [rate_limit.CHECK]` in `ladder.py` | |
| After | `python tools/checkpoint.py --round 1` | about 20/120 (the burst), `rate_limit:ip_rate_limit` |
| Red | `python attacks/round1_single_ip.py --pool cloud_v6` | 120/120: a fresh address from one /64 per request |

Look at the shoppers table: phones on the shared `mobile_cgnat` address are rate-limited too. A limit sized for one person
throttles a neighbourhood. **Discuss:** raise the limit for mobile carrier ASNs, and attackers buy mobile proxies. What else
could tell eight shoppers on one address apart?

## Round 2: free proxies vs blocklists

| Step | Do | Expected |
|---|---|---|
| Before | `python tools/checkpoint.py --round 2 --level 1` | about 100 %: two or three requests per proxy never trip the limit |
| Defend | Read `defenses/blocklists.py` and `defenses/feeds.py`; wire `2: [blocklists.CHECK]` | |
| After | `python tools/checkpoint.py --round 2` | free proxies about 15-25 %, Tor and the bulletproof host 0 % |
| Red | `--pool tor_exit`, `--pool bulletproof_host` on `round2_free_proxies.py` | 0 %: every Tor exit is published |
| Blue | `/lab/ip-check/<ip>` on a proxy that got through (`/lab/decisions?actor=bot:r2`) | on no list: **fresher than your copy** |

`dead_proxy_skipped` in the attack's output is what free proxies cost the attacker: 40 % of the list is dead, and each dead
proxy costs a real scraper a timeout. What still gets through is the **freshness gap**.

## Round 3: fresh cloud VMs vs reputation scoring

| Step | Do | Expected |
|---|---|---|
| Before | `python tools/checkpoint.py --round 3 --level 2` | 120/120: a new VM is on no blocklist |
| Defend | Read `defenses/ip_reputation.py`; wire `3: [ip_reputation.CHECK]` | |
| After | `python tools/checkpoint.py --round 3` | **FAIL**: the bot gets 0/120, but both `private_relay` shoppers are stopped |
| Blue | `defenses/policy.py`: `TRUST_PRIVACY_RELAYS = True`; rerun | PASS: relay users through, the bot still at 0 |
| Red | `IP_POINTS["datacenter"] = 30`; rerun `python attacks/round3_cloud_vms.py` | `cloud_gcp`'s VMs score 30 (monitor) and get through |

The first run fails on purpose. The community VPN list carries the privacy relay's egress, so your best customers look like
VPN users (`/lab/ip-check/198.51.100.65`). The three `consumer_vpn` shoppers stay blocked: that is the round's accepted cost,
and a business decision. **Discuss:** is it safe to trust a relay? The operator knows the customer and rate-limits per
account, but the client is still anonymous to you. Put `datacenter` back to 40 when you are done.

## Round 4: X-Forwarded-For spoofing vs trusted proxies

| Step | Do | Expected |
|---|---|---|
| Before | `python tools/checkpoint.py --round 4 --level 3` | about 100 %: the store scores a fake home address |
| Defend | Read `defenses/client_ip.py` and `defenses/trusted_proxy.py`; wire `4: [trusted_proxy.CHECK]` | |
| After | `python tools/checkpoint.py --round 4` | 0 % for every variant |
| Red | `round4_xff_spoof.py --spoof-as 127.0.0.1` at level 3 | about 15-20 %: reputation skips internal addresses, but they share one bucket |
| Red | `--spoof-as internal-random` at level 3 | about 100 %: a fresh 10.x address, a fresh bucket |

One header bypassed **every** IP-based layer at once, because the rate limit, the blocklists and the reputation score all
asked `client_ip()` and it read the leftmost entry. Getting the client IP right comes before every other IP defense.
`/whoami` with `-H 'X-Forwarded-For: 1.2.3.4'` shows the chain the store receives.

**Discuss (no lab step):** origin bypass. If an attacker can reach your origin without passing the CDN, they write the whole
chain, including the "trusted" last entry. What locks the origin to the edge in production? (A firewall on the CDN's ranges,
mutual TLS, or a shared secret header the edge adds.) This lab's edge is in-process, so there is no origin to go around.

## Round 5: residential proxies vs session signals

| Step | Do | Expected |
|---|---|---|
| Before | `python tools/checkpoint.py --round 5 --level 4` | 120/120: every address is a clean home connection |
| Defend | Read `defenses/prefix_limit.py` and `defenses/geo_velocity.py`; wire `5: [prefix_limit.CHECK, geo_velocity.CHECK]` | |
| After | `python tools/checkpoint.py --round 5` | 0-3/120: `session_country_hop`, `session_ip_churn` |
| Red | `round5_residential.py --pin-country US` | still 0-3/120: no hops, but the session churns |
| Red | `round5_residential.py --no-cookies` | **120/120**: a new session from a new clean address every time |
| Blue | `round1_single_ip.py --pool cloud_v6 --no-cookies` | about 15/120: Round 1's IPv6 rotation is back in one /64 bucket |

Every address the bot used was clean. What gave it away was one session moving between addresses and countries, until it
dropped its cookies. **Discuss:** which information would you need that an IP can't give you? (Chapter 4: headers;
Chapter 8: sessions.)

## Debrief

1. Round 5's last attack wins outright. What does the next layer need to see?
2. Which false positives would you accept to stop the bot, and which never? Who in your company decides?
3. Where would you rather serve the bot slightly wrong data, or nothing at all (a tarpit, Chapter 7)?
4. The rate limit and the blocklists trusted the same `X-Forwarded-For` value. What else in your stack trusts it?

---

## Expected results (self-check)

Generated by `python tools/verify.py --all --catch-up --markdown`; do not edit by hand. Your numbers may differ by a few
requests depending on timing.

The tables below run every round on the reference solutions (Round 3 with `TRUST_PRIVACY_RELAYS = True`). Round 3 with the
shipped policy (`python tools/checkpoint.py --round 3` before the blue step) blocks the bot just as well but FAILs: 9 of 40
shoppers stopped, both `private_relay` shoppers among them (`known_vpn`), next to the 3 `consumer_vpn` and the CGNAT phones.
The CGNAT count moves by one or two between runs, with how the phones' requests overlap.

The `gate ms` column grows from about 6 ms in Round 1 to 80+ ms in Round 5. That is mostly queueing: the store, its
in-process Redis and the shoppers share one Python process while four attacks run eight threads each. On its own, one request
through all six Round 5 checks costs about 2 ms of gate time (`Server-Timing: rate_limit;dur=0.55, blocklists;dur=0.08,
ip_reputation;dur=0.05, trusted_proxy;dur=0.00, prefix_limit;dur=0.40, geo_velocity;dur=0.76`); the two token buckets and the
session history are the expensive part, because each is a Redis round trip.

<!-- results:start -->
| Round | Attack | Before (level N-1) | After (level N) | Shoppers stopped after |
|---|---|---|---|---|
| 1 | `single_ip` | 120/120 | 19/120 | mobile_cgnat 4/8 |
|  | `ipv6_rotation` | 120/120 | 120/120 |  |
| 2 | `free_proxy` | 120/120 | 19/120 | mobile_cgnat 3/8 |
|  | `tor` | 120/120 | 0/120 |  |
|  | `bulletproof` | 120/120 | 0/120 |  |
| 3 | `cloud_vms` | 120/120 | 0/120 | consumer_vpn 3/3, mobile_cgnat 4/8 |
| 4 | `xff_home` | 120/120 | 0/120 | consumer_vpn 3/3, mobile_cgnat 3/8 |
|  | `xff_localhost` | 20/120 | 0/120 |  |
|  | `xff_internal_random` | 120/120 | 0/120 |  |
| 5 | `residential` | 120/120 | 0/120 | consumer_vpn 3/3, mobile_cgnat 3/8 |
|  | `residential_us` | 120/120 | 2/120 |  |
|  | `residential_nocookies` | 120/120 | 120/120 |  |
|  | `ipv6_rotation` | 120/120 | 16/120 |  |

<details><summary>Round 1 scoreboard (one cloud VM vs a per-IP rate limit, level 1: PASS)</summary>

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:r1_cloud_v6 | 121 | 121 | 0 | 0 | 0.0 | 6.86 |
| bot:r1_cloud_vm | 121 | 20 | 0 | 101 | 0.0 | 18.52 |
| human:autofill | 6 | 6 | 1 | 0 | 0.0 | 2.42 |
| human:consumer_vpn | 18 | 18 | 3 | 0 | 0.0 | 18.58 |
| human:home | 144 | 144 | 24 | 0 | 0.0 | 6.44 |
| human:mobile_cgnat | 40 | 36 | 4 | 4 | 0.0 | 9.6 |
| human:no_js | 6 | 6 | 1 | 0 | 0.0 | 2.44 |
| human:old_chrome | 6 | 6 | 1 | 0 | 0.0 | 5.44 |
| human:private_relay | 12 | 12 | 2 | 0 | 0.0 | 1.73 |
Bots stopped: **101/242** requests · shoppers hurt: **4/40** people (4/232 requests stopped, including challenges they then solved) · purchases: {'human': 36} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

</details>

<details><summary>Round 2 scoreboard (free proxies and Tor vs blocklists, level 2: PASS)</summary>

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:r2_bulletproof_host | 121 | 0 | 0 | 121 | 100.0 | 9.27 |
| bot:r2_free_proxy | 121 | 19 | 0 | 102 | 84.3 | 27.91 |
| bot:r2_tor_exit | 121 | 0 | 0 | 121 | 100.0 | 16.31 |
| human:autofill | 6 | 6 | 1 | 0 | 0.0 | 1.95 |
| human:consumer_vpn | 18 | 18 | 3 | 0 | 0.0 | 14.48 |
| human:home | 144 | 144 | 24 | 0 | 0.0 | 6.35 |
| human:mobile_cgnat | 39 | 36 | 5 | 3 | 0.0 | 13.98 |
| human:no_js | 6 | 6 | 1 | 0 | 0.0 | 2.12 |
| human:old_chrome | 6 | 6 | 1 | 0 | 0.0 | 8.99 |
| human:private_relay | 12 | 12 | 2 | 0 | 0.0 | 2.4 |
Bots stopped: **344/363** requests · shoppers hurt: **3/40** people (3/231 requests stopped, including challenges they then solved) · purchases: {'human': 37} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

</details>

<details><summary>Round 3 scoreboard (fresh cloud VMs vs reputation scoring, level 3: PASS)</summary>

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:r3_cloud_vms | 121 | 0 | 0 | 121 | 58.4 | 67.14 |
| human:autofill | 6 | 6 | 1 | 0 | 0.0 | 2.33 |
| human:consumer_vpn | 3 | 0 | 0 | 3 | 40.0 | 65.95 |
| human:home | 144 | 144 | 24 | 0 | 0.0 | 12.37 |
| human:mobile_cgnat | 39 | 35 | 4 | 4 | 0.0 | 24.45 |
| human:no_js | 6 | 6 | 1 | 0 | 0.0 | 2.18 |
| human:old_chrome | 6 | 6 | 1 | 0 | 0.0 | 63.31 |
| human:private_relay | 12 | 12 | 2 | 0 | 0.0 | 2.7 |
Bots stopped: **121/121** requests · shoppers hurt: **7/40** people (7/216 requests stopped, including challenges they then solved) · purchases: {'human': 33} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

</details>

<details><summary>Round 4 scoreboard (X-Forwarded-For spoofing vs trusted proxies, level 4: PASS)</summary>

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:r4_xff_fixed | 121 | 0 | 0 | 121 | 77.6 | 47.48 |
| bot:r4_xff_home | 121 | 0 | 0 | 121 | 68.9 | 47.26 |
| bot:r4_xff_internal_random | 121 | 0 | 0 | 121 | 78.2 | 22.94 |
| human:autofill | 6 | 6 | 1 | 0 | 0.0 | 13.83 |
| human:consumer_vpn | 3 | 0 | 0 | 3 | 40.0 | 99.19 |
| human:home | 144 | 144 | 24 | 0 | 0.0 | 18.4 |
| human:mobile_cgnat | 39 | 36 | 5 | 3 | 0.0 | 41.26 |
| human:no_js | 6 | 6 | 1 | 0 | 0.0 | 2.44 |
| human:old_chrome | 6 | 6 | 1 | 0 | 0.0 | 20.64 |
| human:private_relay | 12 | 12 | 2 | 0 | 0.0 | 23.98 |
Bots stopped: **363/363** requests · shoppers hurt: **6/40** people (6/216 requests stopped, including challenges they then solved) · purchases: {'human': 34} · drop stock left: {'lab-hoodie-1': 50, 'lab-runner-9': 50}

</details>

<details><summary>Round 5 scoreboard (residential proxies vs session signals and /64 limits, level 5: PASS)</summary>

| actor | requests | served | purchased | stopped | avg score | gate ms |
|---|---|---|---|---|---|---|
| bot:r1_cloud_v6 | 120 | 16 | 0 | 104 | 0.0 | 145.6 |
| bot:r5_residential | 121 | 1 | 0 | 120 | 98.8 | 109.85 |
| bot:r5_residential_nocookies | 120 | 120 | 0 | 0 | 0.0 | 165.52 |
| bot:r5_residential_us | 121 | 3 | 0 | 118 | 43.9 | 91.89 |
| human:autofill | 6 | 6 | 1 | 0 | 0.0 | 96.62 |
| human:consumer_vpn | 3 | 0 | 0 | 3 | 40.0 | 185.4 |
| human:home | 144 | 144 | 24 | 0 | 0.0 | 84.82 |
| human:mobile_cgnat | 41 | 38 | 5 | 3 | 0.0 | 85.56 |
| human:no_js | 6 | 6 | 1 | 0 | 0.0 | 125.57 |
| human:old_chrome | 6 | 6 | 1 | 0 | 0.0 | 82.79 |
| human:private_relay | 12 | 12 | 2 | 0 | 0.0 | 138.08 |

</details>
<!-- results:end -->
