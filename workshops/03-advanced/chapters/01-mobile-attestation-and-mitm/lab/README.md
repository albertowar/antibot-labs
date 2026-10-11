# Chapter 1 Lab: Mobile Apps, Attestation & MitM

**Format:** 4 rounds of attack ⚔️ defend, ~130 min. See `../chapter_01_content.md`, §1.9.

You play both sides. First you are the reverse engineer: you intercept a mobile
app's API, replay it, beat certificate pinning, forge and then steal attestation
tokens, and finally farm genuine ones from emulators. After each attack you put
on the defender's hat and add the layer that stops it — and measure what that
layer costs the real customers running the app.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the demo store through `labnet.py` at the lab root, which refuses any target that is not this machine before a single request is sent. Do not remove that check.
- The accounts, credentials and device ids are synthetic. "Egress" IPs are *claimed* with a header from a documentation range (RFC 5737, e.g. `198.51.100.0/24`); the lab never routes through a real proxy or a proxy list.
- The optional mitmproxy demo only intercepts your own local traffic, and `attacks/mitm_capture.py` drops any flow that is not to this machine. The lab never asks you to add the mitmproxy CA to your system trust store.
- Certificate-pinning bypass with Frida / objection needs a rooted device and is **discussed on the slides, not run here**; this lab models it by toggling the client's pin check.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages, browsers and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  README.md            this file
  requirements.txt     pinned versions (Python 3.12+)
  requirements-mitmproxy.txt  optional: mitmproxy for the live demo (pins cryptography 48, see inside)
  docker-compose.yml   OPTIONAL — only for the production-shaped Redis/Postgres path
  demo_site/
    app.py             the Lab Runner mobile API (DEFENSE_LEVEL 0–3)
    models.py          User / Order / Decision
    edge.py, ja4.py    the TLS edge that computes JA4 (reused from W2 Ch5/Ch9)
  defenses/
    mobile_core.py     attestation + signing machinery (the "provider"); NOT a TODO
    request_checks.py  L0: app shape + per-egress rate
    attestation.py     L1 — Round 2 TODO
    request_signing.py L2 — Round 3 TODO
    device_verdict.py  L3 — Round 4 TODO
    pinned_client.py   Round 1 TODO (client-side certificate pinning)
    risk_engine.py     the 0–100 score, three outcomes, shadow mode
  attacks/
    mobile_client.py   the app SDK (genuine app AND attacker use it)
    mitm_capture.py    live mitmproxy addon (instructor demo)
    round1_intercept.py … round4_farm.py
    data/egress_pool.txt
  tools/
    make_cert.py  seed.py  doctor.py  legit_traffic.py  checkpoint.py  scoreboard.py  lab.py
    personas.py        the 12 simulated customers (incl. the false-positive cohort)
  solutions/round1..4/ reference answers (applied by `checkpoint --catch-up`)
```

## Setup (before the session)

```bash
python -m venv .venv && source .venv/bin/activate      # one venv per chapter, see the root README
pip install -r requirements.txt
pip install -r requirements-mitmproxy.txt   # optional: only for the live interception demo
python tools/make_cert.py            # self-signed cert for the TLS edge (the pin target)
python tools/seed.py                 # 12 customer accounts, clean slate
python tools/doctor.py               # preflight: packages, cert, store
# start the store (no Docker needed — SQLite + in-memory Redis):
REDIS_URL=memory:// DEFENSE_LEVEL=0 python demo_site/app.py     # https://localhost:8443
```

Each round runs the store at a specific `DEFENSE_LEVEL`. Restart it with the
level the round needs:

| DEFENSE_LEVEL | Adds | Module | Round |
|---|---|---|---|
| 0 | app shape + per-egress rate | `request_checks.py` | 1 (baseline) |
| 1 | require a valid attestation verdict | `attestation.py` | 2 |
| 2 | bind to this request: hash + nonce + freshness | `request_signing.py` | 3 |
| 3 | verdict integrity + device/egress velocity | `device_verdict.py` | 4 |

Layers above the current level run in **shadow mode**: their points are logged in
`decisions.shadow` but don't count, so you can see what a layer *would* do before
it can block anyone. The risk engine turns the score into an outcome:

```
score < 30  allow      30–59  challenge (step-up)      >= 60  block
```

Round 1's defence is different: certificate pinning lives in the **client**
(`defenses/pinned_client.py`), because it decides whether the attacker can read
the API at all, before the server scores anything.

Debug endpoint, never blocked: `GET /api/mobile/whoami` shows your JA4, whether
you're attested, your integrity level and how L0 scores you.

### Troubleshooting

| Problem | Fix |
|---|---|
| `No TLS certificate` on start | `python tools/make_cert.py` |
| Port 8443 in use | `PORT=9443 python demo_site/app.py` and `export DEMO_URL=https://localhost:9443` |
| `unknown command 'hello'` from Redis | you installed an old `fakeredis`; `pip install -r requirements.txt` (needs `fakeredis==2.39.0`) |
| Checkpoint says "needs DEFENSE_LEVEL=N" | restart the store with that level (and `REDIS_URL=memory://`) |
| mitmproxy won't install | it is in `requirements-mitmproxy.txt`, not in `requirements.txt`, because mitmproxy 12.2 needs `cryptography<=48.1`. Install it only for the live interception demo; the rounds and checkpoint don't need it |
| Want a clean slate | `python tools/seed.py` (wipes and reseeds) |

## How to measure a round

```bash
python tools/checkpoint.py --round 2
```

It measures **both sides**:

- **Bot traffic** — this round's attack, and how many pairs it buys.
- **Legitimate users** — the 12 simulated customers (`tools/legit_traffic.py`):
  allowed / challenged / blocked. Challenges are friction, not failure.
- **Defender cost** — scoring time per buy (from the `Server-Timing` header).

Fell behind, or want to see the finished defense? `--catch-up` copies this
round's reference solution over your edit (saving a `.bak`), then restart the store:

```bash
python tools/checkpoint.py --round 3 --catch-up
```

---

## Round 1 — 🗡️ Intercept & replay ⚔️ 🛡️ Certificate pinning (store at L0)

The attacker put mitmproxy between the app and the store, read the plaintext
`/api/mobile/buy` call, and replays it from Python with the app's User-Agent and
`X-App-Id`. At L0 the mobile API trusts anything app-shaped, so it works.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `python attacks/round1_intercept.py` | 6/6 pairs bought |
| 🛡️ Defend | Implement `check_pin` in `defenses/pinned_client.py` (compute the SPKI pin, raise `PinMismatch`) | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | attack through (the vuln) · pinning refuses the proxy cert · 12/12 allowed |

**Live demo (optional).** In three terminals: start the store; run
`mitmdump --listen-port 8080 -s attacks/mitm_capture.py --ssl-insecure`; drive
the app through `HTTPS_PROXY=http://127.0.0.1:8080`. Watch calls land in
`attacks/data/captured_calls.jsonl`. With pinning on, the app refuses to connect.

**Discuss:** why can't a web page pin like a native app can? What breaks when the
server rotates its certificate?

## Round 2 — 🗡️ Beat the pin ⚔️ 🛡️ App attestation (store at L1)

On a rooted phone the attacker disables the pin (Frida / objection — conceptual)
and intercepts again. They try two things: send no attestation, and forge a
"strong integrity" verdict with their own key. Both fail: they can't produce the
provider's signature.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `DEFENSE_LEVEL=1 … python demo_site/app.py`, then `python attacks/round2_unpin.py` | 0/6 — `[L1] No valid attestation` |
| 🛡️ Defend | Implement `score` in `defenses/attestation.py` | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | 0/6 bought · 12/12 allowed |

**Discuss:** Play Integrity vs. App Attest vs. Private Access Tokens — what does
each actually prove, and to whom?

## Round 3 — 🗡️ Replay a real token ⚔️ 🛡️ Request signing (store at L2)

The attacker can't forge a verdict, so they *lift a genuine one* off the wire and
replay it. The signature is perfect — L1 is satisfied — but the verdict belongs
to another request and its nonce is already spent.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `DEFENSE_LEVEL=2 … python demo_site/app.py`, then `python attacks/round3_replay.py` | 0/6 — `[L2] nonce already spent (replay)` |
| 🛡️ Defend | Implement `score` in `defenses/request_signing.py` (binding + nonce + freshness) | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | 0/6 bought · 12/12 allowed |

**Discuss:** classic (nonce) vs. standard (requestHash) Play Integrity requests —
when do you need each?

## Round 4 — 🗡️ Farm genuine attestations ⚔️ 🛡️ Verdict scoring (store at L3)

The attacker runs the real app on emulators and mints fresh, bound, single-use
verdicts — each individually valid. The tell is the honest verdict of an
emulator: no hardware-backed integrity. The defence scores integrity and device
velocity. **This is where real users get hurt:** rooted, GrapheneOS and old
uncertified devices return weak integrity too.

| Step | Do | Expected |
|---|---|---|
| 🗡️ Attack | `DEFENSE_LEVEL=3 … python demo_site/app.py`, then `python attacks/round4_farm.py` | 0/12 — weak integrity + farm velocity |
| 🛡️ Defend | Implement `score` in `defenses/device_verdict.py` (block the farm, only challenge a lone weak device) | – |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | 0/12 bought · 10/12 allowed · 2 GrapheneOS **challenged (friction)** · 0 blocked |

**Discuss:** your drop just turned away two privacy-conscious customers to stop
the farm. Is that trade acceptable? What would you measure before shipping it?

---

## ☕ Break (10 min)

## Wrap-up: false positives and cost

```bash
python tools/scoreboard.py --action buy
```

Review where the points came from. The signal that stopped the emulator farm
(weak integrity) is the same one that added friction for real GrapheneOS and old
devices. CGNAT makes it worse: cluster many real weak-integrity phones behind one
carrier IP and the per-egress farm signal starts flagging them. The lesson of the
chapter: attestation raises the attacker's cost a lot, but it is a tax on a real,
named set of your users — budget for it.

## Instructor: expected results

Run from a clean `python tools/seed.py`, store at the round's level, store
`REDIS_URL=memory://`. Numbers are deterministic.

| Round | Level | Attack | Pairs bought | Legit (allow/chal/block) | First reason |
|---|---|---|---|---|---|
| 1 | 0 | `round1_intercept` | **6/6 through** (+ pinning refuses proxy cert) | 12 / 0 / 0 | mobile API trusts an app-shaped request |
| 2 | 1 | `round2_unpin` | **0/6** | 12 / 0 / 0 | `[L1] No valid attestation` |
| 3 | 2 | `round3_replay` | **0/6** | 12 / 0 / 0 | `[L2] nonce already spent (replay)` |
| 4 | 3 | `round4_farm` | **0/12** | 10 / 2 / 0 | `[L3] weak integrity` + `N weak devices from <egress> (farm)` |

Defender scoring cost: ~4–7 ms median per buy on the SQLite + memory path.

**Things to watch for:**
- Before students implement a round's TODO, the attack gets through — that is the
  point. `--catch-up` unblocks anyone who falls behind.
- Round 4 blocks zero legitimate users but **challenges the two GrapheneOS
  customers**. If a student's tuning blocks them, that is a real (over-strict)
  policy, worth discussing, not a bug.
- The attacker's `device="emulator"` is not a cheat: `mobile_core.mint()` only
  stamps the honest verdict of the device profile passed in. Nobody holds the
  provider's private key but the lab itself (it stands in for Google/Apple).

**Verified with** Python 3.12.15 on Linux, `requirements.txt` as pinned (Flask 3.1.3, SQLAlchemy 2.1.4, cryptography 50.0.2, redis 8.1.0, fakeredis 2.39.0), SQLite and in-memory Redis (`REDIS_URL=memory://`). Rounds 1-4 each pass `tools/checkpoint.py` with the reference solutions applied (`--catch-up`, store restarted per level), and the numbers match the table above. After `pip install -r requirements-mitmproxy.txt` in the same venv (mitmproxy 12.2.3, cryptography 48.0.1) `mitmdump --version` works and all four checkpoints still pass (Round 4 re-run with cryptography 48.0.1 for this check; the optional mitmproxy extra was checked with cryptography 48.0.1, then the baseline 50.0.2 was restored). The pip resolver prints a harmless `typing_extensions` conflict warning (mitmproxy pins 4.14, anyio wants 4.16). The `docker compose` path is verified separately.

## Bonus challenges

- Make Round 4 harder for the defender: give the farm **one** emulator per egress
  so the per-egress velocity signal never fires. What's left to catch them?
- Add a `/api/mobile/login` attestation requirement and re-run the credential
  tooling from W2 Ch6. Does attestation change the ATO economics?
- Switch the store to the Docker path (`docker compose up -d --wait`, set
  `DATABASE_URL`/`REDIS_URL`, uncomment `psycopg`) and confirm the numbers match.
