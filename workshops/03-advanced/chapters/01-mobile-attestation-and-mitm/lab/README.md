# Chapter 1 Lab: Mobile Apps, Attestation & MitM

Starts from: `workshops/03-advanced/starter/` (contract 1.5). Adds: the Lab Runner mobile API (`demo_site/ext/mobile.py`), a baseline app-shape and rate check (Round 0), the five defenses of the arms race (`pinned_client`, `attestation`, `request_signing`, `device_verdict`, `session_binding`), the attestation provider mock (`mobile_core`, now also vouching for device keys), the app SDK the shoppers and the attackers share, five attackers and the 40 shoppers recast as phone owners. `defenses/ja4.py` and `known_fingerprints.json` are copied byte for byte from W2 Ch3 (see `shared.json`).

<!-- lab-diff:start -->
**Adds** (files not in the starter):

- `defenses/attestation.py`
- `defenses/device_verdict.py`
- `defenses/ja4.py`
- `defenses/known_fingerprints.json`
- `defenses/mobile_core.py`
- `defenses/pinned_client.py`
- `defenses/request_checks.py`
- `defenses/request_signing.py`
- `defenses/session_binding.py`
- `demo_site/ext/mobile.py`
- `tools/make_cert.py`
- `tools/mobile_sdk.py`
- `tools/personas_ch1.py`

**Edits** (student and tuning files):

- `defenses/ladder.py`
- `defenses/policy.py`
- `tools/checkpoint.py`
<!-- lab-diff:end -->

**Format:** five rounds of attack 🔴 and defend 🔵, then a debrief. See `workshops/03-advanced/chapters/01-mobile-attestation-and-mitm/chapter_01_content.md` (slides repo), §1.7 (the device-bound session theory is §1.6). **Style: wire-it.** Each defense ships as a stub with a `TODO (Round N)` and the finished file is in `solutions/roundN/`; `--catch-up` installs rounds 1..N and `--restore` puts your files back. The provider mock, `defenses/mobile_core.py`, is infrastructure, not a TODO.

You play both sides. First you are the reverse engineer: you intercept a mobile app's API, replay it, beat certificate pinning, forge and then steal attestation verdicts, farm genuine ones from emulators, and finally steal the session itself. After each attack you put on the defender's hat and add the layer that stops it, and you measure what that layer costs the real customers running the app.

This lab runs on the W3 starter's store (Kestrel Outfitters) and shows what **this lab adds**: a second front door, the mobile API under `/api/mobile/`, selling the starter's `lab-runner-9` drop (one pair per account). Everything else (catalogue, accounts, the edge, the decision log) is the starter, unchanged. Its contract is `workshops/STORE_CONTRACT.md`.

## Rules of engagement

- **Local only, enforced in code.** Every attack script and tool reaches the store through `tools/labclient.py`, which asks `labnet.py` at the lab root for `DEMO_URL` and refuses anything that is not this machine (side-service URLs such as `REDIS_URL` too) before a single request is sent. The store's edge accepts the lab headers only from loopback. Do not remove that check.
- **Everything is synthetic.** Accounts are the starter's `user000..299@example.test`, plus throwaway `@mail.example` addresses the attackers register. Device ids and attestation verdicts are made by the lab's own provider mock. "Source addresses" are rented from `data/world.json` (documentation ranges, RFC 5737 and RFC 3849) and sent in `X-Lab-Client-IP`; the lab never routes through a real proxy or a proxy list.
- **The TLS fingerprint is claimed, not measured.** The store sits behind no TLS edge (the series' labs speak plain HTTP on loopback), so a client states the JA4 its real stack would put on the wire in `X-Lab-JA4` and the gate reads it as a *claimed* fingerprint (W2 Ch3 builds the measured one). The certificate Round 1 pins is a stand-in written by `tools/make_cert.py`; nothing serves it.
- The optional mitmproxy demo only intercepts your own local traffic, and `attacks/mitm_capture.py` drops any flow that is not to this machine. The lab never asks you to add a proxy CA to your system trust store.
- Certificate-pinning bypass with Frida / objection needs a rooted device and is **discussed on the slides, not run here**; the lab models it by letting the attacker skip the client's pin check.
- **Outbound network:** none during the rounds. Only setup needs the internet: installing packages (and mitmproxy, if you want the live demo) and container images.
- Do not point these scripts, or anything you build from them, at a site you do not own.

```
lab/
  README.md              this file
  requirements.txt       pinned versions (Python 3.12+; cryptography for the provider mock and the pin)
  requirements-mitmproxy.txt  optional: mitmproxy for the live demo (pins cryptography 48, see inside)
  shared.json            the two W2 Ch3 files copied byte for byte (python scripts/lab_diff.py <this lab> --shared)
  demo_site/ext/mobile.py    the Lab Runner API: /api/mobile/{config,nonce,register,login,buy,orders,whoami}, and the
                         enricher that verifies X-Attest and exposes the bound key and proof (Round 5)
  defenses/
    mobile_core.py       the attestation PROVIDER MOCK (key pair, mint, verify) and the device-key/proof helpers: NOT a TODO
    request_checks.py    level 0 (Round 0): app shape, per-address rate, a soft claimed-JA4 tell
    pinned_client.py     Round 1 TODO: certificate pinning (client code, not in the ladder)
    attestation.py       Round 2 TODO: require a valid provider verdict
    request_signing.py   Round 3 TODO: bind to this request, fresh, single-use nonce
    device_verdict.py    Round 4 TODO: integrity + device/address velocity
    session_binding.py   Round 5 TODO: bind the session to a device key (proof check)
    ladder.py            levels 0-5 wired (yours, but the stubs are already in it)
    ja4.py, known_fingerprints.json   W2 Ch3's TLS module, copied
  attacks/
    round1_intercept.py … round5_hijack.py   one attacker per round; _common.py; mitm_capture.py (live demo)
  tools/
    mobile_sdk.py        the app SDK (the genuine app AND the attacker use it)
    personas_ch1.py      the 40 shoppers as phone owners (incl. the false-positive cohort)
    make_cert.py         the certificate the app pins
    checkpoint.py        ROUNDS and thresholds
  solutions/round1..5/   reference files (applied by `checkpoint.py --catch-up`)
```

## Setup

```bash
python3.12 -m venv .venv && . .venv/bin/activate        # one venv per chapter, see the root README
pip install -r requirements.txt
pip install -r requirements-mitmproxy.txt   # optional: only for the live interception demo
python tools/doctor.py                      # preflight
python demo_site/app.py                     # http://127.0.0.1:5000, SQLite + in-process Redis, no Docker
```

Setup beyond the shared walkthrough (`PREWORK.md`) is the line for `cryptography`. Each round runs the store at a `DEFENSE_LEVEL`; the checkpoint sets it for you (`POST /lab/level`), so you rarely restart anything. To drive it by hand:

| DEFENSE_LEVEL | Adds | Module | Round |
|---|---|---|---|
| 0 | app shape + per-address rate + a soft claimed-JA4 tell, always on | `request_checks.py` | (baseline) |
| 1 | nothing on the server: pinning lives in the app | `pinned_client.py` | 1 |
| 2 | require a valid attestation verdict | `attestation.py` | 2 |
| 3 | bind it to this request: hash + nonce + freshness | `request_signing.py` | 3 |
| 4 | verdict integrity + device/address velocity | `device_verdict.py` | 4 |
| 5 | the session is bound to a device key: a signed single-use proof | `session_binding.py` | 5 |

Run with `LAB_SHADOW=1 python demo_site/app.py` and the layers above the current level still run, logged in `X-Lab-Shadow` and the decision log but never enforced: see what a layer *would* do before it can hurt anyone. The starter's bands turn the score into an outcome:

```
score < 20  allow      20-39  monitor (served, logged)      40-74  challenge      >= 75  block
```

This store has no step-up flow behind the `challenge` band, so the gate **enforces it as a refusal** (contract §4.1): the cost of a challenge you cannot serve is visible, and it is the point of Rounds 4 and 5.

Round 1's defense is different: certificate pinning lives in the **client** (`defenses/pinned_client.py`), because it decides whether the attacker can read the API at all, before the server scores anything.

Debug route, never gated: `GET /api/mobile/whoami` shows the JA4 the edge saw, whether you are attested, your integrity level and how level 0 scores you (add `-H 'X-Lab-Client-IP: 203.0.113.9'`, or whatever address you rent).

### Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: cryptography` | `pip install -r requirements.txt` in the lab's own `.venv` |
| `unknown command 'hello'` from Redis | an old `fakeredis`; reinstall the requirements (needs `fakeredis[lua]==2.39.0`) |
| Checkpoint says it cannot reach the store | start it (`python demo_site/app.py`) or use `python tools/verify.py --round N`, which starts one on a free port |
| A round's attacker "succeeded" and you expected a block | restart is not needed (`LAB_RELOAD=1`); check that you saved the module and that its `CHECK` is the one in `defenses/ladder.py` |
| mitmproxy will not install, or pip warns about `typing_extensions` | it is in `requirements-mitmproxy.txt` because mitmproxy 12.2 needs `cryptography<=48.1` (the file downgrades it in your venv). The `typing_extensions` conflict warning (mitmproxy pins 4.14, anyio wants 4.16) is harmless. Only the live demo needs the file |
| Want a clean slate | `curl -X POST 'http://127.0.0.1:5000/lab/reset?mode=full'` |

## How to measure a round

```bash
python tools/checkpoint.py --round 2
```

It prints PASS or FAIL against explicit thresholds and measures **both sides**:

- **Bot traffic**: this round's attacker, and how many pairs it gets (`expect`: `full` = at least 90 %, `blocked` = at most 10 %).
- **The shoppers**: 40 people, each logging in to the app as their own account and buying the drop through the genuine flow. A refusal of any kind that is not the round's expected cost fails the round.
- **Defender cost**: the median gate time of the shoppers' buys (`Server-Timing: gate`).

`--level N-1` runs the same attacker against the previous round's defense (the "before" column). Fell behind, or want the finished defense? `--catch-up` installs rounds 1..N (one `.bak` per file of yours), and `--restore` puts yours back:

```bash
python tools/checkpoint.py --round 3 --catch-up
python tools/checkpoint.py --restore
```

`python tools/verify.py --round N` does the same against a store it starts itself on a free port (used to build this lab; handy when you do not want a second terminal).

---

## Round 1: 🔴 intercept & replay ⚔️ 🔵 certificate pinning (`DEFENSE_LEVEL=1`)

The attacker put mitmproxy between the app and the store, read the plaintext `POST /api/mobile/buy`, and replays it from Python with the app's User-Agent, `X-App-Id` and TLS fingerprint. At level 0 the mobile API trusts anything app-shaped, so it works.

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round1_intercept.py` | 6/6 pairs bought; `pinning refuses an intercepted certificate: False` |
| 🔵 Defend | Implement `check_pin` in `defenses/pinned_client.py` (compute the SPKI pin, raise `PinMismatch`) | |
| ✅ Checkpoint | `python tools/checkpoint.py --round 1` | attacker through (the vulnerability) · the pin refuses a proxy certificate · 40 of 40 shoppers buy |

**Live demo (optional).** In three terminals: start the store, run `mitmdump --listen-host 127.0.0.1 --listen-port 8080 -s attacks/mitm_capture.py`, then drive the app through `HTTP_PROXY=http://127.0.0.1:8080` (the exact command is in the addon's docstring). Calls land in `attacks/data/captured_calls.jsonl`. The lab serves plain HTTP, so the proxy needs no CA; what a pinned client would refuse is a proxy that presents its *own certificate* on a TLS connection, and that is what `round1_intercept.py` checks.

**Discuss.** Why can't a web page pin like a native app can? *A browser trusts the operating system's CA store and lets the user extend it, and a page cannot override that; an app ships its own TLS client and its own list of keys.* What breaks when the server rotates its certificate? *Every installed app that pinned the old key, unless it pinned the SPKI (same key survives renewal) and shipped a backup pin.*

## Round 2: 🔴 beat the pin ⚔️ 🔵 app attestation (`DEFENSE_LEVEL=2`)

On a rooted phone the attacker disables the pin (Frida / objection: conceptual) and intercepts again. They try two things: send no attestation, and forge a "strong integrity" verdict with their own key. Both fail: they cannot produce the provider's signature, so the store sees no verdict at all.

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round2_unpin.py` (store at level 2) | with the stub: 6/6; finished: 0/6 with `attestation:no_verdict` |
| 🔵 Defend | Implement `_check` in `defenses/attestation.py` | |
| ✅ Checkpoint | `python tools/checkpoint.py --round 2` | 0/6 bought · 40 of 40 shoppers buy |

**Discuss.** Play Integrity vs. App Attest vs. Private Access Tokens: what does each actually prove, and to whom? *Play Integrity and App Attest prove "a genuine build on an untampered device" to your server, with a vendor-held key behind them. A Private Access Token proves "some real device vouched for this request" without saying which, so it is a rate-limiting signal, not an identity.*

## Round 3: 🔴 replay a real verdict ⚔️ 🔵 request signing (`DEFENSE_LEVEL=3`)

The attacker can't forge a verdict, so they *lift a genuine one* off the wire and replay it. The signature is perfect, so level 2 is satisfied, but the verdict belongs to another request's nonce, which is already spent.

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round3_replay.py` (store at level 3) | with the stub: 6/6; finished: 0/6 with `request_signing:replay` |
| 🔵 Defend | Implement `_check` in `defenses/request_signing.py` (binding + freshness + nonce) | |
| ✅ Checkpoint | `python tools/checkpoint.py --round 3` | 0/6 bought · 40 of 40 shoppers buy |

The hash covers the request **bytes**: the SDK sends the exact bytes it hashed (`data=`), and the enricher hashes `request.get_data()`. If a client re-serialised its JSON between hashing and sending, every honest buy would fail the binding.

**Discuss.** Classic (nonce) vs. standard (requestHash) Play Integrity requests: when do you need each? *The nonce stops the same request being sent twice; the hash stops a verdict being stapled onto a different request. Replaying an identical request only the nonce catches (the hash matches); a modified request only the hash catches (the attacker could fetch a fresh nonce).*

## Round 4: 🔴 farm genuine attestations ⚔️ 🔵 verdict scoring (`DEFENSE_LEVEL=4`)

The attacker runs the real app on emulators and mints fresh, bound, single-use verdicts: each individually valid. The tell is the honest verdict of an emulator: no hardware-backed integrity. The defense scores integrity and device velocity. **This is where real users get hurt:** rooted phones, GrapheneOS and old uncertified devices return weak integrity too.

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round4_farm.py` (store at level 4) | with the stub: 12/12; finished: 0/12 (6 challenged, 6 blocked) |
| 🔵 Defend | Implement `_check` in `defenses/device_verdict.py` (block the farm, only challenge a lone weak device) | |
| ✅ Checkpoint | `python tools/checkpoint.py --round 4` | 0/12 bought · 37 of 40 shoppers buy · **3 GrapheneOS customers refused at checkout** (the cost) · nobody else touched |

**Discuss.** Your drop just turned away three privacy-conscious customers to stop the farm. Is that trade acceptable, and what would you measure before shipping it? *Weigh the pairs the farm would take (here: 12 of 50 before the defense, and two real shoppers who found the drop sold out) against the customers refused, by segment, and by their lifetime value rather than by head count. Run the layer in shadow (`LAB_SHADOW=1`) first, add a step-up flow so the challenge band is something a person can pass, and keep the integrity signal out of the block band.*

## Round 5: 🔴 steal the bearer ⚔️ 🔵 device-bound session (`DEFENSE_LEVEL=5`)

Rounds 2 to 4 defend the buy; the login still returns a bearer token, and whoever holds it is the user. The attacker lifts a victim's token through the unpinned MitM and uses it from their *own* genuine pixel8 (unique serial, so attestation, nonce and velocity all pass), reading the victim's orders and then buying. Three variants, twice each: the token alone, a proof signed by the attacker's own key, and a proof captured off the wire.

How the store binds a session (infrastructure, like nonce issuance): every `MobileApp` generates its own EC P-256 key; at login/register it sends the public key (`X-Device-Key`) and the provider's claim about where the private half lives (`X-Key-Attest`, from `mobile_core.attest_key`: hardware or software, as in Android key attestation). `demo_site/ext/mobile.py` verifies the claim, checks it names that key and stores the key next to the token. Each sensitive call (`POST /api/mobile/buy`, `GET /api/mobile/orders`) then carries `X-Device-Proof: v1;kid=<key id>;n=<nonce>;ts=<ms>;sig=<b64>`, a signature over `sha256(token)`, the nonce, the time and the request line.

| Step | Do | Expected |
|---|---|---|
| 🔴 Attack | `python attacks/round5_hijack.py` (store at level 5) | with the stub: 6/6; finished: 0/6, every attempt refused on the read or the buy |
| 🔵 Defend | Implement `_check` in `defenses/session_binding.py` (absent / invalid / verified; spend the nonce last) | |
| ✅ Checkpoint | `python tools/checkpoint.py --round 5` | 0/6 bought · 36 of 40 shoppers buy · **4 refused**: the 3 GrapheneOS customers (Round 4) and the `autofill` shopper who restored a backup (the new cost) · nobody else touched |

The new cost is the lost key. The `autofill` shopper restores their phone from a backup between login and checkout (`MobileApp.reinstall()`): the bearer token comes back with the backup, the keystore key does not, so the proof names a different key (`key_changed`, 50: the challenge band, enforced as a refusal here). A thief and a restored phone look the same from the request. With a step-up (re-authenticate, then rebind) the owner passes and the thief does not; this store has none, so the bill is visible.

Clock matters here, unlike Round 3: the proof's timestamp is the *client's*, checked within 2 minutes of the server's. A phone with a wrong clock fails `stale` until the app resyncs from the nonce response.

**Discuss.** Why does a changed key earn the challenge band while a missing proof earns a block? *A missing proof, a bad signature or a spent nonce cannot come from the app holding the bound key. A different key under a valid token is what both a thief and a restored phone look like, so you challenge, then rebind after a step-up.* Real DBSC works the same way in a browser and falls back to software keys; what does that fallback cost you? *A software key can be extracted, so the binding is only as strong as the device. The lab scores it small (`soft_key`, 10) because the rooted and uncertified phones that have one already paid in Round 4.*

---

## Wrap-up: false positives and cost

```bash
python tools/scoreboard.py
```

Review where the points came from. The signal that stopped the emulator farm (weak integrity) is the same one that refused the three GrapheneOS customers, and the layer that stopped the thief (a key-signed proof) refuses the one customer who lost their key; rooted and old uncertified phones sit just under the line (25 points, served and logged). Carrier-grade NAT makes it worse: the starter's eight `mobile_cgnat` shoppers share two addresses, and the per-address farm signal counts *weak* devices per address, so they are safe only because their phones are certified; put four weak phones behind one carrier address and the signal flags real people (Bonus 1). The lesson of the chapter: attestation raises the attacker's cost a lot, but it is a tax on a real, named set of your users. Budget for it.

## Expected results (self-check)

Generated by `python tools/verify.py --write-readme --catch-up` (against your own store: `python tools/checkpoint.py --all --markdown`) with the reference solutions, on Linux x86_64 (WSL2), Python 3.12.15, Flask 3.1.3, SQLAlchemy 2.1.4, redis 8.1.0, fakeredis 2.39.0, cryptography 50.0.2, SQLite and the in-process Redis. The counts are deterministic and were identical across two runs; timings vary.

<!-- results:start -->
| Round | Attack | Before (level N-1) | After (level N) | Shoppers stopped after |
|---|---|---|---|---|
| 1 | `intercept` | 6/6 | 6/6 | none |
| 2 | `unpin` | 6/6 | 0/6 | none |
| 3 | `replay` | 6/6 | 0/6 | none |
| 4 | `farm` | 12/12 | 0/12 | none |
| 5 | `hijack` | 6/6 | 0/6 | none |
<!-- results:end -->

The table above is generated: the attacker's pairs before and after each round (its last column lists only shoppers answered with a plain block; the challenge-band refusals that are Rounds 4 and 5's cost are in the table below). The shopper side, from the same run (Round 1's pin check is separate: the proxy's certificate is accepted before the defense and refused after):

| Round | Shoppers who buy | Refused shoppers | First signals | Gate per buy, median / p95 |
|---|---|---|---|---|
| 1 | 40 / 40 | 0 | none (it looks like the app) | 2.5 / 9.7 ms |
| 2 | 40 / 40 | 0 | `attestation:no_verdict` | 2.6 / 6.7 ms |
| 3 | 40 / 40 (before: 38, the bots took 12 pairs) | 0 | `request_signing:replay` | 3.4 / 11 ms |
| 4 | **37 / 40** (before: 38) | **3** (`consumer_vpn`, GrapheneOS: `challenge` band) | `device_verdict:weak_integrity`, `unrecognised_app`, `farm` | 4.0 / 8.9 ms |
| 5 | **36 / 40** (before: 37, the bots took 6 pairs) | **4**: the same 3 GrapheneOS customers (Round 4's level still runs) plus `autofill`, who restored a backup mid-checkout (`session_binding:key_changed`, `challenge` band) | `session_binding:no_proof`, `key_changed`, `bad_signature` | 5.0 / 17 ms |

"Before" is `--round N --level N-1` with the reference solutions installed (Round 1: the stub). Where the "before" column says 38, the drop has 50 units and the bots took 12 of them (6 captured buys and 6 replays in Round 3; 12 emulators in Round 4; 6 hijacked sessions in Round 5), so real shoppers met a sold-out drop: that is what the attack costs people even when no defense hurts them. Shoppers refused is read from the scoreboard's "shoppers hurt": a person whose last request was a refusal and who bought nothing. With the Docker stack the gate time is higher (every check makes Redis round trips over TCP); the checkpoint allows 250 ms there instead of 25 ms.

**Things to watch for:**
- Until you implement a round's TODO, the attacker gets through. That is the point. `--catch-up` unblocks you if you fall behind.
- Round 4 refuses **exactly** the three GrapheneOS customers, and Round 5 adds exactly one more (the restored phone); if your tuning reaches the rooted phone or the old uncertified Android (25 points: monitor, served), the checkpoint fails, because your policy is more severe than the one the round teaches. If it spares the GrapheneOS phones but lets the farm buy, you built a leaky policy. Both are worth discussing; neither is a bug.
- The attacker's `device="emulator"` is not a cheat: `mobile_core.mint()` only stamps the honest verdict of the device profile passed in. Nobody holds the provider's private key but the lab itself (it stands in for Google and Apple).

### What the mock leaves out

Real attestation uses the vendor's asymmetric keys and a hardware root of trust in a secure element (the lab has an EC key pair in `instance/`), needs a network round trip to Google or Apple (latency and an availability dependency you must handle), rate-limits the verdict calls themselves, and ties app identity to a signing certificate you enrol. The lab reproduces the *protocol and its failure modes*, not the cryptographic hardware.

## Bonus challenges

1. **Put the weak phones behind carrier NAT.** In `tools/personas_ch1.py`, change `device_for` so four of the six `mobile_cgnat` shoppers who share the first carrier address own `rooted` or `old-uncertified` phones. Re-run Round 4: the fourth weak phone is refused as part of a "farm" (`device_verdict:farm`). What does that say about keying a velocity signal on a shared address?
2. **A lazy replay.** Send a request with `ua="python-requests/2.34.2"` and `ja4=mobile_core.PYTHON_LIB_JA4` through `MobileApp` and read the signals (`app_shape:non_app_client`, `library_tls`). Then change only the JA4 back to the app's: which signal is still there, and what does that tell you about a claimed fingerprint?
3. **Make Round 4 harder for the defender.** Give the farm **one** emulator per address so the per-address signal never fires. What is left to catch them? (Weak integrity alone is only a challenge in this store.)
4. **Build the step-up.** Register a challenge type with `hooks.challenges.register(...)` in a new `demo_site/ext/` module (W3 Ch4's `step_up.py` is a model) so the three GrapheneOS customers, and the customer who restored a backup, can pass the challenge band (for the second, re-authenticate and rebind the session to the new key), then ask what the farm, which controls its own mailbox, does with it, and why the thief with only a bearer cannot.
5. **The Docker path.** `docker compose up -d --wait`, then `REDIS_URL=redis://127.0.0.1:6379/0 DATABASE_URL=postgresql+psycopg://workshop:workshop@127.0.0.1:5432/shop python tools/verify.py --round 3 --catch-up`. The counts should match; the gate cost will not. `docker compose down -v` when you are done.
6. **Raise `soft_key`.** In `defenses/session_binding.py` raise the `soft_key` signal from 10 to 30. Re-run Round 5 and read who joins the refused (`old_chrome`, `no_js`: software-backed keys on top of Round 4's 25). Is a refusal for "your key lives in software" a fair price for the thief you stop, given that Round 4 already charged these customers for the device?
7. **Wrong clock.** Give one shopper a client clock five minutes slow (sign proofs with `ts=` shifted in `MobileApp._proof_headers`). Which signal fires, and what should the app do on a `stale` refusal?
