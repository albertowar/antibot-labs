# Post-incident report: the capstone drop

*Template for the final debrief. Fill one in (alone, against the reference answers in the README). It is the same
shape W3 Ch4 (Detection Signal Lifecycle & Ops) uses, because writing the kill chain down is how a stack actually
improves between drops.*

---

## 1. Summary

- **Incident window:** <start> to <end>
- **Scenario:** limited drop, 50 pairs of the Lab Runner 9, one per account
- **Final DEFENSE_LEVEL:** 7 (all layers)
- **Pairs lost to bots:** <n> / 50
- **People hurt:** <n> / 43 blocked · <n> challenged (friction)
- **API clients hurt:** <n> / 3 (a mobile app, a second phone, a partner integration)

## 2. The kill chain (what each attacker move did, and which layer answered it)

| Round | Attacker move | First layer that caught it | Signal | Got through? |
|---|---|---|---|---|
| 0 | `requests`, `curl_cffi` without JS, stock Chromium | L0 | `ua:red_flag` · `sensor_gate:no_sensor` · `client_hints:headless_brand` | no |
| 1 | GraphQL introspection | L5 API hardening | `api_hardening:introspection` | no |
| 1 | GraphQL aliased batch | L5 API hardening | `api_hardening:query_cost` | no |
| 1 | REST pagination scrape | L5 API hardening | `api_hardening:no_token` | no |
| 1 | WebSocket flood | L5 (per-connection bucket) | the socket is closed after 20 messages | no |
| 2 | Micro-burst | L6 streaming (rate) | `streaming:rate` | no |
| 2 | Low-and-slow poll | L6 streaming (regularity) | `streaming:regularity` | no |
| 3 | Third-party skimmer | L7 CSP `connect-src` | the browser refuses the POST; a violation report is sent | no |
| 4 | Integrated assault | L5, then L6, then L0 | <fill in from the checkpoint's kill chain> | no |

## 3. Signal health during the attack

*From `python tools/signalhealth.py` (or the Grafana board under `--profile prod`).*

- Layers that fired: <list>
- **Layers that stayed silent (findings):** <list. For each: was it bypassed, drifted, or simply never attacked? In this lab L1 to L4 are silent unless you replay the Workshop 2 fleet, and that is a finding too: a layer with no live test is a layer you cannot vouch for.>
- Defender cost: gate median <n> ms, max <n> ms on the drop POST (it includes the stream's inline work from level 6)

## 4. False positives

| Population | Layer | Outcome | Acceptable? | Who decides? |
|---|---|---|---|---|
| Privacy-extension browser | L1 `lie_detection` | challenge, then buys | | |
| Voice-control user | L2 `behavior_l1` | challenge, then buys | | |
| Password-manager buyer (1.2 to 1.6 s) | L2 `behavior_l1`, `flow` | challenge, then buys | | |
| No-JavaScript visitor | L0 `sensor_gate`, L4 `token_binding` | blocked | | |
| Mobile app, second phone, partner integration | L5 | allowed | | |

## 5. Where the attacker still wins

- <e.g. a real device farm rotating its fingerprint: every browser-and-timing signal is real. Answered only by attestation, W3 Ch1>
- <e.g. a low-and-slow client spread across many sessions dilutes the per-session stream state>
- <e.g. a skimmer that compromises a script you host yourself sits inside your own CSP origin>

## 6. One improvement for the next drop

- **Signal to add or retune:** <one concrete change>
- **What it would have caught:** <which move from section 2>
- **False-positive cost you would watch:** <population, metric, budget>
