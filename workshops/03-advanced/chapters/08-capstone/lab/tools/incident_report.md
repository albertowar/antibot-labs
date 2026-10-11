# Post-Incident Report — Capstone Drop

*Template for the final debrief (Section 8.8). Fill one in as a team. It is the
same shape W3 Ch4 (Detection Signal Lifecycle & Ops) uses, because writing the
kill chain down is how a stack actually improves between drops.*

---

## 1. Summary

- **Incident window:** <start> – <end>
- **Scenario:** limited drop, 50 pairs of the Lab Runner 9, one per account
- **Final DEFENSE_LEVEL:** 7 (all layers)
- **Pairs lost to bots:** <n> / 50
- **Legitimate customers blocked:** <n> / 40   · **challenged (friction):** <n>
- **Legit API clients blocked:** <n> / 3

## 2. The kill chain (what each attack move did, and which layer answered it)

| Round | Attacker move | First layer that caught it | Reason string | Got through? |
|---|---|---|---|---|
| 1 | GraphQL introspection | L5 API hardening | `introspection is disabled` | no |
| 1 | GraphQL aliased batch | L5 API hardening | `query cost N over budget` | no |
| 1 | REST pagination scrape | L5 API hardening | `no API token` | no |
| 1 | WebSocket flood | L5 (per-conn bucket) | `message rate limit exceeded` | no |
| 2 | Micro-burst | L6 streaming (rate) | `N requests in 10s` | no |
| 2 | Low-and-slow | L6 streaming (regularity) | `CV <= threshold` | no |
| 3 | Third-party skimmer | L7 CSP connect-src | `browser would block exfil` | no |
| 4 | Integrated assault | L0/L5/L6 combined | <fill in from checkpoint> | no |

## 3. Signal health during the attack

*From `python tools/signalhealth.py` (or the Grafana board under `--profile prod`).*

- Layers that fired: <list>
- **Layers that stayed silent (findings):** <list — a silent layer during an attack window was bypassed or has drifted>
- Defender cost: scoring median <n> ms, p95 <n> ms

## 4. False positives

| Population | Layer | Outcome | Acceptable? | Who decides? |
|---|---|---|---|---|
| Privacy browser (firefox-rfp) | L1 | challenge | | |
| VDI software GPU (vdi-citrix) | L1 | challenge | | |
| New device (new-laptop) | L4 | challenge | | |
| Mobile / partner API client | L5 | allow | | |

## 5. Where the attacker still wins

- <e.g. a headed stealth browser on a real GPU defeats the L1 software-render signal>
- <e.g. fingerprint rotation across devices defeats the cluster count — answered only by attestation, W3 Ch1>
- <e.g. a human click-farm defeats behavioral analysis entirely>

## 6. One improvement for the next drop

- **Signal to add or retune:** <one concrete change>
- **What it would have caught:** <which move from section 2>
- **False-positive cost you would watch:** <population, metric, budget>
