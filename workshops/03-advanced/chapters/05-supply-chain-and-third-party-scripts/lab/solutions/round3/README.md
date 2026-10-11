# Round 3 solution — nonce + strict-dynamic, and SRI

The host-allowlist is bypassed by an injected inline script + an <img> pixel.
Strict CSP removes 'unsafe-inline' (the inline script never runs) and tightens
img-src/connect-src (the pixel is blocked); SRI refuses the swapped vendor file.

```bash
cd demo_site && CSP_MODE=strict SRI=on SKIMMER_VARIANT=allowlisted python app.py
python defenses/generate_sri.py                   # how the pin is produced
python attacks/round3_allowlist_bypass.py         # -> nothing sensitive gets out
python tools/checkpoint.py --round 3
```
