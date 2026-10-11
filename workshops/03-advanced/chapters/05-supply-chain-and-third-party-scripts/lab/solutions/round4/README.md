# Round 4 solution — runtime monitor + dependency hygiene

The skim ships inside a first-party bundle, so CSP nonces it and SRI matches
your own build. And because a real store must allow its analytics/beacon origin
in `connect-src` (here `TRUSTED_ANALYTICS`), the bundle rides that one allowed
exception straight out. Strict CSP + SRI do NOT stop it. The runtime monitor —
whose allowlist is just your own origin — flags and blocks the call-out.

```bash
# The store legitimately beacons to one third-party origin; we allow it in CSP.
# In the lab that origin is the collector, standing in for a real analytics host.
cd demo_site && CSP_MODE=strict SRI=on MONITOR=on SKIMMER_VARIANT=firstparty \
  TRUSTED_ANALYTICS=http://127.0.0.1:5001 python app.py

python attacks/round4_poisoned_bundle.py          # -> blocked by the monitor
python tools/scoreboard.py                         # /api/script-violation/log has it
python tools/checkpoint.py --round 4

# Negative control — turn the monitor OFF and watch strict CSP + SRI let it out,
# because the bundle uses the one origin your connect-src had to allow:
cd demo_site && CSP_MODE=strict SRI=on MONITOR=off SKIMMER_VARIANT=firstparty \
  TRUSTED_ANALYTICS=http://127.0.0.1:5001 python app.py
python attacks/round4_poisoned_bundle.py          # -> EXFIL SUCCEEDED

# Dependency side (concept): `npm audit` in CI, and behavioural scanners like
# socket.dev that flag a package that suddenly makes network calls.
```
