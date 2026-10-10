# Round 1 solution — inventory + change detection

Detection only. The card still gets out; that is the lesson.

```bash
# 1) Baseline the KNOWN-GOOD release
cd demo_site && VENDOR=clean python app.py        # shell A
python defenses/inventory_scripts.py              # shell B
python defenses/script_monitor.py --create-baseline

# 2) The vendor swaps the file — restart with the default (compromised) vendor
#    CSP_MODE=off SKIMMER_VARIANT=beacon VENDOR=compromised
cd demo_site && python app.py                     # shell A (Ctrl-C first)

# 3) Detect the change, then watch the skimmer still win
python defenses/inventory_scripts.py
python defenses/script_monitor.py                 # -> CHANGED analytics-helper.js
python attacks/round1_vendor_skimmer.py           # -> EXFIL SUCCEEDED
python tools/checkpoint.py --round 1
```
