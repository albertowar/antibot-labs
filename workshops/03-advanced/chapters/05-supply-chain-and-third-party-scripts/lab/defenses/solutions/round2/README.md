# Round 2 solution — CSP report-only -> enforce

`connect-src 'self'` blocks the skimmer's cross-origin fetch/beacon.

```bash
# See it first in report-only (nothing blocked, violations logged):
cd demo_site && CSP_MODE=report-only SKIMMER_VARIANT=dynamic python app.py
python attacks/round2_checkout_only.py            # still exfils; check /csp-report/log

# Then enforce:
cd demo_site && CSP_MODE=enforce SKIMMER_VARIANT=dynamic python app.py
python attacks/round2_checkout_only.py            # -> nothing sensitive gets out
python tools/checkpoint.py --round 2
```
