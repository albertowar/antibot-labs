# Round 4 reference answer: when one slips through

The containment deadline is the lab clock's last request plus a week, so there is no file to install:
`python tools/checkpoint.py --round 4` rebuilds weeks 1 to 6 and runs these commands. This is the answer key.

```bash
python tools/weeks.py --week 5
python tools/ops.py --week 5                                      # the farm reached accounts; almost nothing fired
python tools/snapshot.py --week 5 --label inc-2026-05             # preserve the evidence before it rolls
python tools/label.py --cluster "<the farm cluster>" --as bot --week 5
python tools/incident.py --week 5 --id INC-2026-05                # pre-fill incident/incident_report.md
python tools/contain.py --step-up-asn 64496 --for-weeks 1         # the farm hides in Example Broadband's ASN
python tools/weeks.py --week 6                                    # the containment window
python tools/ops.py --all
```

The step-up stops the farm (it does not own the victims' mailboxes) and asks every real Example Broadband customer
for an emailed code too. Name that cost in the report: `python tools/ops.py --week 6` lists who was challenged.
Lift it before the timer with `python tools/contain.py --lift`.
