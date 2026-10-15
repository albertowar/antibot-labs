# Round 3 reference answer: retrain without poisoning yourself

The state this round leaves behind is not a pure function of the round (the analyst labels name session ids and
the models are trained from the log), so there is no file to install: `python tools/checkpoint.py --round 3`
rebuilds weeks 1 to 4 and runs these commands. This is the answer key.

```bash
python tools/weeks.py --week 4
python tools/train.py --weeks 2-4 --labels weak                   # v2: the naive retrain, trained on circular labels
python tools/gate.py --candidate v2 --week 4                      # REFUSE: no analyst-confirmed bots to judge on
python tools/label.py --queue --week 4                            # the sessions worth a human eye
python tools/label.py --cluster "<the evader cluster>" --as bot --week 4
python tools/train.py --weeks 2-4 --labels weak+analyst           # v3
python tools/gate.py --candidate v3 --week 4                      # PASS on the labelled set, 0 FP
python tools/roles.py shadow v3                                   # score and log, act on no one
python tools/shadow_report.py --week 4                            # what v3 would newly catch, and the real users it would newly act on
python tools/roles.py canary v3 && python tools/canary.py --pct 50
python tools/rollback_watcher.py                                   # canary within budget
```

The cluster is the one with the most bot sessions in week 4: `python tools/label.py --queue --week 4` lists it.
The checkpoint also labels twelve real customers `human`, so the analyst set has both classes (a recall measured
on bots alone cannot see a false positive).
