# Round 2 reference answer: the world moves under you

`data/world_updates.json` here is what `tools/refresh_corpus.py --all --week 3` writes: the range Example Fiber
bought, Chrome 146's header order and JA4, and the freshness stamps. `python tools/checkpoint.py --round 2 --catch-up`
installs it (every sensor hot-reloads it); the checkpoint also checks that the command writes exactly this file.

```bash
python tools/weeks.py --week 3
python tools/alerts.py --week 3 --drift             # known_good: header_order_mismatch on 70% of the monitors; corpus stale
python tools/refresh_corpus.py --all --week 3
python tools/train.py --weeks 1-2 --labels weak     # v1, trained on the clean weeks
python tools/roles.py promote v1                    # the W2 Ch7 model joins the stack as one more sensor
```

The refresh retires the stale blocklist entry and the datacenter label for 203.0.113.0/27, adds Chrome 146's order
to the corpus (it keeps the old one: older installs still send it), and teaches the TLS table the new JA4.
It fixes every false positive and catches none of the new bots, because they are residential and have a hand.
The model (`v1`) is trained, not shipped by the refresh: models/ is rebuilt by the checkpoint.
