# Round 1 reference answer: a signal goes quiet

`data/ops_config.json` here is the operator state this round leaves behind. `python tools/checkpoint.py --round 1 --catch-up`
installs it (the store hot-reloads it); the checkpoint also checks that the commands below write exactly this file.

```bash
python tools/weeks.py --week 2
python tools/alerts.py --week 2                     # silent: headless_gpu, tz_geo_mismatch, webdriver_flag
python tools/sweep.py --weight mouse_too_straight=25 --weight timing_too_regular=25   # replay first
python tools/configure.py --weight header_order_mismatch=0 --weight mouse_too_straight=25 \
    --weight timing_too_regular=25 --note "R1: header order burned; behaviour re-weighted"
```

Why these three: `header_order_mismatch` is the signal the impersonator burned (it now sends Chrome's own order),
so it goes to weight 0 (intelligence only). The impersonator still trips the two behaviour signals, so they are
lifted until a ruler-straight, timer-driven mouse costs 25 + 25 on top of `datacenter_asn` (25): a block (60).
The price: every real customer who trips one of them alone (a keyboard-only user, a paste) now sits 10 points
closer to a challenge. `tools/sweep.py --signal timing_too_regular` names them.
