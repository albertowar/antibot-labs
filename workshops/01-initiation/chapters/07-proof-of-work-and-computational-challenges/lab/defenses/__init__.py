"""
Defenses: the gate every request passes through.

    pipeline.py   Signal / Verdict / Check and run(): the engine (do not edit in labs)
    policy.py     bands, points and responders: the tuning file
    ladder.py     LADDER = {level: [checks]}: the wiring file students edit
    context.py    Ctx: everything a check may look at (no Flask inside)
    store.py      Redis (or in-process fakeredis) helpers: buckets, counters, namespaces
    decision_log.py  one record per gated request, buffered

A chapter adds `defenses/<name>.py` exposing `CHECK = Check("name", fn)` and
wires it into ladder.LADDER[round]. See example_check.py.
"""
