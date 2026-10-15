"""
The ladder: which checks run at which DEFENSE_LEVEL. Pre-wired in this chapter.

Level k is enforced when k <= DEFENSE_LEVEL, and `python tools/checkpoint.py --round N` sets level N.

    level 0   the bare store: the event log is written and nothing is scored (Round 0: collect the data)
    level 1   the deployed stack: oracle_guard (Round 1, yours) in front of ml_check (the model v2 baseline)
    level 2+  the same two checks, scoring with the model your Round 2, 3, 4 script wrote (model_v3, v4, v5)

Nothing is wired per round because the wiring never changes: ml_check.py reads ctx.level to pick the
model file (defenses/models.py), and the rounds are about WHAT is in the files, not where they are
plugged in. The oracle guard runs first so a probe over its budget never costs a model evaluation.
"""

from . import ml_check, oracle_guard

LADDER = {
    0: [],
    1: [oracle_guard.CHECK, ml_check.CHECK],
}
