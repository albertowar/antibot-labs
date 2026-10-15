"""
The ladder: which checks run at which DEFENSE_LEVEL.

This lab wires ONE check, at level 0, and the chapter's rounds live inside it.

    LADDER = {0: [crawler_gate.CHECK]}

Why not one check per level, like W4 Ch1? Every request must end in a budget decision (verified
lane or anonymous lane), and that decision has to see the result of every proof the level can
make. The ladder runs lower levels first, so a budget check at level 0 would run before the
proofs of levels 1-5, and a budget check at level 5 would not run at levels 0-4. The gate is
therefore one orchestrator whose behaviour depends on `ctx.level`; what you write in each round
are the layers it calls (`rdns.py`, `ip_ranges.py`, `web_bot_auth.py`), and `crawler_gate.py`
ships done. Nothing to wire here.

`python tools/checkpoint.py --round N` sets level N with POST /lab/level.
"""

from . import crawler_gate

LADDER = {
    0: [crawler_gate.CHECK],
}
