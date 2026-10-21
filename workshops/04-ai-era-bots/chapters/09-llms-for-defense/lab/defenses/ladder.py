"""
The ladder: which checks run at which DEFENSE_LEVEL.

This chapter's levels keep their 0–2 meaning from the content doc:

    0  log only: the analyst's tables fill (demo_site/ext/llm_log.py), nothing decides
    1  shadow: the rule engine runs at the checkout, matches are recorded
       (rule_hits, X-Lab-Shadow), nobody is blocked
    2  enforce: a matching checkout is refused before any order is written

Level k is enforced when k <= DEFENSE_LEVEL. Change it, save, and the store
picks it up on the next request (LAB_RELOAD=1). Fell behind?
`python tools/checkpoint.py --round N --catch-up` installs the reference
files for round N.
"""

from . import rule_check

LADDER = {
    0: [],
    1: [rule_check.SHADOW],
    2: [rule_check.CHECK],
}
