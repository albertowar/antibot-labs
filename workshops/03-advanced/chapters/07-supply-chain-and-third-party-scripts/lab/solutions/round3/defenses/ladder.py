"""
The ladder for Chapter 7, as it stands after Round 3. Reference version: `--catch-up` installs it.

Level k is on when k <= DEFENSE_LEVEL (see defenses/ladder.py for the full table). These checks run in the
"page" phase (defenses/page_controls.py): they decide what an HTML response carries to the browser.
"""

from . import csp_policies, generate_sri, inventory

LADDER = {
    0: [],
    1: [inventory.CHECK],
    2: [csp_policies.WEAK],
    3: [csp_policies.STRICT, generate_sri.CHECK],
}
