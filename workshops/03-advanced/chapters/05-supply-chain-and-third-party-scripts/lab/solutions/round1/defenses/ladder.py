"""
The ladder for Chapter 5, as it stands after Round 1. Reference version: `--catch-up` installs it.

Level k is on when k <= DEFENSE_LEVEL (see defenses/ladder.py for the full table). These checks run in the
"page" phase (defenses/page_controls.py): they decide what an HTML response carries to the browser.
"""

from . import inventory

LADDER = {
    0: [],
    1: [inventory.CHECK],
}
