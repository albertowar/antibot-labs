"""
Round 1 (level 1): know every script that runs on a payment page, and get told when one changes.

PCI DSS v4.0 requirement 6.4.3 asks for exactly this on payment pages: an inventory of every script,
a written justification for each, and a check that each is authorized and its integrity assured.
Requirement 11.6.1 adds a change-and-tamper-detection mechanism that looks at the page as a browser
receives it, at least weekly. The tooling for that is out-of-band, so this level changes nothing on
the wire:

    defenses/inventory_scripts.py   a Playwright crawl: every script the page actually loads
    defenses/script_monitor.py      SHA-256 of each one, diffed against a baseline

What the check does here is only mark the level in /lab/supply/status. What this round teaches is the
limit: detection is not prevention. The swap is flagged in minutes and the first checkout is skimmed
anyway.

False-positive profile: none for users (nothing they receive changes). The cost is the alert queue:
every legitimate vendor release is also a CHANGED, so the baseline needs an owner, and a weekly crawl
leaves a window of days.
"""

from .pipeline import Check


def _check(page):
    page.inventory = True


CHECK = Check("inventory", _check, phases=("page",))
