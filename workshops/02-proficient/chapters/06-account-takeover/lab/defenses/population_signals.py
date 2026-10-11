"""L2: per-cohort failure / unknown-account ratios.  <-- you implement this in Round 2.

Fill in the TODOs so that a cohort (the /24 in ctx["cohort"]) which, once it has
at least MIN_SAMPLE attempts, shows either a failure ratio over FAIL_RATIO or an
unknown-account ratio over UNKNOWN_RATIO, gets latched into a challenge.

ctx["user"] is None when the named account does not exist — that is your
unknown-account signal. Counters live in Redis; use ``ratelimit.incr_window``.

Reference solution: solutions/round2/defenses/population_signals.py
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from defenses import ratelimit  # noqa: E402

WINDOW_S = 600
MIN_SAMPLE = 30
FAIL_RATIO = 0.60
UNKNOWN_RATIO = 0.50
FLAG_TTL_S = 1800


def pre_auth(ctx) -> str | None:
    # TODO (Round 2): if ctx["cohort"] is already flagged, return a challenge reason.
    return None


def record(ctx, ok: bool) -> str | None:
    # TODO (Round 2): update attempts / failures / unknown-account counters for
    #   ctx["cohort"], then if attempts >= MIN_SAMPLE and either ratio is over its
    #   threshold, set the flag and return a reason. Otherwise return None.
    return None
