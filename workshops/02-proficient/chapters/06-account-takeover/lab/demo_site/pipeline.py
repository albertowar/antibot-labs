"""The login decision pipeline: compose the round defenses by DEFENSE_LEVEL.

Each round adds one layer. A layer runs only when the level is high enough, so a
single server binary reproduces every round by restarting with a different level:

    L0  no defenses
    L1  login_throttle      per-IP velocity + per-account lockout
    L2  population_signals   per-cohort failure / unknown-account ratios
    L3  breached_passwords   step-up when a *correct* password is in the breach corpus
        (plus oracle hardening, applied in app.py, not here)
    L4  risk_engine          device + network context, and re-auth for sensitive actions

Ordering is deliberate. Throttling and a latched cohort challenge are cheap and
run *before* we touch the password. Credentials are verified once. Everything
after that — population stats, breach screening, risk — reasons about the result,
because "a correct password from the wrong place" is the whole ballgame in ATO.

Which implementation runs is chosen by USE_SOLUTIONS: the student stubs in
``defenses/`` while you work, the reference modules in ``defenses/solutions/``
once you (or ``checkpoint.py --catch-up``) switch them on.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from werkzeug.security import check_password_hash

# Decision actions the app maps onto HTTP responses and logged outcomes.
ALLOW = "allow"
THROTTLE = "throttle"
CHALLENGE = "challenge"
STEP_UP = "step_up"
LOCK = "lock"
INVALID = "invalid"


@dataclass
class Decision:
    action: str
    reason: str = ""
    score: float = 0.0
    signals: list = field(default_factory=list)


def _pkg():
    """The package holding the active defense modules: stubs or reference."""
    if os.environ.get("USE_SOLUTIONS") == "1":
        import defenses.solutions as pkg
    else:
        import defenses as pkg
    return pkg


def _impl():
    """Pick the student stubs or the reference solutions."""
    pkg = _pkg()
    from importlib import import_module

    root = pkg.__name__
    return (
        import_module(f"{root}.login_throttle"),
        import_module(f"{root}.population_signals"),
        import_module(f"{root}.breached_passwords"),
        import_module(f"{root}.risk_engine"),
    )


def get_oracles():
    """The active oracle-hardening module (used by app.py for /forgot-password)."""
    from importlib import import_module

    return import_module(f"{_pkg().__name__}.oracles")


def evaluate(ctx: dict, level: int) -> Decision:
    """Run the active layers for ``level`` and return the first blocking Decision.

    ``ctx`` carries everything a layer might read: ``rds`` (Redis), ``email``,
    ``password``, ``client_ip``, ``cohort``, ``asn``, ``net_type``, ``device_id``,
    ``client_sig``, ``user`` (a ``User`` row or ``None``) and ``now``.
    """
    throttle, population, breached, risk = _impl()

    # --- Pre-auth: block before spending a password hash ----------------------
    if level >= 1:
        reason = throttle.pre_auth(ctx)
        if reason:
            return Decision(THROTTLE, reason, score=100)
    if level >= 2:
        reason = population.pre_auth(ctx)
        if reason:
            return Decision(CHALLENGE, reason, score=80)

    # --- Verify credentials exactly once --------------------------------------
    user = ctx["user"]
    if user:
        ok = check_password_hash(user.password_hash, ctx["password"])
    else:
        ok = False
        if level >= 3:
            # Equalize timing: a missing account must cost the same KDF work as a
            # real one, or the response clock becomes an enumeration oracle.
            get_oracles().equalize_timing(ctx["password"])

    if level >= 1:
        throttle.record(ctx, ok)
    if level >= 2:
        reason = population.record(ctx, ok)
        # A failed attempt that trips the cohort still returns invalid below; a
        # *successful* one that trips it is challenged rather than handed a session.
        if reason and ok:
            return Decision(CHALLENGE, reason, score=80)

    if not ok:
        return Decision(INVALID, "bad credentials")

    # --- Post-auth: the password was correct ----------------------------------
    if level >= 3:
        reason = breached.screen(ctx)
        if reason:
            return Decision(STEP_UP, reason, score=60)
    if level >= 4:
        reason = risk.assess(ctx)
        if reason:
            return Decision(STEP_UP, reason, score=60)
        # Fully clean login: record the device/context so next time is frictionless.
        risk.remember(ctx)

    return Decision(ALLOW, "ok")
