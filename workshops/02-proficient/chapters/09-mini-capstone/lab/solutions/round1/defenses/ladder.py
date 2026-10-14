"""
Round 1 reference ladder (the catch-up file): request layers, the sensor gate and the login throttle.

This lab ships every defense pre-written, so a catch-up only restores the wiring: the ladder says which
checks exist at which DEFENSE_LEVEL, and a level above 2 has nothing wired here. `python tools/checkpoint.py
--round 1 --catch-up` copies this over defenses/ladder.py (your version is kept as ladder.py.bak;
`--restore` puts it back). The full ladder, with the reading guide, is the live defenses/ladder.py.
"""

from . import (automation_artifacts, behavior_l1, behavior_l2, client_hints, consistency, flow, header_inspector,
               header_order, ja4_denylist, lie_detection, login_risk, login_throttle, sensor_gate, session_model,
               tls_family, token_binding, ua_inspector)
from .drop_guard import at_drop

LADDER = {
    0: [],
    1: [ua_inspector.CHECK, header_inspector.CHECK, client_hints.CHECK, header_order.CHECK,
        ja4_denylist.CHECK, tls_family.CHECK, login_throttle.CHECK,
        at_drop(sensor_gate.CHECK), at_drop(automation_artifacts.CHECK)],
    2: [at_drop(consistency.CHECK), at_drop(lie_detection.CHECK)],
    3: [],      # not wired yet
    4: [],      # not wired yet
    5: [],      # not wired yet
}
