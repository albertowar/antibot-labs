"""
Everything a round needs that is not a defense: the training history, the surrogate and the models.

tools/checkpoint.py imports this module. It does two things the checkpoint engine has no hook for
(recorded as a contract gap in TODO.md section 1.2):

  1. It wraps labclient.reset, which check_round calls right after it sets the round's level. Before the
     store is reset, `prepare()` makes sure the drop-day history exists (generated with tools/simulate.py
     if not), that the models the round's level needs exist, and (from Round 2) that the attacker holds a
     surrogate; the store is then reset with a drop big enough for a drop day (the starter's 50 units
     would sell out in seconds).
  2. It wraps checkpoint_core.catch_up. The solution files are installed as usual, and the models are
     then TRAINED by the reference code, once per process, in the order the chapter tells it:

         drop day -> baseline model v2 -> (Round 2) extraction, evasion wave, model v3
                  -> (Round 3) poisoning wave, model v4 -> (Round 4) rare-class wave, model v5

     Without --catch-up your own models are used and a missing one is a clear message.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import checkpoint_core  # noqa: E402
import labclient  # noqa: E402
from defenses import history, models, waves  # noqa: E402

DROP_STOCK = 20000
STATE = {"catch_up": False, "trained": set()}
SURROGATE = os.path.join(LAB, "data", "surrogate_patient.txt")


def sh(*argv):
    """Run a lab script as a child of the checkpoint (same store, same guard)."""
    env = dict(os.environ, DEMO_URL=labclient.BASE_URL, PYTHONPATH=HERE + os.pathsep + os.environ.get("PYTHONPATH", ""))
    print(f"  > {' '.join(argv)}", flush=True)
    r = subprocess.run([sys.executable, *argv], env=env, cwd=LAB, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-1500:], r.stderr[-1500:])
        raise SystemExit(f"{' '.join(argv)} failed (exit {r.returncode})")
    return r.stdout


def ensure_history():
    if not history.exists():
        print("No drop-day history yet: generating it (Round 0, about 2 minutes)...", flush=True)
        sh("tools/simulate.py")


def ensure_wave(wave, attack):
    if not waves.sessions_in(history.load(), wave):
        sh("tools/simulate.py", "--wave", attack)


def ensure_surrogate():
    """The attacker's clone of the deployed model, built against the live oracle at level 1."""
    if os.path.exists(SURROGATE) or STATE.get("surrogate"):
        return
    level = labclient.admin("GET", "/lab/status")["level"]
    labclient.set_level(1)
    try:
        _reset("state", stock=DROP_STOCK)
        sh("attacks/round1_extract.py", "--patient")
    finally:
        labclient.set_level(level)
    STATE["surrogate"] = True


def train_for(level):
    """Reference training for what DEFENSE_LEVEL `level` needs: once per process."""
    steps = []
    if level >= 1:
        steps.append(("v2", None, ["-m", "defenses.baseline_model"]))
    if level >= 2:
        steps += [("surrogate", ensure_surrogate, None),
                  ("wave:evade", lambda: ensure_wave("evade", "round2_evade"), None),
                  ("v3", None, ["-m", "defenses.robust_train"])]
    if level >= 3:
        steps += [("wave:poison", lambda: ensure_wave("poison", "round3_poison"), None),
                  ("v4", None, ["-m", "defenses.provenance"])]
    if level >= 4:
        steps += [("wave:rare", lambda: ensure_wave("rare", "round4_rareclass"), None),
                  ("v5", None, ["-m", "defenses.augment"])]
    for name, fn, argv in steps:
        if name in STATE["trained"]:
            continue
        fn() if fn else sh(*argv)
        STATE["trained"].add(name)


def prepare(level):
    ensure_history()
    if STATE["catch_up"]:
        train_for(level)
    else:
        if models.missing(level):
            raise SystemExit(f"Level {level} needs {', '.join(models.missing(level))}. Train it (python -m defenses.baseline_model, "
                             f"robust_train, provenance, augment), or run with --catch-up.")
        if level >= 2:
            ensure_surrogate()


_reset = labclient.reset


def reset(mode="state", **params):
    prepare(labclient.admin("GET", "/lab/status")["level"])
    return _reset(mode, **{"stock": DROP_STOCK, **params})


labclient.reset = reset

_catch_up = checkpoint_core.catch_up


def catch_up(rounds, upto):
    _catch_up(rounds, upto)
    STATE["catch_up"] = True
    for name in ("surrogate_patient", "surrogate_cheap"):          # the attacker's clone is rebuilt against the reference guard
        for ext in (".txt", ".json"):
            path = os.path.join(LAB, "data", name + ext)
            if os.path.exists(path):
                os.remove(path)


checkpoint_core.catch_up = catch_up
