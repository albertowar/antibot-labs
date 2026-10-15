"""
Everything a round needs that is not a defense: the training history and the models.

tools/checkpoint.py passes `setup` as each Round's setup hook (contract 1.7:
`Round.setup(level, caught_up)` runs right after the round's reset). It makes sure the
drop-day history exists (generated with tools/simulate.py if not) and that the models the
round's level needs exist — trained from the history by the reference code when `--catch-up`
ran, once per process; otherwise a missing model is a clear message. It then resets the store
again with a drop big enough for a drop day (the starter's 50 units would sell out in seconds).
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import labclient  # noqa: E402
from defenses import history, models  # noqa: E402

DROP_STOCK = 20000
STATE = {"trained": set()}


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


def train_for(level):
    """Reference training for what DEFENSE_LEVEL `level` needs: once per process."""
    steps = []
    if level >= 1:
        steps.append(("v1", ["-m", "defenses.train", "--round", "1"]))
    if level >= 2:
        steps.append(("wave", ["tools/simulate.py", "--wave", "round1_humanized"]))
        steps.append(("labels", ["tools/label_cluster.py", "--yes"]))
        steps.append(("v2", ["-m", "defenses.train", "--round", "2"]))
    if level >= 3:
        steps.append(("anomaly", ["-m", "defenses.anomaly"]))
    for name, argv in steps:
        if name in STATE["trained"]:
            continue
        if name == "wave" and history.has_actors("bot:humanized:"):
            STATE["trained"].add(name)
            continue
        if name == "labels" and os.path.exists(history.MANUAL):
            STATE["trained"].add(name)
            continue
        sh(*argv)
        STATE["trained"].add(name)


def setup(level, caught_up=False):
    """Round.setup: history + models for `level`, then a reset with a drop day's stock."""
    ensure_history()
    if caught_up:
        train_for(level)
    elif models.missing(level):
        raise SystemExit(f"Level {level} needs {', '.join(models.missing(level))}. Train it "
                         f"(python -m defenses.train --round N, python -m defenses.anomaly), or run with --catch-up.")
    labclient.reset(stock=DROP_STOCK)
