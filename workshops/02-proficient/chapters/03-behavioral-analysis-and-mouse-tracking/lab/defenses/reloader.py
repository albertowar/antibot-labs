"""
Hot reload for defenses/*.py: edit a check, save, next request runs the new code.
No restarts between rounds, which is what makes `checkpoint.py --catch-up` seamless.

Reload order: changed check modules first, then ladder.py (which imports them),
so LADDER holds the fresh Check objects.
"""

import importlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_mtimes = {}


def _snapshot():
    out = {}
    for name in os.listdir(HERE):
        if name.endswith(".py") and not name.startswith("__"):
            p = os.path.join(HERE, name)
            out[name[:-3]] = os.stat(p).st_mtime
    return out


def ladder():
    """Return the current LADDER, reloading modules whose file changed."""
    global _mtimes
    now = _snapshot()
    changed = [m for m, t in now.items() if _mtimes.get(m) != t]
    first = not _mtimes
    _mtimes = now
    if changed and not first:
        for m in changed:
            if m == "ladder":
                continue
            mod = sys.modules.get(f"defenses.{m}")
            if mod is not None:
                try:
                    importlib.reload(mod)
                except Exception as e:      # keep serving with the last good version
                    print(f"[reloader] defenses/{m}.py: {e!r}")
        try:
            importlib.reload(sys.modules["defenses.ladder"])
        except Exception as e:
            print(f"[reloader] defenses/ladder.py: {e!r}")
    from . import ladder as ladder_mod
    return ladder_mod.LADDER
