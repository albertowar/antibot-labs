"""labnet: the one localhost guard and the catch-up helper every lab shares.

CANONICAL COPY. Every ``workshops/*/chapters/*/lab/labnet.py`` is a byte-identical
vendored copy of this file so that a lab folder runs on its own. Edit this file,
copy it over the vendored ones, and run ``make check`` (scripts/check_labs.py), which
fails on any drift.

Rules of engagement, enforced in code
-------------------------------------
Lab scripts only ever talk to infrastructure you run on this machine. ``target()``
reads the demo-store URL from the environment and refuses anything that is not
loopback before a single request is sent. ``require_local_env()`` does the same for
the side services a lab may talk to (a mock CAPTCHA provider, a collector, a mock
internet, a local Ollama). Do not remove these checks to "try it on something real":
attacking a site you do not own is outside this workshop and may be unlawful.

Catch-up
--------
Reference solutions live at ``lab/solutions/roundN/<path relative to lab>``, each
round holding only the files it changes, in their finished state. ``catch_up(lab, N)``
installs rounds 1..N over the student's files, keeping a ``.bak`` of each file the
first time it is replaced; ``restore(lab)`` puts the ``.bak`` files back. Each lab's
``tools/checkpoint.py --round N --catch-up`` / ``--restore`` are thin wrappers.

Usage::

    import os, sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    from labnet import target, require_local, require_local_env

    BASE_URL = target("DEMO_URL", "http://127.0.0.1:5000")
"""

from __future__ import annotations

import ipaddress
import os
import shutil
from urllib.parse import urlparse

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# Environment variables that may name a side service a lab talks to. Any of them
# that is set must also point at this machine.
SIDE_SERVICE_ENV = ("PROVIDER_URL", "COLLECTOR_URL", "MOCK_URL", "OLLAMA_URL",
                    "OLLAMA_HOST", "LLM_URL", "REDIS_URL", "DATABASE_URL")


def is_local(url: str) -> bool:
    """True when the URL's host is this machine (localhost or a loopback address).

    ``memory://`` and other host-less schemes (the fakeredis / SQLite fallbacks) are
    local by definition.
    """
    try:
        host = urlparse(url).hostname
    except ValueError:
        return False
    if host is None:
        return True
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def require_local(url: str | None = None, what: str = "target") -> str:
    """Refuse to run against anything that is not this machine. Returns the URL.

    With no argument it re-checks ``DEMO_URL`` from the environment (the lab helpers
    guard their default at import time, so a bare ``require_local()`` is a cheap
    second look before a script starts sending).
    """
    if url is None:
        url = os.environ.get("DEMO_URL", "http://127.0.0.1")
    if not is_local(url):
        raise SystemExit(
            f"Refusing to run against non-local {what} {url!r}. Lab traffic only goes to "
            f"the demo store you run yourself (localhost / 127.0.0.1). Do not remove this "
            f"check to 'try it on something real'.")
    return url


def target(env: str = "DEMO_URL", default: str = "http://127.0.0.1:5000") -> str:
    """The demo-store base URL from the environment, guarded and without a trailing slash."""
    url = os.environ.get(env, default).rstrip("/")
    return require_local(url, what=env)


def require_local_env(*names: str) -> None:
    """Guard every side-service URL variable that is set (all of them by default)."""
    for name in names or SIDE_SERVICE_ENV:
        value = os.environ.get(name)
        if value:
            require_local(value, what=name)


def lab_dir(file: str) -> str:
    """The lab root for a script living at lab/, lab/attacks/, lab/tools/ or lab/defenses/."""
    here = os.path.dirname(os.path.abspath(file))
    for _ in range(4):
        if os.path.isfile(os.path.join(here, "labnet.py")):
            return here
        here = os.path.dirname(here)
    raise SystemExit(f"labnet: cannot find the lab root above {file}")


def solution_files(lab: str, upto: int) -> list[tuple[str, str]]:
    """(source, destination) pairs for rounds 1..upto, in install order."""
    pairs = []
    for n in range(1, upto + 1):
        root = os.path.join(lab, "solutions", f"round{n}")
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for name in sorted(files):
                if name.endswith((".pyc", ".bak", ".md")):   # docs are read, never installed
                    continue
                src = os.path.join(dirpath, name)
                rel = os.path.relpath(src, root)
                pairs.append((src, os.path.join(lab, rel)))
    return pairs


def catch_up(lab: str, upto: int) -> list[str]:
    """Install the reference solutions for rounds 1..upto. Returns the files written.

    A student file is backed up to ``<file>.bak`` the first time it is replaced, so a
    later round or a second run never overwrites the backup of the student's own work.
    """
    written = []
    for src, dst in solution_files(lab, upto):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.exists(dst) and not os.path.exists(dst + ".bak"):
            shutil.copy2(dst, dst + ".bak")
        shutil.copy2(src, dst)
        written.append(os.path.relpath(dst, lab))
    return written


def restore(lab: str) -> list[str]:
    """Put every ``<file>.bak`` under the lab back in place. Returns the files restored."""
    restored = []
    for dirpath, dirs, files in os.walk(lab):
        dirs[:] = [d for d in dirs if d not in ("solutions", "__pycache__", ".venv", "node_modules")]
        for name in files:
            if name.endswith(".bak"):
                bak = os.path.join(dirpath, name)
                shutil.move(bak, bak[:-4])
                restored.append(os.path.relpath(bak[:-4], lab))
    return restored


if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else target()
    print(f"{url}: {'local' if is_local(url) else 'NOT local'}")
