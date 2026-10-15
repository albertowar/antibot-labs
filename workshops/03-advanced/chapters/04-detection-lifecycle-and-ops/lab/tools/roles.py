"""
Move a model between roles (Round 3)

Thin CLI over defenses/registry.py. The pipeline reads roles, not versions,
and hot-reloads on the manifest's mtime, so every command here takes effect
on the next request with no restart.

    python tools/roles.py --show
    python tools/roles.py shadow v2        v2 scores and logs, never acts
    python tools/roles.py canary v2        v2 acts for config.canary_pct % of sessions
    python tools/roles.py promote v2       v2 becomes prod
    python tools/roles.py retire v2        v2 holds no role
    python tools/roles.py rollback         prod <- the version it replaced (if known)

Promote is a deliberate, named act. train.py registers a candidate and
gate.py judges it, but neither ships it; a person runs `promote`, and the
rollback path is one command because at 02:00 it has to be.
"""

import argparse
import os
import sys

import report as _lab  # noqa: F401,E402  (puts the lab root on sys.path)
from defenses import registry  # noqa: E402

_PREV = os.path.join(registry.MODELS_DIR, ".prev_prod")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("action", nargs="?", choices=["shadow", "canary", "promote", "retire", "rollback"])
    parser.add_argument("version", nargs="?")
    parser.add_argument("--show", action="store_true")
    args = parser.parse_args()

    if args.action == "promote":
        prev = registry.set_role("prod", args.version)
        if prev:
            open(_PREV, "w").write(prev)
        print(f"prod <- {args.version}" + (f" (was {prev})" if prev else ""))
    elif args.action == "rollback":
        prev = open(_PREV).read().strip() if os.path.exists(_PREV) else None
        if not prev:
            print("no previous prod recorded; set one explicitly: registry.py promote <version>")
            return 1
        registry.set_role("prod", prev)
        print(f"rolled prod back to {prev}")
    elif args.action in ("shadow", "canary"):
        registry.set_role(args.action, args.version)
        print(f"{args.action} <- {args.version}")
    elif args.action == "retire":
        for role, version in registry.load()["roles"].items():
            if version == args.version:
                registry.set_role(role, None)
        print(f"retired {args.version}")
    print("\n" + registry.describe())
    return 0


if __name__ == "__main__":
    sys.exit(main())
