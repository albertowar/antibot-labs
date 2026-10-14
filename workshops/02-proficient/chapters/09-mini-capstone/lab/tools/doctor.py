"""
Doctor: is this machine ready for the lab? Checks Python, dependencies, the
database and Redis URLs you configured, Docker if you plan to use it, and that
DEMO_URL points at this machine.

    python tools/doctor.py
"""

import importlib
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import labnet  # noqa: E402  (stdlib only, so it imports before the dependencies are checked)

ok = True


def say(good, msg):
    global ok
    ok = ok and good
    print(("  ok   " if good else "  FAIL ") + msg)


def main():
    print("Python")
    say(sys.version_info >= (3, 12), f"Python {sys.version.split()[0]} (need 3.12+)")
    say(sys.prefix != sys.base_prefix, "running inside a virtualenv (python -m venv .venv)")
    print("Dependencies")
    for mod in ("flask", "flask_sqlalchemy", "sqlalchemy", "redis", "fakeredis", "requests", "httpx"):
        try:
            importlib.import_module(mod)
            say(True, mod)
        except ImportError:
            say(False, f"{mod} missing: pip install -r requirements.txt")
    print("Configuration")
    try:
        say(True, f"DEMO_URL={labnet.target()} is this machine")
        labnet.require_local_env()
        say(True, "every side-service URL that is set (REDIS_URL, DATABASE_URL, ...) is this machine")
    except SystemExit as e:
        say(False, str(e))
    redis_url = os.environ.get("REDIS_URL", "memory://")
    db_url = os.environ.get("DATABASE_URL", "sqlite:///instance/shop.db")
    print(f"       REDIS_URL={redis_url}  DATABASE_URL={db_url.split('@')[-1] if '@' in db_url else db_url}")
    if redis_url.startswith("redis://"):
        try:
            import redis
            redis.Redis.from_url(redis_url, socket_connect_timeout=2).ping()
            say(True, "Redis answers")
        except Exception as e:
            say(False, f"Redis: {e!r}  (docker compose up -d --wait, or unset REDIS_URL)")
    else:
        say(True, "in-process Redis (fakeredis): single process only, state lost on restart")
    if db_url.startswith("postgres"):
        try:
            import sqlalchemy
            sqlalchemy.create_engine(db_url).connect().close()
            say(True, "PostgreSQL answers")
        except Exception as e:
            say(False, f"PostgreSQL: {e!r}")
    else:
        say(True, "SQLite (WAL mode)")
    print("Optional")
    docker = shutil.which("docker")
    if docker:
        r = subprocess.run([docker, "compose", "version"], capture_output=True, text=True)
        say(r.returncode == 0, "docker compose available")
    else:
        print("  --   docker not found (fine: the no-Docker path is the default)")
    try:
        importlib.import_module("playwright")
        print("  ok   playwright installed (python -m playwright install chromium if a lab needs a browser)")
    except ImportError:
        print("  --   playwright not installed (only browser labs need it)")
    print("\nREADY" if ok else "\nFix the FAIL lines above.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
