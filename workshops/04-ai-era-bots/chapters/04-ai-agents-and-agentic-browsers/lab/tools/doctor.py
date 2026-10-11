"""
W4 Ch4 — Preflight check: packages, Chromium, keys, store reachability

Run before the session to catch the usual setup problems early.

    python tools/doctor.py
"""

import importlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)


def check(label, ok, hint=""):
    print(f"  {'✅' if ok else '❌'} {label}" + ("" if ok else f"  → {hint}"))
    return ok


def main():
    print("=== W4 Ch4 lab doctor ===")
    ok = True
    for pkg in ("flask", "flask_sqlalchemy", "redis", "fakeredis", "cryptography", "playwright", "requests"):
        ok &= check(f"import {pkg}", importlib.util.find_spec(pkg) is not None,
                    "pip install -r requirements.txt")

    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            path = p.chromium.executable_path
        ok &= check("Chromium installed", os.path.exists(path), "python -m playwright install chromium")
    except Exception as exc:
        ok &= check("Chromium installed", False, f"{exc}; python -m playwright install chromium")

    keys = os.path.join(LAB_DIR, "data", "keys", "lab-provider.pem")
    ok &= check("operator keys present", os.path.exists(keys), "python tools/make_keys.py")

    db = os.path.join(LAB_DIR, "instance", "shop.db")
    check("store seeded (instance/shop.db)", os.path.exists(db), "python tools/seed.py (optional until Round 1)")

    try:
        from lab import server_status
        status = server_status()
        check(f"store reachable (DEFENSE_LEVEL={status['level']})", True)
    except Exception:
        check("store reachable", False, "DEFENSE_LEVEL=0 python demo_site/app.py")

    if not os.environ.get("DISPLAY") and sys.platform not in ("darwin", "win32"):
        print("  ℹ  no DISPLAY: the browser agent will run headless (set HEADLESS=1 to force it anywhere)")
    print("OK" if ok else "Some checks failed; fix the hints above.")
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
