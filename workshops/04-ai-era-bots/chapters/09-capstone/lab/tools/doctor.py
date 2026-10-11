"""
W4 Ch9 Capstone — preflight check: packages, keys, seed, store reachability

Run before you start the lab to catch the usual setup problems early. No browser is
needed: the agents are HTTP-level (Playwright is an optional bonus only).

    python tools/doctor.py
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)


def check(label, ok, hint=""):
    print(f"  {'✅' if ok else '❌'} {label}" + ("" if ok else f"  → {hint}"))
    return ok


def main():
    print("=== W4 Ch9 Capstone lab doctor ===")
    ok = True
    for pkg in ("flask", "flask_sqlalchemy", "redis", "fakeredis", "cryptography", "requests", "httpx"):
        ok &= check(f"import {pkg}", importlib.util.find_spec(pkg) is not None, "pip install -r requirements.txt")
    keys = os.path.join(LAB_DIR, "data", "keys", "lab-provider.pem")
    ok &= check("operator keys present", os.path.exists(keys), "python tools/seed.py")
    crawler_keys = os.path.join(LAB_DIR, "attacks", "keys", "registry.json")
    ok &= check("crawler operator keys present (attacks/keys/)", os.path.exists(crawler_keys), "python tools/seed.py")
    db = os.path.join(LAB_DIR, "instance", "shop.db")
    check("store seeded (instance/shop.db)", os.path.exists(db), "python tools/seed.py")
    try:
        from lab import server_status
        status = server_status()
        check(f"store reachable (DEFENSE_LEVEL={status['level']}, policy {status.get('policy')})", True)
    except Exception:
        check("store reachable", False, "DEFENSE_LEVEL=0 PORT=8409 python demo_site/app.py")
    print("OK" if ok else "Some checks failed; fix the hints above.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
