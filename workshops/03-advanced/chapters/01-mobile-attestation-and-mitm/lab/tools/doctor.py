"""
W3 Ch1 — Environment check (run this first)

Confirms the pieces are in place before you start: Python version, the lab
packages, the TLS certificate, and whether the store answers. mitmproxy is
optional (only the live interception demo needs it), so it is reported but never
fails the check.

Run:
    python tools/doctor.py
"""

import importlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, HERE)

OK, BAD, WARN = "✅", "❌", "⚠️ "
REQUIRED = ["flask", "flask_sqlalchemy", "sqlalchemy", "cryptography", "httpx", "requests", "fakeredis"]


def check(label, ok, detail="", warn=False):
    mark = WARN if warn else (OK if ok else BAD)
    print(f"  {mark} {label}{(' — ' + detail) if detail else ''}")
    return ok or warn


def main():
    ok = True
    print("Python & packages")
    ok &= check(f"Python {sys.version_info.major}.{sys.version_info.minor}",
                sys.version_info >= (3, 12), "need 3.12+")
    for name in REQUIRED:
        try:
            importlib.import_module(name)
            check(name, True)
        except ImportError:
            ok &= check(name, False, "pip install -r requirements.txt")
    try:
        importlib.import_module("mitmproxy")
        check("mitmproxy (live demo)", True)
    except ImportError:
        check("mitmproxy (live demo only; rounds work without it)", False, "pip install mitmproxy", warn=True)

    print("\nCertificate")
    ok &= check("instance/cert.pem", os.path.exists(os.path.join(LAB_DIR, "instance", "cert.pem")),
                "python tools/make_cert.py")

    print("\nStore")
    try:
        from lab import BASE_URL, server_status
        status = server_status()
        check(f"Demo store ({BASE_URL})", True, f"DEFENSE_LEVEL={status['level']}, store={status['store']}")
    except Exception as exc:
        print(f"  … store not running yet (fine before you start it): {exc}")

    print("\n" + ("✅ Ready." if ok else "❌ Fix the ❌ lines above, then re-run."))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
