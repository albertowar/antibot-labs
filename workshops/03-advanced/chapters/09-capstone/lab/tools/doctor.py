"""
Chapter 9 — Environment check (run this first)

Confirms the pieces are in place before you start: Python version, the lab
packages, the browser downloads, the TLS certificate, and that Redis,
PostgreSQL and the store answer. With --tls it also prints the JA4 and TLS
stack of each HTTP client, which is the Round 0 / Round 5 teaching aid.

Run:
    python tools/doctor.py
    python tools/doctor.py --tls      # also probe JA4 per client (store must be up)
"""

import argparse
import importlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, HERE)

OK, BAD = "✅", "❌"
PACKAGES = ["flask", "redis", "psycopg", "jwt", "websockets", "curl_cffi", "playwright",
            "patchright", "camoufox", "sklearn", "numpy", "cryptography"]


def check(label, ok, detail=""):
    print(f"  {OK if ok else BAD} {label}{(' — ' + detail) if detail else ''}")
    return ok


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tls", action="store_true")
    args = parser.parse_args()
    ok = True

    print("Python & packages")
    ok &= check(f"Python {sys.version_info.major}.{sys.version_info.minor}",
                sys.version_info >= (3, 12), "need 3.12+")
    for name in PACKAGES:
        try:
            importlib.import_module(name)
            check(name, True)
        except ImportError:
            ok &= check(name, False, "pip install -r requirements.txt")

    print("\nBrowsers")
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            check("Playwright Chromium", bool(p.chromium.executable_path))
    except Exception as exc:
        ok &= check("Playwright Chromium", False, f"playwright install chromium ({exc})")
    cfx = os.path.expanduser("~/.cache/camoufox")
    ok &= check("Camoufox browser", os.path.isdir(cfx) and bool(os.listdir(cfx)),
                "python -m camoufox fetch")

    print("\nCertificate")
    ok &= check("instance/cert.pem", os.path.exists(os.path.join(LAB_DIR, "instance", "cert.pem")),
                "python tools/make_cert.py")

    print("\nServices")
    try:
        import redis
        from lab import BASE_URL
        r = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0"))
        ok &= check("Redis", r.ping())
    except Exception as exc:
        ok &= check("Redis", False, str(exc))
    try:
        from lab import server_status
        status = server_status()
        check(f"Demo store ({BASE_URL})", True, f"DEFENSE_LEVEL={status['level']}, "
              f"model {'loaded' if status['model_loaded'] else 'not loaded'}")
    except Exception as exc:
        print(f"  … store not running yet (fine before you start it): {exc}")

    if args.tls:
        print("\nTLS fingerprints per client (store must be up)")
        probe_tls()

    print("\n" + ("✅ Ready." if ok else "❌ Fix the ❌ lines above, then re-run."))
    return 0 if ok else 1


def probe_tls():
    import json
    import warnings
    warnings.filterwarnings("ignore")
    from lab import BASE_URL, ensure_local
    ensure_local()
    url = f"{BASE_URL}/whoami"
    rows = []
    import requests
    rows.append(("requests", requests.get(url, verify=False).json()))
    from curl_cffi import requests as cffi
    for t in ("chrome", "firefox", "safari260"):
        rows.append((f"curl_cffi:{t}", cffi.get(url, impersonate=t, verify=False).json()))
    for name, d in rows:
        print(f"  {name:18} {d['tls_family']:9} {d['ja4']}")
    print("  (a browser's JA4 appears in the store's /whoami page too)")


if __name__ == '__main__':
    sys.exit(main())
