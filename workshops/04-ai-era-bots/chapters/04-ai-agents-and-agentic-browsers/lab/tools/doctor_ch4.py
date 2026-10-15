"""
Chapter preflight: the browser, the keys, the cohort. (tools/doctor.py is the starter's and checks the rest.)

    python tools/doctor.py        # packages, URLs, Docker
    python tools/doctor_ch4.py    # Playwright's Chromium, the operators' keys, the side service
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
import labnet  # noqa: E402

ok = True


def say(good, msg, hint=""):
    global ok
    ok = ok and good
    print(("  ok   " if good else "  FAIL ") + msg + ("" if good or not hint else f"   -> {hint}"))


def main():
    print("Browser")
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            path = p.chromium.executable_path
        say(os.path.exists(path), "Chromium installed for this Playwright", "python -m playwright install chromium")
    except Exception as exc:
        say(False, f"Playwright: {exc}", "pip install -r requirements-browser.txt, then python -m playwright install chromium")
    if not os.environ.get("DISPLAY") and sys.platform not in ("darwin", "win32"):
        print("       no DISPLAY: the agents run headless (set HEADLESS=1 to force it anywhere)")
    print("Operators")
    try:
        import make_keys
        make_keys.ensure()
        say(True, "operator keys present in tools/fixtures/keys/ (generated here, gitignored)")
    except Exception as exc:
        say(False, f"keys: {exc!r}", "python tools/make_keys.py")
    url = os.environ.get("MOCK_URL", "http://127.0.0.1:5004")
    try:
        labnet.require_local(url, what="MOCK_URL")
        say(True, f"MOCK_URL={url} is this machine (the store starts the operators' websites there)")
    except SystemExit as exc:
        say(False, str(exc))
    print("OK" if ok else "Some checks failed; fix the hints above.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
