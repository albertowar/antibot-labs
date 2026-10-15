"""
slice_check.py: what does the slice's login page carry to the browser at the store's current level?

Reads GET /login the way a browser would and prints, against what the ladder promises:

    level  Content-Security-Policy        <script> nonces   vendor integrity=   runtime monitor
    0, 1   none                           no                no                  no
    2      allowlist (unsafe-inline)      no                no                  no
    3      strict (nonce, strict-dynamic) every tag         yes                 no
    4      strict                         every tag         yes                 first in <head>

    python tools/slice_check.py            # print the table for the store that is running
"""

import os
import re
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from labclient import BASE_URL, admin  # noqa: E402


def observe(path="/login"):
    r = requests.get(BASE_URL + path, timeout=10)
    html = r.text
    tags = re.findall(r"<script[^>]*>", html)
    csp = r.headers.get("Content-Security-Policy") or r.headers.get("Content-Security-Policy-Report-Only") or ""
    vendor = next((t for t in tags if "analytics-helper" in t), "")
    mon = next((i for i, t in enumerate(tags) if "runtime-monitor" in t), None)
    store = next((i for i, t in enumerate(tags) if "store.js" in t), None)
    return {"csp": ("strict" if "strict-dynamic" in csp else "allowlist" if csp else "none"),
            "csp_header": ("Content-Security-Policy" if "Content-Security-Policy" in r.headers else
                           "Content-Security-Policy-Report-Only" if csp else ""),
            "nonce_all": bool(tags) and all("nonce=" in t for t in tags), "nonce_any": any("nonce=" in t for t in tags),
            "integrity": "integrity=" in vendor, "monitor_first": mon is not None and (store is None or mon < store),
            "tags": len(tags), "unsafe_inline": "'unsafe-inline'" in csp.split("script-src")[-1].split(";")[0] if csp else False}


def expected(level):
    return {"csp": "none" if level < 2 else "allowlist" if level == 2 else "strict",
            "nonce_all": level >= 3, "integrity": level >= 3, "monitor_first": level >= 4}


def wire(level, report_only=False):
    """(ok, message): is the page carrying exactly what level `level` promises?"""
    got, want = observe(), expected(level)
    bad = [f"{k}: got {got[k]}, expected {v}" for k, v in want.items() if got[k] != v]
    if got["csp"] != "none":
        header = "Content-Security-Policy-Report-Only" if report_only else "Content-Security-Policy"
        if got["csp_header"] != header:
            bad.append(f"header: got {got['csp_header']}, expected {header}")
    print(f"\nwhat /login carries at level {level}: csp={got['csp']} ({got['csp_header'] or '-'}) · "
          f"nonce on {got['tags']} script tags: {'all' if got['nonce_all'] else 'some' if got['nonce_any'] else 'none'} · "
          f"vendor integrity={'yes' if got['integrity'] else 'no'} · monitor first={'yes' if got['monitor_first'] else 'no'}")
    return (not bad, "; ".join(bad))


if __name__ == "__main__":
    st = admin("GET", "/lab/supply/status")
    ok, msg = wire(st["level"], st["scenario"]["report_only"])
    print("OK" if ok else f"MISMATCH: {msg}")
    sys.exit(0 if ok else 1)
