"""
Round 0: recon. What does each client look like below HTTP?

Sends one request from every client in this lab and prints what the TLS edge measured: JA4, HTTP
version, the HTTP/2 fingerprint and the browser family tls_family would assign.

    python attacks/round0_recon.py                  # through the edge -> /lab/tls/check
    python attacks/round0_recon.py --skip-browser   # HTTP libraries and impersonators only
    python attacks/round0_recon.py --dump           # to tools/clienthello_dump.py instead (raw bytes)

Things to look for:
  1. Same User-Agent, different stacks: requests, httpx and urllib all get their own JA4 even
     though they share OpenSSL.
  2. Run it twice. Chromium's JA4 part c changes between runs while curl_cffi's does not. Then use
     --dump and `python -m defenses.ja4 captures/<name>.hex` to find out why (hint: look at the
     first signature algorithm).
  3. `playwright page.request` is not the browser: Node's TLS, no h2 ALPN match.
  4. The HTTP/2 column: who sends which SETTINGS, in which order?
  5. In --dump mode each browser visits twice; the second visit resumes the TLS session. Compare
     its JA4 part a with the fresh one, and with Firefox's.
"""

import argparse
import json
import os
import ssl
import sys
import urllib.request

import httpx
import requests

from _common import CA_FILE, EDGE_URL, bot_ip, lab_headers, labclient, labnet

DUMP_URL = labnet.target("DUMP_URL", f"https://localhost:{os.environ.get('DUMP_PORT', '9443')}")
CHECK = "/lab/tls/check?format=json"


def _ctx():
    return ssl.create_default_context(cafile=CA_FILE)


def via_requests(url, actor):
    return requests.get(url, headers=lab_headers(actor), verify=CA_FILE, timeout=15).json()


def via_httpx(url, actor):
    return httpx.get(url, headers=lab_headers(actor), verify=_ctx(), timeout=15).json()


def via_urllib(url, actor):
    req = urllib.request.Request(url, headers=lab_headers(actor))
    with urllib.request.urlopen(req, context=_ctx(), timeout=15) as r:
        return json.loads(r.read())


def via_curl_cffi(target):
    def fetch(url, actor):
        from curl_cffi import requests as cffi_requests
        return cffi_requests.get(url, impersonate=target, verify=CA_FILE, timeout=15, headers=lab_headers(actor)).json()
    return fetch


def via_impit(url, actor):
    import impit
    with impit.Client(browser="chrome", verify=False, http3=False) as client:
        return client.get(url, headers=lab_headers(actor)).json()


def via_playwright(browser_name, api_request=False):
    def fetch(url, actor):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = getattr(p, browser_name).launch()
            context = labclient.browser_context(browser, f"bot:{actor}", ip=bot_ip(), ignore_https_errors=True)
            if api_request:
                data = context.request.get(url, headers=lab_headers(actor)).json()
            else:
                page = context.new_page()
                page.goto(url)
                data = json.loads(page.evaluate("document.body.innerText"))
                if "label=" in url:
                    # The dump server closes every connection, so a second visit makes the browser
                    # open a new one and resume the TLS session.
                    page.goto(url + "-resumed")
                    data["resumed"] = json.loads(page.evaluate("document.body.innerText"))
            browser.close()
            return data
    return fetch


LIBRARY_CLIENTS = {
    "python-requests": via_requests,
    "httpx": via_httpx,
    "urllib (stdlib)": via_urllib,
}
IMPERSONATORS = {
    "curl_cffi chrome": via_curl_cffi("chrome"),
    "curl_cffi firefox": via_curl_cffi("firefox"),
    "curl_cffi safari": via_curl_cffi("safari"),
    "impit chrome": via_impit,
}
BROWSERS = {
    "playwright chromium": via_playwright("chromium"),
    "playwright firefox": via_playwright("firefox"),
    "playwright page.request": via_playwright("chromium", api_request=True),
}


def collect(clients, dump=False):
    rows = []
    for name, fetch in clients.items():
        label = name.replace(" ", "-").replace("(", "").replace(")", "")
        url = f"{DUMP_URL}/?label={label}" if dump else f"{EDGE_URL}{CHECK}"
        try:
            data = fetch(url, "recon")
        except Exception as exc:  # a missing browser should not kill the whole table
            data = {"error": f"{type(exc).__name__}: {str(exc).splitlines()[0][:60]}"}
        rows.append((name, data))
    return rows


def print_table(rows, dump=False):
    if dump:
        print(f"{'client':<26} {'JA4 (our parser)':<38} bytes")
        for name, d in rows:
            print(f"{name:<26} {d.get('ja4') or d.get('error', '?'):<38} {d.get('bytes', '')}")
            if "resumed" in d:
                print(f"{'  ... resumed session':<26} {d['resumed'].get('ja4'):<38} {d['resumed'].get('bytes', '')}")
        print("\nSaved to captures/*.hex. Next: python -m defenses.ja4 captures/<client>.hex")
        return
    print(f"{'client':<26} {'JA4':<38} {'http':<9} {'family':<9} HTTP/2 fingerprint")
    for name, d in rows:
        if "error" in d:
            print(f"{name:<26} {d['error']}")
            continue
        print(f"{name:<26} {d.get('ja4') or '-':<38} {d.get('http_version', '-'):<9} "
              f"{d.get('tls_engine') or '-':<9} {d.get('http2') or '-'}")


def main():
    parser = argparse.ArgumentParser(description="Round 0 recon")
    parser.add_argument("--dump", action="store_true", help="send to tools/clienthello_dump.py on :9443")
    parser.add_argument("--skip-browser", action="store_true", help="skip Playwright clients")
    args = parser.parse_args()
    clients = {**LIBRARY_CLIENTS, **IMPERSONATORS, **({} if args.skip_browser else BROWSERS)}
    print(f"=== Round 0: recon via {'ClientHello dump :9443' if args.dump else EDGE_URL + CHECK} ===\n")
    rows = collect(clients, args.dump)
    print_table(rows, args.dump)
    seen = sum("error" not in d for _, d in rows)
    print(json.dumps({"attempted": len(rows), "succeeded": seen}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
