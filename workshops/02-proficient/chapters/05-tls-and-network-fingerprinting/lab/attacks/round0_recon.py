"""
Chapter 5 — Round 0: Recon. What does each client look like below HTTP? (Section 5.8)

Sends one request from every client in this lab and prints what the edge saw:
JA4, HTTP version, HTTP/2 fingerprint and the TLS family Layer 2 would assign.

    python attacks/round0_recon.py                  # through the edge → /tls-check
    python attacks/round0_recon.py --skip-browser   # HTTP libraries only
    python attacks/round0_recon.py --dump           # to tools/clienthello_dump.py instead

Things to look for:
  1. Same User-Agent, different stacks: requests, httpx and urllib all get
     their own JA4 even though they share OpenSSL.
  2. Run it twice. Chromium's JA4 part c changes between runs while
     curl_cffi's doesn't. Then use --dump and `python defenses/ja4.py` to find
     out why (hint: look at the first signature algorithm).
  3. `playwright page.request` is not the browser: Node's TLS, no ALPN.
  4. The HTTP/2 column: who sends which SETTINGS, in which order?
  5. In --dump mode each browser visits twice; the second visit resumes the
     TLS session. Compare its JA4 part a with the fresh one, and with Firefox's.
"""

import argparse
import json
import ssl
import sys
import urllib.request

import httpx
import requests

from _lab import BASE_URL, CA_FILE

DUMP_URL = "https://localhost:9443"


def _ctx():
    return ssl.create_default_context(cafile=CA_FILE)


def via_requests(url):
    return requests.get(url, verify=CA_FILE, timeout=10).json()


def via_httpx(url):
    return httpx.get(url, verify=_ctx(), timeout=10).json()


def via_urllib(url):
    with urllib.request.urlopen(url, context=_ctx(), timeout=10) as r:
        return json.loads(r.read())


def via_curl_cffi(target):
    def fetch(url):
        from curl_cffi import requests as cffi_requests
        return cffi_requests.get(url, impersonate=target, verify=CA_FILE, timeout=10).json()
    return fetch


def via_impit(url):
    import impit
    with impit.Client(browser="chrome", verify=False, http3=False) as client:
        return client.get(url).json()


def via_playwright(browser_name, api_request=False):
    def fetch(url):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = getattr(p, browser_name).launch()
            context = browser.new_context(ignore_https_errors=True)
            if api_request:
                data = context.request.get(url).json()
            else:
                page = context.new_page()
                page.goto(url)
                data = json.loads(page.evaluate("document.body.innerText"))
                if "label=" in url:
                    # The dump server closes every connection, so a second visit
                    # makes the browser open a new one and resume the TLS session.
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
        url = f"{DUMP_URL}/?label={label}" if dump else f"{BASE_URL}/tls-check"
        try:
            data = fetch(url)
        except Exception as exc:  # a missing browser shouldn't kill the whole table
            data = {"error": f"{type(exc).__name__}: {str(exc).splitlines()[0][:60]}"}
        rows.append((name, data))
    return rows


def print_table(rows, dump=False):
    if dump:
        print(f"{'client':<26} {'JA4 (our parser)':<38} bytes")
        for name, d in rows:
            print(f"{name:<26} {d.get('ja4') or d.get('error', '?'):<38} {d.get('bytes', '')}")
            if "resumed" in d:
                print(f"{'  … resumed session':<26} {d['resumed'].get('ja4'):<38} {d['resumed'].get('bytes', '')}")
        print("\nSaved to captures/*.hex. Next: python defenses/ja4.py captures/<client>.hex")
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
    print(f"=== Round 0: recon via {'ClientHello dump :9443' if args.dump else BASE_URL + '/tls-check'} ===\n")
    print_table(collect(clients, args.dump), args.dump)
    return 0


if __name__ == "__main__":
    sys.exit(main())
