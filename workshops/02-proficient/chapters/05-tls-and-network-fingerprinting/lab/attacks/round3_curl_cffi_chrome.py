"""
Chapter 5 — Round 3 Attack: full impersonation with curl_cffi (Section 5.8)

Objective: beat the HTTP/2 check. curl_cffi (MIT) wraps curl-impersonate:
curl built against BoringSSL, with patches that reproduce a given browser's
ClientHello *and* HTTP/2 preface. `impersonate="chrome"` picks the newest
open-source Chrome profile (chrome150 in curl_cffi 0.16.3) and sends that
version's default headers.

Through our edge it's byte-for-byte Chromium:
    JA4  t13d1516h2_8daaf6152771_806a8c22fdea
    H2   1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:256|m,a,s,p

Note: the profile is Chrome 150 while stable is 156. Impersonation profiles
usually trail the real browser. When Chrome changes its ClientHello, a
defender who keeps their family list current sees the old shape linger on
impersonators. That's a signal with a shelf life, not a rule.

Expected results:
  - DEFENSE_LEVEL=3 → 200, TLS and HTTP/2 both match Chromium
  - DEFENSE_LEVEL=4 → 403, [L4] chromium TLS but no valid engine_proof cookie

Run:
    python attacks/round3_curl_cffi_chrome.py
"""

from curl_cffi import requests as cffi_requests

from _lab import BASE_URL, CA_FILE, report, to_result

PATH = "/api/products"
REQUESTS = 10


def run():
    results = []
    with cffi_requests.Session(impersonate="chrome", verify=CA_FILE) as s:
        for _ in range(REQUESTS):
            r = s.get(BASE_URL + PATH, headers={"Referer": BASE_URL + "/"})
            results.append(to_result(PATH, r.status_code, r.json()))
    return results


if __name__ == "__main__":
    print("=== Round 3: curl_cffi impersonate='chrome' ===")
    report(run())
