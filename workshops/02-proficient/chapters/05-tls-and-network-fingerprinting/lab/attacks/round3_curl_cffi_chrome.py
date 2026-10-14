"""
Round 3 attack: full impersonation with curl_cffi.

Objective: beat the HTTP/2 check. curl_cffi (MIT) wraps curl-impersonate: curl built against
BoringSSL, with patches that reproduce a given browser's ClientHello *and* HTTP/2 preface.
`impersonate="chrome"` picks the newest open-source Chrome profile (chrome150 in curl_cffi 0.16.3)
and sends that version's default headers.

Through the edge it is byte-for-byte Chromium:
    JA4  t13d1516h2_8daaf6152771_806a8c22fdea
    H2   1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:256|m,a,s,p

The profile is Chrome 150 while stable is 156: impersonation profiles trail the real browser. When
Chrome changes its ClientHello, a defender who keeps the family list current sees the old shape
linger on impersonators. That is a signal with a shelf life, not a rule.

Expected results:
  - DEFENSE_LEVEL=3 -> 200, TLS and HTTP/2 both match Chromium
  - DEFENSE_LEVEL>=4 -> 403, browser_proof:no_proof (it never ran any JavaScript)

Run:
    python attacks/round3_curl_cffi_chrome.py
"""

from curl_cffi import requests as cffi_requests

from _common import CA_FILE, EDGE_URL, PATH, REQUESTS, finish, lab_headers, result


def run():
    out = []
    with cffi_requests.Session(impersonate="chrome", verify=CA_FILE) as s:
        for _ in range(REQUESTS):
            r = s.get(EDGE_URL + PATH, headers={"Referer": EDGE_URL + "/", **lab_headers("curl_cffi_chrome")})
            out.append(result(r.status_code, r.headers, r.json() if r.status_code == 200 else None))
    return out


if __name__ == "__main__":
    print("=== Round 3: curl_cffi impersonate='chrome' ===")
    finish(run())
