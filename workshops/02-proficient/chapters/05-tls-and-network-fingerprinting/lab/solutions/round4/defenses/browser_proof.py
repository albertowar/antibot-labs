"""
Chapter 5 — Defense Layer 4: a browser claim needs browser proof (Section 5.7)

After Round 3, the network layer has nothing left to catch: curl_cffi sends
Chrome's exact ClientHello and HTTP/2 preface. What it doesn't have is a
JavaScript engine. So when the TLS family says "browser", the protected
endpoints also require a cookie that only a JS engine of *that* family could
have earned:

1. GET /  embeds a signed nonce and a tiny script.
2. The script provokes a TypeError and reads `eval.toString().length`. Both
   differ by engine:
       V8 (Chromium)        "Cannot read properties of null (reading 'f')"   33
       SpiderMonkey (Gecko) "can't access property \"f\" of null"            37
       JavaScriptCore       "null is not an object (evaluating 'null.f')"    33
3. POST /api/engine → the server classifies the engine and sets
   `engine_proof = <engine>.<ja4_b>.<expiry>.<hmac>`, bound to the cipher
   list (JA4 part b) of the connection that earned it. Part b survives
   session resumption; part a doesn't (the extension count changes).
4. Protected paths check: cookie valid, not expired, engine == TLS family,
   ja4_b == this connection's ja4_b.

Why it fails:
- A real browser passes by definition (Round 4: Playwright Chromium). That's
  fine: the attacker now pays for a full browser. In our measurement a
  headless Chromium worker used ~600 MB RSS against ~40 MB for curl_cffi,
  and scraped ~5× slower. The W2 Ch1 automation and W2 Ch3 behavioral
  signals also come into play.
- These signals are public. An attacker who reads the script can forge the
  POST from curl_cffi (Bonus 2). W2 Ch2 is about making that expensive
  (obfuscation, rotating challenges); this layer is the minimal version.

False-positive profile:
- JavaScript disabled (NoScript, Tor Browser "Safest", some accessibility
  setups) → blocked. Offer a non-JS fallback (W1 Ch5 CAPTCHA, login) rather
  than a hard 403.
- Cookie blocking, and first visits that go straight to a deep link before
  any page sets the cookie.
- Cost: one HMAC per request plus one extra POST per session.

Enabled when DEFENSE_LEVEL >= 4. Catches: Round 3 (curl_cffi impersonation).
"""

import hashlib
import hmac
import os
import sys
import time

SECRET = os.environ.get("PROOF_SECRET", "").encode() or os.urandom(32)
COOKIE = "engine_proof"
TTL_SECONDS = 3600
PROTECTED_PATHS = {"/api/products", "/products", "/login"}


def _sign(msg: str) -> str:
    return hmac.new(SECRET, msg.encode(), hashlib.sha256).hexdigest()[:32]


def issue_nonce() -> str:
    ts = str(int(time.time()))
    return f"{ts}.{_sign('nonce|' + ts)}"


def nonce_valid(nonce: str, max_age: int = 300) -> bool:
    try:
        ts, sig = nonce.split(".")
        return hmac.compare_digest(sig, _sign("nonce|" + ts)) and time.time() - int(ts) < max_age
    except (ValueError, AttributeError):
        return False


def classify_engine(error_message: str, eval_length: int):
    """Map the JS signals to an engine. None if they match nothing we know."""
    msg = error_message or ""
    if msg.startswith("Cannot read properties of null") and eval_length == 33:
        return "chromium"
    if msg.startswith("can't access property") and eval_length == 37:
        return "gecko"
    if msg.startswith("null is not an object") and eval_length == 33:
        return "webkit"
    return None


def make_cookie(engine: str, ja4_b: str) -> str:
    expiry = str(int(time.time()) + TTL_SECONDS)
    body = f"{engine}.{ja4_b}.{expiry}"
    return f"{body}.{_sign(body)}"


def parse_cookie(value: str):
    """Return (engine, ja4_b) if the signature and expiry check out, else None."""
    try:
        engine, ja4_b, expiry, sig = value.rsplit(".", 3)
    except (ValueError, AttributeError):
        return None
    body = f"{engine}.{ja4_b}.{expiry}"
    if not hmac.compare_digest(sig, _sign(body)) or int(expiry) < time.time():
        return None
    return engine, ja4_b


def score_browser_proof(fp, tls_engine, cookies, path):
    """Only applies to protected paths, and only to browser TLS families."""
    if tls_engine is None or path not in PROTECTED_PATHS:
        return 0, []
    # Round 4 solution (the student file has a TODO here)
    proof = parse_cookie(cookies.get(COOKIE, ""))
    if proof is None:
        return 50, [f"{tls_engine} TLS but no valid {COOKIE} cookie (no JS engine proof)"]
    engine, ja4_b = proof
    if engine != tls_engine:
        return 50, [f"JS engine proof says {engine} but TLS is {tls_engine}"]
    if ja4_b != fp.ja4_b:
        return 50, [f"{COOKIE} was earned on a different TLS stack ({ja4_b})"]
    return 0, []


if __name__ == "__main__":
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from edge_headers import EdgeFingerprint
    fp = EdgeFingerprint("t13d1516h2_8daaf6152771_806a8c22fdea", None, "x")
    good = make_cookie("chromium", fp.ja4_b)
    print("no cookie:", score_browser_proof(fp, "chromium", {}, "/api/products"))
    print("valid:    ", score_browser_proof(fp, "chromium", {COOKIE: good}, "/api/products"))
    print("wrong eng:", score_browser_proof(fp, "chromium", {COOKIE: make_cookie("gecko", fp.ja4_b)}, "/api/products"))
