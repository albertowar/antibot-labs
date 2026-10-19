"""
engine_signals: the JavaScript half of "a browser claim needs browser proof". (Finished: nothing to write here.)

`browser_proof.py` (Round 4) asks one question: did a JavaScript engine of the same family as this
connection's TLS stack run in this session? This module is how that evidence is earned and stored.

1. The store's pages carry a tiny script (demo_site/static/js/tls_engine.js, injected by the `engine`
   ext) with a per-session nonce.
2. The script provokes a TypeError and reads `eval.toString().length`. Both differ by engine:

       V8 (Chromium)        "Cannot read properties of null (reading 'f')"   33
       SpiderMonkey (Gecko) "can't access property \\"f\\" of null"            37
       JavaScriptCore       "null is not an object (evaluating 'null.f')"    33

3. It posts them to /api/telemetry as kind `engine`. The handler classifies the engine and writes
   `engine_proof = <engine>.<ja4_b>` into the SESSION, bound to the cipher-suite hash (JA4 part b)
   of the connection that posted it. Part b survives session resumption; part a does not (the
   extension count changes).

Why this is weak on purpose: the signals are public. An attacker who reads the script can forge the
POST from curl_cffi (Bonus 1), which is exactly why W2 Ch4 obfuscates and rotates such challenges.
This layer is the minimal version that makes a plain HTTP client pay for a JS engine.
"""

import secrets

NONCE_KEY = "engine_nonce"
PROOF_KEY = "engine_proof"

# (TypeError message prefix, eval.toString().length) -> engine
SIGNATURES = (
    ("Cannot read properties of null", 33, "chromium"),
    ("can't access property", 37, "gecko"),
    ("null is not an object", 33, "webkit"),
)


def classify_engine(error_message, eval_length):
    """Map the page's JS signals to an engine family. None if they match nothing we know."""
    msg = error_message or ""
    for prefix, length, engine in SIGNATURES:
        if msg.startswith(prefix) and eval_length == length:
            return engine
    return None


def issue_nonce(ctx):
    """The session's nonce (created on first use). A script that never loaded a page does not have it."""
    nonce = ctx.session.get(NONCE_KEY)
    if not nonce:
        nonce = secrets.token_urlsafe(12)
        ctx.session.set(NONCE_KEY, nonce)
    return nonce


def nonce_valid(ctx, nonce):
    expected = ctx.session.get(NONCE_KEY)
    return bool(expected) and secrets.compare_digest(str(nonce or ""), expected)


def record_proof(ctx, engine, ja4_b):
    ctx.session.set(PROOF_KEY, f"{engine}.{ja4_b}")


def read_proof(ctx):
    """(engine, ja4_b) this session earned, or None."""
    raw = ctx.session.get(PROOF_KEY)
    if not raw or "." not in raw:
        return None
    engine, ja4_b = raw.split(".", 1)
    return engine, ja4_b
