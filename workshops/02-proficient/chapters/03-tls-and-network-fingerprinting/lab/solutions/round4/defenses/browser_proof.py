"""
browser_proof (Round 4): a browser claim needs browser proof.

After Round 3 the network layer has nothing left to catch: curl_cffi sends Chrome's exact
ClientHello and HTTP/2 preface. What it does not have is a JavaScript engine. So when the TLS family
says "browser", the protected paths (policy.PROOF_PATHS) also require evidence that a JS engine of
that family ran in this session and posted its signals (defenses/engine_signals.py explains how
the proof is earned: a TypeError message and eval's source length, per engine).

The proof is bound twice: to the engine (the JS engine must be the TLS family) and to the cipher
list (JA4 part b) of the connection that earned it. Part b survives session resumption; part a does
not. A pass earned in a real browser and replayed from another TLS stack fails the second binding.

What it misses: a real browser passes by definition (Round 4's attack). That is fine: the attacker
now pays for a full browser (about 600 MB of RAM per worker against about 40 MB for curl_cffi, and
several times slower). The signals are public, so a plain HTTP client can forge the POST (Bonus 1);
W2 Ch4 is about making that expensive. W2 Ch1's automation artifacts and W2 Ch5's behavior come
into play against the browser itself.

Who it hurts: JavaScript disabled (NoScript, Tor Browser "Safest", some accessibility setups): the
`no_js` shopper. Offer a non-JS fallback (W1 Ch5 CAPTCHA, a login) rather than a hard 403. Cookie
blocking, and first visits that go straight to a catalogue deep link before any page ran the
script. Cost: one session read per protected request, one extra POST per session.
"""

from . import engine_signals, ja4, policy
from .pipeline import Check, Signal


def _protected(ctx):
    return ctx.method == "GET" and any(ctx.path.startswith(p) for p in policy.PROOF_PATHS)


def _check(ctx):
    if not _protected(ctx):
        return None
    fp = ja4.fingerprint(ctx)
    engine = ja4.tls_engine(fp, ja4.claimed_engine(ctx.ua.raw))
    if engine is None:
        return None
    proof = engine_signals.read_proof(ctx)
    if proof is None:
        return [Signal("browser_proof", "no_proof", policy.TLS_POINTS, f"{engine} TLS but no engine proof in this session")]
    if proof[0] != engine:
        return [Signal("browser_proof", "engine_mismatch", policy.TLS_POINTS, f"JS engine {proof[0]} and TLS stack {engine} disagree")]
    if proof[1] != fp.ja4_b:
        return [Signal("browser_proof", "other_tls_stack", policy.TLS_POINTS, "proof earned on another TLS stack")]
    return None


CHECK = Check("browser_proof", _check)
