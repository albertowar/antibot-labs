"""
Chapter 4: the "js" challenge type, one scheme per level (Sections 4.1-4.6).

demo_site/ext/jschallenge.py registers this module's issue() and verify() with the store:
the gate serves issue()'s payload in the interstitial (HTML) or the 403 JSON body (API), the
page's script answers through POST /api/challenge/verify {"type": "js", "answer": {...}}, and on
success the store clears the session (demo_site/gate.py). js_gate.py decides who must solve.

    level  scheme                                                     defense module
    1      inline JS sets a fixed cookie (no verify call at all)      cookie_gate.py
    2      signed, session-bound, single-use nonce; one readable      tokens.py, variants.L2_CHAIN
           script for everybody (/jsc/l2.js)
    3      + a pool of polymorphic, obfuscated variants               variants.py + tools/build_variants.py
    4      + the answer folds in the browser's environment            env_integrity.py
    5      + a request budget per clearance                           clearance.py (enforced in js_gate.py)

The signing key lives in Redis, so it survives the hot reload of defenses/ and changes on
/lab/reset (every outstanding token dies with it, as when you rotate a key in production).

Teaching aid, never in production: a failed verify says WHY (the reason reaches the client
and the decision log). That turns the challenge into a free oracle for the attacker.
"""

import json
import os
import random
import secrets
import time

from . import cookie_gate, env_integrity, tokens, variants

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "secrets", "manifest.json")
UAH_FIELD = "jsc_uah"           # session field: the User-Agent the clearance was granted to
_POOL = {"mtime": None, "variants": {}}


def secret(redis):
    key = redis.get("lab:jsc:secret")
    if key is None:
        redis.set("lab:jsc:secret", secrets.token_hex(32), nx=True)
        key = redis.get("lab:jsc:secret")
    return bytes.fromhex(key)


def pool():
    """The variant pool (id -> (chain, probe)), reloaded when tools/build_variants.py rewrites it."""
    if not os.path.exists(MANIFEST):
        return {}
    mtime = os.path.getmtime(MANIFEST)
    if mtime != _POOL["mtime"]:
        with open(MANIFEST) as f:
            data = json.load(f)["variants"]
        _POOL.update(mtime=mtime, variants={v["id"]: (v["chain"], tuple(v["probe"])) for v in data})
    return _POOL["variants"]


def issue(ctx):
    """The payload the interstitial (or the 403 JSON) carries for this level."""
    if ctx.level <= 1:
        return {"scheme": "cookie", "inline": cookie_gate.INLINE_SCRIPT}
    if ctx.level == 2:
        variant_id, script = "l2", "/jsc/l2.js"
    else:
        available = pool()
        if not available:
            return {"scheme": "signed", "error": "no variant pool: run python tools/build_variants.py in lab/"}
        variant_id = random.choice(list(available))
        script = f"/static/js/variants/{variant_id}.js"
    nonce, token = tokens.issue_challenge(ctx.redis, secret(ctx.redis), ctx.session.sid, variant_id, ctx.level)
    return {"scheme": "signed", "token": token, "nonce": nonce, "env": ctx.level >= 4, "script": script}


def _diagnose(nonce, chain, probe, answer, ua):
    """Teaching aid: work out WHICH environment fact was wrong. Never ship this."""
    width = variants.probe_width(probe)
    for layout in (width, 0):
        for native in (True, False):
            for engine in (variants.ENGINE_V8, variants.ENGINE_OTHER):
                if variants.expected_answer(nonce, chain, (layout, native, engine)) == answer:
                    wrong = []
                    if layout != width:
                        wrong.append("offsetWidth was 0 (no layout engine)")
                    if not native:
                        wrong.append("DOM methods are not native code")
                    if engine != env_integrity.expected_engine(ua):
                        wrong.append("Error.stack style doesn't match the UA's engine")
                    return "; ".join(wrong) or "env matched"
    if variants.expected_answer(nonce, chain) == answer:
        return "answer ignores the environment (a port of the env-less chain?)"
    return "answer doesn't match this variant"


def verify(ctx, answer):
    """(ok, reason) for {"token", "answer", "solve_ms"}. On success, remember the UA for js_gate's binding."""
    if ctx.level <= 1:
        return False, "nothing to verify at level 1 (the cookie is the pass)"
    answer = answer if isinstance(answer, dict) else {}
    ua = ctx.header("User-Agent", "")
    payload, reason = tokens.redeem_challenge(ctx.redis, secret(ctx.redis), str(answer.get("token", "")),
                                              ctx.session.sid, ctx.level)
    if payload is None:
        return False, reason
    if payload["v"] == "l2":
        chain, probe = variants.L2_CHAIN, variants.L2_PROBE
    elif payload["v"] in pool():
        chain, probe = pool()[payload["v"]]
    else:
        return False, "unknown variant (pool rotated?)"
    env = env_integrity.expected_env(probe, ua) if ctx.level >= 4 else None
    expected = variants.expected_answer(payload["n"], chain, env)
    elapsed_ms = (time.time() - payload["iat"]) * 1000
    ctx.note(jsc_variant=payload["v"], jsc_elapsed_ms=round(elapsed_ms, 1),
             jsc_solve_ms=answer.get("solve_ms") if isinstance(answer.get("solve_ms"), (int, float)) else None)
    given = str(answer.get("answer", ""))
    if not secrets.compare_digest(given, expected):
        why = "wrong answer"
        if env is not None:
            why += f": {_diagnose(payload['n'], chain, probe, given, ua)}"
        return False, why
    if ctx.level >= 4 and not env_integrity.within_window(elapsed_ms):
        return False, f"solved in {elapsed_ms:.0f} ms, over the {env_integrity.MAX_SOLVE_MS:.0f} ms window"
    ctx.session.set(UAH_FIELD, tokens.ua_hash(ua))
    return True, ""
