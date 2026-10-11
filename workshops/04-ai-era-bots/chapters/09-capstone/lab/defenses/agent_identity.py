"""
W4 Ch4 — L3 verified agent identity (Round 3)

defenses/httpsig.py parses the Web Bot Auth headers and checks the Ed25519
signature. This module decides what a valid signature *means* for the store,
and it does the checks in the cheapest-first order a verifier should:

    1. Is the claimed operator (Signature-Agent host) one we trust?
       Checked BEFORE any key lookup. A verifier that fetches a directory from
       whatever host a request names is a server-side request forgery waiting
       to happen, and it hands a cost (a fetch) to anyone who asks.
    2. Does the keyid exist in that operator's key directory?
    3. Does the signature verify over this request's @authority?
    4. Is it fresh? created not in the future (small skew), not expired, and
       the window no longer than MAX_WINDOW_S.
    5. Is the nonce new? Stored with SET NX for the window's duration.

Statuses: none (no headers), verified, unknown_operator, invalid, expired, replayed.
A claim that fails checks 2–5 is scored like a hostile request (+60): nobody
presents a bad signature by accident. 'none' and 'verified' score 0.

What a verified identity proves: that the request came from infrastructure
holding the operator's key. What it does NOT prove: who the human behind the
agent is, what they asked for, or whether they consented to this purchase.
Round 4 deals with that.
"""

import json
import os
import time

import httpsig

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_WINDOW_S = 300      # the draft recommends short-lived signatures
CLOCK_SKEW_S = 30
NONCE_TTL_S = MAX_WINDOW_S + CLOCK_SKEW_S


def trusted_operators():
    with open(os.path.join(HERE, "trusted_operators.json")) as f:
        return set(json.load(f)["trusted"])


def _result(status, operator=None, keyid=None, reason=""):
    return {"status": status, "operator": operator, "keyid": keyid, "reasons": [reason] if reason else []}


def verify(ctx, store):
    parsed = httpsig.parse(ctx["headers"])
    if parsed is None:
        return _result("none")
    if not parsed["ok"]:
        return _result("invalid", reason=f"Signature headers present but unusable: {parsed['error']}")
    host, keyid = parsed["agent"], parsed["keyid"]
    if parsed.get("tag") != httpsig.TAG:
        return _result("invalid", host, keyid, f"Signature tag {parsed.get('tag')!r} is not {httpsig.TAG!r}")
    if host not in trusted_operators():
        return _result("unknown_operator", host, keyid,
                       f"Signature-Agent {host} is not a trusted operator (no key lookup attempted)")
    directory = httpsig.load_directory(host)
    key = httpsig.find_key(directory, keyid) if directory else None
    if key is None:
        return _result("invalid", host, keyid, f"keyid {keyid} not in {host}'s key directory")
    ok, why = httpsig.verify_signature(parsed, ctx["authority"], key)
    if not ok:
        return _result("invalid", host, keyid, f"Signature from {host} rejected: {why}")
    now = time.time()
    if parsed["created"] > now + CLOCK_SKEW_S:
        return _result("expired", host, keyid, "Signature created in the future")
    if parsed["expires"] < now - CLOCK_SKEW_S:
        return _result("expired", host, keyid, f"Signature expired {int(now - parsed['expires'])} s ago")
    if parsed["expires"] - parsed["created"] > MAX_WINDOW_S:
        return _result("expired", host, keyid, f"Signature window longer than {MAX_WINDOW_S} s")
    if not parsed["nonce"] or not store.set(f"nonce:{host}:{parsed['nonce']}", "1", nx=True, ex=NONCE_TTL_S):
        return _result("replayed", host, keyid, "Signature nonce already seen (replay)")
    return _result("verified", host, keyid)


def score(identity):
    if identity["status"] in ("none", "verified"):
        return 0, []
    return 60, [f"Claimed agent identity did not verify ({identity['status']}): " + "; ".join(identity["reasons"])]


if __name__ == '__main__':
    import fakeredis
    store = fakeredis.FakeStrictRedis(decode_responses=True)
    print(verify({"headers": {}, "authority": "127.0.0.1:8404"}, store))
    print(verify({"headers": {"Signature-Agent": '"agents.evil.test"'}, "authority": "127.0.0.1:8404"}, store))
