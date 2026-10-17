"""
Round 5 defense (level 5): bind the session to the device key. (Reference solution.)

Three states, as in any signature check: ABSENT (no proof: 80), INVALID (wrong key, bad signature, stale,
unknown or spent nonce) and VERIFIED. The order is cheap and certain first, and the nonce is spent LAST: an
attacker's garbage must not burn a nonce that belongs to the owner.

The one subtle signal is `key_changed` (50). A different key under a known token is what a thief looks like
and also what a phone restore looks like: the token comes back from the backup, the keystore key does not.
You cannot tell them apart from the request alone, so it earns the challenge band, not the block band. This
store has no step-up flow behind that band (the checkpoint enforces it as a refusal and lists the restored
phone as the cost); a real deployment re-authenticates and rebinds, and then the owner passes and the thief,
who cannot sign in as the victim, does not.

`soft_key` (10) records a software-backed key. It stays a monitor-band nudge on purpose: the rooted and
uncertified phones that have one already paid in Round 4, and refusing them twice would double-bill the same
customers. Raise it to 30 and watch who joins the refused (README exercise).

Costs: one ECDSA verify and about three Redis operations per sensitive call, and one more request (the nonce)
for the app. Clock skew is a real failure mode here (a phone with a wrong clock fails `stale`); the app can
refresh from the nonce response's Date header.
"""

from .mobile_core import ISSUED_PREFIX, PROOF_SPENT_PREFIX, parse_proof, verify_proof
from .pipeline import Check, Signal

FRESH_MS = 120_000  # +/- two minutes: the client clock matters here, unlike Round 3


def _check(ctx):
    binding = ctx.attrs.get("binding")
    if binding is None:
        return [Signal("session_binding", "unbound", 25, "the token was issued without a device key (legacy app)")]
    proof = parse_proof(ctx.attrs.get("proof"))
    if proof is None:
        return [Signal("session_binding", "no_proof", 80, "no X-Device-Proof on a key-bound session")]
    if proof["kid"] != binding["kid"]:
        return [Signal("session_binding", "key_changed", 50, f"proof by {proof['kid'][:8]}, session bound to {binding['kid'][:8]}")]
    if not verify_proof(binding["pub"], proof, ctx.attrs["bearer"], ctx.method, ctx.path):
        return [Signal("session_binding", "bad_signature", 80, "not signed by the bound key for this bearer and request")]
    if abs(ctx.attrs["now_ms"] - proof["ts"]) > FRESH_MS:
        return [Signal("session_binding", "stale", 80, f"proof is {abs(ctx.attrs['now_ms'] - proof['ts']) // 1000}s off the server clock")]
    if not ctx.redis.get(ISSUED_PREFIX + proof["n"]):
        return [Signal("session_binding", "unknown_nonce", 80, "never issued by this server, or expired")]
    if not ctx.redis.set(PROOF_SPENT_PREFIX + proof["n"], 1, nx=True, ex=FRESH_MS // 1000 + 60):
        return [Signal("session_binding", "replay", 80, "proof nonce already spent")]
    if binding.get("storage") == "software":
        return [Signal("session_binding", "soft_key", 10, "the key lives in software, not a hardware keystore")]
    return None


CHECK = Check("session_binding", _check, phases=("action:mobile_buy", "action:mobile_read"))
