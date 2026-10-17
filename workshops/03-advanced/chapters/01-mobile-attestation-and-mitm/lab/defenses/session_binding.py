"""
Round 5 defense (level 5): bind the session to the device key, not just to a string.

Rounds 2-4 protect the buy. They do nothing for the session: the mobile login returns a bearer token, and
whoever holds it IS the user. Round 5's attacker lifts a token and uses it from their own genuine device.
Everything they send is individually valid, so the fix has to be in the session itself, DBSC-style:

  * At login the app sends the public half of a per-install key (X-Device-Key) and the provider's signed claim
    about where the private half lives (X-Key-Attest). The store already verified that and bound the key to the
    token; that part is infrastructure, like nonce issuance.
  * On every sensitive call the app sends X-Device-Proof: a signature, by that key, over the bearer, a fresh
    server nonce, a timestamp and the request line. A stolen token without the private key cannot make one.

    ctx.attrs["bearer"]    the token on this request
    ctx.attrs["binding"]   {pub, kid, storage, deviceId} the token was bound to, or None (a legacy login)
    ctx.attrs["proof"]     the raw X-Device-Proof header, or None
    parse_proof(header)    -> {kid, n, ts, sig} or None
    verify_proof(binding["pub"], proof, bearer, ctx.method, ctx.path) -> bool
    ctx.attrs["now_ms"], ctx.redis, mobile_core.ISSUED_PREFIX, mobile_core.PROOF_SPENT_PREFIX

The check runs on the buy and on the orders read (phases action:mobile_buy, action:mobile_read), so a
thief cannot even look. Three states, as in real signature checks: absent, invalid, verified.

>>> READ BEFORE YOU TUNE THIS: a bound key that changes is not always a thief. A phone restore keeps the bearer
>>> token (it is in the backup) and loses the keystore key, so an honest customer shows up with a valid token and
>>> a NEW key. Score that in the challenge band (50), not the block band: this store has no step-up flow, so the
>>> checkpoint enforces the band as a refusal and lists that customer as the cost, but a real deployment would
>>> re-authenticate them and rebind. Hard evidence (no proof, bad signature, stale, replay) is block-sized (80).
>>> A software-backed key (rooted, uncertified phones) is a small signal (10), not a refusal: Round 4 already
>>> charged them for the device, and real DBSC falls back to software keys too.
>>> Catch up with:  python tools/checkpoint.py --round 5 --catch-up
"""

from .mobile_core import ISSUED_PREFIX, PROOF_SPENT_PREFIX, parse_proof, verify_proof  # noqa: F401
from .pipeline import Check, Signal  # noqa: F401

FRESH_MS = 120_000  # +/- two minutes: the client clock matters here, unlike Round 3


def _check(ctx):
    binding = ctx.attrs.get("binding")  # noqa: F841
    # TODO (Round 5): replace this stub. One signal per failed check:
    #   binding is None                              -> "unbound"        25  (legacy app: no key was registered)
    #   no X-Device-Proof / unparseable              -> "no_proof"       80  (a bare stolen bearer)
    #   proof kid != binding["kid"]                  -> "key_changed"    50  (another key: restore or thief)
    #   verify_proof(...) is False                   -> "bad_signature"  80
    #   |now_ms - ts| > FRESH_MS                     -> "stale"          80
    #   nonce not issued (ISSUED_PREFIX)             -> "unknown_nonce"  80
    #   nonce already spent (PROOF_SPENT_PREFIX, SET NX) -> "replay"     80
    #   binding["storage"] == "software"             -> "soft_key"       10
    return None


CHECK = Check("session_binding", _check, phases=("action:mobile_buy", "action:mobile_read"))
