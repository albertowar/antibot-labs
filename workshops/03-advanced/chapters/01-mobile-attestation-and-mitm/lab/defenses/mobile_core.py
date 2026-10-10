"""
W3 Ch1 — Mobile attestation & signing core (infrastructure, not a student TODO)

This module is the shared machinery the genuine app AND the attacker's
reverse-engineered SDK both use. In real life:

  * The attestation *provider* is Google Play Integrity (Android) or Apple App
    Attest / DeviceCheck (iOS). The provider holds a private key, inspects the
    real device, and signs a verdict. Your server verifies that signature with
    the provider's public key. The attacker never holds the private key, so the
    attacker cannot invent a "strong integrity" verdict — they can only run the
    real app on whatever device they actually have and get *that* device's
    honest verdict.

  * In the lab we model the provider with a local EC key pair in instance/
    (attest_private.pem signs, attest_public.pem verifies). mint() plays the
    provider: given a *device profile*, it stamps the honest verdict for that
    device and signs it. The attacker's scripts call mint() with device=
    "emulator" because that is the device they really have — they cannot pass
    device="pixel8" and get a strong verdict for hardware they do not own.
    Treat attest_private.pem as if it lived inside Google's datacentre.

Verdict fields mirror Play Integrity's verdict:
    deviceIntegrity : subset of {MEETS_BASIC_INTEGRITY, MEETS_DEVICE_INTEGRITY,
                                 MEETS_STRONG_INTEGRITY}
    appIntegrity    : PLAY_RECOGNIZED | UNRECOGNIZED_VERSION | UNEVALUATED
    appId           : the package name the verdict is bound to
    deviceId        : a stable per-device id (Play recall / App Attest key id)
    nonce           : the server challenge this verdict answers (classic request)
    requestHash     : sha256 of the canonical request (standard request binding)
    ts              : epoch ms the verdict was minted

See the README "What the mock leaves out" box for how this differs from the
real APIs (asymmetric crypto detail, hardware roots of trust, Google/Apple
round-trips, rate limits on the verdict calls themselves).
"""

import base64
import hashlib
import json
import os
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

INSTANCE = os.path.join(os.path.dirname(__file__), "..", "instance")
PRIV = os.path.join(INSTANCE, "attest_private.pem")
PUB = os.path.join(INSTANCE, "attest_public.pem")

APP_ID = "com.labstore.runner"          # the genuine app's package name
APP_VERSION = "3.2.0"

# Honest verdict per device profile. The attacker cannot pick a better row than
# the device they actually run on.
DEVICE_PROFILES = {
    # profile:        (deviceIntegrity,                                          appIntegrity,        note)
    "pixel8":         (["MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"], "PLAY_RECOGNIZED",     "certified flagship"),
    "iphone15":       (["MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"], "PLAY_RECOGNIZED",     "iOS App Attest analog"),
    "pixel6-old":     (["MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY"],                           "PLAY_RECOGNIZED",     "older but certified"),
    "rooted":         (["MEETS_BASIC_INTEGRITY"],                                                     "PLAY_RECOGNIZED",     "rooted power user"),
    "graphene":       ([],                                                                            "UNRECOGNIZED_VERSION","de-Googled custom ROM, sideloaded"),
    "old-uncertified":(["MEETS_BASIC_INTEGRITY"],                                                     "PLAY_RECOGNIZED",     "cheap uncertified Android"),
    "emulator":       ([],                                                                            "UNEVALUATED",         "emulator / device farm"),
}


# --------------------------------------------------------------------------
# Provider key (lazy: created on first use, like a real enrolment)
# --------------------------------------------------------------------------

def _ensure_keys():
    if os.path.exists(PRIV) and os.path.exists(PUB):
        return
    os.makedirs(INSTANCE, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    with open(PRIV, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(PUB, "wb") as f:
        f.write(key.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo))


def _private_key():
    _ensure_keys()
    with open(PRIV, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _public_key():
    _ensure_keys()
    with open(PUB, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# --------------------------------------------------------------------------
# Canonical request + hashing (shared by client and server)
# --------------------------------------------------------------------------

def canonical(method, path, body_bytes):
    """A stable string for the request content, so both sides hash the same thing.

    Like a Play Integrity "standard request", the hash covers the request
    CONTENT only. Freshness is handled separately by the verdict timestamp, and
    replay by the single-use nonce, so the hash does not include the time.
    """
    digest = hashlib.sha256(body_bytes or b"").hexdigest()
    return f"{method.upper()}\n{path}\n{digest}"


def request_hash(method, path, body_bytes):
    return hashlib.sha256(canonical(method, path, body_bytes).encode()).hexdigest()


def device_id(profile, serial=""):
    """A stable per-device id. Real farms burn through many of these."""
    return hashlib.sha256(f"{profile}:{serial}".encode()).hexdigest()[:24]


# --------------------------------------------------------------------------
# Provider side: mint a signed verdict (models Google/Apple)
# --------------------------------------------------------------------------

def mint(profile="pixel8", serial="", nonce=None, req_hash=None):
    """
    The provider inspects the device and signs the honest verdict. The caller
    cannot choose the verdict fields: they come from DEVICE_PROFILES[profile].
    """
    integrity, app_integrity, _ = DEVICE_PROFILES[profile]
    payload = {
        "appId": APP_ID,
        "appVersion": APP_VERSION,
        "deviceId": device_id(profile, serial),
        "deviceIntegrity": integrity,
        "appIntegrity": app_integrity,
        "nonce": nonce,
        "requestHash": req_hash,
        "ts": int(time.time() * 1000),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = _private_key().sign(raw, ec.ECDSA(hashes.SHA256()))
    return base64.urlsafe_b64encode(raw).decode() + "." + base64.urlsafe_b64encode(sig).decode()


# --------------------------------------------------------------------------
# Server side: verify the signature and return the verdict, or None
# --------------------------------------------------------------------------

def verify(token):
    """Return the verdict payload if the signature is the provider's, else None."""
    if not token or "." not in token:
        return None
    raw_b64, sig_b64 = token.split(".", 1)
    try:
        raw = base64.urlsafe_b64decode(raw_b64.encode())
        sig = base64.urlsafe_b64decode(sig_b64.encode())
        _public_key().verify(sig, raw, ec.ECDSA(hashes.SHA256()))
        return json.loads(raw)
    except (InvalidSignature, ValueError, TypeError):
        return None


def integrity_level(verdict):
    """Coarse label for the strongest integrity the verdict carries."""
    di = set(verdict.get("deviceIntegrity") or [])
    if "MEETS_STRONG_INTEGRITY" in di:
        return "strong"
    if "MEETS_DEVICE_INTEGRITY" in di:
        return "device"
    if "MEETS_BASIC_INTEGRITY" in di:
        return "basic"
    return "none"


if __name__ == '__main__':
    # Self-test: a minted verdict verifies; a tampered one does not.
    t = mint("pixel8", nonce="abc", req_hash="deadbeef")
    v = verify(t)
    print("verify genuine:", integrity_level(v), v["appIntegrity"])
    print("verify emulator:", integrity_level(verify(mint("emulator"))))
    print("verify tampered:", verify(t[:-4] + "aaaa"))
