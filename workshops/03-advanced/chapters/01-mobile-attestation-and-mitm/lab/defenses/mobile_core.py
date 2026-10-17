"""
W3 Ch1: mobile attestation & signing core (infrastructure, not a TODO for you)

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

What the mock leaves out: hardware roots of trust and certificate chains, the
Google/Apple round-trip (the real verdict is decrypted or verified through the
provider's API, with its own quota), and the provider's rate limits on the
verdict calls themselves. The README's "What the mock leaves out" box says more.

Round 5 adds the other half of a device-bound session (a DBSC-style design): a per-install EC P-256 key.
The app generates it, the provider vouches for where it lives (attest_key: hardware keystore or software,
like Android key attestation), the server stores the public half next to the bearer token at login, and the
app signs a short proof with it on every sensitive call (sign_proof / verify_proof). A stolen bearer without
the private key is then just a string. Real DBSC has the browser do this with a TPM-backed key and a
short-lived cookie; the mock keeps the three moving parts (bound key, signed proof, single-use nonce) and
leaves out the cookie refresh dance.

Run it on its own (from the lab folder):  python -m defenses.mobile_core
"""

import base64
import hashlib
import json
import os
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

INSTANCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "instance")
PRIV = os.path.join(INSTANCE, "attest_private.pem")
PUB = os.path.join(INSTANCE, "attest_public.pem")

APP_ID = "com.labstore.runner"        # the genuine app's package name
APP_VERSION = "3.2.0"
APP_UA = f"LabRunner/{APP_VERSION} (Android 14; Pixel 8) okhttp/4.12.0"

# The TLS fingerprint the genuine app's stack puts on the wire. The lab has no TLS edge, so a client
# CLAIMS it in X-Lab-JA4 (tools/labclient.py) and the gate reads it as a claimed fingerprint (W2 Ch5's
# measured version needs a real TLS edge). The app is modelled with Chromium/BoringSSL's JA4 from
# defenses/known_fingerprints.json; a stock Python HTTP client has the library JA4 below.
APP_JA4 = "t13d1516h2_8daaf6152771_806a8c22fdea"
PYTHON_LIB_JA4 = "t13d1712h1_ab0a1bf427ad_882d495ac381"

# Redis keys the nonce flow uses. Everything under "lab:" is wiped by POST /lab/reset.
ISSUED_PREFIX = "lab:ch1:issued:"      # a nonce the server handed out (GET /api/mobile/nonce)
SPENT_PREFIX = "lab:ch1:spent:"        # a nonce a buy already used (Round 3 writes it)

# Round 5: the proof nonce is the same server challenge (/api/mobile/nonce, ISSUED_PREFIX) spent in its own
# namespace, so a buy's attestation nonce and its proof nonce never collide. BIND_PREFIX holds the public key a
# bearer token was bound to at login.
PROOF_SPENT_PREFIX = "lab:ch1:pspent:"
BIND_PREFIX = "lab:ch1:bind:"

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

# Where each device profile keeps a freshly generated key. The client cannot claim "hardware": the provider
# says so in attest_key(), from this table. Not a fourth DEVICE_PROFILES column (mint() unpacks 3-tuples).
# GrapheneOS fails Play Integrity but still has a hardware keystore; rooted and uncertified phones, and
# emulators, fall back to a software key the OS (or the attacker) can read.
KEY_STORAGE = {
    "pixel8": "hardware", "iphone15": "hardware", "pixel6-old": "hardware", "graphene": "hardware",
    "rooted": "software", "old-uncertified": "software", "emulator": "software",
}


# --------------------------------------------------------------------------
# Provider key (lazy: created on first use, like a real enrolment)
# --------------------------------------------------------------------------

def ensure_keys():
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
    ensure_keys()
    with open(PRIV, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _public_key():
    ensure_keys()
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

def mint(profile="pixel8", serial="", nonce=None, req_hash=None, extra=None):
    """
    The provider inspects the device and signs the honest verdict. The caller
    cannot choose the verdict fields: they come from DEVICE_PROFILES[profile].
    `extra` is for the provider's own additions (attest_key's keyStorage).
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
        **(extra or {}),
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


# --------------------------------------------------------------------------
# Round 5: the device key and the signed proof (shared by the app and the server)
# --------------------------------------------------------------------------

def _b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def new_device_key():
    """A fresh per-install EC P-256 key. In a real app it lives in the Android Keystore / Secure Enclave."""
    return ec.generate_private_key(ec.SECP256R1())


def public_b64(key):
    """The public half as base64url SPKI DER: what the app sends at login in X-Device-Key."""
    return _b64(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def thumbprint(pub_b64):
    """A short stable name for a public key (sha256 of its DER, 32 hex chars): the proof's `kid`."""
    return hashlib.sha256(_unb64(pub_b64)).hexdigest()[:32]


def attest_key(profile="pixel8", serial="", pub_b64=""):
    """
    Provider side (models Android key attestation): vouch that this public key was generated on this device and
    say where the private half lives. The signed claims are {deviceId, keyStorage, thumbprint}; the thumbprint
    rides in the verdict's requestHash field (it is "the thing this verdict is bound to", as in Round 3). The
    app cannot self-claim "hardware": keyStorage comes from KEY_STORAGE[profile].
    """
    return mint(profile, serial, nonce=None, req_hash=thumbprint(pub_b64), extra={"keyStorage": KEY_STORAGE[profile]})


def proof_message(bearer, nonce, ts, method, path):
    """What the proof signs: the bearer (hashed), a server nonce, a timestamp and the request line."""
    return f"{hashlib.sha256(bearer.encode()).hexdigest()}\n{nonce}\n{ts}\n{method.upper()} {path}".encode()


def sign_proof(key, bearer, nonce, method, path, ts=None):
    """The X-Device-Proof header: v1;kid=<thumbprint>;n=<nonce>;ts=<ms>;sig=<b64>."""
    ts = int(time.time() * 1000) if ts is None else ts
    sig = key.sign(proof_message(bearer, nonce, ts, method, path), ec.ECDSA(hashes.SHA256()))
    return f"v1;kid={thumbprint(public_b64(key))};n={nonce};ts={ts};sig={_b64(sig)}"


def parse_proof(header):
    """{kid, n, ts, sig} from an X-Device-Proof header, or None when it is missing or malformed."""
    if not header or not header.startswith("v1;"):
        return None
    fields = dict(part.split("=", 1) for part in header[3:].split(";") if "=" in part)
    try:
        return {"kid": fields["kid"], "n": fields["n"], "ts": int(fields["ts"]), "sig": fields["sig"]}
    except (KeyError, ValueError):
        return None


def verify_proof(pub_b64, proof, bearer, method, path):
    """True when `proof` (parse_proof's dict) is a valid signature, by the bound key, over THIS bearer and request."""
    try:
        pub = serialization.load_der_public_key(_unb64(pub_b64))
        pub.verify(_unb64(proof["sig"]), proof_message(bearer, proof["n"], proof["ts"], method, path), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError):
        return False


if __name__ == '__main__':
    # Self-test: a minted verdict verifies; a tampered one does not.
    t = mint("pixel8", nonce="abc", req_hash="deadbeef")
    v = verify(t)
    print("verify genuine:", integrity_level(v), v["appIntegrity"])
    print("verify emulator:", integrity_level(verify(mint("emulator"))))
    print("verify tampered:", verify(t[:-4] + "aaaa"))
    # Round 5: a key attested as hardware, and a proof only that key can sign.
    k = new_device_key()
    pub = public_b64(k)
    print("key attested:", verify(attest_key("pixel8", "x", pub))["keyStorage"])
    proof = parse_proof(sign_proof(k, "bearer", "n1", "GET", "/api/mobile/orders"))
    print("proof ok:", verify_proof(pub, proof, "bearer", "GET", "/api/mobile/orders"),
          "| other bearer:", verify_proof(pub, proof, "other", "GET", "/api/mobile/orders"),
          "| other path:", verify_proof(pub, proof, "bearer", "POST", "/api/mobile/buy"))
