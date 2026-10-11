"""
W4 Ch4 — HTTP Message Signatures (RFC 9421) with the Web Bot Auth profile. GIVEN, not a TODO.

This is the cryptographic core both sides use: the agent operator signs with
it (attacks/agent/identity.py, tools/legit_traffic.py) and the store verifies
with it (defenses/agent_identity.py). It implements exactly what the IETF
webbotauth working group's draft asks for, nothing more:

    Signature-Agent:  "agents.lab-provider.test"          where the keys live
    Signature-Input:  sig1=("@authority" "signature-agent");created=…;expires=…;
                      keyid="<JWK thumbprint>";alg="ed25519";nonce="…";tag="web-bot-auth"
    Signature:        sig1=:<base64 Ed25519 signature>:

The signature base is the RFC 9421 canonical form of the covered components
plus the @signature-params line. Keys are Ed25519 JWKs; keyid is the RFC 7638
thumbprint. In production the verifier fetches
https://<Signature-Agent>/.well-known/http-message-signatures-directory and
caches it; in the lab, tools/make_keys.py writes those directories into
data/directories/<host>.json and load_directory() reads them from disk.

What this module deliberately leaves to agent_identity.py (the Round 3 TODO):
freshness (created/expires), nonce single-use, and whether the operator is one
you trust. A valid signature from a key you have never heard of proves only
that someone owns a key.

Sources: RFC 9421 (2024); draft-ietf-webbotauth-httpsig-protocol-00 (2026);
RFC 7638 (2015); RFC 8941 structured fields (2021).
"""

import base64
import hashlib
import json
import os
import re
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

COVERED = ("@authority", "signature-agent")
TAG = "web-bot-auth"
DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"
LAB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DIRECTORIES = os.path.join(LAB_DIR, "data", "directories")


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------

def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_private_key():
    return ed25519.Ed25519PrivateKey.generate()


def save_private_key(key, path):
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem)


def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def public_jwk(public_key):
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}
    jwk["kid"] = jwk_thumbprint(jwk)
    return jwk


def jwk_thumbprint(jwk):
    """RFC 7638: SHA-256 over the required members in lexicographic order, no whitespace."""
    canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canon.encode()).digest())


def public_key_from_jwk(jwk):
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("only Ed25519 OKP keys are supported")
    return ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))


def directory_for(private_key):
    """The JSON the operator serves at /.well-known/http-message-signatures-directory."""
    return {"keys": [public_jwk(private_key.public_key())]}


def load_directory(host, directories=DIRECTORIES):
    """Lab stand-in for fetching https://<host>/.well-known/http-message-signatures-directory."""
    if not re.fullmatch(r"[a-z0-9.-]+", host or ""):
        return None
    path = os.path.join(directories, f"{host}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


# --------------------------------------------------------------------------
# Signing (the agent operator's side)
# --------------------------------------------------------------------------

def signature_params(keyid, created, expires, nonce, label_components=COVERED, tag=TAG):
    comps = " ".join(f'"{c}"' for c in label_components)
    return (f'({comps});created={created};expires={expires};keyid="{keyid}";'
            f'alg="ed25519";nonce="{nonce}";tag="{tag}"')


def signature_base(components, values, params):
    lines = [f'"{name}": {values[name]}' for name in components]
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines).encode()


def sign(private_key, authority, agent_host, created=None, ttl=300, nonce=None, label="sig1"):
    """Return the three headers an agent adds to one request."""
    created = int(created if created is not None else time.time())
    expires = created + ttl
    nonce = nonce or b64url(secrets.token_bytes(24))
    keyid = public_jwk(private_key.public_key())["kid"]
    params = signature_params(keyid, created, expires, nonce)
    values = {"@authority": authority, "signature-agent": f'"{agent_host}"'}
    sig = private_key.sign(signature_base(COVERED, values, params))
    return {
        "Signature-Agent": f'"{agent_host}"',
        "Signature-Input": f"{label}={params}",
        "Signature": f"{label}=:{base64.b64encode(sig).decode()}:",
    }


# --------------------------------------------------------------------------
# Parsing and verifying (the store's side)
# --------------------------------------------------------------------------

_PARAMS_RE = re.compile(r'^(?P<label>[a-zA-Z0-9_-]+)=(?P<params>\((?P<comps>[^)]*)\)(?P<rest>.*))$')
_PARAM_KV = re.compile(r';([a-z]+)=("(?:[^"\\]|\\.)*"|[^;]+)')


def parse(headers):
    """Parse Signature-Agent / Signature-Input / Signature. Returns a dict or None if absent."""
    agent = headers.get("Signature-Agent")
    sig_input = headers.get("Signature-Input")
    sig = headers.get("Signature")
    if not (agent or sig_input or sig):
        return None
    out = {"agent_raw": agent, "ok": False, "error": None}
    if not (agent and sig_input and sig):
        out["error"] = "incomplete: Signature-Agent, Signature-Input and Signature are all required"
        return out
    m = _PARAMS_RE.match(sig_input.strip())
    if not m:
        out["error"] = "malformed Signature-Input"
        return out
    comps = re.findall(r'"([^"]+)"', m.group("comps"))
    params = {}
    for key, value in _PARAM_KV.findall(m.group("rest")):
        params[key] = value[1:-1] if value.startswith('"') else value
    sm = re.match(rf'^{re.escape(m.group("label"))}=:([A-Za-z0-9+/=]+):$', sig.strip())
    if not sm:
        out["error"] = "malformed Signature (label mismatch or not a byte sequence)"
        return out
    try:
        signature = base64.b64decode(sm.group(1), validate=True)
        created = int(params.get("created", "0"))
        expires = int(params.get("expires", "0"))
    except (ValueError, TypeError):
        out["error"] = "malformed signature parameters"
        return out
    host = agent.strip()
    if host.startswith('"') and host.endswith('"'):
        host = host[1:-1]
    out.update({
        "label": m.group("label"), "components": comps, "params_str": m.group("params"),
        "params": params, "signature": signature, "agent": host.lower(),
        "keyid": params.get("keyid"), "created": created, "expires": expires,
        "nonce": params.get("nonce"), "tag": params.get("tag"), "alg": params.get("alg"), "ok": True,
    })
    return out


def verify_signature(parsed, authority, public_key):
    """Pure signature check: does the key sign this request's base? (No freshness, no trust.)"""
    if not parsed or not parsed.get("ok"):
        return False, parsed.get("error") if parsed else "no signature"
    if set(parsed["components"]) != set(COVERED):
        return False, f"covered components must be {list(COVERED)}, got {parsed['components']}"
    if parsed.get("alg") not in (None, "ed25519"):
        return False, f"unsupported alg {parsed['alg']!r}"
    values = {"@authority": authority, "signature-agent": parsed["agent_raw"].strip()}
    base = signature_base(parsed["components"], values, parsed["params_str"])
    try:
        public_key.verify(parsed["signature"], base)
    except InvalidSignature:
        return False, "signature does not verify for this authority and key"
    return True, "signature verifies"


def find_key(directory, keyid):
    for jwk in (directory or {}).get("keys", []):
        if jwk.get("kid") == keyid or jwk_thumbprint(jwk) == keyid:
            return public_key_from_jwk(jwk)
    return None


if __name__ == '__main__':
    key = generate_private_key()
    hdrs = sign(key, "127.0.0.1:8404", "agents.lab-provider.test")
    for k, v in hdrs.items():
        print(f"{k}: {v}")
    parsed = parse(hdrs)
    print(verify_signature(parsed, "127.0.0.1:8404", key.public_key()))
    print(verify_signature(parsed, "shop.example", key.public_key()))
