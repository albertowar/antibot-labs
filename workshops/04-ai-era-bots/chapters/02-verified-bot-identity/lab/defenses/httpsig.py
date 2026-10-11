"""RFC 9421 HTTP Message Signatures, the subset Web Bot Auth uses. Ships done.

This is given infrastructure so you can read it, not a student exercise. It
implements just enough of RFC 9421 to sign and verify the way the IETF
`draft-ietf-webbotauth-httpsig-protocol-00` and Cloudflare's verifier do:

  * Ed25519 only (the one algorithm Cloudflare's verifier accepts in 2026).
  * Derived components `@method`, `@authority`, `@path`, `@target-uri`, plus any
    header, plus a Dictionary member of a header (`"signature-agent";key="sig1"`,
    the form the working-group draft now requires).
  * Signature parameters `created`, `expires`, `keyid`, `tag`, `nonce`, `alg`.
  * JWK thumbprints (RFC 7638 / RFC 8037) as key ids, and the Ed25519 JWK Set
    served at /.well-known/http-message-signatures-directory.

Why hand-roll instead of `http-message-signatures` (PyPI, Apache-2.0)? The point of
Round 4 is to *see* the signature base: the exact bytes the agent signed, line by
line. A library hides that, and the Python libraries did not yet document the
Web Bot Auth parameters when this was written. In production use a maintained
library (Cloudflare's `web-bot-auth` in TypeScript/Rust, or `http-message-signatures`
in Python) and keep this file as the reference for what it must be doing.

The one deliberate simplification: the structured-field parser below handles the
grammar these three headers actually use, not all of RFC 9651.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

WEB_BOT_AUTH_TAG = "web-bot-auth"
DIRECTORY_TAG = "http-message-signatures-directory"
DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"


# ---------------------------------------------------------------- keys & JWK

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jwk_from_public(pub: Ed25519PublicKey) -> dict:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}


def public_from_jwk(jwk: dict) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("only Ed25519 JWKs are supported")
    return Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"]))


def thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint; RFC 8037 fixes the OKP member set to crv, kty, x."""
    canonical = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
                           separators=(",", ":"), sort_keys=True)
    return b64u(hashlib.sha256(canonical.encode()).digest())


def load_private(hex_seed: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_seed))


def generate() -> tuple[str, dict, str]:
    """Return (private seed hex, public JWK, thumbprint) for a fresh Ed25519 key."""
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                              serialization.NoEncryption()).hex()
    jwk = jwk_from_public(priv.public_key())
    return seed, jwk, thumbprint(jwk)


# ---------------------------------------------------- structured fields (subset)

def sf_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sf_unquote(text: str) -> str:
    return text[1:-1].replace('\\"', '"').replace("\\\\", "\\")


_PARAM = re.compile(r';([a-z*][a-z0-9_\-.*]*)(?:=("(?:[^"\\]|\\.)*"|[^;"\s)]+))?')
_ITEM = re.compile(r'"((?:[^"\\]|\\.)*)"((?:;[a-z*][a-z0-9_\-.*]*(?:=(?:"(?:[^"\\]|\\.)*"|[^;"\s)]+))?)*)')


def _parse_params(text: str) -> dict:
    params: dict = {}
    for m in _PARAM.finditer(text):
        key, raw = m.group(1), m.group(2)
        if raw is None:
            params[key] = True
        elif raw.startswith('"'):
            params[key] = _sf_unquote(raw)
        elif re.fullmatch(r"-?\d+", raw):
            params[key] = int(raw)
        else:
            params[key] = raw
        # Reject anything we did not consume so a crafted header can't smuggle bytes.
    return params


def serialize_params(params: dict) -> str:
    out = []
    for key, value in params.items():
        if value is True:
            out.append(f";{key}")
        elif isinstance(value, int):
            out.append(f";{key}={value}")
        else:
            out.append(f";{key}={sf_string(str(value))}")
    return "".join(out)


def serialize_component_id(name: str, params: dict | None = None) -> str:
    return sf_string(name) + serialize_params(params or {})


def serialize_inner_list(components: list[tuple[str, dict]]) -> str:
    return "(" + " ".join(serialize_component_id(n, p) for n, p in components) + ")"


@dataclass
class SignatureInput:
    label: str
    components: list[tuple[str, dict]]
    params: dict
    raw: str  # everything after "label=", used verbatim in the signature base


def parse_signature_input(header: str) -> dict[str, SignatureInput]:
    """Parse `sig1=("@authority" "signature-agent");created=...;...`, one or more labels."""
    out: dict[str, SignatureInput] = {}
    pos = 0
    text = header.strip()
    while pos < len(text):
        m = re.match(r'\s*,?\s*([a-z*][a-z0-9_\-.*]*)=\(', text[pos:])
        if not m:
            raise ValueError("malformed Signature-Input")
        label = m.group(1)
        start = pos + m.end() - 1          # at "("
        close = text.index(")", start)
        inner = text[start + 1:close]
        components = [(_sf_unquote('"' + im.group(1) + '"'), _parse_params(im.group(2)))
                      for im in _ITEM.finditer(inner)]
        pm = re.match(r'((?:;[a-z*][a-z0-9_\-.*]*(?:=(?:"(?:[^"\\]|\\.)*"|[^;",\s]+))?)*)', text[close + 1:])
        params_text = pm.group(1) if pm else ""
        end = close + 1 + len(params_text)
        out[label] = SignatureInput(label, components, _parse_params(params_text), text[start:end])
        pos = end
    return out


def parse_signature(header: str) -> dict[str, bytes]:
    """Parse `sig1=:base64:, sig2=:base64:` into label -> raw signature bytes."""
    out: dict[str, bytes] = {}
    for m in re.finditer(r'([a-z*][a-z0-9_\-.*]*)=:([A-Za-z0-9+/=]*):', header):
        out[m.group(1)] = base64.b64decode(m.group(2))
    return out


def parse_signature_agent(header: str) -> dict[str, str]:
    """Both wire forms. Returns {label-or-"*": origin}.

    String form (what Cloudflare's verifier requires in 2026):   "https://chatgpt.com"
    Dictionary form (what the WG draft now says signers MUST send): sig1="https://chatgpt.com";type=directory
    """
    text = header.strip()
    if text.startswith('"'):
        m = re.match(r'"((?:[^"\\]|\\.)*)"', text)
        return {"*": _sf_unquote(m.group(0))} if m else {}
    out: dict[str, str] = {}
    for m in re.finditer(r'([a-z*][a-z0-9_\-.*]*)="((?:[^"\\]|\\.)*)"', text):
        out[m.group(1)] = _sf_unquote('"' + m.group(2) + '"')
    return out


# ---------------------------------------------------------------- signature base

@dataclass
class MessageContext:
    """What the verifier knows about the request it received (or the signer is about to send)."""
    method: str
    authority: str
    path: str
    headers: dict[str, str]              # lower-cased names
    scheme: str = "http"
    query: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def target_uri(self) -> str:
        q = f"?{self.query}" if self.query else ""
        return f"{self.scheme}://{self.authority}{self.path}{q}"


def component_value(name: str, params: dict, ctx: MessageContext, label: str) -> str:
    if name == "@method":
        return ctx.method.upper()
    if name == "@authority":
        return ctx.authority.lower()
    if name == "@path":
        return ctx.path
    if name == "@target-uri":
        return ctx.target_uri
    if name == "@scheme":
        return ctx.scheme
    if name.startswith("@"):
        raise ValueError(f"unsupported derived component {name}")
    value = ctx.headers.get(name.lower())
    if value is None:
        raise ValueError(f"covered header {name} is missing")
    value = " ".join(value.split())
    if "key" in params:
        # Dictionary member: re-serialize just that member's value (RFC 9421 §2.1.2).
        members = parse_signature_agent(value) if name.lower() == "signature-agent" else {}
        member = members.get(params["key"])
        if member is None:
            raise ValueError(f"{name} has no member {params['key']!r}")
        return sf_string(member)
    return value


def signature_base(si: SignatureInput, ctx: MessageContext) -> str:
    lines = [f"{serialize_component_id(n, p)}: {component_value(n, p, ctx, si.label)}"
             for n, p in si.components]
    lines.append(f'"@signature-params": {si.raw}')
    return "\n".join(lines)


# ----------------------------------------------------------------- sign / verify

def sign(private_key: Ed25519PrivateKey, keyid: str, ctx: MessageContext,
         components: list[tuple[str, dict]], *, label: str = "sig1",
         created: int | None = None, expires: int | None = None, nonce: str | None = None,
         tag: str = WEB_BOT_AUTH_TAG, extra_params: dict | None = None) -> dict[str, str]:
    """Return the Signature-Input and Signature headers for this request context."""
    created = int(time.time()) if created is None else created
    expires = created + 60 if expires is None else expires
    params: dict = {"created": created, "expires": expires, "keyid": keyid}
    if nonce:
        params["nonce"] = nonce
    params["tag"] = tag
    if extra_params:
        params.update(extra_params)
    raw = serialize_inner_list(components) + serialize_params(params)
    si = SignatureInput(label, components, params, raw)
    sig = private_key.sign(signature_base(si, ctx).encode())
    return {"Signature-Input": f"{label}={raw}",
            "Signature": f"{label}=:{base64.b64encode(sig).decode()}:"}


def verify_signature(public_key: Ed25519PublicKey, si: SignatureInput, signature: bytes,
                     ctx: MessageContext) -> bool:
    try:
        public_key.verify(signature, signature_base(si, ctx).encode())
        return True
    except (InvalidSignature, ValueError):
        return False


def agent_headers(private_key: Ed25519PrivateKey, keyid: str, agent_origin: str, ctx: MessageContext,
                  *, components: tuple[str, ...] = ("@authority", "signature-agent"),
                  agent_form: str = "string", created: int | None = None,
                  expires: int | None = None, nonce: str | None = "auto", label: str = "sig1") -> dict[str, str]:
    """Everything a Web Bot Auth client adds to a request: Signature-Agent + the two signature headers.

    `agent_form="string"` sends `Signature-Agent: "https://..."` (Cloudflare's wire form);
    `"dict"` sends `Signature-Agent: sig1="https://..."` and covers it as `"signature-agent";key="sig1"`
    (the working-group draft form).
    """
    if agent_form == "dict":
        sa_value = f'{label}={sf_string(agent_origin)}'
        comps = [(c, {"key": label}) if c == "signature-agent" else (c, {}) for c in components]
    else:
        sa_value = sf_string(agent_origin)
        comps = [(c, {}) for c in components]
    headers = dict(ctx.headers)
    headers["signature-agent"] = sa_value
    sctx = MessageContext(ctx.method, ctx.authority, ctx.path, headers, ctx.scheme, ctx.query)
    if nonce == "auto":
        nonce = b64u(secrets.token_bytes(16))
    out = sign(private_key, keyid, sctx, comps, label=label, created=created, expires=expires, nonce=nonce)
    out["Signature-Agent"] = sa_value
    return out


# ---------------------------------------------------- the signed key directory

def sign_directory(jwks: dict, private_keys: dict[str, Ed25519PrivateKey], authority: str,
                   *, created: int | None = None, ttl: int = 3600) -> dict[str, str]:
    """One signature per key over `("@authority";req)`, tagged for the directory (draft App. B / Cloudflare).

    `authority` is the host the directory was requested from: the proof binds the keys to
    the origin that serves them, so a copy of the file hosted elsewhere does not verify.
    """
    created = int(time.time()) if created is None else created
    ctx = MessageContext("GET", authority, DIRECTORY_PATH, {})
    comps = [("@authority", {"req": True})]
    inputs, sigs = [], []
    for i, jwk in enumerate(jwks["keys"]):
        kid = thumbprint(jwk)
        h = sign(private_keys[kid], kid, ctx, comps, label=f"binding-{i}", created=created,
                 expires=created + ttl, tag=DIRECTORY_TAG)
        inputs.append(h["Signature-Input"])
        sigs.append(h["Signature"])
    return {"Signature-Input": ", ".join(inputs), "Signature": ", ".join(sigs),
            "Content-Type": DIRECTORY_MEDIA_TYPE}


def verify_directory(jwks: dict, headers: dict[str, str], authority: str, now: int | None = None) -> tuple[bool, str]:
    """Check every key in the JWK Set is bound to `authority` by a valid directory signature."""
    now = int(time.time()) if now is None else now
    try:
        inputs = parse_signature_input(headers.get("signature-input", ""))
        sigs = parse_signature(headers.get("signature", ""))
    except ValueError as exc:
        return False, f"directory headers malformed: {exc}"
    ctx = MessageContext("GET", authority, DIRECTORY_PATH, {})
    by_kid = {si.params.get("keyid"): (si, sigs.get(label)) for label, si in inputs.items()}
    for jwk in jwks.get("keys", []):
        kid = thumbprint(jwk)
        si, sig = by_kid.get(kid, (None, None))
        if si is None or sig is None:
            return False, f"no directory signature for key {kid[:8]}"
        if si.params.get("tag") != DIRECTORY_TAG:
            return False, "directory signature has the wrong tag"
        if si.params.get("created", 0) > now + 60:
            return False, "directory signature created in the future"
        if si.params.get("expires", 0) < now:
            return False, "directory signature expired"
        if not verify_signature(public_from_jwk(jwk), si, sig, ctx):
            return False, f"directory signature invalid for key {kid[:8]}"
    return True, "directory bound to origin"


if __name__ == "__main__":
    # Self-test: sign a request both ways, verify, then tamper.
    seed, jwk, kid = generate()
    priv = load_private(seed)
    for form in ("string", "dict"):
        ctx = MessageContext("GET", "shop.example", "/product/7", {"user-agent": "ChatGPT-User/1.0"})
        h = agent_headers(priv, kid, "https://chatgpt.com", ctx, agent_form=form)
        rctx = MessageContext("GET", "shop.example", "/product/7",
                              {"user-agent": "ChatGPT-User/1.0", "signature-agent": h["Signature-Agent"]})
        si = parse_signature_input(h["Signature-Input"])["sig1"]
        sig = parse_signature(h["Signature"])["sig1"]
        print(f"--- {form} form ---")
        print(signature_base(si, rctx))
        print("verify:", verify_signature(public_from_jwk(jwk), si, sig, rctx))
        tampered = MessageContext("GET", "evil.example", "/product/7", rctx.headers)
        print("verify (other authority):", verify_signature(public_from_jwk(jwk), si, sig, tampered))
    jwks = {"keys": [jwk]}
    dh = sign_directory(jwks, {kid: priv}, "chatgpt.com")
    print("directory:", verify_directory(jwks, {k.lower(): v for k, v in dh.items()}, "chatgpt.com"))
    print("directory (moved):", verify_directory(jwks, {k.lower(): v for k, v in dh.items()}, "mirror.example"))
