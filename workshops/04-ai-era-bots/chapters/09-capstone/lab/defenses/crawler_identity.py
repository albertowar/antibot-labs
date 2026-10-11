"""Crawler identity verification (GIVEN infrastructure, not a student exercise).

Answers one question for the policy, enforcement and paywall layers: *is this
request really from the operator its User-Agent claims?* Two ways to say yes:

  1. **Signed request** (Workshop 4, Chapter 2's Web Bot Auth). The crawler sends
     ``Signature-Agent``, ``Signature-Input`` and ``Signature`` headers (RFC 9421
     HTTP Message Signatures) and the signature verifies with a key the operator
     published under that ``keyid``. This is the strong path, and the one a
     pay-per-crawl ledger needs: you cannot bill an IP range.
  2. **Published egress range** (Workshop 4, Chapter 1). The source IP falls in
     the ranges the operator publishes. Weaker (ranges leak, get reused, and a
     declared UA from outside them is exactly the stealth pivot of Round 2), but
     it is what most sites have today.

What this module deliberately simplifies, because Chapter 2 owns the full
protocol: the signature base covers only ``@authority`` and ``signature-agent``
(as in the Web Bot Auth examples), there is no nonce cache against replay, and
the key directory is a local registry instead of a fetch of the operator's
``/.well-known/http-message-signatures-directory``. Swap in Chapter 2's
implementation when it exists; the call site (``verify(request)``) stays.
"""

from __future__ import annotations

import base64
import re
import time
from collections import namedtuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import crawler_registry as registry

Identity = namedtuple("Identity", "operator purpose verified how reason")

COVERED = ("@authority", "signature-agent")
MAX_SKEW = 300  # seconds: created/expires window we accept


def _b64url_decode(s: str) -> bytes:
    s = s.strip().strip('"')
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def signature_base(authority: str, signature_agent: str, params: str) -> bytes:
    """RFC 9421 §2.5 signature base for the two covered components."""
    lines = [
        f'"@authority": {authority}',
        f'"signature-agent": {signature_agent}',
        f'"@signature-params": {params}',
    ]
    return "\n".join(lines).encode()


_INPUT_RE = re.compile(r'^\s*(?P<label>[a-z0-9_-]+)=(?P<params>\(.*\).*)$', re.I)
_PARAM_RE = re.compile(r';(?P<k>[a-z]+)=(?P<v>"[^"]*"|[^;]+)', re.I)


def parse_signature_input(value: str):
    m = _INPUT_RE.match(value or "")
    if not m:
        return None, None, {}
    label, params = m.group("label"), m.group("params")
    kv = {k: v.strip('"') for k, v in _PARAM_RE.findall(params)}
    return label, params, kv


def verify_signature(headers, authority: str):
    """Return (operator_name, record, reason) for a valid signature, else (None, None, why)."""
    agent = headers.get("Signature-Agent")
    sig_input = headers.get("Signature-Input")
    sig = headers.get("Signature")
    if not (agent and sig_input and sig):
        return None, None, "no signature"
    name, record = registry.operator_for_agent(agent)
    if not record:
        return None, None, f"unknown signature-agent {agent}"
    label, params, kv = parse_signature_input(sig_input)
    if not label:
        return None, None, "malformed Signature-Input"
    if kv.get("alg", "ed25519") != "ed25519" or kv.get("tag") != "web-bot-auth":
        return None, None, "unexpected alg/tag"
    for comp in COVERED:
        if f'"{comp}"' not in params:
            return None, None, f"signature does not cover {comp}"
    now = time.time()
    try:
        created, expires = int(kv["created"]), int(kv["expires"])
    except (KeyError, ValueError):
        return None, None, "missing created/expires"
    if not (created - MAX_SKEW <= now <= expires) or expires - created > 3600:
        return None, None, "signature expired or window too wide"
    pub_b64 = record["keys"].get(kv.get("keyid", ""))
    if not pub_b64:
        return None, None, f"unknown keyid {kv.get('keyid')!r} for {name}"
    sig_m = re.match(rf'^\s*{re.escape(label)}=:(?P<b64>[^:]+):\s*$', sig)
    if not sig_m:
        return None, None, "malformed Signature"
    base = signature_base(authority, agent, params)
    try:
        Ed25519PublicKey.from_public_bytes(_b64url_decode(pub_b64)).verify(
            base64.b64decode(sig_m.group("b64")), base)
    except (InvalidSignature, ValueError):
        return None, None, "bad signature"
    return name, record, f"signed by {name} ({kv.get('keyid')})"


def verify(headers, client_ip: str, authority: str) -> Identity:
    """Identity verdict for one request. Never raises.

    Precedence: a valid signature names the operator even if the UA is odd; a
    declared UA is then checked against published ranges; anything else is
    unverified. A declared UA with a *bad* signature is unverified, not merely
    unsigned: lying about identity is a stronger tell than saying nothing.
    """
    ua = headers.get("User-Agent", "")
    s_name, s_rec, s_reason = verify_signature(headers, authority)
    if s_name:
        return Identity(s_name, s_rec["purpose"], True, "signature", s_reason)
    d_name, d_rec = registry.operator_for_ua(ua)
    if not d_name:
        return Identity("", "", False, "none", "undeclared client")
    if headers.get("Signature"):
        return Identity(d_name, d_rec["purpose"], False, "bad-signature", s_reason)
    if registry.ip_in_published_ranges(client_ip, d_rec):
        return Identity(d_name, d_rec["purpose"], True, "ip-range",
                        f"{client_ip} in {d_name}'s published ranges")
    return Identity(d_name, d_rec["purpose"], False, "declared-only",
                    f"claims {d_name} but {client_ip} is outside its ranges and unsigned")
