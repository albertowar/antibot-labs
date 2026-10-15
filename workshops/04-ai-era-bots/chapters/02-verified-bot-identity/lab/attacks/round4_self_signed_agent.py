"""Round 4 attack (a): be your own certificate authority.

Web Bot Auth has no central registry. An agent publishes its keys at
https://<its origin>/.well-known/http-message-signatures-directory and signs requests with
Signature-Agent pointing there. The attacker owns attacker.example, so it publishes a perfectly
valid, correctly self-signed directory (to the mock's hosting panel) and signs every request
correctly, with a fresh nonce and a short window. The signature *is* valid. The question the
verifier must ask is a different one: do we trust this origin?

Expected: L4 -> the whole catalogue in the verified lane (valid signature, naive policy). L5 -> held
to the anonymous lane ("valid signature from untrusted origin: identity noted, no entitlement").

    python attacks/round4_self_signed_agent.py
"""

from __future__ import annotations

from _common import UA, attacker_ip, authority, catalog_paths, finish, key_of, mock, report, scrape, httpsig

ORIGIN = "https://attacker.example"


def publish_directory(priv, jwk: dict, kid: str) -> None:
    jwks = {"keys": [jwk]}
    mock("PUT", "/hosting/directory", json={"host": "attacker.example", "jwks": jwks,
                                            "headers": httpsig.sign_directory(jwks, {kid: priv}, "attacker.example")})


def run() -> dict:
    priv, jwk, kid = key_of("attacker.example")
    publish_directory(priv, jwk, kid)
    host = authority()

    def sign(path: str) -> list:
        ctx = httpsig.MessageContext("GET", host, path, {"user-agent": UA["AcmeShoppingAgent"]})
        return list(httpsig.agent_headers(priv, kid, ORIGIN, ctx).items())

    return scrape("self-signed-agent", attacker_ip("self_signed"), UA["AcmeShoppingAgent"], catalog_paths(), sign)


if __name__ == "__main__":
    print("=== Round 4a: publish our own key directory, sign every request correctly ===")
    out = run()
    report("Signature-Agent attacker.example", out)
    finish(out)
