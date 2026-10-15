"""
The Lab Runner app SDK (and the attacker's copy of it).

In this lab the genuine mobile app and the attacker's tooling are the SAME client code, because a reverse
engineer who has beaten certificate pinning and watched the traffic rebuilds exactly this. The shoppers in
tools/personas_ch1.py drive it as the honest app; the round scripts in attacks/ drive it as the attacker.

MobileApp does the real app's flow:
    1. GET  /api/mobile/nonce                      (a single-use server challenge)
    2. compute requestHash over the exact buy body
    3. mint a provider attestation bound to (nonce, requestHash)         [defenses/mobile_core.py]
    4. POST /api/mobile/buy with X-Attest and the bearer token

The knobs are how each round deviates from that honest flow:
    attest=False        send no attestation              (Rounds 1-2: the faithful replay)
    replay_token=...    resend a lifted genuine verdict  (Round 3)
    device="emulator"   the honest verdict of a farmed device (Round 4)

Nothing here forges a verdict: mint() is the provider, and it only stamps the honest verdict of the device
profile you pass. forge_token() is what Round 2's attacker TRIES with a key of their own; the provider's
public key does not validate it.

It sits on tools/labclient.py: ordered headers, a rented source address from data/world.json, a scoreboard
label, and the claimed JA4 (X-Lab-JA4), so the localhost guard and the lab edge apply to it like to any actor.
"""

import base64
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

from labclient import LabClient  # noqa: E402  (also runs the labnet guard)
from defenses import mobile_core  # noqa: E402

DROP_SKU = "lab-runner-9"
APP_UA = mobile_core.APP_UA


class MobileApp:
    def __init__(self, actor, device="pixel8", serial="", ip=None, ua=APP_UA, ja4=mobile_core.APP_JA4):
        self.device, self.serial, self.ua = device, serial, ua
        self.client = LabClient(actor, ip=ip, ja4=ja4)
        self.bearer = None

    def _headers(self, extra=()):
        headers = [("User-Agent", self.ua), ("X-App-Id", mobile_core.APP_ID), ("Accept", "application/json")]
        if self.bearer:
            headers.append(("Authorization", f"Bearer {self.bearer}"))
        return headers + list(extra)

    # -- honest app steps -------------------------------------------------
    def login(self, email, password):
        r = self.client.post("/api/mobile/login", json={"email": email, "password": password}, headers=self._headers())
        if r.status_code == 200:
            self.bearer = r.json()["token"]
        return r

    def register(self, ident):
        r = self.client.post("/api/mobile/register", json=ident, headers=self._headers())
        if r.status_code == 201:
            self.bearer = r.json()["token"]
        return r

    def nonce(self):
        return self.client.get("/api/mobile/nonce", headers=self._headers()).json()["nonce"]

    @staticmethod
    def buy_body(sku=DROP_SKU):
        return json.dumps({"sku": sku}, separators=(",", ":")).encode()

    def mint_buy(self, sku=DROP_SKU):
        """(token, body) for a genuine, bound, fresh buy: what a MitM proxy would capture off the wire."""
        body = self.buy_body(sku)
        req_hash = mobile_core.request_hash("POST", "/api/mobile/buy", body)
        return mobile_core.mint(self.device, self.serial, self.nonce(), req_hash), body

    def post_buy(self, body, token):
        extra = [("Content-Type", "application/json")] + ([("X-Attest", token)] if token else [])
        return self.client.post("/api/mobile/buy", data=body, headers=self._headers(extra))

    def buy(self, sku=DROP_SKU, attest=True, replay_token=None):
        """
        default                -> the honest flow (fresh bound verdict)
        attest=False           -> no attestation at all (Rounds 1-2)
        replay_token=<token>   -> resend a captured or forged verdict on this body (Rounds 2-3)
        """
        if replay_token is not None:
            return self.post_buy(self.buy_body(sku), replay_token)
        if not attest:
            return self.post_buy(self.buy_body(sku), None)
        token, body = self.mint_buy(sku)
        return self.post_buy(body, token)

    # -- what happened -----------------------------------------------------
    def result(self):
        """The last response as {outcome, bought, status, score, signals}. Reads the gate's X-Lab-* answer."""
        r = self.client.last
        verdict, score, signals = self.client.verdict()
        if r.status_code == 201:
            outcome = "bought"
        elif verdict == "challenge":
            outcome = "challenged"       # the band is enforced as a refusal here: there is no step-up to pass
        elif r.status_code in (403, 429):
            outcome = "blocked"
        elif r.status_code in (409, 410):
            outcome = "refused"
        else:
            outcome = "error"
        return {"outcome": outcome, "bought": outcome == "bought", "status": r.status_code, "verdict": verdict,
                "score": int(score or 0), "signals": [s for s in (signals or "").split(",") if s]}


def forge_token(profile="pixel8"):
    """
    What a Round 2 attacker tries: mint a 'strong integrity' verdict with a key they control, hoping the server
    does not really check the signature. The provider's public key will NOT validate it, so
    mobile_core.verify() returns None and the attestation check sees no verdict.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())  # NOT the provider's key
    integrity, app_integrity, _ = mobile_core.DEVICE_PROFILES[profile]
    payload = {"appId": mobile_core.APP_ID, "appVersion": mobile_core.APP_VERSION,
               "deviceId": mobile_core.device_id(profile, "forged"),
               "deviceIntegrity": integrity, "appIntegrity": app_integrity,
               "nonce": None, "requestHash": None, "ts": int(time.time() * 1000)}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = key.sign(raw, ec.ECDSA(hashes.SHA256()))
    return base64.urlsafe_b64encode(raw).decode() + "." + base64.urlsafe_b64encode(sig).decode()
