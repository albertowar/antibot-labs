"""
W3 Ch1 — The Lab Runner app SDK (and the attacker's copy of it)

In this lab the genuine mobile app and the attacker's tooling are the SAME
client code, because a reverse engineer who has beaten certificate pinning and
watched the traffic rebuilds exactly this. tools/legit_traffic.py drives it as
the honest app; the round scripts drive it as the attacker.

MobileApp does the real app's flow:
    1. GET /api/mobile/nonce                      (a single-use server challenge)
    2. compute requestHash over the buy body
    3. mint a provider attestation bound to (nonce, requestHash)    [mobile_core]
    4. POST /api/mobile/buy with X-Attest + Authorization

The knobs are how each round deviates from that honest flow:
    attest=False        send no attestation            (Round 1 faithful replay)
    replay_token=...    resend a lifted genuine verdict (Round 3)
    device="emulator"   the honest verdict of a farmed device (Round 4)

Nothing here forges a verdict: mint() is the provider, and it only stamps the
honest verdict for the device you actually pass. See defenses/mobile_core.py.
"""

import json
import os
import sys

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "defenses"))
import mobile_core  # noqa: E402

from _common import target  # noqa: E402

APP_UA = f"LabRunner/{mobile_core.APP_VERSION} (Android 14; Pixel 8) okhttp/4.12.0"


class MobileApp:
    def __init__(self, base=None, device="pixel8", serial="", egress=None, ua=APP_UA, device_id=None):
        self.base = target() if base is None else base
        self.device = device
        self.serial = serial
        self.bearer = None
        headers = {"User-Agent": ua, "X-App-Id": mobile_core.APP_ID,
                   "X-Lab-Device": device_id or mobile_core.device_id(device, serial)}
        if egress:
            headers["X-Lab-Egress"] = egress
        self.http = httpx.Client(base_url=self.base, headers=headers, verify=False, timeout=15)

    # -- honest app steps -------------------------------------------------
    def login(self, email, password):
        r = self.http.post("/api/mobile/login", json={"email": email, "password": password})
        if r.status_code == 200:
            self.bearer = r.json()["token"]
        return r

    def register(self, ident):
        r = self.http.post("/api/mobile/register", json=ident)
        if r.status_code == 200:
            self.bearer = r.json()["token"]
        return r

    def _nonce(self):
        return self.http.get("/api/mobile/nonce").json()["nonce"]

    def mint_buy(self, sku="lab-runner-9"):
        """Build (token, body) for a genuine, bound, fresh buy — what MitM would capture."""
        body = json.dumps({"sku": sku}, separators=(",", ":")).encode()
        req_hash = mobile_core.request_hash("POST", "/api/mobile/buy", body)
        token = mobile_core.mint(self.device, self.serial, self._nonce(), req_hash)
        return token, body

    def _post_buy(self, body, token):
        headers = {"Content-Type": "application/json"}
        if self.bearer:
            headers["Authorization"] = f"Bearer {self.bearer}"
        if token is not None:
            headers["X-Attest"] = token
        return self.http.post("/api/mobile/buy", content=body, headers=headers)

    def buy(self, sku="lab-runner-9", attest=True, replay_token=None):
        """
        attest=True, replay_token=None  -> the honest flow (fresh bound verdict)
        attest=False                    -> no attestation at all (Round 1/2)
        replay_token=<token>            -> resend a captured verdict (Round 3)
        """
        if replay_token is not None:
            body = json.dumps({"sku": sku}, separators=(",", ":")).encode()
            return self._post_buy(body, replay_token)
        if not attest:
            body = json.dumps({"sku": sku}, separators=(",", ":")).encode()
            return self._post_buy(body, None)
        token, body = self.mint_buy(sku)
        return self._post_buy(body, token)

    def close(self):
        self.http.close()


def outcome_of(response):
    """Normalize a buy response into (outcome, bought, reasons)."""
    try:
        data = response.json()
    except Exception:
        return "error", False, [f"HTTP {response.status_code}"]
    outcome = data.get("outcome", "error")
    bought = response.status_code == 200 and outcome == "allow"
    return outcome, bought, data.get("reasons", [data.get("message", "")])


def forge_token(profile="pixel8"):
    """
    What a Round 2 attacker tries: mint a 'strong integrity' verdict with a key
    they control, hoping the server does not really check the signature. The
    provider's public key will NOT validate it, so mobile_core.verify() returns
    None. This is why beating certificate pinning is not enough on its own.
    """
    import base64, json, time
    from cryptography.hazmat.primitives import hashes, serialization
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
