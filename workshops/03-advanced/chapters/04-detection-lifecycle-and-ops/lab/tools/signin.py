"""
One sign-in, the way the page's script does it (static/js/risk.js), for customers and bots alike.

    GET /login  ->  POST /api/telemetry {kind: "risk"}  ->  POST /api/login  ->  any challenge that
    comes back (solve the proof of work; read the emailed code from /lab/mailbox/<email>)  ->  the
    same login again

Every simulated visit goes through `sign_in`, so a customer and a bot are told apart by what they
*send*, never by how they are driven. What differs is the client's means: a real customer owns the
mailbox and answers a step-up, a credential stuffer does not (`owns_mailbox=False`) and is stuck.

`OpsClient` adds the lab calendar. `tools/weeks.py` replays five weeks in a few minutes, and the
store's edge drops every `X-Lab-*` request header except the three it documents, so the calendar
travels in `Lab-Week` / `Lab-Clock` (demo_site/ext/ops.py reads and removes them). They go to the
decision log and the containment TTL, and nowhere else.
"""

import hashlib
import time

from labclient import LabClient  # (labclient runs the labnet localhost guard on import)


def leading_zero_bits(digest):
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + 8 - byte.bit_length()
    return bits


def solve_pow(prefix, bits):
    """What the page's WebCrypto loop does."""
    nonce = 0
    while leading_zero_bits(hashlib.sha256(f"{prefix}:{nonce}".encode()).digest()) < bits:
        nonce += 1
    return str(nonce)


class OpsClient(LabClient):
    """A LabClient that stamps every request with the lab calendar."""

    def __init__(self, actor, ip=None, week=0, clock=0, **kw):
        super().__init__(actor, ip=ip, **kw)
        self.week, self.clock = week, clock

    def request(self, method, path, headers=(), **kw):
        headers = list(headers) + [("Lab-Week", str(self.week)), ("Lab-Clock", str(int(self.clock)))]
        return super().request(method, path, headers, **kw)


def gate_ms(response):
    for part in response.headers.get("Server-Timing", "").split(","):
        name, _, dur = part.strip().partition(";dur=")
        if name == "gate" and dur:
            return float(dur)
    return None


def answer(client, headers, email, kind, payload, owns_mailbox, res):
    """What a client does with a challenge. True if the answer verified."""
    if kind == "pow":
        started = time.perf_counter()
        nonce = solve_pow(payload["prefix"], payload["bits"])
        res["pow_ms"] = res.get("pow_ms", 0.0) + (time.perf_counter() - started) * 1000
        body = {"type": "pow", "answer": {"nonce": nonce}}
    else:
        code = "000000"                              # a stuffer cannot read the victim's inbox: it guesses
        if owns_mailbox:
            mail = client.get(f"/lab/mailbox/{email}").json()["messages"]
            codes = [m["code"] for m in mail if "code" in m]
            code = codes[-1] if codes else code
        body = {"type": "step_up", "answer": {"code": code}}
    return client.post("/api/challenge/verify", json=body, headers=headers).status_code == 200


def sign_in(client, headers, email, password, fp, mouse, keys, pointer="mouse", owns_mailbox=True,
            website="", telemetry=True):
    """Play the page. Returns a result dict:
        status     the last HTTP status (200 signed in, 401 'wrong password' or a deceptive block, 403 stopped)
        challenge  the first rung met ("pow" | "step_up" | "")
        stuck      the client could not complete a challenge
        pow_ms     CPU spent on proofs of work (Python; a browser's WebCrypto is faster)
        gate_ms    the gate time of the first POST /api/login (the defender's cost)
    """
    res = {"challenge": "", "stuck": False, "pow_ms": 0.0, "gate_ms": None}
    client.get("/login", headers)
    if telemetry:
        client.post("/api/telemetry", json={"kind": "risk", "fp": fp, "behavior": {
            "mouse": mouse, "keys": keys, "pointer_type": pointer}}, headers=headers)
    body = {"email": email, "password": password, "website": website}
    r = client.post("/api/login", json=body, headers=headers)
    res["gate_ms"] = gate_ms(r)
    for _ in range(2):
        err = (r.json().get("error") or {}) if r.status_code == 403 else {}
        if err.get("code") != "challenge_required":
            break
        res["challenge"] = res["challenge"] or err["challenge"]
        if not answer(client, headers, email, err["challenge"], err["payload"], owns_mailbox, res):
            res["stuck"] = True
            break
        r = client.post("/api/login", json=body, headers=headers)
    res["status"], res["verdict"] = r.status_code, client.verdict()
    return res
