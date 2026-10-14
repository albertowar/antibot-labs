"""
Round 3 attack: infostealer log replay.

Credential stuffing tests LEAKED passwords, so the breached-password screen kills it. This attack
sidesteps that entirely: it uses credentials an infostealer lifted straight from the victim's
browser. They are correct, current and have never appeared in any breach corpus, so the screen
sees nothing. The malware also grabbed the victim's device cookie (`did`), which the attacker
replays. The one thing it cannot copy is the victim's network.

Setup (not the attack): each of the 10 victims signs in from home on their usual device, so the
store has a history for the account. The "stealer log" is then what the malware copied from that
browser: the email, the password and the device id.

Against Round 3 this walks straight in. Against Round 4's device and network check it is stopped:
the login arrives over an ASN the account has never used and a step-up code goes to the victim's
inbox, not to the attacker.

    python attacks/round3_stealer_log_replay.py
"""

from _common import LabClient, is_success, login, password_for, report, username, victim_signs_in, world_pool

ACTOR = "bot:stealer"
VICTIMS = range(200, 210)


def run():
    home, hosting = world_pool("home_fiber"), world_pool("hosting_asn")
    hits = []
    for n, i in enumerate(VICTIMS):
        victim = victim_signs_in(i, home[n])
        stolen_did = victim.http.cookies.get("did")                  # what the malware copied
        attacker = LabClient(ACTOR, ip=hosting[n])
        attacker.set_cookie("did", stolen_did)
        if is_success(login(attacker, username(i), password_for(i))):
            hits.append(username(i))
    return {"attacker": ACTOR, "attempted": len(VICTIMS), "succeeded": len(hits), "accounts_taken_over": len(hits)}


if __name__ == "__main__":
    out = run()
    print(f"[{ACTOR}] {out['attempted']} stolen credentials -> {out['accounts_taken_over']} accounts taken over")
    report(**out)
