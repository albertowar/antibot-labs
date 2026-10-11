"""
W4 Ch4 — Who the legitimate users are ("measuring both sides")

Forty simulated customers. The mix is chosen to contain the people an
agent-aware defense hurts, not an average day's traffic:

    persona         n  input        why they are here
    chrome-win      9  mouse        the majority case
    chrome-mac      4  mouse
    firefox-linux   4  mouse
    brave-win       2  mouse        farbling: new canvas / cores every session
    firefox-rfp     2  mouse        resistFingerprinting: screen == window
    office-nat      6  mouse        six identical laptops behind one office IP
    safari-ios      3  touch        tap: no pointer path at all
    screen-reader   2  keyboard     Tab, Tab, Enter: clicks arrive with detail 0, no pointer path
    voice-control   1  at           activates controls through the accessibility tree: detail 0, no keys
    autofill        2  autofill     password manager fills the login with zero keystrokes
    rpa-macro       1  rpa          a procurement macro: teleport clicks AND instant fills. The honest FP.
    power-user      1  fast         knows the URL, buys in seconds
    first-timer     1  mouse        registers during the drop: a fresh account, like a fleet's
    agent-user      2  agent-user   a person whose OWN agent (declared, signed by its operator) buys
                                    for them, with a mandate once the store supports one

All accounts, names, addresses and passwords are synthetic (@customers.example).
The five attacker-owned accounts the Round 1–3 agent logs in with are generated
here too (@mail.example), so the attack scripts never need a real identity.
"""

import hashlib
import random

PERSONAS = [
    {"name": "chrome-win", "count": 9, "profile": "chrome-win", "behavior": "mouse"},
    {"name": "chrome-mac", "count": 4, "profile": "chrome-mac", "behavior": "mouse"},
    {"name": "firefox-linux", "count": 4, "profile": "firefox-linux", "behavior": "mouse"},
    {"name": "brave-win", "count": 2, "profile": "brave-win", "behavior": "mouse"},
    {"name": "firefox-rfp", "count": 2, "profile": "firefox-rfp", "behavior": "mouse"},
    {"name": "office-nat", "count": 6, "profile": "office-win", "behavior": "mouse", "egress": "203.0.113.10"},
    {"name": "safari-ios", "count": 3, "profile": "safari-ios", "behavior": "touch"},
    {"name": "screen-reader", "count": 2, "profile": "chrome-win", "behavior": "keyboard"},
    {"name": "voice-control", "count": 1, "profile": "chrome-win", "behavior": "at"},
    {"name": "autofill", "count": 2, "profile": "chrome-mac", "behavior": "autofill"},
    {"name": "rpa-macro", "count": 1, "profile": "office-win", "behavior": "rpa", "egress": "203.0.113.10"},
    {"name": "power-user", "count": 1, "profile": "chrome-mac", "behavior": "fast"},
    {"name": "first-timer", "count": 1, "profile": "firefox-linux", "behavior": "mouse", "register": True},
    {"name": "agent-user", "count": 2, "profile": "chrome-win", "behavior": "agent-user"},
]
HUMAN_PERSONAS = {p["name"] for p in PERSONAS if p["name"] != "agent-user"}
LAB_OPERATOR = "agents.lab-provider.test"

FIRST = ["maria", "james", "aisha", "chen", "lucas", "sofia", "omar", "emma", "ravi", "noah", "yuki", "elena",
         "kofi", "anna", "diego", "fatima", "liam", "mei", "jonas", "zara", "pablo", "ines", "tomas", "leila"]
LAST = ["lopez", "smith", "khan", "wang", "silva", "rossi", "haddad", "brown", "patel", "jones", "tanaka",
        "petrova", "mensah", "novak", "garcia", "ali", "murphy", "lin", "berg", "ahmed", "costa", "dubois"]
STREETS = ["Maple", "Cedar", "Harbor", "Hillcrest", "Lake", "Willow", "Orchard", "Station", "Bridge", "Mill"]
CITIES = ["Portland OR 97205", "Austin TX 78701", "Columbus OH 43215", "Raleigh NC 27601", "Denver CO 80202",
          "Madison WI 53703", "Tucson AZ 85701", "Albany NY 12207"]


def device_id(email):
    """The device cookie each customer's own browser already holds."""
    return hashlib.sha256(f"device:{email}".encode()).hexdigest()[:32]


def _person(rng, used):
    while True:
        first, last = rng.choice(FIRST), rng.choice(LAST)
        email = f"{first}.{last}" + (str(rng.randint(70, 99)) if rng.random() < 0.25 else "")
        if email not in used:
            used.add(email)
            return f"{email}@customers.example"


def legit_users():
    """Deterministic customer accounts, one per simulated user (the first-timer registers live)."""
    rng = random.Random(2026)
    used, users, n = set(), [], 0
    for persona in PERSONAS:
        for i in range(persona["count"]):
            n += 1
            email = _person(rng, used)
            users.append({
                "persona": persona["name"], "index": i, "email": email,
                "password": f"pw-{hashlib.sha256(email.encode()).hexdigest()[:10]}",
                "address": f"{100 + n * 7} {rng.choice(STREETS)} St, {rng.choice(CITIES)}",
                "age_days": rng.randint(45, 1800), "prior_orders": rng.randint(1, 6),
                "register": persona.get("register", False),
            })
    return users


def owner_accounts(n=5):
    """The attacker's own aged accounts for Rounds 1–3 (an agent buys for 'its user')."""
    rng = random.Random(404)
    out = []
    for i in range(n):
        email = f"agent.owner{i + 1}@mail.example"
        out.append({"email": email, "password": f"pw-{hashlib.sha256(('owner' + email).encode()).hexdigest()[:10]}",
                    "address": f"{200 + i * 3} {rng.choice(STREETS)} Ave, {rng.choice(CITIES)}",
                    "age_days": rng.randint(200, 900), "prior_orders": rng.randint(2, 6)})
    return out


if __name__ == '__main__':
    users = legit_users()
    print(f"{len(users)} legitimate users across {len(PERSONAS)} personas; {len(owner_accounts())} attacker-owned accounts")
