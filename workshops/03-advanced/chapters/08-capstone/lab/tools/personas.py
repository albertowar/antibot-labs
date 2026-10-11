"""
Chapter 9 — Who the legitimate users are (Section 9.7, "Measuring both sides")

Forty simulated customers. The mix is chosen to contain the people
antibot defenses hurt in production, not an average day's traffic:

    persona         n  profile         why they are here
    chrome-win      8  chrome-win      the majority case
    chrome-mac      4  chrome-mac
    firefox-linux   4  firefox-linux
    safari-ios      5  safari-ios      touch only: no mouse path
    brave-win       2  brave-win       farbling: new canvas/cores/plugins every session
    firefox-rfp     2  firefox-rfp     resistFingerprinting: screen == window, 2 cores
    screen-reader   2  chrome-win      keyboard only: Tab, Tab, Enter
    vdi-citrix      2  vdi-citrix      software WebGL, just like a headless bot
    office-nat      7  office-win      7 identical laptops behind one office IP
    power-user      2  chrome-mac      knows the URL, buys in about 1.5 s
    new-laptop      1  chrome-mac      real customer on a device the store has never seen
    first-timer     1  firefox-linux   registers during the drop: a fresh account, like a bot's

All accounts, names, addresses and passwords are synthetic. Victim accounts
for the Round 4 credential-stuffing exercise are generated here as well, and
the combo list in attacks/data/ is derived from them.
"""

import hashlib
import random

PERSONAS = [
    {"name": "chrome-win", "count": 8, "profile": "chrome-win", "behavior": "mouse"},
    {"name": "chrome-mac", "count": 4, "profile": "chrome-mac", "behavior": "mouse"},
    {"name": "firefox-linux", "count": 4, "profile": "firefox-linux", "behavior": "mouse"},
    {"name": "safari-ios", "count": 5, "profile": "safari-ios", "behavior": "touch"},
    {"name": "brave-win", "count": 2, "profile": "brave-win", "behavior": "mouse"},
    {"name": "firefox-rfp", "count": 2, "profile": "firefox-rfp", "behavior": "mouse"},
    {"name": "screen-reader", "count": 2, "profile": "chrome-win", "behavior": "keyboard"},
    {"name": "vdi-citrix", "count": 2, "profile": "vdi-citrix", "behavior": "mouse"},
    {"name": "office-nat", "count": 7, "profile": "office-win", "behavior": "mouse", "egress": "203.0.113.10"},
    {"name": "power-user", "count": 2, "profile": "chrome-mac", "behavior": "fast"},
    {"name": "new-laptop", "count": 1, "profile": "chrome-mac", "behavior": "mouse", "new_device": True},
    {"name": "first-timer", "count": 1, "profile": "firefox-linux", "behavior": "mouse", "register": True},
]

FIRST = ["maria", "james", "aisha", "chen", "lucas", "sofia", "omar", "emma", "ravi", "noah", "yuki", "elena",
         "kofi", "anna", "diego", "fatima", "liam", "mei", "jonas", "zara", "pablo", "ines", "tomas", "leila"]
LAST = ["lopez", "smith", "khan", "wang", "silva", "rossi", "haddad", "brown", "patel", "jones", "tanaka",
        "petrova", "mensah", "novak", "garcia", "ali", "murphy", "lin", "berg", "ahmed", "costa", "dubois"]
STREETS = ["Maple", "Cedar", "Harbor", "Hillcrest", "Lake", "Willow", "Orchard", "Station", "Bridge", "Mill"]
CITIES = ["Portland OR 97205", "Austin TX 78701", "Columbus OH 43215", "Raleigh NC 27601", "Denver CO 80202",
          "Madison WI 53703", "Tucson AZ 85701", "Albany NY 12207"]


# The account your own captured profile (tools/profiles/mine.json) logs in with.
MINE_USER = {"persona": "mine", "index": 0, "email": "you@customers.example", "password": "pw-you-lab-capture",
             "address": "1 Capture Way, Portland OR 97205", "age_days": 400, "prior_orders": 2, "register": False}


def device_id(email):
    """The device cookie each customer's own browser already holds."""
    return hashlib.sha256(f"device:{email}".encode()).hexdigest()[:32]


def _person(rng, used):
    while True:
        first, last = rng.choice(FIRST), rng.choice(LAST)
        email = f"{first}.{last}" + (str(rng.randint(70, 99)) if rng.random() < 0.25 else "")
        if email not in used:
            used.add(email)
            return first, last, f"{email}@customers.example"


def legit_users():
    """Deterministic customer accounts, one per simulated user (first-timers register live)."""
    rng = random.Random(2026)
    used, users, n = set(), [], 0
    for persona in PERSONAS:
        for i in range(persona["count"]):
            n += 1
            _, _, email = _person(rng, used)
            users.append({
                "persona": persona["name"], "index": i, "email": email,
                "password": f"pw-{hashlib.sha256(email.encode()).hexdigest()[:10]}",
                "address": f"{100 + n * 7} {rng.choice(STREETS)} St, {rng.choice(CITIES)}",
                "age_days": rng.randint(45, 1800), "prior_orders": rng.randint(1, 6),
                "register": persona.get("register", False),
            })
    return users


def victims():
    """Aged accounts for Round 4. Ten of them reuse a password that is in the breach list."""
    rng = random.Random(404)
    used, out = set(), []
    for n in range(40):
        _, _, email = _person(rng, used)
        email = email.replace("@customers.example", "@mail.example")
        real = f"pw-{hashlib.sha256(('victim' + email).encode()).hexdigest()[:10]}"
        reused = n % 4 == 0
        breached = real if reused else f"{rng.choice(FIRST).capitalize()}{rng.randint(1980, 2009)}!"
        out.append({"email": email, "password": real, "breach_password": breached, "reused": reused,
                    "address": f"{200 + n * 3} {rng.choice(STREETS)} Ave, {rng.choice(CITIES)}",
                    "age_days": rng.randint(200, 2500), "prior_orders": rng.randint(2, 9)})
    return out


def combo_list():
    """email:password lines as a stuffer would buy them: 40 victims + 20 addresses that never existed."""
    rng = random.Random(77)
    lines = [f"{v['email']}:{v['breach_password']}" for v in victims()]
    for n in range(20):
        lines.append(f"{rng.choice(FIRST)}{rng.randint(100, 999)}@mail.example:"
                     f"{rng.choice(LAST).capitalize()}{rng.randint(10, 99)}")
    rng.shuffle(lines)
    return lines


if __name__ == '__main__':
    users = legit_users()
    print(f"{len(users)} legitimate users across {len(PERSONAS)} personas")
    print(f"{sum(v['reused'] for v in victims())}/{len(victims())} victims reuse a breached password")
