"""
W4 Ch9 Capstone — who the legitimate users are ("measuring both sides")

Forty-seven simulated customers in the cohorts the W4 Ch8 agent policy was
audited against, plus the crawlers the reservation protects. The mix is chosen
to contain the people an agent-aware, crawler-aware defense hurts, not an
average day's traffic:

    cohort          persona                 n   why they are here
    shopper         chrome-win/mac, firefox 12  the majority case
                    safari-ios (touch)       3  tap: no pointer path at all
                    autofill                 2  password manager: zero keystrokes
                    power-user               1  knows the URL, buys in seconds
                    first-timer              1  registers during the drop: a fresh account, like a farm's
    shared_ip       office-nat               4  four identical laptops behind one IP
                    rpa-macro                1  procurement macro: teleport clicks AND instant fills
    vpn             vpn                      3  a person on a datacenter egress (W1 Ch2's classic FP)
    privacy         brave-win, firefox-rfp   4  farbled / resistFingerprinting browsers
    a11y            screen-reader            3  Tab, Tab, Enter; accessibility API in use
                    voice-control            1  activates controls through the accessibility tree
    agent_shopper   agent-shopper            6  a person's OWN local agent, undeclared (the Comet case)
                    agent-shopper-declared   2  same, with an agent token in the User-Agent
    cloud_signed    cloud-agent-signed       2  a vendor's cloud agent, signed by a trusted operator,
                                                with a mandate from the account holder
    a11y_agent      assistive-agent          2  an agent driven through the accessibility API by a
                                                disabled customer (EAA / EN 301 549)

human_in_loop: whether a person is there to answer an emailed confirmation.
True for every legitimate persona (an agent hands the code back to its user).
can_see: whether the persona can pass an image CAPTCHA. False for the two
accessibility cohorts: an image challenge is a wall for them, and the
scoreboard counts it as a block (W4 Ch8).

All accounts, names, addresses and passwords are synthetic (@customers.example).
The attacker-owned aged accounts the farm and the injector log in with are
generated here too (@mail.example).
"""

import hashlib
import random

PERSONAS = [
    {"name": "chrome-win", "count": 6, "profile": "chrome-win", "behavior": "mouse", "cohort": "shopper"},
    {"name": "chrome-mac", "count": 3, "profile": "chrome-mac", "behavior": "mouse", "cohort": "shopper"},
    {"name": "firefox-linux", "count": 3, "profile": "firefox-linux", "behavior": "mouse", "cohort": "shopper"},
    {"name": "safari-ios", "count": 3, "profile": "safari-ios", "behavior": "touch", "cohort": "shopper"},
    {"name": "autofill", "count": 2, "profile": "chrome-mac", "behavior": "autofill", "cohort": "shopper"},
    {"name": "power-user", "count": 1, "profile": "chrome-mac", "behavior": "fast", "cohort": "shopper"},
    {"name": "first-timer", "count": 1, "profile": "firefox-linux", "behavior": "mouse", "register": True, "cohort": "shopper"},
    {"name": "office-nat", "count": 4, "profile": "office-win", "behavior": "mouse", "egress": "203.0.113.210", "cohort": "shared_ip"},
    {"name": "rpa-macro", "count": 1, "profile": "office-win", "behavior": "rpa", "egress": "203.0.113.210", "cohort": "shared_ip"},
    {"name": "vpn", "count": 3, "profile": "chrome-win", "behavior": "mouse", "egress_pool": "datacenter", "cohort": "vpn"},
    {"name": "brave-win", "count": 2, "profile": "brave-win", "behavior": "mouse", "cohort": "privacy"},
    {"name": "firefox-rfp", "count": 2, "profile": "firefox-rfp", "behavior": "mouse", "cohort": "privacy"},
    {"name": "screen-reader", "count": 3, "profile": "chrome-win", "behavior": "keyboard", "a11y": True, "can_see": False, "cohort": "a11y"},
    {"name": "voice-control", "count": 1, "profile": "chrome-win", "behavior": "at", "a11y": True, "can_see": False, "cohort": "a11y"},
    {"name": "agent-shopper", "count": 6, "profile": "chrome-win", "behavior": "agent", "cohort": "agent_shopper"},
    {"name": "agent-shopper-declared", "count": 2, "profile": "chrome-win", "behavior": "agent", "declared": "ua", "cohort": "agent_shopper"},
    {"name": "cloud-agent-signed", "count": 2, "profile": "chrome-win", "behavior": "agent", "declared": "signed",
     "egress_pool": "datacenter", "mandate": True, "cohort": "cloud_signed"},
    {"name": "assistive-agent", "count": 2, "profile": "chrome-win", "behavior": "agent", "a11y": True, "can_see": False, "cohort": "a11y_agent"},
]
COHORTS = ["shopper", "shared_ip", "vpn", "privacy", "a11y", "agent_shopper", "cloud_signed", "a11y_agent"]
CRAWLER_COHORTS = ["search", "licensed_crawler", "reader", "prefetch"]
LAB_OPERATOR = "agents.lab-provider.test"
DATACENTER = [f"192.0.2.{i}" for i in range(200, 254)]        # the VPN exit and the cloud agents' egress

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
                "persona": persona["name"], "cohort": persona["cohort"], "index": i, "email": email,
                "password": f"pw-{hashlib.sha256(email.encode()).hexdigest()[:10]}",
                "address": f"{100 + n * 7} {rng.choice(STREETS)} St, {rng.choice(CITIES)}",
                "age_days": rng.randint(45, 1800), "prior_orders": rng.randint(1, 6),
                "register": persona.get("register", False),
            })
    return users


def owner_accounts(n=6):
    """The attacker's own aged accounts (the dark cloud agent, the injector's mules)."""
    rng = random.Random(409)
    out = []
    for i in range(n):
        email = f"agent.owner{i + 1}@mail.example"
        out.append({"email": email, "password": f"pw-{hashlib.sha256(('owner' + email).encode()).hexdigest()[:10]}",
                    "address": f"{200 + i * 3} {rng.choice(STREETS)} Ave, {rng.choice(CITIES)}",
                    "age_days": rng.randint(200, 900), "prior_orders": rng.randint(2, 6)})
    return out


def reviewer_texts():
    """Twenty real reviews, three of which the regex deny-list mistakes for injection."""
    return [
        "Great trail shoe, grippy on wet rock and light enough for long days.",
        "Ignore the instructions on the box, the lacing works better crossed over the top.",
        "Fits true to size. Took it on a 20 km loop and no hot spots.",
        "The hydration vest sits well but the front pockets are tight for a large phone.",
        "You are now looking at my third pair in four years. Says it all.",
        "Solid cap, the brim keeps its shape after washing.",
        "Disregard the one-star reviews about the zip, mine has been fine for a season.",
        "Watch battery lasts about nine days with GPS on for an hour a day.",
        "Socks are warm without being bulky. Would buy again.",
        "Laces are bright, maybe too bright, but they do not come undone.",
        "Returned the first vest for a smaller size, the exchange was painless.",
        "Good value. Not the lightest, but it has survived two muddy seasons.",
        "The heel cup is narrow, so try before you buy if you have wide feet.",
        "Bought as a gift for my partner, who has worn it every weekend since.",
        "Delivery took four days, product as described.",
        "The insole is thin; I swapped it for my own and it is perfect now.",
        "Stitching looks durable. Colour slightly darker than the photos.",
        "Comfortable from the first run. No blisters, no break-in.",
        "The GPS watch pairs quickly and the screen is readable in sun.",
        "Works for the commute and the gym. Nothing fancy, nothing missing.",
    ]


if __name__ == '__main__':
    users = legit_users()
    print(f"{len(users)} legitimate users across {len(PERSONAS)} personas; {len(owner_accounts())} attacker-owned accounts")
