"""
Chapter 8: The demo store's synthetic user table

300 customers, user000@example.test ... user299@example.test, plus
mallory@example.test, an account the attacker registered legitimately to
calibrate their bot (Round 2). Every password is generated from a fixed
seed, so the population simulator (playing the real customers) can "remember"
its own password. None of this is real data.

Passwords are stored as salted PBKDF2-SHA256 with a deliberately low
iteration count so the lab stays fast. In production use Argon2id or
scrypt with the current OWASP parameters, and remember that every login
attempt, including the ones you are about to block, costs one of these.
"""

import hashlib
import hmac
import random

SEED = 808
N_USERS = 300
ITERATIONS = 5_000  # lab only
WORDS = ["amber", "basil", "cedar", "delta", "ember", "fjord", "gamma", "harbor", "indigo",
         "juniper", "kestrel", "lumen", "maple", "nectar", "onyx", "pepper", "quartz",
         "raven", "saffron", "tundra", "umber", "violet", "willow", "zephyr"]


def username(i):
    return f"user{i:03d}@example.test"


def password(i):
    rng = random.Random(SEED * 1000 + i)
    return f"{rng.choice(WORDS)}-{rng.choice(WORDS)}-{rng.randint(10, 99)}"


ATTACKER_ACCOUNT = ("mallory@example.test", "mallory-owns-this-1")


def _hash(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITERATIONS)


def build():
    table = {}
    for i in range(N_USERS):
        salt = f"salt{i}".encode()
        table[username(i)] = (salt, _hash(password(i), salt))
    salt = b"salt-mallory"
    table[ATTACKER_ACCOUNT[0]] = (salt, _hash(ATTACKER_ACCOUNT[1], salt))
    return table


_DUMMY = (b"salt-dummy", _hash("dummy", b"salt-dummy"))


def check(table, user, pw):
    """Return "valid", "wrong_password" or "unknown_user", in constant-ish time."""
    salt, expected = table.get(user, _DUMMY)
    ok = hmac.compare_digest(_hash(pw, salt), expected)
    if user not in table:
        return "unknown_user"
    return "valid" if ok else "wrong_password"
