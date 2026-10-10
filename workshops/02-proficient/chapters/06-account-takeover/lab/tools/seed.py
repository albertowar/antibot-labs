"""Seed every piece of synthetic data the lab needs. Deterministic (fixed seed).

Produces, under ``data/``:
  * shop.db            — 40 stuffable + 150 human + 10 victim accounts
  * combo_list.txt     — 2000 pairs: the 40 stuffable (correct) + 1960 junk
  * breach_ranges/     — offline HIBP-style k-anonymity corpus of breached passwords
  * legit_users.json   — the humans the simulator plays, with scenario tags
  * stealer_logs.json  — 10 victims' *fresh* (non-breached) creds + device cookie
  * stolen_sessions.json — valid signed session cookies for those 10 victims
  * device_history.json  — home device/ASN history the risk engine compares against

Everything is fictional. Emails use the reserved ``.shop`` demo domain, passwords
are invented, IPs are documentation/benchmark ranges only. No real data, ever.

Run once, from the lab root:  python tools/seed.py
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "demo_site"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

LAB = os.path.join(os.path.dirname(__file__), "..")
DATA = os.path.join(LAB, "data")
RANGES = os.path.join(DATA, "breach_ranges")

RNG = random.Random(20260310)

# Start from a clean store/level so seed-time logins succeed and cookies are valid.
os.environ["DEFENSE_LEVEL"] = "0"
os.environ.pop("USE_SOLUTIONS", None)

# A small pool of weak/breached passwords the stuffable accounts reuse.
BREACHED_POOL = [
    "password123", "qwerty2020", "letmein!", "sunshine1", "iloveyou2",
    "football99", "dragonfly7", "monkeybiz", "trustno1!", "welcome12",
    "hunter2hun", "baseball8", "shadow999", "master2021", "superman0",
    "princess5", "flower123", "whatever7", "ginger22x", "cookie888",
]
# Passwords for the breached subset of humans (also in the corpus).
HUMAN_BREACHED_POOL = ["summer2019", "liverpool4", "pokemon25", "chelsea10", "batman007"]

HOME_ASN = "64503"          # 192.0.2.0/24, residential
HOME_IP = "192.0.2.{}"      # distinct per user
CGNAT_IP = "100.64.1.1"     # one shared CGNAT address for the whole cohort
NEWDEV_IP = "198.19.{}.{}"  # travellers / new devices (disjoint from attacker pools)


def strong_pw(tag: str, i: int) -> str:
    return f"{tag.capitalize()}-{RNG.randint(1000,9999)}-{hashlib.md5(f'{tag}{i}'.encode()).hexdigest()[:6]}"


def sha1_upper(pw: str) -> str:
    return hashlib.sha1(pw.encode()).hexdigest().upper()


def write_breach_corpus(passwords: set[str]) -> None:
    """Write one file per 5-hex prefix: SUFFIX:COUNT, like the HIBP range API."""
    if os.path.isdir(RANGES):
        for f in os.listdir(RANGES):
            os.remove(os.path.join(RANGES, f))
    os.makedirs(RANGES, exist_ok=True)
    buckets: dict[str, list[str]] = {}
    for pw in passwords:
        d = sha1_upper(pw)
        buckets.setdefault(d[:5], []).append(d[5:])
    for prefix, suffixes in buckets.items():
        with open(os.path.join(RANGES, f"{prefix}.txt"), "w") as fh:
            for suf in suffixes:
                fh.write(f"{suf}:{RNG.randint(50, 90000)}\n")


def main() -> None:
    os.makedirs(DATA, exist_ok=True)
    from store import User, db  # imported after env is set
    import app as demo            # the Flask app (uses DEFENSE_LEVEL=0)
    from defenses.labhash import hash_pw

    with demo.app.app_context():
        db.drop_all()
        db.create_all()

        combo_valid: list[tuple[str, str]] = []
        breached_passwords: set[str] = set(BREACHED_POOL) | set(HUMAN_BREACHED_POOL)
        legit: list[dict] = []
        stealer: list[dict] = []
        history: dict[str, dict] = {}

        def add_user(uid, email, pw, breached, totp=False):
            secret = None
            if totp:
                import pyotp
                secret = pyotp.random_base32()
            db.session.add(User(id=uid, email=email, password_hash=hash_pw(pw),
                                totp_secret=secret, password_breached=breached))
            return secret

        # --- 40 stuffable accounts: breached password, present in the combo list -
        for i in range(40):
            email = f"stuffable{i:03d}@demo.shop"
            pw = BREACHED_POOL[i % len(BREACHED_POOL)]
            add_user(f"stf_{i:03d}", email, pw, breached=True)
            combo_valid.append((email, pw))

        # --- 150 human accounts the simulator plays -----------------------------
        def home_history(uid, did, asn=HOME_ASN):
            history[uid] = {"devices": [did], "asns": [asn], "sigs": [f"sig-{uid}"]}

        hi = 0

        def human(scenario, pw, breached, totp, ip, did, present_did, present_ip, present_sig,
                  home_asn=HOME_ASN):
            nonlocal hi
            uid, email = f"hum_{hi:03d}", f"human{hi:03d}@demo.shop"
            secret = add_user(uid, email, pw, breached=breached, totp=totp)
            home_history(uid, did, home_asn)  # the account's *real* home device/network
            legit.append({
                "email": email, "password": pw, "scenario": scenario,
                "ip": present_ip, "did": present_did, "sig": present_sig,
                "totp_secret": secret, "breached": breached,
            })
            hi += 1

        # 50 returning users: strong password, home device/network -> clean success
        for _ in range(50):
            did = f"dev-{hi:03d}"
            ip = HOME_IP.format(10 + hi % 200)
            human("returning", strong_pw("ret", hi), False, False, ip, did, did, ip, f"sig-hum_{hi:03d}")

        # 25 breached-password returning users (TOTP-enrolled) -> L3 step-up friction
        for _ in range(25):
            did = f"dev-{hi:03d}"
            ip = HOME_IP.format(10 + hi % 200)
            pw = HUMAN_BREACHED_POOL[hi % len(HUMAN_BREACHED_POOL)]
            human("breached_returning", pw, True, True, ip, did, did, ip, f"sig-hum_{hi:03d}")

        # 15 typo users: correct account, wrong password this attempt -> invalid
        for _ in range(15):
            did = f"dev-{hi:03d}"
            ip = HOME_IP.format(10 + hi % 200)
            human("typo", strong_pw("typo", hi), False, False, ip, did, did, ip, f"sig-hum_{hi:03d}")

        # 35 CGNAT users sharing ONE IP -> some throttled by naive per-IP limits
        for _ in range(35):
            did = f"dev-{hi:03d}"
            # Home network IS the CGNAT carrier (ASN 64502), so the risk engine
            # recognizes it — the only cost these users pay is the per-IP throttle.
            human("cgnat", strong_pw("cg", hi), False, False, CGNAT_IP, did, did, CGNAT_IP,
                  f"sig-hum_{hi:03d}", home_asn="64502")

        # 20 new-device / traveller users (TOTP) -> L4 step-up friction
        for _ in range(20):
            home_did = f"dev-{hi:03d}"
            fresh_did = f"newdev-{hi:03d}"
            present_ip = NEWDEV_IP.format(hi % 2, 20 + hi % 200)
            uid, email = f"hum_{hi:03d}", f"human{hi:03d}@demo.shop"
            pw = strong_pw("trav", hi)
            secret = add_user(uid, email, pw, breached=False, totp=True)
            home_history(uid, home_did)  # home is a *different* device than they present now
            legit.append({"email": email, "password": pw, "scenario": "new_device",
                          "ip": present_ip, "did": fresh_did, "sig": f"sig-new-{uid}",
                          "totp_secret": secret, "breached": False})
            hi += 1

        # --- 10 victim accounts: strong creds, captured by an infostealer --------
        for i in range(10):
            uid, email = f"vic_{i:02d}", f"victim{i:02d}@demo.shop"
            pw = strong_pw("victim", i)
            did = f"vicdev-{i:02d}"
            add_user(uid, email, pw, breached=False)
            home_history(uid, did)  # home network is HOME_ASN; attacker will differ
            stealer.append({
                "email": email, "password": pw, "did": did,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
                "client_sig": f"sig-vic_{i:02d}",
            })

        db.session.commit()

        # --- combo list: 40 valid + 1960 junk (non-existent accounts) -----------
        existing = {u.email for u in User.query.all()}
        combo = list(combo_valid)
        while len(combo) < 1000:
            email = f"junk{RNG.randint(0, 9_999_999)}@mail.example"
            if email in existing:
                continue
            combo.append((email, strong_pw("junk", RNG.randint(0, 1_000_000))))
        RNG.shuffle(combo)
        with open(os.path.join(DATA, "combo_list.txt"), "w") as fh:
            for email, pw in combo:
                fh.write(f"{email}:{pw}\n")

        write_breach_corpus(breached_passwords)

        with open(os.path.join(DATA, "legit_users.json"), "w") as fh:
            json.dump(legit, fh, indent=2)
        with open(os.path.join(DATA, "stealer_logs.json"), "w") as fh:
            json.dump(stealer, fh, indent=2)
        with open(os.path.join(DATA, "device_history.json"), "w") as fh:
            json.dump(history, fh, indent=2)

        # --- mint "stolen" session cookies via the app itself (level 0) ---------
        demo.load_device_history()
        stolen = []
        for v in stealer:
            client = demo.app.test_client()  # fresh client (and cookie jar) per victim
            resp = client.post("/login", json={"email": v["email"], "password": v["password"]},
                               headers={"X-Lab-Client-IP": HOME_IP.format(50),
                                        "X-Lab-Actor": "seed"})
            cookie = None
            for header in resp.headers.getlist("Set-Cookie"):
                if header.startswith("session="):
                    cookie = header.split(";", 1)[0]
                    break
            stolen.append({"email": v["email"], "cookie": cookie})
        with open(os.path.join(DATA, "stolen_sessions.json"), "w") as fh:
            json.dump(stolen, fh, indent=2)

    print(f"Seeded {len(existing)} accounts, {len(combo)} combo pairs, "
          f"{len(os.listdir(RANGES))} breach-range files, {len(legit)} sim users, "
          f"{len(stealer)} stealer logs, {sum(1 for s in stolen if s['cookie'])} session cookies.")


if __name__ == "__main__":
    main()
