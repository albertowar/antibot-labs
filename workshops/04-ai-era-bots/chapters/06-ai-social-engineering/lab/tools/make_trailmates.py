#!/usr/bin/env python3
"""
W4 Ch6 lab: generate the Kestrel Trailmates community log. Deterministic, standard library only.

    python tools/make_trailmates.py                # data/*.jsonl(.gz), data/world.json, solutions/answer_key.json (~15 s)
    python tools/make_trailmates.py --check        # also assert the invariants the campaign tiers rely on
    python tools/make_trailmates.py --scale 0.25 --out-dir /tmp/tm   # a smaller community to experiment with
                                                   # (the answer key is only written at full scale)

Trailmates is Kestrel Outfitters' hobby community: members message each other about trips, sell
used gear on a swap board, and pay through the community wallet. Ninety days of it are written as
the trust-and-safety team would see them: who joined from where, who messaged whom and when, what
was paid to whom, what was reported, and what a partner bank shared.

What it writes is a FEATURE LOG, never a chat log. A message is a row of metadata (sender,
recipient, time, a length bucket, whether it carried a link, a payout reference or an "add me on
another app" handle, and a structure hash that lets near-duplicates cluster). No row holds message
text, and nothing here can produce one. The chapter teaches how scam operations are built in
theory only; the lab's campaigns exist as the traces they would leave, which is all a defender
measures anyway.

Four campaign tiers, each built to slip past the previous round's detector family:
    A  farm      new accounts, reused photos, hosting/VPN egress, bursts of templated first contacts
    B  LLM crew  aged accounts, unique photos and wording, but one operator shift and many parallel
                 threads that move off-platform within days
    C  closer    few targets, human pace and hours, early off-platform hop, high-value payment chains
    D  dispersed one or two targets per account; visible only through reports, the partner bank's
                 indicators, shared devices and shared payout handles

Genuine cohorts carry the false positives each round has to stay clear of (2% budget per cohort):
newcomers after the trail festival, default-avatar members, households sharing a device,
long-distance couples, gear sellers, translation users, VPN users and the community guides.

Every address is non-routable (198.18.0.0/15, 100.64.0.0/10, the RFC 5737 /24s), every ASN is
private (RFC 6996), every domain ends in .example, and every member is invented.
"""

import argparse
import bisect
import gzip
import hashlib
import json
import os
import random
import statistics
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
DATA = os.path.join(LAB, "data")
SOL = os.path.join(LAB, "solutions")

SEED = 2026
T0 = int(datetime(2026, 7, 1, tzinfo=timezone.utc).timestamp())
DAY = 86400
DAYS = 90
T1 = T0 + DAYS * DAY
FESTIVAL_DAY = 40

REGIONS = {"US-W": -7, "US-E": -4, "GB": 1, "DE": 2, "BR": -3, "PH": 8, "JP": 9, "AU-E": 10}
NON_EN = ["DE", "BR", "PH", "JP"]
GENUINE_DOMAINS = ["kestrel-outfitters.example", "trailmaps.example", "photos.example", "gearlist.example"]
SCAM_WORDS = (["nimbus", "harbor", "lumen", "orchid", "cedar", "vantage", "aurora", "meridian"],
              ["yield", "capital", "markets", "fx", "assets", "vault", "trade", "growth"])

# cohort sizes at scale 1.0
COHORTS = {"regular": 2400, "household": 100, "default_avatar": 200, "long_distance_couple": 100,
           "seller": 120, "translation_user": 180, "newcomer": 260, "vpn_user": 140, "guide": 24}
NEW_COUPLES = 3                      # pairs that meet inside the window (the honest Round 3 cost)
# campaigns: tier, accounts at scale 1.0, start day
CAMPAIGNS = [("A1", "A", 25, 8), ("A2", "A", 25, 33), ("A3", "A", 25, 61),
             ("B1", "B", 12, 0), ("B2", "B", 12, 4), ("B3", "B", 12, 9),
             ("C1", "C", 6, 2), ("C2", "C", 6, 12),
             ("D1", "D", 15, 0), ("D2", "D", 15, 10)]
B_SHIFT = {"B1": 0, "B2": 3, "B3": 21}  # UTC hour each crew's ten-hour shift starts

COHORT_INFO = {
    "regular": "Ordinary members. Some of them are the campaigns' victims, so flagging a victim is a false positive too.",
    "household": "Families share one tablet. A shared device is a link, not a verdict: cluster on it only from a seed with scam evidence (Round 4).",
    "default_avatar": "Members who never uploaded a photo all share the community's default avatars. A photo-reuse rule must skip them (Round 1).",
    "long_distance_couple": "They message at all hours across time zones, move to another app, and send each other money. Four couples meet inside the window and their first gift looks like a scam's first payment (Round 3).",
    "seller": "Gear sellers message strangers, ask for payment and sometimes say 'text me'. Outbound fan-out plus off-platform is a seller, not a crew, unless the hours are a shift (Round 2).",
    "translation_user": "Non-native members who use the built-in translator. Translation is how LLM crews talk too; it is never a signal on its own.",
    "newcomer": "Joined at the trail festival and messaged everyone they met within two days. New account plus burst fan-out is not a farm without reused photos or hosting egress (Round 1).",
    "vpn_user": "Privacy-minded members on VPN and cloud egress. Egress alone is not a signal (Round 1).",
    "guide": "Volunteer guides answer questions in office hours and post announcements: shift-shaped hours and huge fan-out, but nobody is asked to leave the platform (Round 2).",
}


def rng_for(*parts):
    return random.Random(":".join([str(SEED)] + [str(p) for p in parts]))


def hexid(*parts, n=10):
    return hashlib.sha256(":".join(str(p) for p in parts).encode()).hexdigest()[:n]


def u01(*parts):
    return int(hashlib.sha256(":".join(map(str, parts)).encode()).hexdigest()[:12], 16) / 16 ** 12


def tid(a, b):
    key = (a, b) if a < b else (b, a)
    return "t_" + hexid("thread", *key)


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- the simulated internet
def build_world():
    asns = []
    for kind, n, base, name in (("residential", 6, 64601, "Example Residential Broadband"),
                                ("mobile", 3, 64611, "Example Mobile"),
                                ("hosting", 3, 64621, "Example Cloud Hosting"),
                                ("vpn", 2, 64631, "Example VPN")):
        for i in range(n):
            asns.append({"asn": base + i, "name": f"{name} {i + 1}", "kind": kind, "index": i})
    return {
        "window": {"start": iso(T0), "end": iso(T1), "festival": iso(T0 + FESTIVAL_DAY * DAY)},
        "regions": REGIONS,
        "asns": asns,
        "default_avatars": ["av_" + hexid("default-avatar", i) for i in range(6)],
        "genuine_domains": GENUINE_DOMAINS,
        "notes": "All addresses are non-routable (198.18.0.0/15 residential, 100.64.0.0/10 mobile, "
                 "203.0.113.0/24 hosting, 198.51.100.0/24 VPN); ASNs are private (RFC 6996).",
    }


def ip_for(rng, asn):
    i = asn["index"]
    if asn["kind"] == "residential":
        return f"198.18.{i * 8 + rng.randrange(8)}.{rng.randrange(1, 255)}"
    if asn["kind"] == "mobile":
        return f"100.64.{i * 16 + rng.randrange(16)}.{rng.randrange(1, 255)}"
    if asn["kind"] == "hosting":
        return f"203.0.113.{i * 80 + rng.randrange(1, 80)}"
    return f"198.51.100.{i * 120 + rng.randrange(1, 120)}"


def personal_profile(region):
    off = REGIONS[region]
    return (frozenset((h - off) % 24 for h in range(8, 24)), frozenset(range(7)))


def office_profile(region):
    off = REGIONS[region]
    return (frozenset((h - off) % 24 for h in range(9, 17)), frozenset(range(5)))


def shift_profile(start):
    return (frozenset((start + k) % 24 for k in range(10)), frozenset(range(7)))


ANY_HOUR = (frozenset(range(24)), frozenset(range(7)))


def next_active(rng, ts, prof):
    hours, days = prof
    t = ts
    for _ in range(24 * 8):
        dt = datetime.fromtimestamp(t, timezone.utc)
        if dt.hour in hours and dt.weekday() in days:
            return t
        t = (t // 3600 + 1) * 3600 + rng.randrange(0, 1500)
    return ts


# --------------------------------------------------------------------------- the community
class World:
    def __init__(self, scale):
        self.scale = scale
        self.world = build_world()
        self.by_kind = {}
        for a in self.world["asns"]:
            self.by_kind.setdefault(a["kind"], []).append(a)
        self.members = {}          # id -> platform-visible record
        self.meta = {}             # id -> generator-only facts (profile, latency, cohort, campaign)
        self.cohorts = {k: [] for k in COHORTS}
        self.campaigns = {}
        self.events = []           # DM events (no ids yet)
        self.threads = {}          # sorted pair -> {"id", "start", "initiator"}
        self.prior_paid = set()    # (payer, payee) pairs that paid each other before the window
        self.handle_first_seen = {}
        self.handle_owner = {}
        self.payments = []
        self.reports = []
        self.scam_chains = []      # (campaign, victim, [payment dicts]) filled in order
        self.victims = {}          # victim -> campaign
        self.intel = []

    def n(self, x, lo=1):
        return max(lo, round(x * self.scale))

    # ---- members
    def add_member(self, mid, *, joined, kind, region, device=None, photo=None, prof=None, latency=(120, 5400),
                   translated=0.0, email=0.9, phone=0.6, login_regions=None, asn=None, rng=None):
        rng = rng or rng_for("member", mid)
        asn = asn or rng.choice(self.by_kind[kind])
        rec = {"member_id": mid, "joined_at": iso(joined), "signup_ip": ip_for(rng, asn), "signup_asn": asn["asn"],
               "device_id": device or "d_" + hexid("device", mid), "declared_region": region,
               "login_regions": login_regions or [region], "photo": photo or "ph_" + hexid("photo", mid),
               "email_verified": rng.random() < email, "phone_verified": rng.random() < phone,
               "bio_words": rng.randint(0, 60)}
        self.members[mid] = rec
        self.meta[mid] = {"joined": joined, "prof": prof or personal_profile(region), "latency": latency,
                          "translated": translated, "ip": rec["signup_ip"], "device": rec["device_id"]}
        return mid

    def thread(self, a, b, start, initiator=None):
        key = (a, b) if a < b else (b, a)
        th = self.threads.get(key)
        if th is None:
            th = {"id": tid(a, b), "start": start, "initiator": initiator or a}
            self.threads[key] = th
        return th

    def msg(self, rng, ts, sender, recipient, *, length=None, link=None, payout=None, offplatform=False,
            media=False, shape=None):
        th = self.thread(sender, recipient, ts, sender)
        m = self.meta[sender]
        if length is None:
            length = rng.choices("SML", weights=(5, 4, 1))[0]
        if shape is None:
            shape = ("sh_" + hexid("common", rng.randrange(25))) if (length == "S" and rng.random() < 0.35) \
                else "sh_" + hexid("shape", sender, ts, rng.random())
        self.events.append({"ts": ts, "thread": th["id"], "sender": sender, "recipient": recipient,
                            "first_contact": False, "len": length, "link": link, "payout_ref": payout,
                            "offplatform": offplatform, "media": media,
                            "translated": rng.random() < m["translated"], "shape": shape,
                            "device": m["device"], "ip": m["ip"]})

    def chat(self, rng, a, b, t, n, flags=None, a_only=False):
        """n messages starting with a at/after t, mostly alternating; returns the time after the last."""
        s, r = a, b
        for i in range(n):
            t = next_active(rng, t, self.meta[s]["prof"])
            if t >= T1:
                return t
            self.msg(rng, t, s, r, **(flags(i, s, t) if flags else {}))
            if not a_only and rng.random() < 0.8:
                s, r = r, s
            t += rng.randint(*self.meta[s]["latency"])
        return t

    def pay(self, ts, payer, payee, amount, kind="member", truth=None):
        if ts >= T1 or ts < T0:
            return None
        p = {"ts": ts, "payer": payer, "payee": payee, "payee_kind": kind, "amount": round(amount, 2)}
        self.payments.append(p)
        if truth is not None:
            p["_truth"] = truth
        return p

    def report(self, ts, reporter, reported, reason):
        if T0 <= ts < T1:
            self.reports.append({"ts": ts, "reporter": reporter, "reported": reported, "reason": reason})


def make_genuine(W):
    rng = rng_for("genuine")
    regions = list(REGIONS)
    defaults = W.world["default_avatars"]
    counter = 0

    def new_id():
        nonlocal counter
        counter += 1
        return "m_" + hexid("member", counter)

    def kind_res(r):
        return "residential" if r.random() < 0.75 else "mobile"

    for cohort, size in COHORTS.items():
        size = W.n(size, 2)
        if cohort == "household":
            fam = 0
            while len(W.cohorts["household"]) < size:
                fam += 1
                dev = "d_" + hexid("family", fam)
                region = rng.choice(regions)
                asn = rng.choice(W.by_kind["residential"])
                for _ in range(rng.choice((2, 2, 3))):
                    mid = new_id()
                    W.add_member(mid, joined=T0 - rng.randint(60, 2000) * DAY, kind="residential", region=region,
                                 device=dev, asn=asn)
                    W.cohorts["household"].append(mid)
            continue
        if cohort == "long_distance_couple":
            for k in range(size // 2):
                a, b = new_id(), new_id()
                ra, rb = rng.sample(regions, 2)
                for mid, r in ((a, ra), (b, rb)):
                    W.add_member(mid, joined=T0 - rng.randint(120, 1500) * DAY, kind=kind_res(rng), region=r,
                                 latency=(60, 3600))
                    W.cohorts[cohort].append(mid)
            continue
        for _ in range(size):
            mid = new_id()
            r = rng.choice(regions)
            if cohort == "regular":
                W.add_member(mid, joined=T0 - rng.randint(30, 2000) * DAY, kind=kind_res(rng), region=r,
                             login_regions=[r] + ([rng.choice(regions)] if rng.random() < 0.08 else []))
            elif cohort == "default_avatar":
                W.add_member(mid, joined=T0 - rng.randint(10, 1500) * DAY, kind=kind_res(rng), region=r,
                             photo=rng.choice(defaults), email=0.7, phone=0.3)
            elif cohort == "seller":
                W.add_member(mid, joined=T0 - rng.randint(200, 2500) * DAY, kind="residential", region=r,
                             phone=0.95, latency=(60, 2400))
            elif cohort == "translation_user":
                r = rng.choice(NON_EN)
                W.add_member(mid, joined=T0 - rng.randint(30, 1800) * DAY, kind=kind_res(rng), region=r,
                             translated=0.8)
            elif cohort == "newcomer":
                wifi = len(W.cohorts["newcomer"]) < W.n(6)          # signed up on the festival's cloud-hosted Wi-Fi
                W.add_member(mid, joined=T0 + FESTIVAL_DAY * DAY + rng.randint(0, 2 * DAY),
                             kind="hosting" if wifi else kind_res(rng),
                             region="US-W", photo=rng.choice(defaults) if rng.random() < 0.15 else None,
                             email=0.8, phone=0.4)
            elif cohort == "vpn_user":
                kind = "vpn" if rng.random() < 0.7 else "hosting"
                W.add_member(mid, joined=T0 - rng.randint(60, 2000) * DAY, kind=kind, region=r,
                             login_regions=[r, rng.choice(regions)] if rng.random() < 0.6 else [r])
            elif cohort == "guide":
                W.add_member(mid, joined=T0 - rng.randint(400, 2500) * DAY, kind="residential", region="US-W",
                             prof=office_profile("US-W"), latency=(300, 5400), phone=1.0, email=1.0)
            W.cohorts[cohort].append(mid)


def genuine_activity(W):
    rng = rng_for("activity")
    c = W.cohorts
    social = c["regular"] + c["household"] + c["default_avatar"] + c["translation_user"] + c["vpn_user"]
    # friendships that predate the window
    for i, a in enumerate(social):
        r = rng_for("friends", a)
        for b in r.sample(social, r.randint(1, 3)):
            if a == b:
                continue
            W.thread(a, b, T0 - r.randint(30, 900) * DAY, a)
    for (a, b), th in sorted(W.threads.items()):
        r = rng_for("friend-chat", th["id"])
        t = T0 + r.randint(0, 20 * DAY)
        while t < T1:
            t = W.chat(r, a, b, t, r.randint(2, 7))
            t += int(r.expovariate(1 / (24 * DAY)))
        if r.random() < 0.15:          # friends split a trip cost
            W.prior_paid.add((a, b))
            W.pay(T0 + r.randint(0, DAYS * DAY - 1), a, b, r.uniform(15, 120))
    # households message each other too
    fams = {}
    for m in c["household"]:
        fams.setdefault(W.members[m]["device_id"], []).append(m)
    for dev, ms in sorted(fams.items()):
        r = rng_for("family", dev)
        for a, b in zip(ms, ms[1:]):
            W.thread(a, b, T0 - 400 * DAY, a)
            t = T0 + r.randint(0, 5 * DAY)
            while t < T1:
                t = W.chat(r, a, b, t, r.randint(2, 5))
                t += r.randint(2, 9) * DAY

    # long-distance couples: all hours (two time zones), already on another app, regular gifts
    pairs = list(zip(c["long_distance_couple"][::2], c["long_distance_couple"][1::2]))
    for k, (a, b) in enumerate(pairs):
        r = rng_for("couple", a)
        new = k < W.n(NEW_COUPLES)
        if new:
            start = T0 + r.randint(5, 30) * DAY
            W.thread(a, b, start, a)
            hop_day = r.randint(3, 9)
            t = start
            while t < T1:
                t = W.chat(r, a, b, t, r.randint(4, 10))
                t += r.randint(DAY // 2, 2 * DAY)
            W.msg(r, next_active(r, start + hop_day * DAY, W.meta[b]["prof"]), b, a, offplatform=True)
            gift = start + r.randint(15, 40) * DAY
            W.pay(gift, a, b, r.uniform(60, 400))
            for _ in range(r.randint(0, 2)):
                gift += r.randint(5, 20) * DAY
                W.pay(gift, r.choice((a, b)), b if r.random() < 0.5 else a, r.uniform(30, 300))
        else:
            W.thread(a, b, T0 - r.randint(100, 700) * DAY, a)
            W.prior_paid.update({(a, b), (b, a)})
            t = T0 + r.randint(0, DAY)
            while t < T1:
                t = W.chat(r, a, b, t, r.randint(3, 9))
                t += r.randint(DAY // 2, 2 * DAY)
            for _ in range(r.randint(2, 6)):
                x, y = (a, b) if r.random() < 0.5 else (b, a)
                W.pay(T0 + r.randint(0, DAYS * DAY - 1), x, y, r.uniform(25, 300))

    # gear sellers: inbound buyers, outbound promos, some 'text me', a few external payouts
    buyers = social + c["newcomer"]
    for s in c["seller"]:
        r = rng_for("seller", s)
        h = "h_" + hexid("handle", s)
        W.handle_first_seen[h] = T0 - r.randint(100, 900) * DAY
        W.handle_owner[h] = s
        W.prior_paid.add((s, h))
        for _ in range(r.randint(25, 50)):
            b = r.choice(buyers)
            if b == s:
                continue
            day0 = r.randint(0, DAYS - 1)
            if b in W.cohorts["newcomer"] and day0 < FESTIVAL_DAY + 2:
                day0 = r.randint(FESTIVAL_DAY + 2, DAYS - 1)
            t = T0 + day0 * DAY + r.randint(0, DAY)
            ext = r.random() < 0.08
            textme = r.random() < 0.25

            def flags(i, snd, ts, ext=ext, textme=textme):
                f = {}
                if snd == s and i == 3 and ext:
                    f["payout"] = h
                if snd == s and i == 1 and textme:
                    f["offplatform"] = True
                if snd == s and i == 1 and not textme and r.random() < 0.5:
                    f["link"] = "gearlist.example"
                    f["media"] = True
                return f
            end = W.chat(r, b, s, t, r.randint(4, 8), flags)
            if r.random() < 0.85:
                W.pay(end + r.randint(600, 2 * DAY), b, h if ext else s, r.lognormvariate(4.4, 0.7),
                      kind="external" if ext else "member")
        for _ in range(r.randint(15, 40)):           # outbound promos to members who liked a listing
            b = r.choice(buyers)
            if b == s:
                continue
            t = T0 + r.randint(0, DAYS - 1) * DAY + r.randint(0, DAY)
            if b in W.cohorts["newcomer"] and t < T0 + (FESTIVAL_DAY + 2) * DAY:
                continue
            promo_off = r.random() < 0.45

            def flags(i, snd, ts, promo_off=promo_off):
                return {"offplatform": promo_off and snd == s and i in (0, 2), "link": "gearlist.example" if i == 0 else None,
                        "media": i == 0}
            W.chat(r, s, b, t, 1 if r.random() < 0.7 else 3, flags)
        for _ in range(r.randint(1, 3)):             # withdrawals to the seller's own bank handle
            W.pay(T0 + r.randint(0, DAYS * DAY - 1), s, h, r.uniform(100, 1500), kind="external")

    # guides: inbound questions in office hours, outbound announcements with a map link
    for g in c["guide"]:
        r = rng_for("guide", g)
        for _ in range(r.randint(30, 80)):
            b = r.choice(social + c["newcomer"])
            t = T0 + r.randint(0, DAYS - 1) * DAY + r.randint(0, DAY)
            if b in W.cohorts["newcomer"] and t < T0 + (FESTIVAL_DAY + 1) * DAY:
                continue
            W.chat(r, b, g, t, r.randint(2, 6),
                   lambda i, snd, ts: {"link": "trailmaps.example" if snd == g and i == 1 else None})
        trip_group = g == c["guide"][0]       # runs the summer trip's group chat on another app
        for _ in range(r.randint(50, 140)):
            b = r.choice(social + c["newcomer"])
            t = T0 + r.randint(0, DAYS - 1) * DAY + r.randint(0, DAY)
            if b in W.cohorts["newcomer"] and t < T0 + (FESTIVAL_DAY + 1) * DAY:
                continue
            inv = trip_group and r.random() < 0.6
            W.chat(r, g, b, t, 1, lambda i, snd, ts, inv=inv: {"link": "trailmaps.example", "length": "M", "offplatform": inv})

    # newcomers: meet people at the festival, message all of them within two days
    pool = c["newcomer"] + c["guide"] + social[:300]
    for m in c["newcomer"]:
        r = rng_for("newcomer", m)
        joined = W.meta[m]["joined"]
        for b in r.sample(pool, r.randint(6, 28)):
            if b == m:
                continue
            t = joined + r.randint(600, 2 * DAY)
            insta = r.random() < 0.3
            W.chat(r, m, b, t, r.randint(1, 6),
                   lambda i, snd, ts, insta=insta: {"offplatform": insta and i == 2, "media": i == 0 and r.random() < 0.3})

    # newcomers move festival-sale money to their own new bank handle (a brand-new external payee)
    for m in c["newcomer"]:
        r = rng_for("withdraw", m)
        if r.random() < 0.12:
            h = "h_" + hexid("handle", m)
            W.handle_first_seen[h] = W.meta[m]["joined"] + r.randint(1, 5) * DAY
            W.handle_owner[h] = m
            W.pay(W.handle_first_seen[h] + r.randint(0, 20) * DAY, m, h, r.uniform(20, 300), kind="external")

    # translation users, VPN users and regulars also report the odd member; sellers get disputes
    for s in c["seller"]:
        r = rng_for("dispute", s)
        if r.random() < 0.12:
            W.report(T0 + r.randint(0, DAYS * DAY - 1), r.choice(buyers), s, "scam")
    disputed = c["seller"][0]
    for k in range(2):
        W.report(T0 + (20 + 10 * k) * DAY, c["regular"][k], disputed, "scam")
    for g in c["guide"]:
        r = rng_for("guide-report", g)
        for _ in range(r.randint(0, 2)):
            W.report(T0 + r.randint(0, DAYS * DAY - 1), r.choice(social), g, "spam")
    r = rng_for("misc-reports")
    for _ in range(W.n(40)):
        W.report(T0 + r.randint(0, DAYS * DAY - 1), r.choice(social), r.choice(social), r.choice(("harassment", "other")))


# --------------------------------------------------------------------------- the campaigns
def scam_domain(cid):
    r = rng_for("domain", cid)
    return f"{r.choice(SCAM_WORDS[0])}-{r.choice(SCAM_WORDS[1])}.example"


def chain(W, r, cid, tier, victim, handles, start, steps, base, growth, cap, first_to_member=None):
    """A victim's payment chain. Truth carries the step; the scorer decides what an intervention stops."""
    t = start
    paid = []
    for step in range(steps):
        amount = min(cap, base * (growth ** step) * r.uniform(0.8, 1.2))
        if step == 0 and first_to_member:
            p = W.pay(t, victim, first_to_member, amount, kind="member", truth=(cid, step))
        else:
            h = handles[0] if step < max(1, steps // 2) else handles[-1]
            p = W.pay(t, victim, h, amount, kind="external", truth=(cid, step))
        if p:
            paid.append(p)
        t += r.randint(2, 7) * DAY
    return t


def make_campaigns(W):
    social = W.cohorts["regular"] + W.cohorts["household"] + W.cohorts["default_avatar"] + \
        W.cohorts["translation_user"] + W.cohorts["vpn_user"]
    pool = sorted(social)
    rng_for("victims").shuffle(pool)
    cursor = 0

    def targets(k):
        nonlocal cursor
        out = pool[cursor:cursor + k]
        cursor += k
        return out

    regions = list(REGIONS)
    for cid, tier, size, day in CAMPAIGNS:
        r = rng_for("campaign", cid)
        n_acc = W.n(size, 2)
        start = T0 + day * DAY
        dom = scam_domain(cid)
        handles = ["h_" + hexid("scam-handle", cid, i) for i in range(3 if tier == "B" else 2)]
        for i, h in enumerate(handles):
            W.handle_first_seen[h] = start + i * 20 * DAY - r.randint(1, 5) * DAY
            W.handle_owner[h] = cid
        devices = ["d_" + hexid("op-device", cid, i) for i in range(5 if tier == "A" else 4)]
        photos = ["ph_" + hexid("op-photo", cid, i) for i in range(4)]
        members = []
        W.campaigns[cid] = {"tier": tier, "members": members, "victims": [], "handles": handles, "domain": dom}
        for k in range(n_acc):
            mid = "m_" + hexid("op", cid, k)
            ar = rng_for("op", cid, k)
            region = ar.choice(["US-W", "US-E", "GB", "AU-E"])
            if tier == "A":
                W.add_member(mid, joined=start + ar.randint(0, 2 * DAY), kind="hosting" if ar.random() < 0.6 else "vpn",
                             region=region, device=ar.choice(devices), photo=ar.choice(photos), prof=ANY_HOUR,
                             latency=(30, 600), email=0.5, phone=0.05, login_regions=[region, "SEA"], rng=ar)
            elif tier == "B":
                W.add_member(mid, joined=T0 - ar.randint(400, 1500) * DAY, kind="residential", region=region,
                             prof=shift_profile(B_SHIFT[cid]), latency=(60, 400), translated=0.7, email=1.0,
                             phone=0.5, rng=ar)
            elif tier == "C":
                W.add_member(mid, joined=T0 - ar.randint(300, 1800) * DAY, kind="residential", region=region,
                             latency=(300, 5400), translated=0.3, email=1.0, phone=0.9, rng=ar)
            else:
                W.add_member(mid, joined=T0 - ar.randint(200, 1500) * DAY,
                             kind="residential" if ar.random() < 0.6 else "mobile", region=ar.choice(regions),
                             device=devices[(k // 2) % len(devices)], latency=(600, 7200), email=1.0, phone=0.8, rng=ar)
            members.append(mid)

        for k, mid in enumerate(members):
            ar = rng_for("op-run", cid, k)
            if tier == "A":
                t0 = W.meta[mid]["joined"] + ar.randint(600, DAY)
                for v in ar.sample(pool[-1500:], ar.randint(40, 90)):
                    t = t0 + ar.randint(0, 2 * DAY)
                    W.msg(ar, t, mid, v, length="M", shape="sh_" + hexid("template", cid, ar.randrange(3)),
                          link=dom if ar.random() < 0.3 else None, offplatform=ar.random() < 0.5)
                    if ar.random() < 0.06:
                        W.chat(ar, v, mid, t + ar.randint(600, DAY), ar.randint(1, 3))
                        if ar.random() < 0.2:
                            W.victims[v] = cid
                            W.campaigns[cid]["victims"].append(v)
                            chain(W, ar, cid, tier, v, handles, t + ar.randint(2, 6) * DAY, ar.randint(1, 2), 80, 1.5, 600)
                    if ar.random() < 0.08:
                        W.report(t + ar.randint(DAY // 4, 5 * DAY), v, mid, "spam" if ar.random() < 0.6 else "scam")
            elif tier == "B":
                active_from = start + ar.randint(0, 20) * DAY
                for v in targets(ar.randint(20, 35)):
                    t = active_from + ar.randint(0, 60) * DAY
                    if t >= T1 - 3 * DAY:
                        continue
                    t = next_active(ar, t, W.meta[mid]["prof"])
                    W.msg(ar, t, mid, v, length="M")
                    if ar.random() > 0.35:
                        if ar.random() < 0.03:
                            W.report(t + ar.randint(DAY // 4, 4 * DAY), v, mid, "spam")
                        continue
                    W.victims[v] = cid
                    W.campaigns[cid]["victims"].append(v)
                    first = t
                    hop = ar.randint(2, 5)
                    t += ar.randint(600, 6 * 3600)
                    while t < first + hop * DAY:
                        t = W.chat(ar, v, mid, t, ar.randint(6, 14))
                        t += ar.randint(DAY // 3, DAY)
                    t = next_active(ar, t, W.meta[mid]["prof"])
                    W.msg(ar, t, mid, v, length="M", offplatform=True)
                    end = first + ar.randint(15, 40) * DAY
                    while t < end:          # after the hop the platform sees only the odd check-in
                        t += ar.randint(3, 7) * DAY
                        t = W.chat(ar, mid, v, t, ar.randint(1, 3))
                    if ar.random() < 0.55:
                        last = chain(W, ar, cid, tier, v, handles[ar.randrange(2):], first + ar.randint(8, 25) * DAY,
                                     ar.randint(3, 6), ar.uniform(100, 600), 1.7, 25000)
                        if ar.random() < 0.15:
                            W.report(last + ar.randint(5, 20) * DAY, v, mid, "scam")
            elif tier == "C":
                for v in targets(ar.randint(3, 5)):
                    first = start + ar.randint(0, 40) * DAY + ar.randint(0, DAY)
                    W.victims[v] = cid
                    W.campaigns[cid]["victims"].append(v)
                    hop = ar.randint(3, 7)
                    t = first
                    first_msg = True
                    while t < first + hop * DAY:
                        if first_msg:
                            t = next_active(ar, t, W.meta[mid]["prof"])
                            W.msg(ar, t, mid, v, length="L")
                            first_msg = False
                            t += ar.randint(1800, 8 * 3600)
                        t = W.chat(ar, v, mid, t, ar.randint(3, 8))
                        t += ar.randint(DAY // 2, 2 * DAY)
                    t = next_active(ar, t, W.meta[mid]["prof"])
                    W.msg(ar, t, mid, v, length="M", offplatform=True)
                    end = first + ar.randint(30, 60) * DAY
                    while t < end:
                        t += ar.randint(4, 9) * DAY
                        t = W.chat(ar, mid, v, t, ar.randint(1, 2))
                    if ar.random() < 0.85:
                        last = chain(W, ar, cid, tier, v, handles, first + ar.randint(10, 25) * DAY, ar.randint(5, 9),
                                     ar.uniform(150, 500), 1.6, 40000, first_to_member=mid)
                        if ar.random() < 0.2:
                            W.report(last + ar.randint(3, 15) * DAY, v, mid, "scam")
            else:   # D
                for v in targets(ar.randint(1, 2)):
                    first = start + ar.randint(0, 50) * DAY + ar.randint(0, DAY)
                    W.victims[v] = cid
                    W.campaigns[cid]["victims"].append(v)
                    t = first
                    end = first + ar.randint(30, 50) * DAY
                    shared = first + ar.randint(5, 15) * DAY
                    sent_link = k % 2 == 1           # half the crew never posts the link on-platform
                    first_msg = True
                    while t < end:
                        if first_msg:
                            t = next_active(ar, t, W.meta[mid]["prof"])
                            W.msg(ar, t, mid, v, length="M")
                            first_msg = False
                            t += ar.randint(1800, 12 * 3600)
                        if t >= shared and not sent_link:
                            t = next_active(ar, t, W.meta[mid]["prof"])
                            W.msg(ar, t, mid, v, length="M", link=dom, offplatform=ar.random() < 0.3)
                            sent_link = True
                        t = W.chat(ar, v, mid, t, ar.randint(2, 5))
                        t += ar.randint(2, 4) * DAY
                    if ar.random() < 0.85:
                        last = chain(W, ar, cid, tier, v, handles, first + ar.randint(12, 30) * DAY, ar.randint(2, 4),
                                     ar.uniform(150, 400), 2.0, 15000)
                        if ar.random() < 0.35:
                            W.report(last + ar.randint(3, 15) * DAY, v, mid, "scam")

    # the partner bank's indicators: D's handles and domains, one of C's handles, and one mistake
    c1 = W.campaigns["C1"]
    for cid in ("D1", "D2"):
        cp = W.campaigns[cid]
        for h in cp["handles"]:
            W.intel.append({"type": "payout_handle", "value": h, "reported": iso(T0 + 60 * DAY),
                            "note": "partner bank fraud team: customer complaints, payments to this handle"})
        W.intel.append({"type": "link_domain", "value": cp["domain"], "reported": iso(T0 + 62 * DAY),
                        "note": "partner bank: domain named in customer complaints"})
    W.intel.append({"type": "payout_handle", "value": c1["handles"][0], "reported": iso(T0 + 70 * DAY),
                    "note": "partner bank fraud team: customer complaints, payments to this handle"})
    honest = "h_" + hexid("handle", W.cohorts["seller"][1])
    W.intel.append({"type": "payout_handle", "value": honest, "reported": iso(T0 + 55 * DAY),
                    "note": "partner bank: one disputed payment (chargeback)"})


# --------------------------------------------------------------------------- finalize
def finalize(W):
    events = sorted(W.events, key=lambda e: (e["ts"], e["thread"], e["sender"], e["shape"]))
    for i, e in enumerate(events):
        e["event_id"] = f"e{i:07d}"
    W.events = events

    # thread starts and first contacts from the sorted log; pre-window threads keep their start
    start = {th["id"]: th["start"] for th in W.threads.values() if th["start"] < T0}
    seen = set()
    for e in events:
        t = e["thread"]
        e["first_contact"] = t not in start and t not in seen
        if t not in start and t not in seen:
            start[t] = e["ts"]
        seen.add(t)

    def thread_start(a, b):
        return start.get(tid(a, b))

    # offplatform proposals received, per recipient, and message times per thread, for the
    # decision-time features: of the new contacts who asked the payer to move apps, the one the
    # payer has exchanged the most messages with (a bond is dozens of messages, a promo one or two)
    offp = {}
    thread_times = {}
    for e in events:
        thread_times.setdefault(e["thread"], []).append(e["ts"])
        if e["offplatform"]:
            offp.setdefault(e["recipient"], []).append((e["ts"], e["sender"]))

    pays = sorted(W.payments, key=lambda p: (p["ts"], p["payer"], p["payee"]))
    paid_pairs = set(W.prior_paid)
    first_pay_times = {}
    history = {}
    out, truth = [], {}
    for i, p in enumerate(pays):
        pid = f"p{i:06d}"
        ts, payer, payee = p["ts"], p["payer"], p["payee"]
        prior = history.get(payer, [])
        first = (payer, payee) not in paid_pairs
        if p["payee_kind"] == "member":
            age = (ts - W.meta[payee]["joined"]) / DAY
            ts0 = thread_start(payer, payee)
            is_contact = ts0 is not None and ts0 <= ts
            cdays = round((ts - ts0) / DAY, 2) if is_contact else None
        else:
            age = (ts - W.handle_first_seen.get(payee, T0 - 365 * DAY)) / DAY
            is_contact, cdays = False, None
        recent = [t for t in first_pay_times.get(payee, []) if ts - 7 * DAY <= t < ts]
        oc, ocd, best = None, None, (-1, 0)
        lst = offp.get(payer, [])
        for t_o, snd in lst[:bisect.bisect_left(lst, (ts, ""))]:
            s0 = thread_start(payer, snd)
            if s0 is None or s0 < ts - 60 * DAY:
                continue
            n_msgs = bisect.bisect_left(thread_times[tid(payer, snd)], ts)
            if (n_msgs, t_o) > best:
                best = (n_msgs, t_o)
                oc, ocd = snd, round((ts - s0) / DAY, 2)
        row = {"payment_id": pid, "ts": iso(ts), "payer": payer, "payee": payee, "payee_kind": p["payee_kind"],
               "amount": p["amount"], "first_to_payee": first, "payer_prior_payments": len(prior),
               "payer_median_amount": round(statistics.median(prior), 2) if prior else None,
               "payee_age_days": round(age, 1), "payee_new_payers_7d": len(recent),
               "payee_is_contact": is_contact, "contact_days": cdays,
               "offplatform_contact": oc, "offplatform_contact_days": ocd,
               "offplatform_contact_msgs": best[0] if oc else None,
               "payee_is_offplatform_contact": oc is not None and oc == payee}
        out.append(row)
        if "_truth" in p:
            cid, step = p["_truth"]
            tier = W.campaigns[cid]["tier"]
            pw = {"A": 0.4, "B": 0.3, "C": 0.2, "D": 0.3}[tier] * max(0.2, 1 - 0.15 * step)
            ph = {"A": 0.8, "B": 0.65, "C": 0.55, "D": 0.65}[tier] * max(0.3, 1 - 0.1 * step)
            truth[pid] = {"campaign": cid, "chain": f"{cid}:{payer}", "step": step,
                          "warn_stop": u01(SEED, "warn", pid) < pw, "hold_stop": u01(SEED, "hold", pid) < ph}
        if first:
            first_pay_times.setdefault(payee, []).append(ts)
        paid_pairs.add((payer, payee))
        history.setdefault(payer, []).append(p["amount"])
    W.payment_rows, W.payment_truth = out, truth

    for e in events:
        e["ts"] = iso(e["ts"])
    reports = sorted(W.reports, key=lambda x: (x["ts"], x["reporter"], x["reported"]))
    W.report_rows = [{"report_id": f"r{i:05d}", "ts": iso(x["ts"]), "reporter": x["reporter"],
                      "reported": x["reported"], "reason": x["reason"]} for i, x in enumerate(reports)]


def generate(scale=1.0):
    W = World(scale)
    make_genuine(W)
    genuine_activity(W)
    make_campaigns(W)
    finalize(W)
    return W


def answer_key(W, digest):
    camp_of = {m: cid for cid, c in W.campaigns.items() for m in c["members"]}
    cohorts = {k: sorted(v) for k, v in W.cohorts.items()}
    return {
        "seed": SEED, "scale": W.scale, "sha256": digest,
        "campaigns": {cid: {"tier": c["tier"], "members": sorted(c["members"]), "victims": sorted(set(c["victims"])),
                            "handles": c["handles"], "domain": c["domain"]} for cid, c in sorted(W.campaigns.items())},
        "cohorts": cohorts,
        "cohort_info": COHORT_INFO,
        "scam_payments": W.payment_truth,
        "n_members": len(W.members), "n_scam_members": len(camp_of),
    }


def dumps(rows):
    return "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in rows)


def write_outputs(W, out_dir=DATA, key_path=os.path.join(SOL, "answer_key.json")):
    os.makedirs(out_dir, exist_ok=True)
    members = [W.members[m] for m in sorted(W.members)]
    blobs = {"members.jsonl": dumps(members), "dm_events.jsonl": dumps(W.events),
             "payments.jsonl": dumps(W.payment_rows), "reports.jsonl": dumps(W.report_rows),
             "partner_intel.json": json.dumps(W.intel, indent=1, sort_keys=True) + "\n"}
    h = hashlib.sha256()
    for name in sorted(blobs):
        h.update(name.encode())
        h.update(blobs[name].encode())
    digest = h.hexdigest()
    for name, text in blobs.items():
        if name == "dm_events.jsonl":
            with open(os.path.join(out_dir, name + ".gz"), "wb") as fh:
                with gzip.GzipFile(filename="", mode="wb", fileobj=fh, mtime=0) as gz:
                    gz.write(text.encode())
        else:
            with open(os.path.join(out_dir, name), "w", encoding="utf-8") as fh:
                fh.write(text)
    with open(os.path.join(out_dir, "sample_dm_events.jsonl"), "w", encoding="utf-8") as fh:
        fh.write(dumps(W.events[:500]))
    with open(os.path.join(out_dir, "world.json"), "w", encoding="utf-8") as fh:
        json.dump(W.world, fh, indent=1, sort_keys=True)
        fh.write("\n")
    if key_path:
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        with open(key_path, "w", encoding="utf-8") as fh:
            json.dump(answer_key(W, digest), fh, indent=1, sort_keys=True)
            fh.write("\n")
    return digest


def check(W):
    """The invariants the campaign tiers and the cohort traps rely on."""
    tiers = {}
    for cid, c in W.campaigns.items():
        tiers.setdefault(c["tier"], []).extend(c["members"])
    assert all(tiers[t] for t in "ABCD"), "every tier has members"
    defaults = set(W.world["default_avatars"])
    assert all(W.members[m]["photo"] not in defaults for t in "BCD" for m in tiers[t])
    hosting = {a["asn"] for a in W.world["asns"] if a["kind"] in ("hosting", "vpn")}
    assert all(W.members[m]["signup_asn"] in hosting for m in tiers["A"]), "tier A signs up from hosting/VPN"
    assert not any(W.members[m]["signup_asn"] in hosting for m in tiers["B"] + tiers["C"]), "B and C look residential"
    assert len(W.payment_truth) > 0 and len(W.intel) >= 5
    victims = set(W.victims)
    assert not victims & set(W.cohorts["newcomer"] + W.cohorts["seller"] + W.cohorts["guide"])
    print(f"check: OK ({len(W.members)} members, {len(W.events)} message events, {len(W.payment_rows)} payments, "
          f"{len(W.report_rows)} reports, {len(W.payment_truth)} scam payments)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--out-dir", default=DATA)
    ap.add_argument("--no-key", action="store_true", help="do not (re)write solutions/answer_key.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    W = generate(args.scale)
    if args.check:
        check(W)
    # the committed answer key is the full-scale one; a smaller community never overwrites it
    write_key = not args.no_key and args.scale == 1.0
    digest = write_outputs(W, args.out_dir, os.path.join(SOL, "answer_key.json") if write_key else None)
    if not write_key and args.scale != 1.0:
        print("note: answer key left unchanged (scale != 1.0); the scorer and checkpoints need the full-scale data")
    print(f"wrote {args.out_dir}: {len(W.members)} members, {len(W.events)} message events, "
          f"{len(W.payment_rows)} payments, {len(W.report_rows)} reports; sha256 {digest[:16]}…")


if __name__ == "__main__":
    sys.exit(main())
