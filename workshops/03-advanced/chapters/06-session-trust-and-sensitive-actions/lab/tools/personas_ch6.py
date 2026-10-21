"""
Chapter 6 customers: 80 people with something to get done after they sign in.

Chapter 5's 80 sign-ins, one person per account, now each with a goal (demo_site/ext/session_world.py):

    persona        n  goal                                              sensitive action (weight)
    routine       32  buy to the saved address with the saved card      none (0)
    mover         10  add a new address, ship an order to it            address_add (50), new ship-to (60)
    gift_giver     8  redeem a gift card                                gift_card_redeem (60)
    card_expired   6  replace the saved card                            card_add (60)
    cgnat_phone    6  add a second address, from the phone              address_add (50)
    rotator        4  change the password                               change_password (75)
    traveller      4  ship an order to the hotel                        new ship-to (60), signed in from abroad
    new_phone      4  replace the saved card from the new phone         card_add (60), a device the store never saw
    shared_family  3  redeem a gift card on the family laptop           gift_card_redeem (60), no phone or app on file
    no_inbox       3  change the email address (the old inbox is gone)  change_email (75), cannot read an emailed code

Each signs in through the JSON API (POST /api/login, Chapter 5's prompts and all), then does the goal. When the store
asks for a step-up they answer it with what that person has: the password, their inbox (not `no_inbox`), their
phone's texts, a tap on their enrolled app (number matching), or what they remember of their own account
(`kba`: some answers they know cold, some they do not). A person who cannot answer gives up.

Outcomes: `goal_met`; `delayed` (a 202: the store parked the action for a cooling-off; they would get there
later); `goal_missed` (asked for something they could not give, or refused). `goal_missed`, `blocked` and
`stuck_on_challenge` count as hurt. Every step-up a person met at the goal is recorded in `prompts` (the sign-in's own
code is `login_prompts`, Chapter 5's cost), which is how the checkpoint measures friction and the delayed share.

Shopper pauses are divided by SPEEDUP; the checkpoint and verify.py use the same value.
"""

import time
from dataclasses import dataclass

import browsers
import population
from labclient import BASE_URL, admin, world_pool
from demo_site.ext import rba_world as W
from demo_site.ext import session_world as SW
from demo_site.seed import password_for

SPEEDUP = 5.0
PERSONAS = set(SW.GOALS)
GOAL_PERSONAS = PERSONAS
# How well each person remembers their own account: the chance of answering each question right.
RECALL = {"postcode": 0.95, "card_last4": 0.90, "last_order_total": 0.50, "member_month": 0.60}
HOTEL = {"line1": "1 Harbour View Hotel", "city": "Hamburg", "postcode": "20457", "country": "DE"}
NEW_ADDRESS = {"line1": "88 Cedar Court", "city": "Portland", "postcode": "97214", "country": "US"}

population.HURT.update({"goal_missed"})
population.HAPPY.update({"goal_met"})


@dataclass
class Person(population.Persona):
    rd: str = None
    email: str = ""
    goal: str = ""


def _sleep(rng, lo, hi):
    time.sleep(rng.uniform(lo, hi) / SPEEDUP)


def api_headers(browser):
    ua = dict(browsers.headers_for(browser, "typed", BASE_URL))["User-Agent"]
    return [("User-Agent", ua), ("Accept", "application/json"), ("Accept-Language", "en-US,en;q=0.9"),
            ("Origin", BASE_URL)]


def latest(box, field):
    """The newest message in a mailbox ("<email>" or "sms:<email>") that carries `field`."""
    for msg in reversed(admin("GET", f"/lab/mailbox/{box}")["messages"]):
        if field in msg:
            return msg[field]
    return None


def cohort():
    people, counts = [], {}
    for idx, persona in sorted(SW.cohort().items()):
        a = W.accounts()[idx]
        t = W.today(a)
        k = counts[persona] = counts.get(persona, -1) + 1
        ips = world_pool(t["pool"])
        people.append(Person(actor=f"human:{persona}:{k:02d}", persona=persona, browser=t["browser"],
                             ip=ips[a.home_slot % len(ips)], account=idx, email=a.email, goal=SW.GOALS[persona],
                             rd=W.rd_token(t["rd_of"], t["device"]) if t["device"] else None))
    return people


def people():
    """The round's population: the starter's 40 shoppers plus the 80 account holders."""
    return population.personas() + cohort()


def _stop(p, client, outcome, r=None):
    return population._stop(p, client, outcome, r)


class Session:
    """One person at one browser: the calls they make and how they answer a step-up."""

    def __init__(self, p, client, rng):
        self.p, self.c, self.rng, self.h = p, client, rng, api_headers(p.browser)
        self.password = password_for(p.account)
        self.info = None

    def facts(self):
        if self.info is None:
            self.info = admin("GET", f"/lab/st/channels/{self.p.email}")
        return self.info

    def call(self, method, path, body=None):
        """One request; a step-up is answered once per kind and the request retried. Returns (response, ok)."""
        for _ in range(4):
            r = self.c.post(path, json=body or {}, headers=self.h) if method == "POST" else self.c.get(path, headers=self.h)
            err = (r.json().get("error") or {}) if r.headers.get("Content-Type", "").startswith("application/json") else {}
            if r.status_code == 403 and err.get("code") == "challenge_required":
                kind = err["challenge"]
                self.p.result.setdefault("prompts", []).append(kind)
                if not self.satisfy(kind, err.get("payload") or {}):
                    return r, False
                continue
            return r, True
        return r, False

    def satisfy(self, kind, payload):
        _sleep(self.rng, 4.0, 12.0)
        verify = lambda answer: self.c.post("/api/challenge/verify", json={"type": kind, "answer": answer},      # noqa: E731
                                            headers=self.h).status_code == 200
        if kind == "sudo":
            return verify({"password": self.password})
        if kind == "otp_session":
            if self.p.persona == "no_inbox" or payload.get("channel") is None:
                return False
            return verify({"code": latest(self.p.email, "code")})
        if kind == "sms_otp":
            if payload.get("channel") is None:
                return False
            return verify({"code": latest(f"sms:{self.p.email}", "code")})
        if kind == "device_confirm":
            if payload.get("channel") is None or "request_id" not in payload:
                return False
            ok = self.c.post(f"/lab/devices/{self.facts()['uid']}/{payload['request_id']}/approve",
                             json={"number": payload["number"]}).status_code == 200
            return ok and verify({"request_id": payload["request_id"]})
        if kind == "kba":
            truth, answers = self.facts(), {}
            known = {"postcode": truth["postcode"], "card_last4": truth["saved_card_last4"],
                     "last_order_total": truth["last_order_total"], "member_month": truth["member_month"]}
            for q in payload.get("questions", []):
                right = self.rng.random() < RECALL[q["id"]]
                answers[q["id"]] = known[q["id"]] if right else "unknown"
            return verify({"answers": answers})
        return False

    def saved_address_id(self):
        items = self.c.get("/api/account", headers=self.h).json().get("addresses") or []
        return items[0]["id"] if items else None

    def fill_cart(self):
        r = self.c.get("/api/products?category=jackets", headers=self.h)
        item = next((i for i in r.json().get("items", []) if i.get("sizes")), None)
        self.c.post("/api/cart/add", json={"sku": item["sku"], "size": item["sizes"][0], "qty": 1}, headers=self.h)

    def settle(self, r):
        """Turn the response to the goal request into an outcome."""
        if r.status_code == 202:
            body = r.json() if r.content else {}
            extra = admin("GET", f"/lab/account/changes?user={self.p.email}&status=pending").get("items") or []
            hours = body.get("hold_h") or (((extra[-1].get("extra") or {}).get("hold") or {}).get("hours") if extra else None)
            self.p.result["delay_h"] = hours
            return _stop(self.p, self.c, "delayed", r)
        return _stop(self.p, self.c, "goal_met" if r.status_code in (200, 201) else "goal_missed", r)


def sign_in(s):
    """Chapter 5's login. Returns None on success, else the stopping outcome."""
    p = s.p
    r = s.c.post("/api/login", json={"email": p.email, "password": s.password}, headers=s.h)
    if r.status_code == 403 and (r.json().get("error") or {}).get("code") == "challenge_required":
        kind = r.json()["error"]["challenge"]
        p.result.setdefault("login_prompts", []).append(kind)
        if p.persona == "no_inbox":
            return _stop(p, s.c, "stuck_on_challenge", r)
        _sleep(s.rng, 8.0, 25.0)
        code = latest(p.email, "code")
        r = s.c.post("/api/challenge/verify", json={"type": kind, "answer": {"code": code}}, headers=s.h)
        if r.status_code != 200:
            return _stop(p, s.c, "stuck_on_challenge", r)
    elif r.status_code != 200:
        return _stop(p, s.c, "blocked" if r.status_code in (403, 429) else "failed", r)
    return None


def goal(s):
    p, persona = s.p, s.p.persona
    if persona in ("routine",):
        s.fill_cart()
        r, ok = s.call("POST", "/api/checkout", {"address_id": s.saved_address_id()})
    elif persona == "rotator":
        r, ok = s.call("POST", "/api/account/password", {"current_password": s.password, "new_password": f"new-{s.password}"})
    elif persona in ("mover", "cgnat_phone"):
        r, ok = s.call("POST", "/api/account/address", NEW_ADDRESS)
        if ok and r.status_code == 200 and persona == "mover":
            _sleep(s.rng, 2.0, 6.0)
            s.fill_cart()
            r, ok = s.call("POST", "/api/checkout", {"address_id": s.c.get("/api/account", headers=s.h).json()["addresses"][-1]["id"]})
    elif persona == "traveller":
        s.fill_cart()
        r, ok = s.call("POST", "/api/checkout", HOTEL)
    elif persona in ("card_expired", "new_phone"):
        r, ok = s.call("POST", "/api/account/card", {"card": f"4000056655{p.account:06d}"})
    elif persona in ("gift_giver", "shared_family"):
        r, ok = s.call("POST", "/api/gift-cards/redeem", {"code": s.facts()["gift_code"]})
    elif persona == "no_inbox":
        new = f"fresh.user{p.account}@example.test"
        r, ok = s.call("POST", "/api/account/email", {"new_email": new})
        if ok and r.status_code == 200:
            link = latest(new, "confirm_url")
            r = s.c.get(link, headers=s.h)
    else:
        raise ValueError(persona)
    if not ok:
        return _stop(p, s.c, "goal_missed", r)
    return s.settle(r)


def scenario_ch6(p, client, rng):
    """Browse for the starter's shoppers; sign in and get something done for the account holders."""
    if not isinstance(p, Person):
        return population.scenario_browse(p, client, rng)
    if p.rd:
        client.set_cookie("rd", p.rd)
    s = Session(p, client, rng)
    _sleep(rng, 0.0, 5.0)
    _sleep(rng, 2.0, 6.0)                              # type the email and password
    stopped = sign_in(s)
    if stopped is not None:
        return stopped
    _sleep(rng, 2.0, 8.0)                              # decide what to do
    return goal(s)


population.SCENARIOS["ch6"] = scenario_ch6


def friction(results):
    """(met a step-up or a hold at the goal, total) over the 80 account holders."""
    mine = [r for r in results if r.get("persona") in PERSONAS]
    return sum(1 for r in mine if r.get("prompts") or r.get("outcome") == "delayed"), len(mine)


def delays(results):
    """Hours each delayed person waited (lab hours), sorted."""
    return sorted(r["delay_h"] for r in results if r.get("outcome") == "delayed" and r.get("delay_h"))


if __name__ == "__main__":
    import json
    import random
    from labclient import LabClient
    for q in cohort()[:3]:
        print(json.dumps(scenario_ch6(q, LabClient(q.actor, ip=q.ip), random.Random(1)), default=str))
