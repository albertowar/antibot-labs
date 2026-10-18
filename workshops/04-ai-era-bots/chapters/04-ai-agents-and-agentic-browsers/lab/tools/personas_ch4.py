"""W4 Ch4's cohort: the starter's 40 shoppers, five more people an agent-aware defense can hurt, and two agents that are welcome.

An agent defense is only worth having if it never costs a customer the sale. Next to the 40 shoppers
(tools/population.py) every checkpoint runs:

  screen_reader (2)   keyboard-only users: Tab, Tab, Enter. Their clicks arrive with detail 0 and no
                      pointer path, exactly the shape an accessibility-tree agent also produces
  voice_control (1)   activates controls through the accessibility tree: detail 0, no keys, no pointer
  rpa_macro (1)       a procurement macro: teleport click AND instant fills. The honest false positive
                      of the behavior layer; it meets the step-up and has to answer it
  first_timer (1)     registers during the drop: a brand-new account with no history, like a fleet's
  agent_user (2)      a person whose OWN agent buys for them: declared (LabAgent), signed by the operator
                      the store trusts, with a mandate their human granted. Welcome, once the store can
                      tell. Labelled `legit:agent_user:NN`, so the scoreboard keeps them out of "bots
                      stopped" and "shoppers hurt"; the checkpoint reports them in their own line.

The shoppers themselves get the input style their kind of client has (mouse, touch, autofill, none at
all for the no-JavaScript one) and send the same telemetry static/js/agent.js would. What happens to
each person comes from their responses, never from a label: a 403 is a stop, a step-up is friction
they answer by reading the lab mailbox, the order page is a sale.

This module offers the cohort (checkpoint.py passes `people=personas`) and registers the `agent_drop` scenario;
checkpoint.py imports it, so every round runs these people. Everything is synthetic: accounts are the
seeded users, the mailbox is the lab's, the operator is a .test domain.

Honest caveat: these are models of people, not people. A defense tuned only on simulated humans learns
the simulator.
"""

import json
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "attacks"))

import browsers  # noqa: E402
import population  # noqa: E402
import synthetic_input as si  # noqa: E402
from _common import (DROP_SKU, LAB_AGENT_UA, OPERATOR, Signer, agent_user_accounts, grant_mandate)  # noqa: E402
from labclient import BASE_URL, csrf_of, form_fields, world_pool  # noqa: E402

HOODIE = "lab-hoodie-1"
PROFILES = os.path.join(HERE, "profiles")
STYLE = {"home": "mouse", "mobile_cgnat": "touch", "consumer_vpn": "mouse", "private_relay": "mouse",
         "old_chrome": "mouse", "autofill": "autofill", "no_js": None}
PROFILE = {"home": "chrome-win", "mobile_cgnat": "safari-ios", "consumer_vpn": "brave-win",
           "private_relay": "chrome-mac", "old_chrome": "vdi-citrix", "autofill": "chrome-mac", "no_js": "firefox-linux",
           "screen_reader": "chrome-win", "voice_control": "chrome-win", "rpa_macro": "office-win",
           "first_timer": "firefox-rfp", "agent_user": "chrome-win"}
_STARTER_PERSONAS = population.personas


def personas(seed=population.SEED, n=None):
    people = _STARTER_PERSONAS(seed)
    for p in people:
        p.kind, p.style, p.sku, p.register = "shopper", STYLE.get(p.persona, "mouse"), HOODIE, False
        p.profile = PROFILE.get(p.persona, "chrome-win")
        if p.persona == "home" and p.browser[0] == "safari":
            p.profile = "chrome-mac"
    eu, corp = world_pool("home_eu"), world_pool("corporate")

    def person(actor, persona, ip, style, account=None, **kw):
        q = population.Persona(actor, persona, ("chrome", 153, "windows"), ip, account=account)
        q.kind, q.style, q.sku, q.register, q.profile = "shopper", style, HOODIE, False, PROFILE[persona]
        for k, v in kw.items():
            setattr(q, k, v)
        people.append(q)
        return q

    for i in range(2):
        person(f"human:screen_reader:{i:02d}", "screen_reader", eu[i], "keyboard", 100 + i)
    person("human:voice_control:00", "voice_control", eu[2], "at", 102)
    person("human:rpa_macro:00", "rpa_macro", corp[0], "rpa", 103)
    person("human:first_timer:00", "first_timer", eu[3], "mouse", None, register=True, browser=("firefox", 155))
    cloud = world_pool("cloud_vm")
    for i in range(2):
        q = population.Persona(f"legit:agent_user:{i:02d}", "agent_user", ("tool",), cloud[40 + i], account=agent_user_accounts()[i])
        q.kind, q.style, q.sku, q.register, q.profile = "agent_user", "agent-user", DROP_SKU, False, ["chrome-win", "chrome-mac"][i]
        people.append(q)
    return people[:n] if n else people



# --- what the page's script would send ------------------------------------------------------------------

def _http_ua(p):
    if p.kind == "agent_user":
        return LAB_AGENT_UA
    return next(v for k, v in browsers.headers_for(p.browser, "typed", BASE_URL) if k == "User-Agent")


def _fp(p, rng):
    """The browser fingerprint the page's script would report for this person's kind of client."""
    with open(os.path.join(PROFILES, f"{p.profile}.json")) as f:
        prof = json.load(f)
    fp = json.loads(json.dumps(prof["fp"]))
    fp.update({"ua": _http_ua(p), "webdriver": False, "automation_globals": []})
    fp["worker"] = {"ua": fp["ua"], "platform": fp["platform"], "hc": fp.get("hc"), "languages": fp.get("languages")}
    if "canvas" in prof.get("farble", []):
        fp["canvas"] = f"{rng.getrandbits(32):08x}"
    return fp


def _json_headers(p, referer=None):
    """A browser's fetch(): its own headers with a JSON body (the L0 header checks look at these too)."""
    return [(k, "application/json" if k == "Content-Type" else v)
            for k, v in browsers.headers_for(p.browser, "post", BASE_URL, referer)] if p.kind != "agent_user" \
        else [("User-Agent", LAB_AGENT_UA), ("Accept-Language", "en-US,en;q=0.9"), ("Sec-Fetch-Mode", "cors"),
              ("Content-Type", "application/json")]


class Session:
    """One person (or one agent) at the keyboard: requests with their headers, plus the page's telemetry."""

    def __init__(self, p, client, rng):
        self.p, self.c, self.rng, self.fp = p, client, rng, _fp(p, rng)
        self.signer = Signer(OPERATOR) if p.kind == "agent_user" else None
        self.stepped_up = False

    def _sign(self, method, path):
        if self.signer is None:
            return []
        p, _, q = path.partition("?")
        return list(self.signer.headers(p, q, method).items())

    def get(self, path, kind="link", referer=None):
        if self.p.kind == "agent_user":
            h = [("User-Agent", LAB_AGENT_UA), ("Accept-Language", "en-US,en;q=0.9"), ("Accept", "text/html,*/*;q=0.8"),
                 ("Sec-Fetch-Mode", "navigate")] + self._sign("GET", path)
            return self.c.get(path, headers=h, allow_redirects=False)
        return population._visit(self.p, self.c, path, kind, referer)

    def form(self, path, data, referer):
        if self.p.kind == "agent_user":
            h = [("User-Agent", LAB_AGENT_UA), ("Accept-Language", "en-US,en;q=0.9"), ("Accept", "text/html,*/*;q=0.8"),
                 ("Sec-Fetch-Mode", "navigate"), ("Content-Type", "application/x-www-form-urlencoded")] + self._sign("POST", path)
            return self.c.post(path, data, headers=h, allow_redirects=False)
        return population._post(self.p, self.c, path, data, BASE_URL + referer)

    def telemetry(self, page, events):
        if self.p.style is None:
            return                                   # JavaScript is off: nothing to send
        h = _json_headers(self.p, BASE_URL + page) + self._sign("POST", "/api/telemetry")
        self.c.post("/api/telemetry", headers=h, json={"kind": "agent", "page": page, "fp": self.fp, "events": events})

    def solve_step_up(self, email, referer):
        """Read the code from the lab mailbox and answer the challenge, like a person with a phone in hand."""
        self.stepped_up = True
        time.sleep(self.rng.uniform(0.6, 1.4))
        msgs = self.c.get(f"/lab/mailbox/{email}").json().get("messages") or []
        if not msgs:
            return False
        r = self.c.post("/api/challenge/verify", headers=_json_headers(self.p, BASE_URL + referer),
                        json={"type": "step_up", "answer": {"code": msgs[-1]["code"]}})
        return r.status_code == 200


def scenario_agent_drop(p, client, rng):
    """Land, sign in (or register), read the drop page, buy. A step-up is answered, not skipped."""
    s = Session(p, client, rng)
    time.sleep(rng.uniform(0, 1.5))
    from demo_site.seed import password_for, username
    if p.kind == "agent_user":
        email, password = username(p.account), password_for(p.account)
        owner = population.LabClient(f"legit:agent_owner:{p.actor[-2:]}", ip=world_pool("home_fiber")[int(p.actor[-2:])])
        mandate, why = grant_mandate(owner, email, password, OPERATOR)
        if mandate is None:
            return population._stop(p, client, "error", None)
    elif p.register:
        email, password, mandate = f"firsttimer.{rng.getrandbits(24):06x}@customers.example", "first-time-buyer-pw", None
    else:
        email, password, mandate = username(p.account), password_for(p.account), None

    r = s.get("/", "typed")
    if r.status_code != 200:
        return population._stop(p, client, "blocked", r)
    time.sleep(rng.uniform(0.3, 0.8))
    if p.register:
        r = s.get("/register", "link", BASE_URL + "/")
        s.telemetry("/register", si.typing_events(rng, [("name", 10), ("email", len(email)), ("password", 18)], si.login_style(p.style)))
        r = s.form("/register", {"csrf": csrf_of(r.text), "name": "First Timer", "email": email, "password": password}, "/register")
        entered = r.status_code in (302, 303)
    else:
        r = s.get("/login", "link", BASE_URL + "/")
        s.telemetry("/login", si.typing_events(rng, [("email", len(email)), ("password", 14)], si.login_style(p.style)))
        r = s.form("/login", {"csrf": csrf_of(r.text), "email": email, "password": password, "next": "/account"}, "/login")
        entered = r.status_code in (302, 303)
    if not entered:
        return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)
    time.sleep(rng.uniform(0.3, 0.8))
    r = s.get(f"/drop/{p.sku}", "link", BASE_URL + "/account")
    if r.status_code != 200:
        return population._stop(p, client, "blocked", r)
    fields = form_fields(r.text)
    dwell = rng.uniform(1.5, 3.0)
    time.sleep(dwell)
    s.telemetry(f"/drop/{p.sku}", si.events_for(p.style or "mouse", rng, dwell * 1000, "drop-buy"))
    data = {"csrf": fields.get("csrf", ""), "size": fields.get("size", "") or "M", "mandate": mandate or ""}
    for attempt in range(2):
        r = s.form(f"/drop/{p.sku}", data, f"/drop/{p.sku}")
        if r.status_code == 403 and 'data-challenge="step_up"' in r.text and attempt == 0:
            if s.solve_step_up(email, f"/drop/{p.sku}"):
                continue
            break
        break
    p.result["stepped_up"] = s.stepped_up
    if r.status_code == 200 and "order-confirmed" in r.text:
        return population._stop(p, client, "bought", r)
    if r.status_code == 410:
        return population._stop(p, client, "sold_out", r)
    refused = r.status_code in (403, 429)
    if p.kind == "agent_user":
        return population._stop(p, client, "refused" if refused else "failed", r)    # a welcome client, not a customer
    return population._stop(p, client, "blocked" if refused else "failed", r)


population.SCENARIOS["agent_drop"] = scenario_agent_drop


def agent_users(results):
    """The two welcome agents: how many bought."""
    rows = [r for r in results if r.get("persona") == "agent_user"]
    return sum(r.get("outcome") == "bought" for r in rows), len(rows)


def friction(results):
    """People who met the step-up (and answered it)."""
    rows = [r for r in results if r.get("actor", "").startswith("human:")]
    return [r["actor"].rsplit(":", 1)[0] for r in rows if r.get("stepped_up")], len(rows)
