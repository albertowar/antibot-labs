"""
W3 Ch1's shoppers: the starter's 40 people, now holding a phone.

Every shopper logs in to the Lab Runner app as their own seed account and buys the drop through the genuine
flow (nonce, bound verdict, buy). What changes from person to person is the DEVICE, and with it the verdict the
provider honestly signs:

    persona          n   device (verdict)                         why it is here
    ---------------  --  ---------------------------------------  --------------------------------------------
    home            24   pixel8, iphone15, pixel8, pixel6-old     the easy majority: strong or device integrity
    mobile_cgnat     8   iphone15 / pixel8, two shared addresses  carrier NAT: eight phones, two addresses
    private_relay    2   iphone15                                 Safari customers behind a relay
    autofill         1   pixel6-old                               older, certified; restores a backup mid-checkout
    old_chrome       1   old-uncertified (basic)                  a cheap Android that never passed certification
    no_js            1   rooted (basic)                           an unlocked bootloader: a power user
    consumer_vpn     3   graphene (none, UNRECOGNIZED_VERSION)    privacy-conscious customers on a de-Googled ROM

Round 5 adds one life event. The autofill shopper restores their phone from a backup between login and
checkout: the bearer token comes back with the backup, the keystore key does not (MobileApp.reinstall). At
every level this changes nothing they can see; a device-bound session notices, and that is its cost.

The last three groups return weak integrity for honest reasons. Round 4's defense has to stop the emulator
farm without turning them away; watch them in the checkpoint: they are the false-positive bill.

Outcomes: bought, challenged (the gate's challenge band, which this store enforces as a refusal: there is no
step-up behind it), blocked (a plain refusal; this is what `humans_hurt` counts), sold_out, failed.
"""

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

import population  # noqa: E402
from mobile_sdk import DROP_SKU, MobileApp  # noqa: E402
from demo_site.seed import password_for, username  # noqa: E402

WEAK = {"old_chrome": "old-uncertified", "no_js": "rooted", "consumer_vpn": "graphene"}


def device_for(p):
    """The device profile (defenses/mobile_core.DEVICE_PROFILES) this shopper owns."""
    n = int(p.actor.rsplit(":", 1)[1])
    if p.persona in WEAK:
        return WEAK[p.persona]
    if p.persona == "home":
        return ["pixel8", "iphone15", "pixel8", "pixel6-old"][n % 4]
    if p.persona == "mobile_cgnat":
        return ["iphone15", "pixel8"][n % 2]
    if p.persona == "autofill":
        return "pixel6-old"
    return "iphone15"


def scenario_mobile(p, client, rng):
    time.sleep(rng.uniform(0, 4))
    app = MobileApp(p.actor, device=device_for(p), serial=p.actor, ip=p.ip)
    login = app.login(username(p.account), password_for(p.account))
    if login.status_code != 200:
        outcome, status = ("blocked" if login.status_code in (403, 429) else "failed"), login.status_code
    else:
        time.sleep(rng.uniform(0.5, 2.0))
        if p.persona == "autofill":
            app.reinstall()                       # restored from a backup: same token, new key
        app.buy(DROP_SKU)
        res = app.result()
        status = res["status"]
        outcome = {"bought": "bought", "challenged": "challenged", "blocked": "blocked", "refused": "sold_out"}.get(res["outcome"], "failed")
    p.result.update(outcome=outcome, status=status, requests=app.client.requests, verdict=app.client.verdict(),
                    device=device_for(p))
    return p.result


population.SCENARIOS["ch1_mobile"] = scenario_mobile
