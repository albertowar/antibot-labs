"""
raffle_world: who is in the draw. Pure data and deterministic (WORLD_SEED), with no Flask and no Redis,
so three parties can share it without talking to each other:

  * demo_site/ext/raffle.py seeds the store's accounts from it when a round opens the event
    (POST /lab/raffle/open): ages, order histories, saved cards, saved addresses, verified emails;
  * tools/personas_ch9.py builds the 110 fans from it (each person's account, network and browser);
  * attacks/_common.py reads each crew's KIT from it (the accounts that crew bought or recruited).

The split matters for honesty. The store never reads a kit, and an attack never reads anyone else's
accounts. The one place the two meet is the draw itself, which sees only what an entry carries.

Everything is invented. Names are common given names plus surnames, every email sits on an RFC 2606
domain (example.com, example.net, example.org, *.example, *.test) and every card number is made of a
synthetic prefix and hash digits. `gmail.example` plays Gmail in this lab: the lab's normalizer treats it
like gmail.com (dots ignored, "+tag" ignored); no real mailbox is named anywhere.

The cast (cohort -> accounts):

    fans (people, 110 accounts)
      loyal 52          aged accounts with orders, a saved card, an address of their own
      household 9       three households of three people: one address, three accounts, three cards
      apartment 5       five unrelated people in one building (10 Harbour Street, five unit numbers)
      shared_card 4     two couples who each pay with one card, at two different addresses
      new_real_fan 12   accounts 1 to 5 days old, no orders (two never clicked the verify link)
      power_user 8      aged, many orders
      gift_buyer 6      aged; the pair ships to someone else's address
      traveller 6       aged; on consumer-VPN and privacy-relay addresses
      no_saved_card 8   aged, no card on file: they add one when they win
    crews (accounts a reseller owns)
      aged_farm 100     bought aged accounts, every pair to one drop address, virtual cards from one BIN
      jig_farm 80       aged accounts; the drop address jigged ("3 Pier Ave Apt 7", "#12", "Unit 31") and
                        the mailbox jigged ("m.arlowe+9@gmail.example"); virtual cards from one BIN
      spread_farm 48    aged accounts created in one batch, a distinct clean address each, mailboxes on
                        six domains, virtual cards from one BIN; the pairs go to a forwarder when they win
      crowd 24          paid real people: own account, own card, own home (the honest residual)
    (account_farm and patient_farm register their own fresh accounts while they run.)
"""

import hashlib
import os
import random
from dataclasses import dataclass

WORLD_SEED = 20261021
SKU = "lab-runner-9"
SIZE = "10"
HERE = os.path.dirname(os.path.abspath(__file__))
RESHIPPERS_FILE = os.path.join(HERE, "..", "..", "data", "reshippers.txt")

FIRST = ["Ada", "Ben", "Cleo", "Dev", "Elif", "Finn", "Gus", "Hana", "Ivo", "Jun", "Kai", "Lena", "Mo", "Nia", "Oren",
         "Pia", "Quin", "Rosa", "Sam", "Tess", "Uma", "Vic", "Wren", "Xavi", "Yara", "Zed", "Alma", "Bruno", "Cora", "Dara"]
LAST = ["Abbott", "Baxter", "Cole", "Duarte", "Ellis", "Frost", "Grant", "Hughes", "Iyer", "Jensen", "Khan", "Lowe", "Mills",
        "Nolan", "Ortiz", "Price", "Quill", "Reyes", "Stone", "Tran", "Usher", "Vance", "Wong", "Young", "Zhou"]
STREETS = ["Maple", "Cedar", "Elm", "Willow", "Birch", "Aspen", "Laurel", "Hazel", "Juniper", "Linden", "Spruce", "Alder",
           "Poplar", "Rowan", "Sycamore", "Chestnut", "Larch", "Hawthorn", "Cypress", "Magnolia"]
SUFFIX = ["Street", "Avenue", "Road", "Lane", "Court", "Drive", "Way"]
CITIES = [("Portland", "97201"), ("Boulder", "80301"), ("Madison", "53703"), ("Asheville", "28801"), ("Burlington", "05401"),
          ("Austin", "78701"), ("Pittsburgh", "15201"), ("Duluth", "55802"), ("Santa Fe", "87501"), ("Spokane", "99201")]
DOMAINS = ["example.com", "example.net", "example.org", "mail.example", "post.example", "gmail.example"]
GMAIL_LIKE = ("gmail.com", "googlemail.com", "gmail.example")

FAN_BINS = [f"{b}" for b in (411111, 424242, 453201, 476173, 491618, 400551, 520082, 545454, 510510, 555544, 222300, 371449,
                              378282, 601100, 353011, 630495, 400000, 450875, 462239, 479213, 485932, 516730, 524363,
                              527400, 541333, 552100, 559958, 589916, 620110, 670123)]
BIN_ACCOUNT_FARM = "489120"
BIN_AGED_FARM = "559876"
BIN_JIG_FARM = "531277"
BIN_SPREAD_FARM = "403899"

COHORTS = {"loyal": 52, "household": 9, "apartment": 5, "shared_card": 4, "new_real_fan": 12, "power_user": 8,
           "gift_buyer": 6, "traveller": 6, "no_saved_card": 8}
CREWS = {"aged_farm": 100, "jig_farm": 80, "spread_farm": 48, "crowd": 24}
DROP_ADDRESS = ("7 Depot Row", "Newark", "19711")                  # the account farm's shared drop address
AGED_DROP = ("15 Quay Lane", "Newark", "19713")                    # the aged farm's
JIG_BASE = "3 Pier"                                                # jig_farm: "3 Pier Avenue Apt 7" and friends
JIG_CITY = ("Newark", "19711")
APARTMENT_BASE = ("10 Harbour Street", "Portsmouth", "03801")


@dataclass(frozen=True)
class Acct:
    email: str
    password: str
    name: str
    cohort: str             # a fan cohort or a crew name
    crew: str               # "" for a person
    n: int                  # index inside the cohort
    age_days: float
    paid_orders: int        # paid orders in the account's history
    verified: bool          # the email-verification flag (simulated: the store has no such column)
    card: str               # saved card number ("" for none)
    address: tuple          # saved address (line1, city, postcode) or ()
    group: str = ""         # household / couple / building id


def _h(*parts):
    return hashlib.sha256((str(WORLD_SEED) + ":" + ":".join(str(p) for p in parts)).encode()).hexdigest()


def _digits(tag, n):
    return str(int(_h("digits", tag), 16) % 10 ** n).zfill(n)


def card_number(bin6, tag):
    """A 16-digit synthetic number: the BIN, then hash digits. Same tag, same number."""
    return bin6 + _digits(tag, 10)


def crew_ja4(crew):
    """The TLS fingerprint a crew's tooling presents (claimed): one per crew, the same on all its accounts."""
    return "t13d1517h2_" + _h("ja4", crew)[:12]


def password_of(cohort, n):
    return f"Raffle-{cohort}-{n:03d}-{_h('pw', cohort, n)[:6]}"


def _name(rng):
    return f"{rng.choice(FIRST)} {rng.choice(LAST)}"


def _email(first_last, n, domain):
    first, last = first_last.lower().split()
    dotted = f"{first}.{last}" if domain.startswith("gmail") else f"{first}{last}"
    return f"{dotted}{n:03d}@{domain}"


def _address(rng, i):
    city, post = CITIES[i % len(CITIES)]
    return (f"{100 + 13 * i} {rng.choice(STREETS)} {rng.choice(SUFFIX)}", city, post)


def _fan_card(i):
    return card_number(FAN_BINS[i % len(FAN_BINS)], f"fan-card-{i}")


def _fans():
    rng = random.Random(WORLD_SEED)
    out, i = [], 0

    def person(cohort, n, **kw):
        nonlocal i
        name = _name(rng)
        domain = DOMAINS[(i + n) % len(DOMAINS)]
        fields = dict(email=_email(name, i, domain), password=password_of(cohort, n), name=name, cohort=cohort, crew="", n=n,
                      age_days=round(rng.uniform(120, 900), 2), paid_orders=rng.randint(1, 4), verified=True,
                      card=_fan_card(i), address=_address(rng, i))
        fields.update(kw)
        i += 1
        return Acct(**fields)

    for n in range(COHORTS["loyal"]):
        out.append(person("loyal", n))
    for h, (line1, city, post) in enumerate([("14 Willow Court", "Madison", "53703"), ("9 Cedar Lane", "Duluth", "55802"),
                                              ("31 Birch Way", "Spokane", "99201")]):
        for k in range(3):
            out.append(person("household", h * 3 + k, address=(line1, city, post), group=f"hh{h}",
                              age_days=round(rng.uniform(300, 1500), 2), paid_orders=rng.randint(1, 3)))
    units = ["Apt 1", "#2", "Unit 3", "Apartment 4", "Ste 5"]
    for k in range(COHORTS["apartment"]):
        line1, city, post = APARTMENT_BASE
        out.append(person("apartment", k, address=(f"{line1} {units[k]}", city, post), group="harbour",
                          age_days=round(rng.uniform(100, 800), 2), paid_orders=rng.randint(0, 2)))
    for c in range(2):                                           # two couples, one card each, two addresses
        shared = card_number("476173", f"couple-{c}")
        for k in range(2):
            out.append(person("shared_card", c * 2 + k, card=shared, group=f"couple{c}"))
    for k in range(COHORTS["new_real_fan"]):
        out.append(person("new_real_fan", k, age_days=round(rng.uniform(1, 5), 2), paid_orders=0, verified=k >= 2))
    for k in range(COHORTS["power_user"]):
        out.append(person("power_user", k, age_days=round(rng.uniform(500, 1500), 2), paid_orders=rng.randint(6, 12)))
    for k in range(COHORTS["gift_buyer"]):
        out.append(person("gift_buyer", k, age_days=round(rng.uniform(200, 800), 2), paid_orders=rng.randint(2, 5)))
    for k in range(COHORTS["traveller"]):
        out.append(person("traveller", k, age_days=round(rng.uniform(150, 900), 2)))
    for k in range(COHORTS["no_saved_card"]):
        out.append(person("no_saved_card", k, card="", age_days=round(rng.uniform(100, 600), 2), paid_orders=rng.randint(1, 3)))
    return out


def gift_address(n):
    """Where a gift buyer's pair goes: a different person's door, never a saved address."""
    rng = random.Random(f"gift-{n}")
    city, post = CITIES[(n * 3 + 1) % len(CITIES)]
    return (f"{700 + 11 * n} {rng.choice(STREETS)} {rng.choice(SUFFIX)}", city, post)


def reshippers():
    """The forwarders (street, city, postcode) from data/reshippers.txt."""
    out = []
    with open(RESHIPPERS_FILE) as fh:
        for ln in fh:
            if ln.strip() and not ln.startswith("#"):
                street, city, post = [x.strip() for x in ln.split(",")]
                out.append((street, city, post))
    return out


def _dot_variants(base, k):
    """A deterministic dotted form of `base` ("marlowe" -> "m.arlo.we"): the k-th jig of one mailbox."""
    rng = random.Random(f"dots-{base}-{k}")
    cuts = sorted(rng.sample(range(1, len(base)), rng.randint(1, 3)))
    out, prev = [], 0
    for c in cuts:
        out.append(base[prev:c])
        prev = c
    out.append(base[prev:])
    return ".".join(out)


def _crews():
    rng = random.Random(WORLD_SEED + 1)
    out = []
    domains = ["mail.example", "post.example", "inbox.example", "webmail.example", "example.net", "example.org"]
    for n in range(CREWS["aged_farm"]):                          # lazy: one drop address, written the same way
        out.append(Acct(email=f"agedacct{n:03d}@{domains[n % 6]}", password=password_of("aged_farm", n),
                        name="Pat Holder", cohort="aged_farm", crew="aged_farm", n=n,
                        age_days=round(rng.uniform(240, 700), 2), paid_orders=1, verified=True,
                        card=card_number(BIN_AGED_FARM, f"aged-card-{n}"), address=AGED_DROP))
    bases = ["marlowe", "kingsley", "hartwell", "pembroke", "whitlock"]
    suffixes = ["Avenue", "Ave", "Ave."]
    unit_forms = ["Apt {n}", "#{n}", "Unit {n}", "Apartment {n}", "Ste {n}"]
    for n in range(CREWS["jig_farm"]):
        base = bases[n % 5]
        line1 = f"{JIG_BASE} {suffixes[(n // 5) % 3]} {unit_forms[n % 5].format(n=n + 1)}"
        out.append(Acct(email=f"{_dot_variants(base, n)}+{n}@gmail.example", password=password_of("jig_farm", n),
                        name="Sam Jigger", cohort="jig_farm", crew="jig_farm", n=n,
                        age_days=round(rng.uniform(190, 260), 2), paid_orders=1, verified=True,
                        card=card_number(BIN_JIG_FARM, f"jig-card-{n}"), address=(line1, JIG_CITY[0], JIG_CITY[1])))
    batch = 310.0
    for n in range(CREWS["spread_farm"]):                        # one 90-minute batch, nothing else in common
        city, post = CITIES[(n * 7) % len(CITIES)]
        out.append(Acct(email=f"{rng.choice(FIRST).lower()}{rng.choice(LAST).lower()}{n:03d}@{domains[(n + 2) % 6]}",
                        password=password_of("spread_farm", n), name="Alex Mule", cohort="spread_farm",
                        crew="spread_farm", n=n, age_days=round(batch + rng.uniform(0, 0.06), 3), paid_orders=1,
                        verified=True, card=card_number(BIN_SPREAD_FARM, f"spread-card-{n}"),
                        address=(f"{3000 + 17 * n} {rng.choice(STREETS)} {rng.choice(SUFFIX)}", city, post)))
    for n in range(CREWS["crowd"]):                              # recruited people: nothing links them
        i = 400 + n
        name = _name(rng)
        out.append(Acct(email=_email(name, i, DOMAINS[n % len(DOMAINS)]), password=password_of("crowd", n), name=name,
                        cohort="crowd", crew="crowd", n=n, age_days=round(rng.uniform(100, 800), 2),
                        paid_orders=rng.randint(0, 3), verified=True, card=_fan_card(i + 50), address=_address(rng, i)))
    return out


_CACHE = {}


def fans():
    if "fans" not in _CACHE:
        _CACHE["fans"] = _fans()
    return list(_CACHE["fans"])


def crews():
    if "crews" not in _CACHE:
        _CACHE["crews"] = _crews()
    return list(_CACHE["crews"])


def accounts():
    return fans() + crews()


def kit(crew):
    """The accounts one crew owns (what its attack script logs in with)."""
    return [a for a in crews() if a.crew == crew]


def cohort(name):
    return [a for a in fans() if a.cohort == name]


# --- what a fresh farm registers --------------------------------------------------------------------

def farm_account(crew, n):
    """(email, password, card) of the n-th account a farm registers while it runs."""
    return (f"{crew}{n:03d}@{('burner.example', 'throwaway.example', 'catchall.example')[n % 3]}",
            f"Farm-{crew}-{n:03d}-{_h('farm', crew, n)[:6]}", card_number(BIN_ACCOUNT_FARM, f"{crew}-card-{n}"))
