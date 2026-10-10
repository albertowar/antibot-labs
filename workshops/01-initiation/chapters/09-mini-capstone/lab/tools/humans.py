"""
W1 Ch9 — The 40 shoppers: the other half of every measurement.

A defense is only as good as what it costs real customers. These simulated
shoppers browse like people (land, look, fill the form, pay) from the kinds
of networks and browsers real customers use, including the awkward ones
that every layer in this workshop has a false-positive story about:

    persona          n  network                    why it is here
    ---------------  -- -------------------------  ---------------------------------
    home             24 home broadband, own IP     the easy majority (Chrome, Firefox, Safari)
    mobile_cgnat      8 2 carrier NAT IPs, shared  per-IP rate limits and trap flags (Ch2, Ch8)
      (1 of them switches from home Wi-Fi to cellular mid-checkout: Ch5's session binding)
    consumer_vpn      3 commercial VPN egress      IP reputation (Ch3)
    private_relay     2 iCloud Private Relay       datacenter ranges (Ch3)
    old_chrome        1 Chrome 138, home           stale-version rule (Ch4)
    autofill          1 Chrome, home, 1.2-1.6 s    form timing and honeypot naming (Ch5, Ch8)
    no_js             1 Firefox with JS disabled   JS cookie and proof of work (Ch5, Ch7)

Simulation trade-off: the shoppers are Python, not browsers. Where a
browser would run the page's JavaScript, they do the same work in Python
(set js_ok, solve the proof of work) and then sleep, so the proof of work
costs them what it costs the page's solver in a real browser
(BROWSER_HASHES_PER_SECOND), not what it costs Python.

Run on its own against the store (one drop's worth of shoppers):
    python tools/humans.py
"""

import hashlib
import json
import random
import sys
import threading
import time
from dataclasses import dataclass, field

import browsers
from labnet import BASE_URL, LabClient, form_fields, js_nonce, pow_bits, world_pool

BROWSER_HASHES_PER_SECOND = 80_000   # measured: WebCrypto in headless Chromium 153, one hash per await
AUTOFILL_NAMES = {"email", "email2", "phone", "tel", "name", "fullname", "address", "zip", "postcode", "city"}
SEED = 7


@dataclass
class Persona:
    actor: str
    persona: str
    browser: tuple
    ip: str
    checkout_ip: str = None     # set when the shopper changes network before paying
    js: bool = True
    fill: tuple = (2.0, 6.0)    # seconds spent on the form
    autofill: bool = False
    result: dict = field(default_factory=dict)


def personas(seed=SEED):
    rng = random.Random(seed)
    home, cgnat = world_pool("home_broadband"), world_pool("mobile_cgnat")
    vpn, relay = world_pool("consumer_vpn"), world_pool("private_relay")
    desktop = ([("chrome", 153, "windows")] * 10 + [("chrome", 153, "macos")] * 5 +
               [("firefox", 155)] * 5 + [("safari", "macos")] * 4)
    phones = [("safari", "ios")] * 5 + [("chrome", 153, "android")] * 3
    people = []
    for i, browser in enumerate(desktop):
        people.append(Persona(f"human:home:{i:02d}", "home", browser, home.pop()))
    for i, browser in enumerate(phones):
        people.append(Persona(f"human:mobile_cgnat:{i:02d}", "mobile_cgnat", browser, cgnat[0 if i < 6 else 1]))
    people[-1].ip, people[-1].checkout_ip = home.pop(), cgnat[1]          # leaves the house mid-checkout
    for i in range(3):
        people.append(Persona(f"human:consumer_vpn:{i:02d}", "consumer_vpn", ("chrome", 153, "windows"), vpn[i]))
    for i in range(2):
        people.append(Persona(f"human:private_relay:{i:02d}", "private_relay", ("safari", "macos"), relay[i]))
    people.append(Persona("human:old_chrome:00", "old_chrome", ("chrome", 138, "windows"), home.pop()))
    people.append(Persona("human:autofill:00", "autofill", ("chrome", 153, "windows"), home.pop(),
                          fill=(1.2, 1.6), autofill=True))
    people.append(Persona("human:no_js:00", "no_js", ("firefox", 155), home.pop(), js=False))
    rng.shuffle(people)
    return people


def solve_like_a_browser(challenge, bits):
    """Do the page's proof of work, then wait as long as a browser would have taken."""
    started = time.perf_counter()
    prefix, counter = f"{challenge}:".encode(), 0
    target = 1 << (256 - bits)
    while int.from_bytes(hashlib.sha256(prefix + str(counter).encode()).digest(), "big") >= target:
        counter += 1
    browser_time = (counter + 1) / BROWSER_HASHES_PER_SECOND
    time.sleep(max(0.0, browser_time - (time.perf_counter() - started)))
    return counter, browser_time


def shop(p, rng):
    """One shopper's visit. Fills p.result with what happened to them."""
    r = p.result
    r.update(actor=p.actor, persona=p.persona, outcome=None, pow_seconds=0.0, max_bits=0, retries=0)
    client = LabClient(p.actor, ip=p.ip, rng=rng)

    def visit(path, kind, referer=None):
        resp = client.get(path, browsers.headers_for(p.browser, kind, BASE_URL, referer))
        if p.js and resp.status_code == 200 and js_nonce(resp.text):
            client.set_cookie("js_ok", js_nonce(resp.text)[::-1])     # what the page script does
        return resp

    def stop(outcome, status=None):
        r.update(outcome=outcome, status=status, requests=client.requests)

    time.sleep(rng.uniform(0, 6))                                     # sees the drop announcement
    landing = visit("/", "typed")
    if landing.status_code != 200:
        return stop("blocked", landing.status_code)
    time.sleep(rng.uniform(0.5, 2.0))
    page = visit("/drop", "link", BASE_URL + "/")
    if page.status_code != 200:
        return stop("blocked", page.status_code)
    time.sleep(rng.uniform(*p.fill))

    for attempt in range(3):
        fields = form_fields(page.text)
        data = {"csrf": fields.get("csrf", ""), "email": f"{p.actor.replace(':', '.')}@example.com", "size": "M"}
        if p.autofill:
            data.update({name: data["email"] for name in fields if name in AUTOFILL_NAMES})
        if "pow_challenge" in fields:
            bits = pow_bits(page.text)
            r["max_bits"] = max(r["max_bits"], bits)
            if not p.js:
                return stop("stuck_on_challenge")                    # no JavaScript, no proof of work
            data["pow_challenge"] = fields["pow_challenge"]
            data["pow_counter"], seconds = solve_like_a_browser(fields["pow_challenge"], bits)
            r["pow_seconds"] += seconds
        resp = client.post("/checkout", data, browsers.headers_for(p.browser, "post", BASE_URL, BASE_URL + "/drop"),
                           ip=p.checkout_ip)
        r["verdict"] = f"{resp.headers.get('X-Lab-Verdict')} {resp.headers.get('X-Lab-Score')}"
        r["signals"] = resp.headers.get("X-Lab-Signals", "")
        if resp.status_code == 200 and "Order" in resp.text:
            return stop("bought", 200)
        if resp.status_code == 410:
            return stop("sold_out", 410)
        if resp.status_code == 401:                                   # a fresh challenge came back
            r["retries"] += 1
            page = resp
            continue
        if resp.status_code == 429:
            r["retries"] += 1
            time.sleep(2)
            continue
        return stop({403: "blocked", 409: "over_cap", 400: "bad_form"}.get(resp.status_code, "error"),
                    resp.status_code)
    return stop("gave_up", resp.status_code)


def safe_shop(p, rng):
    try:
        shop(p, rng)
    except Exception as exc:                  # a timeout or a dead store: report it, don't hide it
        p.result.update(outcome="error", status=None, error=repr(exc)[:200])


def run(seed=SEED):
    people = personas(seed)
    threads = [threading.Thread(target=safe_shop, args=(p, random.Random(f"{seed}:{p.actor}"))) for p in people]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return [p.result for p in people]


if __name__ == '__main__':
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else SEED
    results = run(seed)
    if "--json" in sys.argv:
        print(json.dumps(results))
        sys.exit(0)
    for res in sorted(results, key=lambda x: x["actor"]):
        friction = f"PoW {res['max_bits']} bits {res['pow_seconds']:.1f}s" if res["max_bits"] else ""
        checkout = f"checkout: {res['verdict']} {res['signals']}" if res.get("verdict") else ""
        print(f"  {res['actor']:<26} {res['outcome']:<18} {friction:<22} {checkout}")
    hurt = [res for res in results if res["outcome"] not in ("bought", "sold_out")]
    print(f"\n  {sum(res['outcome'] == 'bought' for res in results)} bought, "
          f"{len(hurt)} stopped by a defense (false positives)")
