"""
Chapter 9 shoppers: the 40 people who want a hoodie on Drop Day.

The starter's shoppers are Python, not browsers, so this module gives them what a browser does on this
store's drop page, using only what the page shows:

  js_hook        runs the page's one-line script: the js_ok cookie (Chapter 5). A shopper with JavaScript
                 off (`no_js`) never sets it, and cannot solve a proof of work (Chapter 7 hook, shared
                 with tools/personas_ch7.py)
  fill_form      sends what a person can touch: the hidden fields as they came (csrf, the timing token),
                 the email, the first size. A sighted person never touches the honeypot; the `autofill`
                 persona fills every text box that has a layout box, off-screen or not (Chapter 8)
  scenario_drop_day
                 home page, think, drop page, fill, buy. If the store answers the POST with a proof of
                 work (a phone that changed network mid-checkout), solve it and submit once more

A shopper is HURT (outcome blocked, stuck_on_challenge, gave_up or trapped) if the store stopped, faked
or made them give up. The scenario asks the store directly: a trap signal on a human's request is a false
positive even when the page looked fine ("Order confirmed", but nothing was bought).

    persona        n  what it is                              hurt when
    -------------  -- -------------------------------------- -----------------------------------------
    consumer_vpn    3  commercial VPN egress                   IP reputation scores 40 (a block before
                                                               Round 4, a proof of work after)
    mobile_cgnat    8  phones behind two carrier addresses     shared rate limits; the last one leaves
                                                               its Wi-Fi mid-checkout (asn_changed, and a
                                                               pass bound to the old address)
    no_js           1  JavaScript off                          the proof of work is a wall
    autofill        1  browser autofill, fills in 1.2-1.6 s    the honeypot has a box, or MIN_FILL_SECONDS
                                                               is above 1.2 s
    (the rest)     27  home, relay, old Chrome                 should be untouched

These are MODELS. Real autofill and real phones differ by browser and version.

    python tools/personas_ch9.py [--n 40]       # the shoppers alone, at whatever level the store runs
"""

import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import browsers  # noqa: E402
import personas_ch7  # noqa: E402  (registers the proof-of-work hook; imported here so the order is explicit)
import population  # noqa: E402
import trapkit  # noqa: E402
from labclient import BASE_URL  # noqa: E402

SKU = "lab-hoodie-1"
PATH = f"/drop/{SKU}"
population.HURT |= {"trapped", "gave_up"}
NONCE = re.compile(r'var n = "([0-9a-f]{16})"')


class DropForm(trapkit.FormParser):
    """The drop form (class "buy", no id) with the attributes of every element around each input."""

    def handle_starttag(self, tag, attrs):
        if tag == "form" and "buy" in (dict(attrs).get("class") or "").split():
            self.depth = len(self.stack)
        super().handle_starttag(tag, attrs)


def parse_form(html):
    parser = DropForm("\0")
    parser.feed(html)
    for field in parser.inputs:
        if not field["_label"]:
            field["_label"] = parser.labels.get(field.get("id"), "")
    return [f for f in parser.inputs if f.get("name")]


def js_hook(p, client, r):
    """After each page load: a browser with JavaScript runs the body_end script and sets js_ok."""
    if p.js and r.status_code == 200:
        m = NONCE.search(r.text)
        if m:
            client.set_cookie("js_ok", m.group(1)[::-1])


def install():
    if js_hook not in population.PAGE_HOOKS:
        population.PAGE_HOOKS.append(js_hook)


install()


def fill_form(p, fields, css, email):
    """The POST body this person would send: the fields they touch, and the hidden ones as they came."""
    data, touched = {}, []
    for f in fields:
        name, kind = f["name"], f.get("type", "text")
        if kind == "hidden":
            data[name] = f.get("value", "")                     # a browser submits hidden inputs as they are
        elif kind == "radio":
            if name not in data or "checked" in f:
                data[name] = f.get("value", "")
        elif kind == "email":
            data[name] = email
        elif p.autofill and trapkit.box(f, css) != "none":       # autofill fills what it can reach, focusable or not
            data[name] = email
            touched.append(name)
        # a sighted person never touches a field they cannot see
    return data, touched


def _stuck(p, r):
    """Why a 403 with a proof-of-work page ended the visit."""
    pw = p.result.get("pow") or {}
    return "gave_up" if pw.get("gave_up") else ("stuck_on_challenge" if pw.get("no_js") else "blocked")


def scenario_drop_day(p, client, rng):
    _visit, _post, _stop = population._visit, population._post, population._stop
    time.sleep(rng.uniform(0, 6))
    r = _visit(p, client, "/", "typed")
    if r.status_code != 200:
        return _stop(p, client, _stuck(p, r) if r.status_code == 403 else "blocked", r)
    time.sleep(rng.uniform(0.5, 2.0))
    r = _visit(p, client, PATH, "link", BASE_URL + "/")
    if r.status_code != 200:
        return _stop(p, client, _stuck(p, r) if r.status_code == 403 else "blocked", r)
    fields = parse_form(r.text)
    if not any(f["name"] == "csrf" for f in fields):
        return _stop(p, client, "sold_out", r)                    # the form is gone: nothing left to buy
    css = trapkit.parse_css(client.get("/static/css/traps.css").text)
    email = f"{p.actor.replace(':', '.')}@example.test"
    data, touched = fill_form(p, fields, css, email)
    p.result["touched_hidden"] = touched
    time.sleep(rng.uniform(*p.fill))
    if p.checkout_ip:
        client.ip = p.checkout_ip                                 # the phone left its Wi-Fi: everything from here is the new network
    for attempt in (1, 2):
        r = _post(p, client, PATH, data, BASE_URL + PATH)
        if r.status_code == 403 and "pow-payload" in r.text and attempt == 1:
            for hook in population.PAGE_HOOKS:                    # the pass was bound elsewhere: solve again, then resubmit
                hook(p, client, r)
            fresh = parse_form(client.last.text) if client.last is not None and client.last.status_code == 200 else []
            if fresh:
                data, _ = fill_form(p, fresh, css, email)
            time.sleep(rng.uniform(*p.fill))                      # the form came back empty: type it again
            continue
        break
    if trapkit.tripped(r):
        return _stop(p, client, "trapped", r)                    # a fake success is still a harm
    if r.status_code == 200 and "order-confirmed" in r.text:
        return _stop(p, client, "bought", r)
    if r.status_code == 410:
        return _stop(p, client, "sold_out", r)
    return _stop(p, client, _stuck(p, r) if r.status_code == 403 and "pow-payload" in r.text else
                 ("blocked" if r.status_code in (403, 429) else "failed"), r)


population.SCENARIOS["drop_day"] = scenario_drop_day


def slowed(results, seconds=1.0):
    """Shoppers who waited at least `seconds` on a proof of work (they were slowed, not stopped)."""
    return [r for r in results if (r.get("pow") or {}).get("wait_s", 0) >= seconds]


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=None)
    args = ap.parse_args()
    out = population.run("drop_day", n=args.n)
    personas_ch7.print_pow(out)
