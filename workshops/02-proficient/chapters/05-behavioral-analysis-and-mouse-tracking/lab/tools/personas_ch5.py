"""
Chapter 5 shoppers: the 40 population personas, buying the shoe drop with a behavior profile.

tools/population.py's shoppers are Python, not browsers, so nobody runs the drop page's
collector for them. This file registers the scenario "behavior_drop": each shopper loads
the drop page, reads the layout the server drew (the #behavior-form data-layout), has
tools/humans.py synthesise what the collector would have recorded for its profile,
posts it to /api/telemetry like the page would, then submits the form.

Who gets which profile is fixed per persona (PROFILES below), so a cohort's false
positives show up under the same name in every run:

    phones (mobile_cgnat, 8)          touch
    autofill + home:15                password_mgr
    no_js                             none: no JavaScript, so no telemetry at all
    home:00                           voice       home:01-02  keyboard     home:03-04  screen_reader
    home:05-07                        tremor      home:10-12  trackpad (macOS)
    everyone else (18)                mouse

Outcomes, read from the store's X-Lab-Verdict header:

    bought        the gate let the reservation through (order confirmed)
    sold_out      through the gate, but the pair was gone (410)
    challenged    a challenge verdict: friction, listed by the checkpoint, not counted as hurt
    blocked       a block verdict: a false positive, and the checkpoint fails on it

    python tools/population.py --scenario behavior_drop     # once, at the store's current level
"""

import html
import json
import re
import time

import population
import humans
from labclient import BASE_URL, csrf_of

DROP = "/drop/lab-runner-9"

PROFILES = {"human:no_js:00": None, "human:autofill:00": "password_mgr", "human:home:15": "password_mgr",
            "human:home:00": "voice", "human:home:01": "keyboard", "human:home:02": "keyboard",
            "human:home:03": "screen_reader", "human:home:04": "screen_reader",
            "human:home:05": "tremor", "human:home:06": "tremor", "human:home:07": "tremor",
            "human:home:10": "trackpad", "human:home:11": "trackpad", "human:home:12": "trackpad"}


def profile_for(p):
    if p.actor in PROFILES:
        return PROFILES[p.actor]
    return "touch" if p.persona == "mobile_cgnat" else "mouse"


def _layout(page_html):
    m = re.search(r"data-layout='([^']+)'", page_html)
    return json.loads(html.unescape(m.group(1))) if m else None


def _fetch_headers(p):
    """What the page's fetch() sends: the browser's own User-Agent, JSON, same origin."""
    ua = dict(population.browsers.headers_for(p.browser, "link", BASE_URL)).get("User-Agent", "")
    return [("User-Agent", ua), ("Accept", "*/*"), ("Content-Type", "application/json"),
            ("Origin", BASE_URL), ("Referer", BASE_URL + DROP), ("Sec-Fetch-Mode", "cors"), ("Sec-Fetch-Site", "same-origin")]


def scenario_behavior_drop(p, client, rng):
    profile = profile_for(p)
    p.result["profile"] = profile or "no_telemetry"
    time.sleep(rng.uniform(0, 3))
    r = population._visit(p, client, "/", "typed")
    if r.status_code != 200:
        return population._stop(p, client, "blocked", r)
    time.sleep(rng.uniform(0.3, 1.2))
    r = population._visit(p, client, DROP, "link", BASE_URL + "/")
    rel = _layout(r.text) if r.status_code == 200 else None
    if rel is None:
        return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)
    who = humans.identity(rng)
    if profile is not None:
        telemetry, who, _ = humans.make_session(rel, profile, rng)
        t = client.post("/api/telemetry", json=dict(telemetry, kind="behavior"), headers=_fetch_headers(p))
        p.result["telemetry_bytes"] = len(t.request.body or b"")
    time.sleep(rng.uniform(0.3, 1.0))
    data = {"csrf": csrf_of(r.text), "name": who["name"], "email": f"{p.actor.replace(':', '.')}@example.test",
            "size": who["size"]}
    r = population._post(p, client, DROP, data, BASE_URL + DROP, ip=p.checkout_ip)
    verdict = r.headers.get("X-Lab-Verdict")
    p.result.update(score=int(r.headers.get("X-Lab-Score") or 0), signals=r.headers.get("X-Lab-Signals", ""),
                    gate_ms=_gate_ms(r.headers.get("Server-Timing", "")))
    if r.status_code == 200 and "order-confirmed" in r.text:
        return population._stop(p, client, "bought", r)
    if r.status_code == 410:
        return population._stop(p, client, "sold_out", r)
    if verdict == "challenge":
        return population._stop(p, client, "challenged", r)
    return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)


def _gate_ms(server_timing):
    m = re.search(r"gate;dur=([\d.]+)", server_timing)
    return float(m.group(1)) if m else None


population.SCENARIOS["behavior_drop"] = scenario_behavior_drop
