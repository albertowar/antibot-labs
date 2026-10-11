"""
Chapter 3: synthetic legitimate users (Section 3.7).

Measures the other half of every defense: how many REAL users it stops.
Each run builds a fresh population of 40 visitors, asks the server for a
session (the same layout the page would draw), synthesises the telemetry
the collector would have recorded, and posts the reservation.

    profile          n   what makes them hard
    mouse           24   125-1000 Hz mice, varied skill, a few slow typists
    trackpad         3   60 Hz, smoother, "clutching" (lift and re-place the finger)
    tremor           3   4-6 Hz tremor of 2-4 px, many corrections, slow
    keyboard         2   Tab through the form, Enter on the button: no pointer at all
    screen_reader    2   like keyboard, slower; activation is a keyboard click
    touch            3   taps (no hover path), virtual keyboard (key "Unidentified")
    password_mgr     2   name and email autofilled: text with no keystrokes
    voice            1   voice control: cursor warps to the target centre, dictated text

How the movement is modelled (and why you should not over-trust it):
mouse paths are built from lognormal velocity strokes, the sigma-lognormal
model of Plamondon's Kinematic Theory: a primary stroke that lands near the
target plus one or two corrective strokes, along gently curved arcs, with
physiological tremor, sampled at the device's polling rate. Typing uses
log-normal hold and inter-key times with natural rollover and occasional
typos. This is a stand-in for a labelled corpus of real traffic. Real
deployments calibrate against their own users, and so do you: Round 0 adds
YOUR recorded traces to every checkpoint (tools/traces/*.json).

Run the demo site first, then:
    python tools/humans.py                 # post 40 users, print verdicts
    python tools/humans.py --export 6      # write tools/traces/corpus_NN.json (fixed seed)
"""

import argparse
import json
import math
import os
import sys
import random

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://localhost:5000")

HERE = os.path.dirname(os.path.abspath(__file__))
TRACES_DIR = os.path.join(HERE, "traces")

FIRST = ["Maya", "Jonas", "Priya", "Tomás", "Aiko", "Lena", "Omar", "Grace", "Nikolai", "Zara"]
LAST = ["Holt", "Ibarra", "Kowalski", "Mensah", "Nakamura", "Olsen", "Petrov", "Quinn", "Rossi", "Silva"]

POPULATION = ([("mouse", 24), ("trackpad", 3), ("tremor", 3), ("keyboard", 2),
               ("screen_reader", 2), ("touch", 3), ("password_mgr", 2), ("voice", 1)])


def identity(rng):
    first, last = rng.choice(FIRST), rng.choice(LAST)
    return {"name": f"{first} {last}",
            "email": f"{first.lower()}.{last.lower()}{rng.randint(1, 99)}@example.test",
            "size": str(rng.randint(36, 47))}


class Recorder:
    """Accumulates telemetry in exactly the collector.js format."""

    def __init__(self, rng, viewport, kind="m"):
        self.rng, self.kind = rng, kind
        self.t = rng.uniform(300, 900)           # page load -> first paint
        self.d = {"v": 1, "viewport": viewport, "dpr": 1, "doc_h": 1100, "pointer": [],
                  "moves_dispatched": 0, "downs": [], "clicks": [], "keys": [], "inputs": [],
                  "focus": [], "scroll": [], "t_submit": 0}
        self.pos = None

    def wait(self, ms):
        self.t += max(0.0, ms)

    def lognormal_wait(self, median, sigma=0.5):
        self.wait(self.rng.lognormvariate(math.log(median), sigma))

    def point(self, t, x, y, kind=None):
        self.d["pointer"].append([round(t, 1), round(x, 1), round(y, 1), kind or self.kind])

    def click_at(self, target, x, y, kind="m", hold=None):
        hold = hold if hold is not None else self.rng.uniform(60, 140)
        self.d["downs"].append([round(self.t, 1), round(x, 1), round(y, 1), kind, 0])
        self.wait(hold)
        self.d["clicks"].append([round(self.t, 1), round(x, 1), round(y, 1), 1, target, kind, True])
        if target != "reserve":
            self.d["focus"].append([round(self.t - hold, 1), target])

    def keyboard_click(self, target):
        self.key(target, "e", hold=self.rng.uniform(70, 130), advance=False)
        self.d["clicks"].append([round(self.t + 2, 1), 0, 0, 0, target, "", True])

    def key(self, field, cls, hold, advance=True, input_type=None):
        down = self.t
        self.d["keys"].append([field, round(down, 1), round(down + hold, 1), cls])
        if input_type:
            self.d["inputs"].append([round(down + self.rng.uniform(1, 4), 1), field, input_type, True])
        if not advance:
            self.wait(hold)

    def submit(self):
        self.wait(self.rng.uniform(5, 30))
        self.d["t_submit"] = round(self.t, 1)
        return self.d


# ── movement ───────────────────────────────────────────────────────────────

def _lognormal_cdf(t, mu, sigma):
    if t <= 0:
        return 0.0
    return 0.5 * (1 + math.erf((math.log(t) - mu) / (sigma * math.sqrt(2))))


def stroke(rng, dx, dy, duration_ms, curvature):
    """
    One lognormal stroke covering (dx, dy) along a circular arc.
    Returns displacement samples on a 1 ms grid. sigma ~0.2-0.35 gives the
    asymmetric bell (fast rise, long tail) seen in aimed human movements.
    """
    sigma = rng.uniform(0.2, 0.35)
    # put ~99% of the stroke inside duration_ms
    mu = math.log(duration_ms) - 2.3 * sigma
    t0 = 0.0
    n = int(duration_ms) + 1
    frac = [_lognormal_cdf(t - t0, mu, sigma) for t in range(n)]
    frac = [f / frac[-1] for f in frac]
    dist = math.hypot(dx, dy)
    base = math.atan2(dy, dx)
    out = []
    for f in frac:
        # arc: direction drifts from (base - c/2) to (base + c/2); chord stays on target
        if abs(curvature) < 1e-3:
            along, perp = f * dist, 0.0
        else:
            radius = dist / (2 * math.sin(curvature / 2))
            ang = -curvature / 2 + f * curvature
            along = radius * (math.sin(ang) + math.sin(curvature / 2))
            perp = radius * (math.cos(curvature / 2) - math.cos(ang))
        out.append((along * math.cos(base) - perp * math.sin(base),
                    along * math.sin(base) + perp * math.cos(base)))
    return out


def move(rec, target, person):
    """Move the hand from rec.pos to target with a primary + corrective strokes."""
    rng = rec.rng
    x0, y0 = rec.pos
    tx, ty = target
    dist = math.hypot(tx - x0, ty - y0)
    if dist < 2:
        return
    # Fitts: MT = a + b * log2(D/W + 1) seconds, W ~ 40 px controls
    mt = 1000 * (person["fitts_a"] + person["fitts_b"] * math.log2(dist / 40 + 1)) * rng.lognormvariate(0, 0.15)
    strokes = []
    gain = rng.gauss(0.95, 0.04)               # humans usually undershoot slightly
    err_angle = rng.gauss(0, math.radians(3))
    ang = math.atan2(ty - y0, tx - x0) + err_angle
    d1 = dist * gain
    dx1, dy1 = d1 * math.cos(ang), d1 * math.sin(ang)
    strokes.append((0.0, dx1, dy1, mt * 0.8, rng.gauss(0, 0.35)))
    rx, ry = tx - x0 - dx1, ty - y0 - dy1      # residual for the corrections
    n_corr = person["corrections"] if math.hypot(rx, ry) > 1.5 else 0
    start = mt * rng.uniform(0.55, 0.75)
    for k in range(n_corr):
        share = 1.0 if k == n_corr - 1 else rng.uniform(0.6, 0.9)
        cdx, cdy = rx * share, ry * share
        rx, ry = rx - cdx, ry - cdy
        dur = rng.uniform(120, 260)
        strokes.append((start, cdx, cdy, dur, rng.gauss(0, 0.3)))
        start += dur * rng.uniform(0.6, 0.9)
    total = int(max(s[0] + s[3] for s in strokes)) + 1
    disp = [[0.0, 0.0] for _ in range(total + 1)]
    for s0, dx, dy, dur, curv in strokes:
        samples = stroke(rng, dx, dy, dur, curv)
        off = int(s0)
        for i in range(total + 1 - off):
            sx, sy = samples[min(i, len(samples) - 1)]
            disp[off + i][0] += sx
            disp[off + i][1] += sy
    # tremor: small oscillation, larger for the tremor profile
    amp, freq = person["tremor_px"], person["tremor_hz"]
    phase = rng.uniform(0, 2 * math.pi)
    poll = person["poll_ms"]
    t = rng.uniform(0, poll)
    last = None
    jx = jy = 0.0
    while t <= total:
        i = int(t)
        damp = min(1.0, (total - t) / 120)    # tremor fades as the hand settles
        tr = amp * damp * math.sin(2 * math.pi * freq * t / 1000 + phase)
        # aperiodic jitter (hand + sensor): a smoothed random walk, unique per movement
        jx = 0.8 * jx + rng.gauss(0, person["jitter_px"])
        jy = 0.8 * jy + rng.gauss(0, person["jitter_px"])
        x = round(x0 + disp[i][0] + tr * 0.7 + jx * damp)
        y = round(y0 + disp[i][1] + tr + jy * damp)
        if (x, y) != last:                    # a still mouse sends no events
            rec.point(rec.t + t, x, y)
            last = (x, y)
        t += poll * rng.uniform(0.9, 1.1)
    rec.point(rec.t + total, tx, ty)
    rec.wait(total)
    rec.pos = (tx, ty)


def aim_point(rng, box):
    x, y, w, h = box
    return (round(min(x + w - 3, max(x + 3, rng.gauss(x + w * 0.45, w / 7)))),
            round(min(y + h - 3, max(y + 3, rng.gauss(y + h / 2, h / 6)))))


def type_text(rec, field, text, person):
    rng = rec.rng
    for ch in text:
        if rng.random() < person["typo_rate"]:
            hold = rng.lognormvariate(math.log(person["dwell"]), 0.25)
            rec.key(field, "c", hold, input_type="insertText")
            rec.lognormal_wait(person["iki"] * 1.6, 0.4)
            rec.key(field, "b", rng.lognormvariate(math.log(person["dwell"]), 0.25),
                    input_type="deleteContentBackward")
            rec.lognormal_wait(person["iki"] * 1.3, 0.4)
        hold = rng.lognormvariate(math.log(person["dwell"]), 0.25)
        rec.key(field, "c", hold, input_type="insertText")
        gap = person["iki"] * (1.8 if ch == " " else 1.0)
        rec.lognormal_wait(gap, person["iki_sigma"])


def type_ime(rec, field, text):
    """Android virtual keyboard: key 'Unidentified', keydown and keyup together."""
    rng = rec.rng
    for _ in text:
        rec.key(field, "u", rng.uniform(1, 6), input_type="insertText")
        rec.lognormal_wait(260, 0.45)


# ── profiles ───────────────────────────────────────────────────────────────

def person_for(profile, rng):
    p = {"fitts_a": rng.uniform(0.12, 0.25), "fitts_b": rng.uniform(0.09, 0.15),
         "corrections": rng.choice([1, 1, 1, 2]), "tremor_px": rng.uniform(0.2, 0.7),
         "tremor_hz": rng.uniform(8, 12), "jitter_px": rng.uniform(0.3, 0.7), "poll_ms": rng.choice([8, 8, 8, 8, 4, 2, 1]),
         "dwell": rng.uniform(75, 120), "iki": rng.uniform(140, 260), "iki_sigma": rng.uniform(0.35, 0.55),
         "typo_rate": rng.uniform(0.0, 0.05), "tab_prob": rng.uniform(0.0, 0.5)}
    if rng.random() < 0.15:                        # hunt-and-peck typist
        p.update(iki=rng.uniform(320, 480), dwell=rng.uniform(110, 150), iki_sigma=0.3)
    if profile == "trackpad":
        p.update(poll_ms=16, tremor_px=0.2, fitts_b=rng.uniform(0.14, 0.2))
    if profile == "tremor":
        p.update(tremor_px=rng.uniform(2, 4), tremor_hz=rng.uniform(4, 6), corrections=rng.choice([2, 3]),
                 fitts_a=rng.uniform(0.3, 0.45), fitts_b=rng.uniform(0.18, 0.26),
                 iki=rng.uniform(300, 450), typo_rate=0.06)
    return p


def mouse_session(rec, layout, who, person, profile):
    rng = rec.rng
    boxes = layout["boxes"]
    vw, vh = rec.d["viewport"]
    rec.pos = (rng.uniform(50, vw - 50), rng.uniform(50, vh - 50))
    rec.point(rec.t, *map(round, rec.pos))
    rec.lognormal_wait(1500, 0.5)                  # read the page
    for _ in range(rng.choice([0, 1, 1, 2])):     # wander while reading
        move(rec, (rng.uniform(100, vw - 100), rng.uniform(100, min(vh, 700) - 50)), person)
        rec.lognormal_wait(600, 0.5)
    for i, field in enumerate(("name", "email", "size")):
        if i > 0 and rng.random() < person["tab_prob"]:
            rec.key(("name", "email", "size")[i - 1], "t", rng.uniform(70, 120), advance=False)
            rec.d["focus"].append([round(rec.t, 1), field])
        else:
            target = aim_point(rng, boxes[field])
            if profile == "trackpad" and math.hypot(target[0] - rec.pos[0], target[1] - rec.pos[1]) > 350:
                mid = ((rec.pos[0] + target[0]) / 2 + rng.uniform(-40, 40),
                       (rec.pos[1] + target[1]) / 2 + rng.uniform(-40, 40))
                move(rec, mid, person)             # clutch: lift and re-place the finger
                rec.wait(rng.uniform(80, 200))
            move(rec, target, person)
            rec.lognormal_wait(150, 0.4)           # settle on the target
            rec.click_at(field, *target)
        rec.lognormal_wait(250, 0.4)
        if profile == "password_mgr" and field in ("name", "email"):
            if field == "name":                    # autofill fills name AND email at once
                rec.d["inputs"].append([round(rec.t, 1), "name", None, False])
                rec.d["inputs"].append([round(rec.t + 1, 1), "email", None, False])
                rec.lognormal_wait(400, 0.3)
            continue
        type_text(rec, field, who[field], person)
        rec.lognormal_wait(400, 0.5)
    target = aim_point(rng, boxes["reserve"])
    move(rec, target, person)
    rec.lognormal_wait(180, 0.4)
    rec.click_at("reserve", *target)


def keyboard_session(rec, who, person, slow=False):
    rng = rec.rng
    rec.lognormal_wait(3000 if slow else 1500, 0.4)
    for field in ("name", "email", "size"):
        rec.key(field, "t", rng.uniform(70, 120), advance=False)
        rec.d["focus"].append([round(rec.t, 1), field])
        rec.lognormal_wait(1200 if slow else 300, 0.4)    # a screen reader announces the field
        type_text(rec, field, who[field], person)
        rec.lognormal_wait(400, 0.4)
    rec.key("reserve", "t", rng.uniform(70, 120), advance=False)
    rec.lognormal_wait(1000 if slow else 250, 0.4)
    rec.keyboard_click("reserve")


def touch_session(rec, layout, who):
    rng = rec.rng
    rec.lognormal_wait(1800, 0.4)
    for y in (120, 260, 90):                       # scroll down and back
        rec.d["scroll"].append([round(rec.t, 1), y])
        rec.wait(rng.uniform(150, 400))
    rec.d["scroll"].append([round(rec.t, 1), 0])
    for field in ("name", "email", "size", "reserve"):
        x, y = aim_point(rng, layout["boxes"][field])
        x += rng.uniform(-0.5, 0.5)
        rec.lognormal_wait(700, 0.4)
        rec.point(rec.t, x, y, "t")
        rec.click_at(field, x, y, kind="t", hold=rng.uniform(40, 110))
        if field != "reserve":
            rec.lognormal_wait(500, 0.4)
            type_ime(rec, field, who[field])


def voice_session(rec, layout, who):
    """'Click full name' -> cursor jumps to the centre; dictation inserts words without keys."""
    rng = rec.rng
    rec.pos = (rng.uniform(100, 900), rng.uniform(100, 600))
    rec.point(rec.t, *map(round, rec.pos))
    rec.lognormal_wait(3000, 0.3)
    for field in ("name", "email", "size", "reserve"):
        x, y, w, h = layout["boxes"][field]
        cx, cy = x + w / 2, y + h / 2
        rec.lognormal_wait(2200, 0.3)
        rec.point(rec.t, cx, cy)
        rec.wait(rng.uniform(5, 20))
        rec.click_at(field, cx, cy)
        if field != "reserve":
            for _ in who[field].split(" "):
                rec.lognormal_wait(1500, 0.3)
                rec.d["inputs"].append([round(rec.t, 1), field, "insertText", False])


def make_session(layout, profile, rng):
    who = identity(rng)
    person = person_for(profile, rng)
    viewport = rng.choice([[1280, 720], [1366, 768], [1440, 900], [1920, 1080]])
    if profile == "touch":
        viewport = [820, 1180]
    rec = Recorder(rng, viewport, kind="t" if profile == "touch" else "m")
    if profile in ("mouse", "trackpad", "tremor", "password_mgr"):
        mouse_session(rec, layout, who, person, profile)
    elif profile in ("keyboard", "screen_reader"):
        keyboard_session(rec, who, person, slow=profile == "screen_reader")
    elif profile == "touch":
        touch_session(rec, layout, who)
    elif profile == "voice":
        voice_session(rec, layout, who)
    rec.d["moves_dispatched"] = len(rec.d["pointer"])
    return rec.submit(), who


def population():
    return [name for name, n in POPULATION for _ in range(n)]


def run(seed=None):
    """Post one fresh population. Returns one result per synthetic user."""
    rng = random.Random(seed)
    http = requests.Session()
    http.headers["X-Lab-Client"] = "humans"
    results = []
    for profile in population():
        sess = http.post(f"{BASE_URL}/api/session", timeout=5).json()
        telemetry, who = make_session(sess["layout"], profile, rng)
        r = http.post(f"{BASE_URL}/api/reserve", timeout=10,
                      json={"sid": sess["sid"], "form": who, "telemetry": telemetry})
        body = r.json()
        timing = r.headers.get("Server-Timing", "")
        results.append({
            "profile": profile, "status": body["status"], "score": body["score"],
            "reasons": body.get("reasons", []), "bytes": len(r.request.body or b""),
            "score_ms": float(timing.split("dur=")[1]) if "dur=" in timing else None,
        })
    return results


def export(n, seed=7):
    """Write a fixed 'instructor corpus' of mouse sessions for Round 0 and Round 4."""
    from_layout = {"origin": [360, 200], "boxes": {
        "name": [360, 320, 320, 36], "email": [360, 390, 320, 36],
        "size": [360, 460, 120, 36], "reserve": [360, 530, 160, 44]}}
    rng = random.Random(seed)
    os.makedirs(TRACES_DIR, exist_ok=True)
    for i in range(1, n + 1):
        telemetry, who = make_session(from_layout, "mouse", rng)
        path = os.path.join(TRACES_DIR, f"corpus_{i:02d}.json")
        with open(path, "w") as f:
            json.dump({"sid": f"corpus-{i:02d}", "label": "corpus", "source": "synthetic",
                       "layout": from_layout, "telemetry": telemetry,
                       "form_lengths": {k: len(v) for k, v in who.items()}}, f)
        print(f"  wrote {os.path.relpath(path)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Synthetic legitimate users")
    ap.add_argument("--export", type=int, metavar="N", help="write N corpus traces instead of posting")
    ap.add_argument("--seed", type=int)
    args = ap.parse_args()
    if args.export:
        export(args.export)
        raise SystemExit(0)
    results = run(args.seed)
    print("=== Legitimate users (synthetic population) ===")
    for r in results:
        mark = {"reserved": "✅", "challenge": "🟡", "blocked": "❌"}[r["status"]]
        print(f"  {mark} {r['profile']:<14} {r['status']:<9} score={r['score']:<3} "
              f"{r['bytes'] / 1024:5.1f} KB")
        for reason in r["reasons"]:
            print(f"       - {reason}")
    blocked = sum(r["status"] == "blocked" for r in results)
    challenged = sum(r["status"] == "challenge" for r in results)
    print(f"\n  Blocked: {blocked}/{len(results)}   Challenged: {challenged}/{len(results)}")
