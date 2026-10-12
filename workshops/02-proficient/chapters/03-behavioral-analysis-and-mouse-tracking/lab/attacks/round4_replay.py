"""
Chapter 3, Round 4 attack: replay a real human (Section 3.6).

The scalper stops simulating humans and starts recording them. Two styles:

  --forge   Sensor replay. Skip the browser: load the drop page over plain
            HTTP (for the session cookie and the CSRF token), POST a recorded
            telemetry payload to /api/telemetry, then POST the form. Costs
            nothing per attempt. Works as long as the page always looks the same.

  --jitter-keys  (with the warped replay) perturb every key's hold and gap
            by ~20 ms, to dodge a typing fingerprint. Only the path is left.

  default   Warped replay in a real browser. Read where this session drew
            each element, then replay the recorded pointer path and key
            timings, each approach rotated/scaled/translated onto the new
            targets. Camoufox's `humanize` does the same with ~2,000 traces.

Both pass Layers 1-3: the movement IS human. Layer 4 answers with layout
jitter (the forged clicks land on empty page) and path signatures (the
warped approaches match a shape and timing seen in another session).

Source trace: --trace PATH, else your newest recording from Round 0
(tools/traces/*.json with "source": "browser"), else the shipped corpus.

Expected:
    DEFENSE_LEVEL 0-3  both reserved, every time (no layer has memory)
    DEFENSE_LEVEL 4    --forge: blocked (click outside its target)
                       warped:  first use of a never-seen trace reserved,
                                every reuse blocked (replayed path)

    python attacks/round4_replay.py [--forge] [--runs N] [--trace FILE]
"""

import argparse
import glob
import json
import os
import random
import time

from playwright.sync_api import sync_playwright

from _common import DROP, FIELDS, SELECTOR, LabClient, bot_ip, finish, identity, open_drop, outcome, report, sleep_ms
import browsers           # noqa: E402  (tools/, on the path through _common)
from labclient import BASE_URL, csrf_of  # noqa: E402

TRACES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools", "traces")
LONG_GAP_MS = 2000      # idle pauses longer than this are shortened to SHORT_GAP_MS,
SHORT_GAP_MS = 1200     # so a replay takes seconds, not minutes (typing rhythm is kept)


def pick_trace(path=None):
    if path:
        return json.load(open(path)), path
    candidates = []
    for p in glob.glob(os.path.join(TRACES, "*.json")):
        t = json.load(open(p))
        mouse_clicks = [c for c in t["telemetry"]["clicks"] if c[5] == "m"]
        if t.get("source") == "browser" and len(mouse_clicks) >= 2:
            candidates.append((os.path.getmtime(p), p, t))
    if candidates:
        _, p, t = max(candidates)
        return t, p
    p = os.path.join(TRACES, "corpus_01.json")
    return json.load(open(p)), p


def forge(trace):
    """Replay the recorded payload unchanged, with a brand-new session. No browser."""
    bot = LabClient("bot:round4_forge", ip=bot_ip())
    chrome = ("chrome", 153, "windows")
    page = bot.get(DROP, browsers.headers_for(chrome, "typed", BASE_URL))
    bot.post("/api/telemetry", json=dict(trace["telemetry"], kind="behavior"),
             headers=[("User-Agent", dict(browsers.headers_for(chrome, "typed", BASE_URL))["User-Agent"]),
                      ("Content-Type", "application/json"), ("Origin", BASE_URL)])
    form = dict(identity(), csrf=csrf_of(page.text))
    r = bot.post(DROP, form, browsers.headers_for(chrome, "post", BASE_URL, BASE_URL + DROP))
    return outcome(r.status_code, r.headers.get("X-Lab-Verdict"), r.headers.get("X-Lab-Signals"),
                   confirmed="order-confirmed" in r.text)


def _similarity(p_from, p_to, q_from, q_to):
    """Complex-number similarity transform mapping p_from->q_from and p_to->q_to."""
    a, b = complex(*p_from), complex(*p_to)
    c, d = complex(*q_from), complex(*q_to)
    k = (d - c) / (b - a) if b != a else 1

    def warp(x, y):
        z = (complex(x, y) - a) * k + c
        return z.real, z.imag
    return warp


def build_actions(trace, new_boxes, jitter_keys=False):
    """Turn the recorded telemetry into timed actions mapped onto the new layout."""
    tel, old_boxes = trace["telemetry"], trace["layout"]["boxes"]
    pts = [p for p in tel["pointer"] if p[3] == "m"]
    downs = [d for d in tel["downs"] if d[3] == "m"]
    clicks = {round(c[0]): c for c in tel["clicks"] if c[5] == "m"}
    actions, prev_t, cur_old = [], -1.0, (pts[0][1], pts[0][2]) if pts else (0, 0)
    cur_new = cur_old
    for down in downs:
        click = min(clicks.values(), key=lambda c: abs(c[0] - down[0]))
        target = click[4]
        ob, nb = old_boxes.get(target), new_boxes.get(target)
        if not ob or not nb:
            continue
        old_click = (down[1], down[2])
        new_click = (nb[0] + down[1] - ob[0], nb[1] + down[2] - ob[1])
        warp = _similarity(cur_old, old_click, cur_new, new_click)
        for t, x, y, _ in pts:
            if prev_t < t <= down[0]:
                actions.append((t, "move", warp(x, y)))
        actions.append((down[0], "down", None))
        actions.append((click[0], "up", None))
        prev_t, cur_old, cur_new = click[0], old_click, new_click
    for i, (field, t_down, t_up, cls) in enumerate(tel["keys"]):
        if jitter_keys:
            t_down += random.gauss(0, 20)
            t_up = t_down + max(30, (t_up or t_down + 80) - t_down + random.gauss(0, 20))
        if cls in ("c", "b", "t", "e"):
            actions.append((t_down, "kdown", (i, cls, field)))
            # unique id per keystroke: with rollover two keys are down at once
            actions.append((t_up if t_up is not None else t_down + 80, "kup", (i, cls, field)))
    actions.sort(key=lambda a: a[0])
    # compress idle gaps
    out, last_old, last_new = [], None, 0.0
    for t, kind, data in actions:
        if last_old is not None:
            gap = t - last_old
            last_new += SHORT_GAP_MS if gap > LONG_GAP_MS else gap
        last_old = t
        out.append((last_new, kind, data))
    return out


def texts_for(telemetry, rng=random):
    """
    Text to type, one string per field, exactly as long as what the recording left in that
    field (character keys minus backspaces), so the replayed keystrokes produce a valid form:
    a size the drop sells and an address with an @.
    """
    length = {f: 0 for f in FIELDS}
    for field, _, _, cls in telemetry["keys"]:
        if field in length:
            length[field] += {"c": 1, "b": -1}.get(cls, 0)
    n = {f: max(1, v) for f, v in length.items()}
    letters = "abcdefghijklmnopqrstuvwxyz"
    name = "".join(rng.choice(letters) for _ in range(n["name"]))
    domain = "@example.test" if n["email"] >= 15 else "@e.test"
    local = "".join(rng.choice(letters) for _ in range(max(1, n["email"] - len(domain))))
    size = rng.choice(["10", "11", "12"] if n["size"] >= 2 else ["7", "8", "9"])
    return {"name": name, "email": local + domain, "size": size}


def warped(p, trace, jitter_keys=False):
    browser, page = open_drop(p, "round4_replay")
    boxes = {}
    for name, sel in SELECTOR.items():
        b = page.locator(sel).bounding_box()
        boxes[name] = [b["x"], b["y"], b["width"], b["height"]]
    text = texts_for(trace["telemetry"])
    typed = {f: 0 for f in text}
    held = {}
    with page.expect_navigation(timeout=120000) as nav:    # the replayed click on Reserve submits
        _replay(page, build_actions(trace, boxes, jitter_keys), text, typed, held)
    r = nav.value
    result = outcome(r.status, r.headers.get("x-lab-verdict"), r.headers.get("x-lab-signals"),
                     confirmed="order-confirmed" in page.content())
    browser.close()
    return result


def _replay(page, actions, text, typed, held):
    start = time.perf_counter()
    for t, kind, data in actions:
        now = (time.perf_counter() - start) * 1000
        if kind == "move" and now - t > 20:
            continue                       # behind schedule: drop samples like a 60 Hz device
        sleep_ms(t - now)
        if kind == "move":
            page.mouse.move(*data)
        elif kind == "down":
            page.mouse.down()
        elif kind == "up":
            page.mouse.up()
        elif kind == "kdown":
            i, cls, field = data
            if cls == "c" and field in text:
                key = text[field][typed[field] % len(text[field])]
                typed[field] += 1
            else:
                key = {"b": "Backspace", "t": "Tab", "e": "Enter"}.get(cls)
                if cls == "b" and field in typed:
                    typed[field] = max(0, typed[field] - 1)
            if key:
                for j, other in list(held.items()):
                    if other == key:          # one finger can't hold the same key twice ("ll")
                        page.keyboard.up(key)
                        del held[j]
                page.keyboard.down(key)
                held[i] = key
        elif kind == "kup":
            key = held.pop(data[0], None)
            if key:
                page.keyboard.up(key)


def run(forge_only=False, runs=1, trace_path=None, jitter_keys=False, verbose=False):
    trace, path = pick_trace(trace_path)
    if verbose:
        print(f"  source trace: {os.path.relpath(path)}")
    results = []
    if forge_only:
        for _ in range(runs):
            results.append(forge(trace))
            if verbose:
                report("round4_forge", results[-1])
        return results
    with sync_playwright() as p:
        for _ in range(runs):
            results.append(warped(p, trace, jitter_keys))
            if verbose:
                report("round4_replay", results[-1])
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--forge", action="store_true", help="POST the recorded payload, no browser")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--trace")
    ap.add_argument("--jitter-keys", action="store_true", help="perturb key timings (warped replay)")
    args = ap.parse_args()
    print(f"=== Round 4: {'sensor replay (forged payload)' if args.forge else 'warped replay in Chromium'} ===")
    finish("round4_forge" if args.forge else "round4_replay", run(args.forge, args.runs, args.trace, args.jitter_keys, verbose=True))
