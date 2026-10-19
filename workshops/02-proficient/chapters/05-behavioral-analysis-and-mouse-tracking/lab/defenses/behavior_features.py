"""
Chapter 5: feature extraction (Sections 5.2-5.5).

Turns one session's raw telemetry (see demo_site/static/js/behavior.js) into
numbers the scoring layers can reason about. Standard library only.

The interesting unit is the *approach*: the burst of pointer movement that
ends in a pointerdown, i.e. the hand travelling to a target. Humans plan an
approach as one fast ballistic stroke plus slower corrections. Scripts
interpolate. Most mouse features below are computed per approach.

Touch taps get one extra feature, hold_ms (contact time), for Layer 5.

Feature names the W2 Ch7 ML pipeline expects are kept verbatim:
    mouse_movement_straightness, mouse_acceleration_std, time_to_first_click_ms,
    keystroke_dwell_time_mean_ms, keystroke_flight_time_mean_ms,
    words_per_minute, scroll_to_content_ratio

Trade-off: every threshold that follows depends on how these are computed.
Resampling onto a 10 ms grid makes a 125 Hz office mouse, a 1000 Hz gaming
mouse and a 60 Hz bot comparable, at the cost of smoothing away the very
highest-frequency detail (tremor, sensor quantization).

Run on a saved trace to see the numbers:
    python defenses/behavior_features.py tools/traces/corpus_01.json
"""

import json
import math
import statistics
import sys

MOUSE_KINDS = {"m", "p"}          # mouse and pen; touch ("t") has no hover path
APPROACH_GAP_MS = 300              # a pause this long ends an approach burst
GRID_MS = 10                       # resampling step for speed profiles
TEXT_KEYS = {"c", "b"}             # characters and backspace; Tab/Enter/modifiers excluded
SIGNATURE_POINTS = 64


# ── small helpers ──────────────────────────────────────────────────────────

def _cv(values):
    """Coefficient of variation (std / mean); 0 for constant series."""
    if len(values) < 2:
        return None
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean else 0.0


def _skew(values):
    if len(values) < 3:
        return None
    mean = statistics.fmean(values)
    sd = statistics.pstdev(values)
    if sd == 0:
        return 0.0
    return sum(((v - mean) / sd) ** 3 for v in values) / len(values)


def _median(values):
    return statistics.median(values) if values else None


def _dedupe(points):
    out = []
    for p in points:
        if out and p[0] == out[-1][0] and p[1] == out[-1][1] and p[2] == out[-1][2]:
            continue
        out.append(p)
    return out


def box_center(box):
    x, y, w, h = box
    return x + w / 2, y + h / 2


def in_box(x, y, box, tolerance=3):
    bx, by, bw, bh = box
    return bx - tolerance <= x <= bx + bw + tolerance and by - tolerance <= y <= by + bh + tolerance


# ── approaches ─────────────────────────────────────────────────────────────

def approaches(telemetry):
    """Split mouse samples into approach bursts, one per mouse pointerdown."""
    pts = _dedupe([p for p in telemetry.get("pointer", []) if p[3] in MOUSE_KINDS])
    downs = [d for d in telemetry.get("downs", []) if d[3] in MOUSE_KINDS]
    result, prev_down_t, i = [], -1.0, 0
    for down in downs:
        before = [p for p in pts if prev_down_t < p[0] <= down[0]]
        prev_down_t = down[0]
        # walk back from the last sample until a long pause
        burst = []
        for p in reversed(before):
            if burst and burst[-1][0] - p[0] > APPROACH_GAP_MS:
                break
            burst.append(p)
        burst.reverse()
        result.append({"index": i, "down": down, "points": burst})
        i += 1
    return result


def _resample(times, values, total_t):
    grid, j, t = [], 0, 0.0
    while t <= total_t:
        while j < len(times) - 2 and times[j + 1] < t:
            j += 1
        span = times[j + 1] - times[j]
        frac = (t - times[j]) / span if span > 0 else 0
        grid.append(values[j] + frac * (values[j + 1] - values[j]))
        t += GRID_MS
    return grid


def _smooth(values, half=3):
    # 7-point moving average (70 ms): CDP and the event loop deliver some
    # samples in bursts a few ms apart, which spikes raw speeds
    out = []
    for k in range(len(values)):
        window = values[max(0, k - half):k + half + 1]
        out.append(sum(window) / len(window))
    return out


def speed_profile(points):
    """Distance travelled vs time, resampled on a GRID_MS grid -> smoothed speeds (px/ms)."""
    t0 = points[0][0]
    times, cum = [0.0], [0.0]
    for a, b in zip(points, points[1:]):
        times.append(b[0] - t0)
        cum.append(cum[-1] + math.hypot(b[1] - a[1], b[2] - a[2]))
    if times[-1] < 3 * GRID_MS:
        return []
    grid = _resample(times, cum, times[-1])
    return _smooth([(b - a) / GRID_MS for a, b in zip(grid, grid[1:])])


def closing_profile(points):
    """
    How fast the pointer closes in on where it finally clicks (px/ms).
    Unlike path speed, tremor and jitter around the target add ~nothing:
    wobbling in place doesn't bring you closer.
    """
    t0, (xe, ye) = points[0][0], (points[-1][1], points[-1][2])
    times = [p[0] - t0 for p in points]
    dist = [math.hypot(p[1] - xe, p[2] - ye) for p in points]
    if times[-1] < 3 * GRID_MS:
        return []
    grid = _resample(times, dist, times[-1])
    return _smooth([max(0.0, (a - b) / GRID_MS) for a, b in zip(grid, grid[1:])])


def approach_metrics(points):
    """Shape, kinematics and velocity-profile metrics of one approach burst."""
    if len(points) < 6:
        return None
    steps = [math.hypot(b[1] - a[1], b[2] - a[2]) for a, b in zip(points, points[1:])]
    path = sum(steps)
    chord = math.hypot(points[-1][1] - points[0][1], points[-1][2] - points[0][2])
    if path < 30:
        return None
    speeds = speed_profile(points)
    closing = closing_profile(points)
    m = {
        "n": len(points),
        "path_px": round(path, 1),
        "chord_px": round(chord, 1),
        "duration_ms": round(points[-1][0] - points[0][0], 1),
        "straightness": round(chord / path, 4),
        "step_cv": round(_cv([s for s in steps if s > 0]) or 0.0, 4),
        "speeds": [round(v, 3) for v in closing],     # plotted by /behavior/view
    }
    if len(speeds) >= 6 and len(closing) >= 6:
        # how fast is the hand still closing in during the last 15% of the approach?
        cmax = max(closing)
        tail = closing[int(len(closing) * 0.85):] or closing[-1:]
        m["end_ratio"] = round((sum(tail) / len(tail)) / cmax, 3) if cmax else None
        # when was half the distance covered? Read from cumulative distance,
        # which is far less noisy than locating the speed peak.
        half, cum, t_half = path / 2, 0.0, points[-1][0]
        for a, b, step in zip(points, points[1:], steps):
            if cum + step >= half:
                frac = (half - cum) / step if step else 0
                t_half = a[0] + frac * (b[0] - a[0])
                break
            cum += step
        rise = t_half - points[0][0]
        m["asymmetry"] = round((m["duration_ms"] - rise) / rise, 3) if rise > 0 else None
        acc = [(b - a) / GRID_MS for a, b in zip(speeds, speeds[1:])]
        m["acc_std"] = round(statistics.pstdev(acc), 5) if len(acc) > 1 else 0.0
    return m


def path_signature(points):
    """
    The fine-grained wobble of one approach, independent of where it happened.

    Rotate the approach so its chord lies on the x axis, resample
    SIGNATURE_POINTS points by arc length, and keep the perpendicular offsets
    minus their 9-point moving average: the smooth shape is removed and only
    the jitter of the hand and the sensor is left. That jitter is unique to
    one recording, and a translated, rotated or scaled replay keeps it
    (the overall size changes, so the vector is z-scored and compared by
    correlation). Returns None for paths with no wobble to fingerprint.
    """
    if len(points) < 12:
        return None
    x0, y0 = points[0][1], points[0][2]
    dx, dy = points[-1][1] - x0, points[-1][2] - y0
    chord = math.hypot(dx, dy)
    if chord < 80:
        return None
    cos, sin = dx / chord, dy / chord
    rot = [((x - x0) * cos + (y - y0) * sin, -(x - x0) * sin + (y - y0) * cos) for _, x, y, _ in points]
    cum = [0.0]
    for a, b in zip(rot, rot[1:]):
        cum.append(cum[-1] + math.hypot(b[0] - a[0], b[1] - a[1]))
    perp, j = [], 0
    for k in range(SIGNATURE_POINTS):
        target = cum[-1] * k / (SIGNATURE_POINTS - 1)
        while j < len(cum) - 2 and cum[j + 1] < target:
            j += 1
        span = cum[j + 1] - cum[j]
        frac = (target - cum[j]) / span if span > 0 else 0
        perp.append(rot[j][1] + frac * (rot[j + 1][1] - rot[j][1]))
    resid = [perp[k] - statistics.fmean(perp[max(0, k - 4):k + 5]) for k in range(SIGNATURE_POINTS)]
    mean, sd = statistics.fmean(resid), statistics.pstdev(resid)
    if sd < 0.05:
        return None
    return [round((r - mean) / sd, 3) for r in resid]


def key_signature(telemetry, limit=24):
    """(hold, gap) of the first `limit` text keystrokes, in ms: a typing fingerprint."""
    keys = [k for k in telemetry.get("keys", []) if k[3] in TEXT_KEYS and k[2] is not None]
    return [[round(b[2] - b[1]), round(b[1] - a[2])] for a, b in zip(keys, keys[1:])][:limit]


# ── clicks, keys, fills ────────────────────────────────────────────────────

def click_features(telemetry, layout):
    boxes = layout.get("boxes", {})
    pts = [p for p in telemetry.get("pointer", []) if p[3] in MOUSE_KINDS]
    downs = telemetry.get("downs", [])
    clicks = []
    for t, x, y, detail, target, kind, trusted in telemetry.get("clicks", []):
        keyboard = detail == 0 and kind == "" and trusted
        mouse = kind in MOUSE_KINDS and detail >= 1
        # pointer positions seen in the second before the button went down
        down_t = max([d[0] for d in downs if d[0] <= t] or [t])
        recent = {(p[1], p[2]) for p in pts if down_t - 1000 <= p[0] <= down_t}
        box = boxes.get(target)
        c = {"t": t, "target": target, "keyboard": keyboard, "mouse": mouse,
             "kind": kind, "trusted": trusted, "positions_1s": len(recent)}
        if kind == "t":
            # contact time of a tap: pointerdown -> pointerup (or the click, for older traces)
            ups = [u[0] for u in telemetry.get("ups", []) if down_t <= u[0] <= t]
            c["hold_ms"] = round((ups[0] if ups else t) - down_t, 1)
        if box:
            cx, cy = box_center(box)
            c["center_offset"] = round(math.hypot(x - cx, y - cy), 2)
            c["inside"] = in_box(x, y, box) if (mouse or kind == "t") else None
        clicks.append(c)
    return clicks


def key_features(telemetry):
    keys = [k for k in telemetry.get("keys", []) if k[3] in TEXT_KEYS | {"u"}]
    ime = sum(k[3] == "u" for k in keys)
    hw = [k for k in keys if k[3] in TEXT_KEYS]
    dwell = [k[2] - k[1] for k in hw if k[2] is not None]
    iki, flight = [], []
    for a, b in zip(keys, keys[1:]):
        if a[0] != b[0] or b[1] - a[1] > 2000:
            continue                       # different field or a long pause
        iki.append(b[1] - a[1])
        if a[2] is not None and a[3] in TEXT_KEYS and b[3] in TEXT_KEYS:
            flight.append(b[1] - a[2])     # negative = rollover (next key down first)
    typing_ms = sum(iki)
    chars = sum(k[3] in ("c", "u") for k in keys)
    return {
        "n_keys": len(keys),
        "ime_keys": ime,
        "dwell_mean": round(statistics.fmean(dwell), 2) if dwell else None,
        "dwell_cv": round(_cv(dwell), 4) if len(dwell) > 1 else None,
        "iki_cv": round(_cv(iki), 4) if len(iki) > 1 else None,
        "iki_skew": round(_skew(iki), 3) if len(iki) > 2 else None,
        "flight_mean": round(statistics.fmean(flight), 2) if flight else None,
        "rollover_ratio": round(sum(f < 0 for f in flight) / len(flight), 3) if flight else None,
        # next key pressed within 8 ms of releasing the previous one
        "instant_flight_ratio": round(sum(0 <= f <= 8 for f in flight) / len(flight), 3) if flight else None,
        "n_dwell": len(dwell),
        "n_iki": len(iki),
        "wpm": round((chars / 5) / (typing_ms / 60000), 1) if typing_ms > 0 else None,
    }


def fill_features(telemetry):
    """How did text get into each field: typed, injected, pasted or autofilled?"""
    injected, bulk = set(), set()
    for t, field, input_type, had_key in telemetry.get("inputs", []):
        if had_key:
            continue
        if input_type in ("insertText", "insertCompositionText"):
            injected.add(field)        # text with no key behind it: dictation or a script
        else:
            bulk.add(field)            # paste, autofill, password manager, spellcheck
    return {"injected_fields": sorted(injected), "bulk_fields": sorted(bulk)}


# ── everything ─────────────────────────────────────────────────────────────

def extract(telemetry, layout):
    telemetry = telemetry or {}
    pointer = telemetry.get("pointer", [])
    apps = approaches(telemetry)
    metrics, path_sigs = [], []
    for a in apps:
        m = approach_metrics(a["points"])
        if m:
            m["index"] = a["index"]
            metrics.append(m)
        sig = path_signature(a["points"])
        if sig:
            path_sigs.append(sig)
    clicks = click_features(telemetry, layout)
    keys = key_features(telemetry)
    fills = fill_features(telemetry)

    scroll = telemetry.get("scroll", [])
    viewport_h = (telemetry.get("viewport") or [0, 0])[1]
    doc_h = telemetry.get("doc_h") or 0
    max_scroll = max([s[1] for s in scroll] or [0])
    acc = [m["acc_std"] for m in metrics if m.get("acc_std") is not None]
    straight = [m["straightness"] for m in metrics]
    first = pointer[0] if pointer else None

    return {
        # W2 Ch7 names
        "mouse_movement_straightness": round(statistics.fmean(straight), 4) if straight else None,
        "mouse_acceleration_std": round(statistics.fmean(acc), 5) if acc else None,
        "time_to_first_click_ms": clicks[0]["t"] if clicks else None,
        "keystroke_dwell_time_mean_ms": keys["dwell_mean"],
        "keystroke_flight_time_mean_ms": keys["flight_mean"],
        "words_per_minute": keys["wpm"],
        "scroll_to_content_ratio": round(min(1.0, (max_scroll + viewport_h) / doc_h), 3) if doc_h else None,
        # used by the scoring layers
        "submit_ms": telemetry.get("t_submit"),
        "n_pointer": len(pointer),
        "pointer_kinds": sorted({p[3] for p in pointer if p[3]}),
        "first_point": [first[1], first[2]] if first else None,
        "approaches": metrics,
        "signature": {"paths": path_sigs, "keys": key_signature(telemetry)},
        "clicks": clicks,
        "keys": keys,
        "fills": fills,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python defenses/behavior_features.py <trace.json>")
    with open(sys.argv[1]) as f:
        trace = json.load(f)
    feats = extract(trace["telemetry"], trace["layout"])
    for m in feats["approaches"]:
        m.pop("speeds")
    feats["signature"] = {k: f"{len(v)} entries" for k, v in feats["signature"].items()}
    print(json.dumps(feats, indent=2))
