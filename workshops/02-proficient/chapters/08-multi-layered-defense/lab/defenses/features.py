"""
Client telemetry -> features.

The page's collector (static/js/risk.js, a few lines of what W2 Ch2, Ch4-5 built properly) posts one JSON
blob per session to /api/telemetry with kind "risk": a fingerprint and a short behaviour trace.
This module turns the raw blob into the features the fingerprint, behaviour and correlation layers
read. The store keeps the blob itself (ctx.telemetry("risk")).

Remember who wrote the blob: the client. Every field can be forged, and commercial "sensor data"
generators exist for exactly that. Client telemetry is worth collecting because forging it
*consistently* across fields, sessions and layers is expensive, not because any single field is
trusted.
"""

import hashlib
import json
import math
import statistics

KIND = "risk"
PLATFORM_OS = {
    "Win32": "Windows",
    "MacIntel": "macOS",
    "Linux x86_64": "Linux",
    "iPhone": "iOS",
    "Linux armv81": "Android",
}


def gpu_vendor(renderer):
    r = renderer.lower()
    for needle, vendor in (("swiftshader", "SwiftShader"), ("llvmpipe", "llvmpipe"),
                           ("nvidia", "NVIDIA"), ("amd", "AMD"), ("radeon", "AMD"),
                           ("intel", "Intel"), ("apple", "Apple"), ("adreno", "Qualcomm"),
                           ("mali", "ARM")):
        if needle in r:
            return vendor
    return "unknown"


def _hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:16]


def extract(blob):
    fp = blob.get("fp") or {}
    behavior = blob.get("behavior") or {}
    mouse = behavior.get("mouse") or []        # [[t_ms, x, y], ...]
    keys = behavior.get("keys") or []          # [[down_ms, up_ms], ...]

    path = sum(math.dist(a[1:], b[1:]) for a, b in zip(mouse, mouse[1:]))
    displacement = math.dist(mouse[0][1:], mouse[-1][1:]) if len(mouse) > 1 else 0.0
    intervals = [b[0] - a[0] for a, b in zip(mouse, mouse[1:])]

    stable = {k: fp.get(k) for k in ("platform", "webgl_renderer", "canvas", "screen",
                                     "timezone", "languages", "hardware_concurrency")}
    renderer = fp.get("webgl_renderer", "")
    return {
        "platform": fp.get("platform", ""),
        "platform_os": PLATFORM_OS.get(fp.get("platform", ""), "unknown"),
        "gpu_vendor": gpu_vendor(renderer),
        "canvas_stable": fp.get("canvas") == fp.get("canvas2"),
        "timezone": fp.get("timezone", ""),
        "languages": fp.get("languages") or [],
        "webdriver": bool(fp.get("webdriver")),
        "cdp": bool(fp.get("cdp")),
        "pointer_type": behavior.get("pointer_type", "mouse"),
        "pointer_events": len(mouse),
        "straightness": round(displacement / path, 4) if path else 1.0,
        "interval_std_ms": round(statistics.pstdev(intervals), 2) if len(intervals) > 1 else None,
        "keystrokes": len(keys),
        # Identity of the device and of this exact trace (the correlation layer)
        "fp_hash": _hash(stable),
        "fp_family": f"{fp.get('platform', '?')}/{gpu_vendor(renderer)}",
        "trace_hash": _hash([mouse, keys]) if (mouse or keys) else None,
    }


def of(ctx):
    """This session's features, or None when the collector never reported. Computed once per request."""
    if "ch8_features" not in ctx.attrs:
        blob = ctx.telemetry(KIND)
        ctx.attrs["ch8_features"] = extract(blob) if blob else None
    return ctx.attrs["ch8_features"]
