"""
Chapter 4 — Building a Device ID (Section 4.5, Rounds 3–4)

Three keys, from most to least specific:

  stable_id     hash of every stable component, including the high-entropy
                render hashes (canvas, audio, voices). Best at telling
                devices apart. Changes whenever anything is noised.
  core_id       hash of the noise-resistant components only. Lower entropy,
                but it survives canvas/audio randomisation. This is the
                `fp_id` that Workshop 2, Chapter 6 binds to accounts.
  device_class  OS | GPU model | screen | cores. The coarse "kind of device",
                used to estimate how many real people share a fingerprint
                (see population.py).

The ID is computed on the SERVER from the raw components. Never trust a
visitorId the client computed: the client is the attacker's machine.

What we leave out on purpose:
  - the browser version: it changes every four weeks for everybody;
  - window size: users resize windows;
  - anything per-request (timestamps, nonces, collect_ms);
  - the IP address: identity of the network, not the device (W1 Ch3).

Trade-off: every component you add raises entropy *and* the chance that a
legitimate change (new font, new monitor, OS update) breaks the match.
That is why Round 4 switches from exact matching to fuzzy matching.
"""

import hashlib
import json

from .fields import gpu_model, os_from_ua, renderer


def _hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:16]


def webgl_caps(fp):
    """Capability limits and extensions: set by GPU and driver, rarely noised."""
    w = fp.get("webgl") or {}
    if not w.get("supported"):
        return None
    return _hash([w.get("maxTextureSize"), w.get("maxRenderbufferSize"), w.get("maxViewportDims"),
                  w.get("aliasedLineWidthRange"), w.get("maxVertexUniformVectors"),
                  w.get("extensions")])


def core_components(fp):
    """Noise-resistant components, as a flat dict (also used by fuzzy_cluster.py)."""
    nav = fp.get("nav") or {}
    screen = fp.get("screen") or {}
    intl = fp.get("intl") or {}
    return {
        "os": os_from_ua(nav.get("userAgent")),
        "platform": nav.get("platform"),
        "uad_platform": (fp.get("uad") or {}).get("platform"),
        "gpu": gpu_model(renderer(fp)),
        "webgl_caps": webgl_caps(fp),
        "screen": f"{screen.get('width')}x{screen.get('height')}",
        "dpr": screen.get("devicePixelRatio"),
        "color_depth": screen.get("colorDepth"),
        "cores": nav.get("hardwareConcurrency"),
        "memory": nav.get("deviceMemory"),
        "timezone": intl.get("timeZone"),
        "languages": ",".join(nav.get("languages") or []),
        "fonts": ",".join(sorted(fp.get("fonts") or [])),
    }


def stable_components(fp):
    """Core components plus the high-entropy render hashes."""
    components = core_components(fp)
    components.update({
        "canvas": (fp.get("canvas") or {}).get("hash"),
        "audio": (fp.get("audio") or {}).get("hash"),
        "voices": (fp.get("voices") or {}).get("hash"),
    })
    return components


def stable_id(fp):
    return _hash(stable_components(fp))


def core_id(fp):
    return _hash(core_components(fp))


def device_class(fp):
    c = core_components(fp)
    return f"{c['os']}|{c['gpu']}|{c['screen']}@{c['dpr']}|{c['cores']}"


if __name__ == '__main__':
    fp = {
        "nav": {"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/153.0.0.0 ...",
                "platform": "Win32", "hardwareConcurrency": 16, "deviceMemory": 8, "languages": ["es-ES", "es"]},
        "screen": {"width": 2560, "height": 1440, "devicePixelRatio": 1, "colorDepth": 24},
        "intl": {"timeZone": "Europe/Madrid"},
        "webgl": {"supported": True, "unmaskedRenderer":
                  "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002503) Direct3D11 vs_5_0 ps_5_0, D3D11)",
                  "maxTextureSize": 16384},
        "canvas": {"hash": "a1"}, "audio": {"hash": "b2"}, "fonts": ["Arial", "Segoe UI"],
    }
    print("stable_id   ", stable_id(fp))
    print("core_id     ", core_id(fp))
    print("device_class", device_class(fp))
    fp["canvas"]["hash"] = "noised"
    print("after canvas noise: stable_id", stable_id(fp), "core_id", core_id(fp), "(unchanged)")
