"""
Layer: device fingerprint (stand-in for W2 Ch2)

Three checks on the fingerprint the collector reported:
- a software renderer (SwiftShader, llvmpipe) is what headless Chrome on a server without a GPU
  uses
- two canvas readbacks that differ mean noise injection (anti-fingerprinting)
- navigator.platform or GPU that cannot belong to the OS in the User-Agent

False positives: privacy browsers and Firefox's resistFingerprinting randomize on purpose, and
VMs/VDI desktops really do render in software. "Randomized" tells you the user values privacy,
not that they are a bot.
"""

from . import features, sensor_headers

LAYER = "fingerprint"
SIGNALS = {
    "headless_gpu": "software WebGL renderer",
    "fp_randomized": "canvas readback changes between reads",
    "fp_inconsistent": "platform or GPU contradicts the User-Agent OS",
}

GPU_BY_OS = {
    "Windows": {"NVIDIA", "AMD", "Intel"},
    "macOS": {"Apple", "Intel", "AMD"},
    "Linux": {"NVIDIA", "AMD", "Intel"},
    "iOS": {"Apple"},
    "Android": {"Qualcomm", "ARM"},
}


def sense(ctx):
    t = features.of(ctx)
    if t is None:
        return []
    found = []
    if t["gpu_vendor"] in ("SwiftShader", "llvmpipe"):
        found.append("headless_gpu")
    if not t["canvas_stable"]:
        found.append("fp_randomized")
    ua_os = sensor_headers.ua_of(ctx)["os"]
    platform_wrong = t["platform_os"] not in ("unknown", ua_os)
    gpu_wrong = ua_os in GPU_BY_OS and t["gpu_vendor"] not in GPU_BY_OS[ua_os] | {"SwiftShader", "llvmpipe"}
    if platform_wrong or gpu_wrong:
        found.append("fp_inconsistent")
    return found
