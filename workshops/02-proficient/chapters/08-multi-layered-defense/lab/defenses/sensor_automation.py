"""
Layer: automation artefacts (stand-in for W2 Ch1, Ch4)

Did the page's JavaScript run at all (telemetry present), and does the collector see
`navigator.webdriver` or CDP side effects?

False positives: users with JavaScript disabled or a blocker that strips the collector script,
and pages that fail to load the script on a bad connection. "No telemetry" is strong evidence on
a login form that cannot work without JS, and weak evidence anywhere else.
"""

from . import features

LAYER = "automation"
SIGNALS = {
    "no_telemetry": "the collector script never reported for this session",
    "webdriver_flag": "navigator.webdriver is true",
    "cdp_artifacts": "Chrome DevTools Protocol side effects detected",
}


def sense(ctx):
    t = features.of(ctx)
    if t is None:
        return ["no_telemetry"]
    found = []
    if t["webdriver"]:
        found.append("webdriver_flag")
    if t["cdp"]:
        found.append("cdp_artifacts")
    return found
