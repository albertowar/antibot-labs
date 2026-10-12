"""
W2 Ch1 — Defense Layer 1: Automation Artifacts (Section 1.1)

Automation frameworks announce themselves in the JavaScript environment:

  navigator.webdriver   The WebDriver spec says it MUST be true when the
                        browser is under automation control. Chromium sets
                        it when launched with --enable-automation, which
                        Playwright, Puppeteer and ChromeDriver pass by
                        default.
  driver globals        ChromeDriver's injected helpers (cdc_..., $cdc_...),
                        Playwright's exposed bindings (__playwright__binding__),
                        PhantomJS (callPhantom), Nightmare (__nightmare), etc.

Both are cheap, precise and very easy to remove. Precision is the reason to
keep them: no real user's browser sets navigator.webdriver, so a hit is
close to zero false-positive risk (see the "RPA and test traffic" note in
the content doc). Their weakness is recall: one launch flag
(--disable-blink-features=AutomationControlled) or one patched driver
(patchright) and they go silent.

Round 1: enabled at DEFENSE_LEVEL >= 2 (round N runs at level N+1, see ladder.py), together with the sensor gate (defenses/sensor_gate.py:
no sensor report for the session = no API access). Try it on its own:
    python -m defenses.automation_artifacts
"""

import re

# Pattern -> what left it behind. Matched against window property names and
# document keys reported by the sensor.
AUTOMATION_KEYS = [
    (re.compile(r"^\$?cdc_"), "ChromeDriver (Selenium) helper variable"),
    (re.compile(r"^\$wdc_"), "WebDriver helper variable"),
    (re.compile(r"^__(webdriver|selenium|driver|fxdriver)"), "Selenium/WebDriver global"),
    (re.compile(r"^__playwright"), "Playwright exposed binding"),
    (re.compile(r"^__pw"), "Playwright init-script global"),
    (re.compile(r"^__puppeteer"), "Puppeteer global"),
    (re.compile(r"^(callPhantom|_phantom)$"), "PhantomJS global"),
    (re.compile(r"^__nightmare$"), "Nightmare global"),
    (re.compile(r"^domAutomation"), "Chromium domAutomation controller"),
]


def check_webdriver(signals):
    """
    Round 1: navigator.webdriver must be false (Chromium, Firefox) or
    undefined (older Safari). Only an automated browser reports true.
    Returns (points, reasons).
    """
    # TODO (Round 1): return (60, [a reason]) when signals["webdriver"] is
    # exactly True. Careful: None (property missing) and False are both normal.
    return 0, []


def check_automation_globals(signals):
    """Known driver globals in window / document. Returns (points, reasons)."""
    hits = []
    for key in signals.get("suspicious_keys") or []:
        for pattern, description in AUTOMATION_KEYS:
            if pattern.search(key):
                hits.append(f"{description}: {key}")
                break
    if hits:
        return 60, [f"Automation global found ({hits[0]})"] + hits[1:3]
    return 0, []


def score_automation_artifacts(signals):
    """Layer 1. Returns (score, reasons)."""
    score = 0
    reasons = []
    for check in (check_webdriver, check_automation_globals):
        points, why = check(signals)
        score += points
        reasons.extend(why)
    return score, reasons


# Wiring (no need to edit): score the session's sensor report on the gated paths.
from . import sensor  # noqa: E402
from .pipeline import Check  # noqa: E402

CHECK = Check("automation_artifacts", sensor.layer_check("automation_artifacts", score_automation_artifacts),
              phases=("request",))


if __name__ == '__main__':
    samples = {
        "Real Chrome": {"webdriver": False, "suspicious_keys": []},
        "Default Playwright": {"webdriver": True, "suspicious_keys": []},
        "Playwright + expose_function": {"webdriver": False,
                                         "suspicious_keys": ["__playwright__binding__"]},
        "Selenium + ChromeDriver": {"webdriver": True, "suspicious_keys": ["$cdc_asdjflasutopfhvcZLmcfl_"]},
    }
    for label, signals in samples.items():
        print(label, score_automation_artifacts(signals))
