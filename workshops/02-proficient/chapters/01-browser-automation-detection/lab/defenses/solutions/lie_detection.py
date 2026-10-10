"""
W2 Ch1 — Defense Layer 3: Lie Detection (Section 1.3)

Stealth plugins (playwright-stealth, puppeteer-extra-plugin-stealth) beat
Layer 2 by rewriting the values it reads: they replace getters such as
navigator.plugins or window.outerHeight with JavaScript functions that
return believable answers. We stop asking "is the value plausible?" and ask
"was the value produced by the browser?".

  Native integrity  A browser getter stringifies to native code that names
                    the property, e.g. "function get plugins() { [native code] }",
                    and has no .prototype. A replacement written in JavaScript
                    usually fails at least one of these. A Proxy around the
                    native getter loses its name in Chromium:
                    "function () { [native code] }".
  Own properties    Chrome and Firefox define navigator's properties on
                    Navigator.prototype. A property on the navigator object
                    itself was put there by a script.
  Realms            Init scripts patch the page's main world. A Worker and a
                    fresh iframe are separate JavaScript realms; reading the
                    same values there exposes the patch if it did not follow.

False positives: privacy extensions (JShelter, CanvasBlocker and similar)
replace getters for the same reasons stealth plugins do. A modified
environment ALONE is therefore worth 30 points ("suspicious"); it takes a
lie AND an inconsistency to reach 40 ("bot").

Enabled when DEFENSE_LEVEL >= 3.
"""


def is_native(label, report):
    """True if the sensor's description of a function looks like browser native code."""
    if not report:
        return True                         # not present in this browser: nothing to judge
    prop = label.rsplit(".", 1)[-1]
    src = report.get("src") or ""
    return "[native code]" in src and prop in src and not report.get("proto")


def check_native_getters(signals):
    """Getters and methods we read must be native; navigator must have no own properties."""
    replaced = [label for label, report in (signals.get("native") or {}).items()
                if not is_native(label, report)]
    own = signals.get("navigator_own_props") or []
    reasons = []
    if replaced:
        reasons.append(f"Native code replaced by script: {', '.join(replaced[:4])}"
                       + (f" (+{len(replaced) - 4} more)" if len(replaced) > 4 else ""))
    if own:
        reasons.append(f"Properties redefined on the navigator object itself: {', '.join(own[:4])}")
    return (30, reasons) if reasons else (0, [])


def realm_differences(signals):
    """List the fields where a Worker or an iframe disagrees with the main page."""
    diffs = []
    main_brands = [b.split("/")[0] for b in ((signals.get("uad") or {}).get("brands") or [])]
    worker = signals.get("worker") or {}
    if worker and "error" not in worker:
        main = {"ua": signals.get("ua"), "platform": signals.get("platform"),
                "languages": signals.get("languages"),
                "hardware_concurrency": signals.get("hardware_concurrency"),
                "brands": main_brands or None}
        for field, value in main.items():
            if field in worker and worker[field] != value:
                diffs.append(f"Worker {field}")
    iframe = signals.get("iframe") or {}
    if iframe and "error" not in iframe:
        for field in ("ua", "platform", "webdriver"):
            if field in iframe and iframe[field] != signals.get(field):
                diffs.append(f"iframe {field}")
    return diffs


def check_realm_consistency(signals):
    """
    Round 3: the same navigator values read in a Worker and in an iframe must
    match the main page. Returns (points, reasons).
    """
    diffs = realm_differences(signals)
    if diffs:
        return 40, [f"Another JavaScript realm disagrees with the page: {', '.join(diffs)}"]
    return 0, []


def score_lies(signals):
    """Layer 3. Returns (score, reasons)."""
    score = 0
    reasons = []
    for check in (check_native_getters, check_realm_consistency):
        points, why = check(signals)
        score += points
        reasons.extend(why)
    return score, reasons


if __name__ == '__main__':
    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
    stealth = {
        "ua": ua, "platform": "Linux x86_64", "languages": ["en-US", "en"], "hardware_concurrency": 8,
        "native": {
            "Navigator.plugins": {"src": "get plugins() { return fakePlugins }", "proto": False},
            "Navigator.languages": {"src": "function () { [native code] }", "proto": False},
            "Navigator.webdriver": {"src": "function get webdriver() { [native code] }", "proto": False},
        },
        "navigator_own_props": [],
        "worker": {"ua": ua.replace("Chrome/", "HeadlessChrome/"), "platform": "Linux x86_64",
                   "languages": ["en-US"], "hardware_concurrency": 8},
        "iframe": {"ua": ua, "platform": "Linux x86_64", "webdriver": False},
        "webdriver": False,
    }
    print(score_lies(stealth))
