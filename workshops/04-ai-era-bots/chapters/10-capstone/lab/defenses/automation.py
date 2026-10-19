"""
W2 automation flags (W2 Ch1, Ch9) — carried into W4 Ch4 as a SHADOW instrument

The classic tells, checked when a session tries to check out:

    No telemetry from the drop page   +60   the page's JavaScript never ran (bare HTTP client)
    navigator.webdriver === true      +60   WebDriver / CDP-launched Chromium without patches
    Automation globals on window      +60   $cdc_ (ChromeDriver), __pwInitScripts, __selenium_…
    HeadlessChrome in UA or UA-CH     +60   headless Chromium that didn't rename itself

These catch default Selenium, Puppeteer and Playwright, and a lot of real
bot traffic still is exactly that. They catch none of Patchright, nodriver or
Camoufox, which exist to remove these specific tells. Keep them for the
volume they remove; don't mistake them for the defense.
"""


def score_automation(sess):
    fp, events = sess["fp"], sess["events"]
    if fp is None or events is None:
        return 60, ["No telemetry from the checkout page: its JavaScript never ran"]
    points, reasons = 0, []
    if fp.get("webdriver"):
        points += 60
        reasons.append("navigator.webdriver is true")
    if fp.get("automation_globals"):
        points += 60
        reasons.append(f"Automation globals on window: {', '.join(fp['automation_globals'][:3])}")
    brands = (fp.get("uach") or {}).get("brands") or []
    if "HeadlessChrome" in (fp.get("ua") or "") or any("HeadlessChrome" in b for b in brands):
        points += 60
        reasons.append("HeadlessChrome in navigator.userAgent or UA-CH brands")
    return points, reasons


if __name__ == '__main__':
    print(score_automation({"fp": None, "events": None}))
    print(score_automation({"fp": {"webdriver": True, "ua": "HeadlessChrome/146"}, "events": {}}))
