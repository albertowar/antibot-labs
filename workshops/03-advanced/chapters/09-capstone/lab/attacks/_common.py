"""
Chapter 9 — Shared attacker helpers (rules of engagement built in)

Every attack script imports this module. It enforces the lab's rules:

  - target() only returns http(s)://localhost / 127.0.0.1 / ::1 URLs and
    exits on anything else. These scripts must never point at a site you
    don't own, and that includes "just testing" a real store.
  - Egress IPs are *claimed* with the X-Lab-Egress header from
    data/egress_pool.txt, a documentation range (RFC 5737). No real proxy, no
    proxy list, no third-party infrastructure is ever used.
  - Accounts, emails and addresses are synthetic (@mail.example).

It also measures what each attack costs the attacker (wall time and CPU,
including browser child processes), because the economics are the point of
the last two rounds.
"""

import json
import os
import random
import sys
import time
import warnings
from urllib.parse import urlparse

try:
    import resource  # Unix only; on Windows CPU cost is reported as 0
except ImportError:
    resource = None

HERE = os.path.dirname(os.path.abspath(__file__))
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
FIRST = ["alex", "sam", "jordan", "taylor", "casey", "riley", "morgan", "jamie", "drew", "quinn", "avery", "rowan"]
LAST = ["miller", "davis", "clark", "lewis", "walker", "young", "hall", "allen", "king", "wright", "scott", "green"]
RESHIPPER_UNITS = ["Unit {n}", "Apt {n}", "#{n}", "Ste {n}", "Suite {n}"]
DROP = "/drop/lab-runner-9"

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


def target():
    url = os.environ.get("DEMO_URL", "https://localhost:8443").rstrip("/")
    host = urlparse(url).hostname
    if host not in LOCAL_HOSTS:
        sys.exit(f"🛑 Refusing to attack {host!r}. Lab attacks only run against your own local demo store.")
    return url


def egress_pool():
    with open(os.path.join(HERE, "data", "egress_pool.txt")) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def combo_list():
    with open(os.path.join(HERE, "data", "combo_list.txt")) as f:
        return [line.strip().split(":", 1) for line in f if ":" in line and not line.startswith("#")]


def farm_identity(rng):
    """A scalper's throwaway account: random name + digits, shipping to one reshipper."""
    email = f"{rng.choice(FIRST)}{rng.choice(LAST)}{rng.randint(100, 9999)}@mail.example"
    unit = rng.choice(RESHIPPER_UNITS).format(n=rng.randint(1, 400))
    return {"email": email, "password": f"Farm-{rng.getrandbits(32):08x}",
            "address": f"48 Harbor Freight Way, {unit}, Elizabeth NJ 07201"}


class Cost:
    """Wall-clock and CPU seconds for this process and its (finished) children."""

    def __enter__(self):
        self.wall = time.perf_counter()
        self.cpu = self._cpu()
        return self

    def __exit__(self, *exc):
        self.wall_s = time.perf_counter() - self.wall
        self.cpu_s = self._cpu() - self.cpu
        return False

    @staticmethod
    def _cpu():
        if resource is None:
            return 0.0
        s, c = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
        return s.ru_utime + s.ru_stime + c.ru_utime + c.ru_stime


def summary(name, results, cost, success_key="bought"):
    """The dict every attack's run() returns (read by tools/checkpoint.py)."""
    outcomes = {}
    for r in results:
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
    reasons = {}
    for r in results:
        for reason in r.get("reasons", []):
            reasons[reason] = reasons.get(reason, 0) + 1
    succeeded = sum(1 for r in results if r.get(success_key))
    return {
        "attack": name, "attempts": len(results), "succeeded": succeeded, "outcomes": outcomes,
        "top_reasons": sorted(reasons, key=reasons.get, reverse=True)[:4],
        "sids": [r["sid"] for r in results if r.get("sid")],
        "wall_s": round(cost.wall_s, 2), "cpu_s": round(cost.cpu_s, 2),
        "wall_s_per_attempt": round(cost.wall_s / max(1, len(results)), 2),
        "results": results,
    }


def report(s, success_label="pairs bought"):
    print(f"=== {s['attack']}: {s['succeeded']}/{s['attempts']} {success_label} ===")
    print(f"  outcomes: {json.dumps(s['outcomes'])}")
    for reason in s["top_reasons"]:
        print(f"    - {reason}")
    print(f"  attacker cost: {s['wall_s']} s wall, {s['cpu_s']} s CPU "
          f"({s['wall_s_per_attempt']} s per attempt)")


# --------------------------------------------------------------------------
# Browser helpers (Playwright, Patchright and Camoufox share this API)
# --------------------------------------------------------------------------

def read_result(page, timeout_ms=20000, success_path=None):
    """Wait for #result[data-outcome], or for the redirect a successful form does."""
    deadline = time.monotonic() + timeout_ms / 1000
    while time.monotonic() < deadline:
        if success_path and urlparse(page.url).path == success_path:
            return "allow", []
        try:
            el = page.query_selector("#result[data-outcome]")
            if el is not None:
                reasons = [li.inner_text() for li in page.query_selector_all("#result li")]
                return el.get_attribute("data-outcome"), reasons
        except Exception:  # navigation in progress
            pass
        time.sleep(0.1)
    return "error", ["timed out waiting for the page"]


def page_status(response):
    return response.status if response is not None else 0


def blocked_reasons(page):
    return [li.inner_text() for li in page.query_selector_all("li")] or ["page blocked (403)"]


def whoami_sid(page, base):
    page.goto(f"{base}/whoami")
    try:
        return json.loads(page.inner_text("body"))["sid"]
    except (ValueError, KeyError):
        return None


def browser_register(page, base, ident, type_delay=None):
    response = page.goto(f"{base}/register")
    if page_status(response) == 403:
        return "block", blocked_reasons(page)
    kw = {"delay": type_delay} if type_delay else {}
    for name, value in (("email", ident["email"]), ("password", ident["password"]), ("address", ident["address"])):
        if type_delay:
            page.click(f"#register-form input[name={name}]")
            page.keyboard.type(value, **kw)
        else:
            page.fill(f"#register-form input[name={name}]", value)
    page.click("#register-submit")
    return read_result(page, success_path="/account")


def browser_login(page, base, email, password, type_delay=None):
    response = page.goto(f"{base}/login")
    if page_status(response) == 403:
        return "block", blocked_reasons(page)
    for name, value in (("email", email), ("password", password)):
        if type_delay:
            page.click(f"#login-form input[name={name}]")
            page.keyboard.type(value, delay=type_delay)
        else:
            page.fill(f"#login-form input[name={name}]", value)
    page.click("#login-submit")
    return read_result(page, success_path="/account")


def browser_buy(page, base, before_click=None):
    if urlparse(page.url).path != DROP:
        response = page.goto(f"{base}{DROP}")
        if page_status(response) == 403:
            return "block", blocked_reasons(page)
    if before_click:
        before_click(page)
    page.click("#buy")
    return read_result(page)


def patch_headless_chromium(context, page, browser_version):
    """
    What a headless farm does after the first ban: rewrite the UA *and* the
    UA-CH metadata over CDP so neither says HeadlessChrome. It works on the
    page. It does not reach the page's Web Workers.
    """
    major = browser_version.split(".")[0]
    ua = (f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
          f"Chrome/{major}.0.0.0 Safari/537.36")
    brands = [{"brand": "Chromium", "version": major}, {"brand": "Google Chrome", "version": major},
              {"brand": "Not.A/Brand", "version": "99"}]
    cdp = context.new_cdp_session(page)
    cdp.send("Emulation.setUserAgentOverride", {
        "userAgent": ua, "acceptLanguage": "en-US,en;q=0.9", "platform": "Win32",
        "userAgentMetadata": {"brands": brands, "fullVersionList": brands, "platform": "Windows",
                              "platformVersion": "15.0.0", "architecture": "x86", "model": "",
                              "mobile": False, "bitness": "64"}})


def rng_for(name):
    return random.Random(f"{name}:{time.time_ns()}")
