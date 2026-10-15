"""Round 4 attack (b): replay a signed request that leaked.

A Web Bot Auth signature covering only `@authority` and `signature-agent` is valid for any method,
path or body sent to that host until it expires. Signed requests leak all the time: CDN and proxy
logs, debugging pastes, a browser extension's traffic dump. Two leaks from the mock's "paste site":

  stale: a ChatGPT-User request signed an hour ago with a 24-hour window
  fresh: one signed seconds ago with a 60-second window, replayed once per catalogue page

The signatures are genuine (the real chatgpt.com key signed them). Verification passes. Only policy
can refuse them: a window cap for the stale one, a nonce replay cache for the fresh one.

Expected: L4 -> both take the whole catalogue in the verified lane. L5 -> stale 0 pages (every
request a 403, window), fresh 1 page (the first replay is indistinguishable from the original; the
rest are 403, nonce).

    python attacks/round4_replay.py --stale     # or --fresh; no flag runs both
"""

from __future__ import annotations

import argparse

from _common import attacker_ip, authority, catalog_paths, finish, mock, report, scrape


def replay(kind: str, paths: list[str]) -> dict:
    leak = mock("GET", f"/leak/{kind}", params={"authority": authority()})
    ua = leak["headers"]["User-Agent"]
    sig = [(k, v) for k, v in leak["headers"].items() if k != "User-Agent"]
    return scrape(f"replay-{kind}", attacker_ip(f"replay_{kind}"), ua, paths, lambda path: sig)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stale", action="store_true")
    ap.add_argument("--fresh", action="store_true")
    a = ap.parse_args()
    kinds = [k for k, on in (("stale", a.stale), ("fresh", a.fresh)) if on] or ["stale", "fresh"]
    print("=== Round 4b: replay leaked ChatGPT-User signatures ===")
    paths = catalog_paths()
    out = {}
    for kind in kinds:
        out = replay(kind, paths)
        report({"stale": "stale leak, 24 h window", "fresh": "fresh leak, 60 s window"}[kind], out)
    finish(out)
