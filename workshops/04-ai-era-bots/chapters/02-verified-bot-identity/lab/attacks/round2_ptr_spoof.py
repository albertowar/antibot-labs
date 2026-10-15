"""Round 2 attack: own the reverse zone, name your box after Googlebot.

Level 1 checks that the PTR of the source IP ends in `.googlebot.com`. The PTR of an address in the
attacker's hosting allocation is set by whoever controls that reverse zone, which is the attacker's
hosting provider, and every hosting panel lets a tenant set it to any string. Two tries, from two
rented hosting addresses:

  a) a substring trick, for sloppy matchers:  crawl-1.googlebot.com.attacker-hosting.example
  b) an outright forgery:                    crawl-198-51-100-97.googlebot.com

Try (b) beats a suffix-only check. It cannot beat forward confirmation: Google's zone resolves that
name to 198.51.100.97, not to the attacker's address.

Expected: L1 -> (a) held, (b) the whole catalogue in the verified lane. L2 -> both held
("does not resolve back").

    python attacks/round2_ptr_spoof.py
"""

from __future__ import annotations

from _common import UA, attacker_ip, catalog_paths, finish, mock, report, scrape

SUBSTRING_PTR = "crawl-1.googlebot.com.attacker-hosting.example"
FORGED_PTR = "crawl-198-51-100-97.googlebot.com"


def set_ptr(ip: str, name: str) -> None:
    mock("PUT", "/hosting/ptr", json={"ip": ip, "name": name})


def run() -> dict:
    paths = catalog_paths()
    set_ptr(attacker_ip("ptr_substring"), SUBSTRING_PTR)
    substring = scrape("ptr-substring", attacker_ip("ptr_substring"), UA["Googlebot"], paths)
    set_ptr(attacker_ip("ptr_forged"), FORGED_PTR)
    forged = scrape("ptr-forged", attacker_ip("ptr_forged"), UA["Googlebot"], paths)
    return {**forged, "substring": substring}


if __name__ == "__main__":
    print("=== Round 2: rewrite our own PTR, then claim Googlebot ===")
    out = run()
    report(f"PTR {SUBSTRING_PTR[:30]}…", out["substring"])
    report(f"PTR {FORGED_PTR}", out)
    finish(out)
