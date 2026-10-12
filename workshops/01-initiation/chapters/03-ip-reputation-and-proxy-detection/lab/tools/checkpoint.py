"""
Round checkpoint for Chapter 3 (IP Reputation & Proxy Detection). Declares the rounds and hands over
to checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run the round's attacks next to the shoppers
    python tools/checkpoint.py --round 3 --level 2    # the same attacks against Round 2's defenses (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first
    python tools/checkpoint.py --all --markdown       # every round (the reference table)

Every round measures two numbers: how much of the catalog the scraper got, and which shoppers
the defense stopped. The 40 shoppers run the `rush` scenario (tools/personas_ch3.py) so that the
six phones sharing one carrier-NAT address actually meet the per-IP limit. A round lists the
personas it is allowed to hurt (`allowed_fp`): that list IS the false-positive cost of the
layer, and the scoreboard shows it next to the bots stopped.

There is no challenge type in this chapter, so a challenge verdict is enforced as a block.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch3  # noqa: E402,F401  (registers the `rush` scenario)
from checkpoint_core import Round, main  # noqa: E402
from labclient import admin  # noqa: E402


def hurt(results, persona):
    return [r for r in results if r["persona"] == persona and r.get("outcome") in ("blocked", "stuck_on_challenge")]


def cgnat_pays(board, results):
    """Round 1's lesson: a limit sized for one person throttles everyone behind a carrier NAT."""
    n = len(hurt(results, "mobile_cgnat"))
    return n >= 1, f"expected the per-IP limit to stop at least one mobile_cgnat shopper, stopped {n}"


def relay_not_hurt(board, results):
    """After the blue step (TRUST_PRIVACY_RELAYS = True), privacy relay users get through."""
    n = len(hurt(results, "private_relay"))
    return n == 0, (f"{n} private_relay shoppers stopped: the community VPN list carries the relay's egress. "
                    "Set TRUST_PRIVACY_RELAYS = True in defenses/policy.py (Round 3, blue)")


def dead_proxies_cost(board, results, attacks):
    out = attacks.get("free_proxy") or {}
    return out.get("dead_proxy_skipped", 0) > 0, "the free proxy list should have cost the scraper dead proxies"


def no_geo_on_shoppers(board, results):
    """geo_velocity must not fire on a shopper (one of them checks out from a second address)."""
    rows = admin("GET", "/lab/decisions", params={"actor": "human:", "limit": 5000})["items"]
    flagged = sorted({d["actor"] for d in rows if "geo_velocity:" in (d.get("signals") or "")})
    return not flagged, f"geo_velocity flagged shoppers: {flagged}"


SOL = ("defenses/ladder.py",)

ROUNDS = {
    1: Round(level=1, description="one cloud VM vs a per-IP rate limit", scenario="rush",
             attacks={"single_ip": "attacks/round1_single_ip.py",
                      "ipv6_rotation": "attacks/round1_single_ip.py --pool cloud_v6"},
             expect={"single_ip": "partial", "ipv6_rotation": "full"},
             allowed_fp=("mobile_cgnat",), extra_checks=[cgnat_pays], solutions=SOL),
    2: Round(level=2, description="free proxies and Tor vs blocklists", scenario="rush",
             attacks={"free_proxy": "attacks/round2_free_proxies.py",
                      "tor": "attacks/round2_free_proxies.py --pool tor_exit",
                      "bulletproof": "attacks/round2_free_proxies.py --pool bulletproof_host"},
             expect={"free_proxy": "partial", "tor": "blocked", "bulletproof": "blocked"},
             allowed_fp=("mobile_cgnat",), extra_checks=[dead_proxies_cost], solutions=SOL),
    3: Round(level=3, description="fresh cloud VMs vs reputation scoring", scenario="rush",
             attacks={"cloud_vms": "attacks/round3_cloud_vms.py"},
             expect={"cloud_vms": "blocked"},
             allowed_fp=("mobile_cgnat", "consumer_vpn"), extra_checks=[relay_not_hurt],
             solutions=SOL + ("defenses/policy.py",)),
    4: Round(level=4, description="X-Forwarded-For spoofing vs trusted proxies", scenario="rush",
             attacks={"xff_home": "attacks/round4_xff_spoof.py",
                      "xff_localhost": "attacks/round4_xff_spoof.py --spoof-as 127.0.0.1",
                      "xff_internal_random": "attacks/round4_xff_spoof.py --spoof-as internal-random"},
             expect={"xff_home": "blocked", "xff_localhost": "blocked", "xff_internal_random": "blocked"},
             allowed_fp=("mobile_cgnat", "consumer_vpn"), solutions=SOL),
    5: Round(level=5, description="residential proxies vs session signals and /64 limits", scenario="rush",
             attacks={"residential": "attacks/round5_residential.py",
                      "residential_us": "attacks/round5_residential.py --pin-country US",
                      "residential_nocookies": "attacks/round5_residential.py --no-cookies",
                      "ipv6_rotation": "attacks/round1_single_ip.py --pool cloud_v6 --no-cookies"},
             expect={"residential": "blocked", "residential_us": "blocked", "residential_nocookies": "full",
                     "ipv6_rotation": "partial"},
             allowed_fp=("mobile_cgnat", "consumer_vpn"), extra_checks=[no_geo_on_shoppers], solutions=SOL),
}

if __name__ == "__main__":
    main(ROUNDS)
