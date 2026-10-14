"""
Chapter 2, Round 5 attack: a residential proxy network.

Round 5 fixes the foundation (trusted_proxy makes client_ip read from the right) and adds
per-prefix limits. Against a forged X-Forwarded-For that is fatal, and against IPv6 rotation
inside one /64 it bites. So the attacker's last move in THIS chapter is the one rate limiting
cannot answer: a different real home address, in a different /64, for every request.

Each request here comes from the residential_proxy_net group (six ISPs, six countries, one
address per /64), so no /24 or /64 bucket ever fills and every address is clean. The scrape
sails through. That is the hand-off: rate limiting has run out of road. Catching this needs
IP reputation and session signals, which is Chapter 3.

    python attacks/round5_residential.py

Expected:   level 5 (trusted_proxy + prefix_limit): ~120/120 (full). Rate limiting alone does
            not stop residential rotation; the next chapter picks it up.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import ipkit  # noqa: E402  (guard runs on import)
from labclient import world_pool  # noqa: E402


def run():
    ips = world_pool("residential_proxy_net")
    return ipkit.scrape("r5_residential", lambda i: ips[i % len(ips)], keep_cookies=False,
                        extra={"pool": "residential_proxy_net"})


if __name__ == "__main__":
    ipkit.finish(run())
