"""Network intelligence and the generic rate limiter — shared, not student-edited.

These are the layers the store already had coming out of Workshop 2: it knows a
datacenter IP from a residential one (W1 Ch3), and it rate-limits per IP (W1 Ch2).
They are *not* the point of this chapter. Each round shows where these generic
layers alone fall short and a scenario-specific signature catches what they miss.

The lab runs on one machine, so every request really comes from 127.0.0.1. A
script may *claim* a source IP with ``X-Lab-Client-IP``, but only from the RFC 5737
documentation ranges below, so no real address is ever used. In production the IP
comes from the TCP connection or your own edge, never from a client header.
"""

from __future__ import annotations

import ipaddress

# RFC 5737 documentation ranges, tagged so the store can reason about egress.
LAB_NETWORKS = [
    (ipaddress.ip_network("198.51.100.0/24"), "residential"),
    (ipaddress.ip_network("203.0.113.0/24"), "residential"),
    (ipaddress.ip_network("192.0.2.0/24"), "datacenter"),
]


def net_type(client_ip: str) -> str:
    """residential / datacenter / unknown for a claimed lab IP."""
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return "unknown"
    for net, kind in LAB_NETWORKS:
        if addr in net:
            return kind
    if addr.is_loopback:
        return "residential"  # the real human running the lab in a browser
    return "unknown"


def asn_of(client_ip: str) -> str:
    """A stand-in ASN label, enough to group egress in the scoreboard."""
    kind = net_type(client_ip)
    try:
        block = ".".join(client_ip.split(".")[:3])
    except Exception:
        block = client_ip
    return f"{kind}:{block}"


def rate_ok(rds, key: str, limit: int, window_s: int) -> bool:
    """A plain fixed-window per-key counter. True while under the limit.

    This is the generic rate limit from W1 Ch2. It stops a naive single-IP flood
    and nothing more: an attacker who rotates egress resets the key every request.
    """
    bucket = f"rl:{key}:{int(_time() // window_s)}"
    n = rds.incr(bucket)
    if n == 1:
        rds.expire(bucket, window_s * 2)
    return n <= limit


def _time():
    import time
    return time.time()
