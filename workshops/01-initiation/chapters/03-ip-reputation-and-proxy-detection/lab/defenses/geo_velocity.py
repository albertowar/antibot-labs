"""
Round 5 (with prefix_limit): watch how the address changes within one session.

When every address is clean, the address stops being the signal. What a residential proxy
network cannot hide is that ONE session (one `sid` cookie) keeps arriving from new homes,
often in new countries, seconds apart:

    session_ip_churn      45   more than policy.MAX_IPS_PER_SESSION addresses in GEO_WINDOW_S
    session_country_hop   80   more than policy.MAX_COUNTRIES_PER_SESSION countries in GEO_WINDOW_S

History is a per-session sorted set (`ctx.session.ns("geo")`) of "ip|country", scored by time
and trimmed to the window. The country comes from the ip2asn feed via ip_reputation.lookup().

What it catches: rotating proxies that keep their cookies. Churn alone (pin the country) is
a challenge; churn plus hops is a block.
What it misses: a bot that drops its cookies. A fresh cookie jar per request is a brand-new
session from a brand-new clean address every time, and this check has nothing to compare.
That is where the IP layer ends: the next signals are the client itself (headers in
Chapter 4, sessions in Chapter 5).
Who it hurts: travellers and phones, in principle. A phone hops between Wi-Fi and the carrier
(two addresses, one country), and a traveller changes country over hours, not seconds. Keep
the window short and the thresholds above what one person does. One shopper in this
population checks out from a different address than they browsed from; MAX_IPS_PER_SESSION
= 3 leaves them alone.
"""

import time

from . import policy
from .client_ip import client_ip
from .pipeline import Check, Signal


def _check(ctx):
    from .ip_reputation import lookup
    ip = client_ip(ctx)
    country = lookup(ip)["country"] or "--"
    key = ctx.session.ns("geo") + "seen"
    now = time.time()
    p = ctx.redis.pipeline()
    p.zadd(key, {f"{ip}|{country}": now})
    p.zremrangebyscore(key, 0, now - policy.GEO_WINDOW_S)
    p.zrange(key, 0, -1)
    p.expire(key, policy.GEO_WINDOW_S + 1)
    seen = p.execute()[2]
    ips = {s.split("|")[0] for s in seen}
    countries = {s.split("|")[1] for s in seen} - {"--"}
    out = []
    if len(ips) > policy.MAX_IPS_PER_SESSION:
        out.append(Signal("geo_velocity", "session_ip_churn", policy.GEO_POINTS["session_ip_churn"], f"{len(ips)} IPs"))
    if len(countries) > policy.MAX_COUNTRIES_PER_SESSION:
        out.append(Signal("geo_velocity", "session_country_hop", policy.GEO_POINTS["session_country_hop"],
                          ",".join(sorted(countries))))
    return out


CHECK = Check("geo_velocity", _check)
