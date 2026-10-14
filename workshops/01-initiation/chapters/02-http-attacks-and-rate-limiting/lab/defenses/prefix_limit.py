"""
prefix_limit: rate-limit the network, not just the address.

    policy.RATE_LIMITS["prefix"]    per IPv4 /24    generous: one /24 can hold a whole office or ISP pool
    policy.RATE_LIMITS["prefix6"]   per IPv6 /64    tight: a /64 is ONE host's allocation

An IPv6 host is normally given a whole /64: 18 quintillion addresses. Rotating inside it is
free, so a per-address limit means nothing on IPv6. Counting per /64 puts the whole
allocation back in one bucket.

What it catches: rotation inside one allocation. The cloud_v6 attacker (a fresh address per
request from one VPS) goes from 100 % to its /64 bucket's worth.
What it misses: residential proxy networks. Their addresses are real subscribers spread over
many /64s (one per home), so no prefix bucket fills up. A fleet of IPv4 VMs spread over a
few /24s stays under the loose /24 bucket too.
Who it hurts: the /24 bucket is shared by everyone in that /24. In this world every home
shopper sits in 192.0.2.0/24, so a /24 limit tight enough to matter would hurt all of them.
That is why the v4 bucket is loose and the v6 bucket tight.

Keys on client_ip(ctx).
"""

import ipaddress

from .client_ip import client_ip, is_internal
from .pipeline import Check, Signal, Verdict
from .store import prefix_of


def _check(ctx):
    ip = client_ip(ctx)
    if is_internal(ip):
        return None
    # TODO (Round 5): pick the bucket by address family — "prefix" for IPv4 (/24),
    # "prefix6" for IPv6 (/64) — key it on prefix_of(ip), and when
    # ctx.bucket(bucket, prefix) refuses, return Verdict("rate_limit", retry_after=2,
    # signals=(Signal("rate_limit", f"{bucket}_rate_limit", 0, prefix),)). Shared with
    # Chapter 3: its lab starts from the reference version of this file.
    return None


CHECK = Check("prefix_limit", _check)
