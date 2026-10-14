"""
Round 2: hard-block addresses on the published blocklists.

    tor_exit     data/feeds/tor_exits.txt         every Tor exit (the Tor Project publishes them all)
    open_proxy   data/feeds/open_proxies.txt      public proxy lists, the ones attackers download too
    drop         data/feeds/drop_v4.json          Spamhaus DROP: hijacked or criminal netblocks
    firehol      data/feeds/firehol_level1.netset FireHOL level 1: an aggregate of conservative lists

One hit is a block: these lists are built to have almost no false positives (Tor is the
exception, and blocking it is a business decision; this store has no reason to accept
anonymous checkout).

What it catches: everything that lives on a public list. Tor at 100 %, the listed share of
the free proxies, the bulletproof host.
What it misses: whatever is newer than your copy of the list. A quarter of the free proxies
in this world are "fresher than the snapshot", and a fresh cloud VM is on no list at all.
Who it hurts: Tor users. Nobody else in the shopper population.

Internal addresses are never scored. The real FireHOL level 1 includes bogons (10/8,
127/8, ...): right for an internet-facing firewall, wrong for an app behind a load
balancer, where it would block your own health checks.

Keys on client_ip(ctx): until Round 4 a forged X-Forwarded-For is what gets looked up.
"""

from . import feeds as feeds_mod
from .client_ip import client_ip, is_internal
from .pipeline import Check, Signal, Verdict


def hits(ip):
    """Every blocklist this address is on."""
    if is_internal(ip):
        return []
    f = feeds_mod.feeds()
    found = []
    if ip in f.tor:
        found.append("tor_exit")
    if ip in f.open_proxies:
        found.append("open_proxy")
    if ip in f.drop:
        found.append("drop")
    if ip in f.firehol:
        found.append("firehol")
    return found


def _check(ctx):
    ip = client_ip(ctx)
    found = hits(ip)
    if found:
        return Verdict("block", 100, signals=tuple(Signal("blocklists", name, 100, ip) for name in found))
    return None


CHECK = Check("blocklists", _check)
