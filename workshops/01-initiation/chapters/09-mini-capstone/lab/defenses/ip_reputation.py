"""
Round 3: score the network an address belongs to, before it has done anything.

Signals and points (policy.IP_POINTS), summed on the 0-100 scale:

    datacenter      40   in a cloud provider's published ranges (cloud_ranges.csv)
    known_vpn       40   on the community VPN list (vpn_ranges.csv)
    hosting_asn     25   the ASN is on the community hosting list (hosting_asns.csv)
    privacy_relay    0   in the privacy relay's published egress (relay_ranges.csv): context, not suspicion

    score >= 75 block, >= 40 challenge, >= 20 monitor (policy.BANDS)

There is no challenge type in this chapter (CAPTCHA arrives in Chapter 6, proof of work in
Chapter 7), so the challenge band is enforced as a block: a challenged shopper is a lost one.

What it catches: fresh cloud VMs. A VM bought five minutes ago is on no blocklist, but it
sits in a published cloud range and usually in a hosting ASN.
What it misses:
  - every source has gaps. `cloud_gcp` is in the cloud ranges but its ASN is on no hosting
    list, so it scores exactly 40. Drop `datacenter` to 30 and it falls to monitor.
  - an IPv6 VPS whose provider publishes no ranges and is on no list (`cloud_v6`) scores 0.
  - residential proxies. They ARE home connections: same ISPs, same score as your customers.
Who it hurts: people whose traffic leaves from a datacenter. Consumer VPN users (known_vpn,
40: challenged). Privacy relay users, because the community VPN list carries the relay's
egress too: known_vpn fires for them. Set policy.TRUST_PRIVACY_RELAYS = True and a relay hit
cancels the infrastructure signals. Is that safe? The relay operator knows the customer and
rate-limits per account, but to you the client is still anonymous.

Internal addresses are never scored. Additive points assume independent signals; they are
not (a cloud VM is usually also a hosting ASN). W2 Ch8 calibrates them.

    python -m defenses.ip_reputation                 # one address from every world.json pool
    python -m defenses.ip_reputation 203.0.113.5     # any address
"""

from . import feeds as feeds_mod
from . import policy
from .client_ip import client_ip, is_internal
from .pipeline import Check, Signal

INFRASTRUCTURE_SIGNALS = ("datacenter", "hosting_asn", "known_vpn")


def lookup(ip):
    """Network facts an IP intelligence feed would give you: ASN, organisation, country, cloud provider."""
    if is_internal(ip):
        return {"ip": ip, "asn": None, "org": "internal", "country": None, "provider": None, "internal": True}
    f = feeds_mod.feeds()
    asn, cc, org = f.asn.find(ip) or (None, None, None)
    return {"ip": ip, "asn": asn, "org": org, "country": cc, "provider": f.cloud_provider.find(ip), "internal": False}


def signals(ip):
    """{signal name: points} for every reputation signal that fires for this address."""
    if is_internal(ip):
        return {}
    f = feeds_mod.feeds()
    info = lookup(ip)
    found = {}
    if ip in f.cloud:
        found["datacenter"] = policy.IP_POINTS["datacenter"]
    if info["asn"] in f.hosting_asns:
        found["hosting_asn"] = policy.IP_POINTS["hosting_asn"]
    if ip in f.vpn:
        found["known_vpn"] = policy.IP_POINTS["known_vpn"]
    if ip in f.relay:
        found["privacy_relay"] = policy.IP_POINTS["privacy_relay"]
        if getattr(policy, "TRUST_PRIVACY_RELAYS", False):
            for name in INFRASTRUCTURE_SIGNALS:
                found.pop(name, None)
    return found


def explain(ip):
    """Everything about one address: network, reputation signals, blocklists, score and band."""
    from . import blocklists
    sig = signals(ip)
    lists = blocklists.hits(ip)
    score = 100 if lists else min(100, sum(sig.values()))
    band = "block" if lists else policy.decide(score, [], 0)
    return {"network": lookup(ip), "signals": sig, "blocklists": lists, "score": score, "band": band}


def _check(ctx):
    ip = client_ip(ctx)
    info = lookup(ip)
    where = f"AS{info['asn']} {info['org']}" if info["asn"] else "unknown network"
    return [Signal("ip_reputation", name, points, where) for name, points in signals(ip).items()]


CHECK = Check("ip_reputation", _check)


if __name__ == "__main__":
    import json
    import os
    import sys
    if len(sys.argv) > 1:
        rows = [("", ip) for ip in sys.argv[1:]]
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, os.path.join(here, "..", "tools"))
        os.environ.setdefault("DEMO_URL", "http://127.0.0.1:5000")
        from labclient import WORLD, world_pool
        rows = [(name, world_pool(name)[0]) for name in WORLD["pools"]]
        bad = [name for name, ip in rows if is_internal(ip)]
        assert not bad, f"is_internal() calls lab pools internal: {bad}"
    for pool, ip in rows:
        e = explain(ip)
        net = e["network"]
        sig = dict(e["signals"], **{b: 100 for b in e["blocklists"]})
        print(f"{pool:<18} {ip:<18} AS{net['asn']} {str(net['org'])[:26]:<26} {net['country'] or '--'}  "
              f"score={e['score']:>3} {e['band']:<9} {json.dumps(sig)}")
