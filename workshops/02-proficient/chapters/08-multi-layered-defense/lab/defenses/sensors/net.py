"""
Layer: network reputation (stand-in for W1 Ch3)

Reads what the edge resolved for the source address: ASN type, Tor exit
status and a community blocklist hit (think CrowdSec's community blocklist).

False positives: datacenter ASNs are where VPNs, iCloud Private Relay-style
relays and corporate egress proxies live. Tor exits carry real people who
need privacy. Blocking either outright is a policy choice with a real human
cost, so this layer should rarely decide alone.
"""

LAYER = "net"
SIGNALS = {
    "ip_blocklist": "source IP is on the community blocklist",
    "tor_exit": "source IP is a Tor exit",
    "datacenter_asn": "source ASN is a hosting/VPN provider",
}


def sense(ctx):
    edge = ctx.edge
    found = []
    if edge.get("blocklisted"):
        found.append("ip_blocklist")
    if edge.get("type") == "tor":
        found.append("tor_exit")
    elif edge.get("type") == "datacenter":
        found.append("datacenter_asn")
    return found
