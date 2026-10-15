"""
Layer: network reputation (stand-in for W1 Ch3)

Reads what the feeds say about the source address (netinfo_ch8.py, this chapter's richer fork of the starter's netinfo): a community blocklist hit, a
Tor exit, or a datacenter/VPN range.

False positives: datacenter ranges are where VPNs, corporate egress proxies and cloud desktops
live. Tor exits carry real people who need privacy. Blocking either outright is a policy choice
with a real human cost, so this layer should rarely decide alone. A privacy relay's range is
reported as `relay` and scores nothing (paying Safari customers).
"""

from . import netinfo_ch8 as netinfo

LAYER = "net"
SIGNALS = {
    "ip_blocklist": "source IP is on the community blocklist",
    "tor_exit": "source IP is a Tor exit",
    "datacenter_asn": "source ASN is a hosting/VPN provider",
}


def sense(ctx):
    net = netinfo.of(ctx)
    found = []
    if net["blocklisted"]:
        found.append("ip_blocklist")
    if net["kind"] == "tor":
        found.append("tor_exit")
    elif net["kind"] == "datacenter":
        found.append("datacenter_asn")
    return found
