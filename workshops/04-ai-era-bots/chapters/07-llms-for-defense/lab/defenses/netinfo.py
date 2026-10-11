"""
W4 Chapter 7 — Simulated network edge: IP → ASN type and country

In production your CDN or edge proxy hands the app the client IP plus an
ASN/geo lookup (MaxMind GeoLite2, IPinfo, ...), as built in W1 Ch3. The lab
has no real network, so every simulated client sends its address in
`X-Lab-Client-IP` and this module plays the ASN database.

All prefixes are private or reserved ranges, so lab data can never be
mistaken for a real person's address.

Trade-off worth remembering: `asn_type` is one of the strongest single
features for a bot model, and also the one that hurts VPN users, corporate
egress and CGNAT mobile users the most. Treat it as context, never a verdict.
"""

import ipaddress

# prefix -> (asn, asn_type, country)
PREFIXES = [
    # Residential ISPs (one /16 per ISP)
    ("10.1.0.0/16", "AS64601 Iberia Fibra", "residential", "ES"),
    ("10.2.0.0/16", "AS64602 Lakeside Cable", "residential", "US"),
    ("10.3.0.0/16", "AS64603 Rhein DSL", "residential", "DE"),
    ("10.4.0.0/16", "AS64604 Thames Broadband", "residential", "GB"),
    ("10.5.0.0/16", "AS64605 Prairie Net", "residential", "US"),
    # Mobile carriers: CGNAT, thousands of users behind a handful of IPs
    ("100.64.0.0/16", "AS64611 Meseta Mobile", "mobile", "ES"),
    ("100.65.0.0/16", "AS64612 Coastline Wireless", "mobile", "US"),
    ("100.66.0.0/16", "AS64613 Alpen Mobil", "mobile", "DE"),
    # Hosting / cloud
    ("172.16.0.0/16", "AS64621 NimbusCloud", "datacenter", "US"),
    ("172.17.0.0/16", "AS64622 KraftHost", "datacenter", "DE"),
    # Commercial VPN exits live in hosting ASNs too
    ("172.20.0.0/16", "AS64631 PrivTunnel VPN", "datacenter", "NL"),
    # Corporate egress
    ("192.168.0.0/16", "AS64641 Acme Corp", "corporate", "US"),
]

_TABLE = [(ipaddress.ip_network(p), asn, kind, cc) for p, asn, kind, cc in PREFIXES]
ASN_TYPES = ["residential", "mobile", "datacenter", "corporate", "unknown"]


def lookup(ip):
    """Return {asn, asn_type, country} for an IP; 'unknown' when not in the table."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"asn": "?", "asn_type": "unknown", "country": "??"}
    for net, asn, kind, cc in _TABLE:
        if addr in net:
            return {"asn": asn, "asn_type": kind, "country": cc}
    return {"asn": "?", "asn_type": "unknown", "country": "??"}


def ip24(ip):
    """The /24 a client sits in: the unit residential proxy pools and CGNAT share."""
    return ".".join(str(ip).split(".")[:3])


if __name__ == "__main__":
    for ip in ["10.1.4.20", "100.65.0.3", "172.20.9.9", "192.168.1.1", "8.8.8.8"]:
        print(f"{ip:<14} {lookup(ip)}")
