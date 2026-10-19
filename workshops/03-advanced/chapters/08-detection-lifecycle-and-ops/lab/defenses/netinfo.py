"""
netinfo: what kind of network is this address?

The store's edge hands every check an ASN, an organization and a country (`ctx.edge`). It
never says what KIND of network that is: a production ASN database (IPinfo, MaxMind GeoIP2)
sells that as a separate field, and you derive it from feeds when you do not buy one. This
module does the second, from the same synthetic feeds W1 Ch3 uses (`data/feeds/`):

    tor         the address is on the Tor exit list
    relay       a privacy relay's egress range (paying Safari customers, not bots)
    datacenter  a hosting ASN, a cloud or VPN range, or an open proxy
    mobile      carrier-grade NAT: hundreds of people behind one address
    corporate   an office or university egress
    residential everything else

and, separately, `blocklisted`: the address is on the community blocklist (the synthetic
FireHOL level 1). That list also carries the Tor and open-proxy ranges here, so a Tor exit is
reported as `tor` only: W1 Ch3's lesson is that a Tor Browser user must not be charged twice.

Every one of these is context, never a verdict: datacenter ranges are where VPNs, relays and
corporate proxies live.

Chapter 8: the feeds are *data with a date*. This module reads the store's feeds plus two things
from the chapter's snapshot (corpus.py): an old community-blocklist entry (data/ops_world.json),
and the ranges that changed owner since, which a refresh (tools/refresh_corpus.py) writes to
data/world_updates.json. A reassigned range is judged by its new owner and its old blocklist entry
is retired with it. Until the refresh runs, the sensor keeps charging the new owner's customers
for the previous owner's reputation (Round 2).
"""

import csv
import ipaddress
import os

from . import corpus

FEEDS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "feeds")
_DC_WORDS = ("cloud", "hosting", "vps", "vpn", "bulletproof", "datacenter")
_state = {}


def _load():
    if _state:
        return _state
    def nets(name):
        with open(os.path.join(FEEDS, name)) as fh:
            return [ipaddress.ip_network(r["cidr"]) for r in csv.DictReader(fh)]
    def lines(name):
        with open(os.path.join(FEEDS, name)) as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    with open(os.path.join(FEEDS, "hosting_asns.csv")) as fh:
        hosting = {int(r["asn"]) for r in csv.DictReader(fh)}
    _state.update(hosting=hosting, cloud=nets("cloud_ranges.csv"), vpn=nets("vpn_ranges.csv"),
                  relay=nets("relay_ranges.csv"), tor=set(lines("tor_exits.txt")),
                  proxies=set(lines("open_proxies.txt")),
                  blocklist=[ipaddress.ip_network(c) for c in lines("firehol_level1.netset")
                                  + corpus.snapshot().get("community_blocklist_stale", [])])
    return _state


def _in(addr, networks):
    return any(addr in n for n in networks if n.version == addr.version)


def classify(ip, asn=0, org=""):
    """{"kind": ..., "blocklisted": bool} for an address and the ASN/org the edge resolved for it."""
    s = _load()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"kind": "unknown", "blocklisted": False}
    # What the refresh learned since the snapshot takes precedence over the feeds
    for cidr in corpus.updates().get("reassigned", {}):
        if _in(addr, [ipaddress.ip_network(cidr)]):
            return {"kind": "residential", "blocklisted": False}
    low = org.lower()
    if str(addr) in s["tor"]:
        return {"kind": "tor", "blocklisted": False}
    listed = _in(addr, s["blocklist"])
    if _in(addr, s["relay"]):
        kind = "relay"
    elif (asn in s["hosting"] or str(addr) in s["proxies"] or _in(addr, s["cloud"]) or _in(addr, s["vpn"])
          or any(w in low for w in _DC_WORDS)):
        kind = "datacenter"
    elif "mobile" in low:
        kind = "mobile"
    elif "corp" in low or "university" in low:
        kind = "corporate"
    else:
        kind = "residential"
    return {"kind": kind, "blocklisted": listed}


def of(ctx):
    """classify() for this request's source address, computed once per request."""
    if "ops_net" not in ctx.attrs:
        ctx.attrs["ops_net"] = classify(ctx.edge.ip, ctx.edge.asn, ctx.edge.org)
    return ctx.attrs["ops_net"]


# Continent of the country the edge resolved: enough for "is the browser's time zone on the
# same continent as the address?" (correlation.py). Documentation countries only.
CONTINENT = {"US": "America", "CA": "America", "BR": "America", "NL": "Europe", "DE": "Europe",
             "GB": "Europe", "FR": "Europe", "JP": "Asia", "IN": "Asia"}
