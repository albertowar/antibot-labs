"""
Which IP? Every IP-based check in this lab asks client_ip(ctx), never ctx.edge.ip directly.

In production the app sits behind a CDN or load balancer, so the TCP peer is your own
proxy and the client is reported in X-Forwarded-For. Each proxy APPENDS the address it
saw, so the chain the origin receives is

    X-Forwarded-For: <whatever the client sent>, <client as seen by your edge>

The lab edge forwards exactly that as ctx.edge.xff_claimed. Only the last entry was
written by infrastructure you run. Everything to its left was written by the client.

    naive_client_ip     the leftmost entry: the classic bug. The attacker controls the
                        input to every IP-based defense that keys on it.
    trusted_client_ip   walk from the right, skip only proxies you operate, stop at the
                        first hop you don't: the client as your edge saw it.

Until Round 4 wires `trusted_proxy` into the ladder, client_ip() uses the naive reader,
like many real apps that grew an `request.headers["X-Forwarded-For"].split(",")[0]`
somewhere. Rounds 1-3 work against honest clients and fall over the moment one lies.

Which reader is live depends on the ladder at the CURRENT level, so running Round 4's
attack at `--level 3` still shows the bypass. Shadow checks don't count: a check that is
only logging has not fixed anything.

Not in this lab: origin bypass. If the origin is reachable directly, the attacker writes
the whole chain, including the "trusted" last entry. Lock the origin to the edge with a
firewall on the CDN's ranges, mutual TLS, or a shared secret header (authenticated origin
pulls). The lab's edge is in-process, so there is no origin to reach around it.
"""

import ipaddress

# Proxies you operate. The lab edge is the only hop, and it appends the peer itself,
# so nothing else is trusted. Behind a real load balancer you would list its addresses.
TRUSTED_PROXIES = {"127.0.0.1", "::1"}

# Addresses that are never a client on the internet. Not ipaddress.is_global: that is
# False for the documentation ranges (RFC 5737/3849) every lab address comes from, so
# it would call the whole simulated internet "internal".
INTERNAL = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "::1/128", "::/128", "fc00::/7", "fe80::/10")]


def _valid_ip(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        return None


def is_internal(ip):
    addr = ipaddress.ip_address(ip)
    return any(addr.version == n.version and addr in n for n in INTERNAL)


def forwarded_chain(ctx):
    """The X-Forwarded-For entries as the edge forwards them (client-written ones first)."""
    raw = ctx.edge.xff_claimed or ctx.edge.ip
    return [h.strip() for h in raw.split(",") if h.strip()]


def naive_client_ip(ctx):
    """The classic bug: trust the leftmost X-Forwarded-For entry. The client wrote it."""
    chain = forwarded_chain(ctx)
    return (_valid_ip(chain[0]) if chain else None) or ctx.edge.ip


def trusted_client_ip(ctx, trusted_proxies=TRUSTED_PROXIES):
    """Walk X-Forwarded-For from the right and return the first hop we don't operate."""
    for hop in reversed(forwarded_chain(ctx)):
        ip = _valid_ip(hop)
        if ip is None:
            break                      # garbage in the chain: stop, fall back to the peer
        if ip not in trusted_proxies:
            return ip
    return ctx.edge.ip


def trusted_proxy_enforced(ctx):
    """True when a check named `trusted_proxy` is enforced at this request's level."""
    from . import ladder
    return any(c.name == "trusted_proxy" and not c.shadow
               for k, checks in ladder.LADDER.items() if k <= ctx.level for c in checks)


def client_ip(ctx):
    """The address every IP-based check in this lab keys on. Cached per request."""
    if "client_ip" not in ctx.attrs:
        ip = trusted_client_ip(ctx) if trusted_proxy_enforced(ctx) else naive_client_ip(ctx)
        ctx.attrs["client_ip"] = ip
        if ip != ctx.edge.ip:
            ctx.note(client_ip=ip)     # the decision log shows which address the checks believed
    return ctx.attrs["client_ip"]
