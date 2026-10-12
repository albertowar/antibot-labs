"""
W1 Ch2: /lab/ip-check/<ip>, the full IP reputation breakdown for any address.

    curl -s localhost:5000/lab/ip-check/203.0.113.5 | python -m json.tool

Network facts (ASN, organisation, country, cloud provider), the reputation signals and
their points, the blocklists the address is on, the score and the band it would get.
A lab tool, like /whoami: ungated (everything under /lab/ is), and nothing a production
site should expose, since it tells an attacker exactly which list an address is on.

The breakdown comes from defenses/ip_reputation.py, called through the module at request
time so that edits to it (and to policy.py) show up without a restart. Edits to THIS file
need a restart: ext modules are not reloaded.
"""

import ipaddress

from flask import Blueprint, jsonify

bp = Blueprint("ip_check", __name__)


@bp.route("/lab/ip-check/<path:ip>")
def ip_check(ip):
    from defenses import ip_reputation
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return jsonify(error={"code": "bad_ip", "message": f"{ip!r} is not an IP address."}), 400
    return jsonify(ip=ip, **ip_reputation.explain(ip))


def init(app):
    app.register_blueprint(bp)
