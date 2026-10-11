"""
Round 3, 🔴 forging identity — three ways to fake "verified", all caught.

Round 3's defence (defenses/agent_identity.py) only grants verified status to
a signature that (a) is signed by a key in a trusted operator's directory,
(b) verifies over this request's authority, (c) is fresh, and (d) carries an
unused nonce. This attack tries the three shortcuts an operator reaches for
when it wants the verified-agent checkout without being a trusted operator:

  claim    send Signature-Agent: "agents.lab-provider.test" with NO signature.
           Pure assertion. The store sees a declared agent that cannot prove it
           (the signature is missing) and refuses.
  replay   capture one valid header set from the honest agent and resend it on
           every request. The signature verifies, but the nonce was already
           used and the window has passed: caught by freshness + single-use.
  vouch    sign correctly with the attacker's OWN key, published at
           agents.evil.test. Cryptographically perfect, but that operator is
           not on the store's allow-list, so the store never even fetches its
           directory. Identity needs TRUST, not just a valid key.

None of the three places an order at DEFENSE_LEVEL 3. The honest verified
agent (round3_verified_agent.py) still does.

Run (store at the round's level, from lab/):
    DEMO_URL=http://127.0.0.1:8404 python attacks/round3_forged_agent.py
"""

import os
import sys

import _common
from agent.browser import agent_browser
from agent.identity import capture_once, install_header_claim, install_replayer, install_signer
from agent.loop import run_agent_session

sys.path.insert(0, os.path.join(_common.LAB_DIR, "defenses"))
import httpsig  # noqa: E402

TRUSTED = "agents.lab-provider.test"
EVIL = "agents.evil.test"


def run(base=None, per_variant=2):
    base = base or _common.target()
    authority = _common.authority(base)
    evil_key = httpsig.load_private_key(os.path.join(_common.LAB_DIR, "data", "keys", "evil.pem"))
    lab_key = httpsig.load_private_key(os.path.join(_common.LAB_DIR, "data", "keys", "lab-provider.pem"))
    stale = capture_once(authority, lab_key, TRUSTED)  # a valid set, "sniffed" earlier
    accounts = _common.owner_accounts(per_variant * 3)
    variants = (["claim"] * per_variant) + (["replay"] * per_variant) + (["vouch"] * per_variant)
    results = []
    with _common.Cost() as cost:
        for i, (variant, acct) in enumerate(zip(variants, accounts)):
            with agent_browser(user_agent=_common.LAB_AGENT_UA) as (ctx, page):
                ctx.set_extra_http_headers({"X-Lab-Actor": f"agent-forged-{variant}"})
                if variant == "claim":
                    install_header_claim(ctx, TRUSTED)
                elif variant == "replay":
                    install_replayer(ctx, stale)
                else:
                    install_signer(ctx, authority, evil_key, EVIL)
                r = run_agent_session(page, base, acct, _common.DROP_SKU, label=f"forged-{variant}-{i}")
                r["variant"] = variant
                results.append(r)
    return _common.summary("round3_forged_agent", results, cost)


if __name__ == '__main__':
    _common.report(run())
    sys.exit(0)
