"""
Round 3, 🔴 forging identity: three ways to fake "verified", all caught.

Round 3's defense (defenses/agent_identity.py, on W4 Ch2's verifier) only grants verified status to
a signature that (a) is made by a key in a TRUSTED operator's directory, (b) verifies over this
request, (c) has a window no longer than policy allows, and (d) carries a nonce nobody has used.
This attack tries the three shortcuts an operator reaches for when it wants the verified-agent
purchase without being a trusted operator:

  claim    send Signature-Agent: "https://agents.lab-provider.test" with NO signature. Pure
           assertion: the store sees a declared agent that cannot prove it.
  replay   resend a header set that leaked into a log: genuinely signed by the trusted operator, an
           hour ago, with a 24 h window. The signature verifies; the window is a replayable
           credential and trust() refuses it.
  vouch    sign correctly with the attacker's OWN key, published at agents.evil.test. Cryptographically
           perfect, but that operator is not on the store's allow-list. Identity needs TRUST, not
           just a valid key.

None of the three places an order at DEFENSE_LEVEL 3. The honest verified agent
(round3_verified_agent.py) still does.

Run (store at the round's level, from lab/):
    python attacks/round3_forged_agent.py [--per-variant 2]
"""

import argparse
import sys

import _common
from agent.identity import capture_leak, install_header_claim, install_replayer, install_signer
from agent.loop import run_agent_session

ORIGIN = f"https://{_common.OPERATOR}"


def run(per_variant=2):
    base = _common.target()
    leaked = capture_leak(_common.Signer(_common.OPERATOR), _common.authority(base))
    variants = (["claim"] * per_variant) + (["replay"] * per_variant) + (["vouch"] * per_variant)
    accounts = _common.owner_accounts(len(variants), start=30)
    ips = _common.home_ips(len(variants), start=30)
    results = []
    with _common.Cost() as cost, _common.chromium() as browser:
        for i, (variant, acct, ip) in enumerate(zip(variants, accounts, ips)):
            with _common.agent_session(browser, f"bot:forged_agent:{i:02d}", ip, _common.LAB_AGENT_UA) as (ctx, page):
                if variant == "claim":
                    install_header_claim(ctx, ORIGIN)
                elif variant == "replay":
                    install_replayer(ctx, leaked)
                else:
                    install_signer(ctx, _common.Signer(_common.EVIL))
                r = run_agent_session(page, base, acct, _common.DROP_SKU, label=f"forged-{variant}-{i}")
                r["variant"] = variant
                results.append(r)
    return _common.summary("round3_forged_agent", results, cost)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-variant", type=int, default=2)
    _common.report(run(ap.parse_args().per_variant))
    sys.exit(0)
