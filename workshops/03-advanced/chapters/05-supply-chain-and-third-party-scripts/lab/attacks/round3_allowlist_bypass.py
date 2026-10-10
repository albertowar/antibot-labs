"""
Round 3 attack — bypass the host-allowlist CSP.

Beating Round 2's defence: connect-src 'self' stops fetch and sendBeacon, so
the skimmer stops using them. Instead it injects an INLINE script (allowed by
the allowlist's 'unsafe-inline') and exfils through an <img> pixel (allowed by
the permissive img-src). Both are holes a host-allowlist policy routinely ships
with.

Point of the round: a nonce + strict-dynamic policy has no 'unsafe-inline', so
the injected inline script never runs; its tightened img-src/connect-src close
the pixel channel; and SRI on the vendor <script> refuses the swapped file.

Expects server: SKIMMER_VARIANT=allowlisted; beaten by CSP_MODE=strict + SRI=on
Run:
    python attacks/round3_allowlist_bypass.py
"""
import _common

def run(base=_common.BASE):
    return _common.run(base)

if __name__ == "__main__":
    raise SystemExit(_common.report("Round 3: allowlist-bypass skimmer (inline + pixel)"))
