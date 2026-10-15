"""
Round 3 attack: bypass the host-allowlist CSP.

Beating Round 2's defense: connect-src 'self' stops fetch and sendBeacon, so the skimmer stops using
them. It injects an INLINE script (allowed by the allowlist's 'unsafe-inline') and exfils through an
<img> pixel (allowed by the permissive img-src). Both are holes a host-allowlist policy routinely
ships with.

Point of the round: a nonce + strict-dynamic policy has no 'unsafe-inline', its tightened img-src
closes the pixel channel, and SRI on the vendor <script> refuses the swapped file before it runs.

Technique: variant "allowlisted". Beaten by: strict CSP + SRI (level 3).
    python attacks/round3_allowlist_bypass.py
"""
import _common

if __name__ == "__main__":
    _common.run("Round 3: allowlist-bypass skimmer (inline + pixel)", "allowlisted")
