"""
Chapter 5 — What the edge tells the origin (Section 5.2)

Flask never sees the TLS handshake. fingerproxy terminates TLS on :8443,
computes the fingerprints and forwards them as request headers:

    X-JA4-Fingerprint    t13d1516h2_8daaf6152771_806a8c22fdea
    X-JA3-Fingerprint    MD5 hex (kept for comparison only; unstable for Chrome)
    X-HTTP2-Fingerprint  SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header order
                         absent when the client spoke HTTP/1.1

This module turns those headers into one small object every defense layer
shares, and loads the fingerprint lists.

Three things to remember:
- These headers are only trustworthy if the origin can't be reached any
  other way. In production that means a private network, mTLS or a signed
  header between edge and origin (W1 Ch3 made the same point for
  X-Forwarded-For). In the lab, the attack scripts refuse to talk to :5000.
- fingerproxy v1.2.3 keeps GREASE values inside signature_algorithms when it
  hashes JA4 part c. Chromium sends a random GREASE sig-alg, so its JA4_c
  takes one of 16 values per connection (Round 0 shows this). Parts a and b
  are stable across GREASE, which is why the family checks key on `ja4_ab`.
- Session resumption changes the extension list (pre_shared_key), and with
  it the extension count in part a. Each family lists its resumed shapes too.
"""

import json
import os
from dataclasses import dataclass
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
KNOWN_FILE = os.path.join(HERE, "known_fingerprints.json")
LOCAL_FILE = os.path.join(HERE, "local_fingerprints.json")


@dataclass
class EdgeFingerprint:
    ja4: Optional[str]
    ja3: Optional[str]
    h2: Optional[str]

    @property
    def present(self) -> bool:
        return bool(self.ja4)

    @property
    def ja4_ab(self) -> Optional[str]:
        """JA4 parts a+b: protocol, version, SNI, counts, ALPN + sorted-cipher hash."""
        return self.ja4.rsplit("_", 1)[0] if self.ja4 else None

    @property
    def ja4_b(self) -> Optional[str]:
        """JA4 part b: hash of the sorted cipher suites. Stable across session resumption."""
        parts = self.ja4.split("_") if self.ja4 else []
        return parts[1] if len(parts) == 3 else None

    @property
    def alpn(self) -> Optional[str]:
        """First ALPN value the client offered, as JA4 encodes it ('h2', 'h1', '00')."""
        return self.ja4[8:10] if self.ja4 and len(self.ja4) >= 10 else None

    @property
    def http_version(self) -> str:
        return "h2" if self.h2 else "http/1.1"


def from_headers(headers) -> EdgeFingerprint:
    return EdgeFingerprint(
        ja4=headers.get("X-JA4-Fingerprint"),
        ja3=headers.get("X-JA3-Fingerprint"),
        h2=headers.get("X-HTTP2-Fingerprint"),
    )


def load_known() -> dict:
    """Shipped fingerprints merged with the ones captured on this machine."""
    with open(KNOWN_FILE) as f:
        known = json.load(f)
    if os.path.exists(LOCAL_FILE):
        with open(LOCAL_FILE) as f:
            local = json.load(f)
        known["library_ja4"].update(local.get("library_ja4", {}))
    return known
