"""
ja4: TLS client fingerprints, and the helpers every TLS check shares. (Finished: nothing to write here.)

This is the series' canonical TLS-fingerprinting module. It is written in W2 Ch5 and copied, byte for
byte, by the W2 Ch9 capstone and by W3 Ch1 (their `shared.json`), so it knows nothing about this
chapter's rounds: no thresholds, no point values, no protected paths. Those live in the checks
(`ja4_denylist`, `tls_family`, `h2_fingerprint`, `browser_proof`) and in `policy.py`.

Two halves:

1. Computing a fingerprint from bytes you captured yourself (stdlib only, no ctx):

     python -m defenses.ja4 captures/<name>.hex       # also works as: python defenses/ja4.py <file>

   - JA3 (Salesforce, 2017): MD5 over ciphers, extensions, groups and point formats *in the order
     sent*. Chrome has shuffled its extension order on every connection since Chrome 110, so one
     Chrome install yields a new JA3 on almost every handshake.
   - JA4 (FoxIO, BSD-3-Clause): sorts ciphers and extensions before hashing, keeps a readable prefix.

       JA4 = {proto}{version}{sni}{n_ciphers:02}{n_ext:02}{alpn} _ {hash(ciphers)} _ {hash(exts + sigalgs)}
             t       13       d    15          16         h2
             e.g. t13d1516h2_8daaf6152771_806a8c22fdea   (Chrome / curl_cffi chrome)

   Rules that trip people up (JA4 spec, technical_details/JA4.md): GREASE values (0x0a0a, 0x1a1a, ...)
   are ignored everywhere; the version is the highest value in supported_versions, not the record
   version; the extension *count* includes SNI and ALPN while the extension *hash* excludes them;
   signature algorithms are appended to the extension hash in the order sent; every hash is the
   first 12 hex chars of SHA-256 over comma-joined 4-digit hex.

   Only JA4 itself is BSD-3-Clause. JA4H, JA4S, JA4X, JA4T and the rest of the JA4+ suite are under
   the FoxIO License 1.1 (education and internal use fine; reselling needs a licence), so this lab
   computes JA4 only. The edge (fingerproxy, Go) computes the same value; Round 0 has you reproduce
   it here from a ClientHello you captured with tools/clienthello_dump.py.

2. Reading what a TLS edge measured (works on the store's `Ctx`, duck-typed):

     fp = fingerprint(ctx)            # ctx.edge: measured by fingerproxy, or claimed by X-Lab-JA4
     fp.ja4_ab, fp.ja4_b, fp.h2_core
     tls_families(fp)                 # browser families whose known ClientHellos include this JA4 a+b
     tls_engine(fp, claimed_engine(ctx.ua.raw))

   The family tables come from `known_fingerprints.json` (shipped, verified in Oct 2026) merged with
   `local_fingerprints.json` (what `tools/capture_fingerprints.py` saw on YOUR machine; library
   JA4s depend on the OpenSSL build). Edits to either file are picked up on the next request.

Three facts to carry into every check that uses it:
  - JA4 parts a+b are stable per client build; part c is not, for fingerproxy v1.2.3 keeps GREASE
    values inside signature_algorithms when it hashes it (the spec says to drop them), so one
    Chromium shows up to 16 different part-c values. Key on `ja4_ab`.
  - Session resumption adds pre_shared_key, so a resumed Chrome connection has 17 extensions and
    the same a+b as a fresh Firefox 155. Ask "is this ClientHello consistent with the claimed
    engine?", never "which browser is this?".
  - A fingerprint narrows the set of possible clients; it rarely names one. Every Chromium app, and
    every impersonation profile of it, shares one JA4.
"""

import hashlib
import json
import os
import struct
import sys
from dataclasses import dataclass
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
KNOWN_FILE = os.path.join(HERE, "known_fingerprints.json")
LOCAL_FILE = os.path.join(HERE, "local_fingerprints.json")

GREASE = {0x0A0A + 0x1010 * i for i in range(16)}

EXT_SNI = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B

TLS_VERSION_CODES = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}


# --- Part 1: from raw ClientHello bytes ------------------------------------------------------

class NotClientHello(ValueError):
    """The bytes are not a TLS record holding a ClientHello."""


def _u8(b, i):
    return b[i], i + 1


def _u16(b, i):
    return struct.unpack_from("!H", b, i)[0], i + 2


def _u24(b, i):
    return int.from_bytes(b[i:i + 3], "big"), i + 3


def record_length(data: bytes) -> Optional[int]:
    """Total bytes of the first TLS record, or None while fewer than 5 bytes have arrived."""
    if len(data) < 5:
        return None
    if data[0] != 0x16:
        raise NotClientHello("not a TLS handshake record (plain HTTP on the TLS port?)")
    return 5 + struct.unpack("!H", data[3:5])[0]


def parse_client_hello(record: bytes) -> dict:
    """Parse one TLS record containing a ClientHello. Returns the raw field lists.

    Only what fingerprinting needs is decoded; everything else is skipped.
    Raises NotClientHello (a ValueError) if the bytes are not a ClientHello.
    """
    if len(record) < 9 or record[0] != 0x16:
        raise NotClientHello("not a TLS handshake record")
    i = 5                                   # skip the record header (type, version, length)
    hs_type, i = _u8(record, i)
    if hs_type != 0x01:
        raise NotClientHello("handshake is not a ClientHello")
    _, i = _u24(record, i)                  # handshake length
    legacy_version, i = _u16(record, i)
    i += 32                                 # random
    sid_len, i = _u8(record, i)
    i += sid_len
    cs_len, i = _u16(record, i)
    ciphers = [struct.unpack_from("!H", record, i + k)[0] for k in range(0, cs_len, 2)]
    i += cs_len
    comp_len, i = _u8(record, i)
    i += comp_len

    out = {
        "legacy_version": legacy_version,
        "ciphers": ciphers,
        "extensions": [],          # in wire order
        "sni": None,
        "alpn": [],
        "groups": [],
        "point_formats": [],
        "sig_algs": [],
        "supported_versions": [],
    }
    if i >= len(record):
        return out
    ext_total, i = _u16(record, i)
    end = i + ext_total
    while i + 4 <= end:
        etype, i = _u16(record, i)
        elen, i = _u16(record, i)
        data = record[i:i + elen]
        i += elen
        out["extensions"].append(etype)
        if etype == EXT_SNI and len(data) > 5:
            name_len = struct.unpack_from("!H", data, 3)[0]
            out["sni"] = data[5:5 + name_len].decode("ascii", "replace")
        elif etype == EXT_ALPN and len(data) > 2:
            j = 2
            while j < len(data):
                n = data[j]
                out["alpn"].append(data[j + 1:j + 1 + n].decode("ascii", "replace"))
                j += 1 + n
        elif etype == EXT_SUPPORTED_GROUPS:
            out["groups"] = [struct.unpack_from("!H", data, k)[0] for k in range(2, len(data), 2)]
        elif etype == EXT_EC_POINT_FORMATS:
            out["point_formats"] = list(data[1:1 + data[0]])
        elif etype == EXT_SIGNATURE_ALGORITHMS:
            out["sig_algs"] = [struct.unpack_from("!H", data, k)[0] for k in range(2, len(data), 2)]
        elif etype == EXT_SUPPORTED_VERSIONS:
            out["supported_versions"] = [struct.unpack_from("!H", data, k)[0] for k in range(1, 1 + data[0], 2)]
    return out


def _hash12(values) -> str:
    if not values:
        return "000000000000"
    return hashlib.sha256(",".join(values).encode()).hexdigest()[:12]


def ja4(ch: dict, transport: str = "t") -> str:
    """JA4 from parse_client_hello() output. transport: t=TCP, q=QUIC, d=DTLS."""
    ciphers = [c for c in ch["ciphers"] if c not in GREASE]
    exts = [e for e in ch["extensions"] if e not in GREASE]
    versions = [v for v in ch["supported_versions"] if v not in GREASE]
    version = TLS_VERSION_CODES.get(max(versions) if versions else ch["legacy_version"], "00")
    sni = "d" if ch["sni"] else "i"
    alpn = ch["alpn"][0] if ch["alpn"] else ""
    alpn_code = (alpn[0] + alpn[-1]) if alpn else "00"
    if not alpn_code.isascii():
        alpn_code = "99"
    a = f"{transport}{version}{sni}{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{alpn_code}"
    b = _hash12(sorted(f"{c:04x}" for c in ciphers))
    ext_part = sorted(f"{e:04x}" for e in exts if e not in (EXT_SNI, EXT_ALPN))
    sig_part = [f"{s:04x}" for s in ch["sig_algs"] if s not in GREASE]
    c_input = ",".join(ext_part) + ("_" + ",".join(sig_part) if sig_part else "")
    c = hashlib.sha256(c_input.encode()).hexdigest()[:12] if ext_part else "000000000000"
    return f"{a}_{b}_{c}"


def ja4_from_bytes(data: bytes) -> str:
    return ja4(parse_client_hello(data))


def ja3_string(ch: dict) -> str:
    """JA3 input: version,ciphers,extensions,groups,point_formats (GREASE removed, wire order)."""
    def j(vals):
        return "-".join(str(v) for v in vals if v not in GREASE)
    return ",".join([str(ch["legacy_version"]), j(ch["ciphers"]), j(ch["extensions"]),
                     j(ch["groups"]), j(ch["point_formats"])])


def ja3(ch: dict) -> str:
    return hashlib.md5(ja3_string(ch).encode()).hexdigest()


def describe(ch: dict) -> str:
    """Human-readable summary (Round 0)."""
    lines = [
        f"  SNI:                 {ch['sni']}",
        f"  ALPN:                {ch['alpn']}",
        f"  supported_versions:  {[hex(v) for v in ch['supported_versions']]}",
        f"  ciphers ({len(ch['ciphers']):2}):        {[hex(c) for c in ch['ciphers']][:6]} ...",
        f"  extensions ({len(ch['extensions']):2}):     {[hex(e) for e in ch['extensions']]}",
        f"  groups:              {[hex(g) for g in ch['groups']]}",
        f"  signature algs:      {[hex(s) for s in ch['sig_algs']][:4]} ...  (first one: GREASE?)",
        f"  JA3 string:          {ja3_string(ch)[:90]}...",
        f"  JA3:                 {ja3(ch)}",
        f"  JA4:                 {ja4(ch)}",
    ]
    return "\n".join(lines)


# --- Part 2: what a TLS edge measured --------------------------------------------------------

@dataclass(frozen=True)
class Fingerprint:
    """The connection's fingerprint as the store sees it (ctx.edge), with the derived parts."""
    ja4: str = ""
    h2: str = ""
    source: str = ""        # "measured" (a TLS edge) | "claimed" (X-Lab-JA4) | ""

    @property
    def present(self) -> bool:
        return bool(self.ja4)

    @property
    def measured(self) -> bool:
        return self.source == "measured"

    @property
    def ja4_ab(self) -> str:
        """JA4 parts a+b: protocol, version, SNI, counts, ALPN + the sorted-cipher hash."""
        return self.ja4.rsplit("_", 1)[0] if self.ja4 else ""

    @property
    def ja4_b(self) -> str:
        """JA4 part b: hash of the sorted cipher suites. Stable across session resumption."""
        parts = self.ja4.split("_") if self.ja4 else []
        return parts[1] if len(parts) == 3 else ""

    @property
    def alpn(self) -> str:
        """First ALPN value the client offered, as JA4 encodes it ('h2', 'h1', '00')."""
        return self.ja4[8:10] if len(self.ja4) >= 10 else ""

    @property
    def http_version(self) -> str:
        return "h2" if self.h2 else "http/1.1"

    @property
    def h2_core(self) -> str:
        return h2_core(self.h2)


def fingerprint(ctx) -> Fingerprint:
    """The fingerprint of this request's connection. ctx.edge.ja4_source says who vouches for it."""
    e = ctx.edge
    return Fingerprint(ja4=e.ja4 or "", h2=e.h2 or "", source=e.ja4_source or "")


def h2_core(h2: str) -> str:
    """HTTP/2 fingerprint without the PRIORITY section: 'S|W|P|H' -> 'S|W|H' ('' for HTTP/1.1).

    fingerproxy appends every PRIORITY frame seen on the connection, so a reused Chromium
    connection grows from `1:1:0:256` to `1:1:0:256,3:1:0:256`; the rest is stable.
    """
    if not h2:
        return ""
    parts = h2.split("|")
    if len(parts) != 4:
        return h2
    settings, window_update, _priority, pseudo = parts
    return f"{settings}|{window_update}|{pseudo}"


_cache = {"stamp": None, "data": None}


def known() -> dict:
    """Shipped fingerprints merged with the ones captured on this machine (re-read when either file changes)."""
    stamp = tuple(os.stat(p).st_mtime if os.path.exists(p) else 0 for p in (KNOWN_FILE, LOCAL_FILE))
    if _cache["stamp"] != stamp:
        with open(KNOWN_FILE) as f:
            data = json.load(f)
        if os.path.exists(LOCAL_FILE):
            with open(LOCAL_FILE) as f:
                data["library_ja4"].update(json.load(f).get("library_ja4", {}))
        _cache.update(stamp=stamp, data=data)
    return _cache["data"]


def library_label(fp: Fingerprint) -> Optional[str]:
    """Which HTTP library has exactly this JA4 (a+b+c)? None if it is not on the list."""
    return known()["library_ja4"].get(fp.ja4)


def claimed_engine(user_agent: str) -> Optional[str]:
    """Which engine does the User-Agent claim? None for non-browser UAs. iOS browsers are all webkit."""
    ua = user_agent or ""
    if any(t in ua for t in ("CriOS/", "FxiOS/", "EdgiOS/")) or "iPhone" in ua or "iPad" in ua:
        return "webkit"
    if "Firefox/" in ua:
        return "gecko"
    if any(t in ua for t in ("Chrome/", "Chromium/", "Edg/", "HeadlessChrome/")):
        return "chromium"
    if "Safari/" in ua and "Version/" in ua:
        return "webkit"
    return None


def tls_families(fp: Fingerprint) -> list:
    """Every browser family whose known ClientHello shapes include this JA4 a+b (may be 0, 1 or 2)."""
    return [name for name, family in known()["browser_families"].items() if fp.ja4_ab in family["ja4_ab"]]


def tls_engine(fp: Fingerprint, claimed: Optional[str] = None) -> Optional[str]:
    """The browser family of this ClientHello, preferring the claimed one on a tie. None if no family."""
    families = tls_families(fp)
    if claimed in families:
        return claimed
    return families[0] if families else None


def family_h2(engine: str) -> dict:
    """The known HTTP/2 cores (SETTINGS|WINDOW_UPDATE|pseudo-header order) of a browser family."""
    return known()["browser_families"].get(engine, {}).get("h2", {})


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m defenses.ja4 <file.hex>   (written by tools/clienthello_dump.py)")
    with open(sys.argv[1]) as f:
        raw = bytes.fromhex(f.read().strip())
    print(describe(parse_client_hello(raw)))
