"""
Chapter 5 — JA4 from raw ClientHello bytes (Section 5.3, Round 0)

A readable, dependency-free parser for a TLS ClientHello and the two client
fingerprints this chapter uses:

- **JA3** (Salesforce, 2017): MD5 over ciphers, extensions, groups and point
  formats *in the order they were sent*. Chrome has shuffled its extension
  order on every connection since Chrome 110 (Fastly saw it from 108), so a
  single Chrome install produces a new JA3 on almost every handshake.
- **JA4** (FoxIO, BSD-3-Clause): sorts ciphers and extensions before hashing,
  so permutation no longer matters, and keeps a human-readable prefix.

    JA4 = {proto}{version}{sni}{n_ciphers:02}{n_ext:02}{alpn} _ {hash(ciphers)} _ {hash(exts + sigalgs)}
          t       13       d    15          16         h2
          e.g. t13d1516h2_8daaf6152771_806a8c22fdea   (Chrome / curl_cffi chrome)

Rules that trip people up (all from the JA4 spec, technical_details/JA4.md):
- GREASE values (0x0a0a, 0x1a1a, … 0xfafa) are ignored everywhere.
- The version is the highest value in supported_versions, not the record version.
- Extension *count* includes SNI (0x0000) and ALPN (0x0010); the extension
  *hash* excludes them. Both are already visible in the prefix.
- Signature algorithms are appended to the extension hash in the order sent.
- Hashes are the first 12 hex chars of SHA-256 over comma-joined 4-digit hex.

The edge (fingerproxy) computes the same value in Go; Round 0 asks you to
reproduce it here from bytes you captured yourself with
`tools/clienthello_dump.py`.

Run directly to parse a hex dump:
    python defenses/ja4.py captures/<name>.hex
"""

import hashlib
import struct
import sys

GREASE = {0x0A0A + 0x1010 * i for i in range(16)}

EXT_SNI = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B

TLS_VERSION_CODES = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}


def _u8(b, i):
    return b[i], i + 1


def _u16(b, i):
    return struct.unpack_from("!H", b, i)[0], i + 2


def _u24(b, i):
    return int.from_bytes(b[i:i + 3], "big"), i + 3


def parse_client_hello(record: bytes) -> dict:
    """Parse one TLS record containing a ClientHello. Returns raw field lists.

    Only what fingerprinting needs is decoded; everything else is skipped.
    Raises ValueError if the bytes are not a ClientHello.
    """
    if len(record) < 9 or record[0] != 0x16:
        raise ValueError("not a TLS handshake record")
    i = 5                                   # skip record header (type, version, length)
    hs_type, i = _u8(record, i)
    if hs_type != 0x01:
        raise ValueError("handshake is not a ClientHello")
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
    """Compute JA4 from parse_client_hello() output. transport: t=TCP, q=QUIC, d=DTLS."""
    ciphers = [c for c in ch["ciphers"] if c not in GREASE]
    exts = [e for e in ch["extensions"] if e not in GREASE]
    versions = [v for v in ch["supported_versions"] if v not in GREASE]
    version = TLS_VERSION_CODES.get(max(versions) if versions else ch["legacy_version"], "00")
    sni = "d" if ch["sni"] else "i"
    alpn = ch["alpn"][0] if ch["alpn"] else ""
    alpn_code = (alpn[0] + alpn[-1]) if alpn else "00"
    a = f"{transport}{version}{sni}{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{alpn_code}"
    b = _hash12(sorted(f"{c:04x}" for c in ciphers))
    ext_part = sorted(f"{e:04x}" for e in exts if e not in (EXT_SNI, EXT_ALPN))
    sig_part = [f"{s:04x}" for s in ch["sig_algs"] if s not in GREASE]
    c_input = ",".join(ext_part) + ("_" + ",".join(sig_part) if sig_part else "")
    c = hashlib.sha256(c_input.encode()).hexdigest()[:12] if ext_part else "000000000000"
    return f"{a}_{b}_{c}"


def ja3_string(ch: dict) -> str:
    """JA3 input string: version,ciphers,extensions,groups,point_formats (GREASE removed, wire order)."""
    def j(vals):
        return "-".join(str(v) for v in vals if v not in GREASE)
    return ",".join([str(ch["legacy_version"]), j(ch["ciphers"]), j(ch["extensions"]),
                     j(ch["groups"]), j(ch["point_formats"])])


def ja3(ch: dict) -> str:
    return hashlib.md5(ja3_string(ch).encode()).hexdigest()


def describe(ch: dict) -> str:
    """Human-readable summary used by Round 0."""
    lines = [
        f"  SNI:                 {ch['sni']}",
        f"  ALPN:                {ch['alpn']}",
        f"  supported_versions:  {[hex(v) for v in ch['supported_versions']]}",
        f"  ciphers ({len(ch['ciphers']):2}):        {[hex(c) for c in ch['ciphers']][:6]} …",
        f"  extensions ({len(ch['extensions']):2}):     {[hex(e) for e in ch['extensions']]}",
        f"  groups:              {[hex(g) for g in ch['groups']]}",
        f"  JA3 string:          {ja3_string(ch)[:90]}…",
        f"  JA3:                 {ja3(ch)}",
        f"  JA4:                 {ja4(ch)}",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python defenses/ja4.py <file.hex>   (written by tools/clienthello_dump.py)")
    with open(sys.argv[1]) as f:
        raw = bytes.fromhex(f.read().strip())
    print(describe(parse_client_hello(raw)))
