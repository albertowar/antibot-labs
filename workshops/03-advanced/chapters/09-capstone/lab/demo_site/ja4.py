"""
Chapter 9 — JA4 TLS client fingerprint (Section 9.2)

Computes JA4 (the TLS client fingerprint from FoxIO, BSD-3-Clause) from the raw
bytes of a TLS ClientHello. The edge (edge.py) peeks those bytes off the socket
before the handshake starts, so the fingerprint describes the client's TLS
library, not anything the client says about itself in HTTP.

    JA4 = a_b_c
      a: t + TLS version + d/i (SNI present?) + #ciphers + #extensions + ALPN first/last char
      b: sha256 of the sorted cipher list, first 12 hex chars
      c: sha256 of the sorted extension list (minus SNI and ALPN) + "_" +
         signature algorithms in wire order, first 12 hex chars

Why JA4 and not JA3: Chrome has randomized its extension order since v110, so
a JA3 hash changes on every connection. JA4 sorts ciphers and extensions,
which makes it stable across connections from the same client build.

Trade-off: JA4 identifies the TLS *stack*, not the program. Every app built on
the same Chromium or the same curl-impersonate profile shares one JA4. It is a
consistency signal ("you say Chrome, your TLS says Python"), never an identity.

Only JA4 is implemented here. JA4H, JA4S and the rest of the JA4+ suite use
the FoxIO License 1.1, which allows this kind of education use but not
resale; check the license before you ship them in a product.
"""

import hashlib
import struct

GREASE = {0x0A0A + 0x1010 * i for i in range(16)}  # 0x0a0a, 0x1a1a, ..., 0xfafa
TLS_VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}
EXT_SNI, EXT_ALPN, EXT_SIG_ALGS, EXT_SUPPORTED_VERSIONS = 0x0000, 0x0010, 0x000D, 0x002B


class NotClientHello(ValueError):
    pass


def record_length(data):
    """Total bytes needed for the first TLS record, or None if we can't tell yet."""
    if len(data) < 5:
        return None
    if data[0] != 0x16:  # handshake record
        raise NotClientHello("not a TLS handshake record (plain HTTP on the TLS port?)")
    return 5 + struct.unpack("!H", data[3:5])[0]


def parse_client_hello(data):
    """Parse the first TLS record into the fields JA4 needs."""
    if record_length(data) is None or len(data) < record_length(data):
        raise NotClientHello("incomplete record")
    body = data[5:record_length(data)]
    if body[0] != 0x01:
        raise NotClientHello("handshake is not a ClientHello")
    pos = 4  # handshake type (1) + length (3)
    legacy_version = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2 + 32  # version + random
    pos += 1 + body[pos]  # session id
    (cipher_len,) = struct.unpack("!H", body[pos:pos + 2])
    pos += 2
    ciphers = list(struct.unpack(f"!{cipher_len // 2}H", body[pos:pos + cipher_len]))
    pos += cipher_len
    pos += 1 + body[pos]  # compression methods

    hello = {"legacy_version": legacy_version, "ciphers": ciphers, "extensions": [],
             "sni": None, "alpn": [], "sig_algs": [], "supported_versions": []}
    if pos + 2 > len(body):
        return hello
    (ext_total,) = struct.unpack("!H", body[pos:pos + 2])
    pos += 2
    end = min(pos + ext_total, len(body))
    while pos + 4 <= end:
        ext_type, ext_len = struct.unpack("!HH", body[pos:pos + 4])
        ext = body[pos + 4:pos + 4 + ext_len]
        pos += 4 + ext_len
        hello["extensions"].append(ext_type)
        if ext_type == EXT_SNI and len(ext) > 5:
            name_len = struct.unpack("!H", ext[3:5])[0]
            hello["sni"] = ext[5:5 + name_len].decode("ascii", "replace")
        elif ext_type == EXT_ALPN and len(ext) > 2:
            p = 2
            while p < len(ext):
                n = ext[p]
                hello["alpn"].append(ext[p + 1:p + 1 + n].decode("ascii", "replace"))
                p += 1 + n
        elif ext_type == EXT_SIG_ALGS and len(ext) > 2:
            n = struct.unpack("!H", ext[:2])[0]
            hello["sig_algs"] = list(struct.unpack(f"!{n // 2}H", ext[2:2 + n]))
        elif ext_type == EXT_SUPPORTED_VERSIONS and len(ext) > 1:
            n = ext[0]
            hello["supported_versions"] = list(struct.unpack(f"!{n // 2}H", ext[1:1 + n]))
    return hello


def _hash12(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12] if text else "000000000000"


def ja4(hello):
    """Build the JA4 string from a parsed ClientHello."""
    ciphers = [c for c in hello["ciphers"] if c not in GREASE]
    extensions = [e for e in hello["extensions"] if e not in GREASE]
    versions = [v for v in hello["supported_versions"] if v not in GREASE]
    version = TLS_VERSIONS.get(max(versions) if versions else hello["legacy_version"], "00")
    sni = "d" if hello["sni"] else "i"
    alpn = hello["alpn"][0] if hello["alpn"] else ""
    alpn_chars = (alpn[0] + alpn[-1]) if alpn else "00"
    if alpn_chars and not alpn_chars.isascii():
        alpn_chars = "99"

    part_a = f"t{version}{sni}{min(len(ciphers), 99):02d}{min(len(extensions), 99):02d}{alpn_chars}"
    part_b = _hash12(",".join(f"{c:04x}" for c in sorted(ciphers)))
    ext_for_hash = sorted(e for e in extensions if e not in (EXT_SNI, EXT_ALPN))
    sig_algs = [s for s in hello["sig_algs"] if s not in GREASE]
    ext_text = ",".join(f"{e:04x}" for e in ext_for_hash)
    if sig_algs:
        ext_text += "_" + ",".join(f"{s:04x}" for s in sig_algs)
    part_c = _hash12(ext_text)
    return f"{part_a}_{part_b}_{part_c}"


def ja4_from_bytes(data):
    return ja4(parse_client_hello(data))


if __name__ == '__main__':
    # Spec example from the FoxIO JA4 README (Chrome-like ClientHello fields).
    sample = {
        "legacy_version": 0x0303,
        "ciphers": [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
                    0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035],
        "extensions": [0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002D, 0x000D, 0x0005,
                       0x0023, 0x0012, 0x002B, 0xFF01, 0x000B, 0x000A, 0x0015],
        "sni": "example.com", "alpn": ["h2", "http/1.1"],
        "sig_algs": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        "supported_versions": [0x0304, 0x0303],
    }
    print(ja4(sample))
    print("expected t13d1516h2_8daaf6152771_e5627efa2ab1 (FoxIO README example)")
