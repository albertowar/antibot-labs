"""
W4 Chapter 9 — The field catalog: what the analyst may see, and who wrote it

One table drives the whole pipeline: the prompt (which fields go in), the
sanitizer (caps per untrusted field), the rule DSL (which fields a rule may
test and with which operators) and the output validator (a reason must cite
a field that exists).

The trust column is the point of the chapter. A field is TRUSTED when the
server derived it (counts, timings, the ASN lookup of the edge-reported IP).
It is UNTRUSTED when the client chose its bytes: User-Agent, Referer,
Accept-Language, request paths, the login name. Untrusted text can contain
anything, including instructions aimed at whoever reads the log, human or
model. The LLM cannot tell the difference; the pipeline has to.
"""

# name -> (type, trusted, cap)   cap = max chars kept per value (untrusted only)
FIELDS = {
    # client-controlled text (injection surface)
    "ua":              ("str",  False, 200),
    "accept_language": ("str",  False, 60),
    "referers":        ("list", False, 120),
    "paths":           ("list", False, 80),
    "account":         ("str",  False, 40),
    # server-derived
    "asn":             ("str",  True, None),
    "asn_type":        ("str",  True, None),
    "country":         ("str",  True, None),
    "n_requests":      ("num",  True, None),
    "n_pages":         ("num",  True, None),
    "n_assets":        ("num",  True, None),
    "asset_ratio":     ("num",  True, None),
    "errors_4xx":      ("num",  True, None),
    "duration_s":      ("num",  True, None),
    "median_gap_s":    ("num",  True, None),
    "honeypot_hit":    ("bool", True, None),
    "disallowed_hit":      ("bool", True, None),
    "reached_cart":    ("bool", True, None),
    "logged_in":       ("bool", True, None),
}

FLAT_FIELDS = list(FIELDS)
UNTRUSTED = [f for f, (_, trusted, _) in FIELDS.items() if not trusted]
TRUSTED = [f for f, (_, trusted, _) in FIELDS.items() if trusted]
CAPS = {f: cap for f, (_, trusted, cap) in FIELDS.items() if not trusted}

# The rule DSL vocabulary. Lists are matched element-wise ("contains" any).
OPS = {
    "str":  ["eq", "ne", "in", "contains", "startswith"],
    "list": ["contains"],
    "num":  ["eq", "lt", "lte", "gt", "gte"],
    "bool": ["eq"],
}
RULE_FIELDS = {f: t for f, (t, _, _) in FIELDS.items()}


def field_type(name):
    return FIELDS[name][0]
