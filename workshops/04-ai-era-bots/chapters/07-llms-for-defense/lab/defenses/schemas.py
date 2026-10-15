"""
W4 Chapter 7 — Output schemas and a small validator

Structured output is the first and cheapest layer of output handling (OWASP
LLM05:2025, Improper Output Handling): the model may only answer in a shape
the pipeline can check. The verdict schema is also what Ollama's `format=`
receives, so the model is constrained at decode time, not just checked after.

A schema does not make the *content* true. A perfectly valid verdict can
still say "human" because the User-Agent asked it to. That is what the
sanitizer and the gate are for.

`validate(obj, schema)` is a deliberately small JSON-Schema subset (type,
enum, required, properties, additionalProperties, items, min/max, lengths,
anyOf, $ref into $defs). No dependency, readable in one screen.

`safe_text()` is for every model-written string your tools print: a reason
or a rule description can carry ANSI escapes or control characters aimed at
the analyst's terminal.
"""

import re

from .fields import FLAT_FIELDS, OPS, RULE_FIELDS

RULE_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["description", "action", "when"],
    "properties": {
        "id": {"type": "string", "maxLength": 20},
        "description": {"type": "string", "maxLength": 140},
        "action": {"type": "string", "enum": ["block", "shadow"]},
        "when": {
            "type": "object", "additionalProperties": False, "required": ["all"],
            "properties": {"all": {
                "type": "array", "minItems": 2, "maxItems": 4,
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["field", "op", "value"],
                    "properties": {
                        "field": {"type": "string", "enum": list(RULE_FIELDS)},
                        "op": {"type": "string", "enum": sorted({o for ops in OPS.values() for o in ops})},
                        "value": {"anyOf": [{"type": "string", "maxLength": 80}, {"type": "number"},
                                            {"type": "boolean"},
                                            {"type": "array", "maxItems": 8,
                                             "items": {"type": "string", "maxLength": 80}}]},
                    }}}},
        },
        "source": {"type": "object"},
        "gate": {"type": "object"},
    },
}

VERDICT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["label", "confidence", "reasons"],
    "properties": {
        "label": {"type": "string", "enum": ["human", "bot", "unsure"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "reasons": {
            "type": "array", "maxItems": 5,
            "items": {"type": "object", "additionalProperties": False,
                      "required": ["field", "evidence"],
                      "properties": {"field": {"type": "string", "enum": FLAT_FIELDS},
                                     "evidence": {"type": "string", "maxLength": 160}}},
        },
        "proposed_rule": {"anyOf": [{"$ref": "#/$defs/rule"}, {"type": "null"}]},
    },
    "$defs": {"rule": RULE_SCHEMA},
}

# Ollama's constrained decoder handles enums, nesting and arrays well; `anyOf`
# with `$ref` is the part that varies between versions. The model gets this
# flatter schema and the pipeline validates `proposed_rule` with the full one.
VERDICT_SCHEMA_FOR_MODEL = {
    "type": "object", "required": ["label", "confidence", "reasons"],
    "properties": {
        "label": VERDICT_SCHEMA["properties"]["label"],
        "confidence": {"type": "number"},
        "reasons": VERDICT_SCHEMA["properties"]["reasons"],
        "proposed_rule": {"type": ["object", "null"]},
    },
}

DRAFTS_SCHEMA = {
    "type": "object", "required": ["rules"],
    "properties": {"rules": {"type": "array", "maxItems": 3, "items": {
        "type": "object", "required": ["description", "action", "when"],
        "properties": {
            "description": {"type": "string"},
            "action": {"type": "string", "enum": ["block", "shadow"]},
            "when": {"type": "object", "required": ["all"], "properties": {
                "all": {"type": "array", "items": {
                    "type": "object", "required": ["field", "op", "value"],
                    "properties": {"field": {"type": "string", "enum": list(RULE_FIELDS)},
                                   "op": {"type": "string"},
                                   "value": {"type": ["string", "number", "boolean"]}}}}}},
        }}}},
}

_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def validate(obj, schema, root=None, path="$"):
    """Return a list of error strings (empty = valid)."""
    root = root if root is not None else schema
    if "$ref" in schema:
        node = root
        for part in schema["$ref"].lstrip("#/").split("/"):
            node = node[part]
        return validate(obj, node, root, path)
    if "anyOf" in schema:
        errs = [validate(obj, s, root, path) for s in schema["anyOf"]]
        return [] if any(not e for e in errs) else [f"{path}: matches none of anyOf"]
    errors = []
    t = schema.get("type")
    if t:
        types = t if isinstance(t, list) else [t]
        ok = any(isinstance(obj, (int, float)) and not isinstance(obj, bool) if x == "number"
                 else isinstance(obj, _TYPES[x]) for x in types)
        if not ok:
            return [f"{path}: expected {t}, got {type(obj).__name__}"]
    if "enum" in schema and obj not in schema["enum"]:
        errors.append(f"{path}: {obj!r} not in enum")
    if isinstance(obj, (int, float)) and not isinstance(obj, bool):
        if "minimum" in schema and obj < schema["minimum"]:
            errors.append(f"{path}: {obj} < minimum")
        if "maximum" in schema and obj > schema["maximum"]:
            errors.append(f"{path}: {obj} > maximum")
    if isinstance(obj, str) and "maxLength" in schema and len(obj) > schema["maxLength"]:
        errors.append(f"{path}: longer than {schema['maxLength']}")
    if isinstance(obj, list):
        if "minItems" in schema and len(obj) < schema["minItems"]:
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(obj) > schema["maxItems"]:
            errors.append(f"{path}: more than {schema['maxItems']} items")
        if "items" in schema:
            for i, item in enumerate(obj):
                errors += validate(item, schema["items"], root, f"{path}[{i}]")
    if isinstance(obj, dict):
        for key in schema.get("required", []):
            if key not in obj:
                errors.append(f"{path}: missing {key}")
        props = schema.get("properties", {})
        for key, val in obj.items():
            if key in props:
                errors += validate(val, props[key], root, f"{path}.{key}")
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected key {key}")
    return errors


_CONTROL = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def safe_text(s, limit=160):
    """Strip ANSI escapes and control characters before printing model output."""
    s = _CONTROL.sub("", str(s)).replace("\n", " ").replace("\r", " ")
    return s if len(s) <= limit else s[:limit - 1] + "…"


if __name__ == "__main__":
    good = {"label": "bot", "confidence": 0.9, "reasons": [{"field": "ua", "evidence": "python-httpx"}],
            "proposed_rule": None}
    bad = {"label": "robot", "confidence": 2, "reasons": [{"field": "vibes", "evidence": "x"}], "extra": 1}
    print("good:", validate(good, VERDICT_SCHEMA) or "valid")
    print("bad: ", validate(bad, VERDICT_SCHEMA))
    print(repr(safe_text("\x1b[31mred\x1b[0m\x07 ok")))
