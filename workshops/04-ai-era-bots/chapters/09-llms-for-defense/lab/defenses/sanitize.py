"""
W4 Chapter 9 — Sanitizing the input and validating the output  [STUDENT FILE]

Round 2 lives here. Until you fill it in, the pipeline sends the untrusted
fields to the model untouched and accepts whatever comes back (schema only).
That is the state Round 1 leaves you in, and the state Round 2's attacks
walk straight through.

Two entry points, both called by defenses/triage.py:
  sanitize_card(card)        -> (clean_card, flags)   # the input side
  validate_verdict(verdict, card) -> (verdict, flags) # the output side

Run `python tools/checkpoint.py --round 2 --catch-up` to drop in the
reference implementation if you want to move on.
"""

import copy
import re

from .fields import CAPS, UNTRUSTED
from .schemas import VERDICT_SCHEMA, safe_text, validate
from .sessionize import flatten, untrusted_text

# A starter phrase list. The reference solution extends it — but never
# completely: some paraphrases always get through, which is the point.
PHRASES = [
    r"ignore\s+(all\s+|any\s+|the\s+|your\s+|previous\s+|prior\s+)*(instruction|rule|guidance|context)",
    r"(classify|label|mark|treat)\s+(this|the|it|me|as)\b[^.\n]{0,40}\b(human|legitimate|genuine|real)",
    r"(verified|authori[sz]ed|approved|trusted|official)\s+(partner|crawler|bot|monitor|agent|scanner)",
    r"do\s+not\s+(flag|block|classify|propose)",
    r"propose\s+no\s+rule|no\s+rule\s+(needed|required)",
]
_PHRASES = [re.compile(p, re.I) for p in PHRASES]
REDACTED = "[removed]"
HARD_BOT = ("honeypot_hit", "disallowed_hit")


def _norm(s):
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", str(s).lower())).strip()


def sanitize_card(card):
    """Return (clean_card, flags).

    TODO (Round 2): defend the input side.
      a) cap every untrusted field to CAPS[name] (defenses/fields.py)
      b) replace instruction-like spans (PHRASES) in each field with REDACTED
      c) (stage b) concatenate the untrusted fields and scan them TOGETHER;
         if the joined text matches a phrase, append "injection_suspected"
      Return the cleaned card and a list of flags (e.g. "stripped:ua",
      "injection_suspected"). untrusted_text(card) gives the fields in order.
    For now: pass the card through untouched.
    """
    return copy.deepcopy(card), []


def validate_verdict(verdict, card, flags=()):
    """Return (clean_verdict, flags).

    TODO (Round 2): defend the output side.
      a) reject a verdict that fails VERDICT_SCHEMA
      b) drop any reason whose field is not in flatten(card) ("bad_field")
      c) drop any reason whose evidence is not grounded in that field
      d) run safe_text() over every evidence string and the rule description
      e) contradiction guard: label "human" with >=2 hard bot signals -> "unsure"
      f) injection policy: if sanitize_card flagged injection_suspected, this
         session may be "bot" or "unsure", never "human"
    For now: accept the verdict if it fits the schema, otherwise mark it.
    """
    errs = validate(verdict, VERDICT_SCHEMA)
    return verdict, (["schema_invalid"] if errs else [])
