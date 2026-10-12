"""
Chapter 8 — Form Traps (Section 8.2)

Two traps on the signup form. Both rest on the same invariant: a real person
can't do this.

  1. Honeypot field: an input no human can see, so a human never fills it in.
     Level 1 is the classic textbook version, an inline style="display:none"
     field called "website". Level 2 moves the hiding into the stylesheet and
     gives every field a per-session opaque name, so the HTML alone reveals
     nothing.

  2. Timing token (level 2): a signed timestamp issued with the form. A
     submission with no token never loaded the form. One that arrives faster
     than MIN_FILL_SECONDS was not typed by a person.

What a hit costs us when we are wrong:
  - Hidden fields that a human CAN reach are false positives. Browser autofill
    and password managers fill fields they recognise. Screen-reader and
    keyboard users fill whatever the Tab key lands on. That is what the
    Round 2 TODO below is about.
  - Timing thresholds must stay below your fastest real user. Autofill users
    are fast. Never put a timing trap on a login form, where password managers
    submit in well under a second.

Trade-off: neither trap stops a real browser that only touches what a human
can see and waits a couple of seconds. They catch cheap bots, cheaply, at no
cost to users who never notice them.
"""

import hashlib
import hmac
import time
from html import escape

MIN_FILL_SECONDS = 1.5      # below the fastest real user we measured (autofill: ~2 s)
MAX_FORM_AGE = 2 * 3600     # older tokens ask the user to retry; they are not a trap

L1_HONEYPOT_NAME = "website"

# Field order matters: the honeypot sits between email and password, so the
# Tab key reaches it if it is focusable.
REAL_FIELDS = [
    # logical name, label, input type, autocomplete
    ("username", "Username", "text", "username"),
    ("email", "Email", "email", "email"),
    ("password", "Password", "password", "new-password"),
]

# TODO (Round 2): the autofill_shopper and screenreader_shopper personas get
# trapped at DEFENSE_LEVEL=2. Run the checkpoint and read their notes, then fix
# the honeypot so that no human can reach it:
#   - "hide": "offscreen" only moves the field out of view. It still takes
#     focus and autofill still sees it. Which class in store.css removes it
#     from both the layout and the Tab order?
#   - "name"/"label": "phone" and "Phone" are exactly what autofill looks for.
#     None gives the field a per-session opaque name like the real fields.
#   - "focusable": True leaves the field in the Tab order.
#   - "aria_hidden": is it still needed once the field is hidden by CSS?
#     (Hint: display:none already removes it from the accessibility tree, and
#     look at what round1b_markup_aware.py skips.)
HONEYPOT = {
    "name": "phone",            # None = per-session opaque name
    "label": "Phone",
    "hide": "offscreen",        # "offscreen" (.hp-offscreen) or "css_class" (.hp)
    "focusable": True,          # False adds tabindex="-1"
    "aria_hidden": False,
}

HIDE_CLASSES = {"offscreen": "hp-offscreen", "css_class": "hp"}


def _sign(secret, message):
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def field_name(secret, sid, logical, level):
    """Level 2+: an opaque, per-session field name derived from the session id."""
    if level < 2:
        return logical
    return "f_" + _sign(secret, f"{sid}:{logical}")[:10]


def honeypot_name(secret, sid, level):
    if level < 2:
        return L1_HONEYPOT_NAME
    return HONEYPOT["name"] or field_name(secret, sid, "hp", level)


def issue_token(secret, sid, now=None):
    """A signed timestamp: '<issued ms>.<signature>'. Bound to the session."""
    issued = int((now or time.time()) * 1000)
    return f"{issued}.{_sign(secret, f'{sid}:{issued}')[:16]}"


def _field_html(name, label, input_type, autocomplete):
    return (f'<div class="field"><label for="{name}">{escape(label)}</label>'
            f'<input type="{input_type}" id="{name}" name="{name}" '
            f'autocomplete="{autocomplete}" required></div>')


def _honeypot_html(secret, sid, level):
    name = honeypot_name(secret, sid, level)
    if level < 2:
        # The textbook honeypot: everything a bot needs to skip it is in the markup.
        return (f'<div style="display:none"><label for="{name}">Website</label>'
                f'<input type="text" id="{name}" name="{name}" autocomplete="off"></div>')
    css = HIDE_CLASSES[HONEYPOT["hide"]]
    aria = ' aria-hidden="true"' if HONEYPOT["aria_hidden"] else ""
    tab = "" if HONEYPOT["focusable"] else ' tabindex="-1"'
    return (f'<div class="field {css}"{aria}><label for="{name}">{escape(HONEYPOT["label"])}</label>'
            f'<input type="text" id="{name}" name="{name}" autocomplete="off"{tab}></div>')


def render_fields(secret, sid, level):
    """The inner HTML of the signup form for this session and level."""
    parts = []
    for logical, label, input_type, autocomplete in REAL_FIELDS:
        parts.append(_field_html(field_name(secret, sid, logical, level), label,
                                 input_type, autocomplete))
        if logical == "email" and level >= 1:
            parts.append(_honeypot_html(secret, sid, level))
    if level >= 2:
        parts.append(f'<input type="hidden" name="ts" value="{issue_token(secret, sid)}">')
    return "\n".join(parts)


def check_submission(form, secret, sid, level, now=None):
    """
    Check a signup POST.

    Returns (values, reasons, expired):
      values   {logical name: submitted value} for the real fields
      reasons  trap names that fired; empty means the submission looks human
      expired  True if the form is too old: ask the user to retry, don't trap
    """
    values = {logical: form.get(field_name(secret, sid, logical, level), "").strip()
              for logical, *_ in REAL_FIELDS}
    reasons = []
    if level >= 1 and form.get(honeypot_name(secret, sid, level), "").strip():
        reasons.append("honeypot_field")

    expired = False
    if level >= 2:
        issued, _, sig = form.get("ts", "").partition(".")
        if not issued.isdigit() or not hmac.compare_digest(
                sig, _sign(secret, f"{sid}:{issued}")[:16]):
            # No token, a forged one, or one from another session
            reasons.append("timing_token_missing")
        else:
            elapsed = (now or time.time()) - int(issued) / 1000
            if elapsed < MIN_FILL_SECONDS:
                reasons.append("too_fast")
            elif elapsed > MAX_FORM_AGE:
                expired = True
    return values, reasons, expired


if __name__ == "__main__":
    secret, sid = "demo-secret", "a1b2c3d4"
    print("Level 2 form as this session sees it:\n")
    print(render_fields(secret, sid, 2))

    names = {logical: field_name(secret, sid, logical, 2) for logical, *_ in REAL_FIELDS}
    token = issue_token(secret, sid, now=time.time() - 5)
    human = {names["username"]: "alice", names["email"]: "alice@example.com",
             names["password"]: "correct horse", "ts": token}
    bot = dict(human, ts=issue_token(secret, sid))
    bot[honeypot_name(secret, sid, 2)] = "bot-filled"

    for label, form in [("human (5 s, honeypot empty)", human),
                        ("bot (instant, honeypot filled)", bot),
                        ("bot (no token)", {k: v for k, v in human.items() if k != "ts"})]:
        _, reasons, _ = check_submission(form, secret, sid, 2)
        print(f"\n{label:<32} -> {reasons or 'clean'}")
