"""
form_traps (Rounds 1 and 2): two traps on the signup form. Both rest on the same invariant: a real
person cannot do this.

  1. Honeypot field (Round 1, then hardened in Round 2): an input no human can see, so a human never
     fills it in. Level 1 is the textbook version, an inline style="display:none" field called
     "website". Level 2 moves the hiding into the stylesheet (demo_site/static/css/traps.css) and
     gives the field a per-session opaque name, so the HTML alone reveals nothing.

  2. Timing token (Round 2): a signed timestamp issued with the form, bound to the session. A
     submission with no valid token never loaded the form here; one that arrives faster than
     policy.MIN_FILL_SECONDS was not typed by a person.

The form itself is the store's /register page. The ext (demo_site/ext/traps.py) renders this module's
fields into it through the `form:register` slot; the checks below read them back on the POST.

What a hit costs us when we are wrong:
  - Hidden fields that a human CAN reach are false positives. Browser autofill and password managers
    fill fields they recognise. Screen-reader and keyboard users fill whatever the Tab key lands on.
    That is what the Round 2 TODO is about.
  - Timing thresholds must stay below your fastest real user. Autofill users are fast. Never put a
    timing trap on a login form, where password managers submit in well under a second.

Trade-off: neither trap stops a real browser that only touches what a human can see and waits a
couple of seconds. They catch cheap bots, cheaply, at no cost to users who never notice them.

A hit calls responses.on_hit(): below level 4 the signup is answered with a fake success and not
saved; at level 4 the configured sanction applies as well.
"""

import hashlib
import hmac
import time
from html import escape

from . import policy, responses
from .pipeline import Check

SECRET = "w1-ch08-lab-only-secret"          # signs tokens and derives names; a lab, not a vault

L1_HONEYPOT_NAME = "website"

# TODO (Round 2): the autofill and screen_reader shoppers get trapped at DEFENSE_LEVEL=2. Run the
# checkpoint and read which shoppers it names, then fix the honeypot so that no human can reach it:
#   - "hide": "offscreen" only moves the field out of view. It still takes focus and autofill still
#     sees it. Which class in traps.css removes it from both the layout and the Tab order?
#   - "name"/"label": "phone" and "Phone" are exactly what autofill looks for. None gives the field a
#     per-session opaque name; the label should tell a human who finds it what to do.
#   - "focusable": True leaves the field in the Tab order.
#   - "aria_hidden": is it still needed once the field is hidden by CSS? (Hint: display:none already
#     removes it from the accessibility tree, and look at what round1b_markup_aware.py skips.)
HONEYPOT = {
    "name": "phone",            # None = per-session opaque name
    "label": "Phone",
    "hide": "offscreen",        # "offscreen" (.hp-offscreen) or "css_class" (.hp)
    "focusable": True,          # False adds tabindex="-1"
    "aria_hidden": False,
}

HIDE_CLASSES = {"offscreen": "hp-offscreen", "css_class": "hp"}


def _sign(message):
    return hmac.new(SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()


def honeypot_name(sid, level):
    """Level 1: the textbook 'website'. Level 2+: HONEYPOT['name'], or an opaque per-session name."""
    if level < 2:
        return L1_HONEYPOT_NAME
    return HONEYPOT["name"] or "f_" + _sign(f"{sid}:hp")[:10]


def issue_token(sid, now=None):
    """A signed timestamp: '<issued ms>.<signature>'. Bound to the session."""
    issued = int((now or time.time()) * 1000)
    return f"{issued}.{_sign(f'{sid}:{issued}')[:16]}"


def render_fields(sid, level):
    """The trap fields of the signup form for this session and level (HTML, may be empty)."""
    if level < 1:
        return ""
    name = honeypot_name(sid, level)
    if level < 2:
        # The textbook honeypot: everything a bot needs to skip it is in the markup.
        return (f'<div style="display:none"><label for="{name}">Website</label>'
                f'<input type="text" id="{name}" name="{name}" autocomplete="off"></div>')
    css = HIDE_CLASSES[HONEYPOT["hide"]]
    aria = ' aria-hidden="true"' if HONEYPOT["aria_hidden"] else ""
    tab = "" if HONEYPOT["focusable"] else ' tabindex="-1"'
    return (f'<label class="field {css}"{aria}><span>{escape(HONEYPOT["label"])}</span>'
            f'<input type="text" name="{name}" autocomplete="off"{tab}></label>\n'
            f'<input type="hidden" name="ts" value="{issue_token(sid)}">')


def _is_signup(ctx):
    return ctx.method == "POST" and ctx.path == "/register"


def _honeypot_check(ctx):
    if not _is_signup(ctx):
        return None
    # TODO (Round 1): the signup form carries a hidden field; honeypot_name(sid, level) says which.
    # A person never fills it in. If this POST came back with it non-empty, the client is a form
    # filler: return responses.on_hit(ctx, "form_traps", "honeypot_field", <detail>, form=True),
    # which answers with a fake success (and saves nothing) below level 4. Until you write it, wire
    # the check and run the spammer: the field is on the page and nothing reads it back.
    return None


def _timing_check(ctx):
    if not _is_signup(ctx):
        return None
    sid = ctx.session.sid
    issued, _, sig = ctx.form.get("ts", "").partition(".")
    if not issued.isdigit() or not hmac.compare_digest(sig, _sign(f"{sid}:{issued}")[:16]):
        # No token, a forged one, or one issued to another session
        return responses.on_hit(ctx, "form_traps", "timing_token_missing", "no valid ts", form=True)
    elapsed = time.time() - int(issued) / 1000
    ctx.note(fill_seconds=round(elapsed, 2))
    if elapsed < policy.MIN_FILL_SECONDS:
        return responses.on_hit(ctx, "form_traps", "too_fast", f"{elapsed:.2f}s", form=True)
    # elapsed > policy.MAX_FORM_AGE is a tab someone left open: not a trap, so no signal
    return None


HONEYPOT_CHECK = Check("honeypot", _honeypot_check)
TIMING_CHECK = Check("timing_token", _timing_check)


if __name__ == "__main__":
    sid = "a1b2c3d4"
    print("Level 2 trap fields as this session sees them:\n")
    print(render_fields(sid, 2))
