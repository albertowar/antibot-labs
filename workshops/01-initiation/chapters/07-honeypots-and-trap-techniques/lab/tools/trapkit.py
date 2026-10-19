"""
trapkit: what the Chapter 7 bots and shoppers share, so each script stays about its idea.

  parse_form        the inputs of one form with everything around them (a bot's view of the HTML)
  parse_css         which classes traps.css hides (display:none) or throws off-screen
  box               what a browser would do with a field: "none", "offscreen" or "visible"
  Robots            robots.txt matching by RFC 9309 (the longest matching rule wins)
  follow            follow redirects the way a browser does
  tripped           did the response carry a trap signal? (the lab oracle: X-Lab-Signals)

Why Robots and not urllib.robotparser: the store's base policy starts with `Allow: /`. Python's parser
applies the FIRST matching rule, so it allows everything and never sees a later Disallow. RFC 9309
(and Googlebot) apply the LONGEST matching rule, so `Disallow: /catalog/archive` beats `Allow: /`.
A crawler persona that used the stdlib parser would ignore your robots.txt and look like an attacker.

Importing labclient runs the labnet localhost guard.
"""

import os
import re
import sys
from html.parser import HTMLParser

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import browsers  # noqa: E402
from labclient import BASE_URL, LabClient, world_pool  # noqa: E402,F401

TEXT_TYPES = {"text", "email", "password", "tel", "url", "search", ""}
TRAP_LAYERS = ("form_traps:", "crawl_traps:", "responses:")
BOT_BROWSER = ("chrome", 153, "windows")


def headers(kind="link", referer=None):
    """A real Chrome's header set, in wire order. Headers are free to forge (Chapter 4)."""
    return browsers.headers_for(BOT_BROWSER, kind, BASE_URL, referer)


# --- Reading a form ---------------------------------------------------------------------------------

class FormParser(HTMLParser):
    """Collect the <input> elements of one form, with the attributes of every element around them
    (a markup-aware bot needs the ancestors to spot a wrapper <div style="display:none">)."""

    VOID = {"input", "br", "img", "meta", "link", "hr"}

    def __init__(self, form_id):
        super().__init__()
        self.form_id, self.stack, self.inputs, self.labels = form_id, [], [], {}
        self.depth = None            # stack depth at which the form was opened
        self._label = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("id") == self.form_id:
            self.depth = len(self.stack)
        inside = self.depth is not None
        if inside and tag == "input":
            field = {**attrs, "_ancestors": [a for _, a in self.stack[self.depth + 1:]], "_label": ""}
            self.inputs.append(field)
            if self._label is not None:
                self._label["inputs"].append(field)
        if inside and tag == "label":
            self._label = {"for": attrs.get("for"), "text": [], "inputs": []}
        if tag not in self.VOID:
            self.stack.append((tag, attrs))

    def handle_endtag(self, tag):
        if tag == "label" and self._label is not None:
            text = " ".join(t for t in self._label["text"] if t).strip()
            if self._label["for"]:
                self.labels[self._label["for"]] = text
            for field in self._label["inputs"]:
                field["_label"] = text
            self._label = None
        while self.stack:
            if self.stack.pop()[0] == tag:
                break
        if self.depth is not None and len(self.stack) <= self.depth:
            self.depth = None

    def handle_data(self, data):
        if self._label is not None and data.strip():
            self._label["text"].append(data.strip())


def parse_form(html, form_id="register-form"):
    parser = FormParser(form_id)
    parser.feed(html)
    for field in parser.inputs:
        if not field["_label"]:
            field["_label"] = parser.labels.get(field.get("id"), "")
    return parser.inputs


def fill_value(field, user):
    """What a form-filling bot types into a field, judged by its type and autocomplete hint."""
    kind, hint = field.get("type", "text"), field.get("autocomplete", "")
    if kind == "email":
        return f"{user}@example.test"
    if kind == "password":
        return f"Pw-{user}-2026!"
    if hint == "name":
        return "Spam Bot"
    return user


# --- What a browser would make of the page's CSS ---------------------------------------------------

def parse_css(text):
    """{"none": classes with display:none, "offscreen": classes moved far off-screen}. Simple selectors only."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    css = {"none": set(), "offscreen": set()}
    for selector, body in re.findall(r"([^{}]+)\{([^}]*)\}", text):
        classes = re.findall(r"\.([\w-]+)", selector)
        body = re.sub(r"\s+", "", body)
        if "display:none" in body:
            css["none"].update(classes)
        if re.search(r"left:-\d{3,}px", body):
            css["offscreen"].update(classes)
    return css


def box(field, css):
    """'none' (no layout box: not visible, not focusable, not autofilled), 'offscreen' (a box outside
    the viewport: Playwright's is_visible() is true, Tab and autofill still reach it), or 'visible'."""
    result = "visible"
    for element in [field, *field.get("_ancestors", [])]:
        style = re.sub(r"\s+", "", element.get("style") or "")
        classes = (element.get("class") or "").split()
        if "display:none" in style or "hidden" in element or any(c in css["none"] for c in classes):
            return "none"
        if any(c in css["offscreen"] for c in classes):
            result = "offscreen"
    return result


def tab_reachable(field, css):
    """Does the Tab key land on it? (A box, and not tabindex=-1.)"""
    return box(field, css) != "none" and field.get("tabindex") != "-1"


# --- robots.txt, RFC 9309 --------------------------------------------------------------------------

class Robots:
    """The `*` group of a robots.txt. allowed(path) applies the longest matching rule; a tie is allowed."""

    def __init__(self, text):
        self.rules = []
        for line in text.splitlines():
            key, _, value = line.split("#")[0].partition(":")
            key, value = key.strip().lower(), value.strip()
            if key in ("allow", "disallow") and value:
                self.rules.append((key == "allow", value))

    @staticmethod
    def _matches(rule, path):
        pattern = re.escape(rule).replace(r"\*", ".*")
        if pattern.endswith(r"\$"):
            pattern = pattern[:-2] + "$"
        return re.match(pattern, path) is not None

    def allowed(self, path):
        best = None
        for allow, rule in self.rules:
            if self._matches(rule, path) and (best is None or len(rule) > len(best[1]) or
                                              (len(rule) == len(best[1]) and allow)):
                best = (allow, rule)
        return True if best is None else best[0]


# --- Talking to the store ----------------------------------------------------------------------------

def follow(client, response, hdrs=(), hops=3):
    """Follow redirects like a browser does (LabClient does not)."""
    while response.status_code in (301, 302, 303, 307, 308) and hops:
        location = response.headers["Location"]
        path = location[len(BASE_URL):] if location.startswith(BASE_URL) else location
        response = client.get(path, hdrs)
        hops -= 1
    return response


def tripped(response):
    """The lab oracle: did the store flag this response with a trap or sanction signal? (X-Lab-Signals)"""
    return any(layer in response.headers.get("X-Lab-Signals", "") for layer in TRAP_LAYERS)


def signed_up(response):
    """What a spammer can see: the redirect landed on a 200 /account page."""
    return response.status_code == 200 and "/account" in (response.url or "")
