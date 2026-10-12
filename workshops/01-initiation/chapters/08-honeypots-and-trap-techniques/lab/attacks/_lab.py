"""
Chapter 8 — Shared helpers for the lab's attack scripts and tools.

Rules of engagement, enforced in code:
  - Every script targets DEMO_URL (default http://localhost:5000) and refuses
    to run against anything that isn't localhost.
  - Client IPs are TEST-NET addresses (RFC 5737), sent in X-Forwarded-For to
    the demo store's simulated edge. No traffic leaves your machine.
  - All users, emails and passwords are synthetic.

X-Lab-Actor labels every request for the scoreboard. The demo store never
uses it to make a decision; a real bot obviously wouldn't send it.
"""

import os
import sys
import re
import secrets
from html.parser import HTMLParser

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://localhost:5000")

CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36")
TEXT_TYPES = {"text", "email", "password", "tel", "url", "search", ""}


def lab_headers(actor, ip):
    return {"X-Forwarded-For": ip, "X-Lab-Actor": actor}


def http_client(actor, ip, user_agent=CHROME_UA):
    """An httpx client with its own cookie jar (a fresh session)."""
    require_local()
    return httpx.Client(base_url=BASE_URL, timeout=10, follow_redirects=True,
                        headers={"User-Agent": user_agent, **lab_headers(actor, ip)})


def tag(n=4):
    return secrets.token_hex(n)


def outcome(html):
    """The data-outcome attribute the demo store puts on every result page."""
    m = re.search(r'data-outcome="([^"]+)"', html)
    return m.group(1) if m else None


class FormParser(HTMLParser):
    """
    Collect the <input> elements of one form, with the attributes of every
    element around them. A markup-aware bot needs the ancestors to spot a
    wrapper <div style="display:none">.
    """

    VOID = {"input", "br", "img", "meta", "link", "hr"}

    def __init__(self, form_id):
        super().__init__()
        self.form_id = form_id
        self.stack = []
        self.in_form = False
        self.inputs = []
        self.labels = {}
        self._label_for = None

    def handle_starttag(self, tag_name, attrs):
        attrs = dict(attrs)
        if tag_name == "form" and attrs.get("id") == self.form_id:
            self.in_form = True
        if self.in_form and tag_name == "input":
            self.inputs.append({**attrs, "_ancestors": [a for _, a in self.stack]})
        if self.in_form and tag_name == "label":
            self._label_for = attrs.get("for")
        if tag_name not in self.VOID:
            self.stack.append((tag_name, attrs))

    def handle_endtag(self, tag_name):
        if tag_name == "form" and self.in_form:
            self.in_form = False
        if tag_name == "label":
            self._label_for = None
        while self.stack:
            if self.stack.pop()[0] == tag_name:
                break

    def handle_data(self, data):
        if self._label_for and data.strip():
            self.labels[self._label_for] = data.strip()


def parse_form(html, form_id="signup"):
    parser = FormParser(form_id)
    parser.feed(html)
    for field in parser.inputs:
        field["_label"] = parser.labels.get(field.get("id"), "")
    return parser.inputs


def fill_value(field, i, user):
    """What a form-filling bot types into a field, judged by its type."""
    kind = field.get("type", "text")
    if kind == "email":
        return f"{user}@example.com"
    if kind == "password":
        return f"Pw-{user}-2026"
    return user
