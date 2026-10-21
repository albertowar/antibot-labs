"""
W4 Ch11 Capstone — "HTML to text", what an LLM extractor feeds its model (GIVEN, from W4 Ch5)

Every text node, block elements on their own lines, scripts and styles dropped.
Hidden or not, it is all text to the model: that asymmetry is the whole of the
text-layer trap (a person sees the rendered page; the extractor sees the DOM
text, including the off-screen, aria-hidden block).
"""

import re
from html.parser import HTMLParser

_BLOCK = {"p", "div", "article", "section", "h1", "h2", "h3", "h4", "li", "ul", "ol", "header",
          "footer", "main", "nav", "tr", "br", "table"}


class _Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.lines = [[]]
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag in _BLOCK:
            self.lines.append([])

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        if tag in _BLOCK:
            self.lines.append([])

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.lines[-1].append(data.strip())

    def text(self):
        out = [" ".join(parts) for parts in self.lines if parts]
        return "\n".join(re.sub(r"\s+", " ", line) for line in out)


def html_to_text(html):
    p = _Text()
    p.feed(html)
    return p.text()
