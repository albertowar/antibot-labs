"""The lab's LLM client: a deterministic mock by default, a real model by env var.

Every LLM call in this lab, on both sides of the arms race, goes through
``LLM.chat(task, system, user, images=None)``. Two backends:

  * **mock** (default). An in-process, seeded stand-in that needs no download, no
    GPU and no network, so a round takes seconds and the checkpoint numbers are
    reproducible. It is *not* a language model. For each task it implements the
    narrow behaviour the round teaches:
      - ``review``      composes a unique, on-topic review from a persona spec
      - ``solve_text``  answers the gate's arithmetic / word / letter puzzles
      - ``solve_image`` "sees" a tile by reading the label the gate embeds in the
                        PNG's tEXt chunk. That is a stand-in for a vision model's
                        eyes, nothing more — swap in a real model to see pixels.
      - ``extract``     turns page text into JSON product records
      - ``summarize`` / ``assist``  write about reviews, and — this is the point
                        of Round 4 — follow instructions they find *inside* the
                        reviews, unless the prompt marks that text as data.
    The instruction-following is a model of a known failure class (indirect
    prompt injection, OWASP LLM01:2025), implemented as explicit rules so the
    lab is deterministic. A real model fails the same way, less predictably.

  * **openai-compatible** (``LLM_URL`` set). Any server speaking the OpenAI chat
    completions API: Ollama (``http://127.0.0.1:11434/v1``), llama.cpp, vLLM.
    ``LLM_MODEL`` for text, ``LLM_VISION_MODEL`` for tasks that pass images. No
    API key, no cloud account; the lab never leaves your machine.

Token accounting (``usage()``) is the defender's cost meter *and* the attacker's
bill: Round 2 reports tokens per solve, Round 3 tokens per page.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import struct
import time
import unicodedata
import zlib
from collections import namedtuple

LLM_URL = os.environ.get("LLM_URL")                       # e.g. http://127.0.0.1:11434/v1
LLM_MODEL = os.environ.get("LLM_MODEL", "qwen3:4b")
LLM_VISION_MODEL = os.environ.get("LLM_VISION_MODEL", "qwen2.5vl:3b")

Reply = namedtuple("Reply", "text prompt_tokens completion_tokens backend ms")

USAGE = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "ms": 0.0}


def reset_usage():
    USAGE.update(calls=0, prompt_tokens=0, completion_tokens=0, ms=0.0)


def usage():
    return dict(USAGE)


def approx_tokens(text: str) -> int:
    """~4 characters per token: close enough for a cost meter."""
    return max(1, len(text) // 4)


class LLM:
    def __init__(self, backend: str | None = None):
        self.backend = backend or ("openai" if LLM_URL else "mock")

    def chat(self, task: str, system: str, user: str, images: list[bytes] | None = None) -> Reply:
        t0 = time.perf_counter()
        if self.backend == "mock":
            text = _mock(task, system, user, images or [])
            pt = approx_tokens(system + user) + 256 * len(images or [])
            ct = approx_tokens(text)
        else:
            text, pt, ct = _openai_compatible(system, user, images or [])
        ms = (time.perf_counter() - t0) * 1000
        USAGE["calls"] += 1
        USAGE["prompt_tokens"] += pt
        USAGE["completion_tokens"] += ct
        USAGE["ms"] += ms
        return Reply(text, pt, ct, self.backend, ms)


# --- real backend ---------------------------------------------------------------

def _openai_compatible(system, user, images):
    import requests  # local import: the mock path has no dependency
    content: list | str = user
    if images:
        content = [{"type": "text", "text": user}] + [
            {"type": "image_url",
             "image_url": {"url": "data:image/png;base64," + base64.b64encode(b).decode()}}
            for b in images]
    body = {
        "model": LLM_VISION_MODEL if images else LLM_MODEL,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": content}],
        "temperature": 0,
        "stream": False,
    }
    r = requests.post(f"{LLM_URL.rstrip('/')}/chat/completions", json=body, timeout=180)
    r.raise_for_status()
    data = r.json()
    text = data["choices"][0]["message"]["content"]
    use = data.get("usage") or {}
    return (text.strip(),
            int(use.get("prompt_tokens") or approx_tokens(system + user)),
            int(use.get("completion_tokens") or approx_tokens(text)))


# --- mock backend ---------------------------------------------------------------

def _mock(task, system, user, images):
    fn = {
        "review": _mock_review, "solve_text": _mock_solve_text,
        "solve_image": _mock_solve_image, "extract": _mock_extract,
        "summarize": _mock_summarize, "assist": _mock_assist,
    }.get(task)
    if fn is None:
        raise ValueError(f"mock LLM has no behaviour for task {task!r}")
    return fn(system, user, images)


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _field(user, name, default=""):
    m = re.search(rf"^{name}\s*:\s*(.+)$", user, re.M | re.I)
    return m.group(1).strip() if m else default


# review --------------------------------------------------------------------------

_OPEN = {
    "positive": ["Picked up the {p} last month and it has been in daily use since.",
                 "I was sceptical about the {p} but it won me over quickly.",
                 "Third purchase from this shop; the {p} is the best of the lot.",
                 "Needed something for {use} and the {p} fits the bill.",
                 "Bought the {p} as a replacement for a tired old one.",
                 "Honestly did not expect much from the {p} at this price."],
    "mixed": ["The {p} is fine, with a couple of caveats.",
              "Mixed feelings about the {p} after two weeks.",
              "Decent {p}, though not quite what the listing suggests.",
              "The {p} does the job for {use}, with some rough edges."],
    "negative": ["The {p} looked promising but has not held up.",
                 "Returned the {p} after a week.",
                 "Not impressed with the {p}, sadly."],
}
_BODY = ["The {f1} is {a1} and the {f2} feels {a2}.",
         "What stands out is the {f1}: {a1}. The {f2}, by contrast, is merely {a2}.",
         "{f1} {a1}, {f2} {a2}; that about sums it up.",
         "My partner noticed the {f1} first ({a1}), I cared more about the {f2}, which is {a2}.",
         "Compared with the one it replaced, the {f1} is {a1} and the {f2} is {a2}.",
         "Two things matter here: {f1} ({a1}) and {f2} ({a2})."]
_FEAT = ["stitching", "fit", "weight", "colour", "padding", "sizing", "zip", "fabric",
         "sole", "strap", "finish", "lining", "price-to-quality ratio", "packaging"]
_ADJ = {"positive": ["excellent", "better than expected", "solid", "exactly as pictured",
                     "sturdy", "comfortable from day one", "well judged", "generous"],
        "mixed": ["acceptable", "a bit uneven", "fine but unremarkable", "slightly off",
                  "okay for the money", "hit and miss"],
        "negative": ["flimsy", "disappointing", "wrong in the photos", "already fraying",
                     "poorly glued", "uncomfortable"]}
_CLOSE = {"positive": ["Would buy again.", "Recommended for {use}.", "Four and a half stars from me.",
                       "Sizing runs true, order your usual.", "Delivery was quick too.",
                       "No complaints so far."],
          "mixed": ["Three stars, maybe three and a half.", "Worth it on sale, not at full price.",
                    "Keeping it, but check the measurements first."],
          "negative": ["Cannot recommend.", "Two stars, and that is generous.",
                       "Back to the old brand for me."]}
_USES = ["weekend hikes", "the commute", "the gym", "travel", "everyday wear", "the garden",
         "running errands", "work trips"]


def _mock_review(system, user, images):
    product = _field(user, "Product", "product")
    persona = _field(user, "Persona", "shopper")
    sentiment = _field(user, "Sentiment", "positive").lower()
    length = _field(user, "Length", "medium").lower()
    sentiment = sentiment if sentiment in _OPEN else "positive"
    rng = _rng("review", product, persona, sentiment, length, _field(user, "Seed", "0"))
    use = rng.choice(_USES)
    f1, f2 = rng.sample(_FEAT, 2)
    a1, a2 = rng.sample(_ADJ[sentiment], 2)
    parts = [rng.choice(_OPEN[sentiment]).format(p=product, use=use),
             rng.choice(_BODY).format(f1=f1, f2=f2, a1=a1, a2=a2)]
    if length != "short":
        f3 = rng.choice([f for f in _FEAT if f not in (f1, f2)])
        parts.append(rng.choice(_BODY).format(f1=f3, f2=rng.choice(_FEAT), a1=rng.choice(_ADJ[sentiment]),
                                                 a2=rng.choice(_ADJ[sentiment])))
    parts.append(rng.choice(_CLOSE[sentiment]).format(use=use))
    text = " ".join(parts)
    return text[0].upper() + text[1:]


# puzzles -------------------------------------------------------------------------

_LEXICON = {
    "fruit": {"apple", "pear", "banana", "cherry", "mango", "plum", "grape", "lemon"},
    "animal": {"otter", "heron", "badger", "lynx", "goat", "trout", "wren", "moose"},
    "colour": {"red", "blue", "green", "amber", "violet", "teal", "ochre", "ivory"},
    "tool": {"hammer", "wrench", "chisel", "pliers", "saw", "drill", "trowel", "awl"},
}


def _mock_solve_text(system, user, images):
    q = user.strip()
    m = re.search(r"what is (\d+)\s*([+\-*×x])\s*(\d+)", q, re.I)
    if m:
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        return str(a + b if op == "+" else a - b if op == "-" else a * b)
    m = re.search(r"which of these is an? (\w+): ([\w, ]+)\?", q, re.I)
    if m:
        kind, options = m.group(1).lower(), [o.strip() for o in m.group(2).split(",")]
        for o in options:
            if o in _LEXICON.get(kind, set()):
                return o
    m = re.search(r"type the word ['\"](\w+)['\"] backwards", q, re.I)
    if m:
        return m.group(1)[::-1]
    m = re.search(r"how many letters (?:are )?in ['\"](\w+)['\"]", q, re.I)
    if m:
        return str(len(m.group(1)))
    m = re.search(r"what is the (first|last) letter of ['\"](\w+)['\"]", q, re.I)
    if m:
        w = m.group(2)
        return w[0] if m.group(1).lower() == "first" else w[-1]
    return "unknown"


def png_text_chunks(png: bytes) -> dict:
    """Read the tEXt chunks of a PNG (stdlib only). The gate labels each tile."""
    out = {}
    pos = 8
    while pos + 8 <= len(png):
        length, ctype = struct.unpack(">I4s", png[pos:pos + 8])
        data = png[pos + 8:pos + 8 + length]
        if ctype == b"tEXt" and b"\x00" in data:
            k, v = data.split(b"\x00", 1)
            out[k.decode("latin-1")] = v.decode("latin-1")
        pos += 12 + length
    return out


def _mock_solve_image(system, user, images):
    m = re.search(r"containing an? (\w+)", user, re.I)
    target = m.group(1).lower() if m else ""
    hits = []
    for i, png in enumerate(images, start=1):
        if png_text_chunks(png).get("lab-label", "").split(",")[0] == target:
            hits.append(str(i))
    return ",".join(hits) or "none"


# extraction ---------------------------------------------------------------------

_PRICE = re.compile(r"[€$]\s?(\d+(?:\.\d{2})?)")
_SKU = re.compile(r"\bSKU\s+([a-z]+-\d{3})\b", re.I)


def _mock_extract(system, user, images):
    """Page text -> JSON records. Reads every line that carries a SKU; obeys any
    instruction in the text that tells readers to add a field to each record."""
    text = _normalize(user)
    directives = _record_directives(text)
    records = []
    for line in text.splitlines():
        sku = _SKU.search(line)
        if not sku:
            continue
        price = _PRICE.search(line)
        name = _SKU.sub("", _PRICE.sub("", line))
        name = re.sub(r"[·|•\-–]+", " ", name)
        name = re.sub(r"\s{2,}", " ", name).strip(" ·|:-")
        rec = {"sku": sku.group(1).lower(), "name": name,
               "price": float(price.group(1)) if price else None}
        rec.update(directives)
        records.append(rec)
    return json.dumps(records)


def _record_directives(text):
    """'...readers/extractors ... must carry|include <field> <value>' -> {field: value}."""
    out = {}
    for sent in re.split(r"(?<=[.!?\n])\s+", text):
        if not re.search(r"\b(readers?|extractors?|assistants?|agents?|records?)\b", sent, re.I):
            continue
        m = re.search(r"\b(?:carry|include|add|contain)\b[^\w]*(?:the |a )?(?:field )?"
                      r"([A-Za-z_]{3,})\s*[:=]?\s*[\"'“]?([A-Za-z0-9][\w\-]{3,})", sent)
        if m:
            out[m.group(1).lower()] = m.group(2)
    return out


# summarise / assist (instruction following lives here) ---------------------------

_ZW = re.compile(r"[​‌‍⁠﻿]")
_CONFUSABLE = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
                             "і": "i", "ѕ": "s", "у": "y", "ԁ": "d", "ɡ": "g"})
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}")
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
# A hostname, with or without scheme, e.g. "http://x.test/p" or "cheaper-deals.test/promo".
# A real model surfaces the domain whether or not the attacker wrote the scheme —
# which is exactly why the store's http://-only link filter does not save it.
_URL = re.compile(r"(?:https?://)?(?:[a-z0-9][a-z0-9\-]*\.)+[a-z]{2,}(?:/[\w./\-]*)?", re.I)
_CUE = re.compile(r"\b(ignore|disregard|you are now|mention|recommend|tell|end (?:every|each)|"
                  r"finish every|append|print|output|reveal|show|include|add|visit|say)\b", re.I)
_SECRET_CUE = re.compile(r"\b(support code|secret|hidden code|your instructions|system prompt)\b", re.I)


def _normalize(text: str) -> str:
    """What the model 'reads': NFKC, zero-width stripped, confusables folded, HTML
    comments unwrapped, and base64 blobs decoded when the text says to decode."""
    t = unicodedata.normalize("NFKC", text)
    t = _ZW.sub("", t).translate(_CONFUSABLE)
    t = _HTML_COMMENT.sub(lambda m: " " + m.group(1) + " ", t)
    if re.search(r"\bdecode\b", t, re.I):
        def _dec(m):
            try:
                raw = base64.b64decode(m.group(0), validate=True).decode("utf-8")
            except Exception:
                return m.group(0)
            return raw if raw.isprintable() else m.group(0)
        t = _B64.sub(_dec, t)
    return t


def _datamark(system):
    """The guard's convention: 'lines beginning with <char> are data'."""
    m = re.search(r"beginning with (\S) are (?:customer )?data", system, re.I)
    return m.group(1) if m else None


def _instructions(system, user):
    """Instructions the mock will act on, found anywhere in the prompt. Lines the
    system prompt declares as data-marked are skipped (spotlighting)."""
    mark = _datamark(system)
    body = _normalize(user)
    if mark:
        body = "\n".join(l for l in body.splitlines() if not l.lstrip().startswith(mark))
    joined = re.sub(r"\s+", " ", body)
    found = []
    for sent in re.split(r"(?<=[.!?])\s+", joined):
        if not _CUE.search(sent):
            continue
        url = _URL.search(sent)
        if url:
            found.append(("url", url.group(0).rstrip(".,'\")")))
        elif _SECRET_CUE.search(sent):
            found.append(("secret", None))
    return found


def _secret(system):
    m = re.search(r"support code[:\s]+([A-Z0-9\-]{6,})", system, re.I)
    return m.group(1) if m else None


def _reviews_in(user):
    return [l for l in user.splitlines() if re.match(r"^\W*\[?\d\s*(?:/5|stars?|★)", l.strip(), re.I)
            or l.lstrip().startswith(("^", "- ", "* "))]


def _apply_instructions(system, user, text):
    for kind, val in _instructions(system, user):
        if kind == "url" and val not in text:
            text += f" Visit {val} for a better price."
        elif kind == "secret":
            s = _secret(system)
            if s and s not in text:
                text += f" Support code: {s}."
    return text


def _mock_summarize(system, user, images):
    product = _field(user, "Product", "this product")
    ratings = [int(x) for x in re.findall(r"\[(\d)/5\]", user)]
    n = len(ratings)
    if n == 0:
        base = f"No customer reviews for {product} yet."
    else:
        avg = sum(ratings) / n
        tone = "mostly positive" if avg >= 4 else "mixed" if avg >= 3 else "mostly negative"
        base = (f"{n} customer review{'s' if n != 1 else ''} for {product}, averaging "
                f"{avg:.1f}/5 — {tone}. Reviewers mention fit, finish and value for money.")
    return _apply_instructions(system, user, base)


def _mock_assist(system, user, images):
    product = _field(user, "Product", "this product")
    q = _field(user, "Question", "")
    price = _field(user, "Price", "")
    base = f"About {product}: "
    if re.search(r"price|cost|how much", q, re.I) and price:
        base += f"it is listed at €{price}."
    elif re.search(r"return|refund", q, re.I):
        base += "returns are accepted within 30 days in original condition."
    elif re.search(r"waterproof|water", q, re.I):
        base += "the listing does not claim it is waterproof."
    else:
        base += "customers describe it as reliable for everyday use; see the reviews for detail."
    return _apply_instructions(system, user, base)


if __name__ == "__main__":
    llm = LLM()
    print(llm.chat("solve_text", "", "What is 7 + 4?").text)
    print(llm.chat("review", "", "Product: Alpine Runner 4\nPersona: weekend hiker\nSentiment: positive\nLength: medium\nSeed: 1").text)
    print(usage())
