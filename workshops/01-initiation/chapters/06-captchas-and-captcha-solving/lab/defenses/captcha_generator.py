"""
Chapter 6, Round 3: the self-hosted text CAPTCHA generator (section 6.3)

Two styles:

  basic     5 characters, spaced apart, rotated, light noise lines and dots.
            Looks "hard" to a person. A 40-line segmentation + nearest-
            neighbour solver reads most of them (attacks/round3_ocr.py).

  hardened  YOUR JOB IN ROUND 3. Until you write it, it is the basic style.
            The goal: variable length, touching glyphs, a wave warp and a
            dark decoy stroke through the text. Each one targets a step the solver
            relies on: known length, gaps between characters, upright glyphs,
            and "the text is the only dark thing in the image".

The trade-off this module makes visible: every hardening step that hurts
the solver also hurts people. tools/personas_ch6.py assumes first-try
human success of 97% (basic) and 88% (hardened), in the range Bursztein
et al. measured for distorted-text CAPTCHAs (2010). Harder images cost you real
users long before they cost a determined attacker anything: a custom CNN
or a multimodal model reads the hardened style too (see the content doc).

defenses/captcha_gate.py picks the style from the level: basic below
policy.HARDENED_FROM_LEVEL (3), hardened from it.

Try it on its own:  python defenses/captcha_generator.py   (writes sample_*.png here)
"""

import functools
import io
import math
import random
import secrets

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

# No 0/O or 1/I: humans confuse them, and failing humans is pure cost.
CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
WIDTH, HEIGHT = 220, 72

_secure = secrets.SystemRandom()  # the answer must not be predictable
_rng = random.Random()            # noise and layout only: speed over secrecy
_np_rng = np.random.default_rng()


@functools.lru_cache(maxsize=None)
def _font(size):
    # Pillow's bundled scalable font: identical images on every OS.
    return ImageFont.load_default(size=size)


def random_text(length):
    return "".join(_secure.choice(CHARSET) for _ in range(length))


def _glyph(char, size, angle, fill):
    tile = Image.new("L", (size + 16, size + 16), 0)
    ImageDraw.Draw(tile).text((8, 2), char, font=_font(size), fill=255,
                              stroke_width=1, stroke_fill=255)
    tile = tile.rotate(angle, resample=Image.BICUBIC, expand=True)
    colour = Image.new("RGB", tile.size, fill)
    return colour, tile


def _dots(img, n=220):
    """Pepper the image with dark single-pixel dots."""
    px = np.array(img)
    ys = _np_rng.integers(0, HEIGHT, n)
    xs = _np_rng.integers(0, WIDTH, n)
    px[ys, xs] = _np_rng.integers(0, 120, (n, 3))
    return Image.fromarray(px)


def generate_basic(text):
    """The classic: spaced, rotated characters over light noise."""
    img = Image.new("RGB", (WIDTH, HEIGHT), (255, 255, 255))
    draw = ImageDraw.Draw(img)
    for _ in range(6):   # light noise lines
        shade = _rng.randint(160, 215)
        draw.line([(_rng.randint(0, WIDTH), _rng.randint(0, HEIGHT)),
                   (_rng.randint(0, WIDTH), _rng.randint(0, HEIGHT))],
                  fill=(shade, shade, shade), width=1)
    x = 12
    for char in text:
        fill = tuple(_rng.randint(0, 80) for _ in range(3))
        colour, mask = _glyph(char, 38, _rng.uniform(-18, 18), fill)
        img.paste(colour, (x, _rng.randint(0, 14)), mask)
        x += _rng.randint(36, 42)
    return _dots(img).filter(ImageFilter.GaussianBlur(0.6))


def generate_hardened(text):
    """Round 3 hardening: break each assumption the solver makes.

    Read attacks/ocr_solver.py first: binarize, segment on gaps, classify
    upright glyphs. Then make each step fail, and look at the result
    yourself (python defenses/captcha_generator.py) after every change.
    """
    # TODO (Round 3): touching glyphs. Space characters closer than their
    #   width so there is no clean gap to cut on (hint: step ~28 px).
    # TODO (Round 3): a dark decoy stroke through part of the text, as thick
    #   as a glyph stroke, so "dark pixels = text" stops being true.
    # TODO (Round 3): a wave warp (shift each column up or down by a sine),
    #   so glyphs are no longer upright.
    # TODO (Round 3): stronger rotation (about ±25°) and varied sizes.
    return generate_basic(text)


def text_length(style):
    # TODO (Round 3): variable length (5–7) for the hardened style, so the
    #   solver can no longer assume five characters.
    return 5


def new_challenge(style="basic"):
    """Return (answer, png_bytes) for a fresh challenge in the given style."""
    text = random_text(text_length(style))
    img = generate_basic(text) if style == "basic" else generate_hardened(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return text, buf.getvalue()


if __name__ == "__main__":
    for style in ("basic", "hardened"):
        for i in range(3):
            answer, png = new_challenge(style)
            path = f"sample_{style}_{i}.png"
            with open(path, "wb") as f:
                f.write(png)
            print(f"{path}  ({len(png)} bytes)")
    print("Open the samples. Which ones could you read on the first try?")
