"""
Chapter 5, Round 3: the self-hosted text CAPTCHA generator (section 5.3) REFERENCE SOLUTION

Two styles:

  basic     5 characters, spaced apart, rotated, light noise lines and dots.
            Looks "hard" to a person. A 40-line segmentation + nearest-
            neighbour solver reads most of them (attacks/round3_ocr.py).

  hardened  Variable length, touching glyphs, a wave warp and a dark decoy
            stroke through the text. Each one targets a step the solver
            relies on: known length, gaps between characters, upright glyphs,
            and "the text is the only dark thing in the image".

The trade-off this module makes visible: every hardening step that hurts
the solver also hurts people. tools/personas_ch5.py assumes first-try
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
    """Round 3 hardening: break each assumption the solver makes."""
    img = Image.new("RGB", (WIDTH, HEIGHT), (255, 255, 255))
    draw = ImageDraw.Draw(img)
    for _ in range(6):
        shade = _rng.randint(160, 215)
        draw.line([(_rng.randint(0, WIDTH), _rng.randint(0, HEIGHT)),
                   (_rng.randint(0, WIDTH), _rng.randint(0, HEIGHT))],
                  fill=(shade, shade, shade), width=1)

    # 1. Touching glyphs: the step is narrower than a character, so there
    #    is no clean gap to cut on. Spread the text to fill the canvas.
    step = min(28, (WIDTH - 36) // len(text))
    x = _rng.randint(6, 12)
    for char in text:
        fill = tuple(_rng.randint(0, 80) for _ in range(3))
        size = _rng.randint(32, 38)
        colour, mask = _glyph(char, size, _rng.uniform(-25, 25), fill)
        img.paste(colour, (x, _rng.randint(4, 14)), mask)
        x += step + _rng.randint(-3, 1)

    # 2. A dark decoy stroke through part of the text, as thick as a glyph stroke.
    x0 = _rng.randint(0, WIDTH // 3)
    x1 = x0 + _rng.randint(WIDTH // 2, 2 * WIDTH // 3)
    y0, phase = _rng.randint(30, 42), _rng.uniform(0, math.pi)
    pts = [(px, y0 + 5 * math.sin(px / 16 + phase)) for px in range(x0, x1, 4)]
    draw.line(pts, fill=tuple(_rng.randint(0, 60) for _ in range(3)), width=2)

    # 3. A wave warp: columns shift up and down, so glyphs are no longer upright.
    amp, period = _rng.uniform(2, 4), _rng.uniform(36, 48)
    dy = (amp * np.sin(2 * np.pi * np.arange(WIDTH) / period)).astype(int)
    rows = np.clip(np.arange(HEIGHT)[:, None] - dy[None, :], 0, HEIGHT - 1)
    warped = Image.fromarray(np.array(img)[rows, np.arange(WIDTH)[None, :]])

    return _dots(warped).filter(ImageFilter.GaussianBlur(0.6))


def text_length(style):
    # 4. Variable length: the solver can no longer assume five characters.
    return 5 if style == "basic" else _secure.randint(5, 7)


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
