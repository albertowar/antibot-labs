"""
Chapter 6: a small, targeted CAPTCHA solver (used by Rounds 3 and 4)

Not a general OCR engine. It is the kind of solver one person writes in an
afternoon against ONE site's CAPTCHA, which is the realistic threat for a
self-hosted generator:

  1. Binarize: keep only dark pixels, then a median filter removes the dots.
     The light noise lines fall below the threshold and vanish.
  2. Segment: connected components, sorted left to right. Components much
     wider than a glyph are split evenly (touching characters).
  3. Classify: each glyph is resized to 20x20 and labelled by a k-nearest-
     neighbour model trained on images from the defender's own generator.

White-box training is honest here: a self-hosted generator usually ships in
an open-source library, and when it doesn't, an attacker labels a few
hundred harvested images by hand or buys the labels from a solving farm.

Each step assumes something about the image: dark text on a light
background, gaps between characters, upright glyphs. The hardened style
breaks those assumptions. A segmentation-free CNN would not need them (see
the take-home challenge).
"""

import io
import os
import sys
import time

import numpy as np
from PIL import Image, ImageFilter
from scipy import ndimage
from sklearn.neighbors import KNeighborsClassifier

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import labclient  # noqa: E402,F401  (the localhost guard; also puts the lab root on sys.path)
from defenses import captcha_generator  # noqa: E402  (white-box: the defender's own code)

GLYPH = 20
MIN_PIXELS = 40


def binarize(img):
    gray = img.convert("L").filter(ImageFilter.MedianFilter(3))
    return np.array(gray) < 120


def segment(mask, glyph_width=26):
    labels, n = ndimage.label(mask)
    boxes = []
    for sl in ndimage.find_objects(labels):
        if sl is None:
            continue
        ys, xs = sl
        if mask[sl].sum() < MIN_PIXELS:
            continue
        boxes.append((xs.start, xs.stop, ys.start, ys.stop))
    boxes.sort()
    glyphs = []
    for x0, x1, y0, y1 in boxes:
        parts = max(1, round((x1 - x0) / glyph_width))
        edges = np.linspace(x0, x1, parts + 1).astype(int)
        for a, b in zip(edges[:-1], edges[1:]):
            crop = mask[y0:y1, a:b]
            if crop.sum() >= MIN_PIXELS // 2:
                glyphs.append(crop)
    return glyphs


def features(crop):
    img = Image.fromarray((crop * 255).astype(np.uint8)).resize((GLYPH, GLYPH))
    return (np.array(img) > 127).astype(np.float32).ravel()


class Solver:
    def __init__(self, style="basic"):
        self.style = style
        self.model = KNeighborsClassifier(n_neighbors=3)

    def train(self, samples=300):
        """Generate labelled images with the defender's generator and learn glyphs."""
        start = time.perf_counter()
        X, y = [], []
        for _ in range(samples):
            text, png = captcha_generator.new_challenge(self.style)
            glyphs = segment(binarize(Image.open(io.BytesIO(png))))
            if len(glyphs) != len(text):
                continue   # segmentation failed: unusable for training
            for crop, char in zip(glyphs, text):
                X.append(features(crop))
                y.append(char)
        if len(set(y)) < 2:
            raise RuntimeError("segmentation never matched the text length: nothing to learn")
        self.model.fit(np.array(X), np.array(y))
        self.train_seconds = time.perf_counter() - start
        self.train_glyphs = len(y)
        return self

    def solve(self, png_bytes):
        glyphs = segment(binarize(Image.open(io.BytesIO(png_bytes))))
        if not glyphs:
            return ""
        return "".join(self.model.predict(np.array([features(g) for g in glyphs])))


if __name__ == "__main__":
    for style in ("basic", "hardened"):
        solver = Solver(style).train()
        hits, n, t = 0, 200, 0.0
        for _ in range(n):
            text, png = captcha_generator.new_challenge(style)
            s = time.perf_counter()
            hits += solver.solve(png) == text
            t += time.perf_counter() - s
        print(f"{style:<9} trained on {solver.train_glyphs} glyphs in "
              f"{solver.train_seconds:.1f}s · offline accuracy {hits}/{n} "
              f"({100 * hits / n:.0f}%) · {1000 * t / n:.1f} ms/solve")
