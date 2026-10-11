"""Deterministic junk-text generator for the maze (GIVEN infrastructure).

Nepenthes and iocaine fill their decoy pages with Markov-chain text trained on
a corpus the operator chooses, so the pages read like the site without being
the site. This is the same idea at lab scale: a word-bigram chain built from
the catalogue's own product descriptions, seeded per page so every URL renders
the same "static" page forever (a crawler that re-fetches to check for changes
learns nothing) while no two URLs match.

Why bigrams and not an LLM: the whole point of a deterrent is that generating
the decoy must cost the defender far less than fetching it costs the crawler.
Cloudflare's AI Labyrinth pre-generates with a small model for the same reason.
A page here costs well under a millisecond.
"""

from __future__ import annotations

import random
from collections import defaultdict


class Babbler:
    def __init__(self, corpus_texts):
        self.chain = defaultdict(list)
        self.starts = []
        for text in corpus_texts:
            words = text.split()
            if len(words) < 2:
                continue
            self.starts.append(words[0])
            for a, b in zip(words, words[1:]):
                self.chain[a].append(b)

    def paragraph(self, rng: random.Random, n_words: int) -> str:
        if not self.starts:
            return "nothing to see here " * (n_words // 4)
        out = [rng.choice(self.starts)]
        while len(out) < n_words:
            nxt = self.chain.get(out[-1])
            out.append(rng.choice(nxt) if nxt else rng.choice(self.starts))
        text = " ".join(out)
        return text[0].upper() + text[1:].rstrip(",;") + "."

    def page(self, seed: int, paragraphs: int = 4, words: int = 70):
        rng = random.Random(seed)
        title_words = self.paragraph(rng, 4).rstrip(".").split()
        title = " ".join(w.capitalize() for w in title_words)
        body = [self.paragraph(rng, words + rng.randint(-15, 15)) for _ in range(paragraphs)]
        return title, body, rng
