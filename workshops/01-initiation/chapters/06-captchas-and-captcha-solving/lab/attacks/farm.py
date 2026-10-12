"""
Chapter 6: a simulated human solving service ("CAPTCHA farm").

Real solving services sell human labour over an API: the bot uploads an image (or a sitekey +
page URL), a worker somewhere solves it, and the answer or token comes back 10-40 seconds
later. They charge per thousand solves. Motoyama et al. measured about $1 per 1,000 in 2010,
and public price lists still sit in the same range: roughly $0.50-1 per 1,000 for text images,
and $1-3 per 1,000 for token CAPTCHAs. Check before you quote them.

This module simulates one, entirely on your machine. Its workers are people, so they read the
image through captcha_kit.look_at(), the same simulated eyes the shoppers use, and they make the
same kind of mistakes. Nothing here contacts a real service, and doing so against a site you
don't own breaks its terms and, in many places, the law.
"""

import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import labclient  # noqa: E402,F401  (the localhost guard runs on import)
from captcha_kit import look_at, mint_token, sim_sleep, typo  # noqa: E402

PRICE_PER_1000 = {"image": 1.00, "token": 2.00}   # USD, ballpark
QUEUE_SIM_S = (10.0, 40.0)
ACCURACY = 0.92


class Farm:
    def __init__(self, seed=None):
        self.rng = random.Random(seed)
        self.spent = 0.0
        self.jobs = 0

    def solve_image(self, challenge_id):
        """Return a (usually right) answer after the farm's queue delay."""
        sim_sleep(self.rng.uniform(*QUEUE_SIM_S))
        self.spent += PRICE_PER_1000["image"] / 1000
        self.jobs += 1
        answer = look_at(challenge_id) or ""
        return answer if self.rng.random() < ACCURACY else typo(answer, self.rng) if answer else ""

    def solve_token(self, action, hostname="127.0.0.1"):
        """A worker loads your page in their own browser and passes the widget."""
        sim_sleep(self.rng.uniform(*QUEUE_SIM_S))
        self.spent += PRICE_PER_1000["token"] / 1000
        self.jobs += 1
        ip = self.rng.choice(labclient.world_pool("home_broadband"))
        return mint_token(ip, action, hostname)
