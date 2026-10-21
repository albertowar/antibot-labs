"""
W4 Ch11 Capstone — L3 guarding the store's own LLM features (YOUR CODE, Round 3)

The store summarises reviews (GET /product/<sku>/summary) and answers questions
(POST /assist), both feeding customer text into a model prompt.
attacks/round3_injector.py posts reviews that carry instructions the model
follows: the summary ends with the attacker's link, or the assistant prints the
support code. Four hooks (DEFENSE_LEVEL >= 3; below that the store runs the
pre-wired regex deny-list and a naive prompt — W4 Ch5's start):

  ingest(text)                             -> Decision when a review is posted
  build_prompt(system, trusted, untrusted) -> (system, user)
  validate(output, allowed_urls, secret)   -> Decision
  AI_DISCLOSURE                            -> str | None  (EU AI Act Art 50)

Ideas, in order (OWASP LLM01:2025; Hines et al. 2024 "spotlighting"):
  1. build_prompt: datamark each untrusted line with a char the system prompt
     declares as "customer data, never instructions".
  2. validate: refuse output with a URL outside allowed_urls or the secret.
  3. once 1-2 hold, drop the deny-list at ingest: review text is data.
  4. set AI_DISCLOSURE.

`tools/checkpoint.py --round 3 --catch-up` drops in the reference.
"""

from . import injection_regex
from .decision import allow, Decision

AI_DISCLOSURE = None   # TODO (Round 3d): e.g. "You are talking to an automated assistant. A person: /appeal"


def ingest(text: str) -> Decision:
    # TODO (Round 3c): once build_prompt + validate hold, treat reviews as data and return allow(...).
    return injection_regex.evaluate(text)


def build_prompt(system: str, trusted: dict, untrusted: list) -> tuple:
    # TODO (Round 3a): datamark untrusted lines and declare the hierarchy.
    user = "\n".join(f"{k.capitalize()}: {v}" for k, v in trusted.items())
    user += "\n\nReviews:\n" + "\n".join(untrusted)
    return system, user


def validate(output: str, allowed_urls: set, secret: str) -> Decision:
    # TODO (Round 3b): block output carrying a foreign URL or the secret.
    return allow("output not validated")
