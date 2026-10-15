"""
W4 Chapter 7 — The model client: one interface, two backends, honest accounting

    LLM_BACKEND=mock    (default) a deterministic scripted analyst, see llm_mock.py
    LLM_BACKEND=ollama  a real local model through Ollama's structured outputs

Why a mock by default: the lab must run on a laptop in ten minutes with no
GPU, no account and no download, and every checkpoint must be reproducible.
Why Ollama as the swap: it is free, local, MIT-licensed, and `format=` lets
the model be constrained to our JSON schema at decode time, which is the
first layer of output handling (OWASP LLM05:2025).

Accounting. Under the mock, token counts are `ceil(chars / 4)` and flagged
`est`: close enough for prose, generous for header soup (base64 and UA-like
strings tokenize nearer 2–3 chars per token, so a real flood is worse than
the estimate). Under Ollama the counts are the server's own. Dollar
figures use LLM_PRICE_IN / LLM_PRICE_OUT per million tokens (defaults are an
illustrative mid-2026 small-model price, not a quote); a local model costs
$0 in cash and the same tokens in time.

Failure policy: fail closed. If Ollama is not reachable or the model is
not pulled, the pipeline stops with the fix printed. It never silently
falls back to the mock, because a defense that quietly swaps its analyst
is a defense whose numbers you cannot trust.
"""

import json
import math
import os
import time
from dataclasses import dataclass
from urllib.parse import urlparse

BACKEND = os.environ.get("LLM_BACKEND", "mock")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
PRICE_IN = float(os.environ.get("LLM_PRICE_IN", "0.20"))     # $ per 1M prompt tokens
PRICE_OUT = float(os.environ.get("LLM_PRICE_OUT", "0.80"))   # $ per 1M completion tokens
NUM_CTX = int(os.environ.get("OLLAMA_NUM_CTX", "4096"))


class LLMError(RuntimeError):
    pass


@dataclass
class LLMResult:
    content: dict | None
    raw: str
    prompt_tokens: int
    completion_tokens: int
    est: bool
    latency_ms: float
    backend: str
    model: str
    error: str | None = None


def estimate_tokens(text):
    return math.ceil(len(text) / 4)


def usd(prompt_tokens, completion_tokens):
    return prompt_tokens / 1e6 * PRICE_IN + completion_tokens / 1e6 * PRICE_OUT


def messages_text(messages):
    return "\n".join(m.get("content", "") for m in messages)


class LLMClient:
    def __init__(self, backend=None, model=None):
        self.backend = backend or BACKEND
        if self.backend == "mock":
            from .llm_mock import MockBackend
            self.model = model or "scripted-analyst"
            self._impl = MockBackend()
        elif self.backend == "ollama":
            self.model = model or OLLAMA_MODEL
            self._impl = _Ollama(self.model)
        else:
            raise LLMError(f"unknown LLM_BACKEND={self.backend!r} (use mock or ollama)")

    def chat(self, messages, schema):
        """messages: [{role, content}, ...]; schema: JSON schema for the answer."""
        return self._impl.chat(messages, schema)

    def describe(self):
        return f"{self.backend}:{self.model}"


class _Ollama:
    def __init__(self, model):
        host = urlparse(OLLAMA_HOST).hostname
        if host not in ("localhost", "127.0.0.1", "::1"):
            raise LLMError(f"OLLAMA_HOST={OLLAMA_HOST}: the lab only talks to a local model server.")
        import ollama
        self._ollama = ollama
        self.client = ollama.Client(host=OLLAMA_HOST)
        self.model = model

    def chat(self, messages, schema):
        t0 = time.perf_counter()
        try:
            resp = self.client.chat(
                model=self.model, messages=messages, format=schema,
                options={"temperature": 0, "seed": 42, "num_ctx": NUM_CTX, "num_predict": 400},
                keep_alive="10m")
        except self._ollama.ResponseError as e:
            raise LLMError(f"Ollama answered {e.status_code}: {e.error}\n"
                           f"  fix: ollama pull {self.model}") from e
        except Exception as e:   # httpx.ConnectError and friends
            raise LLMError(f"cannot reach Ollama at {OLLAMA_HOST} ({e.__class__.__name__})\n"
                           f"  fix: start it with `ollama serve`, then `ollama pull {self.model}`") from e
        latency = (time.perf_counter() - t0) * 1000
        p_tok = resp.get("prompt_eval_count") or estimate_tokens(messages_text(messages))
        c_tok = resp.get("eval_count") or 0
        if p_tok >= NUM_CTX - 50:
            # Ollama truncates silently from the front, i.e. it drops the system
            # prompt first. A hardened prompt that got truncated is not hardened.
            raise LLMError(f"prompt is {p_tok} tokens, near num_ctx={NUM_CTX}: it would be truncated. "
                           f"Cap the fields (defenses/sanitize.py) or raise OLLAMA_NUM_CTX.")
        raw = resp["message"]["content"]
        try:
            content = json.loads(raw)
            err = None
        except json.JSONDecodeError as e:
            content, err = None, f"not JSON: {e}"
        return LLMResult(content, raw, p_tok, c_tok, False, latency, "ollama", self.model, err)


if __name__ == "__main__":
    import sys
    from schemas import VERDICT_SCHEMA_FOR_MODEL
    client = LLMClient()
    r = client.chat([{"role": "system", "content": "Answer in JSON."},
                     {"role": "user", "content": "User-Agent: python-httpx/0.28.1\nasn_type: datacenter\n"
                                                 "n_pages: 4\nn_assets: 0\nhoneypot_hit: true"}],
                    VERDICT_SCHEMA_FOR_MODEL)
    print(client.describe(), json.dumps(r.content), f"{r.prompt_tokens}+{r.completion_tokens} tok",
          f"{r.latency_ms:.0f} ms", "est" if r.est else "measured")
