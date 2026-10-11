"""
The agent's "brain": given a snapshot and a goal, pick the next action.

Two policies, same interface: decide(goal, snapshot, memory) -> action dict.

    ScriptedPolicy   the DEFAULT. A deterministic planner that drives the buy
                     funnel: products -> product page -> add to cart -> checkout
                     -> place order -> (if asked for a code) read it and confirm.
                     No LLM, no network, no API key, reproducible every run.
    OllamaPolicy     optional. Sends the snapshot to a local open model through
                     Ollama's HTTP API (OLLAMA_URL, OLLAMA_MODEL) and parses a
                     JSON action back. This is exactly the loop a real LLM agent
                     runs; it is off by default so the lab needs no model.

Actions: {"action": "goto", "path": …} | {"click", "selector"|"index"} |
         {"fill", "selector", "text"} | {"read_code"} | {"done", "note"}.

The point of a deterministic default: the DEFENCES are what students study, and
they must behave identically on every machine. Swapping in OllamaPolicy changes
how the agent *thinks*, not how the store *scores* it — the tells are in the
hands and the headers, not the planner.
"""

import json
import os
import sys

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))  # lab root: labnet.py
from labnet import require_local  # noqa: E402

from . import observe

CART_PATH = "/products"


class ScriptedPolicy:
    """A fixed buy-funnel planner. Deterministic stand-in for an LLM."""

    def __init__(self, sku):
        self.sku = sku

    def decide(self, goal, snap, memory):
        path = snap["url"].split(snap["url"].split("/")[2], 1)[-1] if "//" in snap["url"] else snap["url"]
        last = snap.get("last_result", {})
        if last.get("outcome") == "allow" and "order confirmed" in last.get("text", "").lower():
            return {"action": "done", "note": "order confirmed"}

        if memory.get("await_code"):
            return {"action": "read_code"}
        if "/checkout" in path:
            if observe.find(snap, name="confirmation code") and memory.get("code"):
                field = observe.find(snap, name="confirmation code")
                if not memory.get("code_filled"):
                    memory["code_filled"] = True
                    return {"action": "fill", "selector": field["selector"], "text": memory["code"]}
                return {"action": "click", "selector": "#confirm-submit"}
            mandate = observe.find(snap, name="mandate")
            if mandate and memory.get("mandate") and not memory.get("mandate_filled"):
                memory["mandate_filled"] = True
                return {"action": "fill", "selector": mandate["selector"], "text": memory["mandate"]}
            if observe.find(snap, selector="place-order"):
                return {"action": "click", "selector": "#place-order"}
            if observe.find(snap, name="log in"):
                return {"action": "goto", "path": "/login"}
        if "/product/" in path and observe.find(snap, selector="add-to-cart"):
            return {"action": "click", "selector": "#add-to-cart"}
        if "/cart" in path and observe.find(snap, name="checkout"):
            return {"action": "goto", "path": "/checkout"}
        if path in ("/products", "/", CART_PATH):
            return {"action": "goto", "path": f"/product/{self.sku}"}
        return {"action": "goto", "path": f"/product/{self.sku}"}


SYSTEM_PROMPT = """You control a web browser to buy a product. You are given the current page's
elements and visible text. Reply with ONE JSON action and nothing else:
{"action":"goto","path":"/checkout"} | {"action":"click","selector":"#id"} |
{"action":"fill","selector":"#id","text":"..."} | {"action":"read_code"} | {"action":"done","note":"..."}"""


class OllamaPolicy:
    """Optional: a local open model via Ollama. Same interface as ScriptedPolicy."""

    def __init__(self, sku, url=None, model=None):
        self.sku = sku
        # The model server must be on this machine too: no prompts leave the laptop.
        self.url = require_local((url or os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")).rstrip("/"), what="OLLAMA_URL")
        self.model = model or os.environ.get("OLLAMA_MODEL", "llama3")

    def decide(self, goal, snap, memory):
        if memory.get("await_code"):
            return {"action": "read_code"}
        payload = {"model": self.model, "stream": False, "format": "json",
                   "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                {"role": "user", "content": f"Goal: {goal}\nSKU: {self.sku}\n"
                                 f"Page: {json.dumps({k: snap[k] for k in ('url', 'title', 'elements', 'last_result') if k in snap})}"}]}
        r = requests.post(f"{self.url}/api/chat", json=payload, timeout=120)
        try:
            return json.loads(r.json()["message"]["content"])
        except (KeyError, ValueError):
            return {"action": "done", "note": "could not parse model output"}


def make_policy(sku):
    if os.environ.get("AGENT_POLICY", "scripted").lower() == "ollama":
        return OllamaPolicy(sku)
    return ScriptedPolicy(sku)
