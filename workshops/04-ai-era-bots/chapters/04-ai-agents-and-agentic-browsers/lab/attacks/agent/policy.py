"""
The agent's "brain": given a snapshot and a goal, pick the next action.

Two policies, same interface: decide(goal, snapshot, memory) -> action dict.

    ScriptedPolicy   the DEFAULT. A deterministic planner that drives the buy funnel:
                     the drop page -> (mandate field) -> Buy -> (if asked for a code) read it and
                     confirm -> Buy again. No LLM, no network, no API key, reproducible every run.
    OllamaPolicy     optional. Sends the snapshot to a local open model through Ollama's HTTP API
                     (OLLAMA_URL, OLLAMA_MODEL) and parses a JSON action back. This is exactly the
                     loop a real LLM agent runs; it is off by default so the lab needs no model.

Actions: {"action": "goto", "path": ...} | {"click", "selector"} | {"fill", "selector", "text"} |
         {"read_code"} | {"done", "note"}.

The point of a deterministic default: the DEFENSES are what you study, and they must behave
identically on every machine. Swapping in OllamaPolicy changes how the agent *thinks*, not how the
store *scores* it: the tells are in the hands and the headers, not the planner.

A well-behaved agent stops when the store refuses it. So does this one: a refusal ends the session.
"""

import json
import os
import sys
from urllib.parse import urlparse

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))  # lab root: labnet.py
from labnet import require_local  # noqa: E402

MAX_BUYS = 3        # presses of Buy in one session: the first, and one after each answered step-up


class ScriptedPolicy:
    """A fixed buy-funnel planner. Deterministic stand-in for an LLM."""

    def __init__(self, sku):
        self.sku = sku

    def decide(self, goal, snap, memory):
        path = urlparse(snap["url"]).path
        last = snap.get("last_result", {})
        if last.get("outcome") == "allow":
            return {"action": "done", "note": "order confirmed"}
        if last.get("outcome") in ("block", "deny"):
            return {"action": "done", "note": "refused: " + last.get("text", "")[:80]}

        if snap.get("challenge"):
            if memory.get("await_code") or not memory.get("code"):
                memory["await_code"] = True
                return {"action": "read_code"}
            if not memory.get("code_filled"):
                memory["code_filled"] = True
                return {"action": "fill", "selector": "#stepup-form input[name=code]", "text": memory["code"]}
            memory["code"], memory["code_filled"] = None, False        # spent: the page returns to the drop
            return {"action": "click", "selector": "#stepup-submit"}

        if path == f"/drop/{self.sku}":
            if memory.get("mandate") and not memory.get("mandate_filled") and \
                    any(e["selector"] == "input[name=mandate]" for e in snap["elements"]):
                memory["mandate_filled"] = True
                return {"action": "fill", "selector": "form.buy input[name=mandate]", "text": memory["mandate"]}
            memory["buys"] = memory.get("buys", 0) + 1
            if memory["buys"] > MAX_BUYS:
                return {"action": "done", "note": "gave up"}
            return {"action": "click", "selector": "#drop-buy"}
        return {"action": "goto", "path": f"/drop/{self.sku}"}


SYSTEM_PROMPT = """You control a web browser to buy a product. You are given the current page's
elements and visible text. Reply with ONE JSON action and nothing else:
{"action":"goto","path":"/drop/lab-runner-9"} | {"action":"click","selector":"#id"} |
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
