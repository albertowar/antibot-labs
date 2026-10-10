"""Render the round scoreboard: attacker success next to the cost to real users.

The one rule of this lab is that a defense is measured on both sides. This module
turns a round's attack results, the legitimate-traffic summary, and the server's
event log into a single table so you can see, in one place, how many accounts the
attacker took and how many real users paid for it.
"""

from __future__ import annotations

import os
import statistics
import sys

import httpx

sys.path.insert(0, os.path.dirname(__file__))
from _paths import BASE_URL  # noqa: E402


def login_latency(since: float) -> dict:
    """Median and p95 login latency (defender cost) from the event log."""
    try:
        events = httpx.get(f"{BASE_URL}/lab/events", params={"since": since}, timeout=10).json()
    except httpx.RequestError:
        return {"p50": 0.0, "p95": 0.0, "n": 0}
    lat = [e["latency_ms"] for e in events if e["endpoint"] == "login" and e["latency_ms"] > 0]
    if not lat:
        return {"p50": 0.0, "p95": 0.0, "n": 0}
    lat.sort()
    p95 = lat[min(len(lat) - 1, int(len(lat) * 0.95))]
    return {"p50": statistics.median(lat), "p95": p95, "n": len(lat)}


def render(round_no: int, level: int, attacks: list[dict], legit: dict, latency: dict) -> str:
    lines = []
    lines.append(f"=== Scoreboard: Round {round_no} (DEFENSE_LEVEL={level}) ===\n")
    lines.append("Attacker")
    for a in attacks:
        if a["attack"].endswith("round4"):
            lines.append(f"  {a['attack']:<16} {a.get('accounts_read', 0)}/{a['attempts']} "
                         f"accounts read, {a.get('sensitive_actions', 0)} sensitive actions")
        else:
            extra = f" (pruned to {a['pruned_to']})" if "pruned_to" in a else ""
            lines.append(f"  {a['attack']:<16} {a['accounts_taken_over']}/{a['attempts']} "
                         f"accounts taken over{extra}")
    lines.append("")
    lines.append("Legitimate users")
    lines.append(f"  logged in            {legit['logged_in']}/{legit['total']}")
    lines.append(f"  wrongly blocked      {legit['blocked_false_positive']} "
                 f"(false positives)")
    lines.append(f"  extra step (step-up) {legit['friction_stepup']}")
    lines.append(f"  typos rejected       {legit['typo_rejected']} (correct, not a false positive)")
    lines.append("")
    lines.append(f"Defender cost")
    lines.append(f"  login latency: median {latency['p50']:.2f} ms, p95 {latency['p95']:.2f} ms "
                 f"({latency['n']} logins)")
    return "\n".join(lines)
