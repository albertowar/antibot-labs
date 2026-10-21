"""
W4 Ch4 — L2 agent behavior: how a session acts, scored to CHALLENGE, never to block (Round 2)

W2 Ch5 taught pointer kinematics against humanized bots. Agents are a
different animal: they don't fake a hand, they *don't have one*. A DOM- or
accessibility-tree-driven agent (browser-use, Playwright MCP, Chrome DevTools
MCP, Claude in Chrome) resolves an element and acts on it. Five tells, all
from the in-page collector plus the server's own flow log:

    teleport clicks        pointer click (detail >= 1) with no pointer path before it   +20
    paste-like fills       a field's value changed with no keydowns (fill(), autofill)   +15
    metronome cadence      page-to-page gaps with CV < 0.20 (fixed "think time")        +15
    programmatic scrolls   scroll events with no wheel / key before them (scrollIntoView) +10
    tooling overlay        an injected fixed, pointer-events:none, max-z overlay node    +30
                                                                        cap: 59 (challenge)

Who else looks like this (the false positives you must price in):
    screen-reader / switch / voice-control users   clicks via the accessibility tree: detail 0,
                                                   no pointer path -> EXEMPT (keyboard-activated)
    password managers and browser autofill          paste-like fills (+15 alone stays under 30)
    corporate RPA / macro users                     teleport + fill = 35 -> challenged. Real cost.
    a human's own agentic browser                   looks exactly like an agent, because it is one

That is why this layer caps at 59: it may ask a human to confirm; it may not
decide on its own. Round 4 turns the challenge into a hand-off (emailed code).
FP-Agent (Wang, Shafiq & Vekaria, 2026) found behavior separates agents from
humans far better than browser fingerprints do, and this module is why: the
fingerprint is the user's real Chrome.
"""

import statistics

CHALLENGE_MAX = 59
TELEPORT_WINDOW_MS = 400
MIN_MOVES_FOR_A_PATH = 3
CADENCE_MIN_GAPS = 3
CADENCE_CV = 0.20


def _teleport(click, moves, touches):
    t, _, _, detail, _ = click[:5]
    if detail == 0 or touches:
        return False  # keyboard-activated (Enter/Space, AT "doDefault") or a tap
    before = [m for m in moves if t - TELEPORT_WINDOW_MS <= m[0] <= t]
    return len(before) < MIN_MOVES_FOR_A_PATH


def features(sess):
    """One feature dict per session, across every page it sent telemetry for."""
    pages = sess.get("pages") or {}
    f = {"pages": len(pages), "pointer_clicks": 0, "teleport_clicks": 0, "keyboard_clicks": 0,
         "fills_without_keys": 0, "typed_fields": 0, "programmatic_scrolls": 0, "wheel_scrolls": 0,
         "overlays": 0, "untrusted": 0, "first_action_ms": None, "flow_gaps_cv": None}
    first = []
    for ev in pages.values():
        moves, touches = ev.get("moves", []), ev.get("touches", [])
        for c in ev.get("clicks", []):
            if len(c) < 5:
                continue
            if c[3] == 0:
                f["keyboard_clicks"] += 1
            else:
                f["pointer_clicks"] += 1
                f["teleport_clicks"] += _teleport(c, moves, touches)
        for inp in ev.get("inputs", []):          # [t, field, chars_inserted, keydowns_since_last]
            if len(inp) >= 4 and inp[2] >= 3 and inp[3] == 0:
                f["fills_without_keys"] += 1
            elif len(inp) >= 4 and inp[3] > 0:
                f["typed_fields"] += 1
        for s in ev.get("scroll_events", []):     # [t, programmatic(0/1)]
            f["programmatic_scrolls" if s[1] else "wheel_scrolls"] += 1
        f["overlays"] += len(ev.get("overlays", []))
        f["untrusted"] += ev.get("untrusted", 0)
        ts = [c[0] for c in ev.get("clicks", [])] + [i[0] for i in ev.get("inputs", [])]
        if ts:
            first.append(min(ts))
    if first:
        f["first_action_ms"] = min(first)
    # Server-measured cadence: gaps between consecutive page views in the flow log.
    times = [t for t, _ in sess.get("flow", [])]
    gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
    if len(gaps) >= CADENCE_MIN_GAPS:
        mean = statistics.fmean(gaps)
        f["flow_gaps_cv"] = round(statistics.pstdev(gaps) / mean, 3) if mean else None
    return f


def score(sess):
    f = features(sess)
    if not sess.get("pages"):
        return 0, []  # no telemetry at all is W2's L0 problem, not ours
    points, reasons = 0, []
    if f["pointer_clicks"] and f["teleport_clicks"] / f["pointer_clicks"] >= 0.5:
        points += 20
        reasons.append(f"{f['teleport_clicks']}/{f['pointer_clicks']} pointer clicks with no pointer path (teleport)")
    if f["fills_without_keys"]:
        points += 15
        reasons.append(f"{f['fills_without_keys']} field(s) filled with no keystrokes (fill()/autofill)")
    if f["flow_gaps_cv"] is not None and f["flow_gaps_cv"] < CADENCE_CV:
        points += 15
        reasons.append(f"Metronome cadence between pages (CV {f['flow_gaps_cv']:.2f})")
    if f["programmatic_scrolls"] and not f["wheel_scrolls"]:
        points += 10
        reasons.append(f"{f['programmatic_scrolls']} programmatic scroll(s), no wheel or key scroll")
    if f["overlays"]:
        points += 30
        reasons.append(f"{f['overlays']} injected overlay node(s): agent tooling highlights")
    return min(points, CHALLENGE_MAX), reasons


if __name__ == '__main__':
    agent = {"flow": [[0, "/"], [1210, "/products"], [2405, "/product/lab-runner-9"], [3620, "/checkout"]],
             "pages": {"/checkout": {"moves": [[1200, 300, 400]], "clicks": [[1201, 300, 400, 1, "place-order"]],
                                     "inputs": [[900, "code", 6, 0]], "scroll_events": [[1190, 1]],
                                     "overlays": [{"id": "lab-agent-highlights"}], "untrusted": 0, "touches": []}}}
    print(score(agent))
    reader = {"flow": [[0, "/"], [4300, "/products"], [9100, "/checkout"], [10900, "/checkout"]],
              "pages": {"/checkout": {"moves": [], "clicks": [[3000, 0, 0, 0, "place-order"]], "inputs": [[900, "code", 6, 6]],
                                      "scroll_events": [], "overlays": [], "untrusted": 0, "touches": []}}}
    print(score(reader))
