"""
Chapter 3, Round 0: recon. What does the collector actually see? (Section 3.2)

Runs the laziest possible scalper once (page.fill + page.click, as in
Round 1), then puts its telemetry next to a human's: your newest recorded
trace if you saved one (tools/save_trace.py), else the shipped corpus.

    python attacks/round0_recon.py

Then open both /lab/behavior/view/<sid> links it prints and compare the pictures.
"""

import glob
import json
import os
import statistics
import sys

import requests

from _common import BASE_URL, finish
import round1_click_fill

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from defenses.behavior_features import extract   # noqa: E402

TRACES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools", "traces")


def human_trace():
    mine = [p for p in glob.glob(os.path.join(TRACES, "*.json"))
            if json.load(open(p)).get("source") == "browser"]
    path = max(mine, key=os.path.getmtime) if mine else os.path.join(TRACES, "corpus_01.json")
    return json.load(open(path)), os.path.relpath(path)


def summary(telemetry, layout):
    f = extract(telemetry, layout)
    k = f["keys"]
    ends = [a["end_ratio"] for a in f["approaches"] if a.get("end_ratio") is not None]
    return {
        "pointer samples": len(telemetry.get("pointer", [])),
        "mouse approaches": len(f["approaches"]),
        "straightness (mean)": f["mouse_movement_straightness"],
        "end ratio (median)": statistics.median(ends) if ends else None,
        "keystrokes": k["n_keys"],
        "dwell mean (ms)": k["dwell_mean"],
        "inter-key CV": k["iki_cv"],
        "text without keys": ", ".join(f["fills"]["injected_fields"]) or "-",
        "first click (ms)": round(f["time_to_first_click_ms"]) if f["time_to_first_click_ms"] else None,
        "submitted after (ms)": round(f["submit_ms"] or 0),
        "payload (KB)": round(len(json.dumps(telemetry)) / 1024, 1),
    }


if __name__ == "__main__":
    bot = round1_click_fill.run()
    bot_trace = requests.get(f"{BASE_URL}/lab/behavior/trace/latest", timeout=5).json()
    human, source = human_trace()
    b = summary(bot_trace["telemetry"], bot_trace["layout"])
    h = summary(human["telemetry"], human["layout"])
    print(f"=== Round 0: bot vs human ({source}) ===\n")
    print(f"  {'':<22} {'bot':>14} {'human':>14}")
    for key in b:
        print(f"  {key:<22} {str(b[key]):>14} {str(h[key]):>14}")
    print(f"\n  bot trace:   {BASE_URL}/lab/behavior/view/{bot_trace['sid']}")
    if human.get("source") == "browser":
        print(f"  your trace:  {BASE_URL}/lab/behavior/view/{human['sid']}")
    else:
        print("  no recording of yours yet: reserve a pair in your browser, then")
        print("  python tools/save_trace.py --name <you>")
    finish("round0_recon", bot)
