"""
Scoreboard: bots stopped next to shoppers hurt, from the store's decision log.

    python tools/scoreboard.py              # table
    python tools/scoreboard.py --markdown   # paste into a README expected-results table
"""

import argparse
import json

from labclient import scoreboard


def rows(board):
    out = []
    for a in board["actors"]:
        if a["kind"] not in ("human", "bot"):
            continue
        out.append({"actor": a["actor"], "requests": a["requests"], "served": a["served"] + a["purchased"],
                    "purchased": a["purchased"], "stopped": a["stopped"], "avg_score": a["avg_score"], "avg_ms": a["avg_ms"]})
    return out


def render(board, markdown=False):
    s = board["summary"]
    head = ["actor", "requests", "served", "purchased", "stopped", "avg score", "gate ms"]
    lines = []
    if markdown:
        lines.append("| " + " | ".join(head) + " |")
        lines.append("|" + "---|" * len(head))
        for r in rows(board):
            lines.append(f"| {r['actor']} | {r['requests']} | {r['served']} | {r['purchased']} | {r['stopped']} | {r['avg_score']} | {r['avg_ms']} |")
        lines.append("")
        lines.append(f"Bots stopped: **{s['bots_stopped']}/{s['bot_requests']}** requests · shoppers hurt: **{s['humans_hurt']}/{s['humans']}** people "
                     f"({s['human_requests_stopped']}/{s['human_requests']} requests stopped, including challenges they then solved) · "
                     f"purchases: {s['purchases']} · drop stock left: {s['drops']}")
    else:
        lines.append(f"{'actor':<28}{'req':>6}{'served':>8}{'bought':>8}{'stopped':>9}{'score':>7}{'ms':>8}")
        for r in rows(board):
            lines.append(f"{r['actor']:<28}{r['requests']:>6}{r['served']:>8}{r['purchased']:>8}{r['stopped']:>9}{r['avg_score']:>7}{r['avg_ms']:>8}")
        lines.append("")
        lines.append(f"bots stopped {s['bots_stopped']}/{s['bot_requests']} requests   shoppers hurt {s['humans_hurt']}/{s['humans']} people "
                     f"({s['human_requests_stopped']}/{s['human_requests']} requests stopped)   "
                     f"purchases {s['purchases']}   drop stock {s['drops']}")
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--markdown", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--since", default=None)
    args = ap.parse_args()
    board = scoreboard(args.since)
    print(json.dumps(board, indent=1) if args.json else render(board, args.markdown))
