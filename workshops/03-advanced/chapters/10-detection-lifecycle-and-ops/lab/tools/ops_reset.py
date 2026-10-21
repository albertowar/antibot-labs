"""
Back to the start of the chapter: the store's counters, log and orders (POST /lab/reset) and the
operator's state (POST /lab/ops/reset): overrides, corpus refresh, analyst labels and models.

    python tools/ops_reset.py

The checkpoint does this for you before it rebuilds a round's history.
"""

import labclient


def reset():
    labclient.reset()
    return labclient.admin("POST", "/lab/ops/reset")


if __name__ == "__main__":
    labclient.wait_for_store()
    print("reset:", reset())
