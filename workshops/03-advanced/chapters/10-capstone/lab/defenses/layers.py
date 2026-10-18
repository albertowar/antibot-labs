"""
Which layer (L0 to L7) a signal belongs to: the vocabulary of the post-incident report.

A Signal's `layer` is the name of the check that produced it. The chapter talks about layers: L0 request, TLS and
sensor gate, L1 fingerprint coherence, L2 behavior and flow, L3 the session model, L4 the login token and cluster,
then the Workshop 3 layers L5 API, L6 streaming and L7 supply chain. This table maps one to the other, so the
signal-health tool, the /metrics endpoint and the kill chain printed by attacks/round4_integrated.py all speak in
layers. A check that is missing from the table is reported as "L?": add it here.

Levels are not layers. The store's level 0 is the bare store (the contract), so the Workshop 2 stack is spread over
levels 1 to 4 (levels 3 and 4 hold two layers each), and from level 5 the layer number and the level agree.
"""

LAYER_OF = {
    "ua_inspector": "L0", "header_inspector": "L0", "client_hints": "L0", "header_order": "L0", "ja4_denylist": "L0",
    "tls_family": "L0", "sensor_gate": "L0", "automation_artifacts": "L0", "login_throttle": "L0",
    "ua": "L0", "headers": "L0", "rate_limit": "L0",        # signal layers of the Chapter 1 and 6 header and throttle checks
    "consistency": "L1", "lie_detection": "L1",
    "behavior_l1": "L2", "behavior_l2": "L2", "flow": "L2",
    "session_model": "L3",
    "token_binding": "L4", "login_risk": "L4",
    "api_hardening": "L5",
    "streaming": "L6",
    "supply_chain": "L7",
}
LAYERS = ["L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7"]
LAYER_NAME = {"L0": "request/TLS/sensor", "L1": "fingerprint", "L2": "behavior/flow", "L3": "session model",
              "L4": "login/token", "L5": "API hardening", "L6": "streaming", "L7": "supply chain"}


def layer_of(flag):
    """'api_hardening:query_cost' -> 'L5'."""
    return LAYER_OF.get(flag.split(":")[0], "L?")
