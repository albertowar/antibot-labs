"""
Round 4 (level 4): watch what the page's own code does with the network.

CSP and SRI judge where code comes from. A poisoned dependency that is bundled into your own
first-party file comes from your own origin: SRI matches your own build, the nonce is on the tag, and
the beacon goes to the one analytics origin connect-src has to allow. Neither control fires.

demo_site/static/js/runtime-monitor.js loads before everything else, wraps fetch, XMLHttpRequest and
navigator.sendBeacon, and for a call to an origin that is not the store's own it (a) reports it to
POST /api/telemetry {"kind": "script_violation"} and (b) refuses the sendBeacon. It is a detection
layer with a blocking lever, not a wall:
  - a script that runs before it can keep the originals (so it must be first, which the head slot
    guarantees);
  - Image().src and form posts are not wrapped;
  - it ships in the page, so the attacker can read it.
Its value is that the attacker has to know about it; most skimmers do not look.

False-positive profile: a legitimate third-party call (a payment iframe's own traffic is outside it,
but your analytics SDK's is not) looks the same as a skim, so the monitor needs an allowlist, and the
allowlist needs an owner. Cost to run: a few hundred bytes of JS per page and a report stream.
"""

from .pipeline import Check


def _check(page):
    page.monitor = True


CHECK = Check("runtime_monitor", _check, phases=("page",))
