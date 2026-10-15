"""
PageControls: what the store decides about one HTML response, before it is sent.

This chapter's defenses are not verdicts on a request (allow / block); they are things the page
carries to the browser: a Content-Security-Policy header, an integrity hash on a <script> tag, a
monitor script that loads first. So a check here runs in its own phase, "page", with a PageControls
as its argument instead of a Ctx, and a check turns its control on by setting a field:

    def _check(page):
        page.csp = "default-src 'self'"

The ladder decides which checks are on at which DEFENSE_LEVEL, exactly as in every other lab:
level k is on when k <= DEFENSE_LEVEL, and a higher level's check runs after (and may replace) a
lower one's. demo_site/ext/supply.py builds one PageControls per HTML response, runs the "page"
phase over the ladder, then turns the result into response headers and template variables.

A check that fails is skipped (the engine catches it), so a typo in a policy string never takes the
store down. It also means a broken control is silent: read the headers (`tools/slice_check.py`).
"""

from dataclasses import dataclass, field


@dataclass
class PageControls:
    nonce: str                      # fresh per response; only used if a check demands nonces
    analytics_origin: str           # the one third-party origin the business needs (see csp_policies.strict)
    report_only: bool = False       # send the CSP as Report-Only (the lab flips this for Round 2's first step)
    level: int = 0                  # set by the engine
    phase: str = "page"             # set by the engine
    csp: str = ""                   # the Content-Security-Policy value ("" = no header)
    nonce_scripts: bool = False     # put the nonce on every <script> the store renders
    sri: str = ""                   # integrity value for the vendor <script> ("" = no integrity attribute)
    monitor: bool = False           # load runtime-monitor.js first
    inventory: bool = False         # the store's payment-page scripts are inventoried (Round 1)
    notes: list = field(default_factory=list)

    def describe(self):
        """One line for /lab/supply/status and the checkpoint's wire check."""
        kind = "none" if not self.csp else ("report-only" if self.report_only else "enforce")
        policy = "strict" if "strict-dynamic" in self.csp else ("allowlist" if self.csp else "none")
        return {"csp": kind, "policy": policy, "nonce": self.nonce_scripts, "sri": bool(self.sri),
                "monitor": self.monitor, "inventory": self.inventory}
