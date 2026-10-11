// Third-party "analytics helper" — the benign version.
//
// On a real site this file is served from a vendor/CDN and loaded with trust.
// That trust is the supply-chain risk: whoever controls this file controls a
// script running on every page. attacks/round3_skimmer.py rewrites this file to
// append a skimmer (see static/skimmer.js) and shows what CSP + SRI do about it.
(function () {
  "use strict";
  // A harmless pageview ping to our own origin (allowed by connect-src 'self').
  try {
    window.__analytics = { loaded: true, page: location.pathname };
  } catch (e) {}
})();
