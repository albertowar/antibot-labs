/*
 * analytics-helper.js 2.3.0: third-party analytics include (KNOWN-GOOD baseline).
 *
 * The benign file the vendor shipped, and the one the SRI hash is pinned to
 * (defenses/generate_sri.py hashes THIS file). If the served file ever differs
 * from it, a browser enforcing the pin refuses to run it. Keep it byte-for-byte
 * identical to the good release.
 */
(function () {
  "use strict";
  window.AnalyticsHelper = { version: "2.3.0" };
  // Harmless page-view ping to the vendor's path (same origin in this lab).
  try {
    var img = new Image();
    img.src = "/static/vendor/pixel.gif?p=" + encodeURIComponent(location.pathname);
  } catch (_) {}
})();
