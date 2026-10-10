/*
 * analytics-helper.js — third-party analytics include (KNOWN-GOOD baseline).
 *
 * This is the benign file the vendor originally shipped and the one your SRI
 * hash is pinned to. generate_sri.py hashes THIS file. If the served file ever
 * differs from this baseline, an SRI check refuses it. Keep this file byte-for-
 * byte identical to the good release.
 */
(function () {
  "use strict";
  // Harmless page-view ping to the vendor's own (same-origin, in this lab) path.
  try {
    var img = new Image();
    img.src = "/static/vendor/pixel.gif?p=" + encodeURIComponent(location.pathname);
  } catch (_) {}
})();
