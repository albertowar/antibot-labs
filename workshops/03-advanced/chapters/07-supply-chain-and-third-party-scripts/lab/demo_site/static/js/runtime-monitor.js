/*
 * runtime-monitor.js: DEFENSE (Round 4, level 4).
 *
 * Defence in depth for the case CSP and SRI cannot see: malicious code that runs
 * from your OWN origin (a poisoned first-party bundle). It wraps the three network
 * sinks a skimmer uses and, for a call to an origin that is not on the allowlist,
 * reports it (POST /api/telemetry, kind "script_violation") and, for sendBeacon,
 * refuses it.
 *
 * A detection layer with a blocking lever, not a wall. It must be the first script
 * on the page, before any other include, or a script that runs earlier can grab the
 * original functions first. CSP remains the real enforcement layer.
 *
 * XMLHttpRequest is patched on the PROTOTYPE, so every instance is seen.
 * Not wrapped: Image().src, form posts, WebSocket, navigation.
 */
(function () {
  "use strict";

  var ALLOWED = new Set([location.origin]);
  var REPORT = "/api/telemetry";

  // Capture the originals up front so our own report cannot be re-wrapped.
  var realFetch = window.fetch ? window.fetch.bind(window) : null;

  function isAllowed(url) {
    try { return ALLOWED.has(new URL(url, location.href).origin); }
    catch (_) { return true; } // un-parseable / relative: treat as same-origin
  }

  function report(method, url) {
    if (!realFetch) return;
    realFetch(REPORT, {
      method: "POST", headers: { "Content-Type": "application/json" }, keepalive: true,
      body: JSON.stringify({ kind: "script_violation", method: method, url: String(url), page: location.href })
    }).catch(function () {});
  }

  if (window.fetch) {
    window.fetch = function (input, init) {
      var url = (typeof input === "string") ? input : (input && input.url);
      if (!isAllowed(url)) report("fetch", url);
      return realFetch(input, init);
    };
  }

  var realOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    if (!isAllowed(url)) report("xhr", url);
    return realOpen.apply(this, arguments);
  };

  if (navigator.sendBeacon) {
    var realBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      if (!isAllowed(url)) {
        report("sendBeacon", url);
        return false; // BLOCK: sendBeacon returns false on failure
      }
      return realBeacon(url, data);
    };
  }
})();
