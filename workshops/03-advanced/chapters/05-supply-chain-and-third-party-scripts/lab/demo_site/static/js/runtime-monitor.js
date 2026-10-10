/*
 * runtime-monitor.js — DEFENSE (Round 4).
 *
 * Defence in depth for the case CSP and SRI cannot see: malicious code that
 * runs from your OWN origin (a poisoned first-party bundle). It wraps the three
 * network sinks a skimmer uses and reports — or blocks — any call to an origin
 * that is not on the allowlist.
 *
 * This is a DETECTION layer, not a wall. It must be the first script on the
 * page, before any third-party include, or a script that runs earlier can grab
 * the original functions first. CSP remains the real enforcement layer.
 *
 * Fix vs. the naive version: XHR is patched on the PROTOTYPE, so calls made
 * through XMLHttpRequest.prototype.open (not just via a wrapped constructor)
 * are still seen.
 */
(function () {
  "use strict";

  var ALLOWED = new Set([location.origin]);
  var REPORT = "/api/script-violation";

  // Capture originals up front so our own report call cannot be re-wrapped.
  var realFetch = window.fetch ? window.fetch.bind(window) : null;

  function sameOrigin(url) {
    try { return new URL(url, location.href).origin === location.origin; }
    catch (_) { return true; } // un-parseable / relative -> treat as same-origin
  }

  function isAllowed(url) {
    try { return ALLOWED.has(new URL(url, location.href).origin); }
    catch (_) { return true; }
  }

  function report(method, url) {
    var body = JSON.stringify({ method: method, url: String(url), page: location.href });
    // Use the captured original fetch so a later wrap cannot hide the report.
    if (realFetch) {
      realFetch(REPORT, { method: "POST", headers: { "Content-Type": "application/json" },
        body: body, keepalive: true }).catch(function () {});
    }
  }

  // ── fetch ──
  if (window.fetch) {
    window.fetch = function (input, init) {
      var url = (typeof input === "string") ? input : (input && input.url);
      if (!isAllowed(url)) report("fetch", url);
      return realFetch(input, init);
    };
  }

  // ── XMLHttpRequest (patched on the prototype) ──
  var realOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    if (!isAllowed(url)) report("xhr", url);
    return realOpen.apply(this, arguments);
  };

  // ── navigator.sendBeacon (the skimmer's favourite — fires on unload) ──
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
