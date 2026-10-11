// Capstone L7 — runtime fetch/sendBeacon monitor (W3 Ch5)
//
// Wraps the two APIs a skimmer uses to exfiltrate, and reports any call to an
// origin that is not our own. This is DETECTION, not enforcement: a script that
// loads before this one can capture the originals, and CSP connect-src is what
// actually blocks the request. We load it first (before analytics-helper.js) so
// it sees the skimmer's calls, and send reports to the same sink CSP uses.
(function () {
  "use strict";
  var SELF = location.origin;
  function report(url, via) {
    try {
      var sameOrigin = new URL(url, SELF).origin === SELF;
      if (sameOrigin) return;
      // Use the original sendBeacon if we still can; fall back to an Image ping.
      var body = JSON.stringify({ "blocked-uri": url, via: via, ts: Date.now() });
      navigator.__sendBeacon
        ? navigator.__sendBeacon("/api/script-violation", body)
        : fetch("/api/script-violation", { method: "POST", body: body, keepalive: true });
    } catch (e) { /* never break the page over telemetry */ }
  }
  var _fetch = window.fetch;
  window.fetch = function (input) {
    var url = typeof input === "string" ? input : (input && input.url);
    if (url) report(url, "fetch");
    return _fetch.apply(this, arguments);
  };
  if (navigator.sendBeacon) {
    navigator.__sendBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      report(url, "sendBeacon");
      return navigator.__sendBeacon(url, data);
    };
  }
})();
