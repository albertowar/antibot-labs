/* Progressive enhancement only. Every form on the site works with this file blocked.
   Chapters add their own scripts (collectors, challenge solvers) as separate files via slots. */
(function () {
  "use strict";
  var $ = function (sel, root) { return (root || document).querySelector(sel); };

  // Drop countdowns
  document.querySelectorAll("[data-drop-at]").forEach(function (el) {
    var at = Date.parse(el.getAttribute("data-drop-at"));
    function tick() {
      var left = at - Date.now();
      if (left <= 0) { el.textContent = "Live now"; location.reload(); return; }
      var s = Math.floor(left / 1000), h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
      el.textContent = "Opens in " + (h ? h + "h " : "") + m + "m " + String(sec).padStart(2, "0") + "s";
      setTimeout(tick, 1000);
    }
    tick();
  });

  // Add to cart without leaving the product page
  var buy = $("form.buy[action='/cart/add']");
  if (buy && window.fetch) {
    buy.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var fd = new FormData(buy);
      fetch("/api/cart/add", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sku: fd.get("sku"), size: fd.get("size") || "", qty: Number(fd.get("qty") || 1) }) })
        .then(function (r) { return r.json(); })
        .then(function (j) {
          if (j && j.ok) { var c = $("#cart-count"); if (c) c.textContent = j.count; flash("Added to cart.", "ok"); }
          else { buy.submit(); }
        }).catch(function () { buy.submit(); });
    });
  }

  // Gift card redeem link on the gift-card page
  var redeem = $("[data-redeem]");
  if (redeem) redeem.addEventListener("click", function (ev) {
    ev.preventDefault();
    fetch("/api/gift-cards/redeem", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: redeem.getAttribute("data-redeem") }) })
      .then(function (r) { return r.json(); })
      .then(function (j) { flash(j.ok ? "Redeemed. You now have " + j.loyalty_points + " points." : (j.error && j.error.message) || "Could not redeem.", j.ok ? "ok" : "warn"); });
  });

  // Password reset request from the login page (lands in /lab/mailbox/<email> in the lab)
  var reset = $("[data-reset]");
  if (reset) reset.addEventListener("click", function (ev) {
    ev.preventDefault();
    var email = $("input[name=email]") ? $("input[name=email]").value : "";
    if (!email) { flash("Enter your email first.", "warn"); return; }
    fetch("/api/password-reset", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: email }) })
      .then(function (r) { return r.json(); }).then(function (j) { flash(j.message || "Sent.", "ok"); });
  });

  function flash(msg, kind) {
    var main = $("#main"); if (!main) return;
    var old = $(".flash", main); if (old) old.remove();
    var el = document.createElement("div"); el.className = "flash " + (kind || "info"); el.setAttribute("role", "status"); el.textContent = msg;
    main.insertBefore(el, main.firstChild);
  }

  // A challenge interstitial that interrupted a form POST carries the form along
  // (#challenge-replay). A chapter's solver calls this after a successful solve to
  // resubmit it; without JavaScript the same form is a visible Continue button.
  window.labReplay = function () {
    var f = document.getElementById("challenge-replay");
    if (f) f.submit();
    return !!f;
  };
})();
