/*
 * shop-bundle.js: the store's FIRST-PARTY page bundle for the slice (your own build).
 *
 * Legitimate behaviour: stop a double click on the pay / sign-in button from
 * posting the form twice. The poisoned build of this file is shop-bundle.poisoned.js.
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
})();
