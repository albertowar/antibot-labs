// Progressive enhancement: the two promo forms work without JavaScript (plain POSTs).
// With JS we post them in the background and show the voucher inline.
(function () {
  function wire(form, done) {
    if (!form) return;
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      fetch(form.action, { method: "POST", body: new FormData(form),
                           headers: { "Accept": "application/json" } })
        .then(function (r) { return r.json().then(function (b) { return { ok: r.ok, body: b }; }); })
        .then(done)
        .catch(function () { form.submit(); });
    });
  }
  var status = document.createElement("p");
  status.className = "muted";
  var unlock = document.getElementById("promo-unlock");
  if (unlock) unlock.appendChild(status);
  wire(unlock, function (res) {
    status.textContent = res.ok ? "Unlocked. Redeem your voucher below." : (res.body.error || {}).message || "Try again.";
  });
  wire(document.getElementById("promo-redeem"), function (res) {
    status.textContent = res.ok ? "Voucher: " + res.body.voucher : (res.body.error || {}).message || "Locked.";
  });
})();
