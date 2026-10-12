/* Chapter 5: the page side of the `captcha` challenge.
   - Captcha.mount(box, payload, onSolved): draws the image, takes the answer, posts it to
     POST /api/challenge/verify and calls onSolved() when the store clears the session.
   - The interstitial (a 403 page) mounts itself and reloads the page it came from.
   - The promo page claims the voucher with fetch(): a 403 `challenge_required` mounts the CAPTCHA
     inline, then the claim is retried (a solve clears exactly one redemption).
   No framework, no build step. Without JavaScript neither page works: that is the point. */
(function () {
  "use strict";
  var $ = function (sel) { return document.querySelector(sel); };

  function post(url, body) {
    return fetch(url, { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" },
                        body: JSON.stringify(body) }).then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); });
  }

  function mount(box, payload, onSolved) {
    box.innerHTML = "";
    var img = document.createElement("img");
    img.src = payload.image; img.width = 220; img.height = 72; img.alt = "CAPTCHA: distorted characters";
    var input = document.createElement("input");
    input.name = "captcha"; input.autocomplete = "off"; input.placeholder = "type the characters"; input.setAttribute("aria-label", "CAPTCHA answer");
    var go = document.createElement("button");
    go.type = "button"; go.className = "btn small"; go.textContent = "Verify";
    var msg = document.createElement("p");
    msg.className = "muted small"; msg.setAttribute("role", "status");
    [img, input, go, msg].forEach(function (el) { box.appendChild(el); });
    function submit() {
      go.disabled = true;
      post("/api/challenge/verify", { type: "captcha", answer: { id: payload.id, text: input.value } }).then(function (r) {
        if (r.status === 200) { onSolved(); return; }
        msg.textContent = "That did not match. Here is a new one.";
        fetch("/api/challenge?type=captcha", { headers: { Accept: "application/json" } }).then(function (x) { return x.json(); })
          .then(function (j) { mount(box, j.payload, onSolved); box.querySelector("p").textContent = msg.textContent; });
      });
    }
    go.addEventListener("click", submit);
    input.addEventListener("keydown", function (ev) { if (ev.key === "Enter") { ev.preventDefault(); submit(); } });
    input.focus();
  }
  window.Captcha = { mount: mount };

  var inter = $("section.interstitial[data-challenge='captcha']");
  if (inter) {
    var payload = JSON.parse($("#captcha-payload").textContent);
    var next = inter.getAttribute("data-next") || "/";
    mount($("#captcha-box"), payload, function () {
      location.href = next.indexOf("/redeem") > -1 ? "/lab/promo/" : next;      // a POST cannot be replayed by a reload
    });
  }

  var form = $("#promo-form");
  if (form && window.fetch) {
    var msg = $("#promo-msg");
    var claim = function () {
      post("/lab/promo/redeem", {}).then(function (r) {
        if (r.status === 200) {
          $("#voucher").hidden = false; $("#voucher").querySelector("strong").textContent = r.body.voucher;
          $("#captcha-box").innerHTML = ""; msg.textContent = ""; return;
        }
        if (r.status === 403 && r.body.error && r.body.error.code === "challenge_required") {
          msg.textContent = "Type the characters to continue.";
          mount($("#captcha-box"), r.body.error.payload, claim);
          return;
        }
        msg.textContent = (r.body.error && r.body.error.message) || "Something went wrong.";
      });
    };
    form.addEventListener("submit", function (ev) { ev.preventDefault(); claim(); });
  }
})();
