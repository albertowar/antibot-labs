// W2 Ch3, Round 4: tell the store which JavaScript engine this is.
// The TypeError text and the length of eval's source differ between V8, SpiderMonkey and
// JavaScriptCore (defenses/engine_signals.py). Posted once per browser session.
(function () {
  var script = document.currentScript;
  var nonce = script && script.getAttribute("data-nonce");
  if (!nonce) return;
  try { if (sessionStorage.getItem("tls_engine") === "1") return; } catch (e) {}
  var message = "";
  try { null.f(); } catch (e) { message = e.message; }
  fetch("/api/telemetry", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({kind: "engine", nonce: nonce, error_message: message, eval_length: eval.toString().length})
  }).then(function (r) {
    if (r.ok) { try { sessionStorage.setItem("tls_engine", "1"); } catch (e) {} }
  }).catch(function () {});
})();
