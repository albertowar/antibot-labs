/*
 * W4 Ch4 — Store page wiring
 *
 * Every protected action flushes this page's telemetry first and then calls
 * the API. The reply goes into #result with data-outcome (allow / challenge /
 * block / error) and a plain-English message, which humans, the attack
 * scripts and the lab agent all read the same way: from the page.
 *
 * A 202 "challenge" at checkout reveals #confirm-form: the step-up. A real
 * agentic browser stops here and hands control back to its user.
 */
(function () {
  "use strict";
  const result = document.getElementById("result");

  function show(reply) {
    if (!result) return;
    result.dataset.outcome = reply.outcome || "error";
    result.textContent = reply.message || JSON.stringify(reply);
    if (reply.reasons && reply.reasons.length) {
      const ul = document.createElement("ul");
      for (const r of reply.reasons) { const li = document.createElement("li"); li.textContent = r; ul.appendChild(li); }
      result.appendChild(ul);
    }
    if (reply.hint) {
      const p = document.createElement("p"); p.className = "hint"; p.textContent = reply.hint; result.appendChild(p);
    }
  }

  async function post(url, body) {
    const r = await fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    try { return await r.json(); } catch (err) { return { outcome: "error", message: `HTTP ${r.status}` }; }
  }

  async function flushThen(fn) {
    try { await window.labTelemetry.flush(); } catch (err) { /* telemetry is best effort */ }
    return fn();
  }

  const add = document.getElementById("add-to-cart");
  if (add) {
    add.addEventListener("click", () => flushThen(async () => {
      add.disabled = true;
      const reply = await post("/api/cart/add", { sku: add.dataset.sku });
      show(reply);
      add.disabled = false;
      if (reply.outcome === "allow") {
        const a = document.createElement("a"); a.href = "/cart"; a.id = "view-cart"; a.textContent = "View cart";
        result.appendChild(document.createTextNode(" ")); result.appendChild(a);
      }
    }));
  }

  const place = document.getElementById("place-order");
  const confirmForm = document.getElementById("confirm-form");
  if (place) {
    place.addEventListener("click", () => flushThen(async () => {
      place.disabled = true;
      const mandate = (document.querySelector("input[name=mandate]") || {}).value || "";
      const reply = await post("/api/checkout", { mandate: mandate.trim() || null });
      show(reply);
      place.disabled = false;
      if (reply.outcome === "challenge" && reply.step_up && confirmForm) confirmForm.hidden = false;
    }));
  }
  if (confirmForm) {
    confirmForm.addEventListener("submit", (e) => {
      e.preventDefault();
      flushThen(async () => {
        const reply = await post("/api/checkout/confirm", { code: confirmForm.code.value.trim() });
        show(reply);
        if (reply.outcome === "allow") confirmForm.hidden = true;
      });
    });
  }

  const login = document.getElementById("login-form");
  if (login) {
    login.addEventListener("submit", (e) => {
      e.preventDefault();
      flushThen(async () => {
        const reply = await post("/api/login", { email: login.email.value, password: login.password.value });
        show(reply);
        if (reply.outcome === "allow" && login.dataset.next) location.href = login.dataset.next;
      });
    });
  }

  const register = document.getElementById("register-form");
  if (register) {
    register.addEventListener("submit", (e) => {
      e.preventDefault();
      flushThen(async () => {
        const reply = await post("/api/register", {
          email: register.email.value, password: register.password.value, address: register.address.value,
        });
        show(reply);
        if (reply.outcome === "allow" && register.dataset.next) location.href = register.dataset.next;
      });
    });
  }

  const mandate = document.getElementById("mandate-form");
  if (mandate) {
    mandate.addEventListener("submit", (e) => {
      e.preventDefault();
      flushThen(async () => {
        const reply = await post("/api/account/mandates", {
          operator: mandate.operator.value, sku: mandate.sku.value, ttl_min: Number(mandate.ttl_min.value || 15),
        });
        const out = document.getElementById("mandate-result");
        out.dataset.outcome = reply.outcome || "error";
        out.textContent = reply.outcome === "allow"
          ? `Mandate ${reply.mandate.id} granted to ${reply.mandate.operator} for ${reply.mandate.sku}, expires ${reply.mandate.expires_at}`
          : (reply.message || JSON.stringify(reply));
      });
    });
  }
})();
