// Workshop Store. A real browser runs this; a crawler usually never asks for it.
document.addEventListener("DOMContentLoaded", function () {
  var el = document.getElementById("js-ok");
  if (el) { el.textContent = "scripts ran"; }
});
