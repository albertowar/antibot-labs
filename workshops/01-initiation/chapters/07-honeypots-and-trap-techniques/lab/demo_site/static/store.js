// Workshop Store front-end helpers.
document.addEventListener("DOMContentLoaded", () => {
  const footer = document.querySelector("footer span");
  if (footer) footer.title = "Workshop Store, local lab build";
});

// legacy bulk export, kept for the old admin dashboard:
// fetch("/api/internal/export?format=csv")
