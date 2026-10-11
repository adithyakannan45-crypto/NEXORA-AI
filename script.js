const menuBtn = document.getElementById("menuBtn");
const navLinks = document.getElementById("navLinks");

function closeMenu() {
  navLinks?.classList.remove("mobile-open");
  if (menuBtn) {
    menuBtn.textContent = "☰";
    menuBtn.setAttribute("aria-label", "Open menu");
  }
}

menuBtn?.addEventListener("click", () => {
  const open = navLinks.classList.toggle("mobile-open");
  menuBtn.textContent = open ? "✕" : "☰";
  menuBtn.setAttribute("aria-label", open ? "Close menu" : "Open menu");
});

navLinks?.querySelectorAll("a").forEach(link => {
  link.addEventListener("click", closeMenu);
});

document.addEventListener("click", (event) => {
  if (!navLinks || !menuBtn) return;
  if (window.innerWidth <= 900 && navLinks.classList.contains("mobile-open") &&
      !navLinks.contains(event.target) && !menuBtn.contains(event.target)) {
    closeMenu();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeMenu();
});

window.addEventListener("resize", () => {
  if (window.innerWidth > 900) closeMenu();
});

// Small reveal animation for sections/cards.
const revealItems = document.querySelectorAll(".feature-card, .step, .price-card, .ai-window");

if ("IntersectionObserver" in window) {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add("visible");
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12 });

  revealItems.forEach(item => observer.observe(item));
} else {
  revealItems.forEach(item => item.classList.add("visible"));
}
