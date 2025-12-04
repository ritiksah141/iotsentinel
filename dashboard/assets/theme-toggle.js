/**
 * Theme Toggle for IoTSentinel Dashboard
 * Handles switching between light and dark modes
 */

(function () {
  "use strict";

  // Check for saved theme preference or default to light
  const savedTheme = localStorage.getItem("iotsentinel-theme") || "light";

  // Apply saved theme on page load
  if (savedTheme === "dark") {
    document.body.classList.add("dark-mode");
  }

  // Create theme toggle button
  function createThemeToggle() {
    // Check if button already exists
    if (document.querySelector(".theme-toggle")) {
      return;
    }

    const button = document.createElement("button");
    button.className = "theme-toggle";
    button.setAttribute("aria-label", "Toggle theme");
    button.setAttribute("title", "Toggle light/dark mode");

    // Set initial icon
    updateIcon(button);

    // Add click handler
    button.addEventListener("click", toggleTheme);

    // Add to page
    document.body.appendChild(button);
  }

  // Toggle between light and dark themes
  function toggleTheme() {
    const body = document.body;
    const isDark = body.classList.contains("dark-mode");

    if (isDark) {
      // Switch to light mode
      body.classList.remove("dark-mode");
      localStorage.setItem("iotsentinel-theme", "light");
    } else {
      // Switch to dark mode
      body.classList.add("dark-mode");
      localStorage.setItem("iotsentinel-theme", "dark");
    }

    // Update button icon
    const button = document.querySelector(".theme-toggle");
    if (button) {
      updateIcon(button);
    }
  }

  // Update button icon based on current theme
  function updateIcon(button) {
    const isDark = document.body.classList.contains("dark-mode");

    if (isDark) {
      // Show sun icon (to switch to light)
      button.innerHTML = '<i class="fa fa-sun"></i>';
    } else {
      // Show moon icon (to switch to dark)
      button.innerHTML = '<i class="fa fa-moon"></i>';
    }
  }

  // Initialize when DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", createThemeToggle);
  } else {
    createThemeToggle();
  }

  // Re-create button if Dash re-renders the page
  const observer = new MutationObserver(function (mutations) {
    if (!document.querySelector(".theme-toggle")) {
      createThemeToggle();
    }
  });

  // Start observing
  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });
})();
