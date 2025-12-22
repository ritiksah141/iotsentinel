/**
 * Debounce utility for Dash callbacks
 * Prevents excessive callback firing on rapid user input
 */

// Prevent duplicate loading
if (window.debounceUtilsLoaded) {
  console.log("⚡ Debounce utilities already loaded, skipping...");
} else {
  window.debounceUtilsLoaded = true;

// Debounce function - delays execution until user stops typing
function debounce(func, delay) {
  let timeoutId;
  return function (...args) {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func.apply(this, args), delay);
  };
}

// Throttle function - limits execution to once per time period
function throttle(func, limit) {
  let inThrottle;
  return function (...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => (inThrottle = false), limit);
    }
  };
}

// Debounce search inputs automatically
document.addEventListener("DOMContentLoaded", function () {
  // Find all search/filter inputs
  const searchInputs = document.querySelectorAll(
    'input[placeholder*="search" i], input[placeholder*="filter" i], input[type="search"]'
  );

  searchInputs.forEach((input) => {
    if (!input.hasAttribute("data-debounced")) {
      input.setAttribute("data-debounced", "true");

      // Store original oninput handler
      const originalHandler = input.oninput;

      // Replace with debounced version (500ms delay)
      input.oninput = debounce(function (e) {
        if (originalHandler) {
          originalHandler.call(this, e);
        }
      }, 500);

      console.log("✅ Debounced input:", input.placeholder || input.id);
    }
  });
});

// Export for use in custom callbacks
window.debounce = debounce;
window.throttle = throttle;

// Clientside callback helper for debounced updates
window.dash_clientside = Object.assign({}, window.dash_clientside, {
  debounce: {
    // Debounced search callback
    search: debounce(function (value) {
      return value;
    }, 500),

    // Throttled scroll callback
    scroll: throttle(function (value) {
      return value;
    }, 100),
  },
});

console.log("⚡ Debounce utilities loaded");
} // End duplicate check
