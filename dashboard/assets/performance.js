/**
 * Performance optimizations for instant load and buttery smooth experience
 */

// Remove no-animations class after initial load
window.addEventListener("load", function () {
  setTimeout(function () {
    document.body.classList.remove("no-animations");
  }, 100);
});

// Add no-animations class immediately to prevent animation jank on load
(function () {
  document.documentElement.classList.add("no-animations");

  // Remove after DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      setTimeout(function () {
        document.documentElement.classList.remove("no-animations");
      }, 50);
    });
  }
})();

// Smooth scroll optimization
if ("scrollBehavior" in document.documentElement.style) {
  // Browser supports smooth scrolling
  document.documentElement.style.scrollBehavior = "smooth";
}

// Passive event listeners for better scroll performance
let supportsPassive = false;
try {
  const opts = Object.defineProperty({}, "passive", {
    get: function () {
      supportsPassive = true;
    },
  });
  window.addEventListener("testPassive", null, opts);
  window.removeEventListener("testPassive", null, opts);
} catch (e) {}

// Add passive listeners to scroll and touch events
const passiveIfSupported = supportsPassive ? { passive: true } : false;

document.addEventListener(
  "scroll",
  function () {
    // Scroll handler
  },
  passiveIfSupported
);

document.addEventListener(
  "touchstart",
  function () {
    // Touch handler
  },
  passiveIfSupported
);

document.addEventListener(
  "touchmove",
  function () {
    // Touch move handler
  },
  passiveIfSupported
);

// Lazy load images when they come into view
if ("IntersectionObserver" in window) {
  const imageObserver = new IntersectionObserver(function (entries, observer) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        const img = entry.target;
        if (img.dataset.src) {
          img.src = img.dataset.src;
          img.removeAttribute("data-src");
        }
        imageObserver.unobserve(img);
      }
    });
  });

  // Observe all images with data-src
  document.querySelectorAll("img[data-src]").forEach(function (img) {
    imageObserver.observe(img);
  });
}

// Debounce function for resize events
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = function () {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Optimize window resize handling
window.addEventListener(
  "resize",
  debounce(function () {
    // Handle resize
  }, 250)
);

// Request idle callback for non-critical tasks
if ("requestIdleCallback" in window) {
  requestIdleCallback(function () {
    // Perform non-critical initialization here
    console.log("Performance optimizations loaded");
  });
}

// Preconnect to external resources
const preconnectLinks = [
  "https://fonts.googleapis.com",
  "https://fonts.gstatic.com",
];

preconnectLinks.forEach(function (url) {
  const link = document.createElement("link");
  link.rel = "preconnect";
  link.href = url;
  link.crossOrigin = "anonymous";
  document.head.appendChild(link);
});

// Force hardware acceleration on interactive elements
document.addEventListener("DOMContentLoaded", function () {
  const interactiveElements = document.querySelectorAll(
    "button, a, .card, .dropdown-item"
  );
  interactiveElements.forEach(function (el) {
    el.style.transform = "translateZ(0)";
  });
});

// Optimize Dash callbacks
window.dash_clientside = Object.assign({}, window.dash_clientside, {
  clientside: {
    // Optimized state updates
    optimized_update: function () {
      // Use requestAnimationFrame for smooth updates
      return window.dash_clientside.no_update;
    },
  },
});

// Monitor performance metrics
if ("PerformanceObserver" in window) {
  try {
    // Observe long tasks
    const perfObserver = new PerformanceObserver(function (list) {
      for (const entry of list.getEntries()) {
        if (entry.duration > 50) {
          console.warn("Long task detected:", entry.duration.toFixed(2), "ms");
        }
      }
    });
    perfObserver.observe({ entryTypes: ["longtask"] });
  } catch (e) {
    // Browser doesn't support longtask
  }

  // Observe layout shifts
  try {
    const clsObserver = new PerformanceObserver(function (list) {
      for (const entry of list.getEntries()) {
        if (!entry.hadRecentInput && entry.value > 0.1) {
          console.warn("Layout shift detected:", entry.value.toFixed(4));
        }
      }
    });
    clsObserver.observe({ entryTypes: ["layout-shift"] });
  } catch (e) {
    // Browser doesn't support layout-shift
  }
}

// Log performance metrics on load
window.addEventListener("load", function () {
  if ("performance" in window && "timing" in performance) {
    setTimeout(function () {
      const perfData = performance.timing;
      const pageLoadTime = perfData.loadEventEnd - perfData.navigationStart;
      const connectTime = perfData.responseEnd - perfData.requestStart;
      const renderTime = perfData.domComplete - perfData.domLoading;

      console.log("=== Performance Metrics ===");
      console.log("Page Load Time:", pageLoadTime, "ms");
      console.log("Connection Time:", connectTime, "ms");
      console.log("Render Time:", renderTime, "ms");
      console.log("==========================");
    }, 0);
  }
});
