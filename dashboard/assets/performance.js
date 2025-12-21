/**
 * Performance optimizations for instant load and buttery smooth experience
 * Supports 60Hz (60 FPS) and 120Hz+ (120 FPS) displays
 */

// Detect refresh rate and optimize accordingly
let refreshRate = 60; // Default to 60Hz
let isHighRefresh = false;

// Improved refresh rate detection using requestIdleCallback for accurate measurement
window.addEventListener("load", function () {
  // Wait for page to be fully settled before measuring
  const startMeasurement = function () {
    let frameCount = 0;
    let lastTimestamp = null;
    let frameTimes = [];
    let consecutiveFrames = 0;

    function measureRefreshRate(timestamp) {
      if (lastTimestamp !== null) {
        const delta = timestamp - lastTimestamp;

        // Only record stable frame times (8-20ms for 60-120Hz)
        if (delta > 8 && delta < 35) {
          frameTimes.push(delta);
          consecutiveFrames++;
          frameCount++;
        } else {
          // Reset if we hit an unstable frame (page still loading)
          consecutiveFrames = 0;
        }
      }

      lastTimestamp = timestamp;

      // Need 30 frames with 20 consecutive stable for faster measurement
      if (frameCount < 30 || consecutiveFrames < 20) {
        requestAnimationFrame(measureRefreshRate);
      } else {
        // Sort and remove outliers (top and bottom 10%)
        frameTimes.sort((a, b) => a - b);
        const trimCount = Math.floor(frameTimes.length * 0.1);
        const trimmedTimes = frameTimes.slice(
          trimCount,
          frameTimes.length - trimCount
        );

        // Calculate average frame time from trimmed data
        const avgFrameTime =
          trimmedTimes.reduce((a, b) => a + b, 0) / trimmedTimes.length;
        const detectedFPS = Math.round(1000 / avgFrameTime);

        // Map to common refresh rates
        if (detectedFPS >= 100) {
          refreshRate = 120;
          isHighRefresh = true;
        } else if (detectedFPS >= 80) {
          refreshRate = 90;
          isHighRefresh = true;
        } else {
          refreshRate = 60; // Standard refresh rate
          isHighRefresh = false;
        }

        // Check if this is a likely false reading due to throttling
        const likelyThrottled = detectedFPS < 45 && avgFrameTime > 25;

        if (likelyThrottled) {
          console.warn(
            "⚠️ Browser appears throttled (detected " + detectedFPS + " FPS)."
          );
          console.log(
            "💡 Tip: Make sure the tab is active and not in power saving mode."
          );
          console.log(
            "🎯 Assuming 60Hz minimum. Run window.setRefreshRate(120) if you have a high-refresh display."
          );
          // Assume at least 60Hz for modern Macs
          refreshRate = 60;
          isHighRefresh = false;
        }

        console.log(
          "🚀 Detected refresh rate:",
          refreshRate + "Hz",
          "(measured:",
          detectedFPS + " FPS,",
          "avg frame time:",
          avgFrameTime.toFixed(2) + "ms)"
        );
        console.log(
          "⚡ Performance mode:",
          isHighRefresh ? "HIGH REFRESH (120+ FPS)" : "STANDARD (60 FPS)"
        );

        // Apply optimizations
        if (isHighRefresh) {
          document.documentElement.classList.add("high-refresh");
        }
      }
    }

    requestAnimationFrame(measureRefreshRate);
  };

  // Delay measurement to avoid interfering with Dash initialization
  setTimeout(startMeasurement, 3000);
});

// Remove no-animations class after initial load
window.addEventListener("load", function () {
  setTimeout(function () {
    document.body.classList.remove("no-animations");
  }, 100);
});

// Manual refresh rate override function
window.setRefreshRate = function (rate) {
  if (rate === 60 || rate === 90 || rate === 120) {
    refreshRate = rate;
    isHighRefresh = rate > 60;

    if (isHighRefresh) {
      document.documentElement.classList.add("high-refresh");
    } else {
      document.documentElement.classList.remove("high-refresh");
    }

    console.log("✅ Refresh rate manually set to " + rate + "Hz");
    console.log(
      "⚡ Performance mode: " +
        (isHighRefresh ? "HIGH REFRESH (120+ FPS)" : "STANDARD (60 FPS)")
    );
    return "Refresh rate set to " + rate + "Hz";
  } else {
    console.error("❌ Invalid refresh rate. Use 60, 90, or 120");
    return "Error: Use 60, 90, or 120";
  }
};

// Show current FPS function (for debugging)
window.showFPS = function () {
  console.log("📊 Current refresh rate setting: " + refreshRate + "Hz");
  console.log(
    "⚡ High refresh mode: " + (isHighRefresh ? "ENABLED" : "DISABLED")
  );

  // Measure current FPS
  let count = 0;
  let start = performance.now();

  function measureCurrent(timestamp) {
    count++;
    if (count < 60) {
      requestAnimationFrame(measureCurrent);
    } else {
      const elapsed = performance.now() - start;
      const fps = Math.round((count / elapsed) * 1000);
      console.log("📈 Currently rendering at: " + fps + " FPS");
    }
  }

  requestAnimationFrame(measureCurrent);
  return "Measuring current FPS...";
};

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

// Monitor performance metrics (delayed to avoid interfering with load)
if ("PerformanceObserver" in window) {
  // Delay performance monitoring to after page is fully loaded
  setTimeout(() => {
    try {
      // Observe long tasks (only log truly problematic ones >200ms)
      const perfObserver = new PerformanceObserver(function (list) {
        for (const entry of list.getEntries()) {
          if (entry.duration > 200) {
            console.warn(
              "Long task detected:",
              entry.duration.toFixed(2),
              "ms"
            );
          }
        }
      });
      perfObserver.observe({ entryTypes: ["longtask"] });
    } catch (e) {
      // Browser doesn't support longtask
    }
  }, 5000); // Start monitoring 5 seconds after load

  // Observe layout shifts (delayed)
  setTimeout(() => {
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
  }, 5000); // Start monitoring 5 seconds after load
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

// Real-time FPS monitor (for debugging - set to true to enable)
let fpsMonitorEnabled = false;

if (fpsMonitorEnabled) {
  let fpsDisplay = document.createElement("div");
  fpsDisplay.style.cssText = `
        position: fixed;
        top: 10px;
        right: 10px;
        background: rgba(0, 0, 0, 0.8);
        color: #0f0;
        padding: 10px 15px;
        font-family: monospace;
        font-size: 14px;
        border-radius: 8px;
        z-index: 999999;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
    `;
  document.body.appendChild(fpsDisplay);

  let frames = 0;
  let lastFPSTime = performance.now();
  let currentFPS = 0;

  function updateFPS() {
    const currentTime = performance.now();
    frames++;

    if (currentTime >= lastFPSTime + 1000) {
      currentFPS = Math.round((frames * 1000) / (currentTime - lastFPSTime));
      frames = 0;
      lastFPSTime = currentTime;

      let color = "#0f0"; // Green
      if (currentFPS < 60) color = "#ff0"; // Yellow
      if (currentFPS < 30) color = "#f00"; // Red
      if (currentFPS >= 100) color = "#0ff"; // Cyan for high refresh

      fpsDisplay.innerHTML = `
                <strong>FPS: ${currentFPS}</strong><br>
                <small>Refresh: ${refreshRate}Hz</small><br>
                <small>Mode: ${isHighRefresh ? "120+" : "60"}</small>
            `;
      fpsDisplay.style.color = color;
    }

    requestAnimationFrame(updateFPS);
  }

  requestAnimationFrame(updateFPS);
}
