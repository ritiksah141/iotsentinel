/**
 * Static Asset Caching Strategy
 * Implements aggressive caching for static resources
 */

// Prevent duplicate loading
if (window.staticCacheLoaded) {
  console.log("💾 Static cache already loaded, skipping...");
} else {
  window.staticCacheLoaded = true;

// Cache static assets in memory
const assetCache = new Map();

// Preload critical assets
const CRITICAL_ASSETS = [
  "/assets/custom.css",
  "/assets/performance.js",
  "/assets/debounce.js",
  "/assets/virtual-scroll.js",
];

// Cache asset responses
function cacheAsset(url, data) {
  assetCache.set(url, {
    data: data,
    timestamp: Date.now(),
    size: new Blob([data]).size,
  });
}

// Get cached asset
function getCachedAsset(url, maxAge = 3600000) {
  // 1 hour default
  const cached = assetCache.get(url);
  if (cached && Date.now() - cached.timestamp < maxAge) {
    return cached.data;
  }
  return null;
}

// Preload critical assets
function preloadCriticalAssets() {
  CRITICAL_ASSETS.forEach((url) => {
    if (!assetCache.has(url)) {
      fetch(url)
        .then((response) => response.text())
        .then((data) => {
          cacheAsset(url, data);
          console.log(`✅ Cached: ${url} (${(new Blob([data]).size / 1024).toFixed(1)}KB)`);
        })
        .catch((err) => console.warn(`Failed to cache ${url}:`, err));
    }
  });
}

// Prefetch visible images
function prefetchImages() {
  const images = document.querySelectorAll("img[data-src]");
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const img = entry.target;
          if (img.dataset.src) {
            img.src = img.dataset.src;
            img.removeAttribute("data-src");
            observer.unobserve(img);
          }
        }
      });
    },
    { rootMargin: "50px" }
  );

  images.forEach((img) => observer.observe(img));
}

// Initialize on page load
document.addEventListener("DOMContentLoaded", function () {
  // Preload critical assets
  setTimeout(preloadCriticalAssets, 1000);

  // Setup image lazy loading
  prefetchImages();

  // Log cache stats
  setTimeout(() => {
    const totalSize = Array.from(assetCache.values()).reduce(
      (sum, item) => sum + item.size,
      0
    );
    console.log(
      `💾 Asset cache: ${assetCache.size} items, ${(totalSize / 1024).toFixed(1)}KB`
    );
  }, 2000);
});

// Export
window.assetCache = assetCache;
window.preloadCriticalAssets = preloadCriticalAssets;

console.log("💾 Static asset caching enabled");
} // End duplicate check
