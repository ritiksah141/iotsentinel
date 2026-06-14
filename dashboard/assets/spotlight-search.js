/**
 * Spotlight Search for IoTSentinel
 * Fuzzy search · NLP intent · Preview pane · Stagger animation
 * Shortcut: Cmd+K / Ctrl+K to open
 */

(function () {
  "use strict";

  // ============================================================================
  // RECENT SEARCHES
  // ============================================================================

  const RECENT_SEARCHES_KEY = "iotsentinel_recent_searches";
  const MAX_RECENT_SEARCHES = 5;

  function saveRecentSearch(query) {
    if (!query || query.trim().length < 2) return;
    try {
      let recent = JSON.parse(localStorage.getItem(RECENT_SEARCHES_KEY) || "[]");
      recent = recent.filter((q) => q.toLowerCase() !== query.toLowerCase());
      recent.unshift(query.trim());
      recent = recent.slice(0, MAX_RECENT_SEARCHES);
      localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(recent));
    } catch (e) {}
  }

  function getRecentSearches() {
    try {
      return JSON.parse(localStorage.getItem(RECENT_SEARCHES_KEY) || "[]");
    } catch (e) {
      return [];
    }
  }

  function clearRecentSearches() {
    try { localStorage.removeItem(RECENT_SEARCHES_KEY); } catch (e) {}
  }

  function removeRecentSearch(query) {
    try {
      let recent = JSON.parse(localStorage.getItem(RECENT_SEARCHES_KEY) || "[]");
      recent = recent.filter((q) => q !== query);
      localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(recent));
    } catch (e) {}
  }

  // ============================================================================
  // SEARCH ANALYTICS
  // ============================================================================

  const SEARCH_ANALYTICS_KEY = "iotsentinel_search_analytics";

  function recordFeatureAccess(featureId) {
    if (!featureId) return;
    try {
      const analytics = JSON.parse(localStorage.getItem(SEARCH_ANALYTICS_KEY) || "{}");
      analytics[featureId] = (analytics[featureId] || 0) + 1;
      localStorage.setItem(SEARCH_ANALYTICS_KEY, JSON.stringify(analytics));
    } catch (e) {}
  }

  function getTopFeatures(limit = 5) {
    try {
      const analytics = JSON.parse(localStorage.getItem(SEARCH_ANALYTICS_KEY) || "{}");
      return Object.entries(analytics)
        .map(([id, count]) => ({ id, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, limit);
    } catch (e) {
      return [];
    }
  }

  function getSearchAnalytics() {
    try {
      return JSON.parse(localStorage.getItem(SEARCH_ANALYTICS_KEY) || "{}");
    } catch (e) {
      return {};
    }
  }

  // ============================================================================
  // PREVIEW PANE
  // ============================================================================

  function getFeatureData(rowEl) {
    try {
      return JSON.parse(rowEl.getAttribute("data-feature") || "{}");
    } catch (e) {
      return {};
    }
  }

  function updatePreview(featureData) {
    const pane = document.getElementById("sl-preview-content");
    if (!pane) return;

    if (!featureData || !featureData.name) {
      pane.innerHTML = "";
      pane.className = "sl-preview-inner sl-preview-empty";
      return;
    }

    const color = featureData.color || "#6366f1";
    const icon = featureData.icon || "fa-circle";
    const kwHtml = (featureData.keywords || [])
      .slice(0, 6)
      .map((k) => `<span class="sl-kw-badge">${k}</span>`)
      .join("");

    pane.className = "sl-preview-inner";
    pane.innerHTML = `
      <div class="sl-pv-icon-wrap" style="background:${color}22">
        <i class="fa ${icon}" style="color:${color}; font-size:2rem;"></i>
      </div>
      <div class="sl-pv-category">${featureData.category || ""}</div>
      <div class="sl-pv-name">${featureData.name}</div>
      <div class="sl-pv-desc">${featureData.description || ""}</div>
      ${kwHtml ? `<div class="sl-pv-keywords">${kwHtml}</div>` : ""}
      <div class="sl-pv-hint">
        <i class="fa fa-arrow-up-right-from-square me-1"></i>Tap or click to open
      </div>
    `;
  }

  function clearPreview() {
    updatePreview(null);
  }

  // ============================================================================
  // NLP INTENT ENGINE
  // ============================================================================

  const NLP_INTENT_MAP = [
    {
      patterns: ["risky device", "dangerous device", "vulnerable device", "high risk device", "show risk"],
      features: [{ id: "device-mgmt-modal", boost: 50 }, { id: "risk-heatmap-modal", boost: 60 }],
    },
    {
      patterns: ["what threat", "show threat", "today threat", "recent threat", "latest threat", "attack today", "any attack"],
      features: [{ id: "threat-modal", boost: 60 }, { id: "threat-map-modal", boost: 50 }],
    },
    {
      patterns: ["block device", "block untrusted", "emergency block", "stop device", "prevent attack"],
      features: [{ id: "lockdown-modal", boost: 70 }, { id: "firewall-modal", boost: 50 }],
    },
    {
      patterns: ["check performance", "network slow", "network speed", "how fast", "bandwidth", "throughput"],
      features: [{ id: "performance-modal", boost: 60 }, { id: "analytics-modal", boost: 40 }],
    },
    {
      patterns: ["scan network", "find device", "new device", "detect device", "discover device"],
      features: [{ id: "device-mgmt-modal", boost: 50 }, { id: "vuln-scanner-modal", boost: 60 }],
    },
    {
      patterns: ["export data", "download report", "generate report", "get report", "export report"],
      features: [{ id: "quick-actions-modal", boost: 60 }],
    },
    {
      patterns: ["emergency", "lockdown", "incident response", "under attack"],
      features: [{ id: "lockdown-modal", boost: 100 }, { id: "auto-response-modal", boost: 60 }],
    },
    {
      patterns: ["who logged in", "user activity", "login activity", "audit log", "user access"],
      features: [{ id: "compliance-modal", boost: 50 }, { id: "user-modal", boost: 60 }],
    },
    {
      patterns: ["firmware update", "device patch", "update device", "device version", "outdated firmware"],
      features: [{ id: "firmware-modal", boost: 60 }],
    },
    {
      patterns: ["ai help", "ai assistant", "ask ai", "help me", "what should i do"],
      features: [{ id: "chat-modal", boost: 70 }],
    },
    {
      patterns: ["data leak", "privacy risk", "data exposure", "private data", "data sharing"],
      features: [{ id: "privacy-modal", boost: 60 }],
    },
    {
      patterns: ["smart home", "alexa", "google home", "iot hub", "home automation"],
      features: [{ id: "smarthome-modal", boost: 60 }],
    },
    {
      patterns: ["network traffic", "mqtt", "http traffic", "coap", "packet analysis"],
      features: [{ id: "protocol-modal", boost: 60 }],
    },
    {
      patterns: ["gdpr", "hipaa", "compliance check", "security standard", "regulation"],
      features: [{ id: "compliance-modal", boost: 70 }],
    },
  ];

  function parseNLPIntent(query) {
    if (!query || query.trim().length < 3) return [];
    const lower = query.toLowerCase().trim();
    const matches = [];

    NLP_INTENT_MAP.forEach((intent) => {
      intent.patterns.forEach((pattern) => {
        if (lower.includes(pattern)) {
          intent.features.forEach((feature) => {
            const existing = matches.find((m) => m.featureId === feature.id);
            if (existing) {
              existing.boost = Math.max(existing.boost, feature.boost);
            } else {
              matches.push({ featureId: feature.id, boost: feature.boost, pattern });
            }
          });
        }
      });
    });

    return matches;
  }

  // ============================================================================
  // FUZZY MATCHING
  // ============================================================================

  function fuzzyMatch(searchTerm, targetString) {
    searchTerm = searchTerm.toLowerCase();
    targetString = targetString.toLowerCase();
    let searchIndex = 0, score = 0, consecutiveMatches = 0;

    for (let i = 0; i < targetString.length && searchIndex < searchTerm.length; i++) {
      if (targetString[i] === searchTerm[searchIndex]) {
        searchIndex++;
        consecutiveMatches++;
        score += 1 + consecutiveMatches;
      } else {
        consecutiveMatches = 0;
      }
    }

    if (searchIndex === searchTerm.length) {
      if (targetString === searchTerm) score += 100;
      if (targetString.startsWith(searchTerm)) score += 50;
      return score;
    }
    return 0;
  }

  // ============================================================================
  // SEARCH FUNCTION
  // ============================================================================

  function searchFeatures(query, featureCatalog, maxResults = 50, categoryFilter = null, contextBoosts = null) {
    const startTime = performance.now();

    if (query && query.trim().length >= 2) saveRecentSearch(query);

    if (!query || query.trim() === "") {
      const featured = featureCatalog.slice(0, 10);
      return {
        results: featured,
        totalCount: featured.length,
        hasMore: false,
        query: "",
        categories: groupByCategory(featured),
        topHit: featured[0] || null,
        searchTime: (performance.now() - startTime).toFixed(2),
        categoryFilter,
      };
    }

    const results = [];

    featureCatalog.forEach((feature) => {
      let bestScore = 0;
      bestScore = Math.max(bestScore, fuzzyMatch(query, feature.name) * 3);
      feature.keywords.forEach((kw) => {
        bestScore = Math.max(bestScore, fuzzyMatch(query, kw) * 2);
      });
      bestScore = Math.max(bestScore, fuzzyMatch(query, feature.description));
      bestScore = Math.max(bestScore, fuzzyMatch(query, feature.category));
      if (bestScore > 0) results.push({ ...feature, score: bestScore });
    });

    const nlpMatches = parseNLPIntent(query);
    if (nlpMatches.length > 0) {
      results.forEach((r) => {
        const m = nlpMatches.find((n) => n.featureId === r.id);
        if (m) { r.score += m.boost; r.nlpMatch = true; }
      });
      nlpMatches.forEach((m) => {
        if (!results.find((r) => r.id === m.featureId)) {
          const f = featureCatalog.find((f) => f.id === m.featureId);
          if (f) results.push({ ...f, score: m.boost, nlpMatch: true });
        }
      });
    }

    if (contextBoosts && typeof contextBoosts === "object") {
      results.forEach((r) => {
        if (contextBoosts[r.id]) { r.score += contextBoosts[r.id]; r.contextBoosted = true; }
      });
    }

    let sorted = results.sort((a, b) => b.score - a.score);
    if (categoryFilter) sorted = sorted.filter((r) => r.category === categoryFilter);
    const limited = sorted.slice(0, maxResults);

    return {
      results: limited,
      totalCount: sorted.length,
      hasMore: sorted.length > maxResults,
      query,
      categories: groupByCategory(limited),
      topHit: sorted[0] || null,
      searchTime: (performance.now() - startTime).toFixed(2),
      categoryFilter,
    };
  }

  function groupByCategory(results) {
    const grouped = {};
    results.forEach((r) => {
      const cat = r.category || "Other";
      if (!grouped[cat]) grouped[cat] = [];
      grouped[cat].push(r);
    });
    return grouped;
  }

  function getAllCategories(catalog) {
    const cats = new Set();
    catalog.forEach((item) => { if (item.category) cats.add(item.category); });
    return Array.from(cats).sort();
  }

  function getAutocompleteSuggestions(query, catalog) {
    if (!query || query.length < 2) return [];
    const suggestions = new Set();
    const lq = query.toLowerCase();
    catalog.forEach((f) => {
      if (f.name.toLowerCase().includes(lq)) suggestions.add(f.name);
      f.keywords.forEach((kw) => { if (kw.toLowerCase().includes(lq)) suggestions.add(kw); });
    });
    return Array.from(suggestions).slice(0, 5);
  }

  // ============================================================================
  // PREDICTIVE SUGGESTIONS
  // ============================================================================

  function getPredictiveSuggestions(catalog) {
    const hour = new Date().getHours();
    const suggestions = [];

    let timeLabel, timeFeatureIds;
    if (hour >= 6 && hour < 10) {
      timeLabel = "🌅 Morning — recommended checks";
      timeFeatureIds = ["analytics-modal", "alert-details-modal", "device-mgmt-modal"];
    } else if (hour >= 10 && hour < 14) {
      timeLabel = "☀️ Active monitoring";
      timeFeatureIds = ["threat-modal", "performance-modal", "risk-heatmap-modal"];
    } else if (hour >= 14 && hour < 18) {
      timeLabel = "☀️ Afternoon security review";
      timeFeatureIds = ["vuln-scanner-modal", "threat-modal", "firmware-modal"];
    } else if (hour >= 18 && hour < 21) {
      timeLabel = "🌆 End-of-day summary";
      timeFeatureIds = ["compliance-modal", "analytics-modal", "auto-response-modal"];
    } else {
      timeLabel = "🌙 Night watch";
      timeFeatureIds = ["system-modal", "performance-modal", "analytics-modal"];
    }

    const resolve = (ids) => ids.map((id) => catalog.find((f) => f.id === id)).filter(Boolean);
    suggestions.push({ type: "time", label: timeLabel, features: resolve(timeFeatureIds) });

    const topFeatures = getTopFeatures(3);
    if (topFeatures.length >= 2) {
      const topObjects = topFeatures.map((tf) => catalog.find((f) => f.id === tf.id)).filter(Boolean);
      if (topObjects.length > 0) {
        suggestions.push({
          type: "frequent",
          label: "⭐ Your most used",
          features: topObjects,
          counts: topFeatures.map((tf) => tf.count),
        });
      }
    }

    return suggestions;
  }

  // ============================================================================
  // ROW CLICK — click the hidden go-to button inside the clicked row
  // ============================================================================

  document.addEventListener("click", function (e) {
    const row = e.target.closest("[data-feature]");
    if (!row) return;
    if (e.target.closest("button")) return;
    const goToBtn = row.querySelector('button[id*="spotlight-go-to-btn"]');
    if (goToBtn) {
      e.stopPropagation();
      goToBtn.click();
    }
  });

  // ============================================================================
  // HOVER — update preview pane on mouse-over
  // ============================================================================

  document.addEventListener("mouseover", function (e) {
    const row = e.target.closest("[data-feature]");
    if (row) updatePreview(getFeatureData(row));
  });

  // ============================================================================
  // Cmd+K / Ctrl+K — open spotlight
  // ============================================================================

  document.addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === "k") {
      e.preventDefault();
      const btn = document.getElementById("spotlight-search-button");
      if (btn) btn.click();
    }
  });

  // ============================================================================
  // STAGGER ANIMATION
  // ============================================================================

  function applyStaggerDelays(container) {
    container.querySelectorAll(".sl-result-row").forEach(function (row, i) {
      row.style.animationDelay = i * 18 + "ms";
    });
  }

  // ============================================================================
  // INIT
  // ============================================================================

  function init() {
    const modal = document.getElementById("spotlight-search-modal");

    // Auto-focus search input when modal opens; clear preview on close
    if (modal) {
      new MutationObserver(function () {
        if (modal.classList.contains("show")) {
          const input = document.getElementById("spotlight-search-input");
          if (input) setTimeout(() => input.focus(), 100);
        } else {
          clearPreview();
        }
      }).observe(modal, { attributes: true, attributeFilter: ["class"] });
    }

    // Stagger animation on results re-render
    const container = document.getElementById("spotlight-results-container") || document.body;
    new MutationObserver(function (mutations) {
      mutations.forEach(function (m) {
        if (m.addedNodes.length) applyStaggerDelays(container);
      });
    }).observe(container, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  // ============================================================================
  // EXPORT
  // ============================================================================

  window.spotlightSearch = {
    fuzzyMatch,
    searchFeatures,
    getRecentSearches,
    clearRecentSearches,
    removeRecentSearch,
    groupByCategory,
    getAllCategories,
    getAutocompleteSuggestions,
    recordFeatureAccess,
    getTopFeatures,
    getSearchAnalytics,
    parseNLPIntent,
    getPredictiveSuggestions,
  };

  console.log("✨ Spotlight loaded (search · NLP · preview · click-to-open)");
})();
