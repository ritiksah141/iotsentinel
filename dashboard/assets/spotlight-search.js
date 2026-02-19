/**
 * Spotlight-like Universal Search for IoTSentinel
 * Provides fuzzy search across all dashboard features and modals
 * with keyboard shortcuts (Cmd+K / Ctrl+K)
 * Enhanced with: Top Hit, Category Grouping, Result Count, Recent Searches
 */

(function () {
  "use strict";

  // ============================================================================
  // RECENT SEARCHES - localStorage Management
  // ============================================================================

  const RECENT_SEARCHES_KEY = "iotsentinel_recent_searches";
  const MAX_RECENT_SEARCHES = 5;

  /**
   * Save a search query to recent searches
   * @param {string} query - Search query to save
   */
  function saveRecentSearch(query) {
    if (!query || query.trim().length < 2) return;

    try {
      let recent = JSON.parse(
        localStorage.getItem(RECENT_SEARCHES_KEY) || "[]",
      );

      // Remove if already exists (to move to top)
      recent = recent.filter((q) => q.toLowerCase() !== query.toLowerCase());

      // Add to beginning
      recent.unshift(query.trim());

      // Limit to MAX_RECENT_SEARCHES
      recent = recent.slice(0, MAX_RECENT_SEARCHES);

      localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(recent));
    } catch (e) {
      console.warn("Failed to save recent search:", e);
    }
  }

  /**
   * Get recent searches from localStorage
   * @returns {Array} - Array of recent search strings
   */
  function getRecentSearches() {
    try {
      return JSON.parse(localStorage.getItem(RECENT_SEARCHES_KEY) || "[]");
    } catch (e) {
      console.warn("Failed to load recent searches:", e);
      return [];
    }
  }

  /**
   * Clear all recent searches
   */
  function clearRecentSearches() {
    try {
      localStorage.removeItem(RECENT_SEARCHES_KEY);
    } catch (e) {
      console.warn("Failed to clear recent searches:", e);
    }
  }

  /**
   * Remove a specific recent search
   * @param {string} query - Search query to remove
   */
  function removeRecentSearch(query) {
    try {
      let recent = JSON.parse(
        localStorage.getItem(RECENT_SEARCHES_KEY) || "[]",
      );
      recent = recent.filter((q) => q !== query);
      localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(recent));
    } catch (e) {
      console.warn("Failed to remove recent search:", e);
    }
  }

  // ============================================================================
  // SEARCH ANALYTICS - Track feature access frequency (localStorage)
  // ============================================================================

  const SEARCH_ANALYTICS_KEY = "iotsentinel_search_analytics";

  /**
   * Record a feature access event for analytics.
   * @param {string} featureId - The modal/feature ID
   */
  function recordFeatureAccess(featureId) {
    if (!featureId) return;
    try {
      const analytics = JSON.parse(
        localStorage.getItem(SEARCH_ANALYTICS_KEY) || "{}",
      );
      analytics[featureId] = (analytics[featureId] || 0) + 1;
      localStorage.setItem(SEARCH_ANALYTICS_KEY, JSON.stringify(analytics));
    } catch (e) {
      console.warn("Failed to record feature access:", e);
    }
  }

  /**
   * Get top features sorted by access count.
   * @param {number} limit - Max features to return
   * @returns {Array} - [{id, count}] sorted descending
   */
  function getTopFeatures(limit = 5) {
    try {
      const analytics = JSON.parse(
        localStorage.getItem(SEARCH_ANALYTICS_KEY) || "{}",
      );
      return Object.entries(analytics)
        .map(([id, count]) => ({ id, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, limit);
    } catch (e) {
      return [];
    }
  }

  /**
   * Get the full analytics object.
   * @returns {Object} - featureId → access count
   */
  function getSearchAnalytics() {
    try {
      return JSON.parse(localStorage.getItem(SEARCH_ANALYTICS_KEY) || "{}");
    } catch (e) {
      return {};
    }
  }

  // ============================================================================
  // NLP INTENT ENGINE - Natural Language Query Parsing
  // ============================================================================

  /**
   * Intent map: each entry has pattern strings (substring matches) and the
   * feature IDs to boost when those patterns are found in the query.
   */
  const NLP_INTENT_MAP = [
    {
      patterns: [
        "risky device",
        "dangerous device",
        "vulnerable device",
        "high risk device",
        "show risk",
      ],
      features: [
        { id: "device-mgmt-modal", boost: 50 },
        { id: "risk-heatmap-modal", boost: 60 },
      ],
    },
    {
      patterns: [
        "what threat",
        "show threat",
        "today threat",
        "recent threat",
        "latest threat",
        "attack today",
        "any attack",
      ],
      features: [
        { id: "threat-modal", boost: 60 },
        { id: "threat-map-modal", boost: 50 },
      ],
    },
    {
      patterns: [
        "block device",
        "block untrusted",
        "emergency block",
        "stop device",
        "prevent attack",
      ],
      features: [
        { id: "lockdown-modal", boost: 70 },
        { id: "firewall-modal", boost: 50 },
      ],
    },
    {
      patterns: [
        "check performance",
        "network slow",
        "network speed",
        "how fast",
        "bandwidth",
        "throughput",
      ],
      features: [
        { id: "performance-modal", boost: 60 },
        { id: "analytics-modal", boost: 40 },
      ],
    },
    {
      patterns: [
        "scan network",
        "find device",
        "new device",
        "detect device",
        "discover device",
      ],
      features: [
        { id: "device-mgmt-modal", boost: 50 },
        { id: "vuln-scanner-modal", boost: 60 },
      ],
    },
    {
      patterns: [
        "export data",
        "download report",
        "generate report",
        "get report",
        "export report",
      ],
      features: [{ id: "quick-actions-modal", boost: 60 }],
    },
    {
      patterns: ["emergency", "lockdown", "incident response", "under attack"],
      features: [
        { id: "lockdown-modal", boost: 100 },
        { id: "auto-response-modal", boost: 60 },
      ],
    },
    {
      patterns: [
        "who logged in",
        "user activity",
        "login activity",
        "audit log",
        "user access",
      ],
      features: [
        { id: "compliance-modal", boost: 50 },
        { id: "user-modal", boost: 60 },
      ],
    },
    {
      patterns: [
        "firmware update",
        "device patch",
        "update device",
        "device version",
        "outdated firmware",
      ],
      features: [{ id: "firmware-modal", boost: 60 }],
    },
    {
      patterns: [
        "ai help",
        "ai assistant",
        "ask ai",
        "help me",
        "what should i do",
      ],
      features: [{ id: "chat-modal", boost: 70 }],
    },
    {
      patterns: [
        "data leak",
        "privacy risk",
        "data exposure",
        "private data",
        "data sharing",
      ],
      features: [{ id: "privacy-modal", boost: 60 }],
    },
    {
      patterns: [
        "smart home",
        "alexa",
        "google home",
        "iot hub",
        "home automation",
      ],
      features: [{ id: "smarthome-modal", boost: 60 }],
    },
    {
      patterns: [
        "network traffic",
        "mqtt",
        "http traffic",
        "coap",
        "packet analysis",
      ],
      features: [{ id: "protocol-modal", boost: 60 }],
    },
    {
      patterns: [
        "gdpr",
        "hipaa",
        "compliance check",
        "security standard",
        "regulation",
      ],
      features: [{ id: "compliance-modal", boost: 70 }],
    },
  ];

  /**
   * Parse a natural language query and return NLP feature boosts.
   * @param {string} query - User search query
   * @returns {Array} - [{featureId, boost, pattern}]
   */
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
              matches.push({
                featureId: feature.id,
                boost: feature.boost,
                pattern,
              });
            }
          });
        }
      });
    });

    return matches;
  }

  // ============================================================================
  // FUZZY MATCHING ALGORITHM
  // ============================================================================

  /**
   * Simple fuzzy matching algorithm
   * @param {string} searchTerm - The search query
   * @param {string} targetString - The string to search in
   * @returns {number} - Match score (0 if no match)
   */
  function fuzzyMatch(searchTerm, targetString) {
    searchTerm = searchTerm.toLowerCase();
    targetString = targetString.toLowerCase();

    let searchIndex = 0;
    let score = 0;
    let consecutiveMatches = 0;

    for (
      let i = 0;
      i < targetString.length && searchIndex < searchTerm.length;
      i++
    ) {
      if (targetString[i] === searchTerm[searchIndex]) {
        searchIndex++;
        consecutiveMatches++;
        // Bonus for consecutive matches
        score += 1 + consecutiveMatches;
      } else {
        consecutiveMatches = 0;
      }
    }

    // Full match?
    if (searchIndex === searchTerm.length) {
      // Bonus for exact match
      if (targetString === searchTerm) {
        score += 100;
      }
      // Bonus for match at start
      if (targetString.startsWith(searchTerm)) {
        score += 50;
      }
      return score;
    }

    return 0; // No match
  }

  // ============================================================================
  // SEARCH FUNCTION - Enhanced with metadata
  // ============================================================================

  /**
   * Search function that returns ranked results with metadata
   * @param {string} query - Search query
   * @param {Array} featureCatalog - Array of feature objects
   * @param {number} maxResults - Maximum number of results to return
   * @param {string} categoryFilter - Optional category to filter by
   * @returns {Object} - Object with results, count, categories, top hit, and search stats
   */
  function searchFeatures(
    query,
    featureCatalog,
    maxResults = 50,
    categoryFilter = null,
    contextBoosts = null,
  ) {
    // Performance tracking
    const startTime = performance.now();

    // Save to recent searches if query is valid
    if (query && query.trim().length >= 2) {
      saveRecentSearch(query);
    }

    // Empty query - return featured/popular items
    if (!query || query.trim() === "") {
      const featured = featureCatalog.slice(0, 10);
      const endTime = performance.now();

      return {
        results: featured,
        totalCount: featured.length,
        hasMore: false,
        query: "",
        categories: groupByCategory(featured),
        topHit: featured[0] || null,
        searchTime: (endTime - startTime).toFixed(2),
        categoryFilter: categoryFilter,
      };
    }

    const results = [];

    featureCatalog.forEach((feature, index) => {
      let bestScore = 0;

      // Search in name (highest priority - 3x weight)
      const nameScore = fuzzyMatch(query, feature.name) * 3;
      bestScore = Math.max(bestScore, nameScore);

      // Search in keywords (2x weight)
      feature.keywords.forEach((keyword) => {
        const keywordScore = fuzzyMatch(query, keyword) * 2;
        bestScore = Math.max(bestScore, keywordScore);
      });

      // Search in description (1x weight)
      const descScore = fuzzyMatch(query, feature.description);
      bestScore = Math.max(bestScore, descScore);

      // Search in category (1x weight)
      const catScore = fuzzyMatch(query, feature.category);
      bestScore = Math.max(bestScore, catScore);

      if (bestScore > 0) {
        results.push({
          ...feature,
          score: bestScore,
          originalIndex: index,
        });
      }
    });

    // Apply NLP intent boosts — surfaces features matched via natural language
    const nlpMatches = parseNLPIntent(query);
    if (nlpMatches.length > 0) {
      results.forEach((result) => {
        const nlpMatch = nlpMatches.find((m) => m.featureId === result.id);
        if (nlpMatch) {
          result.score += nlpMatch.boost;
          result.nlpMatch = true;
        }
      });
      // Ensure NLP-only matched features (zero fuzzy score) also appear
      nlpMatches.forEach((nlpMatch) => {
        if (!results.find((r) => r.id === nlpMatch.featureId)) {
          const feature = featureCatalog.find(
            (f) => f.id === nlpMatch.featureId,
          );
          if (feature) {
            results.push({
              ...feature,
              score: nlpMatch.boost,
              nlpMatch: true,
              originalIndex: featureCatalog.indexOf(feature),
            });
          }
        }
      });
    }

    // Apply context-aware boosts from server-side system state (active alerts, CPU)
    if (contextBoosts && typeof contextBoosts === "object") {
      results.forEach((result) => {
        if (contextBoosts[result.id]) {
          result.score += contextBoosts[result.id];
          result.contextBoosted = true;
        }
      });
    }

    // Sort by score (descending)
    let sortedResults = results.sort((a, b) => b.score - a.score);

    // Apply category filter if specified
    if (categoryFilter) {
      sortedResults = sortedResults.filter(
        (r) => r.category === categoryFilter,
      );
    }

    // Get top results
    const limitedResults = sortedResults.slice(0, maxResults);

    const endTime = performance.now();

    return {
      results: limitedResults,
      totalCount: sortedResults.length,
      hasMore: sortedResults.length > maxResults,
      query: query,
      categories: groupByCategory(limitedResults),
      topHit: sortedResults[0] || null,
      searchTime: (endTime - startTime).toFixed(2),
      categoryFilter: categoryFilter,
    };
  }

  /**
   * Group results by category
   * @param {Array} results - Search results
   * @returns {Object} - Object with category names as keys and arrays of results as values
   */
  function groupByCategory(results) {
    const grouped = {};

    results.forEach((result) => {
      const cat = result.category || "Other";
      if (!grouped[cat]) {
        grouped[cat] = [];
      }
      grouped[cat].push(result);
    });

    return grouped;
  }

  /**
   * Get all unique categories from catalog
   * @param {Array} catalog - Feature catalog
   * @returns {Array} - Array of unique category names sorted alphabetically
   */
  function getAllCategories(catalog) {
    const categories = new Set();
    catalog.forEach((item) => {
      if (item.category) {
        categories.add(item.category);
      }
    });
    return Array.from(categories).sort();
  }

  /**
   * Get autocomplete suggestions based on query
   * @param {string} query - Search query
   * @param {Array} catalog - Feature catalog
   * @returns {Array} - Array of suggestion strings
   */
  function getAutocompleteSuggestions(query, catalog) {
    if (!query || query.length < 2) return [];

    const suggestions = new Set();
    const lowerQuery = query.toLowerCase();

    catalog.forEach((feature) => {
      // Add matching feature names
      if (feature.name.toLowerCase().includes(lowerQuery)) {
        suggestions.add(feature.name);
      }

      // Add matching keywords
      feature.keywords.forEach((keyword) => {
        if (keyword.toLowerCase().includes(lowerQuery)) {
          suggestions.add(keyword);
        }
      });
    });

    return Array.from(suggestions).slice(0, 5);
  }

  // ============================================================================
  // PREDICTIVE SUGGESTIONS - Time-of-day + Frequency Based
  // ============================================================================

  /**
   * Build predictive feature suggestions based on time of day and usage history.
   * @param {Array} catalog - Feature catalog
   * @returns {Array} - [{type, label, features}]
   */
  function getPredictiveSuggestions(catalog) {
    const hour = new Date().getHours();
    const suggestions = [];

    let timeLabel, timeFeatureIds;
    if (hour >= 6 && hour < 10) {
      timeLabel = "\uD83C\uDF05 Morning \u2014 recommended checks";
      timeFeatureIds = [
        "analytics-modal",
        "alert-details-modal",
        "device-mgmt-modal",
      ];
    } else if (hour >= 10 && hour < 14) {
      timeLabel = "\u2600\uFE0F Active monitoring";
      timeFeatureIds = [
        "threat-modal",
        "performance-modal",
        "risk-heatmap-modal",
      ];
    } else if (hour >= 14 && hour < 18) {
      timeLabel = "\u2600\uFE0F Afternoon security review";
      timeFeatureIds = ["vuln-scanner-modal", "threat-modal", "firmware-modal"];
    } else if (hour >= 18 && hour < 21) {
      timeLabel = "\uD83C\uDF06 End-of-day summary";
      timeFeatureIds = [
        "compliance-modal",
        "analytics-modal",
        "auto-response-modal",
      ];
    } else {
      timeLabel = "\uD83C\uDF19 Night watch";
      timeFeatureIds = ["system-modal", "performance-modal", "analytics-modal"];
    }

    const resolveFeatures = (ids) =>
      ids.map((id) => catalog.find((f) => f.id === id)).filter(Boolean);

    suggestions.push({
      type: "time",
      label: timeLabel,
      features: resolveFeatures(timeFeatureIds),
    });

    // Frequency-based: user's most accessed features
    const topFeatures = getTopFeatures(3);
    if (topFeatures.length >= 2) {
      const topObjects = topFeatures
        .map((tf) => catalog.find((f) => f.id === tf.id))
        .filter(Boolean);
      if (topObjects.length > 0) {
        suggestions.push({
          type: "frequent",
          label: "\u2B50 Your most used",
          features: topObjects,
          counts: topFeatures.map((tf) => tf.count),
        });
      }
    }

    return suggestions;
  }

  // ============================================================================
  // KEYBOARD NAVIGATION - Track selected result index
  // ============================================================================

  let selectedResultIndex = -1; // -1 means no selection

  /**
   * Get all result items currently visible
   * @returns {Array} - Array of result wrapper elements
   */
  function getResultItems() {
    const containers = document.querySelectorAll(
      '[id*="spotlight-result-item"]',
    );
    return Array.from(containers);
  }

  /**
   * Update visual selection state
   * @param {number} newIndex - Index to select (-1 for none)
   */
  function updateSelection(newIndex) {
    const items = getResultItems();

    // Remove previous selection
    items.forEach((item) => {
      const card = item.querySelector(".spotlight-result-card");
      if (card) {
        card.classList.remove("spotlight-result-selected");
      }
    });

    // Add new selection
    if (newIndex >= 0 && newIndex < items.length) {
      selectedResultIndex = newIndex;
      const card = items[newIndex].querySelector(".spotlight-result-card");
      if (card) {
        card.classList.add("spotlight-result-selected");
        // Scroll into view
        items[newIndex].scrollIntoView({
          behavior: "smooth",
          block: "nearest",
        });
      }
    } else {
      selectedResultIndex = -1;
    }
  }

  /**
   * Navigate to next result
   */
  function selectNext() {
    const items = getResultItems();
    if (items.length === 0) return;

    const newIndex =
      selectedResultIndex < items.length - 1 ? selectedResultIndex + 1 : 0;
    updateSelection(newIndex);
  }

  /**
   * Navigate to previous result
   */
  function selectPrevious() {
    const items = getResultItems();
    if (items.length === 0) return;

    const newIndex =
      selectedResultIndex > 0 ? selectedResultIndex - 1 : items.length - 1;
    updateSelection(newIndex);
  }

  /**
   * Open the currently selected result
   */
  function openSelected() {
    const items = getResultItems();
    if (selectedResultIndex < 0 || selectedResultIndex >= items.length) {
      console.log("[Spotlight] No item selected or out of range");
      return false;
    }

    const item = items[selectedResultIndex];
    const goToBtn = item.querySelector('[id*="spotlight-go-to-btn"]');

    if (goToBtn) {
      console.log("[Spotlight] Clicking button:", goToBtn.id);
      goToBtn.click();
      return true;
    } else {
      console.warn("[Spotlight] No button found in selected item");
    }
    return false;
  }

  /**
   * Reset selection when search changes
   */
  function resetSelection() {
    selectedResultIndex = -1;
    const items = getResultItems();
    items.forEach((item) => {
      const card = item.querySelector(".spotlight-result-card");
      if (card) {
        card.classList.remove("spotlight-result-selected");
      }
    });
  }

  // ============================================================================
  // EMERGENCY KEYBOARD SHORTCUTS - Cmd/Ctrl+Shift+L / E / T
  // ============================================================================

  /**
   * Flash a red visual ring on the page to confirm an emergency action.
   * @param {string} action - 'lockdown' | 'export' | 'threat'
   */
  function triggerEmergencyIndicator(action) {
    document.body.classList.add("spotlight-emergency-active");
    document.body.setAttribute("data-emergency-action", action);
    setTimeout(() => {
      document.body.classList.remove("spotlight-emergency-active");
      document.body.removeAttribute("data-emergency-action");
    }, 1800);
  }

  // Cmd+Shift+L → Lockdown | Cmd+Shift+E → Emergency Export | Cmd+Shift+T → Threat Response
  document.addEventListener("keydown", function (e) {
    if (!(e.metaKey || e.ctrlKey) || !e.shiftKey) return;
    const key = e.key.toLowerCase();
    if (key === "l") {
      e.preventDefault();
      triggerEmergencyIndicator("lockdown");
      const btn = document.getElementById("spotlight-emergency-lockdown-btn");
      if (btn) btn.click();
    } else if (key === "e") {
      e.preventDefault();
      triggerEmergencyIndicator("export");
      const btn = document.getElementById("spotlight-emergency-export-btn");
      if (btn) btn.click();
    } else if (key === "t") {
      e.preventDefault();
      triggerEmergencyIndicator("threat");
      const btn = document.getElementById("spotlight-emergency-threat-btn");
      if (btn) btn.click();
    }
  });

  // Cmd+K / Ctrl+K shortcut to open search
  document.addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === "k") {
      e.preventDefault();
      const spotlightBtn = document.getElementById("spotlight-search-button");
      if (spotlightBtn) {
        spotlightBtn.click();
      }
    }
  });

  /**
   * Keyboard navigation inside spotlight modal
   */
  document.addEventListener("keydown", function (e) {
    const modal = document.getElementById("spotlight-search-modal");
    const input = document.getElementById("spotlight-search-input");

    // Only handle if modal is open
    if (!modal || !modal.classList.contains("show")) {
      return;
    }

    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        selectNext();
        break;

      case "ArrowUp":
        e.preventDefault();
        selectPrevious();
        break;

      case "Tab":
        e.preventDefault();
        if (e.shiftKey) {
          selectPrevious();
        } else {
          selectNext();
        }
        break;

      case "Enter":
        e.preventDefault();
        // If nothing selected, select first item
        if (selectedResultIndex === -1) {
          updateSelection(0);
        }
        // Open the selected item
        const opened = openSelected();
        // Don't manually close - let the Dash callback handle it
        // The clientside callback will close the spotlight modal after opening the target modal
        break;

      case "Escape":
        // Let the default Escape handling close the modal
        resetSelection();
        break;
    }
  });

  /**
   * Auto-focus search input when modal opens and reset selection
   */
  const modalObserver = new MutationObserver(function () {
    const modal = document.getElementById("spotlight-search-modal");
    if (modal && modal.classList.contains("show")) {
      const input = document.getElementById("spotlight-search-input");
      if (input) {
        setTimeout(() => {
          input.focus();
          resetSelection(); // Reset selection when modal opens
        }, 100);
      }
    } else {
      // Modal closed, reset selection
      resetSelection();
    }
  });

  /**
   * Reset selection when search input changes
   */
  document.addEventListener("DOMContentLoaded", function () {
    const input = document.getElementById("spotlight-search-input");
    if (input) {
      input.addEventListener("input", function () {
        // Reset selection when user types
        resetSelection();
      });
    }
  });

  // Start observing when DOM is ready
  document.addEventListener("DOMContentLoaded", function () {
    // Observe modal for open/close to auto-focus input
    const modal = document.getElementById("spotlight-search-modal");
    if (modal) {
      modalObserver.observe(modal, {
        attributes: true,
        attributeFilter: ["class"],
      });
    }
  });

  // Export to window for Dash callbacks
  window.spotlightSearch = {
    fuzzyMatch,
    searchFeatures,
    getRecentSearches,
    clearRecentSearches,
    removeRecentSearch,
    groupByCategory,
    getAllCategories,
    getAutocompleteSuggestions,
    // Search analytics
    recordFeatureAccess,
    getTopFeatures,
    getSearchAnalytics,
    // NLP intent engine
    parseNLPIntent,
    // Predictive suggestions
    getPredictiveSuggestions,
    // Keyboard navigation
    selectNext,
    selectPrevious,
    openSelected,
    resetSelection,
    updateSelection,
  };

  console.log(
    "\u2728 Spotlight Search loaded (Enhanced: NLP + Context Boosts + Emergency Shortcuts + Predictive + Cross-Domain)",
  );
})();
