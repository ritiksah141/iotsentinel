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

  const RECENT_SEARCHES_KEY = 'iotsentinel_recent_searches';
  const MAX_RECENT_SEARCHES = 5;

  /**
   * Save a search query to recent searches
   * @param {string} query - Search query to save
   */
  function saveRecentSearch(query) {
    if (!query || query.trim().length < 2) return;

    try {
      let recent = JSON.parse(localStorage.getItem(RECENT_SEARCHES_KEY) || '[]');

      // Remove if already exists (to move to top)
      recent = recent.filter(q => q.toLowerCase() !== query.toLowerCase());

      // Add to beginning
      recent.unshift(query.trim());

      // Limit to MAX_RECENT_SEARCHES
      recent = recent.slice(0, MAX_RECENT_SEARCHES);

      localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(recent));
    } catch (e) {
      console.warn('Failed to save recent search:', e);
    }
  }

  /**
   * Get recent searches from localStorage
   * @returns {Array} - Array of recent search strings
   */
  function getRecentSearches() {
    try {
      return JSON.parse(localStorage.getItem(RECENT_SEARCHES_KEY) || '[]');
    } catch (e) {
      console.warn('Failed to load recent searches:', e);
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
      console.warn('Failed to clear recent searches:', e);
    }
  }

  /**
   * Remove a specific recent search
   * @param {string} query - Search query to remove
   */
  function removeRecentSearch(query) {
    try {
      let recent = JSON.parse(localStorage.getItem(RECENT_SEARCHES_KEY) || '[]');
      recent = recent.filter(q => q !== query);
      localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(recent));
    } catch (e) {
      console.warn('Failed to remove recent search:', e);
    }
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

    for (let i = 0; i < targetString.length && searchIndex < searchTerm.length; i++) {
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
  function searchFeatures(query, featureCatalog, maxResults = 50, categoryFilter = null) {
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
        categoryFilter: categoryFilter
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
          originalIndex: index
        });
      }
    });

    // Sort by score (descending)
    let sortedResults = results.sort((a, b) => b.score - a.score);

    // Apply category filter if specified
    if (categoryFilter) {
      sortedResults = sortedResults.filter(r => r.category === categoryFilter);
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
      categoryFilter: categoryFilter
    };
  }

  /**
   * Group results by category
   * @param {Array} results - Search results
   * @returns {Object} - Object with category names as keys and arrays of results as values
   */
  function groupByCategory(results) {
    const grouped = {};

    results.forEach(result => {
      const cat = result.category || 'Other';
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
    catalog.forEach(item => {
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

    catalog.forEach(feature => {
      // Add matching feature names
      if (feature.name.toLowerCase().includes(lowerQuery)) {
        suggestions.add(feature.name);
      }

      // Add matching keywords
      feature.keywords.forEach(keyword => {
        if (keyword.toLowerCase().includes(lowerQuery)) {
          suggestions.add(keyword);
        }
      });
    });

    return Array.from(suggestions).slice(0, 5);
  }

  // Cmd+K / Ctrl+K shortcut to open search
  document.addEventListener('keydown', function(e) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      const spotlightBtn = document.getElementById('spotlight-search-button');
      if (spotlightBtn) {
        spotlightBtn.click();
      }
    }
  });

  /**
   * Auto-focus search input when modal opens
   */
  const modalObserver = new MutationObserver(function() {
    const modal = document.getElementById('spotlight-search-modal');
    if (modal && modal.classList.contains('show')) {
      const input = document.getElementById('spotlight-search-input');
      if (input) {
        setTimeout(() => input.focus(), 100);
      }
    }
  });

  // Start observing when DOM is ready
  document.addEventListener('DOMContentLoaded', function() {
    // Observe modal for open/close to auto-focus input
    const modal = document.getElementById('spotlight-search-modal');
    if (modal) {
      modalObserver.observe(modal, {
        attributes: true,
        attributeFilter: ['class']
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
    getAutocompleteSuggestions
  };

  console.log("✨ Spotlight Search loaded (Enhanced Edition - Full Features)");
})();
