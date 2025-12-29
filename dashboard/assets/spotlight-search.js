/**
 * Spotlight-like Universal Search for IoTSentinel
 * Provides fuzzy search across all dashboard features and modals
 * with keyboard shortcuts (Cmd+K / Ctrl+K)
 */

(function () {
  "use strict";

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

  /**
   * Search function that returns ranked results
   * @param {string} query - Search query
   * @param {Array} featureCatalog - Array of feature objects
   * @param {number} maxResults - Maximum number of results to return
   * @returns {Array} - Sorted array of matching features
   */
  function searchFeatures(query, featureCatalog, maxResults = 10) {
    if (!query || query.trim() === "") {
      return featureCatalog.slice(0, maxResults);
    }

    const results = [];

    featureCatalog.forEach((feature) => {
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
          score: bestScore
        });
      }
    });

    // Sort by score (descending) and limit results
    return results
      .sort((a, b) => b.score - a.score)
      .slice(0, maxResults);
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
    searchFeatures
  };

  console.log("✨ Spotlight Search loaded");
})();
