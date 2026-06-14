/* IoTSentinel Keyboard Shortcuts
 *
 * Cmd+K / Ctrl+K    → Spotlight search   (handled by spotlight-search.js)
 * Escape            → Close overlay, then close any open modal
 * Cmd+Shift+L       → Emergency Lockdown
 * Cmd+Shift+C       → Open AI Chat
 * Cmd+\             → Toggle dark / light mode
 * /                 → Show / hide shortcuts overlay
 */
(function () {
  if (window._iotShortcutsLoaded) return;
  window._iotShortcutsLoaded = true;

  function getOverlay() {
    return document.getElementById("shortcuts-overlay");
  }

  function showOverlay() {
    const o = getOverlay();
    if (o) o.style.display = "flex";
  }

  function hideOverlay() {
    const o = getOverlay();
    if (o) o.style.display = "none";
  }

  function isOverlayVisible() {
    const o = getOverlay();
    return o ? o.style.display !== "none" : false;
  }

  // Close overlay when clicking outside the card
  document.addEventListener("click", function (e) {
    const o = getOverlay();
    if (!o || o.style.display === "none") return;
    if (!e.target.closest(".shortcuts-overlay-card")) hideOverlay();
  });

  document.addEventListener("keydown", function (e) {
    const tag = e.target.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || e.target.isContentEditable) return;

    // Cmd+Shift+L / Ctrl+Shift+L — Emergency Lockdown
    if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === "l") {
      e.preventDefault();
      const btn = document.getElementById("spotlight-emergency-lockdown-btn");
      if (btn) btn.click();
      return;
    }

    // Escape — close overlay first; then actively close any open modal so Dash
    // state stays in sync (Bootstrap keyboard=True closes the visual, clicking
    // the X button also fires the Dash callback).
    if (e.key === "Escape") {
      if (isOverlayVisible()) {
        e.preventDefault();
        hideOverlay();
        return;
      }
      // Click the top-most modal's close button so is_open syncs back to Dash
      const modals = document.querySelectorAll(".modal.show");
      if (modals.length > 0) {
        const top = modals[modals.length - 1];
        const closeBtn = top.querySelector('[aria-label="Close"]');
        if (closeBtn) closeBtn.click();
      }
      return;
    }

    // Cmd+Shift+C / Ctrl+Shift+C — Open AI Chat
    if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === "c") {
      e.preventDefault();
      const chatBtn = document.getElementById("open-chat-button");
      if (chatBtn) chatBtn.click();
      return;
    }

    // Cmd+\ / Ctrl+\ — Toggle dark / light mode
    if ((e.metaKey || e.ctrlKey) && e.key === "\\") {
      e.preventDefault();
      const darkBtn = document.getElementById("dark-mode-toggle");
      if (darkBtn) darkBtn.click();
      return;
    }

    // / (no modifiers) — toggle shortcuts overlay
    // Same pattern as GitHub, Notion, Linear. Shift+/ (i.e. ?) is NOT needed.
    if (e.key === "/" && !e.metaKey && !e.ctrlKey && !e.altKey && !e.shiftKey) {
      e.preventDefault();
      isOverlayVisible() ? hideOverlay() : showOverlay();
      return;
    }
  });

  console.log("⌨️  Shortcuts: Cmd+K · Cmd+Shift+L · Cmd+Shift+C · Cmd+\\ · / · Esc");
})();
