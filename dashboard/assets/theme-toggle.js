/**
 * Early theme apply — adds body.dark-mode from the saved preference before
 * Dash hydrates, so dark-mode users never see light-styled components flash.
 * The authoritative theme logic (including live switching and "auto") is the
 * clientside theme applicator in callbacks_global.py; this only covers the
 * window between first paint and hydration.
 */
(function () {
  "use strict";
  try {
    var theme = localStorage.getItem("iotsentinel-theme") || "light";
    var dark =
      theme === "dark" ||
      (theme === "auto" &&
        window.matchMedia &&
        window.matchMedia("(prefers-color-scheme: dark)").matches);
    if (dark) {
      document.body.classList.add("dark-mode");
    }
  } catch (e) {
    /* localStorage unavailable (private mode) — default light */
  }
})();
