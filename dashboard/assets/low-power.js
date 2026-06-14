/* IoTSentinel — low-power.js
 * Auto-applies body.low-power when the browser is on a Pi-class device.
 * Detection signals (any one triggers low-power unless overridden):
 *   - navigator.hardwareConcurrency ≤ 4  (Pi 4: 4 cores)
 *   - navigator.deviceMemory ≤ 4         (Pi 4: 4 GB; API absent → skip)
 *   - prefers-reduced-motion: reduce      (user/OS accessibility preference)
 * The user can pin the setting via the Preferences toggle, which stores its
 * choice in localStorage under "iotsentinel-low-power" ("1" = on, "0" = off).
 */
(function () {
  var KEY = "iotsentinel-low-power";
  var stored = localStorage.getItem(KEY);

  function applyLowPower(on) {
    document.body.classList.toggle("low-power", on);
  }

  if (stored === "1") {
    applyLowPower(true);
  } else if (stored === "0") {
    applyLowPower(false);
  } else {
    var cores = navigator.hardwareConcurrency || 4;
    var mem   = navigator.deviceMemory;           // undefined if API absent
    var reducedMotion = window.matchMedia &&
                        window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    var isPiClass = (cores <= 4) ||
                    (mem !== undefined && mem <= 4) ||
                    reducedMotion;

    applyLowPower(isPiClass);
  }
})();
