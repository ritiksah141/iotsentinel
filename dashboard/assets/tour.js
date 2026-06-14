/* IoTSentinel Interactive Product Tour
 *
 * Uses driver.js v1.3.5 (vendored at assets/driver.min.js) to walk users
 * through every AI feature with element highlighting and a Skip option.
 *
 * Public API:
 *   window.startIotTour()  -- start or restart the tour
 *   window._iotTourDrv     -- live driver instance
 *
 * On finish or skip: clicks #tour-complete-sentinel so the Dash
 * clientside callback can persist completion to onboarding-store.
 */
(function () {
  if (window._iotTourLoaded) return;
  window._iotTourLoaded = true;

  // -----------------------------------------------------------------------
  // Tour step definitions
  // -----------------------------------------------------------------------
  var STEPS = [
    // 1 - Welcome (centred, no element target)
    {
      popover: {
        title: '<img src="/assets/logo.png" style="height:26px;vertical-align:middle;margin-right:8px;border-radius:4px;"> Welcome to IoTSentinel',
        description:
          '<p>This quick tour walks you through every AI-powered feature in about 2 minutes.</p>' +
          '<p>IoTSentinel uses <strong>machine learning</strong> and a multi-tier <strong>AI engine</strong> ' +
          '(Groq, OpenAI, local Ollama, or smart templates) to secure your home network around the clock.</p>' +
          '<p class="iot-tour-hint">Use <strong>Next</strong> and <strong>Prev</strong> to navigate. ' +
          'Click <strong>&times;</strong> to skip at any time.</p>',
        side: 'over',
        align: 'center',
      },
    },

    // 2 - Security score
    {
      element: '#security-score-section',
      popover: {
        title: '&#x1F4CA; Live Security Score',
        description:
          '<p>Your real-time security score (0-100) rolls up device health, open alerts, ' +
          'and network risk into one number, updated continuously.</p>' +
          '<p>IoTSentinel\'s <strong>River ML</strong> engine learns your network from the very first ' +
          'packet - no manual setup needed. Accuracy improves over the first 24-48 hours.</p>',
        side: 'bottom',
        align: 'start',
      },
    },

    // 3 - Network Briefing card
    {
      element: '#tour-ai-briefing-card',
      popover: {
        title: '&#x1F4E1; Network Briefing',
        description:
          '<p>An AI-generated plain-English summary of your network\'s current state, ' +
          'refreshed every 10 minutes or on demand.</p>' +
          '<p>The coloured badge next to the title (e.g. <strong>Groq AI</strong> or ' +
          '<strong>Local AI</strong>) shows exactly which provider wrote it. ' +
          'Every AI surface in IoTSentinel is labelled this way.</p>',
        side: 'bottom',
        align: 'start',
      },
    },

    // 4 - AI Insights card
    {
      element: '#tour-ai-insights-card',
      popover: {
        title: '&#x1F4A1; AI Insights',
        description:
          '<p>2-3 bite-size facts grounded in your live network data: new devices spotted, ' +
          'alert spikes, unusual traffic, and good-news lines like ' +
          '"no critical alerts today."</p>' +
          '<p>These are derived from your own data, not generic security tips.</p>',
        side: 'bottom',
        align: 'end',
      },
    },

    // 5 - Weekly story (target inner content, not full card)
    {
      element: '#weekly-story-content',
      popover: {
        title: '&#x1F4D6; This Week on Your Network',
        description:
          '<p>Each week the AI narrates what happened on your network in warm, plain English: ' +
          'alerts handled, new devices, bandwidth trends, busiest device, and more.</p>' +
          '<p><em>No other home-security product generates a personalised, AI-narrated ' +
          'weekly story from your own data.</em></p>' +
          '<p class="iot-tour-hint">Click <strong>Refresh</strong> to generate it now. ' +
          'Works fully offline via the Smart Template fallback.</p>',
        side: 'top',
        align: 'center',
      },
    },

    // 6 - Security Alerts card on Overview page
    {
      element: '#tour-alerts-card',
      popover: {
        title: '&#x1F6A8; Plain-English Alerts',
        description:
          '<p>Every alert is <strong>rewritten in plain English by AI</strong> before you see it, ' +
          'so you never need to decode raw threat logs.</p>' +
          '<p>Click any alert card, then hit <strong>Ask AI</strong> to start a per-alert chat. ' +
          'Quick chips ("Why is this bad?", "What should I do?") let you drill into ' +
          'any alert in seconds - grounded in real device context.</p>',
        side: 'top',
        align: 'center',
      },
    },

    // 7 - AI chat + NL-to-SQL
    {
      element: '#open-chat-button',
      popover: {
        title: '&#x1F4AC; AI Assistant and Network Queries',
        description:
          '<p>Ask anything about your network in natural language. Try:</p>' +
          '<ul style="padding-left:1.2rem;margin:.25rem 0">' +
          '<li>"Show me high-risk devices"</li>' +
          '<li>"Did any device contact a flagged IP this week?"</li>' +
          '</ul>' +
          '<p>The AI translates your question into a safe, read-only database query ' +
          'and answers in plain English with a results table.</p>' +
          '<p class="iot-tour-hint">Shortcut: <kbd>Ctrl+Shift+C</kbd> / <kbd>&#x2318;&#x21E7;C</kbd></p>',
        side: 'bottom',
        align: 'end',
      },
    },

    // 8 - Autonomous security agent
    {
      element: '#open-agent-button',
      popover: {
        title: '&#x1F575;&#xFE0F; Autonomous Security Agent',
        description:
          '<p>The Security Agent runs every 60 seconds. On a critical threat it acts immediately: ' +
          'checks connection history, looks up IPs against AbuseIPDB threat intelligence, ' +
          'and blocks at the firewall if needed.</p>' +
          '<p>A badge shows pending actions awaiting your review. Open the panel to see every ' +
          'investigation as a colour-coded timeline with step-by-step AI reasoning.</p>' +
          '<p class="iot-tour-hint">New devices trigger an NVD CVE scan and Trust/Block triage automatically.</p>',
        side: 'bottom',
        align: 'end',
      },
    },

    // 9 - AI privacy mode (centred - setting lives in Edit Profile modal, not sidebar)
    {
      popover: {
        title: '&#x1F512; AI Privacy Mode',
        description:
          '<p>Every AI surface shows which provider generated its text ' +
          '(Groq AI, Local AI, Smart Template) so there are no surprises.</p>' +
          '<p>To run <strong>fully on-device</strong>, open the <strong>Profile menu</strong> ' +
          '(top-right corner) and go to <strong>Edit Profile &rsaquo; AI Settings</strong>. ' +
          'Toggle <strong>Privacy Mode</strong> and all AI calls go to your local Ollama ' +
          'model first - your data never leaves the house.</p>',
        side: 'over',
        align: 'center',
      },
    },

    // 10 - Wrap-up (centred)
    {
      popover: {
        title: '&#x1F389; You\'re All Set!',
        description:
          '<p>IoTSentinel is monitoring your network continuously.</p>' +
          '<div class="iot-tour-shortcuts">' +
          '<strong>Keyboard shortcuts</strong><br>' +
          '<span><kbd>Ctrl+K</kbd> / <kbd>&#x2318;K</kbd> &nbsp; Spotlight search</span><br>' +
          '<span><kbd>Ctrl+Shift+C</kbd> / <kbd>&#x2318;&#x21E7;C</kbd> &nbsp; AI chat</span><br>' +
          '<span><kbd>Ctrl+Shift+L</kbd> / <kbd>&#x2318;&#x21E7;L</kbd> &nbsp; Emergency Lockdown</span>' +
          '</div>' +
          '<p class="iot-tour-hint">Restart this tour any time from the <strong>Profile menu</strong> (top-right corner).</p>',
        side: 'over',
        align: 'center',
        doneBtnText: 'Start Exploring &#x1F680;',
      },
    },
  ];

  // -----------------------------------------------------------------------
  // Helper: click sentinel so Dash persists completion
  // -----------------------------------------------------------------------
  function markComplete() {
    var btn = document.getElementById('tour-complete-sentinel');
    if (btn) btn.click();
  }

  // -----------------------------------------------------------------------
  // Main entry point
  // -----------------------------------------------------------------------
  window.startIotTour = function () {
    var driverFn =
      window.driver && window.driver.js && window.driver.js.driver;
    if (!driverFn) {
      console.warn('[iot-tour] driver.js not ready, retry in 300 ms');
      setTimeout(window.startIotTour, 300);
      return;
    }

    if (window._iotTourDrv && window._iotTourDrv.isActive()) {
      window._iotTourDrv.destroy();
    }

    var drv = driverFn({
      animate: true,
      showProgress: true,
      progressText: '{{current}} of {{total}}',
      allowClose: true,
      overlayClickBehavior: 'close',
      smoothScroll: false,
      stagePadding: 6,
      stageRadius: 6,
      popoverClass: 'iot-tour-theme',
      nextBtnText: 'Next &#8250;',
      prevBtnText: '&#8249; Prev',
      doneBtnText: 'Done',
      steps: STEPS,
      onDestroyed: function () {
        markComplete();
        // Restore scrollIntoView patch
        Element.prototype.scrollIntoView = _origScrollIntoView;
        // Restore body and scroll position after tour ends
        document.body.style.removeProperty('overflow');
        document.body.style.removeProperty('padding-right');
        document.body.classList.remove('driver-active', 'driver-fade', 'driver-simple');
        window.scrollTo(0, 0);
      },
    });

    window._iotTourDrv = drv;

    // Patch scrollIntoView so driver.js inline:"center" doesn't drift layout horizontally
    var _origScrollIntoView = Element.prototype.scrollIntoView;
    Element.prototype.scrollIntoView = function (opts) {
      if (opts && typeof opts === 'object') {
        opts = Object.assign({}, opts, { inline: 'nearest' });
      }
      return _origScrollIntoView.call(this, opts);
    };

    drv.drive();
  };

  console.log('[iot-tour] loaded');
})();
