/**
 * plotly-dark-theme.js
 *
 * Patches Plotly chart backgrounds and text colours for dark mode AFTER each
 * chart render.  CSS !important cannot reliably override Plotly's JS-applied
 * inline SVG styles across all browsers — this JS approach is definitive.
 *
 * Strategy:
 *  1. Listen to the Plotly `plotly_afterplot` CustomEvent (bubbles from each
 *     chart div).  Patch immediately after each render, before the browser
 *     paints — so there is zero white-flash.
 *  2. Watch <body class="…"> via MutationObserver so charts already on screen
 *     are patched the moment the user switches to dark mode.
 *  3. Watch for new chart divs added to the DOM (Dash lazy-renders modals).
 */
(function () {
  'use strict';

  var DARK_FONT  = '#e4e4e7';
  var TRANSPARENT = 'rgba(0,0,0,0)';

  /* Selectors for all text elements Plotly renders */
  var TEXT_SEL = [
    '.gtitle',
    '.g-gtitle text',
    '.xtitle', '.ytitle',
    '.xtick text', '.ytick text',
    '.legendtext',
    '.legend text',
    '.annotation text',
    '.slicetext text',     /* pie / donut labels */
    '.cbfrac text',        /* colorbar tick labels */
    '.cbtitle text',       /* colorbar title */
    '.infolayer text',     /* general info layer */
    '.sankey text',        /* Sankey node labels */
    '.radialaxis text',    /* radar / polar */
    '.angularaxis text',
    '.polarsublayer text',
    '.treemaplayerlayer text',
    '.sunburstlayer text'
  ].join(',');

  function isDark() {
    return document.body.classList.contains('dark-mode');
  }

  /**
   * Patch a single Plotly graph div.
   * Only direct SVG manipulation — does NOT call Plotly.relayout() so there
   * is no risk of triggering infinite re-render loops.
   */
  function patchChart(graphDiv) {
    if (!isDark()) return;

    /* --- container div background (Plotly sets div.style.background = paper_bgcolor) --- */
    graphDiv.style.background = TRANSPARENT;
    graphDiv.style.backgroundColor = TRANSPARENT;

    /* --- SVG element backgrounds --- */
    graphDiv.querySelectorAll('svg').forEach(function (el) {
      el.style.background = TRANSPARENT;
      el.style.backgroundColor = TRANSPARENT;
    });

    /* --- inner SVG rect.bg (also carries paper_bgcolor as SVG fill) --- */
    graphDiv.querySelectorAll('.bg').forEach(function (el) {
      el.style.fill = TRANSPARENT;
    });

    /* --- all chart text --- */
    graphDiv.querySelectorAll(TEXT_SEL).forEach(function (el) {
      el.style.fill = DARK_FONT;
    });

    /* --- axis lines / grid strokes --- */
    graphDiv.querySelectorAll('.xgrid, .ygrid').forEach(function (el) {
      el.style.stroke = 'rgba(255,255,255,0.08)';
    });
    graphDiv.querySelectorAll('.zerolinelayer path').forEach(function (el) {
      el.style.stroke = 'rgba(255,255,255,0.15)';
    });

    /* --- geo chart backgrounds (country fills are SVG paths) --- */
    graphDiv.querySelectorAll('.geo .bg').forEach(function (el) {
      el.style.fill = 'rgba(20,25,40,0.85)';
    });
    graphDiv.querySelectorAll('.geo .land').forEach(function (el) {
      el.style.fill = 'rgb(40,45,60)';
    });
    graphDiv.querySelectorAll('.geo .water').forEach(function (el) {
      el.style.fill = 'rgb(20,25,40)';
    });
  }

  /** Patch every Plotly chart currently in the DOM. */
  function patchAllCharts() {
    if (!isDark()) return;
    document.querySelectorAll('.js-plotly-plot').forEach(patchChart);
    /* Also clear any white background on the .dash-graph wrapper Dash creates */
    document.querySelectorAll('.dash-graph').forEach(function (el) {
      el.style.background = TRANSPARENT;
      el.style.backgroundColor = TRANSPARENT;
    });
  }

  /* ── 1. Post-render hook ──────────────────────────────────────────────── */
  /*
   * plotly_afterplot is dispatched by Plotly.js as a bubbling CustomEvent on
   * the graph div after EVERY render (new data, relayout, etc.).
   * Capture phase (useCapture=true) fires before bubble so we patch the SVG
   * before the browser composites the frame.
   */
  document.addEventListener('plotly_afterplot', function (e) {
    var div = e.target;
    if (div && div.classList && div.classList.contains('js-plotly-plot')) {
      patchChart(div);
    }
  }, true /* capture */);

  /* ── 2. Theme-switch hook ─────────────────────────────────────────────── */
  var themeObs = new MutationObserver(function () {
    patchAllCharts();
  });
  themeObs.observe(document.body, { attributes: true, attributeFilter: ['class'] });

  /* ── 3. New chart divs (modal lazy-render) ───────────────────────────── */
  var domObs = new MutationObserver(function (mutations) {
    if (!isDark()) return;
    var needsPatch = false;
    mutations.forEach(function (m) {
      m.addedNodes.forEach(function (n) {
        if (n.nodeType === 1) needsPatch = true;
      });
    });
    if (needsPatch) {
      /* Small delay — Plotly initialises asynchronously inside new divs. */
      setTimeout(patchAllCharts, 250);
    }
  });
  domObs.observe(document.body, { childList: true, subtree: true });

  /* ── 4. Initial application on page load ─────────────────────────────── */
  document.addEventListener('DOMContentLoaded', function () {
    setTimeout(patchAllCharts, 500);
  });

})();
