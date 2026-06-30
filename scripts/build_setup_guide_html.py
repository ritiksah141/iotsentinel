#!/usr/bin/env python3
"""
build_setup_guide_html.py — turn docs/START_HERE.md into a single, fully self-contained
IoTSentinel-Setup-Guide.html that ships inside the downloaded image package.

Non-technical buyers won't open a .md on GitHub, so the release/artifact includes a
double-clickable HTML. It is rendered entirely at BUILD time (Python `markdown`) and
all images - the IoTSentinel logo, screenshots, and the flow diagram - are inlined
(base64 data URIs / inline SVG). The page is fully **offline**: no CDN, no external
files, no network. The only scripting is a small block of inline vanilla JavaScript for
navigation (table of contents, reading progress, dark mode, back-to-top), so it stays
usable on the same phone joined to the offline IoTSentinel-Setup hotspot and degrades
to a readable document if JS is off.

The colour grading mirrors the in-app dashboard tokens (zinc/monochrome surfaces with a
slate accent, plus a matching dark mode) so the guide feels like part of the product.

Usage:
    python scripts/build_setup_guide_html.py [output.html] [source.md]
Defaults: output = IoTSentinel-Setup-Guide.html, source = docs/START_HERE.md
"""
import base64
import io
import re
import sys
from pathlib import Path

import markdown  # required (pure-Python); install with: pip install markdown

REPO = Path(__file__).resolve().parent.parent
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "IoTSentinel-Setup-Guide.html"
SRC = Path(sys.argv[2]) if len(sys.argv) > 2 else REPO / "docs" / "START_HERE.md"
LOGO = REPO / "dashboard" / "assets" / "logo.png"

MAX_IMG_WIDTH = 1100   # screenshots are 1600-2560px wide; shrink to keep the file small

# The setup flow, rendered in the guide as a compact, wrapping, tap-to-tick checklist
# instead of the long static flow-diagram SVG. (title, detail) — detail may be "".
FLOW_STEPS = [
    ("Download the IoTSentinel image", ""),
    ("Flash it to the SD card", "Raspberry Pi Imager - skip every prompt (click No)"),
    ("Put the card in the Pi and power on", "No screen or keyboard needed"),
    ("Wait about 2 minutes", "First-boot setup runs on its own"),
    ("Join the open Wi-Fi on your phone", "Network name: IoTSentinel-Setup"),
    ("Open the setup page", "https://10.42.0.1:8050/setup - your browser warns the connection is not private (expected for a local device); tap Advanced then Proceed"),
    ("Run the whole wizard", "Set your password, type your home Wi-Fi name, choose alerts and mode - all while staying on the setup hotspot"),
    ("Finish setup", "Only now does the Pi join your home Wi-Fi and close the setup hotspot"),
    ("Reconnect your phone to your home Wi-Fi", "The setup hotspot is gone now"),
    ("Open the dashboard", "https://iotsentinel.local:8050 (accept the one-time not-private warning)"),
    ("Live monitoring", "Devices, alerts, security score"),
    ("Turn on remote access (optional)", "Quick Settings -> Network -> Enable Remote Access - reach the dashboard from anywhere"),
]


def render_flow() -> str:
    """Build the interactive 'setup at a glance' checklist that replaces the long
    static flow SVG: a responsive wrapping grid of numbered steps you tap to tick off."""
    items = []
    for i, (title, sub) in enumerate(FLOW_STEPS, 1):
        sub_html = f"<small>{sub}</small>" if sub else ""
        items.append(
            f'<li><button class="flow-step" type="button" aria-pressed="false">'
            f'<span class="flow-num">{i}</span>'
            f'<span class="flow-text"><b>{title}</b>{sub_html}</span>'
            f'<span class="flow-check" aria-hidden="true">&#10003;</span>'
            f'</button></li>'
        )
    return (
        '<div class="flow" id="setupFlow">'
        '<div class="flow-head"><strong>Setup at a glance</strong>'
        f'<span class="flow-progress" id="flowProgress">0 / {len(FLOW_STEPS)} done</span>'
        '<span class="flow-hint">Tap each step to tick it off as you go.</span></div>'
        '<ol class="flow-grid">' + "".join(items) + "</ol></div>"
    )

# Placeholder-based template (NOT str.format) so the inline CSS/JS braces stay readable.
# Palette tokens mirror dashboard/assets/custom.css (--surface-*/--ink-*/--info etc.).
TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IoTSentinel - Setup Guide</title>
<style>
  :root {
    /* In-app light tokens (zinc surfaces, near-black ink, slate accent) */
    --accent:#18181b; --link:#475569; --ink:#18181b; --muted:#52525b;
    --line:rgba(0,0,0,.08); --line-strong:rgba(0,0,0,.12);
    --bg:#f4f4f5; --card:#ffffff; --code:#f4f4f5; --quote:#f4f4f5;
    --header:rgba(244,244,245,.85); --shadow:rgba(20,30,50,.06);
  }
  html[data-theme="dark"] {
    /* In-app dark tokens */
    --accent:#fafafa; --link:#94a3b8; --ink:#fafafa; --muted:#c4c4cc;
    --line:rgba(255,255,255,.10); --line-strong:rgba(255,255,255,.16);
    --bg:#09090b; --card:#1c1c23; --code:#1c1c23; --quote:#15171c;
    --header:rgba(9,9,11,.85); --shadow:rgba(0,0,0,.5);
  }
  * { box-sizing:border-box; }
  html { scroll-behavior:smooth; }
  body { margin:0; background:var(--bg); color:var(--ink);
         font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
         -webkit-text-size-adjust:100%; }

  /* Sticky header + reading-progress bar */
  header.topbar { position:sticky; top:0; z-index:50; backdrop-filter:saturate(160%) blur(12px);
    -webkit-backdrop-filter:saturate(160%) blur(12px); background:var(--header);
    border-bottom:1px solid var(--line); }
  .topbar-inner { max-width:1180px; margin:0 auto; padding:10px 18px; display:flex;
    align-items:center; gap:12px; }
  .brand { font-weight:800; letter-spacing:.01em; color:var(--ink);
    display:flex; align-items:center; gap:10px; font-size:1.05rem; }
  .brand-logo { height:30px; width:auto; display:block; }
  .spacer { flex:1; }
  .btn-ghost { font:inherit; font-size:.9rem; color:var(--ink); background:transparent;
    border:1px solid var(--line-strong); border-radius:999px; padding:6px 12px; cursor:pointer; }
  .btn-ghost:hover { border-color:var(--ink); }
  #progress { height:3px; background:var(--accent); width:0%; transition:width .1s linear; }

  /* Layout: TOC sidebar + content */
  .layout { max-width:1180px; margin:0 auto; padding:24px 18px 90px;
    display:grid; grid-template-columns:260px minmax(0,1fr); gap:28px; align-items:start; }
  nav.toc { position:sticky; top:78px; max-height:calc(100vh - 96px); overflow:auto;
    background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px 12px; }
  nav.toc .toc-title { font-size:.72rem; text-transform:uppercase; letter-spacing:.08em;
    color:var(--muted); margin:2px 8px 8px; }
  nav.toc a { display:block; color:var(--muted); text-decoration:none; font-size:.9rem;
    padding:6px 10px; border-radius:8px; border-left:2px solid transparent; }
  nav.toc a:hover { background:var(--bg); color:var(--ink); }
  nav.toc a.active { color:var(--ink); border-left-color:var(--accent);
    background:var(--bg); font-weight:600; }

  .card { background:var(--card); border:1px solid var(--line); border-radius:16px;
    padding:28px 34px; box-shadow:0 6px 24px var(--shadow); }
  h1 { font-size:2rem; margin:.1em 0 .5em; line-height:1.2; }
  h2 { font-size:1.35rem; margin:1.8em 0 .5em; padding-top:.7em; border-top:1px solid var(--line); }
  h3 { font-size:1.08rem; margin:1.3em 0 .4em; }
  h1,h2,h3 { color:var(--ink); scroll-margin-top:84px; }
  a { color:var(--link); }
  code { background:var(--code); padding:.12em .4em; border-radius:6px; font-size:.92em; }
  pre code { display:block; padding:12px 14px; overflow:auto; }
  blockquote { margin:1em 0; padding:.7em 1em; background:var(--quote);
    border-left:3px solid var(--link); border-radius:0 8px 8px 0; color:var(--ink); }
  table { border-collapse:collapse; width:100%; margin:1em 0; display:block; overflow-x:auto; }
  th,td { border:1px solid var(--line-strong); padding:9px 12px; text-align:left; vertical-align:top; }
  th { background:var(--bg); }
  ol,ul { padding-left:1.4em; }
  li { margin:.3em 0; }
  img { max-width:100%; height:auto; display:block; margin:1.2em auto; border-radius:12px;
    border:1px solid var(--line); box-shadow:0 4px 18px var(--shadow); }
  .diagram { text-align:center; margin:1.4em 0; }
  .diagram svg { max-width:520px; height:auto; }

  /* Interactive 'setup at a glance' checklist (replaces the long flow SVG) */
  .flow { margin:1.5em 0; border:1px solid var(--line); border-radius:14px;
    background:var(--bg); padding:14px 14px 8px; }
  .flow-head { margin:0 4px 12px; font-size:.95rem; }
  .flow-progress { color:var(--link); font-weight:700; margin-left:10px; }
  .flow-hint { display:block; color:var(--muted); font-size:.84rem; margin-top:2px; }
  .flow-grid { list-style:none; margin:0; padding:0; display:grid;
    grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:10px; }
  .flow-grid li { margin:0; }
  .flow-step { width:100%; text-align:left; display:flex; align-items:flex-start; gap:10px;
    padding:12px 14px; border:1px solid var(--line-strong); border-radius:12px;
    background:var(--card); color:var(--ink); cursor:pointer; font:inherit;
    transition:border-color .15s, background .15s, transform .05s; }
  .flow-step:hover { border-color:var(--ink); }
  .flow-step:active { transform:scale(.99); }
  .flow-num { flex:0 0 auto; width:26px; height:26px; border-radius:50%; background:var(--accent);
    color:var(--card); display:flex; align-items:center; justify-content:center;
    font-weight:700; font-size:.85rem; }
  .flow-text { flex:1; font-size:.92rem; line-height:1.4; }
  .flow-text small { display:block; color:var(--muted); font-size:.82rem; margin-top:2px; }
  .flow-check { flex:0 0 auto; color:var(--accent); font-weight:800; opacity:0; transition:opacity .15s; }
  .flow-step.done { border-color:var(--accent); background:var(--bg); }
  .flow-step.done .flow-check { opacity:1; }
  .flow-step.done .flow-text { color:var(--muted); }

  footer { text-align:center; color:var(--muted); font-size:.85rem; margin-top:24px; }

  /* Back-to-top */
  .to-top { position:fixed; right:18px; bottom:18px; z-index:60; width:44px; height:44px;
    border-radius:50%; border:1px solid var(--line-strong); background:var(--card); color:var(--ink);
    font-size:1.1rem; cursor:pointer; box-shadow:0 6px 20px var(--shadow);
    opacity:0; pointer-events:none; transition:opacity .2s; }
  .to-top.show { opacity:1; pointer-events:auto; }

  /* Mobile: TOC collapses into a toggle panel, single column */
  @media (max-width:900px) {
    .layout { grid-template-columns:1fr; gap:16px; padding:16px 14px 90px; }
    nav.toc { position:static; max-height:none; display:none; }
    nav.toc.open { display:block; }
    .card { padding:20px 18px; }
    h1 { font-size:1.6rem; }
  }
  @media (min-width:901px) { #tocToggle { display:none; } }
  @media print {
    header.topbar,nav.toc,.to-top,#tocToggle,#themeToggle { display:none !important; }
    body { background:#fff; } .layout { display:block; }
    .card { box-shadow:none; border:none; padding:0; }
  }
</style>
</head>
<body>
<header class="topbar">
  <div class="topbar-inner">
    <span class="brand">__LOGO__IoTSentinel</span>
    <span class="spacer"></span>
    <button id="tocToggle" class="btn-ghost" aria-expanded="false">&#9776; Contents</button>
    <button id="themeToggle" class="btn-ghost" aria-label="Toggle dark mode">&#9790; Theme</button>
  </div>
  <div id="progress" role="progressbar" aria-label="Reading progress"></div>
</header>

<div class="layout">
  <nav class="toc" id="toc" aria-label="Table of contents">
    <div class="toc-title">On this page</div>
  </nav>
  <main>
    <article class="card" id="content">
      __CONTENT__
    </article>
    <footer>IoTSentinel - home network security &middot; github.com/ritiksah141/iotsentinel</footer>
  </main>
</div>

<button class="to-top" id="toTop" aria-label="Back to top">&#8593;</button>

<script>
(function () {
  var content = document.getElementById('content');
  var toc = document.getElementById('toc');
  var heads = content ? content.querySelectorAll('h2, h3') : [];

  function slug(t) {
    return (t || 'section').toLowerCase().trim()
      .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'section';
  }

  // Build the table of contents from the headings (assign stable ids if missing).
  var used = {}, links = [];
  heads.forEach(function (h) {
    var id = h.id || slug(h.textContent);
    while (used[id]) { id = id + '-x'; }
    used[id] = 1; h.id = id;
    var a = document.createElement('a');
    a.href = '#' + id;
    a.textContent = h.textContent;
    if (h.tagName === 'H3') { a.style.paddingLeft = '22px'; a.style.fontSize = '.84rem'; }
    toc.appendChild(a);
    links.push(a);
  });

  // Active-section highlight as you scroll.
  if ('IntersectionObserver' in window && links.length) {
    var byId = {};
    links.forEach(function (a) { byId[a.getAttribute('href').slice(1)] = a; });
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          links.forEach(function (a) { a.classList.remove('active'); });
          var cur = byId[e.target.id];
          if (cur) cur.classList.add('active');
        }
      });
    }, { rootMargin: '-80px 0px -70% 0px' });
    heads.forEach(function (h) { io.observe(h); });
  }

  // Reading-progress bar + back-to-top visibility.
  var bar = document.getElementById('progress');
  var toTop = document.getElementById('toTop');
  function onScroll() {
    var st = document.documentElement.scrollTop || document.body.scrollTop;
    var h = (document.documentElement.scrollHeight - document.documentElement.clientHeight) || 1;
    var pct = Math.min(100, Math.max(0, (st / h) * 100));
    if (bar) bar.style.width = pct + '%';
    if (toTop) toTop.classList.toggle('show', st > 400);
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
  if (toTop) toTop.addEventListener('click', function () {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  // Mobile contents toggle.
  var tocToggle = document.getElementById('tocToggle');
  if (tocToggle) {
    tocToggle.addEventListener('click', function () {
      var open = toc.classList.toggle('open');
      tocToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    toc.addEventListener('click', function (e) {
      if (e.target.tagName === 'A' && window.matchMedia('(max-width:900px)').matches) {
        toc.classList.remove('open');
        tocToggle.setAttribute('aria-expanded', 'false');
      }
    });
  }

  // Dark mode: respect saved choice, else the OS preference.
  var root = document.documentElement;
  var saved = null;
  try { saved = localStorage.getItem('iot-guide-theme'); } catch (e) {}
  if (saved === 'dark' || (saved === null &&
      window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    root.setAttribute('data-theme', 'dark');
  }
  var themeToggle = document.getElementById('themeToggle');
  if (themeToggle) themeToggle.addEventListener('click', function () {
    var dark = root.getAttribute('data-theme') === 'dark';
    root.setAttribute('data-theme', dark ? 'light' : 'dark');
    try { localStorage.setItem('iot-guide-theme', dark ? 'light' : 'dark'); } catch (e) {}
  });

  // Interactive setup checklist: tap a step to tick it off; track progress.
  var flow = document.getElementById('setupFlow');
  if (flow) {
    var steps = flow.querySelectorAll('.flow-step');
    var prog = document.getElementById('flowProgress');
    function refresh() {
      var done = flow.querySelectorAll('.flow-step.done').length;
      if (prog) prog.textContent = done + ' / ' + steps.length + ' done';
    }
    steps.forEach(function (b) {
      b.addEventListener('click', function () {
        var done = b.classList.toggle('done');
        b.setAttribute('aria-pressed', done ? 'true' : 'false');
        refresh();
      });
    });
    refresh();
  }
})();
</script>
</body>
</html>
"""


def _encode_raster(path: Path) -> str | None:
    """Return a base64 data URI for a PNG/JPEG, resized/recompressed when possible."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    mime = "image/png" if path.suffix.lower() == ".png" else "image/jpeg"
    try:
        from PIL import Image  # optional — only to shrink large screenshots
        im = Image.open(io.BytesIO(data))
        if im.width > MAX_IMG_WIDTH:
            h = round(im.height * MAX_IMG_WIDTH / im.width)
            im = im.resize((MAX_IMG_WIDTH, h), Image.LANCZOS)
            buf = io.BytesIO()
            if mime == "image/png":
                im.save(buf, format="PNG", optimize=True)
            else:
                im.convert("RGB").save(buf, format="JPEG", quality=82)
            data = buf.getvalue()
    except Exception:
        pass  # Pillow missing or odd image — embed the original bytes
    return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"


def embed_images(html: str, base_dir: Path) -> str:
    """Make every <img> self-contained: SVGs are inlined, rasters become data URIs."""
    def repl(m: re.Match) -> str:
        tag = m.group(0)
        src_m = re.search(r'src="([^"]+)"', tag)
        if not src_m:
            return tag
        src = src_m.group(1)
        if src.startswith(("http://", "https://", "data:")):
            return tag
        # Replace the long static flow diagram with the interactive checklist.
        if Path(src).name == "setup-flow.svg":
            return render_flow()
        path = (base_dir / src).resolve()
        if path.suffix.lower() == ".svg":
            try:
                return f'<div class="diagram">{path.read_text(encoding="utf-8")}</div>'
            except OSError:
                print(f"WARNING: svg not found: {src}", file=sys.stderr)
                return tag
        uri = _encode_raster(path)
        if uri is None:
            print(f"WARNING: image not found: {src}", file=sys.stderr)
            return tag
        return re.sub(r'src="[^"]+"', f'src="{uri}"', tag)
    return re.sub(r"<img\b[^>]*>", repl, html)


def main() -> int:
    if not SRC.exists():
        print(f"ERROR: source not found: {SRC}", file=sys.stderr)
        return 1
    md_text = SRC.read_text(encoding="utf-8")
    body = markdown.markdown(
        md_text,
        extensions=["tables", "fenced_code", "sane_lists", "attr_list", "toc"],
    )
    body = embed_images(body, SRC.parent)

    # Inline the real product logo (replaces the placeholder coloured box). If the logo
    # is missing we simply fall back to the wordmark alone.
    logo_uri = _encode_raster(LOGO)
    logo_html = (f'<img class="brand-logo" src="{logo_uri}" alt="IoTSentinel logo">'
                 if logo_uri else "")
    if logo_uri is None:
        print(f"WARNING: logo not found: {LOGO}", file=sys.stderr)

    html = TEMPLATE.replace("__CONTENT__", body).replace("__LOGO__", logo_html)
    OUT.write_text(html, encoding="utf-8")
    print(f"Wrote {OUT} ({OUT.stat().st_size // 1024} KB, offline/self-contained) from {SRC.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
