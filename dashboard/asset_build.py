"""Boot-time CSS minification for first-party stylesheets.

custom.css (~260 KB) is kept readable for development, but the browser pays
the parse cost of every byte on each cold load — a measurable chunk of the
<100 ms first-paint budget on Pi 4. At app start this module regenerates
``<name>.min.css`` next to each first-party source when stale, and app.py
passes the returned ``assets_ignore`` regex to Dash so only the minified
copies are injected. Vendored files (bootstrap.min.css, fontawesome.min.css,
driver.css) are already minified and left untouched.

If minification fails for any reason the caller receives ``None`` and Dash
falls back to serving the unminified sources — never a broken page.
"""

import logging
import os

logger = logging.getLogger(__name__)

# First-party stylesheets to minify. Dash injects assets alphabetically;
# each <name>.min.css sorts in the same relative position as its source,
# so the cascade order is unchanged.
MINIFY_TARGETS = ('custom.css', 'mobile-responsive.css', 'skeleton.css')

# Anchored so custom.min.css etc. do NOT match (Dash uses re.search on the
# bare filename).
ASSETS_IGNORE_REGEX = r'^(custom|mobile-responsive|skeleton)\.css$'

_WHITESPACE = ' \t\n\r\f'
# Whitespace adjacent to these never separates tokens, so it can be dropped.
# ':' appears only in the prev-set: space *after* a colon is always safe to
# remove, but space *before* one is not (".foo :hover" is a descendant
# selector, distinct from ".foo:hover").
_PREV_NO_SPACE = '{};,>:'
_NEXT_NO_SPACE = '{};,>'


def minify_css(css: str) -> str:
    """Conservative CSS minifier: strips comments, collapses whitespace,
    drops semicolons before ``}``. String literals (and therefore attribute
    selectors, url() quotes and ``content:`` values) pass through untouched.
    Spaces inside ``calc()`` and before ``(`` in media queries are preserved.
    """
    out = []
    i, n = 0, len(css)
    in_str = None
    while i < n:
        c = css[i]
        if in_str:
            out.append(c)
            if c == '\\' and i + 1 < n:
                out.append(css[i + 1])
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in '"\'':
            in_str = c
            out.append(c)
            i += 1
            continue
        if c in _WHITESPACE or css[i:i + 2] == '/*':
            # Consume the whole run of whitespace and comments as one
            # separator, then decide whether a single space must remain.
            j = i
            while j < n:
                if css[j] in _WHITESPACE:
                    j += 1
                elif css[j:j + 2] == '/*':
                    k = css.find('*/', j + 2)
                    j = n if k == -1 else k + 2
                else:
                    break
            i = j
            prev = out[-1] if out else ''
            nxt = css[i] if i < n else ''
            if prev and nxt and prev not in _PREV_NO_SPACE and nxt not in _NEXT_NO_SPACE:
                out.append(' ')
            continue
        if c == ';':
            j = i + 1
            while j < n and css[j] in _WHITESPACE:
                j += 1
            if j < n and css[j] == '}':
                i += 1  # drop the final semicolon in a block
                continue
        out.append(c)
        i += 1
    return ''.join(out).strip()


def ensure_minified_css(assets_dir: str):
    """Regenerate stale ``.min.css`` files for MINIFY_TARGETS.

    Returns the assets_ignore regex for Dash when every target has a fresh
    minified copy, or ``None`` (serve the sources) when anything fails.
    """
    try:
        for name in MINIFY_TARGETS:
            src = os.path.join(assets_dir, name)
            dst = os.path.join(assets_dir, name[:-len('.css')] + '.min.css')
            if not os.path.isfile(src):
                logger.warning("asset_build: %s missing, serving unminified CSS", name)
                return None
            if os.path.isfile(dst) and os.path.getmtime(dst) >= os.path.getmtime(src):
                continue
            with open(src, encoding='utf-8') as fh:
                minified = minify_css(fh.read())
            tmp = dst + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as fh:
                fh.write(minified)
            os.replace(tmp, dst)
            logger.info(
                "asset_build: %s -> %s (%d -> %d bytes)",
                name, os.path.basename(dst),
                os.path.getsize(src), os.path.getsize(dst),
            )
        return ASSETS_IGNORE_REGEX
    except Exception as exc:
        logger.warning("asset_build: minification failed (%s), serving unminified CSS", exc)
        return None


# ---------------------------------------------------------------------------
# PWA icons
# ---------------------------------------------------------------------------
# logo.png is portrait (242x300); PWA/home-screen icons must be square. We pad
# to a square canvas (never crop, so the wordmark is never clipped) and ship a
# transparent set for "any" plus opaque sets for Android maskable masks and iOS
# (which renders transparency as black). Generated at boot — committed copies in
# assets/ mean the PWA works on the very first paint and even if Pillow is absent.
_BRAND_DARK = (15, 23, 42, 255)  # #0f172a — matches the FOUC + manifest background

# (filename, size, opaque_bg, logo_fraction_of_canvas)
_PWA_ICONS = (
    ('icon-192.png', 192, None, 0.92),
    ('icon-512.png', 512, None, 0.92),
    ('icon-maskable-512.png', 512, _BRAND_DARK, 0.70),  # logo inside maskable safe zone
    ('apple-touch-icon.png', 180, _BRAND_DARK, 0.86),   # iOS: opaque, no transparency
)


def _render_icon(logo, size, bg, fraction):
    """Return a square ``size``x``size`` icon with ``logo`` centred at ``fraction``
    of the canvas. ``bg`` None => transparent, else an opaque RGBA fill."""
    from PIL import Image

    canvas = Image.new('RGBA', (size, size), bg if bg else (0, 0, 0, 0))
    box = int(size * fraction)
    lw, lh = logo.size
    scale = min(box / lw, box / lh)
    resized = logo.resize((max(1, int(lw * scale)), max(1, int(lh * scale))), Image.LANCZOS)
    offset = ((size - resized.width) // 2, (size - resized.height) // 2)
    canvas.paste(resized, offset, resized)
    return canvas


def ensure_pwa_icons(assets_dir: str):
    """Regenerate stale PWA icons from ``logo.png``.

    Idempotent: an icon is only rewritten when it is missing or older than the
    source logo. Never raises — on any failure (e.g. Pillow missing) it logs a
    warning and returns, leaving any committed icons in place.
    """
    try:
        from PIL import Image

        logo_path = os.path.join(assets_dir, 'logo.png')
        if not os.path.isfile(logo_path):
            logger.warning("asset_build: logo.png missing, skipping PWA icon generation")
            return
        logo_mtime = os.path.getmtime(logo_path)

        stale = [
            spec for spec in _PWA_ICONS
            if not os.path.isfile(os.path.join(assets_dir, spec[0]))
            or os.path.getmtime(os.path.join(assets_dir, spec[0])) < logo_mtime
        ]
        if not stale:
            return

        logo = Image.open(logo_path).convert('RGBA')
        for name, size, bg, fraction in stale:
            dst = os.path.join(assets_dir, name)
            icon = _render_icon(logo, size, bg, fraction)
            tmp = dst + '.tmp'
            icon.save(tmp, 'PNG', optimize=True)
            os.replace(tmp, dst)
            logger.info("asset_build: generated %s (%dx%d)", name, size, size)
    except Exception as exc:
        logger.warning("asset_build: PWA icon generation failed (%s)", exc)
