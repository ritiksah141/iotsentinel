"""
Network-topology device icons
==============================
Flat, single-stroke SVG glyphs (Lucide-style) rendered as inline ``data:`` URIs so
the Cytoscape topology shows a real device icon per node — laptop, phone, camera,
TV, printer, router, etc. — instead of a flat coloured blob.

Everything is generated in-process (no icon files, no CDN) so it works fully offline
on the Pi. The node's status stays readable via the coloured ring around the icon;
these glyphs only convey *what kind* of device it is.
"""
from __future__ import annotations

from urllib.parse import quote

# 24x24 viewBox inner markup for each glyph. Drawn as strokes (no fill) so a single
# `stroke` colour themes them. Kept deliberately simple and recognisable.
_GLYPHS = {
    # networking
    "router_hub": '<rect x="3" y="13" width="18" height="7" rx="2"/>'
                  '<circle cx="7" cy="16.5" r="1"/><line x1="11" y1="16.5" x2="17" y2="16.5"/>'
                  '<path d="M9 13l2-4"/><path d="M15 13l-2-4"/>',
    "wifi": '<path d="M5 12.55a11 11 0 0 1 14 0"/><path d="M8.5 16.1a6 6 0 0 1 7 0"/>'
            '<line x1="12" y1="20" x2="12.01" y2="20"/>',
    # computers
    "laptop": '<rect x="4" y="5" width="16" height="10" rx="1"/>'
              '<path d="M2 19h20l-1.5-3H3.5z"/>',
    "chip": '<rect x="6" y="6" width="12" height="12" rx="1"/>'
            '<path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/>',
    "server": '<rect x="3" y="4" width="18" height="7" rx="2"/>'
              '<rect x="3" y="13" width="18" height="7" rx="2"/>'
              '<line x1="7" y1="7.5" x2="7.01" y2="7.5"/>'
              '<line x1="7" y1="16.5" x2="7.01" y2="16.5"/>',
    # mobile
    "phone": '<rect x="7" y="3" width="10" height="18" rx="2"/>'
             '<line x1="11" y1="18" x2="13" y2="18"/>',
    "tablet": '<rect x="5" y="3" width="14" height="18" rx="2"/>'
              '<line x1="10.5" y1="18" x2="13.5" y2="18"/>',
    "watch": '<rect x="7" y="7" width="10" height="10" rx="2.5"/>'
             '<path d="M9.6 7l.6-3.1a1 1 0 0 1 1-.9h1.6a1 1 0 0 1 1 .9L15.4 7"/>'
             '<path d="M9.6 17l.6 3.1a1 1 0 0 0 1 .9h1.6a1 1 0 0 0 1-.9l.6-3.1"/>',
    # entertainment
    "tv": '<rect x="2" y="7" width="20" height="13" rx="2"/><path d="M17 2l-5 5-5-5"/>',
    "speaker": '<rect x="6" y="3" width="12" height="18" rx="2"/>'
               '<circle cx="12" cy="14" r="3"/><line x1="12" y1="7" x2="12.01" y2="7"/>',
    "game": '<rect x="2" y="8" width="20" height="9" rx="4.5"/>'
            '<path d="M6.5 12.5h3M8 11v3"/>'
            '<circle cx="16" cy="11.5" r="1"/><circle cx="18" cy="13.8" r="1"/>',
    # security
    "camera": '<rect x="2" y="6" width="14" height="12" rx="2"/><path d="M16 10l5-3v10l-5-3z"/>',
    "lock": '<rect x="5" y="11" width="14" height="10" rx="2"/>'
            '<path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    # smart home
    "bulb": '<path d="M9 18h6"/><path d="M10 22h4"/>'
            '<path d="M12 2a6 6 0 0 0-4 10.5c.7.6 1 1.5 1 2.5h6c0-1 .3-1.9 1-2.5A6 6 0 0 0 12 2z"/>',
    "plug": '<path d="M9 2v6"/><path d="M15 2v6"/>'
            '<path d="M6 8h12v2a6 6 0 0 1-12 0z"/><path d="M12 16v6"/>',
    "thermostat": '<path d="M14 14.76V5a2 2 0 1 0-4 0v9.76a4 4 0 1 0 4 0z"/>',
    "printer": '<path d="M6 9V3h12v6"/>'
               '<path d="M6 18H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-2"/>'
               '<rect x="6" y="14" width="12" height="7"/>',
    # fallback — a generic monitor/box
    "device": '<rect x="3" y="4" width="18" height="12" rx="2"/>'
              '<line x1="8" y1="20" x2="16" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/>',
    # private / unidentified — laptop + phone with a padlock in the screen. Shared with
    # the dashboard Device List (dashboard.shared.create_device_icon) so both surfaces
    # render the SAME glyph. Replaces the old red question-mark emoji.
    "private": '<rect x="2.3" y="4.3" width="12.2" height="8.4" rx="1.4"/>'
               '<path d="M1.3 16H14.7M3.4 12.7L2.2 16M13.4 12.7L14.6 16"/>'
               '<rect x="15.4" y="7.8" width="6.6" height="12.2" rx="1.4"/>'
               '<path d="M17.6 18.3H19.8"/>'
               '<rect x="6.5" y="8.6" width="3.9" height="3.1" rx="0.6"/>'
               '<path d="M7.35 8.6V7.7a1.1 1.1 0 0 1 2.2 0V8.6"/>',
}

# device_type -> glyph key. Keys are normalised (lower-case, spaces -> underscores),
# matching both the ML device_classifier output and dashboard.shared.DEVICE_TYPE_ICONS.
_TYPE_MAP = {
    # networking
    "router": "wifi", "hub": "wifi", "access_point": "wifi", "gateway": "wifi",
    "network": "wifi", "modem": "wifi", "switch": "wifi",
    # computers
    "computer": "laptop", "laptop": "laptop", "desktop": "laptop", "pc": "laptop",
    "mac": "laptop", "workstation": "laptop",
    # single-board / iot / sensors
    "raspberry_pi": "chip", "iot": "chip", "iot_hub": "chip",
    "microcontroller": "chip", "sensor": "chip",
    # storage
    "server": "server", "nas": "server", "storage": "server",
    # mobile
    "mobile": "phone", "phone": "phone", "smartphone": "phone",
    "iphone": "phone", "android": "phone",
    "tablet": "tablet", "ipad": "tablet",
    # wearables
    "watch": "watch", "smartwatch": "watch", "fitness_tracker": "watch",
    # entertainment
    "tv": "tv", "smart_tv": "tv", "streaming": "tv", "streaming_device": "tv",
    "media": "tv", "roku": "tv", "apple_tv": "tv", "fire_stick": "tv",
    "chromecast": "tv",
    # audio
    "speaker": "speaker", "smart_speaker": "speaker", "voice_assistant": "speaker",
    "alexa": "speaker", "echo": "speaker", "google_home": "speaker", "homepod": "speaker",
    # gaming
    "game_console": "game", "gaming_console": "game", "gaming": "game",
    "playstation": "game", "xbox": "game", "nintendo": "game",
    # security
    "camera": "camera", "smart_camera": "camera", "security_camera": "camera",
    "doorbell": "camera",
    # locks
    "lock": "lock", "smart_lock": "lock",
    # lighting
    "light": "bulb", "bulb": "bulb", "smart_bulb": "bulb", "light_bulb": "bulb",
    # power
    "plug": "plug", "smart_plug": "plug", "outlet": "plug", "switch_plug": "plug",
    # climate
    "thermostat": "thermostat",
    # print
    "printer": "printer", "scanner": "printer",
}

# classifier category -> glyph key (coarser fallback when the exact type is unknown)
_CATEGORY_MAP = {
    "network": "wifi", "computer": "laptop", "mobile": "phone",
    "entertainment": "tv", "security": "camera", "smart_home": "bulb",
}

_DEFAULT_ICON_COLOR = "#334155"   # slate — legible on the light node face


def _svg_uri(inner: str, color: str) -> str:
    """Wrap glyph markup in a themed SVG and return a urlencoded data: URI."""
    # width/height are REQUIRED: an SVG with only a viewBox has no intrinsic size,
    # so it defaults to ~300x150 and Cytoscape (background-fit: none) rasterises the
    # glyph at that huge natural size at some zoom levels — the icons balloon and
    # look broken. Explicit 24x24 pins the natural size to the viewBox.
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" '
        'viewBox="0 0 24 24" fill="none" '
        f'stroke="{color}" stroke-width="2" stroke-linecap="round" '
        f'stroke-linejoin="round">{inner}</svg>'
    )
    return "data:image/svg+xml," + quote(svg)


def _glyph_key(device_type: str | None, category: str | None) -> str:
    dt = (device_type or "").strip().lower().replace(" ", "_").replace("-", "_")
    key = _TYPE_MAP.get(dt)
    if not key and dt:
        # Loose contains-match (e.g. "apple_tv_4k" -> "apple_tv" -> tv).
        for k, v in _TYPE_MAP.items():
            if k in dt or dt in k:
                key = v
                break
    if not key:
        cat = (category or "").strip().lower().replace(" ", "_")
        key = _CATEGORY_MAP.get(cat)
    # Unidentified / private device gets the padlock-device glyph, never a blank blob.
    return key or "private"


def device_icon_uri(device_type: str | None = None, category: str | None = None,
                    color: str = _DEFAULT_ICON_COLOR) -> str:
    """Return a data: URI for the icon matching a device's type/category."""
    return _svg_uri(_GLYPHS[_glyph_key(device_type, category)], color)


def router_icon_uri(color: str = "#ffffff") -> str:
    """Icon for the central router/gateway hub node (white on the indigo node)."""
    return _svg_uri(_GLYPHS["router_hub"], color)
