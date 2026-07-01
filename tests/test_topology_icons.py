"""Tests for utils.topology_icons — the offline SVG device glyphs used by the
Network Topology graph. The key guarantee is that every generated icon is a
well-formed, fully-offline SVG data URI (a malformed path would silently render
as a blank node)."""
import sys
import xml.dom.minidom as minidom
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import topology_icons as ti


def test_all_glyphs_are_wellformed_svg():
    """Every glyph must parse as XML — guards against a typo'd path silently
    breaking a device icon."""
    for key in ti._GLYPHS:
        uri = ti._svg_uri(ti._GLYPHS[key], "#334155")
        svg = unquote(uri.split(",", 1)[1])
        minidom.parseString(svg)  # raises on malformed markup


def test_svg_has_intrinsic_width_height():
    """An SVG with only a viewBox has no intrinsic size and defaults to ~300x150,
    so Cytoscape rasterises the glyph huge at some zoom levels (icons balloon/break).
    Explicit width/height pins the natural size to the 24x24 viewBox."""
    svg = unquote(ti.device_icon_uri("laptop").split(",", 1)[1])
    assert 'width="24"' in svg and 'height="24"' in svg
    assert 'viewBox="0 0 24 24"' in svg


def test_device_icon_is_offline_data_uri():
    uri = ti.device_icon_uri("mobile")
    # A data: URI is inherently offline (no network fetch); the only URL inside is the
    # SVG xmlns namespace, which browsers never request.
    assert uri.startswith("data:image/svg+xml,")
    svg = unquote(uri.split(",", 1)[1])
    assert "href" not in svg and "src=" not in svg, "no external resource references"
    assert "%23" in uri, "the '#' in the stroke colour must be url-encoded"


def test_type_and_category_mapping():
    assert ti._glyph_key("camera", None) == "camera"
    assert ti._glyph_key("laptop", "computer") == "laptop"
    assert ti._glyph_key("raspberry_pi", None) == "chip"
    # exact type unknown -> fall back to category
    assert ti._glyph_key("weird-thing", "smart_home") == "bulb"
    # neither known -> the private (padlock-device) glyph, never a blank blob
    assert ti._glyph_key(None, None) == "private"
    assert ti._glyph_key("nope", "nope") == "private"
    # spaces / underscores normalise to the same glyph
    assert ti._glyph_key("smart tv", None) == ti._glyph_key("smart_tv", None) == "tv"
    assert ti._glyph_key("gaming console", None) == "game"
    assert ti._glyph_key("smartwatch", None) == "watch"


def test_router_hub_icon():
    uri = ti.router_icon_uri("#ffffff")
    assert uri.startswith("data:image/svg+xml,")
    svg = unquote(uri.split(",", 1)[1])
    minidom.parseString(svg)


# ---------------------------------------------------------------------------
# Private/unknown device glyph (dashboard.shared) — the Quick Status, Device List
# and Devices-page cards used to render the red ❓ emoji (U+2753) for every
# unfingerprinted device, so a home network (mostly private devices) looked
# alarmed. They now render a "devices + padlock" glyph meaning 'private'.
# ---------------------------------------------------------------------------
def test_private_glyph_is_wellformed_offline_svg():
    # The private glyph lives in topology_icons and is shared with the Device List.
    uri = ti.device_icon_uri(None)  # unknown type -> private glyph
    assert uri.startswith("data:image/svg+xml")
    svg = unquote(uri.split(",", 1)[1])
    minidom.parseString(svg)  # raises on malformed markup
    assert "href" not in svg and "src=" not in svg  # fully offline
    # laptop rect + phone rect + lock body = >= 3 rects
    assert svg.count("<rect") >= 3


def test_device_list_and_topology_use_the_same_glyph():
    """The Device List (dashboard.shared) must render the SAME SVG as the topology
    graph (utils.topology_icons) for a given device type — that's the whole point of
    unifying them. Emoji must be gone; unknown -> private glyph, never ❓."""
    from dashboard.shared import create_device_icon
    import re
    for t in ("smartphone", "smart tv", "camera", "printer", "gaming console",
              None, "unknown", "brand-new-type"):
        comp = create_device_icon(t, use_emoji=True, use_fa=False, size="1rem")
        s = str(comp)
        assert "device-glyph" in s and "❓" not in s
        # The masked span's URI must equal the topology graph's URI for the same type.
        m = re.search(r"data:image/svg\+xml[^\"')]+", s)
        assert m, f"no SVG data URI rendered for {t!r}"
        assert m.group(0) == ti.device_icon_uri(t), (
            f"Device List glyph for {t!r} differs from the topology glyph")
