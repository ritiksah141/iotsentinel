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
    # neither known -> generic device glyph
    assert ti._glyph_key(None, None) == "device"
    assert ti._glyph_key("nope", "nope") == "device"


def test_router_hub_icon():
    uri = ti.router_icon_uri("#ffffff")
    assert uri.startswith("data:image/svg+xml,")
    svg = unquote(uri.split(",", 1)[1])
    minidom.parseString(svg)
