"""Tests for the PWA layer — installable "native app" support.

Why this exists: the dashboard is installable as a Progressive Web App so users
can launch it like a native app (home-screen icon, standalone window) over the
Tailscale Funnel HTTPS URL. That relies on three fragile pieces — a root-scoped
service worker, a valid manifest, and the correct <head> tags — plus a service
worker whose caching must NEVER cache auth/dynamic requests. These tests pin all
of that so a refactor can't silently break install or, worse, cache a login.
"""

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

ASSETS = Path(__file__).parent.parent / "dashboard" / "assets"


@pytest.fixture(scope="module", autouse=True)
def _icons_generated():
    """PWA icons are build artifacts (gitignored, generated at boot from logo.png).
    Generate them so the file-based assertions below run regardless of whether the
    app has been booted yet in this session."""
    from dashboard.asset_build import ensure_pwa_icons
    ensure_pwa_icons(str(ASSETS))


# --------------------------------------------------------------------------
# Static asset correctness (no app boot required — fast, high signal)
# --------------------------------------------------------------------------

class TestManifestFile:
    def _load(self):
        return json.loads((ASSETS / "manifest.webmanifest").read_text())

    def test_manifest_is_valid_json(self):
        assert isinstance(self._load(), dict)

    def test_required_fields(self):
        m = self._load()
        assert m["name"]
        assert m["short_name"] == "IoTSentinel"
        assert m["start_url"] == "/"
        assert m["scope"] == "/"
        assert m["display"] == "standalone"
        assert m["icons"]

    def test_icon_srcs_are_root_assets_and_exist(self):
        for icon in self._load()["icons"]:
            assert icon["src"].startswith("/assets/")
            fname = icon["src"].split("/assets/")[1]
            assert (ASSETS / fname).is_file(), f"missing icon file {fname}"

    def test_has_a_maskable_icon(self):
        purposes = {i.get("purpose") for i in self._load()["icons"]}
        assert "maskable" in purposes


class TestServiceWorkerFile:
    def _text(self):
        return (ASSETS / "sw.js").read_text()

    def test_versioned_cache_name(self):
        assert "iotsentinel-static-v" in self._text()

    def test_never_caches_dynamic_or_auth_paths(self):
        # Regression pin: the network-only guards must stay present, or the worker
        # could start serving stale auth/live responses.
        t = self._text()
        for guard in ("_dash-update-component", "/api/", "/auth/", "/login", "/logout"):
            assert guard in t, f"service worker lost the {guard} network-only guard"

    def test_bypasses_non_get(self):
        # Every POST (login, Dash callbacks, WebAuthn) must skip the worker.
        assert "method !== 'GET'" in self._text()

    def test_navigations_are_network_first_with_offline_fallback(self):
        t = self._text()
        assert "navigate" in t
        assert "offline.html" in t


class TestOfflineFallback:
    def test_offline_page_exists(self):
        assert (ASSETS / "offline.html").is_file()


# --------------------------------------------------------------------------
# Icon generation (light import of asset_build — no full app)
# --------------------------------------------------------------------------

class TestIconGeneration:
    def test_generated_icons_are_square_and_correct_size(self):
        from PIL import Image
        expected = {
            "icon-192.png": 192,
            "icon-512.png": 512,
            "icon-maskable-512.png": 512,
            "apple-touch-icon.png": 180,
        }
        for name, size in expected.items():
            im = Image.open(ASSETS / name)
            assert im.size == (size, size), f"{name} is {im.size}, expected {size}x{size}"

    def test_ensure_pwa_icons_is_idempotent(self, tmp_path):
        from PIL import Image
        from dashboard.asset_build import ensure_pwa_icons

        # Seed a tiny logo so generation has a source.
        Image.new("RGBA", (242, 300), (10, 20, 30, 255)).save(tmp_path / "logo.png")
        ensure_pwa_icons(str(tmp_path))
        first = os.path.getmtime(tmp_path / "icon-192.png")
        ensure_pwa_icons(str(tmp_path))   # second run: nothing newer than logo
        assert os.path.getmtime(tmp_path / "icon-192.png") == first

    def test_ensure_pwa_icons_never_raises_without_logo(self, tmp_path):
        from dashboard.asset_build import ensure_pwa_icons
        # No logo.png present — must be a quiet no-op, not an exception.
        ensure_pwa_icons(str(tmp_path))


# --------------------------------------------------------------------------
# Routes + index_string (boots the app once — module-scoped fixture)
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    import dashboard.app as appmod
    return appmod.app.server.test_client(), appmod.app


class TestPwaRoutes:
    def test_manifest_route(self, client):
        c, _ = client
        r = c.get("/manifest.webmanifest")
        assert r.status_code == 200
        assert "application/manifest+json" in r.headers["Content-Type"]

    def test_manifest_route_is_unauthenticated(self, client):
        # Must be fetchable before login (browser reads it on the login page).
        c, _ = client
        assert c.get("/manifest.webmanifest").status_code == 200

    def test_sw_route_js_mime(self, client):
        c, _ = client
        r = c.get("/sw.js")
        assert r.status_code == 200
        assert "javascript" in r.headers["Content-Type"]

    def test_sw_served_at_root_with_allowed_header(self, client):
        c, _ = client
        r = c.get("/sw.js")
        assert r.headers.get("Service-Worker-Allowed") == "/"

    def test_index_string_has_pwa_tags(self, client):
        _, app = client
        idx = app.index_string
        assert 'rel="manifest"' in idx
        assert "/sw.js" in idx
        assert "apple-touch-icon" in idx
        assert "theme-color" in idx


class TestHealthCapture:
    def test_health_reports_capture_component(self, client):
        # The capture-freshness field surfaces a dead Zeek/parser pipeline.
        import json
        c, _ = client
        data = json.loads(c.get("/health").data)
        assert "capture" in data["components"]
        # Must never be a status that degrades the endpoint for a quiet network.
        assert data["components"]["capture"]["status"] in ("healthy", "idle", "unknown")
