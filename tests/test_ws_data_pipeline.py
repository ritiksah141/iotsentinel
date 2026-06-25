#!/usr/bin/env python3
"""
Regression guards for the live-data WebSocket pipeline. Three bugs left the
dashboard's live cards / device list / graphs empty on real hardware:

  1. ws.message is delivered by dash-extensions as {data: "<raw json>"}, but the
     callbacks read it as a parsed dict -> every ws_message.get(...) missed.
     Fix: a clientside callback parses it into the ws-data Store; callbacks read
     ws-data.data.
  2. The background producer thread was started only from the Socket.IO 'connect'
     handler, but the page talks plain /ws -> the thread never started over LAN.
     Fix: the plain /ws handler also starts it.
  3. The WebSocket URL was hardcoded to 127.0.0.1 -> only worked when browsing
     ON the Pi. Fix: a clientside callback points it at window.location.host.

These are static-wiring checks (no heavy app import), mirroring test_pi_scripts.

Run: pytest tests/test_ws_data_pipeline.py -v
"""

from pathlib import Path

ROOT = Path(__file__).parent.parent
APP = (ROOT / "dashboard" / "app.py").read_text()
GLOBAL = (ROOT / "dashboard" / "callbacks" / "callbacks_global.py").read_text()
CALLBACK_FILES = list((ROOT / "dashboard" / "callbacks").glob("callbacks_*.py"))


# --- Bug 1: payload parsing -------------------------------------------------
def test_ws_data_store_exists_in_layout():
    assert 'dcc.Store(id="ws-data")' in APP


def test_parser_callback_parses_message_into_store():
    assert 'Output("ws-data", "data")' in GLOBAL
    assert 'Input("ws", "message")' in GLOBAL
    assert "JSON.parse(msg.data)" in GLOBAL


def test_no_callback_consumes_raw_ws_message_directly():
    # Only the parser may bind ('ws','message'); everything else reads ws-data.
    import re
    pat = re.compile(r"""['"]ws['"]\s*,\s*['"]message['"]""")
    for f in CALLBACK_FILES:
        text = f.read_text()
        hits = pat.findall(text)
        if f.name == "callbacks_global.py":
            assert len(hits) == 1, f"expected only the parser in {f.name}, got {len(hits)}"
        else:
            assert not hits, f"{f.name} still reads raw ('ws','message') — use ws-data.data"


# --- Bug 2: background thread start -----------------------------------------
def test_plain_ws_handler_starts_background_thread():
    assert "_ensure_background_thread" in APP
    # The plain /ws handler must kick the producer thread (not only Socket.IO).
    handler = APP[APP.index("def _plain_ws_handler"):APP.index("def _plain_ws_handler") + 600]
    assert "_ensure_background_thread()" in handler


# --- Bug 3: dynamic WebSocket URL ------------------------------------------
def test_ws_url_is_set_from_browser_location():
    assert 'Output("ws", "url")' in GLOBAL
    assert "window.location.host" in GLOBAL
    assert "wss://" in GLOBAL and "ws://" in GLOBAL


def test_websocket_component_is_not_hardcoded_to_localhost():
    # A hardcoded url made the component connect to 127.0.0.1 on mount (before the
    # clientside override fired), so every remote browser dialed its own localhost.
    # Leaving url unset lets dash-extensions default to the page's own host.
    assert "ws://127.0.0.1:8050/ws" not in APP
    assert 'WebSocket(id="ws")' in APP
