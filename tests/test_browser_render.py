"""Headless-browser render gate.

The rest of the suite asserts on *file contents* (grep performance.js, count CSS
braces). That cannot catch a runtime renderer crash: a clientside bug like
reassigning ``window.dash_clientside`` ships a perfectly valid file that still
takes down every page in the browser with

    TypeError: Cannot read properties of undefined (reading 'apply')

curl /login returns 200 (the server is fine) and a grep test stays green, so the
breakage only shows up on the actual hardware gate — by which point an image is
already built. This test closes that hole: it boots the real app, loads it in
headless Chrome, runs the JavaScript, and FAILS if the renderer crashes or the
inline clientside callbacks (login / WebAuthn biometrics live here) never
register.

Skips cleanly when Chrome/Selenium is unavailable so local runs without a browser
are not blocked; CI installs Chrome and runs it for real.
"""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("selenium")
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

REPO = Path(__file__).resolve().parent.parent
APPLY_CRASH = "Cannot read properties of undefined (reading 'apply')"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _make_driver():
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--disable-dev-shm-usage")
    opts.set_capability("acceptInsecureCerts", True)  # self-signed HTTPS cert
    opts.set_capability("goog:loggingPrefs", {"browser": "ALL"})
    try:
        return webdriver.Chrome(options=opts)
    except Exception as exc:  # no Chrome / driver on this machine
        pytest.skip(f"headless Chrome unavailable: {exc}")


@pytest.fixture(scope="module")
def live_login_url():
    """Boot the real Dash app in a subprocess and yield its /login URL."""
    import urllib.request
    import ssl

    port = _free_port()
    env = dict(os.environ,
               IOTSENTINEL_DEBUG="true",      # Werkzeug dev server (no eventlet)
               IOTSENTINEL_PORT=str(port))
    proc = subprocess.Popen([sys.executable, "dashboard/app.py"],
                            cwd=str(REPO), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = None
    try:
        for _ in range(60):
            if proc.poll() is not None:
                out = proc.stdout.read().decode(errors="replace")[-2000:]
                pytest.fail(f"app exited during boot:\n{out}")
            for scheme in ("https", "http"):
                url = f"{scheme}://127.0.0.1:{port}/login"
                try:
                    urllib.request.urlopen(url, timeout=2, context=ctx)
                    base = url
                    break
                except Exception:
                    continue
            if base:
                break
            time.sleep(1)
        if not base:
            pytest.fail("app did not serve /login within 60s")
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


def test_login_page_renders_without_clientside_crash(live_login_url):
    """Load /login in a real browser; fail on the dash_renderer apply crash and
    confirm the inline clientside callbacks registered."""
    driver = _make_driver()
    try:
        driver.get(live_login_url)
        # Give dash_renderer time to mount and fire its initial clientside callbacks.
        time.sleep(4)

        severe = [e.get("message", "") for e in driver.get_log("browser")
                  if e.get("level") == "SEVERE"]

        # (1) The dash_renderer clientside crash (e.g. performance.js wiping
        #     window.dash_clientside) — takes down every page including login/WebAuthn.
        crashes = [m for m in severe if APPLY_CRASH in m]
        assert not crashes, (
            "dash_renderer crashed in the browser with the clientside apply error "
            f"(the bug the hardware gate hits):\n{crashes}")

        # (2) Any uncaught parse error in an inline script — e.g. a clientside JS string
        #     built from a Python triple-quoted block where a literal '\\n' became a real
        #     newline, producing 'Uncaught SyntaxError: Invalid or unexpected token' and
        #     killing the whole script (this is what silently broke WebAuthn biometrics).
        syntax = [m for m in severe if "SyntaxError" in m or "Uncaught" in m]
        assert not syntax, (
            "uncaught JS error in an inline script on /login — an inline clientside "
            f"handler failed to parse/run:\n{syntax}")

        # (3) The 31 inline clientside_callback(...) functions (login + WebAuthn live
        #     here) must register under window.dash_clientside._dashprivate_clientside_funcs.
        #     If anything wipes window.dash_clientside, this drops to 0.
        registered = driver.execute_script(
            "var f=(window.dash_clientside||{})._dashprivate_clientside_funcs;"
            "return f?Object.keys(f).length:0;")
        assert registered and registered > 0, (
            "no inline clientside callbacks registered under window.dash_clientside."
            f"_dashprivate_clientside_funcs; the global was wiped (registered={registered})")
    finally:
        driver.quit()
