"""
End-to-end test for the proxy + Streamlit stack using Playwright (real Chromium).

Starts both Streamlit (port 8501) and the FastAPI proxy (port 8080),
then opens a real browser to verify the full stack works — including
WebSocket connections with real browser headers (Origin, etc.).

Usage:
    SECRET_KEY=test uv run python test_proxy_e2e.py

Exit code 0 = all checks pass, non-zero = failure.
"""

import os
import signal
import subprocess
import sys
import time

import httpx
from playwright.sync_api import sync_playwright

STREAMLIT_PORT = 8501
PROXY_PORT = 8080
STARTUP_TIMEOUT = 30


def start_streamlit() -> subprocess.Popen:
    return subprocess.Popen(
        [
            sys.executable, "-m", "streamlit", "run", "streamlit_app.py",
            "--server.address=127.0.0.1",
            f"--server.port={STREAMLIT_PORT}",
            "--server.headless=true",
        ],
        env={**os.environ, "APP_URL": f"http://localhost:{PROXY_PORT}"},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def start_proxy() -> subprocess.Popen:
    return subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", "proxy:app",
            "--host", "127.0.0.1",
            "--port", str(PROXY_PORT),
            "--loop", "asyncio",
            "--log-level", "warning",
        ],
        env={
            **os.environ,
            "SECRET_KEY": os.environ.get("SECRET_KEY", "test-secret-key"),
            "HTTPS_ONLY": "false",
            "UPSTREAM_URL": f"http://127.0.0.1:{STREAMLIT_PORT}",
            "APP_URL": f"http://localhost:{PROXY_PORT}",
            "SWEATSTACK_CLIENT_ID": "dummy",
            "SWEATSTACK_CLIENT_SECRET": "dummy",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def wait_for_http(url: str, timeout: float = STARTUP_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=2, follow_redirects=True)
            if r.status_code == 200:
                return True
        except (httpx.ConnectError, httpx.ReadTimeout):
            pass
        time.sleep(0.5)
    return False


def kill_proc(proc: subprocess.Popen, name: str):
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        print(f"  Stopped {name} (pid {proc.pid})")


def read_output(proc: subprocess.Popen, name: str, max_lines: int = 50):
    if proc.stdout:
        try:
            output = proc.stdout.read()
        except Exception:
            return
        if output:
            lines = output.decode(errors="replace").splitlines()
            tail = lines[-max_lines:] if len(lines) > max_lines else lines
            print(f"\n--- {name} output (last {len(tail)} lines) ---")
            for line in tail:
                print(f"  {line}")
            print(f"--- end {name} ---")


def test_with_browser() -> bool:
    """Use Playwright to load the app through the proxy like a real browser.

    Checks:
    - Page loads (HTTP proxy works)
    - No WebSocket errors in console
    - Streamlit renders content (WebSocket connection succeeded)
    """
    console_errors = []
    ws_events = {"opened": 0, "closed": 0, "errors": 0, "frames_received": 0}

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # Capture console errors
        def on_console(msg):
            if msg.type == "error":
                console_errors.append(msg.text)
                print(f"  [console.error] {msg.text}")

        page.on("console", on_console)

        # Capture page-level errors (uncaught exceptions)
        page_errors = []
        def on_page_error(error):
            page_errors.append(str(error))
            print(f"  [page error] {error}")

        page.on("pageerror", on_page_error)

        # Track WebSocket lifecycle via CDP
        client = context.new_cdp_session(page)

        def on_ws_created(params):
            print(f"  [WS] Created: {params.get('url', '?')}")

        def on_ws_closed(params):
            ws_events["closed"] += 1
            print(f"  [WS] Closed")

        def on_ws_error(params):
            ws_events["errors"] += 1
            print(f"  [WS] Error: {params.get('errorMessage', '?')}")

        def on_ws_frame_received(params):
            ws_events["frames_received"] += 1

        def on_ws_handshake_response(params):
            status = params.get("response", {}).get("status", "?")
            print(f"  [WS] Handshake response: {status}")
            if status == 101:
                ws_events["opened"] += 1

        client.send("Network.enable")
        client.on("Network.webSocketCreated", on_ws_created)
        client.on("Network.webSocketClosed", on_ws_closed)
        client.on("Network.webSocketFrameError", on_ws_error)
        client.on("Network.webSocketFrameReceived", on_ws_frame_received)
        client.on("Network.webSocketHandshakeResponseReceived", on_ws_handshake_response)

        # Navigate to the app through the proxy
        proxy_url = f"http://localhost:{PROXY_PORT}"
        print(f"  Navigating to {proxy_url} ...")
        page.goto(proxy_url, wait_until="networkidle", timeout=30_000)

        # Wait for Streamlit to render — look for the app's content
        # Streamlit renders into a stApp container
        print("  Waiting for Streamlit to render...")
        try:
            page.wait_for_selector("[data-testid='stAppViewContainer']", timeout=15_000)
            print("  Streamlit app container rendered")
        except Exception as e:
            print(f"  WARNING: stAppViewContainer not found: {e}")

        # Give WebSocket time to exchange messages
        page.wait_for_timeout(3000)

        # Check for the app title or "Please log in" text (expected without auth)
        body_text = page.text_content("body") or ""
        has_streamlit_content = (
            "SweatStack" in body_text
            or "Please log in" in body_text
            or "streamlit" in body_text.lower()
        )

        print(f"\n  --- Results ---")
        print(f"  Page title: {page.title()}")
        print(f"  Has Streamlit content: {has_streamlit_content}")
        print(f"  Body text preview: {body_text[:200]}")
        print(f"  Console errors: {len(console_errors)}")
        print(f"  Page errors: {len(page_errors)}")
        print(f"  WebSocket opened: {ws_events['opened']}")
        print(f"  WebSocket closed: {ws_events['closed']}")
        print(f"  WebSocket errors: {ws_events['errors']}")
        print(f"  WebSocket frames received: {ws_events['frames_received']}")

        browser.close()

    # Evaluate results
    ok = True

    if not has_streamlit_content:
        print("\n  FAIL: No Streamlit content visible in browser")
        ok = False

    if ws_events["opened"] == 0:
        print("\n  FAIL: No WebSocket connection was established")
        ok = False

    if ws_events["errors"] > 0:
        print(f"\n  FAIL: {ws_events['errors']} WebSocket error(s)")
        ok = False

    if ws_events["frames_received"] == 0:
        print("\n  FAIL: No WebSocket frames received — Streamlit protocol not working")
        ok = False

    # Filter out noise from console errors (some Streamlit versions emit benign errors)
    real_errors = [e for e in console_errors if "websocket" in e.lower() or "connection" in e.lower()]
    if real_errors:
        print(f"\n  FAIL: WebSocket-related console errors: {real_errors}")
        ok = False

    if ok:
        print("\n  ALL BROWSER CHECKS PASSED")
    return ok


def _login_cookie() -> dict:
    """A token cookie the proxy accepts, encrypted with the same SECRET_KEY it uses."""
    os.environ.setdefault("SECRET_KEY", "test-secret-key")
    import proxy

    value = proxy._encode_token_cookie("dummy-access", "dummy-refresh", time.time() + 600)
    return {"name": proxy.TOKEN_COOKIE_NAME, "value": value, "url": f"http://localhost:{PROXY_PORT}"}


def test_pwa_with_browser() -> bool:
    """Check the PWA pieces in Chromium: service worker, install banner, logout through the worker.

    Needs manifest.json, so run it from a generated project.
    """
    proxy_url = f"http://localhost:{PROXY_PORT}"
    banner = "#pwa-install-banner"
    checks = {}

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # Desktop, logged out: service worker registers, no banner.
        context = browser.new_context()
        page = context.new_page()
        page.goto(proxy_url, wait_until="networkidle")
        checks["service worker active"] = page.evaluate(
            "navigator.serviceWorker.ready.then(r => r.active !== null)"
        )
        checks["no banner on desktop"] = page.locator(banner).count() == 0

        # Logout is a redirect that clears the cookie; it must survive the service worker.
        context.add_cookies([_login_cookie()])
        page.reload(wait_until="networkidle")
        checks["page is controlled by service worker"] = page.evaluate("navigator.serviceWorker.controller !== null")
        page.goto(f"{proxy_url}/logout", wait_until="networkidle")
        checks["logout clears cookie through service worker"] = not any(
            c["name"] == "sweatstack_tokens" for c in context.cookies()
        )
        context.close()

        # iPhone, logged out: no banner.
        iphone = p.devices["iPhone 13"]
        context = browser.new_context(**iphone)
        page = context.new_page()
        page.goto(proxy_url, wait_until="networkidle")
        checks["no banner on iPhone when logged out"] = page.locator(banner).count() == 0

        # iPhone, logged in: banner with Share instructions; dismissing it sticks.
        context.add_cookies([_login_cookie()])
        page.reload(wait_until="networkidle")
        checks["banner on iPhone when logged in"] = page.locator(banner).is_visible()
        checks["banner shows Share instructions"] = "Add to Home Screen" in (page.text_content(banner) or "")
        page.click(f"{banner} button[aria-label='Dismiss']")
        checks["dismiss removes banner"] = page.locator(banner).count() == 0
        page.reload(wait_until="networkidle")
        checks["dismissal survives reload"] = page.locator(banner).count() == 0
        context.close()

        browser.close()

    for name, passed in checks.items():
        print(f"  {'PASS' if passed else 'FAIL'}: {name}")
    ok = all(checks.values())
    if ok:
        print("\n  ALL PWA CHECKS PASSED")
    return ok


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    print("Starting Streamlit...")
    streamlit_proc = start_streamlit()
    print("Starting proxy...")
    proxy_proc = start_proxy()

    try:
        print(f"Waiting for Streamlit on :{STREAMLIT_PORT}...")
        if not wait_for_http(f"http://127.0.0.1:{STREAMLIT_PORT}/healthz"):
            print("FAIL: Streamlit did not start in time")
            sys.exit(1)
        print("Streamlit ready.")

        print(f"Waiting for proxy on :{PROXY_PORT}...")
        if not wait_for_http(f"http://127.0.0.1:{PROXY_PORT}/"):
            print("FAIL: Proxy did not start in time")
            sys.exit(1)
        print("Proxy ready.\n")

        print("[Test] Browser-based end-to-end test (Chromium via Playwright)...")
        passed = test_with_browser()

        if os.path.isfile("manifest.json"):
            print("\n[Test] PWA checks (Chromium via Playwright)...")
            passed = test_pwa_with_browser() and passed
        else:
            print("\n[Skip] PWA checks need manifest.json (run from a generated project)")

    finally:
        kill_proc(proxy_proc, "proxy")
        kill_proc(streamlit_proc, "streamlit")
        read_output(proxy_proc, "Proxy")

    print(f"\n{'='*40}")
    if passed:
        print("TEST PASSED")
    else:
        print("TEST FAILED")
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
