"""
End-to-end test: only the proxy holds the refresh token, and a tab left open keeps working.

Runs the real proxy (through proxy.serve(), as supervisord does), Streamlit, the sweatstack
library and Chromium. Only SweatStack is faked, at its strictest: every refresh rotates the
refresh token, a retired one is accepted again only within the 30-second grace period, and any
other reuse ends the whole sign-in (SweatStack's Phase 2). The library must never refresh.

Tokens live 40 seconds, so the page's script (static/keepalive.js) refreshes halfway, and the
proxy's page refresh window is scaled to match (22 s instead of 5 minutes).

Usage:
    uv run python test_token_renewal_e2e.py

Takes about five minutes. Exit code 0 = all checks pass.
"""
import base64
import json
import os
import signal
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from playwright.sync_api import sync_playwright

TOKEN_TTL = 40
GRACE_SECONDS = 30
FAKE_PORT, PROXY_PORT, INTERNAL_PORT, STREAMLIT_PORT = 8597, 8080, 8081, 8501
APP_URL = f"http://localhost:{PROXY_PORT}"
FAKE_URL = f"http://127.0.0.1:{FAKE_PORT}"
PROXY_LOG = "renewal_proxy.log"


def jwt(sub: str, exp: float) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'none'})}.{enc({'sub': sub, 'exp': int(exp), 'tz': 'UTC'})}.sig"


# --- Fake SweatStack: rotating refresh tokens with reuse detection --------------------------

lock = threading.Lock()
refresh_tokens: dict[str, dict] = {}  # token -> {"family", "retired_at", "successor", "dead"}
events: list[dict] = []  # {"at", "family", "kind"}: rotate, grace, reuse, unknown, library, revoke


def new_sign_in(family: str) -> str:
    """The refresh token of a new sign-in (a new family)."""
    with lock:
        return _issue(family)


def _issue(family: str) -> str:
    token = f"refresh_{family}_{sum(r['family'] == family for r in refresh_tokens.values()) + 1}"
    refresh_tokens[token] = {"family": family, "retired_at": None, "successor": None, "dead": False}
    return token


def family_events(family: str, kind: str) -> list[dict]:
    return [e for e in events if e["family"] == family and e["kind"] == kind]


fake = FastAPI()


@fake.post("/api/v1/oauth/token")
async def token(request: Request):
    form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
    presented = form.get("refresh_token", "")
    now = time.time()
    with lock:
        record = refresh_tokens.get(presented)
        family = record["family"] if record else "?"
        if "python-sweatstack" in request.headers.get("user-agent", ""):
            kind = "library"  # the session must never refresh: refuse, and record it
        elif record is None or record["dead"]:
            kind = "unknown"
        elif record["retired_at"] is None:
            kind = "rotate"
            record["retired_at"], record["successor"] = now, _issue(family)
        elif now - record["retired_at"] < GRACE_SECONDS and refresh_tokens[record["successor"]]["retired_at"] is None:
            kind = "grace"
        else:
            kind = "reuse"  # ends the sign-in, as SweatStack's Phase 2 does
            for other in refresh_tokens.values():
                if other["family"] == family:
                    other["dead"] = True
        events.append({"at": now, "family": family, "kind": kind})
        if kind not in ("rotate", "grace"):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        successor = record["successor"]
    return {"access_token": jwt(f"user_{family}", now + TOKEN_TTL), "token_type": "Bearer",
            "expires_in": TOKEN_TTL, "refresh_token": successor}


@fake.post("/api/v1/oauth/revoke")
async def revoke(request: Request):
    form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
    with lock:
        record = refresh_tokens.get(form.get("token", ""))
        if record:
            events.append({"at": time.time(), "family": record["family"], "kind": "revoke"})
    return PlainTextResponse("")


# --- The app, the proxy and Streamlit -------------------------------------------------------

APP = '''
import base64, json, time
import streamlit as st
from sweatstack.streamlit import StreamlitAuth

st.session_state["runs"] = st.session_state.get("runs", 0) + 1
auth = StreamlitAuth.behind_proxy(redirect_uri="http://localhost:8080/auth/callback")
if not auth.is_authenticated():
    st.write("LOGGED-OUT")
    st.stop()
try:
    token = auth.client.api_key.get_secret_value()
    exp = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))["exp"]
    st.write(f"RUN:{st.session_state['runs']} VALID-FOR:{int(exp - time.time())}")
except Exception as error:
    st.write(f"RUN:{st.session_state['runs']} ERROR:{type(error).__name__}: {error}")
st.button("rerun")
'''

# Runs the proxy as production does, with SweatStack's URLs pointed at the fake and the page
# refresh window scaled to the short token lifetime.
PROXY = f'''
import asyncio, logging, os, sys
sys.path.insert(0, os.getcwd())
import proxy
proxy.SWEATSTACK_TOKEN_URL = "{FAKE_URL}/api/v1/oauth/token"
proxy.SWEATSTACK_REVOKE_URL = "{FAKE_URL}/api/v1/oauth/revoke"
proxy.PAGE_REFRESH_WINDOW_SECONDS = {TOKEN_TTL // 2 + 2}
logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
asyncio.run(proxy.serve(public_host="127.0.0.1", log_level="warning"))
'''

# Emulates what a browser does to a tab in the background: the keepalive script's timers do not
# run while the tab is hidden, and it gets a visibilitychange when it is shown again. Only that
# script's timers are held back, recognised by its file name on the stack.
HIDDEN_TAB = '''
(() => {
  const realSetTimeout = window.setTimeout.bind(window);
  window.__hidden = false;
  window.setTimeout = function (fn, delay, ...args) {
    if (typeof fn === "function" && (new Error().stack || "").includes("keepalive.js")) {
      return realSetTimeout(() => { if (!window.__hidden) fn(...args); }, delay);
    }
    return realSetTimeout(fn, delay, ...args);
  };
  let state = "visible";
  Object.defineProperty(document, "visibilityState", { get: () => state, configurable: true });
  window.__setVisibility = (next) => {
    window.__hidden = next === "hidden";
    state = next;
    document.dispatchEvent(new Event("visibilitychange"));
  };
})();
'''

# Sets the page's clock off by this many seconds, as on a device with a wrong clock.
CLOCK_OFF = '''
(() => {
  const offset = %d * 1000;
  const RealDate = Date;
  class OffDate extends RealDate {
    constructor(...args) { if (args.length === 0) super(RealDate.now() + offset); else super(...args); }
    static now() { return RealDate.now() + offset; }
  }
  window.Date = OffDate;
})();
'''


def start_proxy() -> subprocess.Popen:
    log = open(PROXY_LOG, "a")
    return subprocess.Popen([sys.executable, "renewal_proxy.py"], stdout=log, stderr=subprocess.STDOUT)


def start_streamlit() -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "renewal_app.py", "--server.headless=true",
         f"--server.port={STREAMLIT_PORT}", "--server.address=127.0.0.1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )


def stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def wait_until_up(url: str, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            httpx.get(url, timeout=1)
            return
        except httpx.HTTPError:
            time.sleep(0.2)
    raise RuntimeError(f"{url} did not come up")


# --- The checks -----------------------------------------------------------------------------

def main() -> int:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    os.environ.update(SECRET_KEY="test-secret-key", HTTPS_ONLY="false",
                      UPSTREAM_URL=f"http://127.0.0.1:{STREAMLIT_PORT}",
                      SWEATSTACK_CLIENT_ID="app_123", SWEATSTACK_CLIENT_SECRET="secret_123",
                      SWEATSTACK_URL=FAKE_URL)
    sys.path.insert(0, os.getcwd())
    import proxy  # for the cookie format, with the same SECRET_KEY as the proxy process

    server = uvicorn.Server(uvicorn.Config(fake, port=FAKE_PORT, log_level="error", loop="asyncio"))
    threading.Thread(target=server.run, daemon=True).start()
    for name, content in (("renewal_app.py", APP), ("renewal_proxy.py", PROXY)):
        with open(name, "w") as f:
            f.write(content)
    if os.path.exists(PROXY_LOG):
        os.remove(PROXY_LOG)
    proxy_process, streamlit = start_proxy(), start_streamlit()
    checks: dict[str, bool] = {}
    sids: set[str] = set()

    try:
        wait_until_up(f"http://127.0.0.1:{STREAMLIT_PORT}/_stcore/health")
        wait_until_up(f"http://127.0.0.1:{INTERNAL_PORT}/")
        with sync_playwright() as p:
            browser = p.chromium.launch()

            def signed_in_context(family: str, init_script: str | None = None, legacy: bool = False):
                """A browser signed in as a new sign-in of its own (family), its token fresh."""
                context = browser.new_context()
                if init_script:
                    context.add_init_script(init_script)
                expires_at = time.time() + TOKEN_TTL
                access, refresh = jwt(f"user_{family}", expires_at), new_sign_in(family)
                if legacy:  # a cookie from 0.3.0: no session id
                    value = proxy._get_fernet().encrypt(json.dumps(
                        {"access_token": access, "refresh_token": refresh, "expires_at": expires_at}
                    ).encode()).decode()
                else:
                    value = proxy._encode_token_cookie(access, refresh, expires_at, f"sid_{family}")
                context.add_cookies([{"name": proxy.TOKEN_COOKIE_NAME, "value": value, "url": APP_URL}])
                return context

            def cookie_data(context) -> dict:
                value = next((c["value"] for c in context.cookies(APP_URL) if c["name"] == proxy.TOKEN_COOKIE_NAME), "")
                data = proxy._decode_token_cookie(value) or {} if value else {}
                if data.get("sid"):
                    sids.add(data["sid"])
                return data

            def holds_current_token(context) -> bool:
                with lock:
                    record = refresh_tokens.get(cookie_data(context).get("refresh_token", ""))
                    return bool(record) and record["retired_at"] is None and not record["dead"]

            def output(page) -> str:
                return page.locator("text=/RUN:\\d+/").last.text_content(timeout=30_000) or ""

            def run_number(text: str) -> int:
                return int(text.split()[0].split(":")[1])

            def rerun(page, timeout: float = 15) -> str:
                """Click rerun and wait for that run's output."""
                before = run_number(output(page))
                page.get_by_role("button", name="rerun").click()
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    text = output(page)
                    if run_number(text) > before:
                        return text
                    page.wait_for_timeout(250)
                return output(page)

            def valid(text: str) -> bool:
                return "VALID-FOR:" in text and int(text.rsplit(":", 1)[1]) > 0

            def open_page(context):
                page = context.new_page()
                sockets = []
                page.on("websocket", lambda ws: sockets.append(ws.url))
                page.goto(APP_URL, wait_until="networkidle")
                return page, sockets

            # Batch 1: every scenario is its own sign-in, all waiting out one token lifetime together.
            solo = signed_in_context("solo")
            solo_page, solo_sockets = open_page(solo)
            pair = signed_in_context("pair")
            pair_pages = [open_page(pair)[0], open_page(pair)[0]]
            hidden = signed_in_context("hidden", HIDDEN_TAB)
            hidden_page, _ = open_page(hidden)
            hidden_page.evaluate("window.__setVisibility('hidden')")
            ahead = signed_in_context("ahead", CLOCK_OFF % 600)
            ahead_page, _ = open_page(ahead)
            behind = signed_in_context("behind", CLOCK_OFF % -600)
            behind_page, _ = open_page(behind)
            legacy = signed_in_context("legacy", legacy=True)
            legacy_page, _ = open_page(legacy)

            checks["fresh page: token valid"] = valid(output(solo_page))
            checks["0.3.0 cookie: accepted, and given a session id"] = (
                valid(output(legacy_page)) and bool(cookie_data(legacy).get("sid"))
            )
            batch_start = time.time()
            print(f"  waiting {TOKEN_TTL + 5}s for the tokens to expire with the tabs open...")
            solo_page.wait_for_timeout((TOKEN_TTL + 5) * 1000)

            # 1. One tab, past the token's lifetime, without reconnecting.
            text = rerun(solo_page)
            checks["1 a tab open past the lifetime keeps working"] = valid(text)
            checks["1 without reconnecting (one WebSocket)"] = len(solo_sockets) == 1
            checks["1 the page's script refreshed, at least once per lifetime"] = (
                len(family_events("solo", "rotate")) >= 2
            )
            # 2. The cookie holds the newest refresh token, so a reload works.
            checks["2 the cookie holds the current refresh token"] = holds_current_token(solo)
            solo_page.reload(wait_until="networkidle")
            checks["2 a reload works"] = valid(output(solo_page))

            # 3. Two tabs of one browser: both work, and they don't both refresh.
            texts = [rerun(page) for page in pair_pages]
            checks["3 two tabs past the lifetime: both keep working"] = all(valid(t) for t in texts)
            rotations = [e["at"] for e in family_events("pair", "rotate") if e["at"] >= batch_start]
            gaps = [later - earlier for earlier, later in zip(rotations, rotations[1:])]
            checks["3 one refresh per half-lifetime, not one per tab"] = (
                len(rotations) >= 2 and min(gaps) >= TOKEN_TTL / 2 - 5
            )

            # 5. A hidden tab whose timers did not run is shown again after its token expired.
            checks["5 while hidden, nothing refreshed"] = not [
                e for e in family_events("hidden", "rotate") if e["at"] >= batch_start
            ]
            hidden_page.evaluate("window.__setVisibility('visible')")
            text = rerun(hidden_page, timeout=20)
            checks["5 shown again: the next rerun works"] = valid(text)

            # 6. A device whose clock is 10 minutes off.
            checks["6 clock 10 minutes ahead: keeps working"] = valid(rerun(ahead_page))
            checks["6 clock 10 minutes behind: keeps working"] = valid(rerun(behind_page))

            checks["0.3.0 cookie: keeps working past the lifetime"] = valid(rerun(legacy_page))
            for context in (solo, pair, hidden, ahead, behind, legacy):
                cookie_data(context)  # collects the session ids for the log check
            for context in (pair, hidden, ahead, behind, legacy):
                context.close()

            # 4. Restarts. The proxy alone (supervisord restarts each program on its own): the
            # tab reconnects through the new process and keeps working past the next expiry.
            restart = signed_in_context("restart")
            restart_page, restart_sockets = open_page(restart)
            deadline = time.monotonic() + TOKEN_TTL
            while not family_events("restart", "rotate") and time.monotonic() < deadline:
                restart_page.wait_for_timeout(500)
            stop(proxy_process)
            proxy_process = start_proxy()
            wait_until_up(f"http://127.0.0.1:{INTERNAL_PORT}/")
            restart_page.wait_for_timeout(3000)  # Streamlit's frontend reconnects
            print(f"  proxy restarted; waiting {TOKEN_TTL + 5}s past the next expiry...")
            restart_page.wait_for_timeout((TOKEN_TTL + 5) * 1000)
            checks["4 proxy restarted: the tab reconnected"] = len(restart_sockets) >= 2
            checks["4 proxy restarted: keeps working past the next expiry"] = valid(rerun(restart_page))
            # Streamlit down for longer than SweatStack's grace period, as a slow deploy: the tab
            # keeps reconnecting, and handshakes refresh while Streamlit cannot answer them.
            stop(streamlit)
            print(f"  Streamlit stopped; waiting {TOKEN_TTL + 5}s...")
            restart_page.wait_for_timeout((TOKEN_TTL + 5) * 1000)
            streamlit = start_streamlit()
            wait_until_up(f"http://127.0.0.1:{STREAMLIT_PORT}/_stcore/health")
            restart_page.wait_for_timeout(5000)
            checks["4 Streamlit down past the grace period: the tab comes back signed in"] = valid(output(restart_page))
            checks["4 and the cookie holds the current refresh token"] = holds_current_token(restart)
            # The proxy and Streamlit together, as a deploy does.
            stop(proxy_process)
            stop(streamlit)
            proxy_process, streamlit = start_proxy(), start_streamlit()
            wait_until_up(f"http://127.0.0.1:{STREAMLIT_PORT}/_stcore/health")
            wait_until_up(f"http://127.0.0.1:{INTERNAL_PORT}/")
            restart_page.wait_for_timeout(5000)
            text = output(restart_page)
            checks["4 proxy and Streamlit restarted: the tab reconnects signed in"] = valid(text)
            checks["4 the cookie still holds the current refresh token"] = holds_current_token(restart)
            cookie_data(restart)

            # Sign-out ends the sign-in at SweatStack.
            restart_page.goto(f"{APP_URL}/logout", wait_until="networkidle")
            checks["sign-out revokes the sign-in at SweatStack"] = bool(family_events("restart", "revoke"))
            browser.close()
    finally:
        stop(proxy_process)
        stop(streamlit)
        server.should_exit = True
        for name in ("renewal_app.py", "renewal_proxy.py"):
            if os.path.exists(name):
                os.remove(name)

    with lock:
        kinds = [e["kind"] for e in events]
        issued = list(refresh_tokens)
    checks["the session never refreshed (only the proxy holds the refresh token)"] = "library" not in kinds
    checks["no refresh token was ever used again (SweatStack's strictest rules)"] = (
        "reuse" not in kinds and "unknown" not in kinds
    )
    with open(PROXY_LOG) as f:
        log = f.read()
    os.remove(PROXY_LOG)
    checks["no session ever waited in vain (session token outcome=timeout)"] = "outcome=timeout" not in log
    leaked = [secret for secret in (*issued, *sids) if secret in log]
    checks["the proxy's log names no token and no session id"] = not leaked and "token refresh via=" in log

    for name, ok in checks.items():
        print(f"  {'PASS' if ok else 'FAIL'}: {name}")
    print(f"  SweatStack saw: { {kind: kinds.count(kind) for kind in sorted(set(kinds))} }")
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
