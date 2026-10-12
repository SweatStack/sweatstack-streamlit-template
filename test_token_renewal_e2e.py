"""
End-to-end test: a tab left open past the token lifetime keeps working, without reconnecting.

Streamlit only sees the tokens the proxy sends when the page connects. The sweatstack library
(>= 0.94.0) renews the access token inside the session with the forwarded refresh token. This
runs the real proxy, Streamlit, sweatstack library and Chromium; only the SweatStack token
endpoint is faked, issuing short-lived tokens and never rotating refresh tokens (as the real
one does).

Usage:
    uv run python test_token_renewal_e2e.py

Takes about a minute (it waits for a token to expire). Exit code 0 = all checks pass.
"""
import base64
import json
import os
import subprocess
import sys
import threading
import time
from collections import Counter

from urllib.parse import parse_qs

import uvicorn
from fastapi import FastAPI, Request
from playwright.sync_api import sync_playwright

TOKEN_TTL = 40
FAKE_PORT, PROXY_PORT, STREAMLIT_PORT = 8597, 8080, 8501
refreshes = Counter()


def jwt(sub: str, exp: float) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'none'})}.{enc({'sub': sub, 'exp': int(exp), 'tz': 'UTC'})}.sig"


fake = FastAPI()


@fake.post("/api/v1/oauth/token")
async def token(request: Request):
    form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
    grant_type, refresh_token = form.get("grant_type"), form.get("refresh_token")
    caller = "library" if "python-sweatstack" in request.headers.get("user-agent", "") else "proxy"
    refreshes[caller] += 1
    assert grant_type == "refresh_token" and refresh_token == "refresh_123"
    return {"access_token": jwt("user_123", time.time() + TOKEN_TTL), "token_type": "Bearer",
            "expires_in": TOKEN_TTL, "refresh_token": refresh_token}


APP = '''
import base64, json, time
import streamlit as st
from sweatstack.streamlit import StreamlitAuth

auth = StreamlitAuth.behind_proxy(redirect_uri="http://localhost:8080/auth/callback")
if not auth.is_authenticated():
    st.write("LOGGED-OUT")
    st.stop()
token = auth.client.api_key.get_secret_value()
exp = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))["exp"]
st.write(f"VALID-FOR:{int(exp - time.time())}")
st.button("rerun")
'''


def main() -> int:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    os.environ.update(SECRET_KEY="test-secret-key", HTTPS_ONLY="false",
                      UPSTREAM_URL=f"http://127.0.0.1:{STREAMLIT_PORT}",
                      SWEATSTACK_CLIENT_ID="app_123", SWEATSTACK_CLIENT_SECRET="secret_123")
    sys.path.insert(0, os.getcwd())
    import proxy
    proxy.SWEATSTACK_TOKEN_URL = f"http://127.0.0.1:{FAKE_PORT}/api/v1/oauth/token"

    for app, port in ((fake, FAKE_PORT), (proxy.app, PROXY_PORT)):
        server = uvicorn.Server(uvicorn.Config(app, port=port, log_level="error", loop="asyncio"))
        threading.Thread(target=server.run, daemon=True).start()
    with open("renewal_app.py", "w") as f:
        f.write(APP)
    streamlit = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "renewal_app.py", "--server.headless=true",
         f"--server.port={STREAMLIT_PORT}", "--server.address=127.0.0.1"],
        env={**os.environ, "SWEATSTACK_URL": f"http://127.0.0.1:{FAKE_PORT}"},
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )
    checks = {}
    try:
        time.sleep(6)
        with sync_playwright() as p:
            browser = p.chromium.launch()
            context = browser.new_context()
            expires_at = time.time() + TOKEN_TTL
            context.add_cookies([{
                "name": proxy.TOKEN_COOKIE_NAME,
                "value": proxy._encode_token_cookie(jwt("user_123", expires_at), "refresh_123", expires_at),
                "url": f"http://localhost:{PROXY_PORT}",
            }])
            page = context.new_page()
            sockets = []
            page.on("websocket", lambda ws: sockets.append(ws.url))

            def valid_for() -> int:
                text = page.locator("text=/VALID-FOR:/").last.text_content(timeout=15_000)
                return int(text.split(":")[1])

            page.goto(f"http://localhost:{PROXY_PORT}/", wait_until="networkidle")
            checks["fresh page: token valid"] = valid_for() > 0

            print(f"  waiting {TOKEN_TTL + 5}s for the token to expire with the tab open...")
            page.wait_for_timeout((TOKEN_TTL + 5) * 1000)

            page.get_by_role("button", name="rerun").click()
            page.wait_for_timeout(2000)
            remaining = valid_for()
            checks["after expiry: renewed in place (token valid again)"] = remaining > TOKEN_TTL - 5
            checks["no error shown"] = page.locator("[data-testid='stException']").count() == 0
            checks["exactly one renewal by the session"] = refreshes["library"] == 1
            checks["no reconnect (one WebSocket)"] = len(sockets) == 1

            page.get_by_role("button", name="rerun").click()
            page.wait_for_timeout(2000)
            checks["next rerun reuses the renewed token"] = refreshes["library"] == 1 and valid_for() > 0

            page.reload(wait_until="networkidle")
            checks["reload: proxy refreshes, session uses header token"] = (
                valid_for() > 0 and refreshes["proxy"] == 1 and refreshes["library"] == 1
            )
            browser.close()
    finally:
        streamlit.terminate()
        streamlit.wait()
        os.remove("renewal_app.py")

    for name, ok in checks.items():
        print(f"  {'PASS' if ok else 'FAIL'}: {name}")
    print(f"  token requests: {dict(refreshes)}")
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
