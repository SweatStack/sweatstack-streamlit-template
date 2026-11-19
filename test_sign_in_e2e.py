"""
End-to-end test: sign-in, including one that finishes in another browser.

Runs the real proxy and real Chromium. SweatStack and the upstream app are one fake app, so no
Streamlit is needed and this runs from the repository root in about half a minute. Each Playwright
context is one browser with its own cookies. Also checks what the proxy tells the app, its
refresh and token endpoints, sign-out and its log (T19 to T26).

Usage:
    uv run python test_sign_in_e2e.py

Exit code 0 = all checks pass.
"""
import asyncio
import base64
import json
import logging
import os
import sys
import threading
import time
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlparse

import uvicorn
import httpx
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from playwright.sync_api import sync_playwright

FAKE_PORT, PROXY_PORT, INTERNAL_PORT = 8597, 8080, 8081
INTERNAL_URL = f"http://127.0.0.1:{INTERNAL_PORT}"
FAKE_URL = f"http://127.0.0.1:{FAKE_PORT}"
APP_URL = f"http://localhost:{PROXY_PORT}"
PAGE = "/page?x=1"
FAILURE_TEXT = "Sign-in didn't finish"
SESSION_COOKIE = "ss_session"

authorize_calls: list[dict] = []
token_calls: list[dict] = []
revoke_calls: list[dict] = []
issued_codes: list[str] = []
switches = {"deny": False, "token": "ok", "revoke": "ok"}
logs: list[str] = []  # the proxy's warnings
all_logs: list[str] = []  # everything the proxy logs, for T26
upstream_headers: list[dict] = []


def reset() -> None:
    authorize_calls.clear()
    token_calls.clear()
    revoke_calls.clear()
    issued_codes.clear()
    logs.clear()
    upstream_headers.clear()
    switches.update(deny=False, token="ok", revoke="ok")


fake = FastAPI()


@fake.get("/oauth/authorize")
async def authorize(request: Request):
    query = dict(request.query_params)
    authorize_calls.append(query)
    if switches["deny"]:
        return RedirectResponse(f"{query['redirect_uri']}?{urlencode({'error': 'access_denied', 'state': query['state']})}")
    if SESSION_COOKIE not in request.cookies:
        return HTMLResponse("SWEATSTACK-LOGIN")
    code = f"code_{len(issued_codes) + 1}"
    issued_codes.append(code)
    return RedirectResponse(f"{query['redirect_uri']}?{urlencode({'code': code, 'state': query['state']})}")


@fake.get("/fake/sign-in")
async def sign_in():
    response = HTMLResponse("SIGNED-IN")
    response.set_cookie(SESSION_COOKIE, "1")
    return response


@fake.post("/api/v1/oauth/token")
async def token(request: Request):
    form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
    token_calls.append(form)
    if switches["token"] == "500":
        return PlainTextResponse("boom", status_code=500)
    if switches["token"] == "no_access_token":
        return {"token_type": "Bearer"}
    if switches["token"] == "invalid_json":
        return PlainTextResponse("not json")
    if switches["token"] == "invalid_grant":
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if form.get("grant_type") == "refresh_token" or form.get("code") in issued_codes:
        return {"access_token": "access_123", "refresh_token": "refresh_123", "expires_in": 900}
    return JSONResponse({"error": "invalid_grant"}, status_code=400)


@fake.post("/api/v1/oauth/revoke")
async def revoke(request: Request):
    revoke_calls.append({k: v[0] for k, v in parse_qs((await request.body()).decode()).items()})
    if switches["revoke"] == "500":
        return PlainTextResponse("boom", status_code=500)
    return PlainTextResponse("")


@fake.websocket("/ws")
async def upstream_websocket(websocket: WebSocket):
    upstream_headers.append({k: v for k, v in websocket.headers.items() if k.startswith("x-sweatstack-")})
    await websocket.accept()
    await websocket.send_text("hello")
    await websocket.close()


@fake.api_route("/{path:path}", methods=["GET", "POST"])
async def upstream(path: str, request: Request):
    upstream_headers.append({k: v for k, v in request.headers.items() if k.startswith("x-sweatstack-")})
    has_token = "yes" if "x-sweatstack-token" in request.headers else "no"
    return HTMLResponse(f"<html><head></head>PAGE:{path}?{request.url.query} TOKEN:{has_token}</html>")


def _answers(url: str) -> bool:
    """Whether a server listens at ``url``, whatever it answers."""
    try:
        httpx.get(url, timeout=1)
        return True
    except httpx.HTTPError:
        return False


def make_state(attempt: object, next_url: str = PAGE, nonce: str = "n") -> str:
    """A state as it appears on the wire, built independently of the proxy's code."""
    page = base64.urlsafe_b64encode(next_url.encode()).rstrip(b"=").decode()
    return f"{nonce}.{attempt}.{page}"


def main() -> int:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    os.environ.update(SECRET_KEY="test-secret-key", HTTPS_ONLY="false", APP_URL=APP_URL,
                      AUTO_LOGIN="false", ALLOW_SIGNUP="true",
                      SWEATSTACK_CLIENT_ID="app_123", SWEATSTACK_CLIENT_SECRET="secret_123")
    os.environ.pop("OAUTH_SCOPES", None)
    sys.path.insert(0, os.getcwd())
    import proxy

    token_url = f"{FAKE_URL}/api/v1/oauth/token"
    proxy.SWEATSTACK_AUTHORIZE_URL = f"{FAKE_URL}/oauth/authorize"
    proxy.SWEATSTACK_TOKEN_URL = token_url
    proxy.SWEATSTACK_REVOKE_URL = f"{FAKE_URL}/api/v1/oauth/revoke"
    proxy.UPSTREAM_URL = FAKE_URL

    class Capture(logging.Handler):
        def __init__(self, into: list[str], level: int) -> None:
            super().__init__(level)
            self.into = into

        def emit(self, record: logging.LogRecord) -> None:
            self.into.append(record.getMessage())

    proxy.logger.setLevel(logging.INFO)
    proxy.logger.addHandler(Capture(logs, logging.WARNING))
    proxy.logger.addHandler(Capture(all_logs, logging.INFO))

    # The proxy runs as in production, through proxy.serve(): public and internal listener.
    fake_server = uvicorn.Server(uvicorn.Config(fake, port=FAKE_PORT, log_level="error", loop="asyncio"))
    threading.Thread(target=fake_server.run, daemon=True).start()
    threading.Thread(
        target=lambda: asyncio.run(proxy.serve(PROXY_PORT, INTERNAL_PORT, public_host="127.0.0.1", log_level="error")),
        daemon=True,
    ).start()
    deadline = time.monotonic() + 15
    while not fake_server.started or not _answers(f"{INTERNAL_URL}/"):
        if time.monotonic() > deadline:
            print("FAIL: the fake SweatStack or the proxy did not start")
            return 1
        time.sleep(0.05)

    checks = {}

    with sync_playwright() as p:
        browser = p.chromium.launch()

        def new_browser(session: bool = False, **cookies: str):
            """A clean browser, optionally signed in to SweatStack, with cookies on the app."""
            reset()
            context = browser.new_context()
            if session:
                context.add_cookies([{"name": SESSION_COOKIE, "value": "1", "url": FAKE_URL}])
            if cookies:
                context.add_cookies([{"name": k, "value": v, "url": APP_URL} for k, v in cookies.items()])
            return context

        def cookie(context, name: str) -> str | None:
            return next((c["value"] for c in context.cookies(APP_URL) if c["name"] == name), None)

        def callback(context, state: str | None, code: str | None = "code_x", **extra: str):
            """One callback request, without following its redirect."""
            params = {"state": state, "code": code, **extra}
            query = urlencode({k: v for k, v in params.items() if v is not None})
            return context.request.get(f"{APP_URL}/auth/callback?{query}", max_redirects=0)

        def is_failure(response) -> bool:
            return response.status == 400 and FAILURE_TEXT in response.text()

        def body(page) -> str:
            return page.locator("body").inner_text()

        def token_cookie(expires_at: float, refresh_token: str = "refresh_old", sid: str = "sid_test") -> str:
            return proxy._encode_token_cookie("access_old", refresh_token, expires_at, sid)

        def decoded(context) -> dict:
            return proxy._decode_token_cookie(cookie(context, proxy.TOKEN_COOKIE_NAME) or "") or {}

        def refresh_call(context, header: bool = True):
            headers = {"X-SweatStack-Refresh": "1"} if header else {}
            return context.request.post(f"{APP_URL}/_proxy/refresh", headers=headers)

        # T1: the sign-in starts in browser A and finishes in browser B.
        context_a = new_browser()
        page_a = context_a.new_page()
        page_a.goto(f"{APP_URL}/login?next=%2Fpage%3Fx%3D1")
        authorize_url = page_a.url
        context_b = new_browser(session=True)
        page_b = context_b.new_page()
        page_b.goto(authorize_url)
        checks["T1 browser switch: ends signed in on the requested page"] = "PAGE:page?x=1 TOKEN:yes" in body(page_b)
        checks["T1 two authorize calls, the second with attempt 2"] = (
            [call["state"].split(".")[1] for call in authorize_calls] == ["1", "2"]
        )
        checks["T1 one token call, with the second code"] = (
            len(issued_codes) == 2 and [call.get("code") for call in token_calls] == ["code_2"]
        )
        checks["T1 the restart is logged"] = logs == ["Sign-in restarted: no state cookie"]
        context_a.close()
        context_b.close()

        # T2: normal round trip in one browser.
        context = new_browser(session=True, auth_attempted="1")
        page = context.new_page()
        page.goto(f"{APP_URL}/login?next=%2Fpage%3Fx%3D1")
        checks["T2 round trip: lands on the page, signed in"] = "PAGE:page?x=1 TOKEN:yes" in body(page)
        checks["T2 token cookie set"] = cookie(context, proxy.TOKEN_COOKIE_NAME) is not None
        checks["T2 oauth_state and auth_attempted gone"] = (
            cookie(context, "oauth_state") is None and cookie(context, "auth_attempted") is None
        )
        checks["T2 one token call, authorization_code"] = (
            [call.get("grant_type") for call in token_calls] == ["authorization_code"]
        )
        checks["T2 nothing logged at warning"] = logs == []
        context.close()

        # T3: no cookie, code, attempt 1.
        context = new_browser()
        response = callback(context, make_state(1))
        checks["T3 no cookie, attempt 1: restarts with the encoded page"] = (
            300 <= response.status < 400
            and response.headers["location"] == f"/login?retry=1&next={quote(PAGE, safe='')}"
        )
        checks["T3 no token call"] = token_calls == []
        checks["T3 no auth_attempted"] = cookie(context, "auth_attempted") is None
        context.close()

        # T4: no cookie, code, attempt 2.
        context = new_browser()
        response = callback(context, make_state(2))
        checks["T4 no cookie, attempt 2: failure page"] = is_failure(response)
        checks["T4 auth_attempted set"] = cookie(context, "auth_attempted") == "1"
        checks["T4 no token call"] = token_calls == []
        checks["T4 logged, without the state"] = logs == ["Sign-in failed: no state cookie"]
        context.close()

        # T5: a different state cookie never retries and is left alone.
        for attempt in (1, 2):
            context = new_browser(oauth_state="other.1.")
            response = callback(context, make_state(attempt))
            checks[f"T5 different cookie, attempt {attempt}: failure page"] = is_failure(response)
            checks[f"T5 different cookie, attempt {attempt}: no token call"] = token_calls == []
            checks[f"T5 different cookie, attempt {attempt}: oauth_state unchanged"] = (
                cookie(context, "oauth_state") == "other.1."
            )
            checks[f"T5 different cookie, attempt {attempt}: logged, without the state"] = (
                logs == ["Sign-in failed: state mismatch"]
            )
            context.close()

        # T6: states that aren't ours.
        for state in (None, "abc", "a.1", "a.1.b.c", "n.3.", "n.1.gICA"):
            context = new_browser()
            response = callback(context, state)
            checks[f"T6 state {state!r}: failure page, no retry, no token call"] = (
                is_failure(response) and token_calls == []
            )
            context.close()
        context = new_browser()
        response = callback(context, make_state(1), code=None)
        checks["T6 attempt 1 without a code: failure page, no retry"] = is_failure(response)
        context.close()

        # T7: a hostile page in the state.
        for hostile in ("//evil.example", "https://evil.example", "\\\\evil", "/\\evil"):
            context = new_browser()
            response = callback(context, make_state(1, hostile))
            checks[f"T7 next {hostile!r} becomes /"] = response.headers.get("location") == "/login?retry=1&next=%2F"
            context.close()

        # T8: a tab in the page, through to the callback.
        context = new_browser(session=True)
        url = f"{APP_URL}/login?next=/%09/evil.example"
        for _ in range(2):  # /login, then the fake's authorize
            url = urljoin(url, context.request.get(url, max_redirects=0).headers["location"])
        location = context.request.get(url, max_redirects=0).headers["location"]
        checks["T8 tab in next: Location is encoded and stays on the app"] = (
            location == "/%09/evil.example" and urlparse(urljoin(APP_URL, location)).netloc == f"localhost:{PROXY_PORT}"
        )
        context.close()

        # T9: XSS through the page on the failure page, in a real page.
        xss = '/"><img src=x onerror=alert(1)>'
        context = new_browser()
        page = context.new_page()
        dialogs = []
        page.on("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.dismiss()))
        query = urlencode({"code": "code_x", "state": make_state(2, xss)})
        page.goto(f"{APP_URL}/auth/callback?{query}")
        page.wait_for_timeout(500)
        checks["T9 XSS: no dialog fires"] = dialogs == []
        checks["T9 XSS: no img element"] = page.locator("img").count() == 0
        checks["T9 XSS: button href is percent-encoded"] = (
            page.get_by_role("link", name="Try again").get_attribute("href") == f"/login?next={quote(xss, safe='')}"
        )
        context.close()

        # T10: overlong and exactly-at-the-limit pages, in real Chromium.
        context = new_browser(session=True)
        page = context.new_page()
        page.goto(f"{APP_URL}/login?next=/{'a' * 4999}")
        checks["T10 5000-character next: signs in on /"] = body(page).startswith("PAGE:? TOKEN:yes")
        checks["T10 5000-character next: exactly one token call"] = len(token_calls) == 1
        context.close()
        at_limit = "b" * 1023  # with the leading slash, exactly 1024 bytes
        context = new_browser(session=True)
        page = context.new_page()
        page.goto(f"{APP_URL}/login?next=/{at_limit}")
        checks["T10 1024-byte next is preserved"] = f"PAGE:{at_limit}? TOKEN:yes" in body(page)
        checks["T10 1024-byte next: exactly one token call"] = len(token_calls) == 1
        context.close()

        # T11: already signed in, no state cookie.
        context = new_browser(**{proxy.TOKEN_COOKIE_NAME: token_cookie(time.time() + 600)})
        response = callback(context, make_state(2))
        checks["T11 valid token, attempt 2: redirect to the page"] = (
            300 <= response.status < 400 and response.headers["location"] == "/page?x=1"
        )
        checks["T11 no token call"] = token_calls == []
        checks["T11 no auth_attempted"] = cookie(context, "auth_attempted") is None
        context.close()

        # T12: signed in, but the token needs a refresh.
        expired = token_cookie(time.time() - 60)
        context = new_browser(**{proxy.TOKEN_COOKIE_NAME: expired})
        response = callback(context, make_state(1))
        checks["T12 expiring token: redirect to the page"] = (
            300 <= response.status < 400 and response.headers["location"] == "/page?x=1"
        )
        checks["T12 token cookie rewritten"] = cookie(context, proxy.TOKEN_COOKIE_NAME) not in (None, expired)
        checks["T12 token endpoint received refresh_token, and no code"] = (
            [call.get("grant_type") for call in token_calls] == ["refresh_token"]
        )
        context.close()

        # T13: SweatStack answers with an error for a verified state.
        context = new_browser(session=True)
        page = context.new_page()
        switches["deny"] = True
        response = page.goto(f"{APP_URL}/login?next=%2Fpage%3Fx%3D1")
        checks["T13 error on a verified state: failure page"] = (
            response.status == 400 and FAILURE_TEXT in body(page)
        )
        checks["T13 oauth_state deleted"] = cookie(context, "oauth_state") is None
        checks["T13 auth_attempted set"] = cookie(context, "auth_attempted") == "1"
        checks["T13 logged with the error"] = logs == ["Sign-in failed: SweatStack returned error 'access_denied'"]
        context.close()

        # T14: the token exchange fails for a verified state.
        for name, mode, url in (("500", "500", token_url),
                                ("200 without access_token", "no_access_token", token_url),
                                ("invalid JSON", "invalid_json", token_url),
                                ("unreachable", "ok", "http://127.0.0.1:1/api/v1/oauth/token")):
            state = make_state(1)
            context = new_browser(oauth_state=state)
            switches["token"] = mode
            proxy.SWEATSTACK_TOKEN_URL = url
            response = callback(context, state)
            proxy.SWEATSTACK_TOKEN_URL = token_url
            checks[f"T14 token endpoint {name}: failure page, not a 5xx"] = is_failure(response)
            checks[f"T14 token endpoint {name}: no token cookie"] = cookie(context, proxy.TOKEN_COOKIE_NAME) is None
            checks[f"T14 token endpoint {name}: oauth_state deleted"] = cookie(context, "oauth_state") is None
            checks[f"T14 token endpoint {name}: logged"] = (
                len(logs) == 1 and logs[0].startswith("Sign-in failed: token exchange")
            )
            context.close()

        # T15: the authorize request.
        def authorize_query() -> dict:
            context = new_browser()
            location = context.request.get(f"{APP_URL}/login", max_redirects=0).headers["location"]
            context.close()
            return parse_qs(urlparse(location).query)

        query = authorize_query()
        checks["T15 scope is exactly the default"] = query["scope"] == ["activities:read sharing:read profile"]
        checks["T15 no prompt"] = "prompt" not in query
        checks["T15 no comma in scope"] = "," not in query["scope"][0]
        checks["T15 email_auth_mode absent"] = "email_auth_mode" not in query
        proxy.ALLOW_SIGNUP = False
        checks["T15 email_auth_mode kept when signup is off"] = authorize_query()["email_auth_mode"] == ["existing_only"]
        proxy.ALLOW_SIGNUP = True

        # T16: parsing OAUTH_SCOPES.
        checks["T16 empty gives the default"] = proxy._parse_oauth_scopes("") == "activities:read sharing:read profile"
        checks["T16 whitespace is normalized"] = proxy._parse_oauth_scopes(" a:b   c:d ") == "a:b c:d"
        for bad in ("data:read profile", "a:b,c:d"):
            try:
                proxy._parse_oauth_scopes(bad)
                checks[f"T16 {bad!r} raises"] = False
            except RuntimeError:
                checks[f"T16 {bad!r} raises"] = True

        # T17: the failure page itself, with the default white colors.
        context = new_browser()
        page = context.new_page()
        query = urlencode({"code": "code_x", "state": make_state(2)})
        response = page.goto(f"{APP_URL}/auth/callback?{query}")
        border = page.get_by_role("link", name="Try again").evaluate(
            "a => { const s = getComputedStyle(a); return [s.borderTopWidth, s.borderTopStyle, s.borderTopColor] }"
        )
        checks["T17 button has a visible border on white"] = border == ["1px", "solid", "rgb(0, 0, 0)"]
        checks["T17 contrast color of white is black"] = proxy._contrast_color("#ffffff") == "#000000"
        checks["T17 contrast color of black is white"] = proxy._contrast_color("#000000") == "#ffffff"
        source = response.text()
        checks["T17 400, not cacheable, HTML"] = (
            response.status == 400
            and response.headers["cache-control"] == "no-store"
            and response.headers["content-type"] == "text/html; charset=utf-8"
        )
        checks["T17 viewport, lang, no JavaScript"] = (
            '<meta name="viewport" content="width=device-width, initial-scale=1">' in source
            and '<html lang="en">' in source
            and "<script" not in source
        )
        checks["T17 exact copy"] = (
            page.locator("h1").inner_text() == FAILURE_TEXT
            and page.locator("p").inner_text() == "Try again in this browser."
        )
        context.close()

        # T18: Try again recovers in one click.
        context = new_browser(session=True)
        page = context.new_page()
        query = urlencode({"code": "code_x", "state": make_state(2)})
        page.goto(f"{APP_URL}/auth/callback?{query}")
        checks["T18 starts on the failure page with auth_attempted"] = (
            FAILURE_TEXT in body(page) and cookie(context, "auth_attempted") == "1"
        )
        page.get_by_role("link", name="Try again").click()
        page.wait_for_url("**/page?x=1")
        checks["T18 Try again signs in on the original page"] = "PAGE:page?x=1 TOKEN:yes" in body(page)
        checks["T18 auth_attempted gone"] = cookie(context, "auth_attempted") is None
        context.close()

        COOKIE = proxy.TOKEN_COOKIE_NAME

        # T19: the app gets the access token and the session id: never the refresh token, and
        # never an X-SweatStack-* header the browser sent.
        context = new_browser(**{COOKIE: token_cookie(time.time() + 600, sid="sid_t19")})
        context.request.get(
            f"{APP_URL}/page",
            headers={"X-SweatStack-Session": "sid_evil", "X-SweatStack-Refresh-Token": "evil", "X-SweatStack-Token": "evil"},
        )
        sent = upstream_headers[-1]
        checks["T19 the app gets the access token and the session id"] = (
            sent.get("x-sweatstack-token") == "access_old" and sent.get("x-sweatstack-session") == "sid_t19"
        )
        checks["T19 no refresh token, and nothing the browser sent"] = set(sent) == {
            "x-sweatstack-token", "x-sweatstack-session"
        }
        context.close()

        # T20: a cookie from 0.3.0 has no session id: it is accepted and gets one.
        legacy = proxy._get_fernet().encrypt(json.dumps(
            {"access_token": "access_old", "refresh_token": "refresh_old", "expires_at": time.time() + 600}
        ).encode()).decode()
        context = new_browser(**{COOKIE: legacy})
        page = context.new_page()
        page.goto(f"{APP_URL}/page")
        legacy_sid = decoded(context).get("sid")
        checks["T20 a 0.3.0 cookie is accepted"] = "TOKEN:yes" in body(page)
        checks["T20 and comes back with a session id, nothing else changed"] = (
            bool(legacy_sid) and decoded(context).get("refresh_token") == "refresh_old" and token_calls == []
        )
        checks["T20 the app gets that session id"] = upstream_headers[-1].get("x-sweatstack-session") == legacy_sid
        context.close()

        # T21: POST /_proxy/refresh, which static/keepalive.js calls.
        context = new_browser(**{COOKIE: token_cookie(time.time() + 600, sid="sid_t21a")})
        checks["T21 without its header: 403"] = refresh_call(context, header=False).status == 403
        response = refresh_call(context)
        checks["T21 more than 5 minutes left: nothing refreshed, the time left"] = (
            response.status == 200 and 590 <= response.json()["expires_in"] <= 600 and token_calls == []
        )
        checks["T21 not cacheable"] = response.headers.get("cache-control") == "no-store"
        context.close()
        context = new_browser(**{COOKIE: token_cookie(time.time() + 120, sid="sid_t21b")})
        response = refresh_call(context)
        checks["T21 within 5 minutes: refreshed, the new lifetime"] = (
            response.status == 200 and 890 <= response.json()["expires_in"] <= 900
            and [call.get("grant_type") for call in token_calls] == ["refresh_token"]
        )
        checks["T21 the cookie holds the new refresh token and the same session id"] = (
            decoded(context).get("refresh_token") == "refresh_123" and decoded(context).get("sid") == "sid_t21b"
        )
        context.close()
        context = new_browser()
        checks["T21 no cookie: 401"] = refresh_call(context).status == 401
        context.close()
        context = new_browser(**{COOKIE: token_cookie(time.time() + 120, sid="sid_t21c")})
        switches["token"] = "invalid_grant"
        response = refresh_call(context)
        checks["T21 SweatStack ended the sign-in: 401, cookie deleted"] = (
            response.status == 401 and cookie(context, COOKIE) is None
        )
        checks["T21 logged as invalid_grant"] = any("outcome=invalid_grant" in line for line in logs)
        context.close()
        context = new_browser(**{COOKIE: token_cookie(time.time() - 60, sid="sid_t21d")})
        switches["token"] = "500"
        response = refresh_call(context)
        checks["T21 SweatStack failing: 503, cookie kept"] = (
            response.status == 503 and cookie(context, COOKIE) is not None
        )
        context.close()

        # T22: GET /_proxy/token is for Streamlit, on the internal listener only.
        context = new_browser(**{COOKIE: token_cookie(time.time() + 600, sid="sid_t22")})
        context.request.get(f"{APP_URL}/page")  # the proxy reads the cookie and remembers the token
        session = {"X-SweatStack-Session": "sid_t22"}
        public = httpx.get(f"{APP_URL}/_proxy/token", headers=session)
        forwarded = httpx.get(f"{APP_URL}/_proxy/token", headers={**session, "X-Forwarded-For": "127.0.0.1"})
        checks["T22 not served on the public port, whatever the caller claims"] = (
            public.status_code == 404 and forwarded.status_code == 404
            and "access_old" not in public.text + forwarded.text
        )
        response = httpx.get(f"{INTERNAL_URL}/_proxy/token", params={"after": 0}, headers=session)
        answer = response.json() if response.status_code == 200 else {}
        checks["T22 internal port: the remembered access token"] = answer.get("access_token") == "access_old"
        checks["T22 internal port: the session id is required"] = (
            httpx.get(f"{INTERNAL_URL}/_proxy/token").status_code == 400
        )
        checks["T22 internal port: serves nothing else"] = (
            httpx.get(f"{INTERNAL_URL}/page").status_code == 404
            and httpx.post(f"{INTERNAL_URL}/_proxy/refresh", headers={"X-SweatStack-Refresh": "1"}).status_code == 404
        )
        start = time.monotonic()
        response = httpx.get(
            f"{INTERNAL_URL}/_proxy/token", params={"after": answer.get("expires_at", 0)}, headers=session, timeout=20
        )
        checks["T22 nothing newer: 404 after waiting 10 s"] = (
            response.status_code == 404 and 9.5 <= time.monotonic() - start <= 12
        )
        context.close()
        context = new_browser(**{COOKIE: token_cookie(time.time() + 120, sid="sid_t22w")})
        context.request.get(f"{APP_URL}/page")
        session = {"X-SweatStack-Session": "sid_t22w"}
        response = httpx.get(f"{INTERNAL_URL}/_proxy/token", params={"after": 0}, headers=session)
        remembered = response.json() if response.status_code == 200 else {"expires_at": 0}
        waited = {}

        def ask() -> None:
            start = time.monotonic()
            answer = httpx.get(
                f"{INTERNAL_URL}/_proxy/token", params={"after": remembered["expires_at"]}, headers=session, timeout=20
            )
            waited.update(answer=answer, seconds=time.monotonic() - start)

        asker = threading.Thread(target=ask)
        asker.start()
        time.sleep(1)
        refresh_call(context)  # the page refreshes while Streamlit waits
        asker.join()
        answer = waited["answer"].json() if waited["answer"].status_code == 200 else {}
        checks["T22 a waiting session gets the token the page's refresh brings"] = (
            answer.get("access_token") == "access_123" and waited["seconds"] < 5
        )
        context.close()

        # T23: sign-out ends the sign-in at SweatStack.
        context = new_browser(**{COOKIE: token_cookie(time.time() + 600, refresh_token="refresh_t23", sid="sid_t23")})
        context.request.get(f"{APP_URL}/page")
        page = context.new_page()
        page.goto(f"{APP_URL}/logout")
        checks["T23 sign-out revokes the refresh token, with the app's credentials"] = revoke_calls == [
            {"token": "refresh_t23", "client_id": "app_123", "client_secret": "secret_123"}
        ]
        checks["T23 sign-out deletes the cookie and forgets the session"] = (
            cookie(context, COOKIE) is None and "sid_t23" not in proxy._sessions
        )
        context.close()
        context = new_browser(**{COOKIE: token_cookie(time.time() + 600, sid="sid_t23b")})
        switches["revoke"] = "500"
        page = context.new_page()
        page.goto(f"{APP_URL}/logout")
        checks["T23 a failing revoke still signs out, and is logged"] = (
            cookie(context, COOKIE) is None and urlparse(page.url).path == "/"
            and any("revoke failed" in line for line in logs)
        )
        context.close()

        # T24: a WebSocket handshake that refreshes rewrites the cookie on its 101 response.
        context = new_browser(**{COOKIE: token_cookie(time.time() - 60, sid="sid_t24")})
        page = context.new_page()
        page.goto(f"{APP_URL}/_pwa/keepalive.js")  # an origin for the WebSocket, without a refresh
        message = page.evaluate("""() => new Promise(resolve => {
            const ws = new WebSocket(`ws://${location.host}/ws`);
            ws.onmessage = event => resolve(event.data);
            ws.onerror = () => resolve("error");
        })""")
        checks["T24 the handshake refreshes once"] = (
            message == "hello" and [call.get("grant_type") for call in token_calls] == ["refresh_token"]
        )
        checks["T24 the browser stores the cookie from the 101 response"] = (
            decoded(context).get("refresh_token") == "refresh_123" and decoded(context).get("sid") == "sid_t24"
        )
        checks["T24 Streamlit gets the new token and the session id"] = upstream_headers[-1] == {
            "x-sweatstack-token": "access_123", "x-sweatstack-session": "sid_t24"
        }
        context.close()

        # T25: the keepalive script is on signed-in pages only.
        signed_in = new_browser(**{COOKIE: token_cookie(time.time() + 600, sid="sid_t25")})
        signed_out = new_browser()
        checks["T25 keepalive.js on signed-in pages only"] = (
            "/_pwa/keepalive.js?v=" in signed_in.request.get(f"{APP_URL}/page").text()
            and "keepalive.js" not in signed_out.request.get(f"{APP_URL}/page").text()
        )
        signed_in.close()
        signed_out.close()

        # T27: a refresh whose answer never reaches the browser does not end the sign-in.
        def plain_get(path: str, cookie_value: str):
            """A request whose Set-Cookie nobody keeps: a lost response."""
            return httpx.get(f"{APP_URL}{path}", cookies={COOKIE: cookie_value})

        def cookie_of(response) -> dict:
            value = response.cookies.get(COOKIE)
            return (proxy._decode_token_cookie(value) or {}) if value else {}

        reset()
        old = token_cookie(time.time() - 60, refresh_token="refresh_t27", sid="sid_t27")
        first = plain_get("/page", old)
        again = plain_get("/page", old)  # the browser still has the old cookie
        checks["T27 the same old cookie again: the first refresh's result, no second token request"] = (
            cookie_of(first).get("refresh_token") == "refresh_123"
            and cookie_of(again).get("refresh_token") == "refresh_123"
            and [call.get("refresh_token") for call in token_calls] == ["refresh_t27"]
        )
        last = proxy._sessions["sid_t27"].last_refresh
        proxy._sessions["sid_t27"].last_refresh = (last[0], last[1]._replace(expires_at=time.time() - 60), last[2])
        later = plain_get("/page", old)  # hours later: that result's access token has expired too
        checks["T27 much later: refreshes the successor, never the retired token"] = (
            [call.get("refresh_token") for call in token_calls] == ["refresh_t27", "refresh_123"]
            and "TOKEN:yes" in later.text
        )

        # T28: Streamlit down while a request refreshes: the answer still carries the new cookie.
        reset()
        proxy.UPSTREAM_URL = "http://127.0.0.1:9"  # nothing listens there
        down = plain_get("/page", token_cookie(time.time() - 60, refresh_token="refresh_t28", sid="sid_t28"))
        proxy.UPSTREAM_URL = FAKE_URL
        checks["T28 HTTP, upstream down: 502 with the new cookie"] = (
            down.status_code == 502 and cookie_of(down).get("refresh_token") == "refresh_123"
        )
        context = new_browser(**{COOKIE: token_cookie(time.time() - 60, refresh_token="refresh_t28b", sid="sid_t28b")})
        page = context.new_page()
        page.goto(f"{APP_URL}/_pwa/keepalive.js")
        closed = page.evaluate("""() => new Promise(resolve => {
            const ws = new WebSocket(`ws://${location.host}/no-such-socket`);
            ws.onclose = event => resolve(event.code);
        })""")
        checks["T28 WebSocket, upstream refuses: the 101 still delivers the new cookie, then closes"] = (
            closed == 1011 and decoded(context).get("refresh_token") == "refresh_123"
        )
        context.close()

        # T29: a failed refresh while the old token still works: 503, so the page retries soon.
        context = new_browser(**{COOKIE: token_cookie(time.time() + 120, sid="sid_t29")})
        switches["token"] = "500"
        checks["T29 a failed refresh is a 503 even while the old token works"] = refresh_call(context).status == 503
        context.close()

        # T26: the log says what happened, and never names a token or a session id.
        never_logged = [
            "access_old", "access_123", "refresh_old", "refresh_123", "refresh_t23", "refresh_t27", "refresh_t28", legacy_sid,
            *(f"sid_{name}" for name in ("test", "t19", "t21a", "t21b", "t21c", "t21d", "t22", "t22w", "t23", "t23b", "t24", "t25", "t27", "t28", "t28b", "t29")),
        ]
        checks["T26 the log names no token and no session id"] = not [
            line for line in all_logs for secret in never_logged if secret and secret in line
        ]
        checks["T26 the log has the token events"] = all(
            any(event in line for line in all_logs)
            for event in ("token refresh via=refresh outcome=ok", "token refresh via=websocket outcome=ok",
                          "session token outcome=fresh", "session token outcome=waited", "session token outcome=timeout")
        )

        browser.close()

    fake_server.should_exit = True

    for name, ok in checks.items():
        print(f"  {'PASS' if ok else 'FAIL'}: {name}")
    print(f"  {sum(checks.values())}/{len(checks)} checks passed")
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
