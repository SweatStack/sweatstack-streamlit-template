"""
End-to-end test: sign-in, including one that finishes in another browser.

Runs the real proxy and real Chromium. SweatStack and the upstream app are one fake app, so no
Streamlit is needed and this runs from the repository root in seconds. Each Playwright context
is one browser with its own cookies.

Usage:
    uv run python test_sign_in_e2e.py

Exit code 0 = all checks pass.
"""
import base64
import logging
import os
import sys
import threading
import time
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlparse

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from playwright.sync_api import sync_playwright

FAKE_PORT, PROXY_PORT = 8597, 8080
FAKE_URL = f"http://127.0.0.1:{FAKE_PORT}"
APP_URL = f"http://localhost:{PROXY_PORT}"
PAGE = "/page?x=1"
FAILURE_TEXT = "Sign-in didn't finish"
SESSION_COOKIE = "ss_session"

authorize_calls: list[dict] = []
token_calls: list[dict] = []
issued_codes: list[str] = []
switches = {"deny": False, "token": "ok"}
logs: list[str] = []


def reset() -> None:
    authorize_calls.clear()
    token_calls.clear()
    issued_codes.clear()
    logs.clear()
    switches.update(deny=False, token="ok")


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
    if form.get("grant_type") == "refresh_token" or form.get("code") in issued_codes:
        return {"access_token": "access_123", "refresh_token": "refresh_123", "expires_in": 900}
    return JSONResponse({"error": "invalid_grant"}, status_code=400)


@fake.api_route("/{path:path}", methods=["GET", "POST"])
async def upstream(path: str, request: Request):
    has_token = "yes" if "x-sweatstack-token" in request.headers else "no"
    return HTMLResponse(f"<html><head></head>PAGE:{path}?{request.url.query} TOKEN:{has_token}</html>")


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
    proxy.UPSTREAM_URL = FAKE_URL

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            logs.append(record.getMessage())

    proxy.logger.addHandler(Capture(level=logging.WARNING))

    servers = [uvicorn.Server(uvicorn.Config(app, port=port, log_level="error", loop="asyncio"))
               for app, port in ((fake, FAKE_PORT), (proxy.app, PROXY_PORT))]
    for server in servers:
        threading.Thread(target=server.run, daemon=True).start()
    while not all(server.started for server in servers):
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

        def token_cookie(expires_at: float, refresh_token: str = "refresh_old") -> str:
            return proxy._encode_token_cookie("access_old", refresh_token, expires_at)

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

        browser.close()

    for server in servers:
        server.should_exit = True

    for name, ok in checks.items():
        print(f"  {'PASS' if ok else 'FAIL'}: {name}")
    print(f"  {sum(checks.values())}/{len(checks)} checks passed")
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
