import asyncio
import base64
import functools
import hashlib
import html
import io
import json
import logging
import mimetypes
import os
from collections.abc import Coroutine
from pathlib import Path
import secrets
import time
from typing import Any, NamedTuple
from urllib.parse import quote, urlencode

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import RedirectResponse, Response
from PIL import Image, ImageColor
from websockets.asyncio.client import ClientConnection, connect as ws_connect
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK

logger = logging.getLogger(__name__)


def _env_flag(name: str, default: bool) -> bool:
    """Read a boolean environment variable.

    Accepts true/false, 1/0, yes/no and on/off (case-insensitive). Unset or
    empty means ``default``. Anything else logs a warning and also falls back
    to ``default``, so a typo can never silently flip a setting.
    """
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    logger.warning("Ignoring %s=%r (expected true or false), using default: %s", name, raw, default)
    return default


# Configuration
UPSTREAM_URL = os.getenv("UPSTREAM_URL", "http://localhost:8501")
APP_URL = os.getenv("APP_URL", "http://localhost:8080")
SWEATSTACK_BASE_URL = "https://app.sweatstack.no"
SWEATSTACK_AUTHORIZE_URL = f"{SWEATSTACK_BASE_URL}/oauth/authorize"
SWEATSTACK_TOKEN_URL = f"{SWEATSTACK_BASE_URL}/api/v1/oauth/token"

SWEATSTACK_CLIENT_ID = os.getenv("SWEATSTACK_CLIENT_ID")
SWEATSTACK_CLIENT_SECRET = os.getenv("SWEATSTACK_CLIENT_SECRET")

TOKEN_COOKIE_NAME = "sweatstack_tokens"
RETURN_TO_COOKIE_NAME = "return_to"
AUTH_ATTEMPTED_COOKIE_NAME = "auth_attempted"
TOKEN_REFRESH_THRESHOLD_SECONDS = 20
COOKIE_MAX_AGE_SECONDS = 86400 * 365  # 365 days
DEFAULT_TOKEN_EXPIRY_SECONDS = 15 * 60

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required")

HTTPS_ONLY = _env_flag("HTTPS_ONLY", True)
AUTO_LOGIN = _env_flag("AUTO_LOGIN", False)
ALLOW_SIGNUP = _env_flag("ALLOW_SIGNUP", True)
PWA_INSTALL_BANNER = _env_flag("PWA_INSTALL_BANNER", True)

if os.getenv("FORWARD_REFRESH_TOKEN") is not None:
    logger.warning(
        "FORWARD_REFRESH_TOKEN is no longer supported and is ignored: the refresh token is "
        "always forwarded, because the app needs it to renew the access token during long sessions."
    )

# Headers the proxy sets on every request to Streamlit. Any client-supplied
# header with this prefix is dropped, so the app can trust these values.
SWEATSTACK_HEADER_PREFIX = "x-sweatstack-"
TOKEN_HEADER = "X-SweatStack-Token"
REFRESH_TOKEN_HEADER = "X-SweatStack-Refresh-Token"

HOP_BY_HOP_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-encoding",
    "content-length",
})

PROJECT_ROOT = Path(__file__).resolve().parent
STATIC_DIR = PROJECT_ROOT / "static"

# PWA configuration
_manifest_path = PROJECT_ROOT / "manifest.json"
if _manifest_path.is_file():
    MANIFEST = json.loads(_manifest_path.read_text())
    logger.info("Loaded manifest.json for PWA support")
else:
    MANIFEST = None


def _manifest_color(key: str) -> str:
    """Return a manifest color, falling back to white if it is missing or unparseable."""
    value = (MANIFEST or {}).get(key, "#ffffff")
    try:
        ImageColor.getrgb(str(value))
    except ValueError:
        logger.warning("Invalid %s %r in manifest.json, using #ffffff", key, value)
        return "#ffffff"
    return value


def _versioned_static_url(path: Path) -> str:
    """URL for a static/ file with a content hash, so browsers refetch it after it changes."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
    return f"/_pwa/{path.relative_to(STATIC_DIR).as_posix()}?v={digest}"


# iOS ignores the manifest for launch screens: it only shows an
# apple-touch-startup-image whose media query exactly matches the device. Each
# entry is a portrait screen in CSS pixels plus its pixel ratio. Images are
# rendered on demand from the app icon; see serve_splash().
_IOS_SCREENS = (
    (375, 667, 2),    # iPhone SE (2nd/3rd gen), 8
    (414, 896, 2),    # iPhone XR, 11
    (375, 812, 3),    # iPhone X, XS, 11 Pro, 12 mini, 13 mini
    (414, 896, 3),    # iPhone XS Max, 11 Pro Max
    (390, 844, 3),    # iPhone 12, 13, 14, 16e
    (428, 926, 3),    # iPhone 12/13 Pro Max, 14 Plus
    (393, 852, 3),    # iPhone 14 Pro, 15, 15 Pro, 16
    (430, 932, 3),    # iPhone 14 Pro Max, 15 Plus, 15 Pro Max, 16 Plus
    (402, 874, 3),    # iPhone 16 Pro
    (440, 956, 3),    # iPhone 16 Pro Max
    (744, 1133, 2),   # iPad mini (6th gen)
    (768, 1024, 2),   # iPad mini (5th gen), iPad 9.7"
    (810, 1080, 2),   # iPad 10.2"
    (820, 1180, 2),   # iPad Air (4th/5th gen), iPad (10th gen)
    (834, 1194, 2),   # iPad Pro 11"
    (1024, 1366, 2),  # iPad Pro 12.9"
)
SPLASH_SIZES = frozenset((width * ratio, height * ratio) for width, height, ratio in _IOS_SCREENS)
SPLASH_ICON_PATH = STATIC_DIR / "icon-512x512.png"
SERVICE_WORKER_PATH = STATIC_DIR / "sw.js"
INSTALL_BANNER_PATH = STATIC_DIR / "install-banner.js"


def _build_pwa_head_tags() -> str:
    """Manifest, iOS home-screen tags, splash screens and service worker registration."""
    name = html.escape(MANIFEST.get("name", ""))
    tags = [
        '<link rel="manifest" href="/manifest.json">',
        f'<meta name="theme-color" content="{html.escape(_manifest_color("theme_color"))}">',
        '<meta name="apple-mobile-web-app-capable" content="yes">',
        '<meta name="apple-mobile-web-app-status-bar-style" content="default">',
        f'<meta name="apple-mobile-web-app-title" content="{name}">',
        '<link rel="apple-touch-icon" sizes="180x180" href="/_pwa/icon-180x180.png">',
    ]
    if SPLASH_ICON_PATH.is_file():
        tags += [
            '<link rel="apple-touch-startup-image" media="screen and '
            f'(device-width:{width}px) and (device-height:{height}px) and '
            f'(-webkit-device-pixel-ratio:{ratio}) and (orientation:portrait)" '
            f'href="/_pwa/splash-{width * ratio}x{height * ratio}.png">'
            for width, height, ratio in _IOS_SCREENS
        ]
    if SERVICE_WORKER_PATH.is_file():
        tags.append('<script>if("serviceWorker"in navigator)navigator.serviceWorker.register("/sw.js")</script>')
    return "".join(tags)


def _build_install_banner_tag(authenticated: bool) -> str:
    """Script tag for static/install-banner.js; it reads its settings from the data attributes."""
    return (
        f'<script src="{_versioned_static_url(INSTALL_BANNER_PATH)}"'
        f' data-app-name="{html.escape(MANIFEST.get("name", ""))}"'
        f' data-theme-color="{html.escape(_manifest_color("theme_color"))}"'
        f' data-authenticated="{"true" if authenticated else "false"}"></script>'
    )


# Script that rewrites /login links at click time to include ?next= with the
# current page URL. Uses event delegation to handle Streamlit's dynamic DOM.
_LOGIN_NEXT_SCRIPT = (
    "<script>"
    "document.addEventListener('click',function(e){"
    'var a=e.target.closest(\'a[href="/login"]\');'
    "if(a)a.href='/login?next='+encodeURIComponent(location.pathname+location.search)"
    "});"
    "</script>"
)


def _build_head_html(authenticated: bool) -> str:
    """HTML injected at the start of <head> of every HTML page served through the proxy."""
    parts = [_LOGIN_NEXT_SCRIPT]
    if MANIFEST is not None:
        parts.append(_build_pwa_head_tags())
        if PWA_INSTALL_BANNER and INSTALL_BANNER_PATH.is_file():
            parts.append(_build_install_banner_tag(authenticated))
    return "".join(parts)


# Precomputed per login state: the install banner only targets logged-in users.
_HEAD_HTML = {authenticated: _build_head_html(authenticated) for authenticated in (False, True)}

TokenData = dict[str, Any]


def _validate_return_url(url: str) -> str:
    """Validate return URL to prevent open redirects.

    Only allows relative paths. Rejects empty strings, protocol-relative
    URLs (//...), backslash tricks (\\...), and absolute URLs.
    """
    if not url or not url.startswith("/") or url.startswith("//") or "\\" in url:
        return "/"
    return url


def _get_fernet() -> Fernet:
    """Create a Fernet instance using the session secret key."""
    key = hashlib.sha256(SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def _encode_token_cookie(access_token: str, refresh_token: str, expires_at: float) -> str:
    """Encrypt token data for cookie storage."""
    data = json.dumps({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at,
    })
    return _get_fernet().encrypt(data.encode()).decode()


def _decode_token_cookie(cookie_value: str) -> TokenData | None:
    """Decrypt and parse token cookie. Returns None if invalid."""
    try:
        decrypted = _get_fernet().decrypt(cookie_value.encode())
        return json.loads(decrypted)
    except (InvalidToken, json.JSONDecodeError):
        logger.warning("Failed to decrypt token cookie")
        return None


def _set_token_cookie(response: Response, cookie_value: str) -> None:
    """Set the token cookie with secure defaults."""
    response.set_cookie(
        TOKEN_COOKIE_NAME,
        cookie_value,
        httponly=True,
        secure=HTTPS_ONLY,
        samesite="lax",
        max_age=COOKIE_MAX_AGE_SECONDS,
    )


async def _refresh_access_token(refresh_token: str) -> TokenData | None:
    """Exchange refresh token for new access token."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            SWEATSTACK_TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": SWEATSTACK_CLIENT_ID,
                "client_secret": SWEATSTACK_CLIENT_SECRET,
            },
        )
        if response.status_code == 200:
            logger.info("Token refresh successful")
            return response.json()
        logger.warning("Token refresh failed: status=%d", response.status_code)
    return None


class Tokens(NamedTuple):
    """The user's current tokens, as resolved from the token cookie."""

    access_token: str | None = None
    refresh_token: str | None = None
    # Set when the tokens were refreshed and the cookie must be rewritten.
    new_cookie: str | None = None


async def _get_valid_tokens(cookies: dict[str, str]) -> Tokens:
    """Read the tokens from the cookie, refreshing them first if the access token is (nearly) expired.

    Returns empty ``Tokens`` when the user is not logged in or the refresh fails.
    """
    cookie_value = cookies.get(TOKEN_COOKIE_NAME)
    if not cookie_value:
        return Tokens()

    token_data = _decode_token_cookie(cookie_value)
    if not token_data:
        return Tokens()

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token") or None
    expires_at = token_data.get("expires_at", 0)

    if time.time() < expires_at - TOKEN_REFRESH_THRESHOLD_SECONDS:
        return Tokens(access_token, refresh_token)

    if not refresh_token:
        return Tokens()
    new_tokens = await _refresh_access_token(refresh_token)
    if not new_tokens:
        return Tokens()

    new_access = new_tokens.get("access_token")
    # Some OAuth servers rotate refresh tokens; keep the old one if none is returned.
    new_refresh = new_tokens.get("refresh_token") or refresh_token
    new_expires_in = new_tokens.get("expires_in", DEFAULT_TOKEN_EXPIRY_SECONDS)
    new_expires_at = time.time() + new_expires_in
    new_cookie = _encode_token_cookie(new_access, new_refresh, new_expires_at)
    return Tokens(new_access, new_refresh, new_cookie)


def _build_upstream_url(path: str, query_string: str = "", websocket: bool = False) -> str:
    """Build upstream URL from path and optional query string."""
    base = UPSTREAM_URL.rstrip("/")
    if websocket:
        base = base.replace("http://", "ws://").replace("https://", "wss://")
    url = f"{base}/{path}" if path else f"{base}/"
    if query_string:
        url = f"{url}?{query_string}"
    return url


def _prepare_upstream_headers(
    incoming_headers: dict[str, str],
    tokens: Tokens,
) -> dict[str, str]:
    """Prepare headers for upstream request, injecting the user's tokens if available.

    Client-supplied X-SweatStack-* headers are always dropped, so these headers
    only ever carry values set by the proxy.
    """
    headers = {
        name: value
        for name, value in incoming_headers.items()
        if not name.lower().startswith(SWEATSTACK_HEADER_PREFIX)
    }
    headers.pop("host", None)
    headers.pop("accept-encoding", None)
    if tokens.access_token:
        headers[TOKEN_HEADER] = tokens.access_token
    if tokens.refresh_token:
        headers[REFRESH_TOKEN_HEADER] = tokens.refresh_token
    return headers


def _filter_response_headers(headers: dict[str, str]) -> dict[str, str]:
    """Remove hop-by-hop headers that shouldn't be forwarded."""
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}


def _prepare_ws_connection_args(
    client_headers: dict[str, str],
    tokens: Tokens,
) -> tuple[dict[str, str], list[str]]:
    """Prepare headers and subprotocols for an upstream WebSocket connection.

    Extracts subprotocols from the client's Sec-WebSocket-Protocol header for
    separate negotiation via ``ws_connect(subprotocols=...)``, then strips all
    WebSocket handshake headers that the ``websockets`` library manages itself.

    Returns ``(headers, subprotocols)``.
    """
    _ws_handshake_headers = frozenset({
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-extensions",
    })

    headers = _prepare_upstream_headers(client_headers, tokens)

    subprotocols = [
        s.strip()
        for s in headers.pop("sec-websocket-protocol", "").split(",")
        if s.strip()
    ]

    for hdr in _ws_handshake_headers:
        headers.pop(hdr, None)

    return headers, subprotocols


# FastAPI app
app = FastAPI()

STATE_COOKIE_NAME = "oauth_state"


def _set_state_cookie(response: Response, state: str) -> None:
    """Set the OAuth state cookie."""
    response.set_cookie(
        STATE_COOKIE_NAME,
        state,
        httponly=True,
        secure=HTTPS_ONLY,
        samesite="lax",
        max_age=600,  # 10 minutes
    )


def _set_auth_attempted_cookie(response: Response) -> None:
    """Trip the auto-login circuit breaker.

    Set only after a *failed* OAuth round-trip (a callback that came back
    without usable tokens), never at flow initiation. This is what lets the
    proxy distinguish an automatic redirect loop — which always returns through
    /auth/callback with an error — from a user who simply abandoned the flow and
    came back to retry, who never hits the callback at all and should be
    auto-redirected again.
    """
    response.set_cookie(
        AUTH_ATTEMPTED_COOKIE_NAME,
        "1",
        httponly=True,
        secure=HTTPS_ONLY,
        samesite="lax",
        max_age=300,
    )


@app.get("/login")
async def login(request: Request):
    """Initiate OAuth2 login with SweatStack."""
    state = secrets.token_urlsafe(32)
    redirect_uri = f"{APP_URL}/auth/callback"

    params = {
        "client_id": SWEATSTACK_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "data:read,profile",
        "state": state,
        "prompt": "none",
    }
    if not ALLOW_SIGNUP:
        params["email_auth_mode"] = "existing_only"
    auth_url = f"{SWEATSTACK_AUTHORIZE_URL}?{urlencode(params)}"

    response = RedirectResponse(url=auth_url)
    _set_state_cookie(response, state)

    # Only set return_to when explicitly provided — error retries hit /login
    # without ?next=, and must not overwrite the cookie.
    next_url = request.query_params.get("next")
    if next_url is not None:
        response.set_cookie(
            RETURN_TO_COOKIE_NAME,
            _validate_return_url(next_url),
            httponly=True,
            secure=HTTPS_ONLY,
            samesite="lax",
            max_age=600,
        )

    logger.info("Login initiated, redirect_uri=%s", redirect_uri)
    return response


@app.get("/auth/callback")
async def auth_callback(request: Request):
    """Handle OAuth callback and store tokens in encrypted cookie."""
    return_to = _validate_return_url(request.cookies.get(RETURN_TO_COOKIE_NAME, "/"))

    # Verify state
    state_from_cookie = request.cookies.get(STATE_COOKIE_NAME)
    state_from_params = request.query_params.get("state")

    if not state_from_cookie or state_from_cookie != state_from_params:
        logger.warning("State mismatch: cookie=%s, param=%s", state_from_cookie, state_from_params)
        response = RedirectResponse(url=return_to)
        _set_auth_attempted_cookie(response)
        return response

    code = request.query_params.get("code")
    if not code:
        logger.warning("No authorization code received")
        response = RedirectResponse(url=return_to)
        _set_auth_attempted_cookie(response)
        return response

    # Exchange code for tokens
    redirect_uri = f"{APP_URL}/auth/callback"
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            SWEATSTACK_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": SWEATSTACK_CLIENT_ID,
                "client_secret": SWEATSTACK_CLIENT_SECRET,
            },
        )

    if token_response.status_code != 200:
        logger.warning("Token exchange failed: %s", token_response.text)
        response = RedirectResponse(url=return_to)
        _set_auth_attempted_cookie(response)
        return response

    token_data = token_response.json()
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    expires_in = token_data.get("expires_in", DEFAULT_TOKEN_EXPIRY_SECONDS)

    response = RedirectResponse(url=return_to)
    response.delete_cookie(STATE_COOKIE_NAME)
    response.delete_cookie(RETURN_TO_COOKIE_NAME)
    response.delete_cookie(AUTH_ATTEMPTED_COOKIE_NAME)

    if access_token:
        expires_at = time.time() + expires_in
        cookie_value = _encode_token_cookie(access_token, refresh_token or "", expires_at)
        _set_token_cookie(response, cookie_value)
        logger.info("User authenticated successfully")

    return response


@app.get("/logout")
async def logout():
    """Clear the token cookie and redirect to root."""
    response = RedirectResponse(url="/")
    response.delete_cookie(TOKEN_COOKIE_NAME)
    logger.info("User logged out")
    return response


@app.get("/manifest.json")
async def serve_manifest():
    """Serve the web app manifest."""
    if MANIFEST is None:
        return Response(status_code=404)
    return Response(
        content=json.dumps(MANIFEST),
        media_type="application/manifest+json",
        headers={"cache-control": "public, max-age=86400"},
    )


@app.get("/sw.js")
async def serve_service_worker():
    """Serve the service worker from the root, the only place it can control the whole app."""
    if not SERVICE_WORKER_PATH.is_file():
        return Response(status_code=404)
    return Response(
        content=SERVICE_WORKER_PATH.read_bytes(),
        media_type="text/javascript",
        headers={"cache-control": "no-cache"},
    )


@functools.cache
def _render_splash(width: int, height: int) -> bytes:
    """Render an iOS launch screen: the app icon centered on the manifest background color."""
    image = Image.new("RGB", (width, height), _manifest_color("background_color"))
    with Image.open(SPLASH_ICON_PATH) as source:
        icon = source.convert("RGBA")
    # About a third of the short side, never upscaled beyond the source icon.
    size = min(round(min(width, height) * 0.35), icon.width)
    icon = icon.resize((size, size), Image.Resampling.LANCZOS)
    image.paste(icon, ((width - size) // 2, (height - size) // 2), icon)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()


# Registered before the generic /_pwa/ route so it takes precedence.
@app.get("/_pwa/splash-{width:int}x{height:int}.png")
async def serve_splash(width: int, height: int):
    """Serve an iOS launch screen: static/splash-WxH.png if present, otherwise rendered from the icon."""
    if MANIFEST is None or (width, height) not in SPLASH_SIZES or not SPLASH_ICON_PATH.is_file():
        return Response(status_code=404)
    custom_path = STATIC_DIR / f"splash-{width}x{height}.png"
    if custom_path.is_file():
        content = custom_path.read_bytes()
    else:
        content = await asyncio.to_thread(_render_splash, width, height)
    return Response(
        content=content,
        media_type="image/png",
        headers={"cache-control": "public, max-age=604800"},
    )


@app.get("/_pwa/{file_path:path}")
async def serve_static(file_path: str):
    """Serve files from the static/ directory under /_pwa/ to avoid colliding with Streamlit's /static/."""
    safe_path = (STATIC_DIR / file_path).resolve()
    if not safe_path.is_relative_to(STATIC_DIR) or not safe_path.is_file():
        return Response(status_code=404)
    content_type = mimetypes.guess_type(str(safe_path))[0] or "application/octet-stream"
    return Response(
        content=safe_path.read_bytes(),
        media_type=content_type,
        headers={"cache-control": "public, max-age=604800"},
    )


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def http_proxy(full_path: str, request: Request) -> Response:
    """Proxy HTTP requests to upstream, injecting auth token if available."""
    query_string = request.scope.get("query_string", b"").decode()

    tokens = await _get_valid_tokens(request.cookies)
    authenticated = bool(tokens.access_token)

    # Auto-redirect unauthenticated browser navigations to login.
    if (
        AUTO_LOGIN
        and not authenticated
        and "text/html" in request.headers.get("accept", "")
        and AUTH_ATTEMPTED_COOKIE_NAME not in request.cookies
    ):
        next_url = f"/{full_path}"
        if query_string:
            next_url = f"{next_url}?{query_string}"
        # The circuit breaker (auth_attempted) is NOT tripped here. It is set
        # only when a failed OAuth attempt returns through /auth/callback, so
        # that a user who abandons the flow without completing it is still
        # auto-redirected when they retry, while an automatic redirect loop
        # (which always passes back through the callback) is still broken.
        return RedirectResponse(url=f"/login?next={quote(next_url, safe='')}")

    upstream_url = _build_upstream_url(full_path, query_string)
    headers = _prepare_upstream_headers(dict(request.headers), tokens)
    body = await request.body()

    async with httpx.AsyncClient(follow_redirects=True) as client:
        upstream_response = await client.request(
            request.method,
            upstream_url,
            headers=headers,
            content=body,
        )

    content = upstream_response.content
    content_type = upstream_response.headers.get("content-type", "")
    response_headers = _filter_response_headers(dict(upstream_response.headers))

    if "text/html" in content_type:
        page = content.decode("utf-8", errors="replace")
        head_pos = page.find("<head>")
        if head_pos != -1:
            insert_pos = head_pos + len("<head>")
            page = page[:insert_pos] + _HEAD_HTML[authenticated] + page[insert_pos:]
            content = page.encode("utf-8")
        # The injected HTML depends on the login state, so a cached copy (or a
        # 304 revalidation of one) could show a logged-in page's markup after logout.
        response_headers["cache-control"] = "no-store"
        for validator in ("etag", "last-modified"):
            response_headers.pop(validator, None)

    response = Response(
        content=content,
        status_code=upstream_response.status_code,
        headers=response_headers,
    )

    if tokens.new_cookie:
        _set_token_cookie(response, tokens.new_cookie)

    return response


async def _run_until_first_complete(*coros: Coroutine[Any, Any, None]) -> None:
    """Run coroutines concurrently until the first finishes, then cancel the rest.

    Unlike ``asyncio.gather`` — which waits for *every* coroutine, even after a
    sibling has already returned or raised — this tears the survivors down as
    soon as one completes. For a bidirectional relay that distinction is the
    whole game: once either direction ends, the connection is over, and a
    direction still blocked on a read would otherwise stay parked forever,
    keeping its captured connection objects alive (a slow resource leak).

    The completed coroutine's result is retrieved so any *unexpected* exception
    propagates to the caller; expected shutdowns return ``None`` quietly. The
    survivors are always cancelled and awaited, including when the caller itself
    is cancelled.
    """
    tasks = [asyncio.create_task(coro) for coro in coros]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()  # re-raise unexpected errors; clean shutdowns return None
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def _pump_client_to_upstream(websocket: WebSocket, upstream: ClientConnection) -> None:
    """Forward messages from the browser to the upstream Streamlit server."""
    try:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                break
            if "text" in message:
                await upstream.send(message["text"])
            elif "bytes" in message:
                await upstream.send(message["bytes"])
    except (WebSocketDisconnect, ConnectionClosedOK, ConnectionClosedError):
        # Browser hung up, or upstream closed while we were forwarding to it —
        # both are ordinary end-of-connection, not errors.
        pass


async def _pump_upstream_to_client(websocket: WebSocket, upstream: ClientConnection) -> None:
    """Forward messages from the upstream Streamlit server to the browser."""
    try:
        while True:
            data = await upstream.recv()
            if isinstance(data, str):
                await websocket.send_text(data)
            else:
                await websocket.send_bytes(data)
    except (ConnectionClosedOK, ConnectionClosedError, WebSocketDisconnect, RuntimeError):
        # Upstream closed, or the browser vanished before we finished sending.
        # Starlette surfaces a send-after-disconnect as a bare RuntimeError
        # ("Unexpected ASGI message 'websocket.send', after sending
        # 'websocket.close'"); within this send-only loop that only ever means
        # the peer is already gone, so it is an ordinary shutdown too.
        pass


@app.websocket("/{full_path:path}")
async def websocket_proxy(websocket: WebSocket, full_path: str):
    """Proxy WebSocket connections to upstream with auth token."""
    query_string = websocket.scope.get("query_string", b"").decode()
    upstream_url = _build_upstream_url(full_path, query_string, websocket=True)

    # If this refreshes the tokens, the new ones are used for this connection
    # only; the cookie is not updated, so the next request refreshes again.
    # That costs one extra token request and nothing else: SweatStack doesn't
    # rotate refresh tokens, and the session renews its own access token.
    tokens = await _get_valid_tokens(websocket.cookies)
    headers, subprotocols = _prepare_ws_connection_args(dict(websocket.headers), tokens)

    try:
        async with ws_connect(
            upstream_url,
            additional_headers=headers,
            subprotocols=subprotocols or None,
        ) as upstream:
            # Accept only after upstream connects — we need the negotiated
            # subprotocol, and there's no point accepting if upstream is down.
            await websocket.accept(subprotocol=upstream.subprotocol)

            # The two directions are independent; the moment either one ends,
            # the connection is done and the other is cancelled — so a direction
            # blocked on a read can never park and leak the connection.
            await _run_until_first_complete(
                _pump_client_to_upstream(websocket, upstream),
                _pump_upstream_to_client(websocket, upstream),
            )
    except Exception:
        logger.exception("WebSocket proxy error for %s", full_path)
