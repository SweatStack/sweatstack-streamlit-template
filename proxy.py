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
import socket
from collections.abc import Coroutine
from dataclasses import dataclass, field
from pathlib import Path
import secrets
import time
from typing import Any, NamedTuple
from urllib.parse import quote, urlencode

import httpx
import uvicorn
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, RedirectResponse, Response
from PIL import Image, ImageColor
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.websockets import WebSocketState
from websockets.asyncio.client import ClientConnection, connect as ws_connect
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK

# Named, not __name__: `python proxy.py` runs this module as __main__.
logger = logging.getLogger("proxy")


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
# 127.0.0.1, not localhost: Streamlit listens on IPv4 loopback only, and localhost may resolve to ::1.
UPSTREAM_URL = os.getenv("UPSTREAM_URL", "http://127.0.0.1:8501")
APP_URL = os.getenv("APP_URL", "http://localhost:8080")
SWEATSTACK_BASE_URL = "https://app.sweatstack.no"
SWEATSTACK_AUTHORIZE_URL = f"{SWEATSTACK_BASE_URL}/oauth/authorize"
SWEATSTACK_TOKEN_URL = f"{SWEATSTACK_BASE_URL}/api/v1/oauth/token"
SWEATSTACK_REVOKE_URL = f"{SWEATSTACK_BASE_URL}/api/v1/oauth/revoke"

# Browsers connect to the public port. Streamlit asks for a newer access token on the internal
# port, which listens on loopback only: nothing outside the container can reach it.
PUBLIC_PORT = 8080
INTERNAL_PORT = 8081

SWEATSTACK_CLIENT_ID = os.getenv("SWEATSTACK_CLIENT_ID")
SWEATSTACK_CLIENT_SECRET = os.getenv("SWEATSTACK_CLIENT_SECRET")

TOKEN_COOKIE_NAME = "sweatstack_tokens"
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

DEFAULT_OAUTH_SCOPES = "activities:read sharing:read profile"
RETIRED_SCOPES = frozenset({"data:read", "data:write"})


def _parse_oauth_scopes(raw: str) -> str:
    """Normalize OAUTH_SCOPES to a space-separated string; empty means the default.

    A comma or a retired scope stops startup: either would otherwise surface only as a
    failed sign-in, and for some users only.
    """
    scopes = raw.split()
    if not scopes:
        return DEFAULT_OAUTH_SCOPES
    if "," in raw or RETIRED_SCOPES.intersection(scopes):
        raise RuntimeError(
            f"Invalid OAUTH_SCOPES {raw!r}: separate scopes with spaces and use category scopes "
            "such as activities:read. See 'Data Access' in README.md."
        )
    return " ".join(scopes)


OAUTH_SCOPES = _parse_oauth_scopes(os.getenv("OAUTH_SCOPES", ""))

if os.getenv("FORWARD_REFRESH_TOKEN") is not None:
    logger.warning(
        "FORWARD_REFRESH_TOKEN is no longer supported and is ignored: the refresh token is never "
        "forwarded. Only the proxy holds it; the app gets fresh access tokens from the proxy."
    )

# Headers the proxy sets on every request to Streamlit. Any client-supplied
# header with this prefix is dropped, so the app can trust these values.
SWEATSTACK_HEADER_PREFIX = "x-sweatstack-"
TOKEN_HEADER = "X-SweatStack-Token"
# Names the browser's sign-in to the proxy. Streamlit sends it back to /_proxy/token.
SESSION_HEADER = "X-SweatStack-Session"
# Required on POST /_proxy/refresh: a cross-site form cannot set a custom header.
REFRESH_REQUEST_HEADER = "X-SweatStack-Refresh"

# The page asks for a refresh when the access token expires within this time (keepalive.js asks
# 3 minutes before expiry, so a throttled timer in a hidden tab still comes in time).
PAGE_REFRESH_WINDOW_SECONDS = 5 * 60
# How long /_proxy/token waits for the page to refresh before it answers 404.
SESSION_TOKEN_WAIT_SECONDS = 10
# /_proxy/token never hands out a token that expires sooner than this: the library would take it
# for expired (it renews 5 s early) and ask again at once.
SESSION_TOKEN_MIN_LIFETIME_SECONDS = 10
# A refresh's result is kept until the next refresh of the sign-in replaces it, and at most this
# long. A request that presents the refresh token it retired gets that result again, without asking
# SweatStack: its cookie is from before the response that carried the new one, which may never have
# reached the browser (a failed upstream, a lost response). SweatStack's own grace period is only
# 30 seconds; after it, presenting a retired token ends the sign-in.
LAST_REFRESH_KEPT_SECONDS = 24 * 60 * 60
SESSION_SWEEP_INTERVAL_SECONDS = 60
REVOKE_TIMEOUT_SECONDS = 5
TOKEN_REQUEST_TIMEOUT_SECONDS = 15

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


def _contrast_color(color: str) -> str:
    """Black or white, whichever reads best on ``color``. Same formula as textColorFor in static/install-banner.js."""
    channels = [
        channel / 255 / 12.92 if channel / 255 <= 0.03928 else ((channel / 255 + 0.055) / 1.055) ** 2.4
        for channel in ImageColor.getrgb(color)[:3]
    ]
    luminance = 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]
    return "#000000" if luminance > 0.179 else "#ffffff"


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
KEEPALIVE_PATH = STATIC_DIR / "keepalive.js"


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
    if authenticated:
        # Keeps the sign-in fresh while the page is open; see static/keepalive.js.
        parts.append(f'<script src="{_versioned_static_url(KEEPALIVE_PATH)}" defer></script>')
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


def _new_session_id() -> str:
    """128 random bits naming one sign-in in this browser; minted at sign-in, kept across refreshes."""
    return secrets.token_urlsafe(16)


def _log_id(sid: str | None) -> str:
    """What the log says instead of the session id, which must never be logged."""
    return hashlib.sha256(sid.encode()).hexdigest()[:8] if sid else "-"


def _encode_token_cookie(access_token: str, refresh_token: str, expires_at: float, sid: str) -> str:
    """Encrypt token data for cookie storage."""
    data = json.dumps({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at,
        "sid": sid,
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


class Refreshed(NamedTuple):
    """A refresh's result: the new tokens, or why there are none."""

    access_token: str | None = None
    refresh_token: str | None = None
    expires_at: float = 0.0
    # SweatStack refused the refresh token (invalid_grant): the sign-in is over.
    signed_out: bool = False


async def _refresh_access_token(refresh_token: str) -> Refreshed:
    """Exchange the refresh token for new tokens. SweatStack rotates the refresh token every time."""
    try:
        async with httpx.AsyncClient(timeout=TOKEN_REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.post(
                SWEATSTACK_TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": SWEATSTACK_CLIENT_ID,
                    "client_secret": SWEATSTACK_CLIENT_SECRET,
                },
            )
    except httpx.HTTPError as exc:
        logger.warning("token refresh failed: %s", type(exc).__name__)
        return Refreshed()
    try:
        body = response.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        body = {}
    if response.status_code == 200 and body.get("access_token"):
        expires_in = body.get("expires_in")
        if not isinstance(expires_in, (int, float)) or isinstance(expires_in, bool):
            expires_in = DEFAULT_TOKEN_EXPIRY_SECONDS
        return Refreshed(
            access_token=body["access_token"],
            # A server that does not rotate sends none: keep the old one.
            refresh_token=body.get("refresh_token") or refresh_token,
            expires_at=time.time() + expires_in,
        )
    if response.status_code in (400, 401) and body.get("error") == "invalid_grant":
        return Refreshed(signed_out=True)
    logger.warning("token refresh failed: status=%d error=%s", response.status_code, body.get("error"))
    return Refreshed()


@dataclass
class _Session:
    """What the proxy remembers, in memory, about one sign-in (one session id).

    A cache only: after a restart it is empty, and every cookie the proxy reads fills it again.
    """

    # Serializes the refreshes of this sign-in within the process.
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    # The newest access token the proxy has seen for this sign-in, for Streamlit (/_proxy/token).
    access_token: str | None = None
    expires_at: float = 0.0
    # Set when a newer access token arrives, then replaced; /_proxy/token waits on it.
    changed: asyncio.Event = field(default_factory=asyncio.Event)
    waiters: int = 0
    # The last refresh: the digest of the refresh token it presented, its result, and when.
    last_refresh: tuple[str, Refreshed, float] | None = None


_sessions: dict[str, _Session] = {}
_last_sweep = 0.0


def _session(sid: str) -> _Session:
    return _sessions.setdefault(sid, _Session())


def _remember(sid: str, access_token: str, expires_at: float) -> None:
    """Keep the newest access token of a sign-in for Streamlit; an older one never replaces it."""
    record = _session(sid)
    if expires_at > record.expires_at:
        record.access_token, record.expires_at = access_token, expires_at
        record.changed.set()
        record.changed = asyncio.Event()
    _sweep()


def _sweep() -> None:
    """Drop the records of sign-ins nobody uses: token expired, no refresh running, nobody waiting.

    Runs at most once a minute, on a write.
    """
    global _last_sweep
    now = time.time()
    if now - _last_sweep < SESSION_SWEEP_INTERVAL_SECONDS:
        return
    _last_sweep = now
    for sid, record in list(_sessions.items()):
        kept = record.last_refresh is not None and now - record.last_refresh[2] < LAST_REFRESH_KEPT_SECONDS
        if record.expires_at < now and not record.lock.locked() and record.waiters == 0 and not kept:
            del _sessions[sid]


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def _refresh(sid: str, refresh_token: str, via: str, refresh_within: float) -> Refreshed:
    """Refresh one sign-in, one refresh at a time.

    A request that presents the refresh token the last refresh retired gets that refresh's result
    again, without asking SweatStack: its cookie is from before the response that carried the new
    one, which may never have reached the browser. Should that result's access token itself need a
    refresh by now, its refresh token, which SweatStack still takes, is refreshed instead.
    """
    record = _session(sid)
    async with record.lock:
        presented = refresh_token
        last = record.last_refresh
        if last and last[0] == _digest(presented) and time.time() - last[2] < LAST_REFRESH_KEPT_SECONDS:
            if time.time() < last[1].expires_at - refresh_within:
                logger.info("token refresh via=%s outcome=reused session=%s", via, _log_id(sid))
                return last[1]
            presented = last[1].refresh_token or presented
        result = await _refresh_access_token(presented)
        if result.access_token:
            record.last_refresh = (_digest(presented), result, time.time())
            _remember(sid, result.access_token, result.expires_at)
            outcome = "ok"
        else:
            outcome = "invalid_grant" if result.signed_out else "error"
        log = logger.info if outcome == "ok" else logger.warning
        log("token refresh via=%s outcome=%s session=%s", via, outcome, _log_id(sid))
        return result


class Tokens(NamedTuple):
    """The user's current access token, as resolved from the token cookie.

    The refresh token is deliberately not here: it never leaves the cookie and the refresh.
    """

    access_token: str | None = None
    sid: str | None = None
    expires_at: float = 0.0
    # Set when the cookie must be rewritten: after a refresh, or to add a session id.
    new_cookie: str | None = None
    # The sign-in is over (SweatStack refused the refresh token): delete the cookie.
    signed_out: bool = False
    # A refresh was needed and failed for another reason (network, SweatStack down): try again later.
    failed: bool = False


def _read_token_cookie(cookies: dict[str, str]) -> TokenData | None:
    cookie_value = cookies.get(TOKEN_COOKIE_NAME)
    return _decode_token_cookie(cookie_value) if cookie_value else None


async def _get_valid_tokens(
    cookies: dict[str, str],
    *,
    via: str,
    refresh_within: float = TOKEN_REFRESH_THRESHOLD_SECONDS,
) -> Tokens:
    """Read the tokens from the cookie, refreshing them first if the access token expires within
    ``refresh_within`` seconds.

    Only call this where the response can rewrite the cookie (``new_cookie``): a refresh retires
    the refresh token the cookie holds.
    """
    token_data = _read_token_cookie(cookies)
    if not token_data:
        return Tokens()

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token") or None
    expires_at = token_data.get("expires_at", 0)
    sid = token_data.get("sid")
    new_cookie = None
    if not sid:  # a cookie from before 0.4.0: give it a session id
        sid = _new_session_id()
        new_cookie = _encode_token_cookie(access_token, refresh_token or "", expires_at, sid)

    now = time.time()
    still_valid = now < expires_at - TOKEN_REFRESH_THRESHOLD_SECONDS
    if now < expires_at - refresh_within or (still_valid and not refresh_token):
        _remember(sid, access_token, expires_at)
        return Tokens(access_token, sid, expires_at, new_cookie)
    if not refresh_token:
        return Tokens(signed_out=True)

    result = await _refresh(sid, refresh_token, via, refresh_within)
    if result.signed_out:
        _sessions.pop(sid, None)
        return Tokens(signed_out=True)
    if not result.access_token:
        if still_valid:
            return Tokens(access_token, sid, expires_at, new_cookie, failed=True)
        return Tokens(failed=True)
    new_cookie = _encode_token_cookie(result.access_token, result.refresh_token, result.expires_at, sid)
    return Tokens(result.access_token, sid, result.expires_at, new_cookie)


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
    """Prepare headers for upstream request, injecting the user's access token and session id.

    Client-supplied X-SweatStack-* headers are always dropped, so these headers
    only ever carry values set by the proxy. The refresh token is never forwarded.
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
        if tokens.sid:
            headers[SESSION_HEADER] = tokens.sid
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
FIRST_ATTEMPT, RETRY_ATTEMPT = 1, 2
MAX_STATE_NEXT_BYTES = 1024


class OAuthState(NamedTuple):
    attempt: int
    next_url: str


def _build_state(attempt: int, next_url: str) -> str:
    """Build `{nonce}.{attempt}.{next}`. The attempt and page ride in the URL because cookies
    are exactly what is missing after a browser switch. An overlong page falls back to `/`,
    since the whole state must fit in the state cookie."""
    raw = next_url.encode()
    if next_url == "/" or len(raw) > MAX_STATE_NEXT_BYTES:
        raw = b""
    page = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return f"{secrets.token_urlsafe(32)}.{attempt}.{page}"


def _parse_state(state: str | None) -> OAuthState | None:
    """Parse a state from the URL, which anyone can edit. None means it isn't ours: no retry."""
    try:
        nonce, attempt, page = (state or "").split(".")
        next_url = base64.urlsafe_b64decode(page + "=" * (-len(page) % 4)).decode()
    except ValueError:  # includes binascii.Error and UnicodeDecodeError
        return None
    if not nonce or attempt not in {"1", "2"}:
        return None
    return OAuthState(int(attempt), _validate_return_url(next_url))


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


def _sign_in_failed_response(next_url: str) -> Response:
    """The page shown when a sign-in can't be completed or restarted.

    It trips the auto-login circuit breaker, and Try again is the only way onward.
    """
    background = _manifest_color("background_color")
    button = _manifest_color("theme_color")
    text_color = _contrast_color(background)
    # next_url is attacker-controlled: quote(safe='') is what makes it safe in this attribute.
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign-in didn't finish</title>
</head>
<body style="margin:0;padding:2rem;font-family:system-ui,sans-serif;text-align:center;background:{html.escape(background)};color:{text_color}">
<h1>Sign-in didn't finish</h1>
<p>Try again in this browser.</p>
<a href="/login?next={quote(next_url, safe='')}" style="display:inline-block;padding:.75rem 1.5rem;border-radius:.5rem;text-decoration:none;background:{html.escape(button)};color:{_contrast_color(button)};border:1px solid {text_color}">Try again</a>
</body>
</html>
"""
    response = Response(
        content=page,
        status_code=400,
        media_type="text/html; charset=utf-8",
        headers={"cache-control": "no-store"},
    )
    _set_auth_attempted_cookie(response)
    return response


@app.get("/login")
async def login(request: Request):
    """Initiate OAuth2 login with SweatStack."""
    attempt = RETRY_ATTEMPT if request.query_params.get("retry") == "1" else FIRST_ATTEMPT
    next_url = _validate_return_url(request.query_params.get("next", ""))
    state = _build_state(attempt, next_url)
    redirect_uri = f"{APP_URL}/auth/callback"

    params = {
        "client_id": SWEATSTACK_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": OAUTH_SCOPES,
        "state": state,
    }
    if not ALLOW_SIGNUP:
        params["email_auth_mode"] = "existing_only"
    auth_url = f"{SWEATSTACK_AUTHORIZE_URL}?{urlencode(params)}"

    response = RedirectResponse(url=auth_url)
    _set_state_cookie(response, state)

    logger.info("Login initiated, redirect_uri=%s", redirect_uri)
    return response


async def _exchange_code(code: str) -> TokenData | None:
    """Exchange an authorization code for tokens. Returns None, after logging, if that fails."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                SWEATSTACK_TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": f"{APP_URL}/auth/callback",
                    "client_id": SWEATSTACK_CLIENT_ID,
                    "client_secret": SWEATSTACK_CLIENT_SECRET,
                },
            )
    except httpx.HTTPError as exc:
        logger.warning("Sign-in failed: token exchange: %s: %s", type(exc).__name__, exc)
        return None
    if response.status_code != 200:
        logger.warning("Sign-in failed: token exchange: status=%d", response.status_code)
        return None
    try:
        token_data = response.json()
    except ValueError:
        logger.warning("Sign-in failed: token exchange: invalid JSON")
        return None
    if not isinstance(token_data, dict) or not token_data.get("access_token"):
        logger.warning("Sign-in failed: token exchange: no access_token")
        return None
    return token_data


async def _finish_verified_sign_in(request: Request, code: str | None, next_url: str) -> Response:
    """Rows 1 to 3 of the callback: the state matched, so it is used up whatever happens next."""
    if code:
        token_data = await _exchange_code(code)
    else:
        logger.warning("Sign-in failed: SweatStack returned error %r", request.query_params.get("error"))
        token_data = None

    if token_data is None:
        response = _sign_in_failed_response(next_url)
        response.delete_cookie(STATE_COOKIE_NAME)
        return response

    expires_at = time.time() + token_data.get("expires_in", DEFAULT_TOKEN_EXPIRY_SECONDS)
    sid = _new_session_id()
    cookie_value = _encode_token_cookie(
        token_data["access_token"], token_data.get("refresh_token") or "", expires_at, sid
    )
    _remember(sid, token_data["access_token"], expires_at)
    response = RedirectResponse(url=next_url)
    response.delete_cookie(STATE_COOKIE_NAME)
    response.delete_cookie(AUTH_ATTEMPTED_COOKIE_NAME)
    _set_token_cookie(response, cookie_value)
    logger.info("User authenticated successfully")
    return response


@app.get("/auth/callback")
async def auth_callback(request: Request):
    """Finish sign-in. A code is only ever exchanged in the browser that started the flow."""
    state = request.query_params.get("state")
    code = request.query_params.get("code")
    state_cookie = request.cookies.get(STATE_COOKIE_NAME)
    parsed = _parse_state(state)
    next_url = parsed.next_url if parsed else "/"

    if state_cookie and state_cookie == state:
        return await _finish_verified_sign_in(request, code, next_url)

    tokens = await _get_valid_tokens(request.cookies, via="http")
    if tokens.access_token:
        response = RedirectResponse(url=next_url)
        if tokens.new_cookie:
            _set_token_cookie(response, tokens.new_cookie)
        return response

    if state_cookie:
        logger.warning("Sign-in failed: state mismatch")
    elif code and parsed and parsed.attempt == FIRST_ATTEMPT:
        logger.warning("Sign-in restarted: no state cookie")
        return RedirectResponse(url=f"/login?retry=1&next={quote(next_url, safe='')}")
    else:
        logger.warning("Sign-in failed: no state cookie")
    return _sign_in_failed_response(next_url)


async def _revoke(refresh_token: str) -> None:
    """End the sign-in at SweatStack (RFC 7009). Best effort: signing out never waits long or fails."""
    data = {"token": refresh_token, "client_id": SWEATSTACK_CLIENT_ID}
    if SWEATSTACK_CLIENT_SECRET:
        data["client_secret"] = SWEATSTACK_CLIENT_SECRET
    try:
        async with httpx.AsyncClient(timeout=REVOKE_TIMEOUT_SECONDS) as client:
            response = await client.post(SWEATSTACK_REVOKE_URL, data=data)
    except httpx.HTTPError as exc:
        logger.warning("revoke failed: %s", type(exc).__name__)
        return
    if response.status_code != 200:
        logger.warning("revoke failed: status=%d", response.status_code)


@app.get("/logout")
async def logout(request: Request):
    """Sign out: end the sign-in at SweatStack, clear the token cookie and redirect to root."""
    token_data = _read_token_cookie(request.cookies)
    if token_data:
        if refresh_token := token_data.get("refresh_token"):
            await _revoke(refresh_token)
        if sid := token_data.get("sid"):
            _sessions.pop(sid, None)
    response = RedirectResponse(url="/")
    response.delete_cookie(TOKEN_COOKIE_NAME)
    logger.info("User logged out")
    return response


@app.post("/_proxy/refresh")
async def refresh_for_page(request: Request) -> Response:
    """Keep the sign-in fresh for an open page (static/keepalive.js).

    Refreshes when the access token expires within PAGE_REFRESH_WINDOW_SECONDS, rewrites the
    cookie, and answers how long the access token is valid for, as a duration so that the
    page's own clock does not matter. Without a sign-in, or once SweatStack has ended it: 401.
    """
    no_store = {"cache-control": "no-store"}
    if request.headers.get(REFRESH_REQUEST_HEADER) != "1":
        return JSONResponse({"detail": f"{REFRESH_REQUEST_HEADER}: 1 required"}, status_code=403, headers=no_store)
    tokens = await _get_valid_tokens(request.cookies, via="refresh", refresh_within=PAGE_REFRESH_WINDOW_SECONDS)
    if tokens.failed:
        # Also when the old access token still works: SweatStack may have rotated the token
        # without the answer arriving, and only a retry within its 30-second grace period gets
        # the same new token back. The page retries in 10 seconds.
        return JSONResponse({"detail": "refresh failed, try again"}, status_code=503, headers=no_store)
    if tokens.access_token:
        expires_in = max(0, int(tokens.expires_at - time.time()))
        response = JSONResponse({"expires_in": expires_in}, headers=no_store)
        if tokens.new_cookie:
            _set_token_cookie(response, tokens.new_cookie)
        return response
    response = JSONResponse({"detail": "not signed in"}, status_code=401, headers=no_store)
    response.delete_cookie(TOKEN_COOKIE_NAME)
    return response


@app.api_route("/_proxy/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def proxy_reserved(rest: str) -> Response:
    """/_proxy/ belongs to the proxy. Anything else under it, such as /_proxy/token, which only
    the internal listener serves, is a 404 here rather than a request to Streamlit."""
    return Response(status_code=404)


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

    tokens = await _get_valid_tokens(request.cookies, via="http")
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
        redirect = RedirectResponse(url=f"/login?next={quote(next_url, safe='')}")
        if tokens.signed_out:
            redirect.delete_cookie(TOKEN_COOKIE_NAME)
        return redirect

    upstream_url = _build_upstream_url(full_path, query_string)
    headers = _prepare_upstream_headers(dict(request.headers), tokens)
    body = await request.body()

    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            upstream_response = await client.request(
                request.method,
                upstream_url,
                headers=headers,
                content=body,
            )
    except httpx.HTTPError as exc:
        # Streamlit is down or restarting. A refresh may already have rotated the refresh
        # token, so this answer must still carry the new cookie.
        logger.warning("upstream unavailable: %s", type(exc).__name__)
        response = Response("Service unavailable", status_code=502, headers={"cache-control": "no-store"})
        response.raw_headers.extend(_cookie_headers(tokens))
        return response

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
    elif tokens.signed_out:
        response.delete_cookie(TOKEN_COOKIE_NAME)

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


def _cookie_headers(tokens: Tokens) -> list[tuple[bytes, bytes]]:
    """The Set-Cookie headers a response needs for these tokens, as raw ASGI headers."""
    response = Response()
    if tokens.new_cookie:
        _set_token_cookie(response, tokens.new_cookie)
    elif tokens.signed_out:
        response.delete_cookie(TOKEN_COOKIE_NAME)
    return [(name, value) for name, value in response.raw_headers if name == b"set-cookie"]


@app.websocket("/{full_path:path}")
async def websocket_proxy(websocket: WebSocket, full_path: str):
    """Proxy WebSocket connections to upstream with auth token."""
    query_string = websocket.scope.get("query_string", b"").decode()
    upstream_url = _build_upstream_url(full_path, query_string, websocket=True)

    # A refresh here rotates the refresh token, so the new cookie goes out on the
    # 101 response that accepts the connection: the cookie never keeps a
    # refresh token SweatStack has retired.
    tokens = await _get_valid_tokens(websocket.cookies, via="websocket")
    headers, subprotocols = _prepare_ws_connection_args(dict(websocket.headers), tokens)

    try:
        async with ws_connect(
            upstream_url,
            additional_headers=headers,
            subprotocols=subprotocols or None,
        ) as upstream:
            # Accept only after upstream connects — we need the negotiated
            # subprotocol, and there's no point accepting if upstream is down.
            await websocket.accept(subprotocol=upstream.subprotocol, headers=_cookie_headers(tokens))

            # The two directions are independent; the moment either one ends,
            # the connection is done and the other is cancelled — so a direction
            # blocked on a read can never park and leak the connection.
            await _run_until_first_complete(
                _pump_client_to_upstream(websocket, upstream),
                _pump_upstream_to_client(websocket, upstream),
            )
    except Exception:
        logger.exception("WebSocket proxy error for %s", full_path)
        # A refresh may already have rotated the refresh token. If the connection was never
        # accepted, accept it to deliver the new cookie on the 101, then close: the page reconnects.
        cookie_headers = _cookie_headers(tokens)
        if cookie_headers and websocket.client_state == WebSocketState.CONNECTING:
            try:
                await websocket.accept(headers=cookie_headers)
                await websocket.close(code=1011)
            except Exception:  # the browser is gone too: nothing left to deliver
                pass


# The internal app: served only on the internal listener (127.0.0.1:INTERNAL_PORT), for Streamlit.
internal_app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)


def _fresh_token(record: _Session | None, after: float) -> _Session | None:
    """The record, if it holds an access token newer than ``after`` that is not about to expire."""
    if record is None or record.access_token is None:
        return None
    if record.expires_at > max(after, time.time() + SESSION_TOKEN_MIN_LIFETIME_SECONDS):
        return record
    return None


def _token_answer(record: _Session) -> JSONResponse:
    return JSONResponse(
        {"access_token": record.access_token, "expires_at": record.expires_at},
        headers={"cache-control": "no-store"},
    )


@internal_app.get("/_proxy/token")
async def session_token(request: Request) -> Response:
    """A newer access token for a Streamlit session whose handshake token has expired.

    Answers from memory: the newest token any refresh or cookie read has seen for the session
    id. When there is none newer than ``after`` (the caller's token's expiry), it waits up to
    SESSION_TOKEN_WAIT_SECONDS for the page to refresh, then answers 404. It never refreshes
    itself: it has no cookie to rewrite, and the cookie must stay the only holder of the
    refresh token.
    """
    sid = request.headers.get(SESSION_HEADER)
    if not sid:
        return JSONResponse({"detail": f"{SESSION_HEADER} required"}, status_code=400)
    try:
        after = float(request.query_params.get("after", "0"))
    except ValueError:
        return JSONResponse({"detail": "after must be a number"}, status_code=400)

    if found := _fresh_token(_sessions.get(sid), after):
        logger.info("session token outcome=fresh session=%s", _log_id(sid))
        return _token_answer(found)

    waiting = _session(sid)  # the record this request counts itself on
    waiting.waiters += 1
    deadline = time.monotonic() + SESSION_TOKEN_WAIT_SECONDS
    try:
        while (remaining := deadline - time.monotonic()) > 0:
            try:
                await asyncio.wait_for(_session(sid).changed.wait(), timeout=remaining)
            except asyncio.TimeoutError:
                break
            if found := _fresh_token(_sessions.get(sid), after):
                logger.info("session token outcome=waited session=%s", _log_id(sid))
                return _token_answer(found)
    finally:
        waiting.waiters -= 1
    logger.warning("session token outcome=timeout session=%s", _log_id(sid))
    return JSONResponse({"detail": "no newer access token"}, status_code=404)


def _dispatch(internal_port: int) -> ASGIApp:
    """Route each connection by the listener it arrived on: the internal one to ``internal_app``.

    ``scope["server"]`` is the local address of the socket the connection came in on, so this
    does not depend on the caller's address or on any forwarded header.
    """

    async def dispatch(scope: Scope, receive: Receive, send: Send) -> None:
        server = scope.get("server") or (None, None)
        if scope["type"] in ("http", "websocket") and server[1] == internal_port:
            await internal_app(scope, receive, send)
        else:
            await app(scope, receive, send)

    return dispatch


def _listen(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(2048)
    sock.set_inheritable(True)
    return sock


async def serve(
    public_port: int = PUBLIC_PORT,
    internal_port: int = INTERNAL_PORT,
    *,
    public_host: str = "0.0.0.0",
    log_level: str = "info",
) -> None:
    """Run the proxy: browsers on public_host:public_port, Streamlit on 127.0.0.1:internal_port.

    One process and one server for both, because /_proxy/token answers from this process's memory.
    """
    sockets = [_listen(public_host, public_port), _listen("127.0.0.1", internal_port)]
    config = uvicorn.Config(_dispatch(internal_port), loop="asyncio", log_level=log_level)
    await uvicorn.Server(config).serve(sockets=sockets)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:     %(name)s: %(message)s")
    asyncio.run(serve())
