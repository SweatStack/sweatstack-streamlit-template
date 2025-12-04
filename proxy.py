import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import RedirectResponse, Response
from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK

logger = logging.getLogger(__name__)

# Configuration
UPSTREAM_URL = os.getenv("UPSTREAM_URL", "http://localhost:8501")
SWEATSTACK_BASE_URL = "https://app.sweatstack.no"
SWEATSTACK_AUTHORIZE_URL = f"{SWEATSTACK_BASE_URL}/oauth/authorize"
SWEATSTACK_TOKEN_URL = f"{SWEATSTACK_BASE_URL}/api/v1/oauth/token"

SWEATSTACK_CLIENT_ID = os.getenv("SWEATSTACK_CLIENT_ID")
SWEATSTACK_CLIENT_SECRET = os.getenv("SWEATSTACK_CLIENT_SECRET")

TOKEN_COOKIE_NAME = "sweatstack_tokens"
TOKEN_REFRESH_THRESHOLD_SECONDS = 20
COOKIE_MAX_AGE_SECONDS = 86400 * 365  # 365 days
DEFAULT_TOKEN_EXPIRY_SECONDS = 15 * 60

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required")

HTTPS_ONLY = os.getenv("HTTPS_ONLY", "true").lower() == "true"

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

TokenData = dict[str, Any]


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


async def _get_valid_token(cookies: dict[str, str]) -> tuple[str | None, str | None]:
    """
    Extract access token from cookies, refreshing if needed.
    Returns (access_token, new_cookie_value) where new_cookie_value is set
    if the token was refreshed and the cookie needs updating.
    """
    cookie_value = cookies.get(TOKEN_COOKIE_NAME)
    if not cookie_value:
        return None, None

    token_data = _decode_token_cookie(cookie_value)
    if not token_data:
        return None, None

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    expires_at = token_data.get("expires_at", 0)

    if time.time() >= expires_at - TOKEN_REFRESH_THRESHOLD_SECONDS:
        if refresh_token:
            new_tokens = await _refresh_access_token(refresh_token)
            if new_tokens:
                new_access = new_tokens.get("access_token")
                new_refresh = new_tokens.get("refresh_token", refresh_token)
                new_expires_in = new_tokens.get("expires_in", DEFAULT_TOKEN_EXPIRY_SECONDS)
                new_expires_at = time.time() + new_expires_in
                new_cookie = _encode_token_cookie(new_access, new_refresh, new_expires_at)
                return new_access, new_cookie
        return None, None

    return access_token, None


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
    incoming_headers: dict[str, str] | None,
    token: str | None,
) -> dict[str, str]:
    """Prepare headers for upstream request, injecting auth token if available."""
    headers = dict(incoming_headers) if incoming_headers else {}
    headers.pop("host", None)
    headers.pop("accept-encoding", None)
    if token:
        headers["X-SweatStack-Token"] = token
    return headers


def _filter_response_headers(headers: dict[str, str]) -> dict[str, str]:
    """Remove hop-by-hop headers that shouldn't be forwarded."""
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}


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


@app.get("/login")
async def login(request: Request):
    """Initiate OAuth2 login with SweatStack."""
    state = secrets.token_urlsafe(32)
    redirect_uri = str(request.url_for("auth_callback"))

    params = {
        "client_id": SWEATSTACK_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "data:read,profile",
        "state": state,
        "prompt": "none",
    }
    auth_url = f"{SWEATSTACK_AUTHORIZE_URL}?{urlencode(params)}"

    response = RedirectResponse(url=auth_url)
    _set_state_cookie(response, state)
    logger.info("Login initiated, redirect_uri=%s", redirect_uri)
    return response


@app.get("/auth/callback")
async def auth_callback(request: Request):
    """Handle OAuth callback and store tokens in encrypted cookie."""
    # Verify state
    state_from_cookie = request.cookies.get(STATE_COOKIE_NAME)
    state_from_params = request.query_params.get("state")

    if not state_from_cookie or state_from_cookie != state_from_params:
        logger.warning("State mismatch: cookie=%s, param=%s", state_from_cookie, state_from_params)
        return RedirectResponse(url="/login")

    code = request.query_params.get("code")
    if not code:
        logger.warning("No authorization code received")
        return RedirectResponse(url="/login")

    # Exchange code for tokens
    redirect_uri = str(request.url_for("auth_callback"))
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
        return RedirectResponse(url="/login")

    token_data = token_response.json()
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    expires_in = token_data.get("expires_in", DEFAULT_TOKEN_EXPIRY_SECONDS)

    response = RedirectResponse(url="/")
    response.delete_cookie(STATE_COOKIE_NAME)

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


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def http_proxy(full_path: str, request: Request) -> Response:
    """Proxy HTTP requests to upstream, injecting auth token if available."""
    query_string = request.scope.get("query_string", b"").decode()
    upstream_url = _build_upstream_url(full_path, query_string)

    token, new_cookie = await _get_valid_token(request.cookies)
    headers = _prepare_upstream_headers(dict(request.headers), token)
    body = await request.body()

    async with httpx.AsyncClient(follow_redirects=True) as client:
        upstream_response = await client.request(
            request.method,
            upstream_url,
            headers=headers,
            content=body,
        )

    response = Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=_filter_response_headers(dict(upstream_response.headers)),
    )

    if new_cookie:
        _set_token_cookie(response, new_cookie)

    return response


@app.websocket("/{full_path:path}")
async def websocket_proxy(websocket: WebSocket, full_path: str):
    """Proxy WebSocket connections to upstream with auth token."""
    await websocket.accept()

    query_string = websocket.scope.get("query_string", b"").decode()
    upstream_url = _build_upstream_url(full_path, query_string, websocket=True)

    token, _ = await _get_valid_token(websocket.cookies)
    headers = _prepare_upstream_headers(None, token)

    try:
        async with ws_connect(upstream_url, additional_headers=headers) as upstream:

            async def client_to_upstream():
                try:
                    while True:
                        message = await websocket.receive()
                        msg_type = message["type"]
                        if msg_type == "websocket.receive":
                            if "text" in message:
                                await upstream.send(message["text"])
                            elif "bytes" in message:
                                await upstream.send(message["bytes"])
                        elif msg_type == "websocket.disconnect":
                            break
                except WebSocketDisconnect:
                    pass

            async def upstream_to_client():
                try:
                    while True:
                        data = await upstream.recv()
                        if isinstance(data, str):
                            await websocket.send_text(data)
                        else:
                            await websocket.send_bytes(data)
                except (ConnectionClosedOK, ConnectionClosedError):
                    pass

            await asyncio.gather(client_to_upstream(), upstream_to_client())
    except Exception:
        logger.exception("WebSocket proxy error")
