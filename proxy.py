import os
import time
import asyncio
from typing import Dict

import httpx
from itsdangerous import URLSafeSerializer
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import RedirectResponse, Response
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import ConnectionClosedOK, ConnectionClosedError

# -------------------------------------------------------------------
# Config – read from environment
# -------------------------------------------------------------------
UPSTREAM_HTTP = os.getenv("UPSTREAM_HTTP", "http://127.0.0.1:8501")

# OIDC settings for SweatStack
# Authorization: https://app.sweatstack.no/oauth/authorize
# Token: https://app.sweatstack.no/api/v1/oauth/token
OIDC_CLIENT_ID = os.getenv("SWEATSTACK_CLIENT_ID")
OIDC_CLIENT_SECRET = os.getenv("SWEATSTACK_CLIENT_SECRET")

# Session secret for cookie signing (for session middleware)
SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY", "dev-insecure-secret")

# Name of the cookie where we store the encrypted token data
TOKEN_COOKIE_NAME = "sweatstack_tokens"

# Refresh tokens 10 seconds before expiry
TOKEN_REFRESH_THRESHOLD = 10

# Serializer for encrypting/signing cookie data
token_serializer = URLSafeSerializer(SESSION_SECRET_KEY, salt="sweatstack-tokens")

# -------------------------------------------------------------------
# FastAPI app + OAuth client
# -------------------------------------------------------------------
app = FastAPI()

# SessionMiddleware is required by Authlib for storing OAuth state
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)

oauth = OAuth()

# SweatStack doesn't have OIDC discovery, so we configure endpoints manually
oauth.register(
    name="sweatstack",
    client_id=OIDC_CLIENT_ID,
    client_secret=OIDC_CLIENT_SECRET,
    authorize_url="https://app.sweatstack.no/oauth/authorize",
    access_token_url="https://app.sweatstack.no/api/v1/oauth/token",
    client_kwargs={
        "scope": "data:read,profile",
    },
)


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def _build_upstream_url(path: str, query_string: str) -> str:
    """Combine upstream base URL with path + query string."""
    base = UPSTREAM_HTTP.rstrip("/")
    if path:
        url = f"{base}/{path}"
    else:
        url = base + "/"
    if query_string:
        url = url + "?" + query_string
    return url


def _filter_response_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Drop hop-by-hop headers that shouldn't be forwarded."""
    skip_headers = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-encoding",  # httpx auto-decompresses, so don't pass this through
        "content-length",    # length changes after decompression
    }
    return {k: v for k, v in headers.items() if k.lower() not in skip_headers}


def _encode_token_cookie(access_token: str, refresh_token: str, expires_at: float) -> str:
    """Encode token data into a signed cookie value."""
    data = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at,
    }
    return token_serializer.dumps(data)


def _decode_token_cookie(cookie_value: str) -> Dict | None:
    """Decode and verify token cookie. Returns None if invalid."""
    try:
        return token_serializer.loads(cookie_value)
    except Exception:
        return None


async def _refresh_access_token(refresh_token: str) -> Dict | None:
    """Use refresh token to get new access token from SweatStack."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://app.sweatstack.no/api/v1/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": OIDC_CLIENT_ID,
                "client_secret": OIDC_CLIENT_SECRET,
            },
        )
        if response.status_code == 200:
            return response.json()
    return None


async def _get_valid_token(cookies: Dict[str, str]) -> tuple[str | None, str | None]:
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

    # Check if token expires within threshold
    if time.time() >= expires_at - TOKEN_REFRESH_THRESHOLD:
        if refresh_token:
            new_tokens = await _refresh_access_token(refresh_token)
            if new_tokens:
                new_access = new_tokens.get("access_token")
                new_refresh = new_tokens.get("refresh_token", refresh_token)
                new_expires_in = new_tokens.get("expires_in", 3600)
                new_expires_at = time.time() + new_expires_in

                new_cookie = _encode_token_cookie(new_access, new_refresh, new_expires_at)
                return new_access, new_cookie
        # Refresh failed or no refresh token - return None
        return None, None

    return access_token, None


# -------------------------------------------------------------------
# Auth endpoints
# -------------------------------------------------------------------
@app.get("/login")
async def login(request: Request):
    """Kick off OAuth2 login with SweatStack."""
    redirect_uri = request.url_for("auth_callback")
    return await oauth.sweatstack.authorize_redirect(request, redirect_uri)


@app.get("/auth/callback")
async def auth_callback(request: Request):
    """Handle OAuth callback, store tokens in encrypted cookie, then redirect to root."""
    token = await oauth.sweatstack.authorize_access_token(request)
    access_token = token.get("access_token")
    refresh_token = token.get("refresh_token")
    expires_in = token.get("expires_in", 3600)

    redirect_target = "/"
    response = RedirectResponse(url=redirect_target)

    if access_token:
        expires_at = time.time() + expires_in
        cookie_value = _encode_token_cookie(access_token, refresh_token or "", expires_at)

        response.set_cookie(
            TOKEN_COOKIE_NAME,
            cookie_value,
            httponly=True,
            secure=False,  # set True behind HTTPS in real deployments
            samesite="lax",
            max_age=86400 * 30,  # 30 days - refresh token should handle expiry
        )

    return response


@app.get("/logout")
async def logout():
    """Clear the token cookie and go back to root."""
    response = RedirectResponse(url="/")
    response.delete_cookie(TOKEN_COOKIE_NAME)
    return response


# -------------------------------------------------------------------
# HTTP proxy – catch-all
# -------------------------------------------------------------------
@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def http_proxy(full_path: str, request: Request) -> Response:
    """
    Proxy all HTTP requests to the Streamlit upstream, injecting
    SweatStack-Access-Token header if cookie is present. Automatically
    refreshes tokens if they're about to expire.
    """
    # Extract incoming data
    method = request.method
    query_string = request.scope.get("query_string", b"").decode()
    upstream_url = _build_upstream_url(full_path, query_string)

    # Build headers for upstream
    incoming_headers = dict(request.headers)
    incoming_headers.pop("host", None)
    incoming_headers.pop("accept-encoding", None)  # Prevent compressed responses

    # Get token, potentially refreshing if near expiry
    token, new_cookie = await _get_valid_token(request.cookies)
    if token:
        incoming_headers["SweatStack-Access-Token"] = token

    body = await request.body()

    async with httpx.AsyncClient(follow_redirects=True) as client:
        upstream_response = await client.request(
            method,
            upstream_url,
            headers=incoming_headers,
            content=body,
        )

    # Relay response
    headers = _filter_response_headers(dict(upstream_response.headers))

    response = Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=headers,
    )

    # Update cookie if token was refreshed
    if new_cookie:
        response.set_cookie(
            TOKEN_COOKIE_NAME,
            new_cookie,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=86400 * 30,
        )

    return response


# -------------------------------------------------------------------
# WebSocket proxy – catch-all
# -------------------------------------------------------------------
@app.websocket("/{full_path:path}")
async def websocket_proxy(websocket: WebSocket, full_path: str):
    """
    Proxy WebSocket connections to Streamlit, injecting
    SweatStack-Access-Token as a header in the upstream handshake.
    """
    await websocket.accept()

    # Build upstream WS URL
    base_http = UPSTREAM_HTTP.replace("http://", "ws://").replace("https://", "wss://")
    if full_path:
        upstream_ws_url = f"{base_http.rstrip('/')}/{full_path}"
    else:
        upstream_ws_url = base_http.rstrip("/") + "/"

    # Get token (refresh if needed) - can't update cookie on WS, but at least use fresh token
    token, _ = await _get_valid_token(websocket.cookies)
    additional_headers: Dict[str, str] = {}
    if token:
        additional_headers["SweatStack-Access-Token"] = token

    try:
        async with ws_connect(upstream_ws_url, additional_headers=additional_headers) as upstream:
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
                            await upstream.close()
                            break
                except WebSocketDisconnect:
                    await upstream.close()
                except Exception:
                    await upstream.close()

            async def upstream_to_client():
                try:
                    while True:
                        data = await upstream.recv()
                        if isinstance(data, str):
                            await websocket.send_text(data)
                        else:
                            await websocket.send_bytes(data)
                except (ConnectionClosedOK, ConnectionClosedError):
                    await websocket.close()
                except Exception:
                    await websocket.close()

            await asyncio.gather(client_to_upstream(), upstream_to_client())
    finally:
        # Ensure client WS is closed
        await websocket.close()
