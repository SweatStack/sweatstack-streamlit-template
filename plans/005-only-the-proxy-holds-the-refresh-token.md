# Plan 005: Only the proxy holds the refresh token

Status: ready for implementation (2026-11-19). Release: `0.4.0`, with a `sweatstack` release that the
template then requires. Must be released before SweatStack refuses used refresh tokens for template
apps (see fact 3).

This plan is complete. Every decision is made; do not reopen one without hitting a stop condition
(section 8). Sections 1 to 3 explain why. Sections 4 to 8 are what to do.

## 1. Outcome

| Situation | Today | After this release |
|---|---|---|
| Who holds the refresh token | The proxy's cookie **and** every Streamlit session (forwarded in `X-SweatStack-Refresh-Token`) | The proxy's cookie only |
| Who refreshes | The proxy (page requests, WebSocket handshake) and each session (in-session renewal) | The proxy only, and only in a response that rewrites the cookie |
| A tab left open past the access token's 15 minutes | Keeps working (the session refreshes with its copy) | Keeps working (the page asks the proxy to refresh; the session reads the new access token from the proxy) |
| The cookie after a session renewed the token | Holds a refresh token SweatStack already rotated | Always holds the newest refresh token |
| SweatStack refuses a used refresh token and ends the sign-in (its plan, fact 3) | Users of template apps are signed out | Nothing changes for users |
| Sign-out | Deletes the cookie | Also revokes the refresh token at SweatStack |

## 2. Facts this plan rests on

Each was checked on 2026-11-19. "Server" means `~/projects/sweatstack`, "SDK" means `~/projects/sweatstack-python`.

**SweatStack's refresh tokens**
1. From server 0.162.0, every refresh of an app's token returns a new refresh token and retires the presented one (server: plan 095, `app/refresh_rotation.py`).
2. A refresh within 30 seconds with the same retired token, while its successor is unused, returns that same successor (server: `REFRESH_TOKEN_GRACE_PERIOD`). Two tabs or two requests refreshing at once therefore agree.
3. Today (Phase 1) any other retired token still refreshes and is recorded per app as the `refresh_token_not_rotated` deprecation. In Phase 2 it is refused with `invalid_grant` and **ends the whole sign-in**. Phase 2 ships for an app when its deprecation count is zero for 90 days, or on a date agreed with its owner. Apps created after a date the SweatStack owner sets get Phase 2 at once (server: `strict_refresh_tokens_from`).
4. `POST /api/v1/oauth/revoke` (RFC 7009) ends a sign-in; for a token issued with the client secret, send the secret.

**The proxy**
5. The proxy keeps `access_token`, `refresh_token` and `expires_at` in one Fernet-encrypted cookie (`sweatstack_tokens`, `_encode_token_cookie`). It has no server-side storage, and the default Fly config has no volume. The proxy and Streamlit run in one container under supervisord.
6. It refreshes in `_get_valid_tokens`, on every HTTP request and on the WebSocket handshake. On HTTP it rewrites the cookie; on the WebSocket path it does not (comment in `websocket_proxy`: "SweatStack doesn't rotate refresh tokens"), so the cookie keeps the old refresh token.
7. It forwards `X-SweatStack-Token` and `X-SweatStack-Refresh-Token` to Streamlit, and drops every `X-SweatStack-*` header a browser sends (`_prepare_upstream_headers`).
8. It injects HTML at the start of `<head>` of every HTML page (`_build_head_html`), already used for the PWA tags and the install banner.

**Streamlit and the SDK**
9. A Streamlit session sees the headers of the WebSocket handshake only (`st.context.headers`), so it never sees a token the proxy refreshed later.
10. `StreamlitAuth.behind_proxy` (SDK `streamlit.py`) builds the session's client from both headers and renews in the session with the refresh token, keeping the pair in `st.session_state`. That second holder is what breaks under fact 3.
11. The SDK renews in `Client._refresh_if_expired`, which needs a refresh token; there is no other way to give a client a new access token.

## 3. Design

### What must not change

- The browser never sees a token: the cookie is encrypted and `HttpOnly`.
- `X-SweatStack-*` headers reach Streamlit only from the proxy.
- No server-side storage is required: a project deploys exactly as today, on any host.

### The idea

The cookie is the only durable holder, so **every refresh happens in a response that can rewrite the cookie**: an HTTP response to the browser. A long-open tab has no HTTP traffic, so the page itself asks for one: a small script calls `POST /_proxy/refresh` shortly before the access token expires. The proxy refreshes, rewrites the cookie, and remembers the new access token in memory under the browser's session id. The Streamlit session, whose handshake token has expired, asks the proxy for that access token over loopback. It never holds or uses a refresh token.

This is the standard backend-for-frontend pattern (OAuth 2.0 for Browser-Based Applications, RFC 10017 section 6.1), with the encrypted cookie as the backend's token store.

### Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **The refresh token is never forwarded.** Remove `X-SweatStack-Refresh-Token`. | One holder is the only arrangement rotation allows (fact 3). The app never needed the refresh token itself, only fresh access tokens. |
| D2 | **The cookie gains `sid`**: 128 random bits (`secrets.token_urlsafe(16)`), minted at sign-in, kept across refreshes. A cookie without `sid` (from 0.3.0) gets one at its next HTTP request, which rewrites the cookie. The proxy forwards it as `X-SweatStack-Session`. | It names the browser's sign-in to the proxy without being a credential anywhere else. Upgrading signs nobody out. |
| D3 | **The proxy refreshes only where it rewrites the cookie in the same response**: an HTTP request (as today), `POST /_proxy/refresh`, and the WebSocket handshake with `Set-Cookie` on the `101` response (`websocket.accept(headers=...)`). One `asyncio.Lock` per `sid` serializes refreshes within the process. | The cookie then can never hold a used refresh token. A lost response is covered by fact 2: the browser retries with the old cookie within 30 seconds and gets the same successor. |
| D4 | **`POST /_proxy/refresh`** refreshes when the access token expires within 5 minutes, rewrites the cookie, and answers `{"expires_at": ...}`. It requires the header `X-SweatStack-Refresh: 1` (a cross-site form cannot set it; the cookie is `SameSite=Lax` anyway). On `invalid_grant` it deletes the cookie and answers `401`. | A cheap, idempotent call the page can make whenever it likes. |
| D5 | **The page keeps the cookie fresh**: `static/keepalive.js`, injected on authenticated pages, calls D4 at `expires_at` minus 3 minutes, and again on `visibilitychange` to visible and on `online` when that time has passed. It takes a Web Lock (`navigator.locks`) so one tab calls at a time. On `401` it reloads the page, which leads to sign-in. | 3 minutes leaves room for the timer throttling of hidden tabs (at most once a minute). Tabs share the cookie, so whichever tab refreshes, all have the new token. |
| D6 | **The proxy remembers the newest access token per `sid`, in memory**: `{sid: (access_token, expires_at)}`, written at every refresh and every cookie read, entries dropped once expired. | A cache only. After a restart it is empty, but a restart also restarts Streamlit, so every session reconnects and gets a fresh handshake token. |
| D7 | **`GET /_proxy/token`** answers the session: loopback callers only (`request.client.host` is `127.0.0.1` or `::1`), `X-SweatStack-Session` required. It returns `{"access_token", "expires_at"}` from D6 when that token is newer than the caller's (`?after=<expires_at>`); otherwise it waits up to 10 seconds for D5's refresh (an `asyncio.Event` per `sid`), then answers `404`. It **never refreshes**. | It has no cookie to rewrite, so refreshing here would recreate the second holder. The wait covers a tab that just became visible: its script refreshes while the rerun waits. The loopback check and the 128-bit `sid` together keep it internal. |
| D8 | **The SDK renews from the proxy.** `StreamlitAuth.behind_proxy` reads `X-SweatStack-Session` and builds the client with a private renewal function that calls D7 (`token_url`, default `http://127.0.0.1:8080/_proxy/token`). `Client` gains a private `_renew_access_token: Callable[[str | None], str] \| None`, used by `_refresh_if_expired` when it has no refresh token, under the existing per-client lock. On `404` it raises `SweatStackTokenRefreshError` with the existing reload hint. `refresh_header_name` stays for one template minor release (D10) and is then removed. | Fact 11: there is no other way to give a client a new access token. Private, like `_on_refresh` before it: the Streamlit integration is its only user. |
| D9 | **Sign-out revokes**: `/logout` posts the refresh token to `POST /api/v1/oauth/revoke` with the client id and secret (best effort, 5-second timeout), then deletes the cookie. | A sign-out should end the sign-in at SweatStack, not only in this browser (fact 4). |
| D10 | **Old pairs keep working across the upgrade.** A new SDK with an old proxy: the refresh header path stays until the template's next minor release, so `behind_proxy` still accepts it when present (and warns once). An old SDK with a new proxy: no refresh header, so a tab open past 15 minutes shows the existing reload hint. The template requires the new SDK, so a `copier update` moves both. | No project breaks at any step of its upgrade. |

## 4. Build steps

1. **SDK** (`sweatstack-python`, red-green, `make check`):
   - `Client._renew_access_token` and its use in `_refresh_if_expired` (D8). Tests: a client without a refresh token renews through it, once per expiry under concurrency; a `404` gives `SweatStackTokenRefreshError` with the hint.
   - `behind_proxy` reads `X-SweatStack-Session`, builds the client with the renewal function, and keeps the refresh-header path behind a one-time warning (D10). Tests in `tests/test_streamlit_auth.py`.
   - Docstring, `skills/sweatstack-python/streamlit.md` ("Token lifecycle"), `CHANGELOG.md` `[Unreleased]`.
2. **Proxy** (`proxy.py`):
   - `sid` in the cookie (D2); `X-SweatStack-Session`; drop `REFRESH_TOKEN_HEADER` (D1).
   - Per-`sid` lock and memory (D3, D6); `Set-Cookie` on the WebSocket `101` (D3).
   - `POST /_proxy/refresh` (D4), `GET /_proxy/token` (D7), `/logout` revocation (D9).
   - `static/keepalive.js` and its tag in `_build_head_html` for authenticated pages (D5).
   - Remove the WebSocket comment that says SweatStack doesn't rotate.
3. **Template files**: `pyproject.toml.jinja` requires the new `sweatstack`; `README.md.jinja` "Tokens in Your App" and "Using the refresh token yourself" (the app no longer gets a refresh token: say so, and what to use instead); `CHANGELOG.md` 0.4.0 with upgrade notes; `UPGRADING.md` if a step is new.

## 5. Tests

Extend the existing end-to-end tests (real proxy, Streamlit, SDK and Chromium; only the SweatStack token endpoint is faked).

- **`test_token_renewal_e2e.py`**: the fake token endpoint now **rotates and refuses a used refresh token with `invalid_grant`** (fact 3's Phase 2, so the test proves the strictest behavior), with fact 2's 30-second grace. Checks:
  1. A tab left open past the token lifetime keeps working, without reconnecting, and the session never sent a refresh request itself.
  2. After that, a reload works: the cookie holds the newest refresh token.
  3. Two tabs open past the lifetime both keep working, with one refresh per lifetime.
  4. The proxy and Streamlit restart after a renewal (`supervisorctl restart`, or killing both): the tab reconnects signed in.
  5. A hidden tab made visible after its token expired: the next rerun works within the 10-second wait.
- **`test_proxy_e2e.py`**: `X-SweatStack-Refresh-Token` is never sent upstream; a browser-sent `X-SweatStack-Session` is dropped; `/_proxy/token` answers `403` to a non-loopback caller; `POST /_proxy/refresh` without its header is refused; `/logout` calls the revocation endpoint.
- **Cookie upgrade**: a 0.3.0 cookie (no `sid`) is accepted and comes back with a `sid`.

## 6. Release

1. Release the SDK (step 1) to PyPI.
2. Release the template 0.4.0. Upgrade notes: run `copier update`; nothing to configure. A project that read `X-SweatStack-Refresh-Token` itself must use `auth.client` instead (README).
3. Tell template users (the SweatStack owner knows them from the deprecation in fact 3, one `client_id` per deployed app) to update before the Phase 2 date they are given.

## 7. Out of scope

- A server-side session store. Not needed (D6), and it would require a volume on every host.
- Refreshing from the Streamlit session in any form.
- DPoP.

## 8. Stop conditions

Stop and ask if:

- Chromium does not store a cookie set on the WebSocket `101` response (D3). Then the WebSocket path must not refresh at all: forward the handshake token as it is, and let D5 and D7 renew.
- `st.context.headers` does not carry `X-SweatStack-Session` on the handshake (fact 9).
- A host in the README's deployment section puts a proxy on the same machine in front of this one, so that external requests arrive from loopback (D7). Then `/_proxy/token` needs a shared secret from `SECRET_KEY` instead of the loopback check.
- Any end-to-end check in section 5 needs a sleep longer than the token lifetime plus 30 seconds to pass.
