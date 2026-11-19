# Plan 005: Only the proxy holds the refresh token

Status: ready for implementation (2026-11-19). Release: `0.4.0`, with a `sweatstack` release that the
template then requires. Must be released before SweatStack refuses used refresh tokens for template
apps (see fact 3).

This plan is complete. Every decision is made; do not reopen one without hitting a stop condition
(section 9). Sections 1 to 3 explain why. Sections 4 to 9 are what to do.

**Revision of 2026-11-19** (review before the build): the token endpoint is served on an internal
listener instead of being guarded by the caller's address (D7, D12; facts 12, 13); Streamlit listens on
loopback only (D13); the template runs as one machine and says so (D11; fact 14); the app's background
use of the refresh token is ended explicitly, with upgrade notes (D14; fact 15); the page learns the
token's remaining lifetime as a duration, so its clock does not matter (D4, D5); one record per `sid`
holds the lock, the token and the waiters, and is removed as a whole (D3, D6); D6's restart argument
no longer assumes Streamlit restarts with the proxy (fact 16); logging (D15); known limits (section 7).
Facts 12 to 16 were added; the RFC 10017 citation was checked (published August 2026 as BCP 212).

## 1. Outcome

| Situation | Today | After this release |
|---|---|---|
| Who holds the refresh token | The proxy's cookie **and** every Streamlit session (forwarded in `X-SweatStack-Refresh-Token`) | The proxy's cookie only |
| Who refreshes | The proxy (page requests, WebSocket handshake) and each session (in-session renewal) | The proxy only, and only in a response that rewrites the cookie |
| A tab left open past the access token's 15 minutes | Keeps working (the session refreshes with its copy) | Keeps working (the page asks the proxy to refresh; the session reads the new access token from the proxy) |
| The cookie after a session renewed the token | Holds a refresh token SweatStack already rotated | Always holds the newest refresh token |
| SweatStack refuses a used refresh token and ends the sign-in (its plan, fact 3) | Users of template apps are signed out | Nothing changes for users |
| Sign-out | Deletes the cookie | Also revokes the refresh token at SweatStack |
| Who can reach Streamlit's port and the token endpoint | Streamlit listens on every interface of the container | Both listen on `127.0.0.1` only |
| A background job that uses the forwarded refresh token (README) | Works, and is a second holder of the browser's sign-in | Not offered; the README says why and what to do |
| Machines on Fly | Two by default (`fly launch`), which Streamlit does not support | One, stated in the README |

## 2. Facts this plan rests on

Each was checked on 2026-11-19. "Server" means `~/projects/sweatstack`, "SDK" means `~/projects/sweatstack-python`.

**SweatStack's refresh tokens**
1. From server 0.162.0, every refresh of an app's token returns a new refresh token and retires the presented one (server: plan 095, `app/refresh_rotation.py`). All tokens descended from one sign-in form one *family* (plan 095 D5).
2. A refresh within 30 seconds with the same retired token, while its successor is unused, returns that same successor (server: `REFRESH_TOKEN_GRACE_PERIOD`). Two tabs or two requests refreshing at once therefore agree.
3. Today (Phase 1) any other retired token still refreshes and is recorded per app as the `refresh_token_not_rotated` deprecation. In Phase 2 it is refused with `invalid_grant` and **ends the whole family**, so the sign-in. Phase 2 ships for an app when its deprecation count is zero for 90 days, or on a date agreed with its owner. Apps created after a date the SweatStack owner sets get Phase 2 at once (server: `strict_refresh_tokens_from`, plan 095 D24), and that date is set only once this plan is released.
4. `POST /api/v1/oauth/revoke` (RFC 7009) ends a family; for a token issued with the client secret, send the secret.

**The proxy**
5. The proxy keeps `access_token`, `refresh_token` and `expires_at` in one Fernet-encrypted cookie (`sweatstack_tokens`, `_encode_token_cookie`). It has no server-side storage, and the default Fly config has no volume. The proxy and Streamlit run in one container under supervisord.
6. It refreshes in `_get_valid_tokens`, on every HTTP request and on the WebSocket handshake. On HTTP it rewrites the cookie; on the WebSocket path it does not (comment in `websocket_proxy`: "SweatStack doesn't rotate refresh tokens"), so the cookie keeps the old refresh token.
7. It forwards `X-SweatStack-Token` and `X-SweatStack-Refresh-Token` to Streamlit, and drops every `X-SweatStack-*` header a browser sends (`_prepare_upstream_headers`).
8. It injects HTML at the start of `<head>` of every HTML page (`_build_head_html`), already used for the PWA tags and the install banner.

**Streamlit and the SDK**
9. A Streamlit session sees the headers of the WebSocket handshake only (`st.context.headers`), so it never sees a token the proxy refreshed later.
10. `StreamlitAuth.behind_proxy` (SDK `streamlit.py`) builds the session's client from both headers and renews in the session with the refresh token, keeping the pair in `st.session_state`. That second holder is what breaks under fact 3.
11. The SDK renews in `Client._refresh_if_expired`, which needs a refresh token; there is no other way to give a client a new access token.

**The container and the host**
12. uvicorn (0.41.0) trusts `X-Forwarded-For` from `127.0.0.1` by default (`proxy_headers=True`, `forwarded_allow_ips="127.0.0.1"`). So `request.client.host` is whatever a same-host reverse proxy puts in that header, or loopback when it sets none: it cannot tell an internal caller from an external one. What it can tell is the socket a connection arrived on: `scope["server"]` is that socket's local address (`get_local_addr(transport)` in each protocol), and `uvicorn.Server.serve(sockets=[...])` serves one app on several sockets.
13. `supervisord.conf` starts Streamlit with `--server.address=0.0.0.0`. The proxy reaches it at `UPSTREAM_URL`, default `http://localhost:8501`. On Fly, other apps in the same organisation reach every port a machine listens on over the private network, so Streamlit's port is reachable from outside the proxy. The README's guarantee that `X-SweatStack-*` headers come only from the proxy depends on it not being.
14. Streamlit keeps each session, its uploaded files and its media in the memory of one process (`MemoryUploadedFileManager`, `MemoryMediaFileStorage`), so it needs every request of a session to reach one machine. The template does not ship `fly.toml` (it is in `.gitignore`; the README's "the included `fly.toml`" is wrong): `fly launch` writes it, and its `--ha` flag defaults to true, which creates two machines. Fly does not route a browser's requests to one machine.
15. The README section "Using the refresh token yourself" tells projects to store the forwarded refresh token for background jobs. That token is the cookie's family (fact 1): a job that refreshes with it rotates the browser's sign-in, and in Phase 2 either holder ends the other.
16. supervisord runs the proxy and Streamlit as two programs, each restarted on its own (`autorestart=true`). A crash of the proxy restarts the proxy only; Streamlit sessions survive, and the browsers reconnect their WebSockets through the new proxy process.

## 3. Design

### What must not change

- The browser never sees a token: the cookie is encrypted and `HttpOnly`.
- `X-SweatStack-*` headers reach Streamlit only from the proxy. After this release that holds by construction: Streamlit listens on loopback only (D13).
- No server-side storage is required: a project deploys exactly as today, on any host that runs the container.

### The idea

The cookie is the only durable holder, so **every refresh happens in a response that can rewrite the cookie**: an HTTP response to the browser. A long-open tab has no HTTP traffic, so the page itself asks for one: a small script calls `POST /_proxy/refresh` shortly before the access token expires. The proxy refreshes, rewrites the cookie, and remembers the new access token in memory under the browser's session id. The Streamlit session, whose handshake token has expired, asks the proxy for that access token on a listener only processes inside the container can reach. It never holds or uses a refresh token.

This is the backend-for-frontend pattern (OAuth 2.0 for Browser-Based Applications, RFC 10017 section 6.1), with the encrypted cookie as the backend's token store.

### Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **The refresh token is never forwarded.** Remove `X-SweatStack-Refresh-Token`. | One holder is the only arrangement rotation allows (fact 3). The app never needed the refresh token itself, only fresh access tokens. |
| D2 | **The cookie gains `sid`**: 128 random bits (`secrets.token_urlsafe(16)`), minted at sign-in, kept across refreshes. A cookie without `sid` (from 0.3.0) gets one at its next HTTP request, which rewrites the cookie. The proxy forwards it as `X-SweatStack-Session`. It is never logged (D15). | It names the browser's sign-in to the proxy without being a credential anywhere else. Upgrading signs nobody out. |
| D3 | **The proxy refreshes only where it rewrites the cookie in the same response**: an HTTP request (as today), `POST /_proxy/refresh`, and the WebSocket handshake with `Set-Cookie` on the `101` response (`websocket.accept(headers=...)`). Refreshes of one `sid` are serialized by the `asyncio.Lock` in its record (D6). | The cookie then can never hold a used refresh token. A lost response is covered by fact 2: the browser retries with the old cookie within 30 seconds and gets the same successor (the limit of that is in section 7). |
| D4 | **`POST /_proxy/refresh`** refreshes when the access token expires within 5 minutes, rewrites the cookie, and answers `{"expires_in": <whole seconds>}`; with more than 5 minutes left it refreshes nothing and answers the same. It requires the header `X-SweatStack-Refresh: 1` (a cross-site form cannot set it; the cookie is `SameSite=Lax` anyway). Without a cookie, or on `invalid_grant`, it deletes the cookie and answers `401`. | A cheap, idempotent call the page can make whenever it likes. A duration, not the proxy's `expires_at`, so a browser whose clock is off still schedules correctly. |
| D5 | **The page keeps the cookie fresh**: `static/keepalive.js`, injected on authenticated pages only, calls D4 once on load, then again `expires_in − 180` seconds after each answer (at once if that is negative), and on `visibilitychange` to visible and on `online` when that time has passed. Each call runs inside a Web Lock (`navigator.locks.request("sweatstack-refresh", ...)`), so one tab calls at a time and the next tab's call carries the cookie the first one received. On `401` it reloads the page, which leads to sign-in. A network error is retried at the next of those triggers, and after 30 seconds. | 3 minutes leaves room for the timer throttling of hidden tabs (at most once a minute). Tabs share the cookie, so whichever tab refreshes, all have the new token. The call on load covers a page opened with little time left and tells the script its first deadline without injecting anything per page. |
| D6 | **One record per `sid`, in memory**: `{lock, access_token, expires_at, changed: asyncio.Event}`. The token is written at every refresh and every cookie read, and only replaced by one with a later `expires_at` (a request carrying an older cookie never moves it back); each write sets and renews `changed`. A record is removed, as a whole, when its token has expired, its lock is free and nobody waits on `changed`; a sweep runs at most once a minute, on a write. | A cache only. After a proxy restart it is empty; the browsers reconnect their WebSockets through the new process (fact 16), and that handshake reads the cookie, which fills the record again. Until then a session's own handshake token is still valid, because D5 keeps the cookie at least 3 minutes ahead. Removing the record as a whole means locks and events cannot outlive their tokens. |
| D7 | **`GET /_proxy/token`** answers the session, **on the internal listener only** (D12), with `X-SweatStack-Session` required. It returns `{"access_token", "expires_at"}` from D6 when that token is newer than the caller's (`?after=<expires_at>`); otherwise it waits up to 10 seconds on `changed`, then answers `404`. It **never refreshes**. | It has no cookie to rewrite, so refreshing here would recreate the second holder. The wait covers a tab that just became visible: its script refreshes while the rerun waits. The endpoint cannot be reached from outside the container, whatever sits in front of the proxy, and a leaked `sid` is useless outside it. |
| D8 | **The SDK renews from the proxy.** `StreamlitAuth.behind_proxy` reads `X-SweatStack-Session` and builds the client with a private renewal function that calls D7 (`token_url`, default `http://127.0.0.1:8081/_proxy/token`). `Client` gains a private `_renew_access_token: Callable[[str \| None], str] \| None`, used by `_refresh_if_expired` when it has no refresh token, under the existing per-client lock. On `404` or a connection error it raises `SweatStackTokenRefreshError` with the existing reload hint. `refresh_header_name` stays for one template minor release (D10) and is then removed. | Fact 11: there is no other way to give a client a new access token. Private, like `_on_refresh` before it: the Streamlit integration is its only user. |
| D9 | **Sign-out revokes**: `/logout` posts the refresh token to `POST /api/v1/oauth/revoke` with the client id and secret (best effort, 5-second timeout), then deletes the cookie and the `sid`'s record. | A sign-out should end the sign-in at SweatStack, not only in this browser (fact 4). |
| D10 | **Old pairs keep working across the upgrade.** A new SDK with an old proxy: the refresh header path stays until the template's next minor release, so `behind_proxy` still accepts it when present (and warns once). An old SDK with a new proxy: no refresh header, so a tab open past 15 minutes shows the existing reload hint. The template requires the new SDK, so a `copier update` moves both. | No project breaks at any step of its upgrade. |
| D11 | **The template runs as one machine.** The README's Fly section says `fly launch --ha=false`, and tells an existing deployment to run `fly scale count 1`; it says why in one sentence, and drops "the included `fly.toml`". | Streamlit already needs every request of a session on one machine (fact 14), and D6's records are per process. Running more machines needs routing that keeps a browser on one, for Streamlit and the proxy together: out of scope (section 8). |
| D12 | **The proxy listens twice, in one process**: `0.0.0.0:8080` for browsers and `127.0.0.1:8081` for the session. `proxy.serve(public_port=8080, internal_port=8081)` binds both sockets and runs one `uvicorn.Server` on them (`serve(sockets=[...])`, `loop="asyncio"`) with a small ASGI dispatcher: a connection on the internal socket (`scope["server"]` port) goes to `internal_app`, which has `/_proxy/token` and nothing else; every other connection goes to `app`, which does not have it. Lifespan events go to `app`. `if __name__ == "__main__": asyncio.run(serve())`, and supervisord runs `uv run python proxy.py`. | A socket bound to `127.0.0.1` cannot be reached from outside the container, through Fly's private network, or through a reverse proxy, which targets port 8080. No check depends on the caller's address or on forwarded headers (fact 12). One process, because D6 is shared memory. `uvicorn proxy:app` still serves the app, without the internal endpoint: a project that kept the old command fails safe, with the reload hint. |
| D13 | **Streamlit listens on loopback only**: `--server.address=127.0.0.1`, and `UPSTREAM_URL` defaults to `http://127.0.0.1:8501` (not `localhost`, which may resolve to `::1` first). | Makes the guarantee in fact 13 hold by construction instead of by host configuration. |
| D14 | **The app no longer gets a refresh token for background work.** The README's "Using the refresh token yourself" is replaced by a short section: the app receives an access token only; a refresh token from 0.3.0's header belongs to the browser's sign-in (fact 15), so a stored copy must be deleted, not used; work outside a user's session needs a sign-in held by one store of its own, which this template does not provide. The 0.4.0 upgrade notes say the same, first. | Keeping the header for this use would keep a second holder, which Phase 2 punishes by signing the user out of the app. A project that relied on it must hear so in the upgrade notes, not discover it when its users are signed out. |
| D15 | **The proxy logs every token event, never a token or a `sid`**: `token refresh` with `via` (`http`, `refresh`, `websocket`) and `outcome` (`ok`, `invalid_grant`, `error`); `session token` with `outcome` (`fresh`, `waited`, `timeout`); `revoke failed` with the status or error. Each line carries the first 8 hex characters of the SHA-256 of the `sid`, to follow one sign-in through the log. | A refresh that fails in production is otherwise invisible. The `timeout` count is the measure of whether D5 works on real browsers and phones. |

## 4. Build steps

1. **SDK** (`sweatstack-python`, red-green, `make check`):
   - `Client._renew_access_token` and its use in `_refresh_if_expired` (D8). Tests: a client without a refresh token renews through it, once per expiry under concurrency; a `404` and a refused connection give `SweatStackTokenRefreshError` with the hint.
   - `behind_proxy` reads `X-SweatStack-Session`, builds the client with the renewal function (`token_url` as in D8), and keeps the refresh-header path behind a one-time warning (D10). Tests in `tests/test_streamlit_auth.py`.
   - Docstring, `skills/sweatstack-python/streamlit.md` ("Token lifecycle"), `CHANGELOG.md` `[Unreleased]`.
2. **Proxy** (`proxy.py`):
   - `sid` in the cookie (D2); `X-SweatStack-Session`; drop `REFRESH_TOKEN_HEADER` (D1). Reword the `FORWARD_REFRESH_TOKEN` warning: the refresh token is no longer forwarded at all.
   - The per-`sid` record and its sweep (D6); refreshing under its lock (D3); `Set-Cookie` on the WebSocket `101` (D3).
   - `POST /_proxy/refresh` (D4), `/logout` revocation (D9).
   - `internal_app` with `GET /_proxy/token` (D7); `serve()`, the dispatcher and the `__main__` block (D12).
   - `UPSTREAM_URL` default (D13); logging (D15).
   - `static/keepalive.js` and its tag in `_build_head_html` for authenticated pages (D5).
   - Remove the WebSocket comment that says SweatStack doesn't rotate.
3. **Container**: `supervisord.conf` runs the proxy with `uv run python proxy.py` (D12) and Streamlit with `--server.address=127.0.0.1` (D13).
4. **Template files**: `pyproject.toml.jinja` requires the new `sweatstack`; `README.md.jinja`: "Tokens in Your App" (one header less, plus `X-SweatStack-Session`, which the app need not read), the section that replaces "Using the refresh token yourself" (D14), the trust paragraph (Streamlit listens on loopback; drop "the included `fly.toml`"), the Fly section (D11), the `UPSTREAM_URL` row (D13); `CHANGELOG.md` 0.4.0 with upgrade notes; `UPGRADING.md` for the supervisord command if a project changed `supervisord.conf` (Copier then shows a conflict).

## 5. Tests

Extend the existing end-to-end tests (real proxy, Streamlit, SDK and Chromium; only the SweatStack token and revocation endpoints are faked). Every test starts the proxy through `proxy.serve()`, as production does, and Streamlit on `127.0.0.1`.

- **`test_token_renewal_e2e.py`**: the fake token endpoint now **rotates and refuses a used refresh token with `invalid_grant`** (fact 3's Phase 2, so the test proves the strictest behavior), with fact 2's 30-second grace. Checks:
  1. A tab left open past the token lifetime keeps working, without reconnecting, and the session never sent a refresh request itself.
  2. After that, a reload works: the cookie holds the newest refresh token.
  3. Two tabs open past the lifetime both keep working, with one refresh per lifetime.
  4. The proxy alone restarts after a renewal (fact 16): the tab reconnects and keeps working past the next expiry. Then the proxy and Streamlit restart together: the tab reconnects signed in.
  5. A hidden tab made visible after its token expired: the next rerun works within the 10-second wait.
  6. The page's clock set 10 minutes ahead and 10 minutes behind (Playwright's `page.clock`): the tab keeps working past the lifetime (D4's duration).
- **`test_proxy_e2e.py`**: `X-SweatStack-Refresh-Token` is never sent upstream; a browser-sent `X-SweatStack-Session` is dropped; `/_proxy/token` is `404` on port 8080, also with `X-Forwarded-For: 127.0.0.1` from loopback, and answers on port 8081; `POST /_proxy/refresh` without its header is refused; `/logout` calls the revocation endpoint and still signs out when that endpoint fails; the log lines of D15 contain neither a token nor a `sid`.
- **Cookie upgrade**: a 0.3.0 cookie (no `sid`) is accepted and comes back with a `sid`.
- **Records**: with the clock advanced, a record whose token expired is removed, and one with a waiter or a held lock is not (a unit test of D6, without a browser).

## 6. Release

1. Release the SDK (step 1) to PyPI.
2. Release the template 0.4.0. Upgrade notes, in this order: a project that stored `X-SweatStack-Refresh-Token` (README, "Using the refresh token yourself") must stop using it and delete the stored copies (D14); run `copier update`; on Fly, run `fly scale count 1` if the app has more than one machine (D11); nothing to configure.
3. Tell template users (the SweatStack owner knows them from the deprecation in fact 3, one `client_id` per deployed app) to update before the Phase 2 date they are given.
4. Tell the SweatStack owner the release is out, so `strict_refresh_tokens_from` can be set (fact 3).

## 7. Known limits

- **A lost refresh response not retried within 30 seconds** (a laptop closed mid-request, a phone that loses its connection for longer) leaves the cookie with a retired token. In Phase 2 its next use ends the sign-in, and the user signs in again. Inherent to rotation without server-side storage; the window is SweatStack's grace period (fact 2).
- **A tab whose script cannot run** (frozen by the browser and never made visible again) is not kept fresh; when it is used again, D5's `visibilitychange` call and D7's wait cover it. If they do not, the user sees the reload hint, never a wrong account or a broken page.
- **One machine** (D11).

## 8. Out of scope

- A server-side session store. Not needed (D6), and it would require a volume on every host.
- Refreshing from the Streamlit session in any form.
- More than one machine (D11).
- A refresh token for background work (D14).
- DPoP.

## 9. Stop conditions

Stop and ask if:

- Chromium does not store a cookie set on the WebSocket `101` response (D3). Then the WebSocket path must not refresh at all: forward the handshake token as it is, and let D5 and D7 renew.
- `st.context.headers` does not carry `X-SweatStack-Session` on the handshake (fact 9).
- `scope["server"]` does not tell the two sockets of D12 apart, or `uvicorn.Server.serve(sockets=...)` does not serve both.
- Any end-to-end check in section 5 needs a sleep longer than the token lifetime plus 30 seconds to pass.
