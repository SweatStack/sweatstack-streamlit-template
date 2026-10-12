# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The same types of changes should be grouped.
Types of changes:

- `Added` for new features.
- `Changed` for changes in existing functionality.
- `Deprecated` for soon-to-be removed features.
- `Removed` for now removed features.
- `Fixed` for any bug fixes.
- `Security` in case of vulnerabilities.

Releases are not tagged. `copier update` always moves a project to the latest commit on `main`, and each release below is identified by its version and date. To update a project, follow [UPGRADING.md](UPGRADING.md) together with the **Upgrade notes** of each release you cross.


## [0.2.0] - 2026-10-12

Requires `sweatstack` `0.94.0` or later, which fixes two problems in the library's Streamlit and FastAPI integrations. Every app built from this template should upgrade, whichever template version it started from.

### Security
- **Requires `sweatstack>=0.94.0`.** Earlier versions of the library could give one user's session another user's tokens when several users share a server process, as they do in every Streamlit app. See the `sweatstack` changelog for details.

### Fixed
- **Apps no longer fail after being left open.** Streamlit receives the user's tokens only when the page connects, and the access token expires after about 15 minutes, so the first interaction after a long idle period failed (for example with `TokenRefreshError: Access token expired but no refresh token available`). `StreamlitAuth.behind_proxy()` now uses the forwarded refresh token to renew the access token within the session, without reloading the page.

### Removed
- **`FORWARD_REFRESH_TOKEN`.** The refresh token is now always passed to Streamlit, because the library needs it to renew the session's access token; turning it off would bring back the failure above. If the variable is still set, the proxy ignores it and logs a warning.

### Upgrade notes
- **Upgrade `sweatstack` in every deployed app**: after `copier update`, run `uv lock --upgrade-package sweatstack`, check that `uv.lock` now has `0.94.0` or later, and redeploy. `copier update` alone doesn't change the locked version.
- **Remove `FORWARD_REFRESH_TOKEN`** from `.env`, `.env.production` and your hosting secrets (e.g. `fly secrets unset FORWARD_REFRESH_TOKEN`).
- **Remove workarounds for expiring tokens**, such as forced page reloads, or `auth` / `auth.client` kept in `st.cache_resource` or module-level variables. Call `StreamlitAuth.behind_proxy()` at the top of every run instead.
- **If you store the refresh token** for background jobs, re-read "Using the refresh token yourself" in the README; the advice is shorter now that SweatStack's refresh behaviour is documented.


## [0.1.0] - 2026-10-12

First versioned release. Projects generated before this have no version recorded and should treat everything below as new; see [UPGRADING.md](UPGRADING.md).

### Added
- **Refresh token for the Streamlit app.** Besides the access token (`X-SweatStack-Token`), the proxy now passes the user's refresh token to Streamlit as `X-SweatStack-Refresh-Token`, so an app can, for example, store it for webhooks or scheduled jobs. On by default; disable with `FORWARD_REFRESH_TOKEN=false`. Read "Tokens in your app" in the generated README first: the header is a snapshot from page load, and with refresh-token rotation a stored copy can stop working.
- **`ALLOW_SIGNUP`** (default `true`). Set to `false` to let only people with an existing SweatStack account log in (sends `email_auth_mode=existing_only` to the SweatStack authorize endpoint).
- **Installable app, complete.**
  - A service worker (`static/sw.js`, served at `/sw.js`), required by Chrome before it offers installation. It caches nothing, so deploys are visible immediately, and shows a "You're offline" page when a page load fails without a connection.
  - iOS launch screens for current iPhones and iPads, generated from `static/icon-512x512.png` on `background_color`. Add `static/splash-<width>x<height>.png` to use your own design for a size.
  - An "Install this app" banner for logged-in users (`static/install-banner.js`), colored with `theme_color`. On Chrome, Edge and Samsung Internet it has an Install button; on iPhone and iPad it explains Share → "Add to Home Screen". Closing it hides it for 30 days. Disable with `PWA_INSTALL_BANNER=false`.
- **Auto-login** (`AUTO_LOGIN`, default `false`): send logged-out visitors straight to the SweatStack login. A failed login stops the automatic redirect for 5 minutes, so it can't loop, while a user who abandoned the login page is still redirected when they return.
- **Return to the original page after login.** The URL a user was on (path and query) is preserved through the OAuth flow.
- `CHANGELOG.md`, and `UPGRADING.md` with step-by-step update instructions.

### Changed
- **On/off environment variables** (`HTTPS_ONLY`, `AUTO_LOGIN`, and the new ones) accept `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`. An unrecognised value is logged as a warning and the default is used. Previously anything other than `true` meant `false`.
- **HTML pages are sent with `Cache-Control: no-store`**, because their injected content now depends on whether the user is logged in. Other responses (scripts, images, Streamlit's assets) keep their caching.
- **`pillow`** is now a direct dependency; the proxy uses it to render launch screens. It was already installed as a dependency of Streamlit.
- **`.env.template`** lists the required variables first, sets `HTTPS_ONLY=false` explicitly for local development, and lists the optional variables with their defaults.

### Fixed
- **`copier update` works.** Generated projects now get a `.copier-answers.yml`, which records the template version and your answers. Before this release it was never written, so Copier could not update any project. Existing projects adopt it once, via [UPGRADING.md, step 2b](UPGRADING.md#2b-projects-without-copier-answersyml).
- **WebSocket connections no longer leak** when one side closes while the other is idle. The idle direction is now cancelled instead of waiting forever.
- **Browser WebSocket connections work through the proxy**: subprotocol negotiation and client headers are forwarded, and Streamlit's CORS/XSRF checks (which reject the proxy's origin) are disabled in `.streamlit/config.toml`.
- **Manifest values are HTML-escaped** in the injected tags; an app name containing a quote no longer breaks the page head.

### Security
- **The proxy drops any `X-SweatStack-*` header sent by the browser** before forwarding a request, so the app can trust that these headers come from the proxy. Previously a logged-out visitor could send their own `X-SweatStack-Token` to Streamlit.
- **The old `.env.template` placeholder `HTTPS_ONLY=only_set_to_false_for_local_development` now means `true`** (secure cookies) instead of silently meaning `false`.

### Upgrade notes
- **Check `HTTPS_ONLY`.** If `.env` or your hosting secrets still contain the old placeholder value, cookies are now marked `Secure`. That is right for production. For local development over `http://`, set `HTTPS_ONLY=false` explicitly.
- **Your app now receives the refresh token.** If you don't use it, set `FORWARD_REFRESH_TOKEN=false`. If you do, read "Tokens in your app" in the generated README.
- **Install `pillow`**: run `uv sync` after updating `pyproject.toml`.
- **Common customisations of `proxy.py` that are now built in**: remove them during the update.

  | If your `proxy.py` has… | Replace it with… |
  |---|---|
  | A custom install / add-to-home-screen banner | The built-in banner. Its name and colors come from `manifest.json`. To change its behaviour, edit `static/install-banner.js`. |
  | A `/sw.js` route or service worker | The built-in `static/sw.js`. Delete any older custom `sw.js` unless it does something the built-in one doesn't. |
  | `apple-touch-startup-image` tags and splash images | Built-in launch screens. Rename custom images to `static/splash-<width>x<height>.png` (pixel sizes, e.g. `splash-1179x2556.png`) to keep using them. |
  | `email_auth_mode=existing_only` in the login parameters | `ALLOW_SIGNUP=false` |
  | `Cache-Control` changes for HTML pages | Nothing; now built in. |
  | Code that stores tokens or sends them to another service (e.g. for webhooks) | Move it into the Streamlit app and read the refresh token from the `X-SweatStack-Refresh-Token` header. Follow "Tokens in your app" in the generated README, especially the advice on rotation. |
  | A changed auto-login "auth attempted" cookie, or `asyncio.gather` in the WebSocket relay | The template versions. These are the auto-login and WebSocket fixes above; older copies lack them. |
