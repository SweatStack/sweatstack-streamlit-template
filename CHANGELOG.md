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

Releases are not tagged. `copier update` always moves a project to the latest commit on `main`, and each release below is identified by its version and date.


## Updating

These steps are written to be followed by a person or by a coding agent. Point an agent at this section and the release notes it needs to cross ("Upgrade notes" under each release).

### 1. Prepare

1. Make sure the project's git working tree is clean (`git status`), then create a branch for the update.
2. Read every release in this changelog newer than the project's current version, oldest first, paying particular attention to the **Upgrade notes**. `.copier-answers.yml` records the template commit the project is on as `_commit`. Look up that commit's date, e.g. `git log -1 --format=%cs <_commit>` in a clone of this repository, then read every release dated on or after it. When in doubt, include one release more. If that file doesn't exist, the project was created before 0.1.0 (earlier versions of the template never wrote it): read all releases and follow step 2b.

### 2a. Projects created with Copier (`.copier-answers.yml` exists)

```bash
copier update --defaults
```

`--defaults` reuses the answers you gave when creating the project. Copier prints "No git tags found in template; using HEAD as ref"; that is expected. Copier does a three-way merge and marks conflicts inline with `<<<<<<<` / `>>>>>>>` markers. Resolve them with step 3.

### 2b. Projects without `.copier-answers.yml`

This covers projects created with GitHub's "Use this template" button, by copying the repository, or with `copier copy` before 0.1.0. They have no record of their template version, so Copier can't merge. Adopt Copier first; this is a one-time step:

1. **Inventory your changes to the infrastructure files** before anything is overwritten. For each of `proxy.py`, `Dockerfile`, `supervisord.conf`, `.streamlit/config.toml`, `pyproject.toml` and `.env.template`, compare the project's version with the template's history (`git log` / `git diff` in a clone of this repository) to find the template commit it started from. Everything that differs from that commit is a local customisation. Write the list down.
2. Re-generate on top of the project, answering the questions to match the project (name, description, colors):
   ```bash
   copier copy --overwrite gh:SweatStack/sweatstack-streamlit-template .
   ```
3. Restore the project's own files, which the starter versions have just overwritten: `git checkout -- streamlit_app.py manifest.json static/icon-180x180.png static/icon-192x192.png static/icon-512x512.png README.md`, plus any other app files.
4. Go through the list from step 1 and handle each customisation with step 3.

### 3. Resolve conflicts and customisations

Decide per file:

- **Infrastructure files** (`proxy.py`, `Dockerfile`, `supervisord.conf`, `.streamlit/config.toml`, `static/sw.js`, `static/install-banner.js`): **start from the template's version.** Keeping these files identical to the template is what makes future updates painless. For each local change:
  1. **Now built in or configurable?** Use the template feature or environment variable and drop the change. Each release's upgrade notes map common customisations to their replacement.
  2. **App-specific logic** (anything about *your* product rather than authentication or proxying)? Move it into `streamlit_app.py` or your own modules.
  3. **Otherwise**, re-apply it, keep it as small as possible, and consider opening an issue or pull request on the template so it can become a setting.
- **App files** (`streamlit_app.py`, `manifest.json`, `static/icon-*.png`, `static/splash-*.png`, `README.md`): **keep the project's version.** Bring in template changes only where the upgrade notes ask for it.
- **`pyproject.toml`**: keep the project's own dependencies and add any the template added. Then run `uv sync` (or `uv lock`) to update `uv.lock`.
- **`.env.template`**: take the template's version, then add the project's own variables.

### 4. Update configuration

Check the upgrade notes for new, changed or removed environment variables and update every place they are set: `.env`, `.env.production`, and the hosting platform's secrets (e.g. `fly secrets list` / `fly secrets import`).

### 5. Verify

1. `docker build -t my-app . && docker run --rm --env-file .env -p 8080:8080 my-app`
2. In a browser at `http://localhost:8080`: log in, use the app, reload, log out, and log in again.
3. Check the specific behaviour listed under the upgrade notes of each release you crossed.
4. Look through the container logs for warnings, e.g. `Ignoring HTTPS_ONLY=...`, which means an environment variable has a value the proxy doesn't understand.

### 6. Finish

Commit on the update branch, including `.copier-answers.yml`, deploy to a staging environment if you have one, and merge.


## [0.1.0] - 2026-10-12

First versioned release. Projects generated before this have no version recorded and should treat everything below as new; see [Updating](#updating).

### Added
- **Refresh token for the Streamlit app.** Besides the access token (`X-SweatStack-Token`), the proxy now passes the user's refresh token to Streamlit as `X-SweatStack-Refresh-Token`, so an app can, for example, store it for webhooks or scheduled jobs. On by default; disable with `FORWARD_REFRESH_TOKEN=false`. Read "Tokens in your app" in the generated README first: the header is a snapshot from page load, and with refresh-token rotation a stored copy can stop working.
- **`ALLOW_SIGNUP`** (default `true`). Set to `false` to let only people with an existing SweatStack account log in (sends `email_auth_mode=existing_only` to the SweatStack authorize endpoint).
- **Installable app, complete.**
  - A service worker (`static/sw.js`, served at `/sw.js`), required by Chrome before it offers installation. It caches nothing, so deploys are visible immediately, and shows a "You're offline" page when a page load fails without a connection.
  - iOS launch screens for current iPhones and iPads, generated from `static/icon-512x512.png` on `background_color`. Add `static/splash-<width>x<height>.png` to use your own design for a size.
  - An "Install this app" banner for logged-in users (`static/install-banner.js`), colored with `theme_color`. On Chrome, Edge and Samsung Internet it has an Install button; on iPhone and iPad it explains Share → "Add to Home Screen". Closing it hides it for 30 days. Disable with `PWA_INSTALL_BANNER=false`.
- **Auto-login** (`AUTO_LOGIN`, default `false`): send logged-out visitors straight to the SweatStack login. A failed login stops the automatic redirect for 5 minutes, so it can't loop, while a user who abandoned the login page is still redirected when they return.
- **Return to the original page after login.** The URL a user was on (path and query) is preserved through the OAuth flow.
- `CHANGELOG.md`, with an [Updating](#updating) guide.

### Changed
- **On/off environment variables** (`HTTPS_ONLY`, `AUTO_LOGIN`, and the new ones) accept `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`. An unrecognised value is logged as a warning and the default is used. Previously anything other than `true` meant `false`.
- **HTML pages are sent with `Cache-Control: no-store`**, because their injected content now depends on whether the user is logged in. Other responses (scripts, images, Streamlit's assets) keep their caching.
- **`pillow`** is now a direct dependency; the proxy uses it to render launch screens. It was already installed as a dependency of Streamlit.
- **`.env.template`** lists the required variables first, sets `HTTPS_ONLY=false` explicitly for local development, and lists the optional variables with their defaults.

### Fixed
- **`copier update` works.** Generated projects now get a `.copier-answers.yml`, which records the template version and your answers. Before this release it was never written, so Copier could not update any project. Existing projects adopt it once, via [Updating, step 2b](#2b-projects-without-copier-answersyml).
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
