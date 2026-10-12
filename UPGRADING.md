# Upgrading

How to update a project generated from this template to the latest version. The steps are written to be followed by a person or by a coding agent: point an agent at this file.

What changed in each release, and anything specific to it, is in [CHANGELOG.md](CHANGELOG.md) under that release's **Upgrade notes**.

## 1. Prepare

1. Make sure the project's git working tree is clean (`git status`), then create a branch for the update.
2. Read every release in [CHANGELOG.md](CHANGELOG.md) newer than the project's current version, oldest first, paying particular attention to the **Upgrade notes**. `.copier-answers.yml` records the template commit the project is on as `_commit`. Look up that commit's date, e.g. `git log -1 --format=%cs <_commit>` in a clone of this repository, then read every release dated on or after it. When in doubt, include one release more. If that file doesn't exist, the project was created before 0.1.0 (earlier versions of the template never wrote it): read all releases and follow step 2b.

## 2a. Projects created with Copier (`.copier-answers.yml` exists)

```bash
copier update --defaults
```

`--defaults` reuses the answers you gave when creating the project. Copier prints "No git tags found in template; using HEAD as ref"; that is expected. Copier does a three-way merge and marks conflicts inline with `<<<<<<<` / `>>>>>>>` markers. Resolve them with step 3.

## 2b. Projects without `.copier-answers.yml`

This covers projects created with GitHub's "Use this template" button, by copying the repository, or with `copier copy` before 0.1.0. They have no record of their template version, so Copier can't merge. Adopt Copier first; this is a one-time step:

1. **Inventory your changes to the infrastructure files** before anything is overwritten. For each of `proxy.py`, `Dockerfile`, `supervisord.conf`, `.streamlit/config.toml`, `pyproject.toml` and `.env.template`, compare the project's version with the template's history (`git log` / `git diff` in a clone of this repository) to find the template commit it started from. Everything that differs from that commit is a local customisation. Write the list down.
2. Re-generate on top of the project, answering the questions to match the project (name, description, colors):
   ```bash
   copier copy --overwrite gh:SweatStack/sweatstack-streamlit-template .
   ```
3. Restore the project's own files, which the starter versions have just overwritten: `git checkout -- streamlit_app.py manifest.json static/icon-180x180.png static/icon-192x192.png static/icon-512x512.png README.md`, plus any other app files.
4. Go through the list from step 1 and handle each customisation with step 3.

## 3. Resolve conflicts and customisations

Decide per file:

- **Infrastructure files** (`proxy.py`, `Dockerfile`, `supervisord.conf`, `.streamlit/config.toml`, `static/sw.js`, `static/install-banner.js`): **start from the template's version.** Keeping these files identical to the template is what makes future updates painless. For each local change:
  1. **Now built in or configurable?** Use the template feature or environment variable and drop the change. Each release's upgrade notes in the changelog map common customisations to their replacement.
  2. **App-specific logic** (anything about *your* product rather than authentication or proxying)? Move it into `streamlit_app.py` or your own modules.
  3. **Otherwise**, re-apply it, keep it as small as possible, and consider opening an issue or pull request on the template so it can become a setting.
- **App files** (`streamlit_app.py`, `manifest.json`, `static/icon-*.png`, `static/splash-*.png`, `README.md`): **keep the project's version.** Bring in template changes only where the upgrade notes ask for it.
- **`pyproject.toml`**: keep the project's own dependencies and add any the template added. Then run `uv sync` (or `uv lock`) to update `uv.lock`.
- **`.env.template`**: take the template's version, then add the project's own variables.

## 4. Update configuration

Check the upgrade notes for new, changed or removed environment variables and update every place they are set: `.env`, `.env.production`, and the hosting platform's secrets (e.g. `fly secrets list` / `fly secrets import`).

## 5. Verify

1. `docker build -t my-app . && docker run --rm --env-file .env -p 8080:8080 my-app`
2. In a browser at `http://localhost:8080`: log in, use the app, reload, log out, and log in again.
3. Check the specific behaviour listed under the upgrade notes of each release you crossed.
4. Look through the container logs for warnings, e.g. `Ignoring HTTPS_ONLY=...`, which means an environment variable has a value the proxy doesn't understand.

## 6. Finish

Commit on the update branch, including `.copier-answers.yml`, deploy to a staging environment if you have one, and merge.
