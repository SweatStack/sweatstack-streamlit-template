# Upgrading

How to update a project generated from this template to the latest version. The steps are written to be followed by a person or by a coding agent: point an agent at this file.

What changed in each release, and anything specific to it, is in [CHANGELOG.md](CHANGELOG.md) under that release's **Upgrade notes**.

## 1. Prepare

1. Make sure the project's git working tree is clean (`git status`), then create a branch for the update.
2. Clone the template next to the project. Later steps use it to look up versions and compare files:
   ```bash
   git clone https://github.com/SweatStack/sweatstack-streamlit-template ../sweatstack-template
   ```
3. Read every release in [CHANGELOG.md](CHANGELOG.md) newer than the project's current version, oldest first, paying particular attention to the **Upgrade notes**. `.copier-answers.yml` records the template commit the project is on as `_commit`. Look up that commit's date with `git -C ../sweatstack-template log -1 --format=%cs <_commit>`, then read every release dated on or after it. When in doubt, include one release more. If `.copier-answers.yml` doesn't exist, the project was created before 0.1.0 (earlier versions of the template never wrote it): read all releases and follow step 2b.

## 2a. Projects created with Copier (`.copier-answers.yml` exists)

```bash
copier update --defaults
```

`--defaults` reuses the answers you gave when creating the project. Copier prints "No git tags found in template; using HEAD as ref"; that is expected.

Copier does a three-way merge: your changes and the template's changes are combined, and where both changed the same lines it marks a conflict with `<<<<<<<` / `>>>>>>>` markers. A file that both you and the template created (e.g. your own `static/sw.js`) conflicts as a whole. Resolve conflicts with step 3.

## 2b. Projects without `.copier-answers.yml`

This covers projects created with GitHub's "Use this template" button, by copying the repository, or with `copier copy` before 0.1.0. Copier doesn't know which template version they started from, so it can't tell your changes apart from the template's. Record that version once, and the project updates like any other:

1. **Find the template version the project started from**: the last template commit before the project's first commit.
   ```bash
   CREATED=$(git log --reverse --format=%cI | head -1)
   git -C ../sweatstack-template log -1 --format='%h %cs %s' --before="$CREATED"
   ```
   If the result is older than `4a88ddc` (2026-03-23), use `4a88ddc`: earlier versions can't be read by Copier. If the project has no useful history, pick the commit you believe it started from. **When unsure, pick an older commit, never a newer one.** Too old only causes extra conflicts. Too new makes Copier treat template changes you never received as changes you made, and silently keep your old version; the check in step 5 catches that.
2. **Create `.copier-answers.yml`** in the project root, with that commit and values matching the project:
   ```yaml
   # Changes here will be overwritten by Copier; NEVER EDIT MANUALLY
   _commit: 4a88ddc                    # the commit from step 1
   _src_path: gh:SweatStack/sweatstack-streamlit-template
   project_name: My App                # page_title in streamlit_app.py
   project_slug: my-app                # name in pyproject.toml
   description: What my app does       # description in pyproject.toml
   page_icon: 🚀                       # page_icon in streamlit_app.py
   theme_color: '#ffffff'              # theme_color in manifest.json
   background_color: '#ffffff'         # background_color in manifest.json
   ```
   Commit it.
3. Continue with step 2a.

## 3. Resolve conflicts and customisations

Decide per file:

- **Infrastructure files** (`proxy.py`, `Dockerfile`, `supervisord.conf`, `.streamlit/config.toml`, `static/sw.js`, `static/install-banner.js`): **start from the template's version.** Keeping these files identical to the template is what makes future updates painless. To take the template's version of a file, check out the version Copier just updated to and copy the file:
  ```bash
  git -C ../sweatstack-template checkout --quiet "$(sed -n 's/^_commit: //p' .copier-answers.yml)"
  cp ../sweatstack-template/proxy.py proxy.py
  ```
  Then, for each change you had made:
  1. **Now built in or configurable?** Use the template feature or environment variable and drop the change. Each release's upgrade notes in the changelog map common customisations to their replacement.
  2. **App-specific logic** (anything about *your* product rather than authentication or proxying)? Move it into `streamlit_app.py` or your own modules.
  3. **Otherwise**, re-apply it, keep it as small as possible, and consider opening an issue or pull request on the template so it can become a setting. Typical examples: your theme in `.streamlit/config.toml`, and `COPY` lines in the `Dockerfile` for your own modules or `pages/`.
- **App files** (`streamlit_app.py`, `manifest.json`, `static/icon-*.png`, `static/splash-*.png`, `README.md`): **keep the project's version.** Bring in template changes only where the upgrade notes ask for it.
- **`pyproject.toml`**: keep the project's own dependencies and add any the template added. Then run `uv sync` (or `uv lock`) to update `uv.lock`.
- **`.env.template`**: take the template's version, then add the project's own variables.

## 4. Update configuration

Check the upgrade notes for new, changed or removed environment variables, including variables that replace a customisation you removed in step 3 (e.g. `ALLOW_SIGNUP=false`). Update every place they are set: `.env`, `.env.production`, and the hosting platform's secrets (e.g. `fly secrets list` / `fly secrets set`). A variable missing from the hosting secrets silently falls back to its default in production.

## 5. Verify

1. **No conflict markers are left**: `git grep -n '^<<<<<<<'` prints nothing.
2. **The infrastructure files match the template**, apart from the changes you kept on purpose:
   ```bash
   git -C ../sweatstack-template checkout --quiet "$(sed -n 's/^_commit: //p' .copier-answers.yml)"
   for f in proxy.py Dockerfile supervisord.conf .streamlit/config.toml static/sw.js static/install-banner.js; do
     diff -u "../sweatstack-template/$f" "$f"
   done
   ```
   Every difference shown must be a customisation you decided to keep in step 3. Anything else is a template change the update didn't apply: take the template's version of those lines.
3. `uv sync`, then `docker build -t my-app . && docker run --rm --env-file .env -p 8080:8080 my-app`
4. In a browser at `http://localhost:8080`: log in, use the app, reload, log out, and log in again.
5. Check the specific behaviour listed under the upgrade notes of each release you crossed.
6. Look through the container logs for warnings, e.g. `Ignoring HTTPS_ONLY=...`, which means an environment variable has a value the proxy doesn't understand.

## 6. Finish

Commit on the update branch, including `.copier-answers.yml`, deploy to a staging environment if you have one, and merge. You can delete `../sweatstack-template`.
