# SweatStack Streamlit Template

A template for building [Streamlit](https://streamlit.io/) applications with [SweatStack](https://sweatstack.no/).
Example deployment can be found [here](https://sweatstack-streamlit-template.fly.dev/).

> [!IMPORTANT]
> The content in this repository is provided as-is, without warranty or guarantees of any kind. Use at your own risk.

## Creating a New Project

Install [Copier](https://copier.readthedocs.io/):

```bash
uv tool install copier
```

Generate your project:

```bash
copier copy gh:sweatstack/streamlit-template my-app
cd my-app
```

Copier will ask you a few questions (project name, description, etc.) and generate a ready-to-go project.

Then install dependencies and set up your environment:

```bash
uv sync
cp .env.template .env
# Edit .env with your SweatStack credentials (see below)
```

### SweatStack Credentials

Create a new application at [app.sweatstack.no/applications/new](https://app.sweatstack.no/applications/new).

Set the redirect URI to `http://localhost:8080/auth/callback` for local development.

Note your **Client ID** and **Client Secret** and add them to `.env`:

```bash
SWEATSTACK_CLIENT_ID=your_client_id
SWEATSTACK_CLIENT_SECRET=your_client_secret
SECRET_KEY=$(openssl rand -base64 32)
HTTPS_ONLY=false
APP_URL=http://localhost:8080
```

### Build and Run

```bash
make build
make serve
```

Open [http://localhost:8080](http://localhost:8080).

## Updating Your Project

When this template is updated, pull in the changes with:

```bash
copier update
```

Copier performs a three-way merge (old template, new template, your files), so your customisations are preserved. Only lines that *both* sides changed will produce a conflict.

> [!TIP]
> Template updates are tracked via git tags. Run `copier update` periodically to stay current.

## Migrating from the GitHub Template

If you created your project using the **"Use this template"** button on GitHub before Copier was available, follow these steps to adopt Copier for future updates.

### 1. Make sure your work is committed

```bash
git status  # should be clean
```

### 2. Re-generate the project with Copier on top of your existing directory

```bash
copier copy --overwrite gh:sweatstack/streamlit-template .
```

Copier will ask the template questions. Answer them to match your current project (name, description, etc.). It will overwrite infrastructure files with the latest versions and leave a `.copier-answers.yml` file that tracks your template version.

### 3. Review and commit

```bash
git diff
```

Review the changes. Your customisations in `streamlit_app.py` will have been overwritten by the starter template — restore your version:

```bash
git checkout -- streamlit_app.py
```

Do the same for any other files you had customised (e.g. `manifest.json`, `static/` icons).

Commit the result:

```bash
git add -A
git commit -m "Adopt Copier for template updates"
```

From now on, `copier update` will work as described above.

## What's in the Template

### Files You Customise

| File | Purpose |
|------|---------|
| `streamlit_app.py` | Your Streamlit application |
| `manifest.json` | PWA app name, colors, icons |
| `static/icon-*.png` | Homescreen icons (192, 512, 180px) |
| `.env` / `.env.production` | Environment variables and secrets |

### Infrastructure (updated via Copier)

| File | Purpose |
|------|---------|
| `proxy.py` | FastAPI reverse proxy handling OAuth, cookies, token refresh |
| `Dockerfile` | Multi-stage build running proxy + Streamlit |
| `supervisord.conf` | Process manager for the two services |
| `.streamlit/config.toml` | Streamlit settings required for the proxy setup |

## Why This Template Exists

Streamlit doesn't have good support for user sessions out of the box. This template runs a FastAPI proxy in front of Streamlit that:

1. Handles the OAuth flow with SweatStack
2. Stores tokens in encrypted, HTTP-only cookies
3. Injects the access token as a header into requests to Streamlit
4. Automatically refreshes tokens before they expire

## Customizing Your App

Edit `streamlit_app.py` to build your application. The template provides:

- `auth.is_authenticated()` — Check if user is logged in
- `auth.client` — Authenticated SweatStack API client
- `auth.select_user()` — User selector widget for the sidebar
- `auth.logout_button()` — Logout button widget

Read the SweatStack Streamlit documentation [here](https://developer.sweatstack.no/learn/integrations/streamlit/).

## Production Deployment

### Deploying to Fly.io

Install the [Fly.io CLI](https://fly.io/docs/flyctl/), then:

```bash
fly launch
```

Create a production environment:

```bash
cp .env.template .env.production
# Set APP_URL=https://your-app.fly.dev and HTTPS_ONLY=true
cat .env.production | fly secrets import
```

Redeploy with `fly deploy` when you make changes.

## License

See [LICENSE](LICENSE).
