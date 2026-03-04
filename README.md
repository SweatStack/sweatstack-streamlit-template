# SweatStack Streamlit Template

A template for building [Streamlit](https://streamlit.io/) applications with [SweatStack](https://sweatstack.no/).
Example deployment can be found [here](https://sweatstack-streamlit-template.fly.dev/).

> [!IMPORTANT]
> The content in this repository is provided as-is, without warranty or guarantees of any kind. Use at your own risk.


## Quick Start

### 1. Copy this template repository

Copy this repository to your own GitHub account by clicking the big green "Use this template" button at the top right of this page.
More info about using template repositories can be found [here](https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-repository-from-a-template).

### 2. Create a SweatStack Application

Create a new application [here](https://app.sweatstack.no/applications/new).

Set the redirect URI to your callback URL:
- Local development: `http://localhost:8080/auth/callback`
- Production: `https://yourdomain.com/auth/callback`

Note down your **Client ID** and **Client Secret** for the next step.

### 3. Configure Environment

Copy the environment template:

```bash
cp .env.template .env
```

Edit `.env` with your credentials:

```bash
SWEATSTACK_CLIENT_ID=your_client_id
SWEATSTACK_CLIENT_SECRET=your_client_secret
SECRET_KEY=your_random_secret_key
HTTPS_ONLY=false
APP_URL=http://localhost:8080
```

For production, create a separate `.env.production` with your deployed URL (e.g. `APP_URL=https://your-app.fly.dev`). See [Production Deployment](#production-deployment) for details.

Generate a secure secret key:

```bash
openssl rand -base64 32
```

Paste the generated key into the `SECRET_KEY` environment variable in your `.env` file.

### 4. Build and Run

```bash
# Build the Docker image
make build

# Run the application
make serve
```

Open [http://localhost:8080](http://localhost:8080) in your browser.

## Why This Template Exists

Although Streamlit has a really nice development experience for quick local iterations, it doesn't have good support for user sessions out of the box: All users basically share the same server-side state.

This template solves the problem by running a FastAPI proxy in front of Streamlit that:

1. Handles the OAuth flow with SweatStack
2. Stores tokens in encrypted, HTTP-only cookies
3. Injects the access token as a header into requests to Streamlit
4. Automatically refreshes tokens before they expire

To make local development and deployment easier, this template provides a Dockerfile that runs both the proxy and Streamlit in a single container.

## Development

### Local Development with Docker

```bash
# Build the image
make build

# Run with live reload (mounts current directory)
make serve
```

The `make serve` command mounts the current directory, so changes to `streamlit_app.py` will be reflected after a browser refresh.

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SWEATSTACK_CLIENT_ID` | OAuth client ID from SweatStack | Yes |
| `SWEATSTACK_CLIENT_SECRET` | OAuth client secret from SweatStack | Yes |
| `SECRET_KEY` | Secret key for encrypting cookies (min 32 chars) | Yes |
| `APP_URL` | Public URL of the application (used for OAuth redirect) | No (default: `http://localhost:8080`) |
| `HTTPS_ONLY` | Set cookie secure flag (`true` for production, `false` for local dev) | No (default: `true`) |
| `UPSTREAM_URL` | Internal Streamlit URL | No (default: `http://localhost:8501`) |


## Customizing Your App

Edit `streamlit_app.py` to build your application. The template provides:

- `auth.is_authenticated()` - Check if user is logged in
- `auth.client` - Authenticated SweatStack API client
- `auth.select_user()` - User selector widget for the sidebar
- `auth.logout_button()` - Logout button widget

Read the documentation for the SweatStack Python library and its Streamlit integration [here](https://developer.sweatstack.no/learn/integrations/streamlit/).

## PWA / Add to Homescreen

The template supports installing your app to the homescreen on iOS and Android. Edit these files to customize:

- **`manifest.json`** — App name, theme color, and icons shown on the homescreen and splash screen. See the [W3C spec](https://developer.mozilla.org/en-US/docs/Web/Manifest) for all options.
- **`pwa.toml`** — Apple-specific settings (`apple_status_bar_style`, `apple_touch_icon`).
- **`static/`** — Place your icon files here. Required sizes:
  - `icon-192x192.png` — Android homescreen icon
  - `icon-512x512.png` — Android splash screen
  - `icon-180x180.png` — iOS homescreen icon

Icons are served under `/_pwa/` to avoid colliding with Streamlit's own `/static/` path. If `manifest.json` is removed, all PWA features are disabled and the app works as before.

## Production Deployment

For production:

1. Use a strong, unique `SECRET_KEY`
2. Deploy behind HTTPS (required for secure cookies)
3. Update the redirect URI in your SweatStack application settings

### Deploying to Fly.io

Make sure you have the [Fly.io CLI](https://fly.io/docs/flyctl/) installed.

Start by doing an initial deployment of your app to get a URL for your app using this command:
```bash
fly launch
```

The url should look something like `https://your-app-name.fly.dev`.

Create a new `.env.production` file based on the `.env.template` file.
```bash
cp .env.template .env.production
```

Configure `.env.production` following the instructions in the [Quick Start](#3-configure-environment) section.
Set `APP_URL` to the URL of your app.

Run this command to import the secrets into Fly.io and redeploy your app:

```bash
cat .env.production | fly secrets import
```

When you make changes to your app, just run the `fly deploy` command again to redeploy your app.
You can configure the deployment configuration of your app in the `fly.toml` file that was creating during the intitial deploy.

## License

See [LICENSE](LICENSE) for the license of the code in this repository.