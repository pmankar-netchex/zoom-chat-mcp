# Zoom Chat MCP

A [Model Context Protocol](https://modelcontextprotocol.io/) server that exposes [Zoom Chat API](https://developers.zoom.us/docs/api/) operations as tools. It uses OAuth 2.0 with a browser-based authorization flow, caches tokens on disk, and can refresh access tokens automatically.

## Requirements

- Python 3.14+
- A Zoom OAuth app in the [Zoom App Marketplace](https://marketplace.zoom.us/) with:

  - **Redirect URL:** `http://localhost:4199/oauth/callback` (the server listens on port `4199` for the OAuth callback)
  - **Scopes** that allow reading your user profile and chat data (for example, scopes aligned with `GET /users/me`, `GET /chat/users/me/channels`, and `GET /chat/users/me/messages` — see Zoom’s Chat API documentation for the exact scope names for your app type)

## Installation

Using [uv](https://github.com/astral-sh/uv) (recommended):

```bash
cd zoom-chat-mcp
uv sync
```

Or install dependencies with pip from `pyproject.toml` as usual.

## Configuration

Set these environment variables before starting the server:

| Variable | Required | Description |
|----------|----------|-------------|
| `ZOOM_CLIENT_ID` | Yes | OAuth client ID from your Zoom app |
| `ZOOM_CLIENT_SECRET` | Yes | OAuth client secret |
| `ZOOM_TOKEN_CACHE` | No | Path to the token cache JSON file (default: `~/.zoom_token_cache.json`) |
| `ZOOM_SCOPES` | No | Space-separated OAuth scopes to request (default: uses scopes configured in the Zoom app) |

On first run (or when the refresh token is missing or invalid), the process opens your browser for Zoom sign-in. After authorization, tokens are written to the cache file with mode `0600`.

### Authentication security

The OAuth flow includes the following protections:

- **PKCE (S256)** — Proof Key for Code Exchange prevents authorization code interception attacks. A unique `code_verifier` / `code_challenge` pair is generated per authorization attempt.
- **CSRF state parameter** — A random `state` nonce is included in the authorization request and verified on callback. Mismatched state returns HTTP 403.
- **Credential pre-validation** — Client credentials are validated against Zoom's token endpoint before opening the browser, giving an early error if the app is deactivated or the secret is wrong.
- **Token cache permissions** — The cache file is written with mode `0600` (owner read/write only).
- **UTC-based expiry** — All token expiry calculations use UTC internally for portability across timezones.

## Running the server

```bash
uv run python server.py
```

Or:

```bash
python server.py
```

The server runs with [FastMCP](https://github.com/jlowin/fastmcp) and speaks MCP over stdio (suitable for Cursor, Claude Desktop, and other MCP clients).

### Cursor / MCP client config

Point your client at `uv` and `server.py` with the working directory set to this repository (relative script, no hard-coded filesystem paths):

```json
{
  "mcpServers": {
    "zoom-chat": {
      "command": "uv",
      "args": ["run", "python", "server.py"],
      "cwd": "${workspaceFolder}",
      "env": {
        "ZOOM_CLIENT_ID": "your-client-id",
        "ZOOM_CLIENT_SECRET": "your-client-secret"
      }
    }
  }
}
```

Open the cloned repo as the workspace folder so `${workspaceFolder}` resolves correctly (or set `cwd` to whatever your MCP client uses for the project root). Adjust `env` as needed for your Zoom app.

## Tools

| Tool | Description |
|------|-------------|
| `reconnect_zoom` | Clears the token cache and triggers a fresh OAuth browser flow. Use when you get authentication errors. |
| `get_user_profile` | Returns the signed-in user’s profile (email, name, `member_id`, timezone, etc.). |
| `list_channels` | Lists all Zoom chat channels the user belongs to (`id`, `jid`, `name`, `type`). |
| `get_channel_messages` | Fetches messages for a channel **JID** between two ISO datetimes (`from_date`, `to_date`). |
| `scan_recent_chats` | High-level scan: profile + all channels + messages in the last *N* hours (default 6), with **relevance** labels (`high` / `medium` / `low` / `none`) based on mentions, authorship, threads, and bots. |
| `analyze_message_relevance` | Takes a JSON string of raw Zoom message objects plus user identity fields and returns the same relevance analysis without calling the Zoom API. |

Relevance rules (summary): **high** if you are @mentioned or you sent the message; **medium** if the message is in a thread you participated in; **low** otherwise; **none** for bot messages.

## Project layout

- `server.py` — MCP server, OAuth, Zoom API calls, and tools
- `main.py` — placeholder CLI stub (not used by the MCP server)
