#!/usr/bin/env python3
"""
Zoom Chat MCP Server
Exposes Zoom Chat API operations as MCP tools.
"""

import base64
import hashlib
import http.server
import json
import secrets
import sys
import threading
import urllib.parse
import webbrowser
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from mcp.server.fastmcp import FastMCP

UTC = timezone.utc

mcp = FastMCP(
    "Zoom Chat",
    instructions="Zoom Chat API tools — channels, messages, relevance analysis",
)

# ── Configuration (read at import time, overridable via env) ──

REDIRECT_PORT = 4199
OAUTH_CALLBACK_TIMEOUT_S = 180
HTTP_TIMEOUT_S = 15  # timeout per Zoom API request
MAX_WORKERS = 8  # parallel channel fetches
REDIRECT_URI = f"http://localhost:{REDIRECT_PORT}/oauth/callback"
ZOOM_AUTH_URL = "https://zoom.us/oauth/authorize"
ZOOM_TOKEN_URL = "https://zoom.us/oauth/token"
ZOOM_API_BASE = "https://api.zoom.us/v2"


def _get_env(name: str) -> str:
    """Read an env var, returning empty string if missing."""
    import os
    return os.environ.get(name, "")


def _token_cache_path() -> Path:
    return Path(_get_env("ZOOM_TOKEN_CACHE") or str(Path.home() / ".zoom_token_cache.json"))


# ── Token helpers ────────────────────────────────────────────

def _load_cached_token() -> dict | None:
    p = _token_cache_path()
    if p.exists():
        try:
            data = json.loads(p.read_text())
            if data.get("refresh_token"):
                return data
        except (json.JSONDecodeError, KeyError):
            pass
    return None


def _save_token_cache(token_data: dict) -> dict:
    cache = {
        "access_token": token_data["access_token"],
        "refresh_token": token_data.get("refresh_token", ""),
        "expires_at": (datetime.now(UTC) + timedelta(seconds=token_data.get("expires_in", 3600))).isoformat(),
    }
    p = _token_cache_path()
    p.write_text(json.dumps(cache, indent=2))
    p.chmod(0o600)
    return cache


def _invalidate_token_cache():
    """Remove the token cache so the next attempt starts fresh."""
    p = _token_cache_path()
    if p.exists():
        p.unlink()
        print(f"Cleared stale token cache: {p}", file=sys.stderr)


def _refresh_access_token(refresh_token: str) -> str | None:
    client_id = _get_env("ZOOM_CLIENT_ID").strip()
    client_secret = _get_env("ZOOM_CLIENT_SECRET").strip()
    if not client_id or not client_secret:
        print("Refresh failed: ZOOM_CLIENT_ID or ZOOM_CLIENT_SECRET not set", file=sys.stderr)
        return None
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    resp = requests.post(
        ZOOM_TOKEN_URL,
        headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        timeout=HTTP_TIMEOUT_S,
    )
    if resp.status_code == 200:
        token_data = resp.json()
        _save_token_cache(token_data)
        return token_data["access_token"]
    error_body = resp.text[:300]
    print(f"Refresh failed: {resp.status_code} — {error_body}", file=sys.stderr)
    if "invalid_client" in error_body:
        print(
            "ERROR: Zoom rejected client credentials. Check that your Zoom app is "
            "still active at marketplace.zoom.us and that ZOOM_CLIENT_ID / "
            "ZOOM_CLIENT_SECRET are correct.",
            file=sys.stderr,
        )
        _invalidate_token_cache()
    return None


# ── OAuth browser flow ───────────────────────────────────────

_auth_code_result = {"code": None, "expected_state": None}


class _OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/oauth/callback":
            self.send_response(404)
            self.end_headers()
            return
        params = urllib.parse.parse_qs(parsed.query)
        if "code" in params:
            # Verify state to prevent CSRF
            received_state = params.get("state", [None])[0]
            expected_state = _auth_code_result.get("expected_state")
            if expected_state and received_state != expected_state:
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><h2>Error: state mismatch (possible CSRF)</h2></body></html>")
                return
            _auth_code_result["code"] = params["code"][0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h2>Authorization successful!</h2><p>You can close this tab.</p></body></html>")
        else:
            self.send_response(400)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            error = params.get("error", ["unknown"])[0]
            self.wfile.write(f"<html><body><h2>Error: {error}</h2></body></html>".encode())

    def log_message(self, format, *args):
        pass


def _generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and S256 code_challenge."""
    code_verifier = secrets.token_urlsafe(64)  # 86 chars (within 43-128 range)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return code_verifier, code_challenge


def _serve_until_callback(server: http.server.HTTPServer) -> None:
    """Handle HTTP requests in a loop until the OAuth callback arrives."""
    while _auth_code_result["code"] is None:
        server.handle_request()


def _get_access_token_via_oauth() -> str:
    client_id = _get_env("ZOOM_CLIENT_ID").strip()
    client_secret = _get_env("ZOOM_CLIENT_SECRET").strip()
    if not client_id or not client_secret:
        raise RuntimeError(
            f"Missing credentials: ZOOM_CLIENT_ID={'set' if client_id else 'EMPTY'}, "
            f"ZOOM_CLIENT_SECRET={'set' if client_secret else 'EMPTY'}. "
            f"Set these environment variables in your MCP client config."
        )

    # Validate credentials before opening a browser
    _validate_client_credentials(client_id, client_secret)

    print(f"OAuth: client_id={client_id[:6]}…, secret_len={len(client_secret)}", file=sys.stderr)

    # PKCE
    code_verifier, code_challenge = _generate_pkce()

    # CSRF state
    state = secrets.token_urlsafe(32)

    # Reset stale auth code from any previous attempt
    _auth_code_result["code"] = None
    _auth_code_result["expected_state"] = state

    server = http.server.HTTPServer(("localhost", REDIRECT_PORT), _OAuthCallbackHandler)
    server.timeout = 5  # short timeout so the loop re-checks the condition
    server_thread = threading.Thread(target=_serve_until_callback, args=(server,), daemon=True)
    server_thread.start()

    auth_url = (
        f"{ZOOM_AUTH_URL}?response_type=code"
        f"&client_id={client_id}"
        f"&redirect_uri={urllib.parse.quote(REDIRECT_URI)}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
        f"&state={state}"
    )
    # Optional explicit scopes (otherwise uses scopes configured in the Zoom app)
    zoom_scopes = _get_env("ZOOM_SCOPES").strip()
    if zoom_scopes:
        auth_url += f"&scope={urllib.parse.quote(zoom_scopes)}"

    print(f"Opening browser for Zoom authorization...", file=sys.stderr)
    print(f"   If it doesn't open, visit:\n   {auth_url}\n", file=sys.stderr)
    webbrowser.open(auth_url)

    server_thread.join(timeout=OAUTH_CALLBACK_TIMEOUT_S)
    server.server_close()

    if not _auth_code_result["code"]:
        raise RuntimeError(
            f"OAuth authorization timed out after {OAUTH_CALLBACK_TIMEOUT_S}s or failed"
        )

    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    resp = requests.post(
        ZOOM_TOKEN_URL,
        headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={
            "grant_type": "authorization_code",
            "code": _auth_code_result["code"],
            "redirect_uri": REDIRECT_URI,
            "code_verifier": code_verifier,
        },
        timeout=HTTP_TIMEOUT_S,
    )
    if resp.status_code != 200:
        error_body = resp.text[:300]
        if "invalid_client" in error_body:
            raise RuntimeError(
                f"Zoom rejected client credentials during token exchange. "
                f"Your Zoom app may be deactivated — check marketplace.zoom.us. "
                f"Raw: {error_body}"
            )
        raise RuntimeError(f"Token exchange failed: {resp.status_code} — {error_body}")

    token_data = resp.json()
    _save_token_cache(token_data)
    return token_data["access_token"]


def _validate_client_credentials(client_id: str, client_secret: str):
    """Quick check that Zoom recognizes the client credentials.

    Uses a dummy authorization_code exchange — Zoom validates the client
    before checking the code, so 'invalid_grant' means credentials are OK
    while 'invalid_client' means they are not.
    """
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    try:
        resp = requests.post(
            ZOOM_TOKEN_URL,
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "authorization_code",
                "code": "__validation_probe__",
                "redirect_uri": REDIRECT_URI,
            },
            timeout=HTTP_TIMEOUT_S,
        )
        if "invalid_client" in resp.text:
            raise RuntimeError(
                f"Zoom does not recognize these client credentials "
                f"(client_id={client_id[:6]}…). The Zoom app may have been "
                f"deactivated or its secret regenerated. Visit marketplace.zoom.us "
                f"to check the app status and update ZOOM_CLIENT_SECRET in your "
                f"MCP client config."
            )
    except requests.RequestException:
        pass  # network error — let the actual OAuth flow handle it


def _get_access_token() -> str:
    cached = _load_cached_token()
    if cached:
        # Use cached access token if it hasn't expired yet
        expires_at = cached.get("expires_at", "")
        if expires_at and cached.get("access_token"):
            try:
                expiry = datetime.fromisoformat(expires_at)
                if datetime.now(UTC) < expiry - timedelta(minutes=5):
                    return cached["access_token"]
            except (ValueError, TypeError):
                pass
        # Otherwise try refreshing
        if cached.get("refresh_token"):
            token = _refresh_access_token(cached["refresh_token"])
            if token:
                return token
    return _get_access_token_via_oauth()


# ── Low-level API helper ────────────────────────────────────

def _api_get(token: str, endpoint: str, params: dict | None = None) -> dict | None:
    resp = requests.get(
        f"{ZOOM_API_BASE}{endpoint}",
        headers={"Authorization": f"Bearer {token}"},
        params=params or {},
        timeout=HTTP_TIMEOUT_S,
    )
    if resp.status_code == 200:
        return resp.json()
    if resp.status_code == 404:
        return None
    raise RuntimeError(f"Zoom API error on {endpoint}: {resp.status_code} — {resp.text[:300]}")


# ── MCP Tools ────────────────────────────────────────────────

@mcp.tool()
def reconnect_zoom() -> dict:
    """Clear cached tokens and re-authenticate with Zoom.

    Use this when you get authentication errors. It clears the token cache
    and triggers a fresh OAuth browser flow.
    """
    _invalidate_token_cache()
    try:
        token = _get_access_token_via_oauth()
        profile = _api_get(token, "/users/me") or {}
        return {
            "status": "reconnected",
            "user": profile.get("email", "unknown"),
        }
    except RuntimeError as exc:
        return {"status": "failed", "error": str(exc)}


@mcp.tool()
def get_user_profile() -> dict:
    """Get the authenticated Zoom user's profile (name, email, member_id)."""
    token = _get_access_token()
    profile = _api_get(token, "/users/me")
    if not profile:
        return {"error": "Could not fetch user profile"}
    return {
        "email": profile.get("email", ""),
        "first_name": profile.get("first_name", ""),
        "last_name": profile.get("last_name", ""),
        "display_name": f"{profile.get('first_name', '')} {profile.get('last_name', '')}".strip(),
        "member_id": profile.get("member_id", ""),
        "id": profile.get("id", ""),
        "timezone": profile.get("timezone", ""),
    }


@mcp.tool()
def list_channels() -> list[dict]:
    """List all Zoom chat channels the authenticated user belongs to."""
    token = _get_access_token()
    channels = []
    next_page_token = ""
    while True:
        params = {"page_size": 100}
        if next_page_token:
            params["next_page_token"] = next_page_token
        data = _api_get(token, "/chat/users/me/channels", params)
        if not data:
            break
        channels.extend(data.get("channels", []))
        next_page_token = data.get("next_page_token", "")
        if not next_page_token:
            break
    return [
        {
            "id": ch.get("id", ""),
            "jid": ch.get("jid", ""),
            "name": ch.get("name", ""),
            "type": ch.get("type", 0),
        }
        for ch in channels
    ]


@mcp.tool()
def get_channel_messages(
    channel_jid: str,
    from_date: str,
    to_date: str,
) -> list[dict]:
    """Fetch messages from a Zoom chat channel within a date range.

    Args:
        channel_jid: The JID of the channel (from list_channels).
        from_date: Start datetime in ISO format (e.g. 2026-04-07T10:00:00+05:30).
        to_date: End datetime in ISO format (e.g. 2026-04-08T10:00:00+05:30).
    """
    token = _get_access_token()
    from_dt = datetime.fromisoformat(from_date)
    to_dt = datetime.fromisoformat(to_date)

    all_messages = []
    current = from_dt.date()
    end = to_dt.date()
    dates_to_check = set()
    while current <= end:
        dates_to_check.add(current.strftime("%Y-%m-%d"))
        current += timedelta(days=1)

    for date_str in sorted(dates_to_check):
        next_page_token = ""
        while True:
            params = {"to_channel": channel_jid, "date": date_str, "page_size": 50}
            if next_page_token:
                params["next_page_token"] = next_page_token
            data = _api_get(token, "/chat/users/me/messages", params)
            if not data:
                break
            for msg in data.get("messages", []):
                msg_time_str = msg.get("date_time", "")
                if msg_time_str:
                    try:
                        msg_time = datetime.fromisoformat(msg_time_str.replace("Z", "+00:00"))
                        if from_dt <= msg_time <= to_dt:
                            all_messages.append(msg)
                        continue
                    except (ValueError, TypeError):
                        pass
                all_messages.append(msg)
            next_page_token = data.get("next_page_token", "")
            if not next_page_token:
                break

    return all_messages


@mcp.tool()
def scan_recent_chats(hours: int = 6) -> dict:
    """Scan all channels for recent messages and return them with relevance signals.

    This is the main high-level tool. It fetches your profile, lists channels,
    pulls messages from the given lookback window, and tags each message with
    relevance (high/medium/low/none) based on mentions, authorship, and threads.

    Args:
        hours: Number of hours to look back (default 6).
    """
    token = _get_access_token()

    # Profile
    me = _api_get(token, "/users/me") or {}
    my_email = me.get("email", "unknown")
    my_name = f"{me.get('first_name', '')} {me.get('last_name', '')}".strip() or "unknown"
    my_member_id = me.get("member_id", "")

    now = datetime.now(UTC)
    lookback_start = now - timedelta(hours=hours)

    # Channels
    channels = []
    next_page_token = ""
    while True:
        params = {"page_size": 100}
        if next_page_token:
            params["next_page_token"] = next_page_token
        data = _api_get(token, "/chat/users/me/channels", params)
        if not data:
            break
        channels.extend(data.get("channels", []))
        next_page_token = data.get("next_page_token", "")
        if not next_page_token:
            break

    type_labels = {1: "DM", 2: "Private Channel", 3: "Public Channel", 4: "Meeting Chat", 5: "New Chat"}

    dates_to_check = set()
    current = lookback_start.date()
    end = now.date()
    while current <= end:
        dates_to_check.add(current.strftime("%Y-%m-%d"))
        current += timedelta(days=1)
    sorted_dates = sorted(dates_to_check)

    # Fetch messages from one channel (runs in thread pool)
    def _fetch_channel_messages(ch):
        ch_jid = ch.get("jid", ch.get("id", ""))
        ch_name = ch.get("name", "Direct Message")
        ch_type = ch.get("type", 0)
        ch_type_label = type_labels.get(ch_type, f"Type {ch_type}")
        msgs = []
        for date_str in sorted_dates:
            npt = ""
            while True:
                params = {"to_channel": ch_jid, "date": date_str, "page_size": 50}
                if npt:
                    params["next_page_token"] = npt
                try:
                    data = _api_get(token, "/chat/users/me/messages", params)
                except Exception:
                    break
                if not data:
                    break
                for msg in data.get("messages", []):
                    msg_time_str = msg.get("date_time", "")
                    if msg_time_str:
                        try:
                            msg_time = datetime.fromisoformat(msg_time_str.replace("Z", "+00:00"))
                            if lookback_start <= msg_time <= now:
                                msg["_channel_name"] = ch_name
                                msg["_channel_type"] = ch_type_label
                                msgs.append(msg)
                            continue
                        except (ValueError, TypeError):
                            pass
                    msg["_channel_name"] = ch_name
                    msg["_channel_type"] = ch_type_label
                    msgs.append(msg)
                npt = data.get("next_page_token", "")
                if not npt:
                    break
        return msgs

    # Messages — fetch channels in parallel
    all_messages = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_fetch_channel_messages, ch): ch for ch in channels}
        for future in as_completed(futures):
            try:
                all_messages.extend(future.result())
            except Exception:
                pass  # skip channels that error out entirely

    # Relevance analysis
    enriched = _analyze_relevance(all_messages, my_email, my_name, my_member_id)
    relevant = [m for m in enriched if m["relevance"] != "none"]
    high = [m for m in enriched if m["relevance"] == "high"]
    medium = [m for m in enriched if m["relevance"] == "medium"]

    return {
        "scan_metadata": {
            "scan_time": now.isoformat(),
            "lookback_hours": hours,
            "lookback_start": lookback_start.isoformat(),
            "user_email": my_email,
            "user_name": my_name,
            "total_channels": len(channels),
            "total_messages": len(all_messages),
            "relevant_messages": len(relevant),
            "high_relevance": len(high),
            "medium_relevance": len(medium),
        },
        "messages": enriched,
    }


@mcp.tool()
def scan_direct_messages(hours: int = 6) -> dict:
    """Scan recent 1:1 direct messages with all contacts and tag relevance.

    Complements `scan_recent_chats` (which covers group channels) by fetching
    messages from each of the user's Zoom chat contacts via the `to_contact`
    endpoint. Each message is tagged with relevance (high/medium/low/none).

    Args:
        hours: Number of hours to look back (default 6).
    """
    token = _get_access_token()

    # Profile
    me = _api_get(token, "/users/me") or {}
    my_email = me.get("email", "unknown")
    my_name = f"{me.get('first_name', '')} {me.get('last_name', '')}".strip() or "unknown"
    my_member_id = me.get("member_id", "")

    now = datetime.now(UTC)
    lookback_start = now - timedelta(hours=hours)

    # Contacts — internal + external
    contacts = []
    seen_emails = set()
    for contact_type in ("internal", "external"):
        next_page_token = ""
        while True:
            params = {"type": contact_type, "page_size": 100}
            if next_page_token:
                params["next_page_token"] = next_page_token
            try:
                data = _api_get(token, "/chat/users/me/contacts", params)
            except RuntimeError:
                break
            if not data:
                break
            for c in data.get("contacts", []):
                email = c.get("email", "")
                if email and email != my_email and email not in seen_emails:
                    seen_emails.add(email)
                    contacts.append(c)
            next_page_token = data.get("next_page_token", "")
            if not next_page_token:
                break

    dates_to_check = set()
    current = lookback_start.date()
    end = now.date()
    while current <= end:
        dates_to_check.add(current.strftime("%Y-%m-%d"))
        current += timedelta(days=1)
    sorted_dates = sorted(dates_to_check)

    def _fetch_contact_messages(contact):
        contact_email = contact.get("email", "")
        contact_name = (
            f"{contact.get('first_name', '')} {contact.get('last_name', '')}".strip()
            or contact_email
            or "Unknown Contact"
        )
        msgs = []
        for date_str in sorted_dates:
            npt = ""
            while True:
                params = {"to_contact": contact_email, "date": date_str, "page_size": 50}
                if npt:
                    params["next_page_token"] = npt
                try:
                    data = _api_get(token, "/chat/users/me/messages", params)
                except Exception:
                    break
                if not data:
                    break
                for msg in data.get("messages", []):
                    msg_time_str = msg.get("date_time", "")
                    in_window = True
                    if msg_time_str:
                        try:
                            msg_time = datetime.fromisoformat(msg_time_str.replace("Z", "+00:00"))
                            in_window = lookback_start <= msg_time <= now
                        except (ValueError, TypeError):
                            pass
                    if in_window:
                        msg["_channel_name"] = f"DM: {contact_name}"
                        msg["_channel_type"] = "DM"
                        msgs.append(msg)
                npt = data.get("next_page_token", "")
                if not npt:
                    break
        return msgs

    all_messages = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_fetch_contact_messages, c): c for c in contacts}
        for future in as_completed(futures):
            try:
                all_messages.extend(future.result())
            except Exception:
                pass

    enriched = _analyze_relevance(all_messages, my_email, my_name, my_member_id)
    relevant = [m for m in enriched if m["relevance"] != "none"]
    high = [m for m in enriched if m["relevance"] == "high"]
    medium = [m for m in enriched if m["relevance"] == "medium"]

    return {
        "scan_metadata": {
            "scan_time": now.isoformat(),
            "lookback_hours": hours,
            "lookback_start": lookback_start.isoformat(),
            "user_email": my_email,
            "user_name": my_name,
            "total_contacts": len(contacts),
            "total_messages": len(all_messages),
            "relevant_messages": len(relevant),
            "high_relevance": len(high),
            "medium_relevance": len(medium),
        },
        "messages": enriched,
    }


@mcp.tool()
def analyze_message_relevance(
    messages_json: str,
    user_email: str,
    user_name: str,
    user_member_id: str = "",
) -> list[dict]:
    """Analyze relevance of a list of Zoom messages for a given user.

    Tags each message with relevance signals: high (mentioned/sent by user),
    medium (in a thread the user participated in), low (other), none (bot).

    Args:
        messages_json: JSON string of a list of raw Zoom message objects.
        user_email: The user's email address.
        user_name: The user's display name.
        user_member_id: The user's Zoom member_id (optional, improves @mention detection).
    """
    messages = json.loads(messages_json)
    return _analyze_relevance(messages, user_email, user_name, user_member_id)


# ── Relevance analysis (internal) ───────────────────────────

def _analyze_relevance(messages: list[dict], my_email: str, my_name: str, my_member_id: str) -> list[dict]:
    type_labels = {1: "DM", 2: "Private Channel", 3: "Public Channel", 4: "Meeting Chat", 5: "New Chat"}

    threads = defaultdict(list)
    for msg in messages:
        reply_id = msg.get("reply_main_message_id")
        if reply_id:
            threads[reply_id].append(msg)

    user_thread_ids = set()
    for msg in messages:
        if _is_from_user(msg, my_email, my_name):
            reply_id = msg.get("reply_main_message_id")
            if reply_id:
                user_thread_ids.add(reply_id)
            user_thread_ids.add(msg.get("id", ""))

    enriched = []
    for msg in messages:
        is_bot = bool(msg.get("bot_message"))
        is_from = _is_from_user(msg, my_email, my_name)
        is_mention = _is_mention(msg, my_email, my_name, my_member_id)
        reply_id = msg.get("reply_main_message_id")
        is_in_thread = (reply_id in user_thread_ids) if reply_id else (msg.get("id", "") in user_thread_ids)

        relevance = "low"
        reasons = []
        if is_bot:
            relevance = "none"
            reasons.append("bot_message")
        elif is_mention:
            relevance = "high"
            reasons.append("directly_mentioned")
        elif is_from:
            relevance = "high"
            reasons.append("sent_by_user")
        elif is_in_thread:
            relevance = "medium"
            reasons.append("in_user_thread")

        enriched.append({
            "id": msg.get("id", ""),
            "channel_name": msg.get("_channel_name", "Unknown"),
            "channel_type": msg.get("_channel_type", type_labels.get(msg.get("type", 0), "Unknown")),
            "sender_email": msg.get("sender", ""),
            "sender_name": msg.get("sender_display_name", ""),
            "timestamp": msg.get("date_time", ""),
            "message": msg.get("message", ""),
            "is_bot": is_bot,
            "is_from_user": is_from,
            "is_mention": is_mention,
            "is_in_user_thread": is_in_thread,
            "reply_to_thread": reply_id or None,
            "relevance": relevance,
            "relevance_reasons": reasons,
            "has_files": bool(msg.get("files")),
            "reactions_count": sum(r.get("total_count", 0) for r in msg.get("reactions", [])),
        })

    return enriched


def _is_from_user(msg: dict, my_email: str, my_name: str) -> bool:
    sender = msg.get("sender", "")
    sender_name = msg.get("sender_display_name", "")
    return (sender == my_email) or (
        sender_name and my_name and sender_name.lower() == my_name.lower()
    )


def _is_mention(msg: dict, my_email: str, my_name: str, my_member_id: str) -> bool:
    for item in msg.get("at_items", []):
        if item.get("at_contact_member_id") == my_member_id:
            return True
    message_text = msg.get("message", "").lower()
    if my_name and my_name.lower() in message_text:
        if not _is_from_user(msg, my_email, my_name):
            return True
    return False


# ── Entry point ──────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
