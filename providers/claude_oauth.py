from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from mitsu.config import CredentialStore
from mitsu.providers.client import ProviderRequestError


CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
REDIRECT_URI = "https://console.anthropic.com/oauth/code/callback"
SCOPES = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
TOKEN_ENDPOINTS = (
    "https://platform.claude.com/v1/oauth/token",
    "https://console.anthropic.com/v1/oauth/token",
)
OAUTH_BETA = "oauth-2025-04-20"


def create_login() -> tuple[str, str, str]:
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(32)
    query = urlencode(
        {
            "code": "true",
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPES,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
    )
    return f"https://claude.ai/oauth/authorize?{query}", verifier, state


def exchange_login(value: str, verifier: str, expected_state: str) -> dict[str, object]:
    code, separator, state = value.strip().partition("#")
    if not separator or not code or not secrets.compare_digest(state, expected_state):
        raise ProviderRequestError("Claude sign-in code or state did not match. Start sign-in again.")
    token = _token_request(
        {
            "grant_type": "authorization_code",
            "code": code,
            "state": state,
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }
    )
    return _profile_tokens(token)


def access_token(profile: dict[str, object]) -> str:
    expiry = float(profile.get("expires_at", 0) or 0)
    if expiry > time.time() + 60:
        return str(profile.get("access_token", ""))
    refresh = str(profile.get("refresh_token", ""))
    if not refresh:
        raise ProviderRequestError("Claude account session expired. Sign in again.")
    token = _token_request(
        {"grant_type": "refresh_token", "refresh_token": refresh, "client_id": CLIENT_ID}
    )
    profile.update(_profile_tokens(token))
    CredentialStore().update_auth_tokens("anthropic", profile)
    return str(profile["access_token"])


def _profile_tokens(token: dict[str, object]) -> dict[str, object]:
    expires = int(token.get("expires_in", 3600) or 3600)
    return {
        "auth_method": "account",
        "api_key": "",
        "access_token": str(token["access_token"]),
        "refresh_token": str(token.get("refresh_token", "")),
        "expires_at": int(time.time()) + expires,
    }


def _token_request(payload: dict[str, str]) -> dict[str, object]:
    last_error = "Claude OAuth token request failed."
    for endpoint in TOKEN_ENDPOINTS:
        request = Request(
            endpoint,
            data=json.dumps(payload).encode(),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "anthropic-beta": OAUTH_BETA,
                "User-Agent": "claude-cli/2.1.2 (external, cli)",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=30) as response:
                result = json.loads(response.read().decode())
            if isinstance(result, dict) and result.get("access_token"):
                return result
            raise ProviderRequestError("Claude OAuth returned an invalid token response.")
        except HTTPError as error:
            detail = error.read(1024).decode("utf-8", errors="replace")
            for secret in payload.values():
                if secret:
                    detail = detail.replace(secret, "[hidden]")
            last_error = f"Claude OAuth returned HTTP {error.code}: {detail[:240]}"
            if error.code not in {404, 405, 410}:
                break
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
            last_error = f"Could not complete Claude sign-in: {error}"
            break
    raise ProviderRequestError(last_error)
