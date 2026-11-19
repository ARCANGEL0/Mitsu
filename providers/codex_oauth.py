from __future__ import annotations

import base64
import contextlib
import hashlib
import http.server
import json
import os
import secrets
import threading
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen

from mitsu.config import CredentialStore
from mitsu.providers.client import ProviderRequestError


AUTHORIZATION_ENDPOINT = "https://auth.openai.com/api/accounts/authorize"
TOKEN_ENDPOINT = "https://auth.openai.com/api/accounts/oauth/token"
RESOURCE = "https://api.openai.com/v1"
ISSUER = "https://auth.openai.com"
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
_refresh_lock = threading.Lock()
_metadata_lock = threading.Lock()
_metadata_cache: tuple[float, dict[str, object]] | None = None


@contextlib.contextmanager
def _serialized_refresh():
    with _refresh_lock:
        path = CredentialStore().path.with_suffix(".openai-oauth.lock")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            try:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            except ImportError:
                pass
            yield
        finally:
            try:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except ImportError:
                pass
            os.close(descriptor)


def sign_in(profile: dict[str, object]) -> dict[str, object]:
    host_id = str(profile.get("host_id") or f"urn:uuid:{uuid.uuid4()}")
    client_id = str(profile.get("client_id") or "dynamic_agent_client")
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    callback: dict[str, list[str]] = {}

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            if parsed.path != "/auth/callback":
                self.send_error(404)
                return
            received = parse_qs(parsed.query, keep_blank_values=True)
            returned_state = _first(received, "state")
            if not secrets.compare_digest(returned_state, state):
                self.send_error(400)
                return
            callback.update(received)
            body = b"Mitsu sign-in received. You can return to the terminal."
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *args: object) -> None:
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), CallbackHandler)
    server.timeout = 1
    redirect_uri = f"http://127.0.0.1:{server.server_port}/auth/callback"
    query: dict[str, str] = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": SCOPES,
        "resource": RESOURCE,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "ext_agent_host_id": host_id,
    }
    if client_id == "dynamic_agent_client":
        query["agent_name_hint"] = "Mitsu"
    elif profile.get("id_token"):
        query["id_token_hint"] = str(profile["id_token"])
    if profile.get("email"):
        query["login_hint"] = str(profile["email"])
    authorize_url = f"{AUTHORIZATION_ENDPOINT}?{urlencode(query)}"
    import webbrowser

    webbrowser.open(authorize_url)
    deadline = time.monotonic() + 300
    try:
        while not callback and time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()
    if not callback:
        raise ProviderRequestError("OpenAI sign-in timed out. Start account sign-in again.")
    returned_state = _first(callback, "state")
    if not secrets.compare_digest(returned_state, state):
        raise ProviderRequestError("OpenAI sign-in state did not match. Start account sign-in again.")
    oauth_error = _first(callback, "error")
    if oauth_error:
        raise ProviderRequestError(f"OpenAI sign-in was not completed: {oauth_error}")
    code = _first(callback, "code")
    issued_client_id = _first(callback, "client_id") or client_id
    if not code:
        raise ProviderRequestError("OpenAI sign-in did not return an authorization code.")
    if client_id != "dynamic_agent_client" and issued_client_id != client_id:
        raise ProviderRequestError("OpenAI returned a different app registration than the selected account.")
    if issued_client_id == "dynamic_agent_client":
        raise ProviderRequestError("OpenAI did not return the issued app client ID.")
    token = _post_form(
        {
            "grant_type": "authorization_code",
            "client_id": issued_client_id,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": redirect_uri,
            "resource": RESOURCE,
        }
    )
    scopes = str(token.get("scope", "")).split()
    identity = _validate_id_token(str(token.get("id_token", "")), issued_client_id, nonce)
    if "chatgpt.tokens.use.direct" not in scopes:
        raise ProviderRequestError("OpenAI account did not grant ChatGPT plan model access.")
    if profile.get("subject") and profile.get("subject") != identity.get("sub"):
        raise ProviderRequestError("OpenAI sign-in returned a different account than the saved connection.")
    return {
        "auth_method": "account",
        "api_key": "",
        "access_token": str(token.get("access_token", "")),
        "refresh_token": str(token.get("refresh_token", "")),
        "expires_at": int(time.time()) + int(token.get("expires_in", 3600) or 3600),
        "id_token": str(token.get("id_token", "")),
        "client_id": issued_client_id,
        "host_id": host_id,
        "subject": str(identity.get("sub", "")),
        "email": str(identity.get("email", "")),
        "scopes": scopes,
    }


def access_token(profile: dict[str, object]) -> str:
    if float(profile.get("expires_at", 0) or 0) > time.time() + 60:
        return str(profile.get("access_token", ""))
    with _serialized_refresh():
        current = CredentialStore().profile_for("openai") or {}
        if float(current.get("expires_at", 0) or 0) > time.time() + 60:
            for key in ("access_token", "refresh_token", "expires_at", "id_token", "scopes"):
                if key in current:
                    profile[key] = current[key]
            return str(profile.get("access_token", ""))
        refresh = str(profile.get("refresh_token", ""))
        client_id = str(profile.get("client_id", ""))
        if not refresh or not client_id:
            raise ProviderRequestError("OpenAI account session expired. Sign in again.")
        token = _post_form(
            {
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh,
                "resource": RESOURCE,
            }
        )
        updates = _updated_tokens(token, profile)
        profile.update(updates)
        CredentialStore().update_auth_tokens("openai", updates)
        return str(profile["access_token"])


def _updated_tokens(token: dict[str, object], previous: dict[str, object]) -> dict[str, object]:
    scope = str(token.get("scope", ""))
    scopes = scope.split() if scope else previous.get("scopes", [])
    if "chatgpt.tokens.use.direct" not in scopes:
        raise ProviderRequestError("OpenAI account no longer grants ChatGPT plan model access. Sign in again.")
    return {
        "access_token": str(token.get("access_token", "")),
        "refresh_token": str(token.get("refresh_token") or previous.get("refresh_token", "")),
        "expires_at": int(time.time()) + int(token.get("expires_in", 3600) or 3600),
        "id_token": str(token.get("id_token") or previous.get("id_token", "")),
        "scopes": scopes,
    }


def _post_form(payload: dict[str, str]) -> dict[str, object]:
    request = Request(
        TOKEN_ENDPOINT,
        data=urlencode(payload).encode(),
        headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode())
    except HTTPError as error:
        detail = error.read(1024).decode("utf-8", errors="replace")
        for secret in payload.values():
            if secret:
                detail = detail.replace(secret, "[hidden]")
        raise ProviderRequestError(f"OpenAI OAuth returned HTTP {error.code}: {detail[:240]}") from error
    except (URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
        raise ProviderRequestError(f"Could not complete OpenAI sign-in: {error}") from error
    if not isinstance(result, dict) or not result.get("access_token"):
        raise ProviderRequestError("OpenAI OAuth returned an invalid token response.")
    return result


def _validate_id_token(token: str, audience: str, nonce: str) -> dict[str, object]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ProviderRequestError("OpenAI returned a malformed identity token.")
    try:
        header = _decode(parts[0])
        claims = _decode(parts[1])
        signature = _decode_bytes(parts[2])
    except (ValueError, json.JSONDecodeError) as error:
        raise ProviderRequestError("OpenAI returned a malformed identity token.") from error
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ProviderRequestError("OpenAI returned a malformed identity token.")
    if header.get("alg") != "RS256" or not header.get("kid"):
        raise ProviderRequestError("OpenAI identity token uses an unsupported signature.")
    keys = _get_jwks()
    key = next((item for item in keys if item.get("kid") == header["kid"]), None)
    if key is None or key.get("kty") != "RSA":
        raise ProviderRequestError("OpenAI identity token signing key was not found.")
    _verify_rs256(key, f"{parts[0]}.{parts[1]}".encode(), signature)
    audiences = claims.get("aud", [])
    if isinstance(audiences, str):
        audiences = [audiences]
    if not isinstance(audiences, list):
        audiences = []
    try:
        expires = int(claims.get("exp", 0))
        issued = int(claims.get("iat", 0))
    except (TypeError, ValueError) as error:
        raise ProviderRequestError("OpenAI identity token validation failed.") from error
    valid = (
        claims.get("iss") == _oidc_metadata().get("issuer")
        and audience in audiences
        and expires > int(time.time())
        and 0 < issued <= int(time.time()) + 5
        and secrets.compare_digest(str(claims.get("nonce", "")), nonce)
        and bool(claims.get("sub"))
    )
    if not valid:
        raise ProviderRequestError("OpenAI identity token validation failed.")
    return claims


def _get_jwks() -> list[dict[str, object]]:
    jwks_uri = str(_oidc_metadata().get("jwks_uri", ""))
    if not jwks_uri.startswith("https://auth.openai.com/"):
        raise ProviderRequestError("OpenAI identity metadata returned an invalid signing key URL.")
    request = Request(jwks_uri, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=20) as response:
            result = json.loads(response.read().decode())
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
        raise ProviderRequestError(f"Could not validate OpenAI identity token: {error}") from error
    keys = result.get("keys") if isinstance(result, dict) else None
    if not isinstance(keys, list):
        raise ProviderRequestError("OpenAI identity service returned an invalid signing key set.")
    return [key for key in keys if isinstance(key, dict)]


def _oidc_metadata() -> dict[str, object]:
    global _metadata_cache
    with _metadata_lock:
        if _metadata_cache and _metadata_cache[0] > time.time():
            return _metadata_cache[1]
        request = Request(
            f"{ISSUER}/.well-known/openid-configuration",
            headers={"Accept": "application/json"},
        )
        try:
            with urlopen(request, timeout=20) as response:
                metadata = json.loads(response.read().decode())
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
            raise ProviderRequestError(f"Could not load OpenAI identity metadata: {error}") from error
        if not isinstance(metadata, dict) or metadata.get("issuer") != ISSUER:
            raise ProviderRequestError("OpenAI identity metadata failed issuer validation.")
        _metadata_cache = (time.time() + 600, metadata)
        return metadata


def _verify_rs256(key: dict[str, object], signing_input: bytes, signature: bytes) -> None:
    try:
        modulus = int.from_bytes(_decode_bytes(str(key["n"])), "big")
        exponent = int.from_bytes(_decode_bytes(str(key["e"])), "big")
        actual = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes((modulus.bit_length() + 7) // 8, "big")
    except (KeyError, ValueError, OverflowError) as error:
        raise ProviderRequestError("OpenAI identity token signing key is malformed.") from error
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(signing_input).digest()
    padding_size = len(actual) - len(digest_info) - 3
    expected = b"\x00\x01" + b"\xff" * padding_size + b"\x00" + digest_info
    if padding_size < 8 or not secrets.compare_digest(actual, expected):
        raise ProviderRequestError("OpenAI identity token signature validation failed.")


def _decode(value: str) -> object:
    return json.loads(_decode_bytes(value))


def _decode_bytes(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _first(query: dict[str, list[str]], key: str) -> str:
    values = query.get(key, [])
    return values[0] if values else ""
