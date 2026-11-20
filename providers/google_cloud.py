from __future__ import annotations

import shutil
import subprocess
from typing import Any

from .client import ProviderRequestError


VERTEX_BASE_URL = "https://aiplatform.googleapis.com/v1/projects/{project}/locations/{location}/endpoints/openapi"
GOOGLE_MODELS = ("gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash")


def _gcloud(*args: str) -> str:
    if shutil.which("gcloud") is None:
        raise ProviderRequestError("Google Cloud account mode requires the gcloud CLI.")
    try:
        result = subprocess.run(
            ["gcloud", *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except OSError as error:
        raise ProviderRequestError(f"Could not start gcloud: {error}") from error
    output = (result.stdout or "").strip()
    if result.returncode != 0 or not output or output in {"(unset)", "None"}:
        detail = (result.stderr or output or "Google Cloud authentication failed").strip()
        raise ProviderRequestError(detail[:500])
    return output


def account_profile(profile: dict[str, Any]) -> dict[str, Any]:
    project = str(profile.get("project_id") or _gcloud("config", "get-value", "project"))
    location = str(profile.get("location") or "global")
    token = _gcloud("auth", "application-default", "print-access-token")
    return {
        **profile,
        "project_id": project,
        "location": location,
        "base_url": VERTEX_BASE_URL.format(project=project, location=location),
        "api_key": token,
        "auth_method": "account",
    }


def verify(profile: dict[str, Any]) -> str:
    account_profile(profile)
    return "Google Cloud account and Vertex AI credentials verified."
