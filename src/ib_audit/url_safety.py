from __future__ import annotations

import urllib.parse


def validated_https_url(url: str) -> str:
    """Return a normalized HTTPS URL or reject unsafe downloader input."""
    value = str(url or "").strip()
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme.casefold() != "https" or not parsed.hostname:
        raise ValueError("Only absolute HTTPS URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in download URLs are not allowed")
    return value
