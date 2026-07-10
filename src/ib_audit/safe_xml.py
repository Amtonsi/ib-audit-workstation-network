from __future__ import annotations

from typing import Any

from defusedxml.ElementTree import fromstring as defused_fromstring


MAX_XML_BYTES = 128 * 1024 * 1024
_FORBIDDEN_DECLARATIONS = (b"<!doctype", b"<!entity")


def fromstring(payload: bytes | str, *, max_bytes: int = MAX_XML_BYTES) -> Any:
    """Parse bounded XML after rejecting declarations used by entity attacks."""
    raw = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
    if len(raw) > max_bytes:
        raise ValueError(f"XML payload exceeds the {max_bytes}-byte safety limit")
    lowered = raw.lower()
    if any(marker in lowered for marker in _FORBIDDEN_DECLARATIONS):
        raise ValueError("DTD and ENTITY declarations are not allowed")
    return defused_fromstring(payload)
