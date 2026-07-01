from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Callable
from uuid import uuid4

from .models import SourceSnapshot, utc_now


class CacheMiss(FileNotFoundError):
    pass


class CacheCorrupt(ValueError):
    pass


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", value.casefold()).strip("-") or "cache"


class SnapshotCache:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _folder(self, source: str, cache_key: str) -> Path:
        path = self.root / _slug(source) / _slug(cache_key)
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            temp_path = Path(handle.name)
        temp_path.replace(path)

    def store_json(self, source: str, cache_key: str, payload: object) -> SourceSnapshot:
        data = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return self.store_bytes(source, cache_key, data, "json")

    def store_text(self, source: str, cache_key: str, payload: str) -> SourceSnapshot:
        return self.store_bytes(source, cache_key, payload.encode("utf-8"), "text")

    def store_bytes(
        self,
        source: str,
        cache_key: str,
        payload: bytes,
        content_type: str = "json",
    ) -> SourceSnapshot:
        if content_type == "json":
            try:
                json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"Invalid JSON snapshot: {exc}") from exc
        folder = self._folder(source, cache_key)
        digest = hashlib.sha256(payload).hexdigest()
        extension = "json" if content_type == "json" else "txt"
        content_path = folder / f"{digest}.{extension}"
        if not content_path.exists():
            self._atomic_write(content_path, payload)
        fetched_at = utc_now()
        snapshot = SourceSnapshot(
            str(uuid4()), source, cache_key, str(content_path), digest,
            fetched_at, "active", {"content_type": content_type},
        )
        pointer = {
            "id": snapshot.id, "source": source, "cache_key": cache_key,
            "path": str(content_path), "sha256": digest, "fetched_at": fetched_at,
            "status": "active", "metadata": snapshot.metadata,
        }
        self._atomic_write(
            folder / "active.json",
            json.dumps(pointer, ensure_ascii=False, sort_keys=True).encode("utf-8"),
        )
        return snapshot

    def load_json(self, source: str, cache_key: str) -> tuple[object, SourceSnapshot]:
        pointer_path = self._folder(source, cache_key) / "active.json"
        if not pointer_path.exists():
            raise CacheMiss(f"No cached snapshot for {source}/{cache_key}")
        try:
            pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
            content_path = Path(pointer["path"])
            data = content_path.read_bytes()
        except (OSError, KeyError, json.JSONDecodeError) as exc:
            raise CacheCorrupt(f"Invalid active snapshot: {exc}") from exc
        digest = hashlib.sha256(data).hexdigest()
        if digest != pointer.get("sha256"):
            raise CacheCorrupt("Cached snapshot hash mismatch")
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CacheCorrupt(f"Cached JSON is invalid: {exc}") from exc
        snapshot = SourceSnapshot(
            pointer["id"], pointer["source"], pointer["cache_key"], pointer["path"],
            pointer["sha256"], pointer["fetched_at"], pointer["status"],
            pointer.get("metadata", {}),
        )
        return payload, snapshot

    def load_text(self, source: str, cache_key: str) -> tuple[str, SourceSnapshot]:
        pointer_path = self._folder(source, cache_key) / "active.json"
        if not pointer_path.exists():
            raise CacheMiss(f"No cached snapshot for {source}/{cache_key}")
        try:
            pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
            content_path = Path(pointer["path"])
            data = content_path.read_bytes()
        except (OSError, KeyError, json.JSONDecodeError) as exc:
            raise CacheCorrupt(f"Invalid active snapshot: {exc}") from exc
        digest = hashlib.sha256(data).hexdigest()
        if digest != pointer.get("sha256"):
            raise CacheCorrupt("Cached snapshot hash mismatch")
        snapshot = SourceSnapshot(
            pointer["id"], pointer["source"], pointer["cache_key"], pointer["path"],
            pointer["sha256"], pointer["fetched_at"], pointer["status"],
            pointer.get("metadata", {}),
        )
        return data.decode("utf-8", errors="replace"), snapshot

    def get_or_fetch_json(
        self,
        source: str,
        cache_key: str,
        online: bool,
        fetcher: Callable[[], object],
    ) -> tuple[object, SourceSnapshot, str]:
        cached = None
        try:
            cached = self.load_json(source, cache_key)
        except (CacheMiss, CacheCorrupt):
            pass
        if online:
            try:
                payload = fetcher()
                snapshot = self.store_json(source, cache_key, payload)
                return payload, snapshot, "updated"
            except Exception:
                if cached is not None:
                    return cached[0], cached[1], "cached-after-error"
                raise
        if cached is not None:
                return cached[0], cached[1], "cached"
        raise CacheMiss(f"No cached snapshot for {source}/{cache_key}")

    def get_or_fetch_text(
        self,
        source: str,
        cache_key: str,
        online: bool,
        fetcher: Callable[[], str],
    ) -> tuple[str, SourceSnapshot, str]:
        cached = None
        try:
            cached = self.load_text(source, cache_key)
        except (CacheMiss, CacheCorrupt):
            pass
        if online:
            try:
                payload = fetcher()
                snapshot = self.store_text(source, cache_key, payload)
                return payload, snapshot, "updated"
            except Exception:
                if cached is not None:
                    return cached[0], cached[1], "cached-after-error"
                raise
        if cached is not None:
            return cached[0], cached[1], "cached"
        raise CacheMiss(f"No cached snapshot for {source}/{cache_key}")
