from __future__ import annotations

import gzip
import io
import json
import tarfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .cancellation import CancellationToken


CHUNK_SIZE = 1024 * 1024


@contextmanager
def open_nvd_json_text(path: Path) -> Iterator[io.TextIOBase]:
    if path.name.endswith(".tar.gz") or path.name.endswith(".tgz"):
        archive = tarfile.open(path, "r:gz")
        extracted = None
        text = None
        try:
            member = next(
                (
                    item
                    for item in archive.getmembers()
                    if item.isfile() and item.name.casefold().endswith(".json")
                ),
                None,
            )
            if member is None:
                raise ValueError(f"No JSON member found in {path}")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError(f"Cannot read JSON member {member.name} from {path}")
            text = io.TextIOWrapper(extracted, encoding="utf-8", errors="replace")
            yield text
        finally:
            if text is not None:
                text.close()
            elif extracted is not None:
                extracted.close()
            archive.close()
    elif path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            yield handle
    else:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            yield handle


def iter_nvd_feed_items(
    path: str | Path,
    array_name: str,
    cancel_token: CancellationToken | None = None,
) -> Iterator[dict[str, Any]]:
    decoder = json.JSONDecoder()
    path = Path(path)
    marker = f'"{array_name}"'
    with open_nvd_json_text(path) as stream:
        buffer = ""
        eof = False

        while True:
            _raise_if_cancelled(cancel_token)
            marker_at = buffer.find(marker)
            bracket_at = buffer.find("[", marker_at + len(marker)) if marker_at >= 0 else -1
            if bracket_at >= 0:
                buffer = buffer[bracket_at + 1 :]
                break
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                raise ValueError(f"Array {array_name!r} not found")
            buffer += chunk
            if len(buffer) > len(marker) + 64 and buffer.find(marker) < 0:
                buffer = buffer[-(len(marker) + 64) :]

        while True:
            _raise_if_cancelled(cancel_token)
            buffer = buffer.lstrip()
            if buffer.startswith("]"):
                return
            if not buffer and eof:
                return
            try:
                item, end = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                if eof:
                    raise
                chunk = stream.read(CHUNK_SIZE)
                if chunk:
                    buffer += chunk
                    continue
                eof = True
                continue
            if not isinstance(item, dict):
                raise ValueError(f"{array_name} item is not an object")
            yield item
            buffer = buffer[end:].lstrip()
            if buffer.startswith(","):
                buffer = buffer[1:]


def _raise_if_cancelled(cancel_token: CancellationToken | None) -> None:
    if cancel_token is not None:
        cancel_token.raise_if_cancelled()
