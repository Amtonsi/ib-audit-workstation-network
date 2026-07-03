from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import zip_longest
from typing import Literal


@dataclass(frozen=True)
class CpeName:
    uri: str
    part: str
    vendor: str
    product: str
    version: str
    update: str

    @classmethod
    def parse(cls, uri: str) -> "CpeName":
        parts = split_cpe23(uri)
        if len(parts) != 13 or parts[:2] != ["cpe", "2.3"]:
            raise ValueError(f"Invalid CPE 2.3 name: {uri}")
        return cls(
            uri=uri,
            part=unescape_cpe(parts[2]),
            vendor=unescape_cpe(parts[3]),
            product=unescape_cpe(parts[4]),
            version=unescape_cpe(parts[5]),
            update=unescape_cpe(parts[6]),
        )


@dataclass(frozen=True)
class VersionDecision:
    state: Literal[
        "affected",
        "not_affected",
        "product_wide",
        "unknown_version",
        "not_comparable",
    ]
    installed: str
    constraint: str
    reason: str


def split_cpe23(uri: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaping = False
    for char in uri:
        if escaping:
            current.append("\\" + char)
            escaping = False
            continue
        if char == "\\":
            escaping = True
            continue
        if char == ":":
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    if escaping:
        current.append("\\")
    parts.append("".join(current))
    return parts


def unescape_cpe(value: str) -> str:
    output: list[str] = []
    escaping = False
    for char in value:
        if escaping:
            output.append(char)
            escaping = False
        elif char == "\\":
            escaping = True
        else:
            output.append(char)
    if escaping:
        output.append("\\")
    return "".join(output)


def compare_version(
    installed: str,
    *,
    cpe_version: str,
    version_start_including: str = "",
    version_start_excluding: str = "",
    version_end_including: str = "",
    version_end_excluding: str = "",
) -> VersionDecision:
    installed = installed.strip()
    cpe_version = cpe_version.strip()
    constraints = {
        "cpe_version": cpe_version,
        "version_start_including": version_start_including,
        "version_start_excluding": version_start_excluding,
        "version_end_including": version_end_including,
        "version_end_excluding": version_end_excluding,
    }
    constraint = ", ".join(f"{key}={value}" for key, value in constraints.items() if value)
    has_range = any(
        value
        for value in (
            version_start_including,
            version_start_excluding,
            version_end_including,
            version_end_excluding,
        )
    )

    if not installed and (has_range or cpe_version not in {"", "*", "-"}):
        return VersionDecision("unknown_version", installed, constraint, "installed version is missing")

    if cpe_version not in {"", "*", "-"}:
        exact_cmp = _compare_versions(installed, cpe_version)
        if exact_cmp is None:
            if installed.casefold() != cpe_version.casefold():
                return VersionDecision("not_affected", installed, constraint, "installed version differs from exact CPE version")
        elif exact_cmp != 0:
            return VersionDecision("not_affected", installed, constraint, "installed version differs from exact CPE version")

    if not has_range:
        if cpe_version in {"", "*", "-"}:
            return VersionDecision("product_wide", installed, constraint or "product-wide", "CPE has no version constraint")
        return VersionDecision("affected", installed, constraint, "installed version equals exact CPE version")

    for boundary, predicate, label in (
        (version_start_including, lambda value: value >= 0, "versionStartIncluding"),
        (version_start_excluding, lambda value: value > 0, "versionStartExcluding"),
        (version_end_including, lambda value: value <= 0, "versionEndIncluding"),
        (version_end_excluding, lambda value: value < 0, "versionEndExcluding"),
    ):
        if not boundary:
            continue
        comparison = _compare_versions(installed, boundary)
        if comparison is None:
            return VersionDecision("not_comparable", installed, constraint, f"{label} is not comparable")
        if not predicate(comparison):
            return VersionDecision("not_affected", installed, constraint, f"installed version is outside {label}")
    return VersionDecision("affected", installed, constraint, "installed version is inside vulnerable range")


def _compare_versions(left: str, right: str) -> int | None:
    left_parts = _numeric_version(left)
    right_parts = _numeric_version(right)
    if left_parts is None or right_parts is None:
        return None
    for left_item, right_item in zip_longest(left_parts, right_parts, fillvalue=0):
        if left_item < right_item:
            return -1
        if left_item > right_item:
            return 1
    return 0


def _numeric_version(value: str) -> tuple[int, ...] | None:
    numbers = re.findall(r"\d+", value)
    if not numbers:
        return None
    return tuple(int(item) for item in numbers)
