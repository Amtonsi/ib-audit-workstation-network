from __future__ import annotations

import re
from itertools import zip_longest


_VERSION_RE = re.compile(r"\d+(?:[._-]\d+)*")
_V = _VERSION_RE.pattern

_EARLY_KEYWORDS = (
    "до",
    "перед",
    "ранее",
    "раньше",
    "ниже",
    "lower than",
    "before",
    "prior to",
    "earlier than",
    "previous",
    "all earlier",
    "all previous",
    "all prior",
    "and earlier",
    "or earlier",
)
_LATE_KEYWORDS = (
    "после",
    "позже",
    "выше",
    "later than",
    "newer than",
    "after",
    "from",
    "above",
    "and later",
    "or later",
    "all later",
    "all newer",
)
_INCLUSIVE_KEYWORDS = (
    "включая",
    "включительно",
    "including",
    "or equal",
    "and equal",
)


def _to_version_tuple(value: str) -> tuple[int, ...] | None:
    match = _VERSION_RE.search(str(value).strip())
    if not match:
        return None
    try:
        return tuple(int(part) for part in re.split(r"[._-]", match.group(0)) if part != "")
    except ValueError:
        return None


def _compare_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    for left_item, right_item in zip_longest(left, right, fillvalue=0):
        if left_item < right_item:
            return -1
        if left_item > right_item:
            return 1
    return 0


def _contains_any(value: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword in value for keyword in keywords)


def _normalize(expression: str) -> str:
    return re.sub(r"\s+", " ", str(expression or "").strip().casefold())


def _split_expression(expression: str) -> list[str]:
    normalized = _normalize(expression)
    if not normalized:
        return []
    parts = re.split(r"\s*(?:,|;|\bили\b|\bor\b)\s*", normalized)
    return [part.strip() for part in parts if part.strip()]


def _extract_versions(expression: str) -> list[str]:
    return list(_VERSION_RE.findall(expression))


def _range_match(installed: tuple[int, ...], clause: str) -> bool | None:
    # "от X до Y", "from X to Y", "X-Y"
    from_to_match = re.search(
        rf"\b(?:от|from)\b\s*(?P<low>{_V})\s+(?:\b(?:до|to|through|until|по)\b)\s+(?:\b(?:включая|including)?\s*)?(?P<high>{_V})",
        clause,
    )
    if from_to_match:
        low = _to_version_tuple(from_to_match.group("low"))
        high = _to_version_tuple(from_to_match.group("high"))
        if low is None or high is None:
            return None
        low_compare = _compare_versions(installed, low)
        high_compare = _compare_versions(installed, high)
        if low_compare < 0 or high_compare > 0:
            return False
        include_high = _contains_any(clause, _INCLUSIVE_KEYWORDS)
        if high_compare == 0:
            return True if include_high else False
        return True

    hyphen_match = re.search(rf"\b(?P<low>{_V})\s*[-\u2013\u2014]\s*(?P<high>{_V})\b", clause)
    if hyphen_match:
        low = _to_version_tuple(hyphen_match.group("low"))
        high = _to_version_tuple(hyphen_match.group("high"))
        if low is None or high is None:
            return None
        low_compare = _compare_versions(installed, low)
        high_compare = _compare_versions(installed, high)
        if low_compare < 0 or high_compare > 0:
            return False
        return True

    return None


def _directional_match(installed: tuple[int, ...], clause: str) -> bool | None:
    versions = _extract_versions(clause)
    if not versions:
        return None
    version = _to_version_tuple(versions[0])
    if version is None:
        return None
    comparison = _compare_versions(installed, version)
    if _contains_any(clause, _EARLY_KEYWORDS) and not _contains_any(clause, _LATE_KEYWORDS):
        if _contains_any(clause, _INCLUSIVE_KEYWORDS):
            return comparison <= 0
        return comparison < 0
    if _contains_any(clause, _LATE_KEYWORDS) and not _contains_any(clause, _EARLY_KEYWORDS):
        if _contains_any(clause, _INCLUSIVE_KEYWORDS):
            return comparison >= 0
        return comparison > 0
    return None


def _comparator_match(installed: tuple[int, ...], clause: str) -> bool | None:
    match = re.search(rf"\s*(?P<op>>=|<=|>|<|==|=)\s*(?P<version>{_V})\s*$", clause)
    if not match:
        match = re.search(rf"^\s*(?P<version>{_V})\s*(?P<op>>=|<=|>|<|==|=)\s*$", clause)
    if not match:
        return None
    op = match.group("op")
    threshold = _to_version_tuple(match.group("version"))
    if threshold is None:
        return None
    comparison = _compare_versions(installed, threshold)
    if op in {"=", "=="}:
        return comparison == 0
    if op == "<":
        return comparison < 0
    if op == "<=":
        return comparison <= 0
    if op == ">":
        return comparison > 0
    if op == ">=":
        return comparison >= 0
    return None


def _exact_match(installed: tuple[int, ...], clause: str) -> bool | None:
    versions = _extract_versions(clause)
    if not versions:
        return None
    threshold = _to_version_tuple(versions[0])
    if threshold is None:
        return None
    return _compare_versions(installed, threshold) == 0


def matches_version_expression(installed: str, expression: str) -> bool | None:
    installed_version = _to_version_tuple(installed)
    if not installed_version:
        return None
    text = _normalize(expression)
    if not text or text in {"-", "не затронуты", "незатронуто", "not affected"}:
        return None

    saw_false = False
    for clause in _split_expression(text):
        if not clause:
            continue
        for matcher in (_range_match, _directional_match, _comparator_match, _exact_match):
            result = matcher(installed_version, clause)
            if result is True:
                return True
            if result is False:
                saw_false = True
                break
        # continue to next clause; if any clause is matched as true, we return immediately.
    if saw_false:
        return False
    return None
