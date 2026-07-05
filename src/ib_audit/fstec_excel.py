from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from xml.etree import ElementTree


@dataclass(frozen=True)
class FstecProduct:
    product: str
    version_expression: str = ""
    vendor: str = ""


@dataclass(frozen=True)
class FstecExcelRecord:
    source: str
    code: str
    name: str
    description: str
    severity_text: str
    cvss: float | None
    exploit_status: str
    exploit_available: bool
    references: tuple[str, ...]
    external_ids: str
    remediation: str
    version_info: str
    raw: dict[str, str] = field(default_factory=dict)
    products: tuple[FstecProduct, ...] = ()

    def raw_json(self) -> str:
        return json.dumps(self.raw, ensure_ascii=False, sort_keys=True)


HEADER_ALIASES = {
    "code": (
        "код",
        "идентификатор",
        "номер",
        "bdu",
        "bda",
    ),
    "name": (
        "наименование",
        "название",
        "наименование уязвимости",
    ),
    "description": (
        "описание",
        "описание уязвимости",
    ),
    "vendor": (
        "вендор по",
        "производитель по",
        "вендор",
    ),
    "product": (
        "название по",
        "наименование по",
        "продукт",
    ),
    "severity_text": (
        "уровень опасности уязвимости",
        "уровень опасности",
        "степень опасности",
    ),
    "exploit_status": (
        "наличие эксплойта",
        "эксплойт",
    ),
    "references": (
        "ссылки на источники",
        "ссылки",
        "источники",
    ),
    "external_ids": (
        "идентификаторы др. систем",
        "идентификаторы других систем",
        "cve",
    ),
    "remediation": (
        "возможные меры по устранению уязвимости",
        "способ устранения",
        "информация об устранении",
        "меры по устранению",
    ),
    "version_info": (
        "версия по",
        "уязвимое по",
        "версии по",
        "уязвимые версии",
        "версии",
    ),
}


def read_xlsx_rows(path: str | Path) -> list[list[str]]:
    xlsx_path = Path(path)
    with zipfile.ZipFile(xlsx_path) as archive:
        shared_strings = _read_shared_strings(archive)
        sheet_name = _first_sheet_name(archive)
        sheet_xml = archive.read(sheet_name)
    return _read_sheet_rows(sheet_xml, shared_strings)


def detect_header_row(rows: list[list[str]]) -> tuple[int, dict[str, int]]:
    best_index = -1
    best_mapping: dict[str, int] = {}
    best_score = 0
    for index, row in enumerate(rows[:50]):
        mapping = _header_mapping(row)
        score = len(mapping)
        if "code" in mapping and "name" in mapping:
            score += 2
        if score > best_score:
            best_index = index
            best_mapping = mapping
            best_score = score
    if best_index < 0 or "code" not in best_mapping or "name" not in best_mapping:
        raise ValueError("FSTEC XLSX header row was not found")
    return best_index, best_mapping


def rows_to_fstec_records(path: str | Path, source: str) -> list[FstecExcelRecord]:
    rows = read_xlsx_rows(path)
    header_index, header = detect_header_row(rows)
    headers = rows[header_index]
    records: list[FstecExcelRecord] = []
    for row in rows[header_index + 1 :]:
        raw = {
            headers[index]: value
            for index, value in enumerate(row)
            if index < len(headers) and headers[index] and value
        }
        code = _field(row, header, "code")
        name = _field(row, header, "name")
        if not code and not name:
            continue
        description = _field(row, header, "description")
        severity_text = _field(row, header, "severity_text")
        exploit_status = _field(row, header, "exploit_status")
        references = tuple(_urls(_field(row, header, "references")))
        version_info = _field(row, header, "version_info")
        remediation = _field(row, header, "remediation")
        vendor = _field(row, header, "vendor")
        product = _field(row, header, "product")
        extracted_products = extract_fstec_products(
            version_info,
            allowed_products=product,
        )
        if extracted_products:
            products = [
                FstecProduct(
                    product=item.product,
                    version_expression=item.version_expression,
                    vendor=vendor,
                )
                for item in extracted_products
            ]
        elif product:
            products = _products_from_columns(product, version_info, vendor)
        else:
            products = _fallback_products(name, description)
        records.append(
            FstecExcelRecord(
                source=source,
                code=code,
                name=name,
                description=description,
                severity_text=severity_text,
                cvss=_extract_cvss(severity_text),
                exploit_status=exploit_status,
                exploit_available=_exploit_available(exploit_status),
                references=references,
                external_ids=_field(row, header, "external_ids"),
                remediation=remediation,
                version_info=version_info,
                raw=raw,
                products=tuple(products),
            )
        )
    return records


def extract_fstec_products(
    version_info: str,
    allowed_products: str = "",
) -> list[FstecProduct]:
    text = " ".join(str(version_info or "").split())
    if not text:
        return []
    products: list[FstecProduct] = []
    cursor = 0
    for match in re.finditer(r"\(([^()]+)\)", text):
        product = _clean_product(match.group(1))
        if not product:
            continue
        if allowed_products and not _product_is_allowed(product, allowed_products):
            continue
        prefix = text[cursor : match.start()]
        expression = _version_expression_from_prefix(prefix)
        products.append(FstecProduct(product=product, version_expression=expression))
        cursor = match.end()
    return _dedupe_products(products)


def _read_shared_strings(archive: zipfile.ZipFile) -> list[str]:
    try:
        payload = archive.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    root = ElementTree.fromstring(payload)
    strings: list[str] = []
    for item in _children(root, "si"):
        strings.append("".join(node.text or "" for node in item.iter() if _local(node.tag) == "t"))
    return strings


def _first_sheet_name(archive: zipfile.ZipFile) -> str:
    names = sorted(
        name
        for name in archive.namelist()
        if name.startswith("xl/worksheets/") and name.endswith(".xml")
    )
    if not names:
        raise ValueError("XLSX file does not contain worksheets")
    return names[0]


def _read_sheet_rows(payload: bytes, shared_strings: list[str]) -> list[list[str]]:
    root = ElementTree.fromstring(payload)
    rows: list[list[str]] = []
    for row in root.iter():
        if _local(row.tag) != "row":
            continue
        values: list[str] = []
        next_column = 1
        for cell in row:
            if _local(cell.tag) != "c":
                continue
            ref = str(cell.attrib.get("r") or "")
            column = _column_index(ref) or next_column
            while len(values) < column - 1:
                values.append("")
            values.append(_cell_text(cell, shared_strings))
            next_column = column + 1
        while values and values[-1] == "":
            values.pop()
        rows.append(values)
    return rows


def _cell_text(cell: ElementTree.Element, shared_strings: list[str]) -> str:
    cell_type = cell.attrib.get("t", "")
    if cell_type == "s":
        value = _first_child_text(cell, "v")
        try:
            return shared_strings[int(value)]
        except (IndexError, TypeError, ValueError):
            return ""
    if cell_type == "inlineStr":
        return " ".join(
            node.text or ""
            for node in cell.iter()
            if _local(node.tag) == "t"
        ).strip()
    return _first_child_text(cell, "v").strip()


def _first_child_text(node: ElementTree.Element, local_name: str) -> str:
    for child in node:
        if _local(child.tag) == local_name:
            return child.text or ""
    return ""


def _children(node: ElementTree.Element, local_name: str) -> Iterable[ElementTree.Element]:
    return (child for child in node if _local(child.tag) == local_name)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _column_index(ref: str) -> int:
    letters = "".join(ch for ch in ref if ch.isalpha())
    if not letters:
        return 0
    value = 0
    for char in letters.upper():
        value = value * 26 + (ord(char) - 64)
    return value


def _header_mapping(row: list[str]) -> dict[str, int]:
    mapping: dict[str, int] = {}
    for index, value in enumerate(row):
        normalized = _normalize_header(value)
        for field, aliases in HEADER_ALIASES.items():
            if field not in mapping and any(alias == normalized or alias in normalized for alias in aliases):
                mapping[field] = index
    return mapping


def _normalize_header(value: str) -> str:
    value = str(value or "").replace("\xa0", " ").casefold()
    value = re.sub(r"[^0-9a-zа-яё. ]+", " ", value, flags=re.IGNORECASE)
    return " ".join(value.split())


def _field(row: list[str], header: dict[str, int], field: str) -> str:
    index = header.get(field)
    if index is None or index >= len(row):
        return ""
    return str(row[index] or "").strip()


def _extract_cvss(text: str) -> float | None:
    values = []
    for value in re.findall(r"(?:составляет|score|оценка)\s+(\d+(?:[,.]\d+)?)", text, flags=re.IGNORECASE):
        try:
            values.append(float(value.replace(",", ".")))
        except ValueError:
            continue
    if not values:
        for value in re.findall(r"\b([0-9](?:[,.][0-9])?|10(?:[,.]0)?)\b", text):
            try:
                values.append(float(value.replace(",", ".")))
            except ValueError:
                continue
    return max(values) if values else None


def _exploit_available(text: str) -> bool:
    lowered = str(text or "").casefold()
    if not lowered or "уточ" in lowered or "отсутств" in lowered:
        return False
    return "существ" in lowered or "есть" in lowered or "exploit" in lowered


def _urls(text: str) -> list[str]:
    result: list[str] = []
    for url in re.findall(r"https?://[^\s\"'<>]+", text or ""):
        cleaned = url.rstrip(").,;")
        if cleaned not in result:
            result.append(cleaned)
    return result


def _version_expression_from_prefix(prefix: str) -> str:
    segment = re.split(r";", prefix)[-1]
    segment = segment.strip(" ,;-:\u2013\u2014")
    return segment or "-"


def _clean_product(value: str) -> str:
    value = str(value or "").strip()
    value = value.strip(" «»\"'")
    return " ".join(value.split())


def _product_is_allowed(product: str, allowed_products: str) -> bool:
    normalized_product = _normalize_product_label(product)
    if not normalized_product:
        return False
    allowed = {
        _normalize_product_label(value)
        for value in _split_product_names(allowed_products)
    }
    return normalized_product in allowed


def _normalize_product_label(value: str) -> str:
    value = str(value or "").casefold().replace("ё", "е")
    value = re.sub(r"[^0-9a-zа-я]+", " ", value, flags=re.IGNORECASE)
    return " ".join(value.split())


def _dedupe_products(products: list[FstecProduct]) -> list[FstecProduct]:
    result: list[FstecProduct] = []
    seen: set[tuple[str, str, str]] = set()
    for item in products:
        key = (
            item.vendor.casefold(),
            item.product.casefold(),
            item.version_expression.casefold(),
        )
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _products_from_columns(product: str, version_info: str, vendor: str) -> list[FstecProduct]:
    names = _split_product_names(product)
    expression = str(version_info or "").strip() or "-"
    return _dedupe_products(
        [
            FstecProduct(
                product=name,
                version_expression=expression,
                vendor=str(vendor or "").strip(),
            )
            for name in names
        ]
    )


def _split_product_names(value: str) -> list[str]:
    return [
        _clean_product(item)
        for item in re.split(r"\s*[;,]\s*", str(value or ""))
        if _clean_product(item)
    ]


def _fallback_products(name: str, description: str) -> list[FstecProduct]:
    text = " ".join((name or "", description or ""))
    quoted = [
        FstecProduct(product=_clean_product(match.group(1)))
        for match in re.finditer(r"[«\"]([^»\"]{3,80})[»\"]", text)
    ]
    return _dedupe_products([item for item in quoted if item.product])
