from __future__ import annotations

import html
import hashlib
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

from .category_catalog import category_for_name, category_id_for_name
from .models import CollectorDiagnostic, InventoryObject, SourceDocument


MAX_REPORT_BYTES = 100 * 1024 * 1024


class ReportImportError(ValueError):
    pass


@dataclass
class ImportedAuditReport:
    report_format: str
    hostname: str
    inventory: list[InventoryObject]
    document: SourceDocument
    diagnostics: list[CollectorDiagnostic] = field(default_factory=list)


def _clean_text(parts: list[str]) -> str:
    return " ".join("".join(parts).replace("\xa0", " ").split())


def _strip_number(text: str) -> str:
    return re.sub(r"^\s*\d+\)\s*", "", text).strip()


def _safe_hostname(value: str) -> str:
    cleaned = re.sub(r'[<>:"/\\|?*]+', "_", value).strip(" .")
    return cleaned or "imported-host"


def _rows_to_fields(rows: list[list[str]]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for row in rows:
        if len(row) < 2:
            continue
        key, value = row[0].strip(), row[1].strip()
        if not key or (key.lower() == "item" and value.lower() == "value"):
            continue
        fields[key] = value
    return fields


class _TableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.table_depth = 0
        self.current_row: list[str] | None = None
        self.current_cell: list[str] | None = None
        self.current_rows: list[list[str]] = []

    def _start_table_element(self, tag: str) -> None:
        if tag == "table":
            if self.table_depth == 0:
                self.current_rows = []
            self.table_depth += 1
        elif tag == "tr" and self.table_depth == 1:
            self.current_row = []
        elif tag in {"td", "th"} and self.table_depth == 1 and self.current_row is not None:
            self.current_cell = []

    def _end_table_element(self, tag: str) -> bool:
        if tag in {"td", "th"} and self.current_cell is not None and self.current_row is not None:
            self.current_row.append(_clean_text(self.current_cell))
            self.current_cell = None
        elif tag == "tr" and self.current_row is not None:
            if any(self.current_row):
                self.current_rows.append(self.current_row)
            self.current_row = None
        elif tag == "table" and self.table_depth:
            self.table_depth -= 1
            return self.table_depth == 0
        return False

    def handle_data(self, data: str) -> None:
        if self.current_cell is not None:
            self.current_cell.append(data)


class _IbAuditHtmlParser(_TableParser):
    def __init__(self) -> None:
        super().__init__()
        self.title_parts: list[str] | None = None
        self.heading_parts: list[str] | None = None
        self.card_title_parts: list[str] | None = None
        self.document_title = ""
        self.current_category = ""
        self.current_card_title = ""
        self.card_depth = 0
        self.inventory: list[InventoryObject] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key: value or "" for key, value in attrs}
        if tag == "title":
            self.title_parts = []
        elif tag == "h2":
            self.heading_parts = []
        elif tag == "div":
            classes = set(attributes.get("class", "").split())
            if self.card_depth:
                self.card_depth += 1
            elif "card" in classes:
                self.card_depth = 1
                self.current_card_title = ""
        elif tag == "h3" and self.card_depth:
            self.card_title_parts = []
        self._start_table_element(tag)

    def handle_endtag(self, tag: str) -> None:
        table_finished = self._end_table_element(tag)
        if table_finished and self.card_depth:
            self._append_card(_rows_to_fields(self.current_rows))
        if tag == "title" and self.title_parts is not None:
            self.document_title = _clean_text(self.title_parts)
            self.title_parts = None
        elif tag == "h2" and self.heading_parts is not None:
            self.current_category = _clean_text(self.heading_parts)
            self.heading_parts = None
        elif tag == "h3" and self.card_title_parts is not None:
            self.current_card_title = _clean_text(self.card_title_parts)
            self.card_title_parts = None
        elif tag == "div" and self.card_depth:
            self.card_depth -= 1

    def handle_data(self, data: str) -> None:
        super().handle_data(data)
        if self.title_parts is not None:
            self.title_parts.append(data)
        if self.heading_parts is not None:
            self.heading_parts.append(data)
        if self.card_title_parts is not None:
            self.card_title_parts.append(data)

    def _append_card(self, fields: dict[str, str]) -> None:
        category = category_for_name(self.current_category)
        title = self.current_card_title or fields.get("Name") or fields.get("Caption")
        if not title:
            title = category.name
        self.inventory.append(
            InventoryObject(
                category_id=category_id_for_name(category.name),
                category_name=category.name,
                object_type=category.object_type,
                title=title,
                fields=fields,
                source="Imported IB Audit HTML",
                confidence="high",
                raw=fields.copy(),
                source_section=self.current_category,
                source_position=len(self.inventory),
            )
        )


@dataclass
class _WinAuditTable:
    group: str
    object_title: str
    rows: list[list[str]]


class _WinAuditHtmlParser(_TableParser):
    def __init__(self) -> None:
        super().__init__()
        self.title_parts: list[str] | None = None
        self.bold_parts: list[str] | None = None
        self.bold_in_center = False
        self.center_depth = 0
        self.document_title = ""
        self.current_group = ""
        self.current_object_title = ""
        self.hostname = ""
        self.tables: list[_WinAuditTable] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "title":
            self.title_parts = []
        elif tag == "center":
            self.center_depth += 1
        elif tag == "b" and self.table_depth == 0:
            self.bold_parts = []
            self.bold_in_center = self.center_depth > 0
        self._start_table_element(tag)

    def handle_endtag(self, tag: str) -> None:
        table_finished = self._end_table_element(tag)
        if table_finished:
            self.tables.append(
                _WinAuditTable(
                    group=self.current_group,
                    object_title=self.current_object_title,
                    rows=[row[:] for row in self.current_rows],
                )
            )
            self.current_object_title = ""
        if tag == "title" and self.title_parts is not None:
            self.document_title = _clean_text(self.title_parts)
            self.title_parts = None
        elif tag == "b" and self.bold_parts is not None:
            text = _clean_text(self.bold_parts)
            if self.bold_in_center:
                host_match = re.match(r"Computer Audit for\s+(.+)", text, flags=re.IGNORECASE)
                if host_match:
                    self.hostname = host_match.group(1).strip()
                elif text.lower() != "no data available":
                    self.current_group = _strip_number(text)
            else:
                self.current_object_title = _strip_number(text)
            self.bold_parts = None
        elif tag == "center" and self.center_depth:
            self.center_depth -= 1

    def handle_data(self, data: str) -> None:
        super().handle_data(data)
        if self.title_parts is not None:
            self.title_parts.append(data)
        if self.bold_parts is not None:
            self.bold_parts.append(data)

    def inventory(self) -> list[InventoryObject]:
        objects: list[InventoryObject] = []
        for position, table in enumerate(self.tables):
            category = category_for_name(table.group)
            fields = _rows_to_fields(table.rows)
            if not fields:
                fields = {"Rows": table.rows}
            object_type = category.object_type
            if category.name == "System Overview" and (
                fields.get("Operating System") or fields.get("Операционная система")
            ):
                object_type = "operating_system"
            elif category.name == "Services and Drivers":
                service_text = " ".join([table.object_title, *map(str, fields.values())]).casefold()
                object_type = "driver" if "driver" in service_text or "драйвер" in service_text else "service"
            title = (
                fields.get("Name") or fields.get("Caption") or
                fields.get("Operating System") or fields.get("Операционная система") or
                table.object_title or category.name
            )
            objects.append(
                InventoryObject(
                    category_id_for_name(category.name),
                    category.name,
                    object_type,
                    str(title),
                    fields,
                    "Imported WinAudit HTML",
                    raw=fields.copy(),
                    source_section=table.group,
                    source_position=position,
                )
            )
        return objects


def _decode_html(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    for encoding in ("utf-8-sig", "cp1251", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _document_title(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return " ".join(html.unescape(re.sub(r"<[^>]+>", "", match.group(1))).split())


def import_audit_report(path: str | Path) -> ImportedAuditReport:
    report_path = Path(path)
    if report_path.suffix.lower() not in {".html", ".htm"}:
        raise ReportImportError("Unsupported report file type. Select an HTML report.")
    try:
        size = report_path.stat().st_size
    except OSError as exc:
        raise ReportImportError(f"Cannot read report: {exc}") from exc
    if size == 0:
        raise ReportImportError("The report is empty.")
    if size > MAX_REPORT_BYTES:
        raise ReportImportError("The report is larger than the 100 MiB safety limit.")

    try:
        data = report_path.read_bytes()
        text = _decode_html(data)
    except OSError as exc:
        raise ReportImportError(f"Cannot read report: {exc}") from exc
    title = _document_title(text)

    if title.casefold() == "winaudit computer audit":
        parser = _WinAuditHtmlParser()
        parser.feed(text)
        inventory = parser.inventory()
        report_format = "winaudit-html"
        hostname = parser.hostname or report_path.stem
    elif title.casefold().startswith(("иб-аудит ", "ib audit ")):
        parser = _IbAuditHtmlParser()
        parser.feed(text)
        inventory = parser.inventory
        report_format = "ib-audit-html"
        hostname = re.sub(r"^(?:ИБ-аудит|IB Audit)\s+", "", parser.document_title, flags=re.IGNORECASE).strip()
        hostname = hostname or report_path.stem
    else:
        raise ReportImportError("Unsupported HTML report format.")

    if not inventory:
        raise ReportImportError("The report contains no inventory objects.")

    source = str(report_path.resolve())
    document = SourceDocument.create(report_format, title, source, len(data), hashlib.sha256(data).hexdigest())
    for item in inventory:
        item.source_document_id = document.id
    diagnostics = [
        CollectorDiagnostic(
            module="report_import",
            severity="info",
            message=f"Imported {len(inventory)} inventory objects from every parsed section of {report_format}.",
            source=source,
        )
    ]
    return ImportedAuditReport(
        report_format=report_format,
        hostname=_safe_hostname(hostname),
        inventory=inventory,
        document=document,
        diagnostics=diagnostics,
    )
