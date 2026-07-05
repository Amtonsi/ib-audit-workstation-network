import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.fstec_excel import (
    detect_header_row,
    extract_fstec_products,
    read_xlsx_rows,
    rows_to_fstec_records,
)


class FstecExcelTests(unittest.TestCase):
    def test_reads_asutp_xlsx_and_detects_header_row(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "asutp.xlsx"
            self._write_xlsx(
                path,
                [
                    ["Параметры в фильтре отсутствуют"],
                    [],
                    [
                        "Код",
                        "Наименование",
                        "Описание",
                        "Уровень опасности уязвимости",
                        "Наличие эксплойта",
                        "Ссылки на источники",
                        "Идентификаторы др. систем",
                        "Версия ПО",
                    ],
                    [
                        "BDA:2026-157",
                        "Уязвимость PowerChute Serial Shutdown",
                        "Описание",
                        "Средний уровень опасности (базовая оценка CVSS 3.0 составляет 5,3)",
                        "Существует в открытом доступе",
                        "https://vendor.example/advisory",
                        "CVE-2026-0001; БДУ ФСТЭК России",
                        "до 1.5 (PowerChute Serial Shutdown)",
                    ],
                ],
            )

            rows = read_xlsx_rows(path)
            header_index, header = detect_header_row(rows)
            records = rows_to_fstec_records(path, source="fstec-asutp")

        self.assertEqual(2, header_index)
        self.assertEqual(0, header["code"])
        self.assertEqual(7, header["version_info"])
        self.assertEqual(1, len(records))
        self.assertEqual("BDA:2026-157", records[0].code)
        self.assertEqual("fstec-asutp", records[0].source)
        self.assertEqual("PowerChute Serial Shutdown", records[0].products[0].product)
        self.assertEqual("до 1.5", records[0].products[0].version_expression)
        self.assertEqual(5.3, records[0].cvss)
        self.assertTrue(records[0].exploit_available)

    def test_extracts_multiple_products_from_asutp_version_field(self):
        products = extract_fstec_products(
            "- («БУК TS-G»); 4.13.25-0 (программный модуль bukmmadm)"
        )

        self.assertEqual(
            [
                ("БУК TS-G", "-"),
                ("программный модуль bukmmadm", "4.13.25-0"),
            ],
            [(item.product, item.version_expression) for item in products],
        )

    def test_extracts_repeated_product_versions_without_accumulating_prefixes(self):
        products = extract_fstec_products(
            "1.02b11 (DSR-500), 1.02b25 (DSR-500), 1.02b12 (DSR-500)"
        )

        self.assertEqual(
            [
                ("DSR-500", "1.02b11"),
                ("DSR-500", "1.02b25"),
                ("DSR-500", "1.02b12"),
            ],
            [(item.product, item.version_expression) for item in products],
        )

    def test_official_product_filter_ignores_parentheses_inside_version(self):
        products = extract_fstec_products(
            "15.2(4)E (Cisco IOS), 3.10.8s (Cisco IOS XE)",
            allowed_products="Cisco IOS, Cisco IOS XE",
        )

        self.assertEqual(
            [
                ("Cisco IOS", "15.2(4)E"),
                ("Cisco IOS XE", "3.10.8s"),
            ],
            [(item.product, item.version_expression) for item in products],
        )

    def test_official_product_filter_rejects_short_substring_false_product(self):
        products = extract_fstec_products(
            "1.0 (1), 1.0 (Cisco IOS)",
            allowed_products="Cisco IOS, Cisco IOS XE",
        )

        self.assertEqual(
            [("Cisco IOS", "1.0 (1), 1.0")],
            [(item.product, item.version_expression) for item in products],
        )

    def test_reads_official_bdu_product_and_vendor_columns(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "vullist.xlsx"
            self._write_xlsx(
                path,
                [
                    [],
                    [],
                    [
                        "Идентификатор",
                        "Наименование уязвимости",
                        "Описание уязвимости",
                        "Вендор ПО",
                        "Название ПО",
                        "Версия ПО",
                        "Уровень опасности уязвимости",
                    ],
                    [
                        "BDU:2014-00002",
                        "Уязвимость маршрутизатора",
                        "Описание",
                        "D-Link Corp.",
                        "DSR-500",
                        "1.02b11 (DSR-500), 1.02b25 (DSR-500)",
                        "Высокий уровень опасности",
                    ],
                ],
            )

            records = rows_to_fstec_records(path, source="fstec-bdu")

        self.assertEqual(1, len(records))
        self.assertEqual(
            [
                ("D-Link Corp.", "DSR-500", "1.02b11"),
                ("D-Link Corp.", "DSR-500", "1.02b25"),
            ],
            [
                (item.vendor, item.product, item.version_expression)
                for item in records[0].products
            ],
        )

    def test_reads_real_russian_bdu_headers(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "vullist.xlsx"
            self._write_xlsx(
                path,
                [
                    [],
                    [
                        "\u0418\u0434\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u043e\u0440",
                        "\u041d\u0430\u0438\u043c\u0435\u043d\u043e\u0432\u0430\u043d\u0438\u0435 \u0443\u044f\u0437\u0432\u0438\u043c\u043e\u0441\u0442\u0438",
                        "\u041e\u043f\u0438\u0441\u0430\u043d\u0438\u0435 \u0443\u044f\u0437\u0432\u0438\u043c\u043e\u0441\u0442\u0438",
                        "\u0412\u0435\u043d\u0434\u043e\u0440 \u041f\u041e",
                        "\u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435 \u041f\u041e",
                        "\u0412\u0435\u0440\u0441\u0438\u044f \u041f\u041e",
                        "\u0423\u0440\u043e\u0432\u0435\u043d\u044c \u043e\u043f\u0430\u0441\u043d\u043e\u0441\u0442\u0438 \u0443\u044f\u0437\u0432\u0438\u043c\u043e\u0441\u0442\u0438",
                        "\u041d\u0430\u043b\u0438\u0447\u0438\u0435 \u044d\u043a\u0441\u043f\u043b\u043e\u0439\u0442\u0430",
                        "\u0421\u0441\u044b\u043b\u043a\u0438 \u043d\u0430 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0438",
                        "\u0418\u0434\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u043e\u0440\u044b \u0434\u0440. \u0441\u0438\u0441\u0442\u0435\u043c",
                    ],
                    [
                        "BDU:2026-00001",
                        "\u0423\u044f\u0437\u0432\u0438\u043c\u043e\u0441\u0442\u044c Acronis Backup",
                        "\u041e\u043f\u0438\u0441\u0430\u043d\u0438\u0435",
                        "Acronis",
                        "Acronis Backup",
                        "\u0434\u043e 11.7.50059 (Acronis Backup)",
                        "\u041a\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043a\u0438\u0439 \u0443\u0440\u043e\u0432\u0435\u043d\u044c \u043e\u043f\u0430\u0441\u043d\u043e\u0441\u0442\u0438",
                        "\u0421\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u0435\u0442 \u0432 \u043e\u0442\u043a\u0440\u044b\u0442\u043e\u043c \u0434\u043e\u0441\u0442\u0443\u043f\u0435",
                        "https://vendor.example/acronis",
                        "CVE-2026-0002",
                    ],
                ],
            )

            records = rows_to_fstec_records(path, source="fstec-bdu")

        self.assertEqual(1, len(records))
        self.assertEqual("BDU:2026-00001", records[0].code)
        self.assertEqual("Acronis", records[0].products[0].vendor)
        self.assertEqual("Acronis Backup", records[0].products[0].product)
        self.assertEqual("\u0434\u043e 11.7.50059", records[0].products[0].version_expression)
        self.assertTrue(records[0].exploit_available)

    @staticmethod
    def _write_xlsx(path: Path, rows: list[list[str]]) -> None:
        shared: list[str] = []
        shared_index: dict[str, int] = {}

        def sid(value: str) -> int:
            if value not in shared_index:
                shared_index[value] = len(shared)
                shared.append(value)
            return shared_index[value]

        sheet_rows = []
        for row_index, row in enumerate(rows, 1):
            cells = []
            for col_index, value in enumerate(row, 1):
                if value == "":
                    continue
                cell_ref = f"{chr(64 + col_index)}{row_index}"
                cells.append(
                    f'<c r="{cell_ref}" t="s"><v>{sid(str(value))}</v></c>'
                )
            sheet_rows.append(f'<row r="{row_index}">{"".join(cells)}</row>')
        shared_xml = "".join(
            f"<si><t>{escape(value)}</t></si>" for value in shared
        )
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "[Content_Types].xml",
                """<?xml version="1.0" encoding="UTF-8"?>
                <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
                  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
                  <Default Extension="xml" ContentType="application/xml"/>
                  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
                  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
                  <Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
                </Types>""",
            )
            archive.writestr(
                "_rels/.rels",
                """<?xml version="1.0" encoding="UTF-8"?>
                <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
                </Relationships>""",
            )
            archive.writestr(
                "xl/workbook.xml",
                """<?xml version="1.0" encoding="UTF-8"?>
                <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
                  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
                  <sheets><sheet name="Worksheet" sheetId="1" r:id="rId1"/></sheets>
                </workbook>""",
            )
            archive.writestr(
                "xl/_rels/workbook.xml.rels",
                """<?xml version="1.0" encoding="UTF-8"?>
                <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
                  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
                </Relationships>""",
            )
            archive.writestr(
                "xl/sharedStrings.xml",
                f"""<?xml version="1.0" encoding="UTF-8"?>
                <sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
                  count="{len(shared)}" uniqueCount="{len(shared)}">{shared_xml}</sst>""",
            )
            archive.writestr(
                "xl/worksheets/sheet1.xml",
                f"""<?xml version="1.0" encoding="UTF-8"?>
                <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
                  <sheetData>{''.join(sheet_rows)}</sheetData>
                </worksheet>""",
            )


if __name__ == "__main__":
    unittest.main()
