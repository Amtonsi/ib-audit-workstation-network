from __future__ import annotations

import unittest
from pathlib import Path


class UserGuidePdfTests(unittest.TestCase):
    def test_cover_uses_compact_window_mockup(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "scripts" / "build_user_guide_pdf.py").read_text(encoding="utf-8")
        cover_section = source.split("# Page 1 - cover", 1)[1].split(
            "# Page 2 - GitHub and quick start", 1
        )[0]

        self.assertIn("draw_cover_window(", cover_section)
        self.assertNotIn("draw_simple_window(", cover_section)

    def test_usage_page_contains_complete_operator_workflow(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "scripts" / "build_user_guide_pdf.py").read_text(
            encoding="utf-8"
        )
        usage_page = source.split("# Page 4 - usage instructions", 1)[1].split(
            "# Page 5 - logic pipeline", 1
        )[0]

        expected = (
            "Запустить от администратора",
            "Выбрать папку отчётов",
            "Обновить базы",
            "Выбрать режим",
            "Запустить проверку",
            "Следить или отменить",
            "Открыть результат",
            "Перейти к риску",
            "Старые HTML-файлы не изменяются автоматически",
            "audit DB создаётся временно",
            "локальные XLSX ФСТЭК",
        )
        for text in expected:
            self.assertIn(text, usage_page)

    def test_vulnerability_page_explains_cpe_matching_and_hardware_risks(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "scripts" / "build_user_guide_pdf.py").read_text(
            encoding="utf-8"
        )
        vulnerability_page = source.split("# Page 6 - vulnerability sources", 1)[1].split(
            "# Page 7 - batch HTML and cancellation", 1
        )[0]

        expected = (
            "CPE, версии и аппаратные риски",
            "производитель, название, модель и версия",
            "псевдонимы и ребрендинг",
            "Acronis Backup",
            "Acronis Cyber Backup",
            "несколько подходящих CPE-кандидатов",
            "Критические находки отображаются только",
            "Подтверждено",
            "Потенциальный риск",
            "firmware/microcode",
            "--with-cpe-match",
            "vullist.xlsx",
            "АСУ ТП",
        )
        for text in expected:
            self.assertIn(text, vulnerability_page)
        self.assertNotIn("DeltaV", vulnerability_page)
        self.assertNotIn("12.03.0001", vulnerability_page)


if __name__ == "__main__":
    unittest.main()
