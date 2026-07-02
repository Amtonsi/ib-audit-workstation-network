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
        )
        for text in expected:
            self.assertIn(text, usage_page)


if __name__ == "__main__":
    unittest.main()
