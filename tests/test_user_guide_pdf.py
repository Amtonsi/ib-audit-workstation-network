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
        vulnerability_page = source.split("# Page 7 - vulnerability sources", 1)[1].split(
            "# Page 8 - batch HTML and cancellation", 1
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

    def test_vulnerability_page_documents_source_selection_and_online_budget(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "scripts" / "build_user_guide_pdf.py").read_text(encoding="utf-8")
        vulnerability_page = source.split("# Page 7 - vulnerability sources", 1)[1].split(
            "# Page 8 - batch HTML and cancellation", 1
        )[0]

        for text in (
            "Авто и Только локальная база",
            "Только онлайн",
            "vulnerability_sources.db",
            "запрещает HTTP/curl",
            "До 6 запросов NVD",
            "1 запроса ФСТЭК",
            "тайм-ауты 10/6 секунд",
        ):
            self.assertIn(text, vulnerability_page)

    def test_network_page_documents_local_profile_and_process_cleanup(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "scripts" / "build_user_guide_pdf.py").read_text(
            encoding="utf-8"
        )
        network_page = source.split("# Page 6 - network audit", 1)[1].split(
            "# Page 7 - vulnerability sources", 1
        )[0]

        expected = (
            "127.0.0.1",
            "22, 80, 135, 139, 443, 445, 3389, 5985, 5986, 8080, 8443",
            "Режим T3",
            "тайм-аут 120 секунд",
            "Загрузить интерфейсы",
            "Зелёная маркировка",
            "tshark",
            "hex-байты",
            "Nmap, tshark и dumpcap",
            "--network-scan --offline --no-open",
        )
        for text in expected:
            self.assertIn(text, network_page)

    def test_guide_links_to_network_edition_repository(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "scripts" / "build_user_guide_pdf.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("https://github.com/Amtonsi/ib-audit-workstation-network", source)

    def test_build_page_documents_bundled_tools_and_current_spec_command(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "scripts" / "build_user_guide_pdf.py").read_text(
            encoding="utf-8"
        )
        build_page = source.split("# Page 10 - commands and build", 1)[1]

        self.assertIn("tools\\\\nmap", build_page)
        self.assertIn("tools\\\\wireshark", build_page)
        self.assertNotIn("tools\\\\npcap", build_page)
        self.assertIn("Драйвер Npcap не распространяется внутри EXE", build_page)
        self.assertNotIn("IBuditWorkstation.spec", build_page)
        self.assertNotIn("--onefile", build_page)


if __name__ == "__main__":
    unittest.main()
