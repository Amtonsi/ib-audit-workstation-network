import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath("scripts"))

from legal_pdf_pages import INTERNATIONAL_LAWS, RUSSIAN_LAWS  # noqa: E402


class LegalPdfPagesTests(unittest.TestCase):
    def test_legal_appendix_covers_readme_laws(self):
        russian_titles = {item[0] for item in RUSSIAN_LAWS}
        international_titles = {item[0] for item in INTERNATIONAL_LAWS}

        self.assertEqual(6, len(RUSSIAN_LAWS))
        self.assertIn("УК РФ, статья 272", russian_titles)
        self.assertIn("УК РФ, статья 274.1", russian_titles)
        self.assertIn("149-ФЗ, статья 16", russian_titles)
        self.assertIn("152-ФЗ, статья 19", russian_titles)
        self.assertEqual(4, len(INTERNATIONAL_LAWS))
        self.assertIn("Директива ЕС 2013/40/EU", international_titles)
        self.assertIn("США: 18 U.S.C. § 1030", international_titles)

    def test_every_legal_reference_uses_https(self):
        for _title, _body, url in RUSSIAN_LAWS + INTERNATIONAL_LAWS:
            with self.subTest(url=url):
                self.assertTrue(url.startswith("https://"))

    def test_readme_references_legal_diagram(self):
        readme = Path("README.md").read_text(encoding="utf-8")

        self.assertIn("docs/images/legal-boundary.svg", readme)
        self.assertIn("Встроенные ограничения безопасности ПО", readme)


if __name__ == "__main__":
    unittest.main()
