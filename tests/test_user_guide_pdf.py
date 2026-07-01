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


if __name__ == "__main__":
    unittest.main()
