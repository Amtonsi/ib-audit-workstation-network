import os
import sys
import unittest
from xml.etree import ElementTree

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.safe_xml import fromstring as safe_xml_fromstring  # noqa: E402
from ib_audit.url_safety import validated_https_url  # noqa: E402


class InputSafetyTests(unittest.TestCase):
    def test_safe_xml_accepts_normal_document(self):
        root = safe_xml_fromstring(b"<scan><host>127.0.0.1</host></scan>")

        self.assertEqual("scan", root.tag)
        self.assertEqual("127.0.0.1", root.findtext("host"))

    def test_safe_xml_rejects_dtd_and_entity_declarations(self):
        payload = b'<!DOCTYPE scan [<!ENTITY x "unsafe">]><scan>&x;</scan>'

        with self.assertRaisesRegex(ValueError, "DTD and ENTITY"):
            safe_xml_fromstring(payload)

    def test_safe_xml_rejects_oversized_document(self):
        with self.assertRaisesRegex(ValueError, "safety limit"):
            safe_xml_fromstring(b"<scan/>", max_bytes=4)

    def test_safe_xml_preserves_parse_errors(self):
        with self.assertRaises(ElementTree.ParseError):
            safe_xml_fromstring(b"<scan>")

    def test_https_validation_rejects_non_https_and_credentials(self):
        self.assertEqual(
            "https://example.test/feed.json",
            validated_https_url("https://example.test/feed.json"),
        )
        for value in (
            "http://example.test/feed.json",
            "file:///tmp/feed.json",
            "https://user:secret@example.test/feed.json",
            "",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validated_https_url(value)


if __name__ == "__main__":
    unittest.main()
