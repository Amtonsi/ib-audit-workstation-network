import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.source_cache import SnapshotCache


class SnapshotCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cache = SnapshotCache(Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def test_round_trips_json_and_records_hash(self):
        snapshot = self.cache.store_json("cisa-kev", "catalog", {"vulnerabilities": [{"cveID": "CVE-1"}]})
        payload, loaded = self.cache.load_json("cisa-kev", "catalog")
        self.assertEqual("CVE-1", payload["vulnerabilities"][0]["cveID"])
        self.assertEqual(snapshot.sha256, loaded.sha256)

    def test_corrupt_new_payload_does_not_replace_last_good_snapshot(self):
        good = self.cache.store_json("nvd", "tool-1", {"vulnerabilities": []})
        with self.assertRaises(ValueError):
            self.cache.store_bytes("nvd", "tool-1", b"{not-json", content_type="json")
        _payload, active = self.cache.load_json("nvd", "tool-1")
        self.assertEqual(good.sha256, active.sha256)

    def test_offline_fetch_uses_last_good_snapshot(self):
        self.cache.store_json("cisa-kev", "catalog", {"vulnerabilities": []})
        payload, _snapshot, state = self.cache.get_or_fetch_json(
            "cisa-kev", "catalog", online=False,
            fetcher=lambda: (_ for _ in ()).throw(AssertionError()),
        )
        self.assertEqual([], payload["vulnerabilities"])
        self.assertEqual("cached", state)

    def test_round_trips_text_and_records_hash(self):
        snapshot = self.cache.store_text("fstec-bdu-html", "search-example", "<html>ok</html>")

        payload, loaded = self.cache.load_text("fstec-bdu-html", "search-example")

        self.assertEqual("<html>ok</html>", payload)
        self.assertEqual(snapshot.sha256, loaded.sha256)
        self.assertEqual("text", loaded.metadata["content_type"])

    def test_text_fetch_falls_back_to_last_good_snapshot_after_online_error(self):
        self.cache.store_text("fstec-bdu-html", "detail-example", "<html>cached</html>")

        payload, _snapshot, state = self.cache.get_or_fetch_text(
            "fstec-bdu-html",
            "detail-example",
            online=True,
            fetcher=lambda: (_ for _ in ()).throw(OSError("network unavailable")),
        )

        self.assertEqual("<html>cached</html>", payload)
        self.assertEqual("cached-after-error", state)
