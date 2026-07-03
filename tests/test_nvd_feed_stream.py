import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.cancellation import AuditCancelled, CancellationToken
from ib_audit.nvd_feed_stream import iter_nvd_feed_items


class NvdFeedStreamTests(unittest.TestCase):
    def test_iterates_items_from_tar_gz_json_array(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "nvdcpe-2.0.tar.gz"
            self._write_tar_json(
                path,
                {
                    "products": [
                        {"cpe": {"cpeNameId": "A"}},
                        {"cpe": {"cpeNameId": "B"}},
                    ]
                },
            )

            items = list(iter_nvd_feed_items(path, "products"))

        self.assertEqual(["A", "B"], [item["cpe"]["cpeNameId"] for item in items])

    def test_iteration_checks_cancellation_before_next_item(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "nvdcpematch-2.0.tar.gz"
            self._write_tar_json(
                path,
                {
                    "matchStrings": [
                        {"matchString": {"matchCriteriaId": "MATCH-1"}},
                        {"matchString": {"matchCriteriaId": "MATCH-2"}},
                    ]
                },
            )
            token = CancellationToken()
            iterator = iter_nvd_feed_items(path, "matchStrings", token)

            first = next(iterator)
            token.cancel()

            with self.assertRaises(AuditCancelled):
                next(iterator)

        self.assertEqual("MATCH-1", first["matchString"]["matchCriteriaId"])

    @staticmethod
    def _write_tar_json(path: Path, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo("feed.json")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
