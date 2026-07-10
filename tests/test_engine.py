import os
import sys
import unittest

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.engine import _execute_collector


class AuditEngineProgressTests(unittest.TestCase):
    def test_execute_collector_passes_progress_to_optional_progress_argument(self):
        events: list[str] = []

        def collector(progress=None):
            if progress:
                progress("PACKET_ROW|info|{}")
            return [], []

        objects, diagnostics = _execute_collector(collector, events.append)

        self.assertEqual([], objects)
        self.assertEqual([], diagnostics)
        self.assertEqual(["PACKET_ROW|info|{}"], events)


if __name__ == "__main__":
    unittest.main()
