import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.cancellation import AuditCancelled, CancellationToken
from ib_audit.engine import AuditEngine
from ib_audit.models import AuditRun


class CancellationTokenTests(unittest.TestCase):
    def test_new_token_is_active_and_cancel_is_idempotent(self):
        token = CancellationToken()

        self.assertFalse(token.is_cancelled())
        self.assertTrue(token.cancel())
        self.assertTrue(token.is_cancelled())
        self.assertFalse(token.cancel())

    def test_raise_if_cancelled_uses_dedicated_exception(self):
        token = CancellationToken()
        token.cancel()

        with self.assertRaisesRegex(AuditCancelled, "cancelled"):
            token.raise_if_cancelled()


class AuditEngineCancellationTests(unittest.TestCase):
    @patch("ib_audit.engine.get_collectors")
    @patch("ib_audit.engine.is_admin", return_value=True)
    def test_engine_stops_before_next_collector(self, _is_admin, get_collectors):
        token = CancellationToken()
        first = Mock()
        first.name = "first"
        first.category_name = "System"
        first.func.side_effect = lambda: (token.cancel(), ([], []))[1]
        second = Mock()
        second.name = "second"
        second.category_name = "System"
        repository = Mock()
        get_collectors.return_value = [first, second]

        with self.assertRaises(AuditCancelled):
            AuditEngine(repository, cancel_token=token).run()

        first.func.assert_called_once()
        second.func.assert_not_called()
        cancelled_run = repository.save_run.call_args_list[-1].args[0]
        self.assertEqual("cancelled", cancelled_run.status)


class RunAuditCancellationTests(unittest.TestCase):
    @patch("ib_audit.app.AssessmentService")
    @patch("ib_audit.app.AuditEngine")
    @patch("ib_audit.app.SQLiteRepository")
    def test_run_audit_marks_run_cancelled_when_assessment_stops(
        self, repository_class, engine_class, service_class
    ):
        from ib_audit.app import run_audit

        token = CancellationToken()
        run = AuditRun.create("TEST-PC", True)
        engine_class.return_value.run.return_value = (run, [], [])
        service_class.return_value.assess.side_effect = AuditCancelled("cancelled")

        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(AuditCancelled):
                run_audit(
                    output_dir=Path(temp),
                    online_sources=False,
                    cancel_token=token,
                )

        saved_run = repository_class.return_value.save_run.call_args_list[-1].args[0]
        self.assertEqual("cancelled", saved_run.status)
        self.assertIsNotNone(saved_run.finished_at)


if __name__ == "__main__":
    unittest.main()
