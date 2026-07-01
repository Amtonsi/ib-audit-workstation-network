import os
import queue
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.gui_tk import (
    AuditWindow, SOURCE_LABELS, format_result_message, format_source_status,
    presentation_for, progress_value_for_message,
)
from ib_audit.batch import BatchProgress
from ib_audit.cancellation import CancellationToken
from ib_audit.models import SourceSnapshot


class FakeVar:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class FakeWidget:
    def __init__(self, parent=None, kind="Widget", **options):
        self.parent = parent
        self.kind = kind
        self.options = {}
        self.pack_options = {}
        self.children = []
        self.started = False
        if parent is not None and hasattr(parent, "children"):
            parent.children.append(self)
        self.options.update(options)

    def configure(self, **options):
        self.options.update(options)

    def pack(self, **options):
        self.pack_options = options

    def pack_propagate(self, flag):
        self.options["pack_propagate"] = flag

    def __setitem__(self, key, value):
        self.options[key] = value

    def __getitem__(self, key):
        return self.options[key]

    def start(self, interval=None):
        self.started = True

    def stop(self):
        self.started = False


class AuditWindowReportImportTests(unittest.TestCase):
    def test_result_message_includes_risk_coverage_and_insufficient(self):
        message = format_result_message({
            "inventory_count": 200, "diagnostic_count": 4, "risk_count": 18,
            "coverage_percent": 100, "rule_checked_percent": 94, "insufficient_count": 27,
        })
        self.assertIn("рисков=18", message)
        self.assertIn("обработано=100%", message)
        self.assertIn("проверено правилами=94%", message)
        self.assertIn("недостаточно данных=27", message)

    def test_source_status_text_includes_snapshot_date(self):
        text = format_source_status([
            SourceSnapshot("1", "CISA KEV", "catalog", "cache/a", "a" * 64, "2026-06-29T00:00:00+00:00", "active")
        ])
        self.assertIn("CISA KEV", text)
        self.assertIn("29.06.2026", text)

    def test_progress_value_for_message_maps_audit_steps(self):
        self.assertEqual(5, progress_value_for_message("Audit started for PC", 0))
        self.assertEqual(20, progress_value_for_message("Running collector: system_hardware", 5))
        self.assertEqual(85, progress_value_for_message("Assessing vulnerabilities, configuration, and exposure", 70))
        self.assertEqual(100, progress_value_for_message("Готово: объектов=10", 85))

    def test_fstec_progress_uses_real_query_ratio(self):
        self.assertEqual(85, progress_value_for_message("ФСТЭК БДУ: онлайн-поиск 0/100: windows", 85))
        self.assertEqual(90, progress_value_for_message("ФСТЭК БДУ: онлайн-поиск 50/100: windows", 85))
        self.assertEqual(95, progress_value_for_message("ФСТЭК БДУ: онлайн-поиск 100/100: windows", 85))
        self.assertEqual(92, progress_value_for_message("ФСТЭК БДУ: онлайн-поиск 50/100: windows", 92))
        self.assertEqual(85, progress_value_for_message("ФСТЭК БДУ: онлайн-поиск 50/0: windows", 85))

    def test_drain_messages_updates_determinate_progress(self):
        window = self._window()
        window.root = FakeWidget()
        window.root.after = Mock()
        window.messages.put("Audit started for PC")
        window.messages.put("Running collector: system_hardware")
        window.messages.put("__STATUS__:Аудит завершён")

        window._drain_messages()

        self.assertEqual(100, window.progress.options["value"])
        self.assertFalse(window.progress.started)

    def test_batch_progress_updates_document_status_and_percentage(self):
        window = self._window()
        window.root = FakeWidget()
        window.root.after = Mock()
        window.messages.put(
            BatchProgress(2, 4, "completed", Path("C:/reports/pc-02.html"), "PC-02")
        )

        window._drain_messages()

        self.assertEqual(50, window.progress.options["value"])
        self.assertIn("Документ 2 из 4", window.progress_status.get())
        self.assertIn("PC-02", window.progress_status.get())

    def test_progress_bar_is_inside_journal_above_log(self):
        root = FakeWidget(kind="Root")
        window = AuditWindow.__new__(AuditWindow)
        window.root = root
        window.output_dir = FakeVar("C:/outputs")
        window.source_status = FakeVar("кэш источников: проверяется при аудите")
        window.progress_status = FakeVar("Прогресс: ожидание")
        window.vulnerability_mode = FakeVar("full")
        window.status = FakeVar()
        window.action_buttons = []
        window.active_cancel_token = None
        window._log = Mock()

        def widget_factory(kind):
            return lambda parent=None, **options: FakeWidget(parent=parent, kind=kind, **options)

        with patch("ib_audit.gui_tk.ttk.Frame", widget_factory("Frame")), \
                patch("ib_audit.gui_tk.ttk.Label", widget_factory("Label")), \
                patch("ib_audit.gui_tk.ttk.Button", widget_factory("Button")), \
                patch("ib_audit.gui_tk.ttk.Radiobutton", widget_factory("Radiobutton")), \
                patch("ib_audit.gui_tk.ttk.Separator", widget_factory("Separator")), \
                patch("ib_audit.gui_tk.ttk.Progressbar", widget_factory("Progressbar")), \
                patch("ib_audit.gui_tk.scrolledtext.ScrolledText", widget_factory("ScrolledText")):
            window._build()

        self.assertIs(window.progress.parent, window.log.parent)
        journal_children = window.log.parent.children
        self.assertLess(journal_children.index(window.progress), journal_children.index(window.log))

    def test_shell_footer_shows_developer_credit(self):
        root = FakeWidget(kind="Root")
        window = AuditWindow.__new__(AuditWindow)
        window.root = root
        window.output_dir = FakeVar("C:/outputs")
        window.source_status = FakeVar("кэш источников: проверяется при аудите")
        window.progress_status = FakeVar("Прогресс: ожидание")
        window.vulnerability_mode = FakeVar("full")
        window.status = FakeVar()
        window.action_buttons = []
        window.active_cancel_token = None
        window._log = Mock()

        def widget_factory(kind):
            return lambda parent=None, **options: FakeWidget(parent=parent, kind=kind, **options)

        with patch("ib_audit.gui_tk.ttk.Frame", widget_factory("Frame")), \
                patch("ib_audit.gui_tk.ttk.Label", widget_factory("Label")), \
                patch("ib_audit.gui_tk.ttk.Button", widget_factory("Button")), \
                patch("ib_audit.gui_tk.ttk.Radiobutton", widget_factory("Radiobutton")), \
                patch("ib_audit.gui_tk.ttk.Separator", widget_factory("Separator")), \
                patch("ib_audit.gui_tk.ttk.Progressbar", widget_factory("Progressbar")), \
                patch("ib_audit.gui_tk.scrolledtext.ScrolledText", widget_factory("ScrolledText")):
            window._build()

        def descendants(widget):
            for child in widget.children:
                yield child
                yield from descendants(child)

        labels = [child for child in descendants(root) if child.kind == "Label"]
        credit_labels = [
            label for label in labels
            if label.options.get("text") == "Разработал: Абдрахманов Амаль Даулетович"
        ]

        self.assertEqual(1, len(credit_labels))
        self.assertEqual("Footer.TLabel", credit_labels[0].options.get("style"))
        self.assertEqual("bottom", credit_labels[0].parent.pack_options.get("side"))

    def _window(self):
        window = AuditWindow.__new__(AuditWindow)
        window.output_dir = FakeVar("C:/outputs")
        window.db_path = FakeVar("C:/outputs/ib_audit.db")
        window.status = FakeVar()
        window.progress_status = FakeVar("Прогресс: ожидание")
        window.vulnerability_mode = FakeVar("full")
        window.last_report = None
        window.active_cancel_token = None
        window.messages = queue.Queue()
        window._log = Mock()
        window.action_buttons = [FakeWidget(), FakeWidget(), FakeWidget()]
        window.cancel_button = FakeWidget(state="disabled", text="Отменить")
        window.progress = FakeWidget()
        window.status_badge = FakeWidget()
        return window

    def test_presentation_states_and_source_labels(self):
        self.assertEqual(("CISA KEV", "NVD", "ФСТЭК БДУ"), SOURCE_LABELS)
        self.assertFalse(presentation_for("ready").busy)
        self.assertTrue(presentation_for("busy", "Проверка").busy)
        self.assertEqual("Success.TLabel", presentation_for("success").tone)
        self.assertEqual("Error.TLabel", presentation_for("error").tone)
        self.assertEqual("Cancelled.TLabel", presentation_for("cancelled").tone)

    def test_busy_state_disables_actions_and_runs_progress(self):
        window = self._window()

        window._set_busy(True, "Онлайн-проверка")

        self.assertEqual("Онлайн-проверка", window.status.get())
        self.assertFalse(window.progress.started)
        self.assertEqual(0, window.progress.options["value"])
        self.assertTrue(all(button.options["state"] == "disabled" for button in window.action_buttons))

        window._set_busy(False, "Готово", tone="success")

        self.assertFalse(window.progress.started)
        self.assertEqual(100, window.progress.options["value"])
        self.assertTrue(all(button.options["state"] == "normal" for button in window.action_buttons))
        self.assertEqual("Success.TLabel", window.status_badge.options["style"])

    def test_begin_operation_keeps_cancel_available(self):
        window = self._window()

        token = window._begin_operation("Проверка")

        self.assertIs(token, window.active_cancel_token)
        self.assertEqual("normal", window.cancel_button.options["state"])
        self.assertTrue(
            all(button.options["state"] == "disabled" for button in window.action_buttons)
        )

    def test_cancel_requests_active_token_once_and_updates_button(self):
        window = self._window()
        window.active_cancel_token = CancellationToken()

        window._cancel_active()
        window._cancel_active()

        self.assertTrue(window.active_cancel_token.is_cancelled())
        self.assertEqual("disabled", window.cancel_button.options["state"])
        self.assertEqual("Отмена…", window.cancel_button.options["text"])
        window._log.assert_called_once_with(
            "Запрошена отмена. Ожидание безопасной точки остановки…"
        )

    def test_selected_vulnerability_mode_defaults_to_full_for_unknown_value(self):
        window = self._window()
        self.assertEqual("full", window._selected_vulnerability_mode())

        window.vulnerability_mode.set("fast")
        self.assertEqual("fast", window._selected_vulnerability_mode())

        window.vulnerability_mode.set("unexpected")
        self.assertEqual("full", window._selected_vulnerability_mode())

    @patch("ib_audit.gui_tk.threading.Thread")
    @patch(
        "ib_audit.gui_tk.filedialog.askopenfilenames",
        return_value=("C:/reports/a.html", "C:/reports/b.html"),
    )
    def test_choose_reports_starts_background_analysis(self, askopenfilenames, thread_factory):
        window = self._window()
        window.vulnerability_mode.set("fast")
        thread = thread_factory.return_value

        window._choose_reports()

        askopenfilenames.assert_called_once()
        self.assertIn("HTML", window.status.get())
        thread_factory.assert_called_once_with(
            target=window._run_reports_background,
            args=(
                ("C:/reports/a.html", "C:/reports/b.html"),
                "fast",
                window.active_cancel_token,
            ),
            daemon=True,
        )
        thread.start.assert_called_once()

    @patch("ib_audit.gui_tk.threading.Thread")
    def test_start_passes_selected_vulnerability_mode_to_background_audit(self, thread_factory):
        window = self._window()
        window.vulnerability_mode.set("fast")
        thread = thread_factory.return_value

        window._start(True)

        thread_factory.assert_called_once_with(
            target=window._run_background,
            args=(True, "fast", window.active_cancel_token),
            daemon=True,
        )
        thread.start.assert_called_once()

    @patch("ib_audit.gui_tk.analyze_reports")
    def test_batch_analysis_result_becomes_last_report(self, analyze_reports):
        window = self._window()
        token = CancellationToken()
        analyze_reports.return_value = {
            "status": "completed",
            "report_path": "C:/outputs/result.html",
            "selected_count": 2,
            "processed_count": 2,
            "failed_count": 0,
            "inventory_count": 42,
            "risk_count": 3,
            "coverage_percent": 100,
        }

        window._run_reports_background(
            ("C:/reports/a.html", "C:/reports/b.html"),
            "full",
            token,
        )

        self.assertEqual("C:/outputs/result.html", window.last_report)
        analyze_reports.assert_called_once_with(
            ("C:/reports/a.html", "C:/reports/b.html"),
            db_path="C:/outputs/ib_audit.db",
            output_dir="C:/outputs",
            open_report=False,
            progress=window.messages.put,
            vulnerability_mode="full",
            cancel_token=token,
        )
        messages = []
        while not window.messages.empty():
            messages.append(window.messages.get_nowait())
        self.assertTrue(any("2 из 2" in message for message in messages))
        self.assertIn("__STATUS__:success:Проверка HTML завершена", messages)

    @patch("ib_audit.gui_tk.analyze_reports")
    def test_cancelled_batch_keeps_partial_report(self, analyze_reports):
        window = self._window()
        token = CancellationToken()
        analyze_reports.return_value = {
            "status": "cancelled",
            "report_path": "C:/outputs/partial.html",
            "selected_count": 3,
            "processed_count": 1,
            "failed_count": 0,
            "inventory_count": 10,
            "risk_count": 2,
            "coverage_percent": 100,
        }

        window._run_reports_background(("a.html", "b.html", "c.html"), "full", token)

        self.assertEqual("C:/outputs/partial.html", window.last_report)
        messages = list(window.messages.queue)
        self.assertIn("__STATUS__:cancelled:Проверка отменена", messages)


if __name__ == "__main__":
    unittest.main()
