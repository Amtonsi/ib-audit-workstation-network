import os
import json
import queue
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.abspath("src"))

from ib_audit.gui_tk import (
    AuditWindow, SOURCE_LABELS, format_result_message, format_source_status,
    format_database_update_status, presentation_for, progress_status_for_message,
    progress_value_for_message, responsive_layout_for_width, window_bounds_for_screen,
)
from ib_audit.batch import BatchProgress
from ib_audit.cancellation import CancellationToken
from ib_audit.models import SourceSnapshot
from ib_audit.network_scan import NetworkScanConfig


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
    def test_network_state_refresh_preserves_open_live_widgets(self):
        window = AuditWindow.__new__(AuditWindow)
        packet_table = object()
        nmap_console = object()
        window._network_live_packet_table = packet_table
        window._network_live_nmap_text = nmap_console

        window._ensure_network_state()

        self.assertIs(packet_table, window._network_live_packet_table)
        self.assertIs(nmap_console, window._network_live_nmap_text)

    def test_capture_interface_uses_stable_tshark_index(self):
        window = AuditWindow.__new__(AuditWindow)

        token = window._network_interface_id(
            {"index": "11", "name": "Беспроводная сеть", "description": "Wi-Fi"}
        )

        self.assertEqual("11", token)

    def test_window_bounds_fit_small_laptop_screen(self):
        bounds = window_bounds_for_screen(1024, 600)

        self.assertLessEqual(bounds.width, 976)
        self.assertLessEqual(bounds.height, 536)
        self.assertLessEqual(bounds.min_width, bounds.width)
        self.assertLessEqual(bounds.min_height, bounds.height)

    def test_window_bounds_keep_comfortable_desktop_default(self):
        bounds = window_bounds_for_screen(1920, 1080)

        self.assertEqual((1080, 740), (bounds.width, bounds.height))
        self.assertEqual((860, 560), (bounds.min_width, bounds.min_height))

    def test_responsive_layout_reduces_rail_and_wraps_text_on_narrow_window(self):
        desktop = responsive_layout_for_width(1080)
        narrow = responsive_layout_for_width(800)

        self.assertLess(narrow.rail_width, desktop.rail_width)
        self.assertLess(narrow.workspace_padding[0], desktop.workspace_padding[0])
        self.assertLess(narrow.path_wraplength, desktop.path_wraplength)
        self.assertGreaterEqual(narrow.path_wraplength, 320)

    def test_responsive_layout_caps_wraplengths_on_maximized_window(self):
        layout = responsive_layout_for_width(1920)

        self.assertLessEqual(layout.path_wraplength, 1180)
        self.assertLessEqual(layout.status_wraplength, 380)
        self.assertLessEqual(layout.header_wraplength, 1080)

    def test_minimized_configure_event_does_not_reflow_layout(self):
        window = AuditWindow.__new__(AuditWindow)
        window.root = Mock()
        window.root.state.return_value = "iconic"
        window._last_responsive_layout = None
        window._configure_widget = Mock()
        event = type("Event", (), {"width": 1, "height": 1, "widget": window.root})()

        window._on_root_configure(event)

        window._configure_widget.assert_not_called()

    def test_child_configure_event_does_not_reflow_root_layout(self):
        window = AuditWindow.__new__(AuditWindow)
        window.root = Mock()
        window.root.state.return_value = "normal"
        window._last_responsive_layout = None
        window._configure_widget = Mock()
        event = type("Event", (), {"width": 1080, "height": 740, "widget": object()})()

        window._on_root_configure(event)

        window._configure_widget.assert_not_called()

    def test_repeated_configure_event_same_width_does_not_reapply_layout(self):
        window = AuditWindow.__new__(AuditWindow)
        window._last_responsive_layout = None
        window._configure_widget = Mock()
        event = type("Event", (), {"width": 1080})()

        window._on_root_configure(event)
        first_count = window._configure_widget.call_count
        window._on_root_configure(event)

        self.assertGreater(first_count, 0)
        self.assertEqual(first_count, window._configure_widget.call_count)

    def test_reentrant_configure_event_during_layout_is_ignored(self):
        window = AuditWindow.__new__(AuditWindow)
        window._last_responsive_layout = None
        reentered = False

        def configure_widget(*args, **kwargs):
            nonlocal reentered
            if not reentered:
                reentered = True
                window._on_root_configure(type("Event", (), {"width": 1079})())

        window._configure_widget = Mock(side_effect=configure_widget)

        window._apply_responsive_layout(1080)

        self.assertTrue(reentered)
        self.assertEqual(11, window._configure_widget.call_count)

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

    def test_nvd_cpe_progress_uses_real_group_ratio(self):
        self.assertEqual(85, progress_value_for_message("Local NVD/CPE database: 0/100", 85))
        self.assertEqual(88, progress_value_for_message("Local NVD/CPE database: 50/100", 85))
        self.assertEqual(90, progress_value_for_message("Local NVD/CPE database: 100/100", 85))
        self.assertEqual(
            "Прогресс: NVD/CPE 50/100",
            progress_status_for_message("Local NVD/CPE database: 50/100"),
        )

    def test_cpe_update_progress_and_status_are_visible(self):
        status = format_database_update_status({
            "db_path": "C:/outputs/vulnerability_sources.db",
            "stats": {
                "source_files": 7,
                "reused_sources": 2,
                "updated_sources": 5,
                "cpe_names": 123,
                "cpe_match_criteria": 45,
                "active_cpe_generation": 9,
            },
        })

        self.assertIn("CPE Dictionary=123", status)
        self.assertIn("CPE Match=45", status)
        self.assertIn("CPE generation=9", status)
        self.assertEqual("Прогресс: обновление CPE Dictionary", progress_status_for_message("Загрузка CPE Dictionary"))
        self.assertEqual("Прогресс: обновление CPE Match", progress_status_for_message("Загрузка CPE Match"))
        self.assertEqual("Прогресс: индексирование CPE", progress_status_for_message("Индексирование CPE"))
        self.assertEqual(30, progress_value_for_message("Загрузка CPE Dictionary", 0))
        self.assertEqual(50, progress_value_for_message("Загрузка CPE Match", 30))
        self.assertEqual(75, progress_value_for_message("Индексирование CPE", 50))

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

    def test_drain_messages_yields_after_bounded_batch(self):
        window = self._window()
        window.root = FakeWidget()
        window.root.after = Mock()
        for index in range(70):
            window.messages.put(f"Audit event {index}")

        window._drain_messages()

        self.assertEqual(6, window.messages.qsize())
        window.root.after.assert_called_once_with(10, window._drain_messages)

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
        window.vulnerability_source_mode = FakeVar("auto")
        window.status = FakeVar()
        window.action_buttons = []
        window.active_cancel_token = None
        window._log = Mock()

        def widget_factory(kind):
            return lambda parent=None, **options: FakeWidget(parent=parent, kind=kind, **options)

        with patch("ib_audit.gui_tk.ttk.Frame", widget_factory("Frame")), \
                patch("ib_audit.gui_tk.ttk.Label", widget_factory("Label")), \
                patch("ib_audit.gui_tk.ttk.Button", widget_factory("Button")), \
                patch("ib_audit.gui_tk.ttk.Checkbutton", widget_factory("Checkbutton")), \
                patch("ib_audit.gui_tk.ttk.Entry", widget_factory("Entry")), \
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
                patch("ib_audit.gui_tk.ttk.Checkbutton", widget_factory("Checkbutton")), \
                patch("ib_audit.gui_tk.ttk.Entry", widget_factory("Entry")), \
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

    def test_selected_vulnerability_source_mode_supports_explicit_modes(self):
        window = self._window()
        self.assertEqual("auto", window._selected_vulnerability_source_mode())

        window.vulnerability_source_mode = FakeVar("local")
        self.assertEqual("local", window._selected_vulnerability_source_mode())

        window.vulnerability_source_mode.set("Только онлайн")
        self.assertEqual("online", window._selected_vulnerability_source_mode())

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
            args=(True, "fast", window.active_cancel_token, None, False, "auto"),
            daemon=True,
        )
        thread.start.assert_called_once()

    @patch("ib_audit.gui_tk.threading.Thread")
    def test_start_passes_network_command_profile_when_enabled(self, thread_factory):
        window = self._window()
        window._ensure_network_state()
        window.network_scan_enabled.set(True)
        window.network_capture_enabled.set(True)
        window.network_targets.set("192.168.56.0/24")
        window.network_ports.set("80,443")
        window.network_extra_args.set("--min-rate 50")
        window.network_capture_interface.set("3")
        window.network_capture_duration.set("15")
        window.network_capture_filter.set("tcp port 443")
        window.network_nmap_os_detection.set(False)
        window.network_nmap_open_only.set(False)

        window._start(True)

        args = thread_factory.call_args.kwargs["args"]
        self.assertEqual((True, "full", window.active_cancel_token), args[:3])
        config = args[3]
        self.assertTrue(config.enabled)
        self.assertTrue(config.capture_enabled)
        self.assertEqual(("192.168.56.0/24",), config.targets)
        self.assertEqual("80,443", config.ports)
        self.assertEqual("--min-rate 50", config.extra_args)
        self.assertEqual("3", config.capture_interface)
        self.assertEqual(15, config.capture_duration)
        self.assertEqual("tcp port 443", config.capture_filter)
        self.assertFalse(config.nmap_os_detection)
        self.assertFalse(config.nmap_open_only)
        thread_factory.return_value.start.assert_called_once()

    @patch("ib_audit.gui_tk.threading.Thread")
    def test_start_capture_uses_safe_traffic_telemetry_without_npcap_prompt(self, thread_factory):
        window = self._window()
        window.root = Mock()
        window._ensure_network_state()
        window.network_scan_enabled.set(True)
        window.network_capture_enabled.set(True)
        window.network_capture_interface.set("3")

        with patch("ib_audit.gui_tk.messagebox.askyesno") as ask, \
                patch.object(window, "_start_network_scan_live_window"):
            window._start(True)

        ask.assert_not_called()
        thread_factory.assert_called_once()

    @patch("ib_audit.gui_tk.terminate_network_tool_processes")
    def test_close_application_cancels_work_and_stops_network_tools(self, stop_tools):
        window = self._window()
        window.root = Mock()
        window.active_cancel_token = CancellationToken()

        window._close_application()

        self.assertTrue(window.active_cancel_token.is_cancelled())
        stop_tools.assert_called_once_with()
        window.root.destroy.assert_called_once_with()

    def test_capture_only_network_config_disables_nmap_phase(self):
        window = self._window()
        window._ensure_network_state()
        window.network_scan_enabled.set(False)
        window.network_capture_enabled.set(True)
        window.network_capture_interface.set("5")

        config = window._selected_network_scan_config()

        self.assertIsNotNone(config)
        self.assertTrue(config.enabled)
        self.assertTrue(config.capture_enabled)
        self.assertFalse(config.nmap_enabled)

    @patch("ib_audit.gui_tk.threading.Thread")
    def test_start_capture_requires_selected_interface(self, thread_factory):
        window = self._window()
        window.root = Mock()
        window._ensure_network_state()
        window.network_scan_enabled.set(True)
        window.network_capture_enabled.set(True)

        with patch("ib_audit.gui_tk.messagebox.showwarning") as showwarning:
            window._start(True)

        thread_factory.assert_not_called()
        showwarning.assert_called_once()
        warning_text = "\n".join(str(part) for part in showwarning.call_args.args)
        self.assertIn("Загрузить интерфейсы", warning_text)
        self.assertNotIn("???", warning_text)

    def test_network_ui_texts_do_not_use_question_mark_placeholders(self):
        source = Path("src/ib_audit/gui_tk.py").read_text(encoding="utf-8")

        self.assertNotRegex(source, r"\?{3,}")

    def test_live_monitor_classifies_packet_nmap_and_security_events(self):
        window = AuditWindow.__new__(AuditWindow)
        window._network_live_events = [
            "Running nmap: nmap -sT -p 80 192.168.1.10",
            "TRAFFIC_RISK|high|192.168.1.10:51516 -> 93.184.216.34:80 HTTP GET /login",
        ]

        row = window._network_live_packet_row(window._network_live_events[1])

        self.assertIsNotNone(row)
        self.assertEqual("HIGH", row[0])
        self.assertEqual("HTTP", row[1])
        self.assertEqual("192.168.1.10:51516", row[2])
        self.assertEqual("93.184.216.34:80", row[3])
        self.assertTrue(window._network_live_event_is_nmap(window._network_live_events[0]))
        self.assertTrue(window._network_live_event_is_security(window._network_live_events[1]))

    def test_live_monitor_builds_wireshark_packet_row_from_packet_json_event(self):
        window = AuditWindow.__new__(AuditWindow)
        packet = {
            "No.": "7",
            "Time": "10.125",
            "Source": "192.168.1.10:51516",
            "Destination": "93.184.216.34:80",
            "Protocol": "HTTP",
            "Length": "140",
            "Info": "GET /login HTTP/1.1",
            "Details": "Frame 7: 140 bytes\nProtocol stack: eth:ip:tcp:http",
            "Bytes Hex": "00 01 02 0a 0b 0c",
        }

        row = window._network_live_wireshark_packet_row("PACKET_ROW|medium|" + json.dumps(packet))

        self.assertIsNotNone(row)
        self.assertEqual(("7", "10.125", "192.168.1.10:51516", "93.184.216.34:80", "HTTP", "140"), row[:6])
        self.assertIn("GET /login", row[6])
        self.assertEqual("MEDIUM", row[7])
        self.assertIn("Protocol stack", row[8])
        self.assertIn("00 01 02", row[9])

    def test_live_monitor_status_tracks_latest_scan_event(self):
        window = AuditWindow.__new__(AuditWindow)
        window._network_live_window = object()
        window._network_live_text = None
        window._network_live_canvas = None
        window._network_live_packet_table = None
        window._network_live_nodes_table = None
        window._network_live_nmap_text = None
        window._network_live_security_text = None
        window._network_live_log_text = None
        window._network_live_summary_vars = {}
        window._network_live_status = FakeVar("old")
        window._network_live_events = []
        window._network_topology_nodes = set()

        window._append_network_scan_event("Running collector: network_intelligence")

        self.assertIn("network_intelligence", window._network_live_status.get())

    def test_live_monitor_classifies_network_intelligence_collector_as_nmap_event(self):
        window = AuditWindow.__new__(AuditWindow)

        self.assertTrue(window._network_live_event_is_nmap("Running collector: network_intelligence"))

    def test_live_monitor_builds_packet_row_from_safe_telemetry_message(self):
        window = AuditWindow.__new__(AuditWindow)

        row = window._network_live_packet_row("Safe traffic telemetry completed: 12 active TCP connection row(s)")

        self.assertIsNotNone(row)
        self.assertEqual("TCP", row[1])
        self.assertIn("Safe traffic telemetry", row[4])

    def test_live_monitor_visualizes_capture_active_event(self):
        window = AuditWindow.__new__(AuditWindow)
        event = "CAPTURE_ACTIVE|info|Захват трафика выполняется: интерфейсы=5; режим=safe Windows telemetry"

        row = window._network_live_packet_row(event)
        status = window._network_live_status_for_event(event)
        display, tag = window._network_live_event_display(event)

        self.assertIsNotNone(row)
        self.assertEqual("CAPTURE", row[1])
        self.assertIn("Захват трафика выполняется", row[4])
        self.assertEqual("Захват трафика выполняется", status)
        self.assertIn("CAPTURE", display)
        self.assertEqual("packet", tag)

    def test_live_monitor_capture_banner_text_is_unambiguous(self):
        window = AuditWindow.__new__(AuditWindow)
        config = NetworkScanConfig(
            enabled=True,
            nmap_enabled=True,
            capture_enabled=True,
            capture_interfaces=("5", "Wi-Fi"),
            capture_duration=20,
        )

        text = window._network_live_capture_banner_text(config)

        self.assertIn("ЗАХВАТ ТРАФИКА ИДЁТ", text)
        self.assertIn("5, Wi-Fi", text)
        self.assertIn("Nmap после первичного захвата", text)

    def test_network_interface_tone_marks_interfaces_with_traffic(self):
        window = AuditWindow.__new__(AuditWindow)

        tone = window._network_capture_interface_tone({"active": "yes", "kind": "physical", "traffic_active": "yes"})

        self.assertEqual("Traffic", tone)
        self.assertEqual("ДАННЫЕ", window._network_capture_interface_badge({"traffic_active": "yes"}))

    def test_network_interface_panel_defaults_unselected_and_marks_active_status(self):
        root = FakeWidget(kind="Root")
        window = self._window()
        window.root = root
        window._network_capture_interface_frame = FakeWidget(kind="Frame")
        window._network_capture_interface_list_frame = FakeWidget(parent=window._network_capture_interface_frame, kind="Frame")
        window.network_capture_interfaces = [
            {
                "index": "5",
                "name": "5",
                "description": "\\Device\\NPF_{WIFI} (Беспроводная сеть)",
                "friendly_name": "Беспроводная сеть",
                "status": "Up",
                "active": "yes",
                "kind": "physical",
                "link_speed": "866 Mbps",
            },
            {
                "index": "14",
                "name": "14",
                "description": "ciscodump (Cisco remote capture)",
                "friendly_name": "Cisco remote capture",
                "status": "service",
                "active": "no",
                "kind": "extcap",
            },
        ]

        def widget_factory(kind):
            return lambda parent=None, **options: FakeWidget(parent=parent, kind=kind, **options)

        with patch("ib_audit.gui_tk.BooleanVar", FakeVar), \
                patch("ib_audit.gui_tk.ttk.Frame", widget_factory("Frame")), \
                patch("ib_audit.gui_tk.ttk.Label", widget_factory("Label")), \
                patch("ib_audit.gui_tk.ttk.Checkbutton", widget_factory("Checkbutton")):
            window._build_network_capture_interface_checkbox_panel()

        self.assertFalse(any(variable.get() for variable in window._capture_interface_checkbox_vars.values()))
        labels = [
            child.options.get("text", "")
            for row in window._network_capture_interface_list_frame.children
            for group in row.children
            for child in getattr(group, "children", [])
            if child.kind == "Checkbutton"
        ]
        label_text = " ".join(labels)
        self.assertIn("Активен", label_text)
        self.assertIn("Служебный", label_text)

    def test_network_command_window_controls_are_present(self):
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
                patch("ib_audit.gui_tk.ttk.Checkbutton", widget_factory("Checkbutton")), \
                patch("ib_audit.gui_tk.ttk.Entry", widget_factory("Entry")), \
                patch("ib_audit.gui_tk.ttk.Radiobutton", widget_factory("Radiobutton")), \
                patch("ib_audit.gui_tk.ttk.Separator", widget_factory("Separator")), \
                patch("ib_audit.gui_tk.ttk.Progressbar", widget_factory("Progressbar")), \
                patch("ib_audit.gui_tk.scrolledtext.ScrolledText", widget_factory("ScrolledText")):
            window._build()

        def descendants(widget):
            for child in widget.children:
                yield child
                yield from descendants(child)

        buttons = [child for child in descendants(root) if child.kind == "Button"]
        self.assertTrue(any(button.options.get("text") == "Команды сети" for button in buttons))

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
            db_path=None,
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

    @patch("ib_audit.gui_tk.update_vulnerability_database")
    def test_source_update_uses_sqlite_database_updater(self, update_database):
        window = self._window()
        token = CancellationToken()
        update_database.return_value = {
            "db_path": Path("C:/project/vulnerability-database/vulnerability_sources.db"),
            "snapshot_dir": Path("C:/project/vulnerability-database/snapshots"),
            "stats": {
                "reused_sources": 1,
                "updated_sources": 2,
                "source_files": 3,
                "cpe_names": 4,
                "cpe_match_criteria": 5,
                "active_cpe_generation": 6,
                "fstec_vulnerabilities": 7,
                "fstec_products": 8,
                "fstec_import_errors": 1,
                "fstec_download_errors": 2,
            },
        }

        window._run_source_update(token)

        update_database.assert_called_once()
        self.assertEqual(Path("C:/outputs/vulnerability-database"), update_database.call_args.kwargs["output_dir"])
        self.assertTrue(update_database.call_args.kwargs["include_cpe"])
        self.assertFalse(update_database.call_args.kwargs.get("include_cpe_match", False))
        self.assertIs(token, update_database.call_args.kwargs["cancel_token"])
        messages = list(window.messages.queue)
        self.assertTrue(any("CPE Dictionary=4" in message for message in messages))
        self.assertTrue(any("FSTEC=7/8" in message for message in messages))
        self.assertTrue(any("FSTEC XLSX errors=1" in message for message in messages))
        self.assertTrue(any("FSTEC download errors=2" in message for message in messages))
        self.assertIn("__STATUS__:Базы обновлены", messages)

    @patch("ib_audit.gui_tk.threading.Thread")
    def test_update_sources_keeps_cancel_available(self, thread_factory):
        window = self._window()

        window._update_sources()

        self.assertIsNotNone(window.active_cancel_token)
        self.assertEqual("normal", window.cancel_button.options["state"])
        thread_factory.assert_called_once_with(
            target=window._run_source_update,
            args=(window.active_cancel_token,),
            daemon=True,
        )


class AuditWindowDynamicTopologyTests(unittest.TestCase):
    def _window_with_events(self, *events: str) -> AuditWindow:
        window = AuditWindow.__new__(AuditWindow)
        window._network_live_events = list(events)
        window._network_topology_nodes = set()
        return window

    def test_topology_is_built_only_from_observed_packet_endpoints(self) -> None:
        packet = (
            'PACKET_ROW|INFO|{"No.":"1","Time":"0.001","Source":"192.168.10.25",'
            '"Destination":"8.8.8.8","Protocol":"DNS","Length":"74",'
            '"Info":"Standard query A example.test","Details":"","Bytes Hex":""}'
        )
        graph = self._window_with_events(packet)._network_live_topology_graph()

        node_ids = {str(node["id"]) for node in graph["nodes"]}
        self.assertEqual(node_ids, {"192.168.10.25", "8.8.8.8"})
        self.assertEqual(len(graph["edges"]), 1)
        self.assertEqual(graph["center"], "192.168.10.25")
        self.assertEqual(next(node["role"] for node in graph["nodes"] if node["id"] == "8.8.8.8"), "dns")

    def test_topology_risk_and_nmap_service_are_derived_from_events(self) -> None:
        packet = (
            'PACKET_ROW|INFO|{"No.":"2","Time":"0.002","Source":"192.168.10.25",'
            '"Destination":"1.1.1.1","Protocol":"TLS","Length":"1514",'
            '"Info":"Application data","Details":"","Bytes Hex":""}'
        )
        window = self._window_with_events(
            packet,
            "TRAFFIC_RISK|HIGH|Suspicious connection to 1.1.1.1",
            "NMAP|INFO|Host 192.168.10.25 has 443/tcp open https",
        )
        graph = window._network_live_topology_graph()

        nodes = {str(node["id"]): node for node in graph["nodes"]}
        self.assertEqual(nodes["1.1.1.1"]["role"], "risk")
        self.assertEqual(nodes["1.1.1.1"]["severity"], "HIGH")
        service_nodes = [node for node in graph["nodes"] if str(node["id"]).startswith("service:")]
        self.assertEqual(len(service_nodes), 1)
        self.assertEqual(service_nodes[0]["label"], "443/tcp")
        self.assertTrue(any(bool(edge["service"]) for edge in graph["edges"]))

    def test_inactive_loopback_scan_target_does_not_replace_active_local_center(self) -> None:
        packets = [
            (
                'PACKET_ROW|INFO|{"No.":"1","Time":"0.001","Source":"10.8.1.1",'
                '"Destination":"104.18.32.47","Protocol":"TLS","Length":"128",'
                '"Info":"Application data","Details":"","Bytes Hex":""}'
            ),
            (
                'PACKET_ROW|INFO|{"No.":"2","Time":"0.002","Source":"10.8.1.1",'
                '"Destination":"1.1.1.1","Protocol":"DNS","Length":"74",'
                '"Info":"Standard query","Details":"","Bytes Hex":""}'
            ),
        ]
        window = self._window_with_events(*packets)
        window._network_topology_nodes = {"127.0.0.1"}

        graph = window._network_live_topology_graph()

        self.assertEqual(graph["center"], "10.8.1.1")
        center = next(node for node in graph["nodes"] if node["id"] == "10.8.1.1")
        self.assertEqual(center["role"], "local")
        loopback = next(node for node in graph["nodes"] if node["id"] == "127.0.0.1")
        self.assertEqual(loopback["role"], "loopback")

    def test_topology_endpoint_normalizes_ports_without_damaging_ipv6(self) -> None:
        self.assertEqual(AuditWindow._network_live_topology_endpoint("192.168.1.2:443"), "192.168.1.2")
        self.assertEqual(AuditWindow._network_live_topology_endpoint("[fe80::1]:5353"), "fe80::1")
        self.assertEqual(AuditWindow._network_live_topology_endpoint("fe80::2"), "fe80::2")

    def test_live_header_reports_selected_interface_and_real_packet_count(self) -> None:
        class Value:
            text = ""

            def set(self, value: str) -> None:
                self.text = value

        window = AuditWindow.__new__(AuditWindow)
        window._network_live_capture_summary = Value()
        window._network_live_interfaces_label = "11"
        window._network_live_events = ["CAPTURE_ACTIVE|INFO|interface=11"]
        window._network_live_capture_active = lambda: True
        row = ("1", "0.01", "local", "remote", "TCP", "64", "SYN", "INFO", "", "")

        window._update_reference_live_header([row, row])

        self.assertIn("11", window._network_live_capture_summary.text)
        self.assertIn("2 пакетов", window._network_live_capture_summary.text)

    def test_security_card_compacts_packet_json(self) -> None:
        event = (
            'TRAFFIC_RISK|HIGH|{"Source":"192.168.1.2","Destination":"1.1.1.1",'
            '"Protocol":"TLS","Info":"Repeated reset"}'
        )

        severity, title, detail = AuditWindow._reference_security_card_data(event)

        self.assertEqual(severity, "HIGH")
        self.assertIn("высокого уровня", title)
        self.assertEqual(detail, "TLS: 192.168.1.2 → 1.1.1.1. Repeated reset")


if __name__ == "__main__":
    unittest.main()
