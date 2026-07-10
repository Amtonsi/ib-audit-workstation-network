from __future__ import annotations

import os
import json
import queue
import re
import sys
import threading
import webbrowser
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, X, Y, BooleanVar, Canvas, StringVar, Tk, Toplevel, filedialog, messagebox, scrolledtext, ttk

from .app import (
    VULNERABILITY_MODE_FAST,
    VULNERABILITY_MODE_FULL,
    analyze_reports,
    default_output_dir,
    run_audit,
    update_vulnerability_database,
)
from .batch import BatchProgress
from .cancellation import AuditCancelled, CancellationToken
from .models import SourceSnapshot
from .network_scan import (
    DEFAULT_LOCAL_NMAP_PORTS,
    NETWORK_COMMAND_OPTIONS,
    NetworkScanConfig,
    detect_tshark_interfaces,
    local_machine_nmap_targets,
)
from .npcap import NPCAP_DOWNLOAD_URL, launch_npcap_installer, query_npcap_status, resolve_npcap_installer


SOURCE_LABELS = ("CISA KEV", "NVD", "ФСТЭК БДУ")
VULNERABILITY_MODE_TEXT = {
    VULNERABILITY_MODE_FULL: "Полный онлайн ФСТЭК",
    VULNERABILITY_MODE_FAST: "Быстро: кэш NVD/CISA",
}

COLORS = {
    "canvas": "#F3F6F8",
    "header": "#172126",
    "header_muted": "#B8C4C9",
    "rail": "#FFFFFF",
    "panel": "#FFFFFF",
    "border": "#DCE3E7",
    "text": "#172126",
    "muted": "#62727A",
    "teal": "#0F766E",
    "teal_hover": "#115E59",
    "blue": "#2563EB",
    "violet": "#6D4AFF",
    "amber": "#B45309",
    "red": "#B91C1C",
    "green": "#15803D",
}

DEVELOPER_CREDIT = "Разработал: Абдрахманов Амаль Даулетович"


def _frozen_startup_log(message: str) -> None:
    if not getattr(sys, "frozen", False):
        return
    try:
        base_dir = Path(os.environ.get("LOCALAPPDATA") or Path.home())
        log_dir = base_dir / "IBAuditWorkstation" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        with (log_dir / "startup.log").open("a", encoding="utf-8") as handle:
            handle.write(f"{timestamp} {message}\n")
    except OSError:
        return


@dataclass(frozen=True)
class WindowPresentation:
    text: str
    tone: str
    busy: bool


@dataclass(frozen=True)
class WindowBounds:
    width: int
    height: int
    min_width: int
    min_height: int


@dataclass(frozen=True)
class ResponsiveLayout:
    rail_width: int
    rail_padding: tuple[int, int]
    workspace_padding: tuple[int, int, int, int]
    header_padding: tuple[int, int]
    footer_padding: tuple[int, int, int, int]
    path_wraplength: int
    status_wraplength: int
    note_wraplength: int
    header_wraplength: int


class _FallbackVar:
    def __init__(self, value: object = "") -> None:
        self.value = value

    def get(self) -> object:
        return self.value

    def set(self, value: object) -> None:
        self.value = value


class _Tooltip:
    def __init__(self, widget: object, text: str) -> None:
        self.widget = widget
        self.text = text
        self.popup: Toplevel | None = None
        if not text or not hasattr(widget, "bind"):
            return
        try:
            widget.bind("<Enter>", self._show)
            widget.bind("<Leave>", self._hide)
            widget.bind("<ButtonPress>", self._hide)
        except Exception:
            return

    def _show(self, _event: object | None = None) -> None:
        if self.popup is not None:
            return
        try:
            x = int(self.widget.winfo_rootx()) + 18  # type: ignore[attr-defined]
            y = int(self.widget.winfo_rooty()) + int(self.widget.winfo_height()) + 8  # type: ignore[attr-defined]
            self.popup = Toplevel(self.widget)  # type: ignore[arg-type]
            self.popup.wm_overrideredirect(True)
            self.popup.wm_geometry(f"+{x}+{y}")
            label = ttk.Label(
                self.popup,
                text=self.text,
                justify="left",
                wraplength=420,
                background="#172126",
                foreground="#FFFFFF",
                padding=(10, 8),
            )
            label.pack()
        except Exception:
            self.popup = None

    def _hide(self, _event: object | None = None) -> None:
        if self.popup is None:
            return
        try:
            self.popup.destroy()
        except Exception:
            pass
        self.popup = None


def _safe_screen_value(value: int, fallback: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return fallback
    return parsed if parsed > 0 else fallback


def _bounded(value: int, minimum: int, maximum: int) -> int:
    return min(maximum, max(minimum, int(value)))


def window_bounds_for_screen(screen_width: int, screen_height: int) -> WindowBounds:
    width = _safe_screen_value(screen_width, 1366)
    height = _safe_screen_value(screen_height, 768)
    available_width = max(640, width - 48)
    available_height = max(480, height - 64)
    window_width = max(min(760, available_width), min(1080, available_width))
    window_height = max(min(520, available_height), min(740, available_height))
    return WindowBounds(
        width=window_width,
        height=window_height,
        min_width=min(860, window_width),
        min_height=min(560, window_height),
    )


def responsive_layout_for_width(width: int) -> ResponsiveLayout:
    window_width = max(640, int(width or 1080))
    if window_width < 880:
        return ResponsiveLayout(
            rail_width=218,
            rail_padding=(14, 16),
            workspace_padding=(12, 12, 12, 12),
            header_padding=(18, 14),
            footer_padding=(14, 4, 16, 8),
            path_wraplength=_bounded(window_width - 430, 320, 520),
            status_wraplength=_bounded(window_width - 520, 220, 280),
            note_wraplength=180,
            header_wraplength=_bounded(window_width - 260, 320, 520),
        )
    if window_width < 1040:
        return ResponsiveLayout(
            rail_width=248,
            rail_padding=(16, 18),
            workspace_padding=(16, 16, 18, 14),
            header_padding=(22, 16),
            footer_padding=(18, 4, 20, 8),
            path_wraplength=_bounded(window_width - 470, 420, 760),
            status_wraplength=_bounded(window_width - 560, 260, 320),
            note_wraplength=206,
            header_wraplength=_bounded(window_width - 290, 420, 720),
        )
    return ResponsiveLayout(
        rail_width=286,
        rail_padding=(20, 22),
        workspace_padding=(22, 20, 24, 18),
        header_padding=(26, 18),
        footer_padding=(20, 4, 24, 8),
        path_wraplength=_bounded(window_width - 430, 560, 1180),
        status_wraplength=_bounded(window_width - 620, 320, 380),
        note_wraplength=232,
        header_wraplength=_bounded(window_width - 320, 560, 1080),
    )


def _enable_high_dpi_awareness() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        return


FSTEC_PROGRESS_RE = re.compile(r"(?:фстэк|фстек|fstec).*?(\d+)\s*/\s*(\d+)", re.IGNORECASE)
NVD_CPE_PROGRESS_RE = re.compile(r"nvd\s*/\s*cpe.*?(\d+)\s*/\s*(\d+)", re.IGNORECASE)


def presentation_for(state: str, text: str | None = None) -> WindowPresentation:
    defaults = {
        "ready": WindowPresentation("Готово к работе", "Ready.TLabel", False),
        "busy": WindowPresentation("Выполняется анализ", "Busy.TLabel", True),
        "success": WindowPresentation("Операция завершена", "Success.TLabel", False),
        "error": WindowPresentation("Ошибка операции", "Error.TLabel", False),
        "cancelled": WindowPresentation("Операция отменена", "Cancelled.TLabel", False),
    }
    selected = defaults.get(state, defaults["ready"])
    return WindowPresentation(text or selected.text, selected.tone, selected.busy)


def format_result_message(result: dict[str, object]) -> str:
    return (
        f"Готово: объектов={result.get('inventory_count', 0)}, "
        f"диагностик={result.get('diagnostic_count', 0)}, "
        f"рисков={result.get('risk_count', result.get('vulnerability_count', 0))}, "
        f"обработано={result.get('coverage_percent', 0)}%, "
        f"проверено правилами={result.get('rule_checked_percent', result.get('coverage_percent', 0))}%, "
        f"недостаточно данных={result.get('insufficient_count', 0)}"
    )


def format_source_status(snapshots: list[SourceSnapshot]) -> str:
    if not snapshots:
        return "кэш источников отсутствует"
    parts = []
    for item in snapshots:
        date = item.fetched_at[:10].split("-")
        display_date = ".".join(reversed(date)) if len(date) == 3 else item.fetched_at
        parts.append(f"{item.source}: {display_date}")
    return " · ".join(parts)


def format_database_update_status(result: dict[str, object]) -> str:
    db_path = Path(result["db_path"])
    stats = result.get("stats", {})
    if not isinstance(stats, dict):
        stats = {}
    fstec_vulnerabilities = stats.get("fstec_vulnerabilities", stats.get("fstec_records", 0))
    fstec_products = stats.get("fstec_products", 0)
    fstec_errors = stats.get("fstec_import_errors", 0)
    fstec_download_errors = stats.get("fstec_download_errors", 0)
    return (
        f"БД уязвимостей: {db_path.name} · "
        f"источников={stats.get('source_files', 0)} · "
        f"переиспользовано={stats.get('reused_sources', 0)} · "
        f"обновлено={stats.get('updated_sources', 0)} · "
        f"CPE Dictionary={stats.get('cpe_names', 0)} · "
        f"CPE Match={stats.get('cpe_match_criteria', 0)} · "
        f"CPE generation={stats.get('active_cpe_generation', 0)} · "
        f"FSTEC={fstec_vulnerabilities}/{fstec_products} · "
        f"FSTEC XLSX errors={fstec_errors} · "
        f"FSTEC download errors={fstec_download_errors}"
    )


def _fstec_progress_value(message: str, current: int) -> int | None:
    match = FSTEC_PROGRESS_RE.search(message)
    if not match:
        return None
    completed = int(match.group(1))
    total = int(match.group(2))
    if total <= 0:
        return current
    ratio = max(0.0, min(completed / total, 1.0))
    mapped = int(round(85 + ratio * 10))
    return max(current, min(95, mapped))


def _nvd_cpe_progress_value(message: str, current: int) -> int | None:
    match = NVD_CPE_PROGRESS_RE.search(message)
    if not match:
        return None
    completed = int(match.group(1))
    total = int(match.group(2))
    if total <= 0:
        return current
    ratio = max(0.0, min(completed / total, 1.0))
    mapped = int(round(85 + ratio * 5))
    return max(current, min(90, mapped))


def progress_status_for_message(message: str) -> str | None:
    lowered = message.casefold()
    nvd_cpe_match = NVD_CPE_PROGRESS_RE.search(message)
    if nvd_cpe_match:
        return f"Прогресс: NVD/CPE {nvd_cpe_match.group(1)}/{nvd_cpe_match.group(2)}"
    match = FSTEC_PROGRESS_RE.search(message)
    if match:
        return f"Прогресс: ФСТЭК БДУ {match.group(1)}/{match.group(2)}"
    if "running collector:" in lowered:
        collector = message.split(":", 1)[1].strip() if ":" in message else ""
        return f"Прогресс: сбор инвентаря {collector}".strip()
    if lowered.startswith("network intelligence"):
        return f"Прогресс: {message}"
    if lowered.startswith("nmap"):
        return f"Прогресс: {message}"
    if "running nmap" in lowered:
        return f"Прогресс: {message}"
    if "starting traffic capture" in lowered or "traffic capture completed" in lowered:
        return f"Прогресс: {message}"
    if "assessing vulnerabilities" in lowered:
        return "Прогресс: оценка уязвимостей"
    if "audit started" in lowered or "importing local html report" in lowered:
        return "Прогресс: запуск проверки"
    if "updating cisa kev catalog" in lowered:
        return "Прогресс: обновление CISA KEV"
    if "cpe dictionary" in lowered:
        return "Прогресс: обновление CPE Dictionary"
    if "cpe match" in lowered:
        return "Прогресс: обновление CPE Match"
    if "cpe" in lowered and ("индекс" in lowered or "index" in lowered or "активац" in lowered or "building" in lowered):
        return "Прогресс: индексирование CPE"
    if "audit completed" in lowered:
        return "Прогресс: формирование отчёта"
    if "nvd" in lowered:
        return "Прогресс: проверка NVD"
    if "cisa" in lowered:
        return "Прогресс: проверка CISA KEV"
    if "фстэк" in lowered or "фстек" in lowered or "fstec" in lowered:
        return "Прогресс: проверка ФСТЭК БДУ"
    return None


def progress_value_for_message(message: str, current: int) -> int:
    lowered = message.casefold()
    if message.startswith("__STATUS__:"):
        status = message.split(":", 1)[1].casefold()
        explicit_tone = status.split(":", 1)[0]
        if explicit_tone in {"error", "cancelled"}:
            return current
        if explicit_tone == "success":
            return 100
        if "ошибка" in status or "error" in status or "рћс€рёр±рєр°" in status:
            return current
        return 100
    if lowered.startswith("готово:") or lowered.startswith("done:") or lowered.startswith("р“рѕс‚рѕрірѕ:"):
        return 100
    if "audit started" in lowered or "importing local html report" in lowered:
        return max(current, 5)
    if "updating cisa kev catalog" in lowered:
        return max(current, 20)
    if "cpe dictionary" in lowered:
        return max(current, 30)
    if "cpe match" in lowered:
        return max(current, 50)
    if "cpe" in lowered and ("индекс" in lowered or "index" in lowered or "активац" in lowered or "building" in lowered):
        return max(current, 75)
    if "running collector:" in lowered:
        return min(75, max(20, current + 15))
    if "audit completed" in lowered:
        return max(current, 80)
    if "assessing vulnerabilities" in lowered:
        return max(current, 85)
    if lowered.startswith("network intelligence"):
        return min(98, max(current + 8, 25))
    if lowered.startswith("nmap"):
        return min(85, max(current + 8, 30))
    if "running nmap" in lowered or "starting traffic capture" in lowered:
        return min(95, max(current + 8, 55))
    if "traffic capture completed" in lowered:
        return min(92, max(current + 8, 70))
    nvd_cpe_progress = _nvd_cpe_progress_value(message, current)
    if nvd_cpe_progress is not None:
        return nvd_cpe_progress
    fstec_progress = _fstec_progress_value(message, current)
    if fstec_progress is not None:
        return fstec_progress
    if "фстэк" in lowered or "fstec" in lowered or "nvd" in lowered or "cisa" in lowered:
        return min(95, max(current + 2, current))
    return current


class AuditWindow:
    def __init__(self) -> None:
        _frozen_startup_log("AuditWindow.__init__ begin")
        _enable_high_dpi_awareness()
        _frozen_startup_log("dpi awareness ready")
        self.root = Tk()
        _frozen_startup_log("tk root created")
        self.root.title("IB Audit Workstation")
        self.window_bounds = window_bounds_for_screen(
            self.root.winfo_screenwidth(),
            self.root.winfo_screenheight(),
        )
        _frozen_startup_log(
            "screen bounds "
            f"width={self.window_bounds.width} "
            f"height={self.window_bounds.height}"
        )
        self.root.geometry(f"{self.window_bounds.width}x{self.window_bounds.height}")
        self.root.minsize(self.window_bounds.min_width, self.window_bounds.min_height)
        self.root.configure(background=COLORS["canvas"])
        self.output_dir = StringVar(value=str(default_output_dir()))
        self.db_path = StringVar(value=str(default_output_dir() / "ib_audit.db"))
        self.status = StringVar(value=presentation_for("ready").text)
        self.source_status = StringVar(value="кэш источников: проверяется при аудите")
        self.progress_status = StringVar(value="Прогресс: ожидание")
        self.vulnerability_mode = StringVar(value=VULNERABILITY_MODE_FULL)
        self.network_scan_enabled = BooleanVar(value=False)
        self.network_capture_enabled = BooleanVar(value=False)
        self.network_targets = StringVar(value="")
        self.network_ports = StringVar(value=DEFAULT_LOCAL_NMAP_PORTS)
        self.network_extra_args = StringVar(value="")
        self.network_capture_interface = StringVar(value="")
        self.network_capture_excluded_interfaces = StringVar(value="")
        self.network_capture_duration = StringVar(value="20")
        self.network_capture_filter = StringVar(value="")
        self.network_capture_interfaces: list[dict[str, str]] = []
        self._capture_interface_checkbox_vars: dict[str, BooleanVar] = {}
        self._network_capture_interface_frame = None
        self._network_capture_interface_list_frame = None
        self.network_capture_interface_summary = StringVar(value="Интерфейсы не выбраны")
        self._network_topology_nodes: set[str] = set()
        self.network_nmap_no_dns = BooleanVar(value=True)
        self.network_nmap_skip_host_discovery = BooleanVar(value=True)
        self.network_nmap_timing = StringVar(value="T3")
        self.network_nmap_open_only = BooleanVar(value=True)
        self.network_nmap_os_detection = BooleanVar(value=False)
        self.network_nmap_service_detection = BooleanVar(value=True)
        self.network_capture_no_name_resolution = BooleanVar(value=True)
        self.network_capture_quiet = BooleanVar(value=True)
        self.last_report: str | None = None
        self._network_live_events: list[str] = []
        self._network_live_window: Toplevel | None = None
        self._network_live_text: scrolledtext.ScrolledText | None = None
        self._network_live_canvas: Canvas | None = None
        self._network_live_status = StringVar(value="Ожидание запуска")
        self._network_live_report_button: ttk.Button | None = None
        self._network_live_packet_table = None
        self._network_live_packet_details_text = None
        self._network_live_packet_hex_text = None
        self._network_live_packet_detail_cache: dict[str, tuple[str, str]] = {}
        self._network_live_nodes_table = None
        self._network_live_nmap_text: scrolledtext.ScrolledText | None = None
        self._network_live_security_text: scrolledtext.ScrolledText | None = None
        self._network_live_log_text: scrolledtext.ScrolledText | None = None
        self._network_live_summary_vars: dict[str, StringVar] = {}
        self.messages: queue.Queue[object] = queue.Queue()
        self.action_buttons: list[ttk.Button] = []
        self.active_cancel_token: CancellationToken | None = None
        self._last_responsive_layout: ResponsiveLayout | None = None
        self._applying_responsive_layout = False
        self._configure_styles()
        _frozen_startup_log("styles configured")
        self._build()
        _frozen_startup_log("widgets built")
        self.root.after(250, self._load_network_capture_interfaces)
        self.root.after(200, self._drain_messages)
        _frozen_startup_log("after callbacks scheduled")

    def _configure_styles(self) -> None:
        self.style = ttk.Style(self.root)
        self.style.theme_use("clam")
        self.style.configure("App.TFrame", background=COLORS["canvas"])
        self.style.configure("Header.TFrame", background=COLORS["header"])
        self.style.configure("Rail.TFrame", background=COLORS["rail"])
        self.style.configure("Panel.TFrame", background=COLORS["panel"])
        self.style.configure("Footer.TFrame", background=COLORS["canvas"])
        self.style.configure(
            "Title.TLabel",
            background=COLORS["header"],
            foreground="#FFFFFF",
            font=("Segoe UI Semibold", 19),
        )
        self.style.configure(
            "HeaderMuted.TLabel",
            background=COLORS["header"],
            foreground=COLORS["header_muted"],
            font=("Segoe UI", 10),
        )
        self.style.configure(
            "Section.TLabel",
            background=COLORS["panel"],
            foreground=COLORS["text"],
            font=("Segoe UI Semibold", 12),
        )
        self.style.configure(
            "RailSection.TLabel",
            background=COLORS["rail"],
            foreground=COLORS["muted"],
            font=("Segoe UI Semibold", 9),
        )
        self.style.configure(
            "Body.TLabel",
            background=COLORS["panel"],
            foreground=COLORS["text"],
            font=("Segoe UI", 10),
        )
        self.style.configure(
            "Muted.TLabel",
            background=COLORS["panel"],
            foreground=COLORS["muted"],
            font=("Segoe UI", 9),
        )
        self.style.configure(
            "Footer.TLabel",
            background=COLORS["canvas"],
            foreground=COLORS["muted"],
            font=("Segoe UI", 9),
        )
        self.style.configure(
            "Path.TLabel",
            background="#F7F9FA",
            foreground=COLORS["text"],
            font=("Segoe UI", 9),
            padding=(10, 8),
            relief="solid",
            borderwidth=1,
        )
        self.style.configure(
            "Primary.TButton",
            background=COLORS["teal"],
            foreground="#FFFFFF",
            borderwidth=0,
            font=("Segoe UI Semibold", 10),
            padding=(14, 11),
        )
        self.style.map(
            "Primary.TButton",
            background=[("active", COLORS["teal_hover"]), ("disabled", "#9FB8B5")],
            foreground=[("disabled", "#F4F7F7")],
        )
        self.style.configure(
            "Secondary.TButton",
            background="#EDF2F4",
            foreground=COLORS["text"],
            borderwidth=0,
            font=("Segoe UI Semibold", 10),
            padding=(14, 10),
        )
        self.style.map(
            "Secondary.TButton",
            background=[("active", "#DDE7EA"), ("disabled", "#F2F4F5")],
            foreground=[("disabled", "#98A5AA")],
        )
        self.style.configure(
            "Quiet.TButton",
            background=COLORS["panel"],
            foreground=COLORS["muted"],
            borderwidth=0,
            font=("Segoe UI", 9),
            padding=(8, 6),
        )
        self.style.map("Quiet.TButton", foreground=[("active", COLORS["text"])])
        self.style.configure(
            "Accent.Horizontal.TProgressbar",
            troughcolor="#DDE6E8",
            background=COLORS["teal"],
            bordercolor="#DDE6E8",
            lightcolor=COLORS["teal"],
            darkcolor=COLORS["teal"],
        )
        self.style.configure(
            "Mode.TRadiobutton",
            background=COLORS["panel"],
            foreground=COLORS["text"],
            font=("Segoe UI", 9),
        )
        self.style.configure(
            "Mode.TCheckbutton",
            background=COLORS["panel"],
            foreground=COLORS["text"],
            font=("Segoe UI", 9),
        )
        interface_styles = {
            "Traffic": ("#E8F8EF", "#065F46"),
            "Active": ("#FFF7D6", "#92400E"),
            "Quiet": ("#EEF2F7", "#475569"),
            "Inactive": ("#F4F5F7", "#6B7280"),
        }
        for name, (background, foreground) in interface_styles.items():
            self.style.configure(f"Interface{name}.TFrame", background=background)
            self.style.configure(
                f"Interface{name}.TCheckbutton",
                background=background,
                foreground=foreground,
                font=("Segoe UI Semibold" if name == "Traffic" else "Segoe UI", 9),
            )
            self.style.configure(
                f"Interface{name}.TLabel",
                background=foreground,
                foreground="#FFFFFF",
                font=("Segoe UI Semibold", 8),
                padding=(7, 3),
            )
        badge_styles = {
            "Ready.TLabel": (COLORS["header"], "#D7E0E3"),
            "Busy.TLabel": (COLORS["blue"], "#FFFFFF"),
            "Success.TLabel": (COLORS["green"], "#FFFFFF"),
            "Error.TLabel": (COLORS["red"], "#FFFFFF"),
            "Cancelled.TLabel": (COLORS["amber"], "#FFFFFF"),
        }
        for name, (background, foreground) in badge_styles.items():
            self.style.configure(
                name,
                background=background,
                foreground=foreground,
                font=("Segoe UI Semibold", 9),
                padding=(12, 7),
            )
        source_badges = {
            "Cisa.TLabel": ("#E8F0FF", COLORS["blue"]),
            "Nvd.TLabel": ("#F0EDFF", COLORS["violet"]),
            "Fstec.TLabel": ("#FFF1E7", COLORS["amber"]),
        }
        for name, (background, foreground) in source_badges.items():
            self.style.configure(
                name,
                background=background,
                foreground=foreground,
                font=("Segoe UI Semibold", 9),
                padding=(10, 6),
            )

    def _build(self) -> None:
        self._ensure_network_state()
        shell = ttk.Frame(self.root, style="App.TFrame")
        shell.pack(fill=BOTH, expand=True)
        self.shell = shell

        header = ttk.Frame(shell, style="Header.TFrame", padding=(26, 18))
        header.pack(fill=X)
        self.header = header
        heading = ttk.Frame(header, style="Header.TFrame")
        heading.pack(side=LEFT, fill=X, expand=True)
        ttk.Label(heading, text="IB Audit Workstation", style="Title.TLabel").pack(anchor="w")
        self.header_subtitle = ttk.Label(
            heading,
            text="Рабочая станция специалиста информационной безопасности",
            style="HeaderMuted.TLabel",
        )
        self.header_subtitle.pack(
            anchor="w", pady=(3, 0)
        )
        self.status_badge = ttk.Label(header, textvariable=self.status, style="Ready.TLabel")
        self.status_badge.pack(side=RIGHT, padx=(20, 0))

        footer = ttk.Frame(shell, style="Footer.TFrame", padding=(20, 4, 24, 8))
        footer.pack(side="bottom", fill=X)
        self.footer = footer
        self.footer_credit = ttk.Label(footer, text=DEVELOPER_CREDIT, style="Footer.TLabel")
        self.footer_credit.pack(side=RIGHT)

        body = ttk.Frame(shell, style="App.TFrame")
        body.pack(fill=BOTH, expand=True)
        self.body = body

        rail = ttk.Frame(body, style="Rail.TFrame", width=286, padding=(20, 22))
        rail.pack(side=LEFT, fill=Y)
        rail.pack_propagate(False)
        self.rail = rail
        ttk.Label(rail, text="НОВЫЙ АНАЛИЗ", style="RailSection.TLabel").pack(anchor="w", pady=(0, 12))

        live_button = ttk.Button(
            rail,
            text="Полный аудит компьютера",
            command=lambda: self._start(True),
            style="Primary.TButton",
            cursor="hand2",
        )
        live_button.pack(fill=X, pady=(0, 8))
        network_button = ttk.Button(
            rail,
            text="Сетевой аудит",
            command=lambda: self._start(True, network_only=True),
            style="Secondary.TButton",
            cursor="hand2",
        )
        network_button.pack(fill=X, pady=(0, 8))
        import_button = ttk.Button(
            rail,
            text="Проверить HTML-отчёты",
            command=self._choose_reports,
            style="Secondary.TButton",
            cursor="hand2",
        )
        import_button.pack(fill=X, pady=(0, 8))
        update_button = ttk.Button(
            rail, text="Обновить базы", command=self._update_sources,
            style="Secondary.TButton", cursor="hand2",
        )
        update_button.pack(fill=X, pady=(0, 8))
        self.cancel_button = ttk.Button(
            rail,
            text="Отменить",
            command=self._cancel_active,
            style="Secondary.TButton",
            cursor="hand2",
            state="disabled",
        )
        self.cancel_button.pack(fill=X)
        self.action_buttons = [live_button, network_button, import_button, update_button]

        ttk.Separator(rail, orient="horizontal").pack(fill=X, pady=24)
        ttk.Label(rail, text="РЕЗУЛЬТАТЫ", style="RailSection.TLabel").pack(anchor="w", pady=(0, 12))
        ttk.Button(
            rail,
            text="Открыть последний отчёт",
            command=self._open_report,
            style="Secondary.TButton",
            cursor="hand2",
        ).pack(fill=X, pady=(0, 8))
        ttk.Button(
            rail,
            text="Открыть папку отчётов",
            command=self._open_folder,
            style="Secondary.TButton",
            cursor="hand2",
        ).pack(fill=X)

        self.rail_note = ttk.Label(
            rail,
            text="Локальная обработка инвентаризации.\nСетевые запросы выполняются только\nк выбранным источникам уязвимостей.",
            style="Muted.TLabel",
            justify="left",
        )
        self.rail_note.pack(side="bottom", anchor="w")

        workspace = ttk.Frame(body, style="App.TFrame", padding=(22, 20, 24, 18))
        workspace.pack(side=RIGHT, fill=BOTH, expand=True)
        self.workspace = workspace

        sources = ttk.Frame(workspace, style="Panel.TFrame", padding=(16, 14))
        sources.pack(fill=X, pady=(0, 12))
        ttk.Label(sources, text="Источники проверки", style="Section.TLabel").pack(side=LEFT)
        ttk.Label(sources, text=SOURCE_LABELS[0], style="Cisa.TLabel").pack(side=LEFT, padx=(18, 6))
        ttk.Label(sources, text=SOURCE_LABELS[1], style="Nvd.TLabel").pack(side=LEFT, padx=6)
        ttk.Label(sources, text=SOURCE_LABELS[2], style="Fstec.TLabel").pack(side=LEFT, padx=6)
        self.source_status_label = ttk.Label(sources, textvariable=self.source_status, style="Muted.TLabel")
        self.source_status_label.pack(side=RIGHT)

        mode_panel = ttk.Frame(workspace, style="Panel.TFrame", padding=(16, 13))
        mode_panel.pack(fill=X, pady=(0, 12))
        ttk.Label(mode_panel, text="Режим проверки уязвимостей", style="Section.TLabel").pack(side=LEFT)
        ttk.Radiobutton(
            mode_panel,
            text=VULNERABILITY_MODE_TEXT[VULNERABILITY_MODE_FULL],
            variable=self.vulnerability_mode,
            value=VULNERABILITY_MODE_FULL,
            style="Mode.TRadiobutton",
        ).pack(side=LEFT, padx=(18, 6))
        ttk.Radiobutton(
            mode_panel,
            text=VULNERABILITY_MODE_TEXT[VULNERABILITY_MODE_FAST],
            variable=self.vulnerability_mode,
            value=VULNERABILITY_MODE_FAST,
            style="Mode.TRadiobutton",
        ).pack(side=LEFT, padx=6)

        network_panel = ttk.Frame(workspace, style="Panel.TFrame", padding=(16, 13))
        network_panel.pack(fill=X, pady=(0, 12))
        network_header = ttk.Frame(network_panel, style="Panel.TFrame")
        network_header.pack(fill=X, pady=(0, 8))
        ttk.Label(network_header, text="Сетевая проверка", style="Section.TLabel").pack(side=LEFT)
        ttk.Checkbutton(
            network_header,
            text="Включить Nmap",
            variable=self.network_scan_enabled,
            style="Mode.TCheckbutton",
        ).pack(side=LEFT, padx=(18, 8))
        ttk.Checkbutton(
            network_header,
            text="Захват трафика",
            variable=self.network_capture_enabled,
            style="Mode.TCheckbutton",
        ).pack(side=LEFT, padx=(8, 0))
        command_button = ttk.Button(
            network_header,
            text="Команды сети",
            command=self._open_network_commands,
            style="Quiet.TButton",
            cursor="hand2",
        )
        command_button.pack(side=RIGHT)
        _Tooltip(
            command_button,
            "Открывает окно выбора nmap/tshark-команд, дополнительных аргументов и фильтра захвата.",
        )
        network_targets_row = ttk.Frame(network_panel, style="Panel.TFrame")
        network_targets_row.pack(fill=X, pady=(0, 8))
        ttk.Label(network_targets_row, text="Цели", style="Muted.TLabel").pack(side=LEFT)
        ttk.Entry(network_targets_row, textvariable=self.network_targets).pack(side=LEFT, fill=X, expand=True, padx=(12, 0))
        network_options_row = ttk.Frame(network_panel, style="Panel.TFrame")
        network_options_row.pack(fill=X)
        ttk.Label(network_options_row, text="Порты", style="Muted.TLabel").pack(side=LEFT)
        ttk.Entry(network_options_row, textvariable=self.network_ports, width=18).pack(side=LEFT, padx=(12, 14))
        ttk.Label(network_options_row, text="Nmap args", style="Muted.TLabel").pack(side=LEFT)
        ttk.Entry(network_options_row, textvariable=self.network_extra_args).pack(side=LEFT, fill=X, expand=True, padx=(12, 14))
        ttk.Label(network_options_row, text="Сек", style="Muted.TLabel").pack(side=LEFT)
        ttk.Entry(network_options_row, textvariable=self.network_capture_duration, width=6).pack(side=LEFT, padx=(8, 0))
        self._network_capture_interface_frame = ttk.Frame(network_panel, style="Panel.TFrame")
        self._network_capture_interface_frame.pack(fill=X, pady=(8, 0))
        interface_header = ttk.Frame(self._network_capture_interface_frame, style="Panel.TFrame")
        interface_header.pack(fill=X)
        ttk.Label(interface_header, text="Интерфейсы захвата", style="Muted.TLabel").pack(side=LEFT)
        ttk.Button(
            interface_header,
            text="Загрузить интерфейсы",
            command=self._load_network_capture_interfaces,
            style="Quiet.TButton",
            cursor="hand2",
        ).pack(side=LEFT, padx=(12, 0))
        ttk.Label(
            interface_header,
            textvariable=self.network_capture_interface_summary,
            style="Muted.TLabel",
        ).pack(side=RIGHT)
        self._build_network_capture_interface_scroll_area()
        self._build_network_capture_interface_checkbox_panel()

        output_panel = ttk.Frame(workspace, style="Panel.TFrame", padding=(16, 13))
        output_panel.pack(fill=X, pady=(0, 12))
        output_header = ttk.Frame(output_panel, style="Panel.TFrame")
        output_header.pack(fill=X, pady=(0, 8))
        ttk.Label(output_header, text="Папка отчётов", style="Section.TLabel").pack(side=LEFT)
        ttk.Button(
            output_header,
            text="Изменить",
            command=self._choose_output,
            style="Quiet.TButton",
            cursor="hand2",
        ).pack(side=RIGHT)
        self.path_label = ttk.Label(
            output_panel,
            textvariable=self.output_dir,
            style="Path.TLabel",
            anchor="w",
            justify="left",
        )
        self.path_label.pack(fill=X)

        journal = ttk.Frame(workspace, style="Panel.TFrame", padding=(16, 14))
        journal.pack(fill=BOTH, expand=True)
        journal_header = ttk.Frame(journal, style="Panel.TFrame")
        journal_header.pack(fill=X, pady=(0, 9))
        ttk.Label(journal_header, text="Журнал выполнения", style="Section.TLabel").pack(side=LEFT)
        ttk.Button(
            journal_header,
            text="Очистить",
            command=self._clear_log,
            style="Quiet.TButton",
            cursor="hand2",
        ).pack(side=RIGHT)
        progress_panel = ttk.Frame(journal, style="Panel.TFrame")
        progress_panel.pack(fill=X, pady=(0, 10))
        self.progress_status_label = ttk.Label(progress_panel, textvariable=self.progress_status, style="Muted.TLabel")
        self.progress_status_label.pack(
            anchor="w", pady=(0, 4)
        )
        self.progress = ttk.Progressbar(
            journal,
            mode="determinate",
            maximum=100,
            value=0,
            style="Accent.Horizontal.TProgressbar",
        )
        self.progress.pack(fill=X, pady=(0, 10))
        self.log = scrolledtext.ScrolledText(
            journal,
            wrap="word",
            font=("Cascadia Mono", 9),
            background="#F8FAFB",
            foreground=COLORS["text"],
            insertbackground=COLORS["text"],
            selectbackground="#CDE8E5",
            relief="flat",
            borderwidth=0,
            padx=12,
            pady=10,
            state="disabled",
        )
        self.log.pack(fill=BOTH, expand=True)
        self._apply_responsive_layout(getattr(getattr(self, "window_bounds", None), "width", 1080))
        if hasattr(self.root, "bind"):
            self.root.bind("<Configure>", self._on_root_configure)
        self._log("Рабочая станция готова. Для полного сбора запустите приложение от администратора.")

    def _ensure_network_state(self) -> None:
        def ensure(name: str, value: object, boolean: bool = False) -> None:
            if hasattr(self, name):
                return
            try:
                variable = BooleanVar(value=bool(value)) if boolean else StringVar(value=str(value))
            except Exception:
                variable = _FallbackVar(value)
            setattr(self, name, variable)

        ensure("network_scan_enabled", False, boolean=True)
        ensure("network_capture_enabled", False, boolean=True)
        ensure("network_targets", "")
        ensure("network_ports", "1-65535")
        ensure("network_extra_args", "")
        ensure("network_capture_interface", "")
        ensure("network_capture_excluded_interfaces", "")
        ensure("network_capture_duration", "20")
        ensure("network_capture_filter", "")
        ensure("network_nmap_no_dns", True, boolean=True)
        ensure("network_nmap_skip_host_discovery", True, boolean=True)
        ensure("network_nmap_timing", "T2")
        ensure("network_nmap_open_only", True, boolean=True)
        ensure("network_nmap_os_detection", True, boolean=True)
        ensure("network_nmap_service_detection", True, boolean=True)
        ensure("network_capture_no_name_resolution", True, boolean=True)
        ensure("network_capture_quiet", True, boolean=True)
        if not hasattr(self, "network_capture_interfaces"):
            self.network_capture_interfaces = []
        if not hasattr(self, "_capture_interface_checkbox_vars"):
            self._capture_interface_checkbox_vars = {}
        if not hasattr(self, "_network_capture_interface_frame"):
            self._network_capture_interface_frame = None
        if not hasattr(self, "_network_capture_interface_list_frame"):
            self._network_capture_interface_list_frame = None
        if not hasattr(self, "_network_capture_interface_canvas"):
            self._network_capture_interface_canvas = None
        if not hasattr(self, "_network_capture_interface_scrollbar"):
            self._network_capture_interface_scrollbar = None
        if not hasattr(self, "network_capture_interface_summary"):
            try:
                self.network_capture_interface_summary = StringVar(value="Интерфейсы не выбраны")
            except Exception:
                self.network_capture_interface_summary = _FallbackVar("Интерфейсы не выбраны")
        if not hasattr(self, "_network_topology_nodes"):
            self._network_topology_nodes = set()
        if not hasattr(self, "_network_live_events"):
            self._network_live_events = []
        if not hasattr(self, "_network_live_window"):
            self._network_live_window = None
        if not hasattr(self, "_network_live_text"):
            self._network_live_text = None
        if not hasattr(self, "_network_live_canvas"):
            self._network_live_canvas = None
        if not hasattr(self, "_network_live_status"):
            try:
                self._network_live_status = StringVar(value="Ожидание запуска")
            except Exception:
                self._network_live_status = _FallbackVar("Ожидание запуска")
        if not hasattr(self, "_network_live_report_button"):
            self._network_live_report_button = None
        self._network_live_packet_table = None
        self._network_live_packet_details_text = None
        self._network_live_packet_hex_text = None
        self._network_live_packet_detail_cache = {}
        self._network_live_nodes_table = None
        self._network_live_nmap_text = None
        self._network_live_security_text = None
        self._network_live_log_text = None
        self._network_live_summary_vars = {}

    def _build_network_capture_interface_scroll_area(self) -> None:
        frame = self._network_capture_interface_frame
        if frame is None:
            return
        container = ttk.Frame(frame, style="Panel.TFrame")
        container.pack(fill=X, pady=(4, 0))
        try:
            canvas = Canvas(
                container,
                height=142,
                bg=COLORS["panel"],
                highlightthickness=1,
                highlightbackground=COLORS["border"],
                borderwidth=0,
            )
            scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
            list_frame = ttk.Frame(canvas, style="Panel.TFrame")
            window_id = canvas.create_window((0, 0), window=list_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            list_frame.bind("<Configure>", lambda _event: self._refresh_network_capture_scroll_region())
            canvas.bind("<Configure>", lambda event: canvas.itemconfigure(window_id, width=event.width))
            canvas.pack(side=LEFT, fill=X, expand=True)
            scrollbar.pack(side=RIGHT, fill=Y)
            self._network_capture_interface_canvas = canvas
            self._network_capture_interface_scrollbar = scrollbar
            self._network_capture_interface_list_frame = list_frame
        except Exception:
            list_frame = ttk.Frame(container, style="Panel.TFrame")
            list_frame.pack(fill=X)
            self._network_capture_interface_canvas = None
            self._network_capture_interface_scrollbar = None
            self._network_capture_interface_list_frame = list_frame

    def _refresh_network_capture_scroll_region(self) -> None:
        canvas = getattr(self, "_network_capture_interface_canvas", None)
        if canvas is None:
            return
        try:
            canvas.configure(scrollregion=canvas.bbox("all"))
        except Exception:
            return

    def _network_option_var(self, config_field: str) -> object:
        self._ensure_network_state()
        variable_name = f"network_{config_field}"
        return getattr(self, variable_name)

    def _network_bool_value(self, variable_name: str, default: bool = False) -> bool:
        self._ensure_network_state()
        variable = getattr(self, variable_name, None)
        if variable is None:
            return default
        try:
            return bool(variable.get())
        except Exception:
            return default

    def _network_string_value(self, variable_name: str, default: str = "") -> str:
        self._ensure_network_state()
        variable = getattr(self, variable_name, None)
        if variable is None:
            return default
        try:
            return str(variable.get()).strip()
        except Exception:
            return default

    def _network_interface_tokens(self, variable_name: str) -> tuple[str, ...]:
        raw = self._network_string_value(variable_name)
        tokens: list[str] = []
        for raw_token in raw.replace(";", ",").split(","):
            token = raw_token.strip()
            if token:
                tokens.append(token)
        return tuple(dict.fromkeys(tokens))

    def _is_interface_disabled(self, candidate: dict[str, str], disabled: tuple[str, ...]) -> bool:
        disabled_set = {_token.strip().lower() for _token in disabled if _token.strip()}
        for value in (
            candidate.get("index", ""),
            candidate.get("name", ""),
            candidate.get("description", ""),
        ):
            if str(value).strip().lower() in disabled_set:
                return True
        return False

    def _network_interface_id(self, candidate: dict[str, str]) -> str:
        return (
            (candidate.get("name") or "").strip()
            or (candidate.get("index") or "").strip()
            or (candidate.get("description") or "").strip()
        )

    def _network_capture_interface_tokens_from_ui(self) -> tuple[str, ...]:
        self._ensure_network_state()
        selected: list[str] = []
        seen_tokens: set[str] = set()
        for token, variable in self._capture_interface_checkbox_vars.items():
            try:
                enabled = bool(variable.get())
            except Exception:
                enabled = False
            normalized = str(token or "").strip()
            if not enabled or not normalized:
                continue
            key = normalized.lower()
            if key in seen_tokens:
                continue
            seen_tokens.add(key)
            selected.append(normalized)
        fallback = self._network_string_value("network_capture_interface")
        for raw in fallback.replace(";", ",").split(","):
            token = raw.strip()
            if not token:
                continue
            key = token.lower()
            if key in seen_tokens:
                continue
            seen_tokens.add(key)
            selected.append(token)
        return tuple(selected)

    def _network_capture_disabled_interfaces_from_ui(self) -> tuple[str, ...]:
        self._ensure_network_state()
        disabled: set[str] = {_token.lower() for _token in self._network_interface_tokens("network_capture_excluded_interfaces")}
        for candidate in self.network_capture_interfaces:
            token = self._network_interface_id(candidate).lower()
            variable = self._capture_interface_checkbox_vars.get(token)
            if variable is None:
                continue
            try:
                is_enabled = bool(variable.get())
            except Exception:
                is_enabled = True
            if not is_enabled:
                disabled.add(token)
        return tuple(disabled)

    def _update_capture_interface_summary(self) -> None:
        self._ensure_network_state()
        selected = self._network_capture_interface_tokens_from_ui()
        total = len(self.network_capture_interfaces)
        if not total:
            self.network_capture_interface_summary.set("Интерфейсы не загружены")
            return
        if selected:
            self.network_capture_interface_summary.set(f"Выбрано {len(selected)} из {total}")
        else:
            self.network_capture_interface_summary.set("Не выбрано (захват отключён)")

    def _build_network_capture_interface_checkbox_panel(self) -> None:
        self._ensure_network_state()
        frame = self._network_capture_interface_list_frame or self._network_capture_interface_frame
        if frame is None:
            return
        if hasattr(frame, "winfo_children"):
            children = list(frame.winfo_children())
        else:
            children = list(getattr(frame, "children", []))
        for child in children:
            if hasattr(child, "destroy"):
                child.destroy()
        if hasattr(frame, "children"):
            try:
                frame.children.clear()
            except Exception:
                pass
        if not self.network_capture_interfaces:
            ttk.Label(
                frame,
                text="Интерфейсы не загружены. Нажмите «Загрузить интерфейсы».",
                style="Muted.TLabel",
            ).pack(anchor="w", padx=(2, 0), pady=(2, 0))
            self.network_capture_interface_summary.set("Интерфейсы не загружены")
            self._refresh_network_capture_scroll_region()
            return
        check_group = ttk.Frame(frame, style="Panel.TFrame")
        check_group.pack(fill=X)
        selected_tokens = {token.lower() for token in self._network_interface_tokens("network_capture_interface")}
        disabled = {_token.lower() for _token in self._network_interface_tokens("network_capture_excluded_interfaces")}
        new_vars: dict[str, BooleanVar] = {}
        for candidate in self.network_capture_interfaces:
            token = self._network_interface_id(candidate)
            if not token:
                continue
            key = token.lower()
            variable = self._capture_interface_checkbox_vars.get(key)
            if variable is None:
                variable = BooleanVar(value=key in selected_tokens)
            tone = self._network_capture_interface_tone(candidate)
            row = ttk.Frame(check_group, style=f"Interface{tone}.TFrame")
            row.pack(fill=X, pady=2)
            badge = ttk.Label(
                row,
                text=self._network_capture_interface_badge(candidate),
                style=f"Interface{tone}.TLabel",
            )
            badge.pack(side=LEFT, anchor="w", padx=(0, 6))
            label = self._network_capture_interface_label(candidate)
            check = ttk.Checkbutton(
                row,
                text=label,
                variable=variable,
                style=f"Interface{tone}.TCheckbutton",
            )
            check.pack(side=LEFT, anchor="w")
            tooltip_text = self._network_capture_interface_tooltip(candidate)
            _Tooltip(badge, tooltip_text)
            _Tooltip(check, tooltip_text)
            if hasattr(variable, "trace_add"):
                variable.trace_add("write", lambda *_args: self._update_capture_interface_summary())
            new_vars[key] = variable
            if key in disabled:
                try:
                    variable.set(False)
                except Exception:
                    pass
        self._capture_interface_checkbox_vars = new_vars
        self._update_capture_interface_summary()
        self._refresh_network_capture_scroll_region()

    def _network_capture_interface_tone(self, candidate: dict[str, str]) -> str:
        if self._network_capture_interface_has_traffic(candidate):
            return "Traffic"
        if str(candidate.get("active") or "").strip().lower() == "yes":
            return "Active"
        if str(candidate.get("kind") or "").strip().lower() in {"extcap", "loopback", "virtual", "vpn", "bluetooth"}:
            return "Quiet"
        return "Inactive"

    def _network_capture_interface_badge(self, candidate: dict[str, str]) -> str:
        tone = self._network_capture_interface_tone(candidate)
        if tone == "Traffic":
            return "\u0414\u0410\u041d\u041d\u042b\u0415"
        if tone == "Active":
            return "\u041b\u0418\u041d\u041a"
        if tone == "Quiet":
            return "\u0421\u041b\u0423\u0416."
        return "\u041d\u0415\u0422"

    def _network_capture_interface_has_traffic(self, candidate: dict[str, str]) -> bool:
        if str(candidate.get("traffic_active") or "").strip().lower() == "yes":
            return True
        for key in ("received_bytes", "sent_bytes", "ReceivedBytes", "SentBytes"):
            try:
                if int(str(candidate.get(key) or "0").strip()) > 0:
                    return True
            except ValueError:
                continue
        return False

    def _network_capture_interface_traffic_text(self, candidate: dict[str, str]) -> str:
        if not self._network_capture_interface_has_traffic(candidate):
            return ""
        received = str(candidate.get("received_bytes") or candidate.get("ReceivedBytes") or "0").strip()
        sent = str(candidate.get("sent_bytes") or candidate.get("SentBytes") or "0").strip()
        return f"\u0442\u0440\u0430\u0444\u0438\u043a RX={received} TX={sent}"

    def _network_capture_interface_label(self, candidate: dict[str, str]) -> str:
        token = self._network_interface_id(candidate)
        friendly = (candidate.get("friendly_name") or candidate.get("description") or token).strip()
        status = self._network_capture_interface_status_text(candidate)
        kind = self._network_capture_interface_kind_text(candidate)
        link_speed = (candidate.get("link_speed") or "").strip()
        suffix = f"; {link_speed}" if link_speed else ""
        traffic_text = self._network_capture_interface_traffic_text(candidate)
        if traffic_text:
            suffix += f"; {traffic_text}"
        return f"[{token}] {friendly} - {status}; {kind}{suffix}"

    def _network_capture_interface_tooltip(self, candidate: dict[str, str]) -> str:
        return (
            f"Индекс: {candidate.get('index', '-')}; "
            f"Имя: {candidate.get('name', '-')}; "
            f"Статус: {candidate.get('status', '-')}; "
            f"Тип: {candidate.get('kind', '-')}; "
            f"Описание: {candidate.get('description', '-')}"
        )

    def _network_capture_interface_status_text(self, candidate: dict[str, str]) -> str:
        active = (candidate.get("active") or "").strip().lower()
        status = (candidate.get("status") or "").strip()
        if active == "yes":
            return "\u0410\u043a\u0442\u0438\u0432\u0435\u043d"
        if active == "no":
            return "\u041d\u0435\u0430\u043a\u0442\u0438\u0432\u0435\u043d" if status and status.lower() != "service" else "\u0421\u043b\u0443\u0436\u0435\u0431\u043d\u044b\u0439"
        return f"\u0421\u0442\u0430\u0442\u0443\u0441: {status}" if status else "\u0421\u0442\u0430\u0442\u0443\u0441 \u043d\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u0435\u043d"

    def _network_capture_interface_kind_text(self, candidate: dict[str, str]) -> str:
        kind = (candidate.get("kind") or "").strip().lower()
        return {
            "physical": "\u0444\u0438\u0437\u0438\u0447\u0435\u0441\u043a\u0438\u0439",
            "virtual": "\u0432\u0438\u0440\u0442\u0443\u0430\u043b\u044c\u043d\u044b\u0439",
            "vpn": "VPN",
            "loopback": "loopback",
            "extcap": "\u0441\u043b\u0443\u0436\u0435\u0431\u043d\u044b\u0439",
            "bluetooth": "Bluetooth",
        }.get(kind, kind or "\u0442\u0438\u043f \u043d\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u0435\u043d")

    def _load_network_capture_interfaces(self) -> None:
        self._ensure_network_state()
        self.network_capture_interface_summary.set("Поиск интерфейсов…")
        candidates, error = detect_tshark_interfaces()
        if not candidates:
            if error:
                self._log(f"Не удалось найти интерфейсы: {error}")
                message = f"Ошибка поиска интерфейсов: {error}"
            else:
                message = "Интерфейсы не обнаружены."
            self._append_network_scan_event(message)
            self.network_capture_interfaces = []
            self._build_network_capture_interface_checkbox_panel()
            if error:
                self.network_capture_interface_summary.set(error)
            return
        self.network_capture_interfaces = candidates
        self._build_network_capture_interface_checkbox_panel()
        self._log(f"Загружено {len(candidates)} интерфейсов для захвата")
        self._append_network_scan_event(f"Найдено {len(candidates)} интерфейсов захвата")

    def _open_network_commands(self) -> None:
        self._ensure_network_state()
        dialog = Toplevel(self.root)
        dialog.title("Команды сетевой проверки")
        dialog.geometry("760x640")
        dialog.minsize(680, 520)
        dialog.configure(background=COLORS["canvas"])
        container = ttk.Frame(dialog, style="Panel.TFrame", padding=(18, 16))
        container.pack(fill=BOTH, expand=True)
        ttk.Label(
            container,
            text="Профиль Nmap и tshark/Wireshark",
            style="Section.TLabel",
        ).pack(anchor="w", pady=(0, 6))
        ttk.Label(
            container,
            text=(
                "Отметьте команды, которые нужно использовать при сетевой проверке. "
                "Подсказка по каждой команде доступна при наведении мыши."
            ),
            style="Muted.TLabel",
            wraplength=700,
            justify="left",
        ).pack(anchor="w", pady=(0, 14))
        self._build_network_command_group(container, "Nmap: обнаружение узлов, портов, сервисов и ОС", "nmap")
        self._build_network_command_group(container, "tshark/Wireshark: захват и агрегация трафика", "tshark")
        self._build_network_command_entries(container)
        ttk.Button(
            container,
            text="Закрыть",
            command=dialog.destroy,
            style="Secondary.TButton",
            cursor="hand2",
        ).pack(anchor="e", pady=(14, 0))

    def _build_network_command_group(self, parent: object, title: str, group: str) -> None:
        frame = ttk.Frame(parent, style="Panel.TFrame")
        frame.pack(fill=X, pady=(0, 10))
        ttk.Label(frame, text=title, style="Body.TLabel").pack(anchor="w", pady=(0, 5))
        for option in NETWORK_COMMAND_OPTIONS:
            if option.group != group:
                continue
            row = ttk.Frame(frame, style="Panel.TFrame")
            row.pack(fill=X, pady=2)
            check = ttk.Checkbutton(
                row,
                text=f"{option.command_preview} — {option.label}",
                variable=self._network_option_var(option.config_field),
                style="Mode.TCheckbutton",
            )
            check.pack(side=LEFT, fill=X, expand=True)
            _Tooltip(check, option.description_ru)

    def _build_network_command_entries(self, parent: object) -> None:
        frame = ttk.Frame(parent, style="Panel.TFrame")
        frame.pack(fill=X, pady=(4, 0))
        ttk.Label(frame, text="Параметры команд", style="Body.TLabel").pack(anchor="w", pady=(0, 6))
        rows = (
            ("Цели Nmap", self.network_targets, "Например: 192.168.1.0/24, 10.10.10.5 или имя узла."),
            ("Порты Nmap", self.network_ports, "Например: 1-65535, 80,443,3389 или T:1-1024,U:53."),
            ("Профиль скорости", self.network_nmap_timing, "Значение nmap -T0..-T5. По умолчанию T2 — осторожный режим."),
            ("Доп. аргументы Nmap", self.network_extra_args, "Аргументы добавляются в конец nmap-команды перед целями."),
            ("Отключенные интерфейсы", self.network_capture_excluded_interfaces, "Через ; или , перечислите интерфейсы из -D, которые нужно пропустить."),
            ("Длительность захвата, сек", self.network_capture_duration, "Ограничение tshark через -a duration:<секунды>."),
            ("Фильтр захвата", self.network_capture_filter, "BPF-фильтр tshark -f, например: tcp port 443 или host 192.168.1.10."),
        )
        for label_text, variable, tooltip in rows:
            row = ttk.Frame(frame, style="Panel.TFrame")
            row.pack(fill=X, pady=3)
            label = ttk.Label(row, text=label_text, style="Muted.TLabel", width=24)
            label.pack(side=LEFT)
            entry = ttk.Entry(row, textvariable=variable)
            entry.pack(side=LEFT, fill=X, expand=True, padx=(10, 0))
            _Tooltip(label, tooltip)
            _Tooltip(entry, tooltip)

    def _on_root_configure(self, event: object) -> None:
        root = getattr(self, "root", None)
        if root is not None and getattr(event, "widget", root) is not root:
            return
        if root is not None and hasattr(root, "state"):
            try:
                if root.state() in {"iconic", "withdrawn"}:
                    return
            except Exception:
                pass
        width = int(getattr(event, "width", 0) or 0)
        if width <= 0:
            return
        height = getattr(event, "height", None)
        if height is not None and (width < 200 or int(height or 0) < 200):
            return
        self._apply_responsive_layout(width)

    def _configure_widget(self, attribute: str, **options: object) -> None:
        widget = getattr(self, attribute, None)
        if widget is not None:
            widget.configure(**options)

    def _apply_responsive_layout(self, width: int) -> None:
        if getattr(self, "_applying_responsive_layout", False):
            return
        layout = responsive_layout_for_width(width)
        if getattr(self, "_last_responsive_layout", None) == layout:
            return
        self._last_responsive_layout = layout
        self._applying_responsive_layout = True
        try:
            self._configure_widget("header", padding=layout.header_padding)
            self._configure_widget("footer", padding=layout.footer_padding)
            self._configure_widget("rail", width=layout.rail_width, padding=layout.rail_padding)
            self._configure_widget("workspace", padding=layout.workspace_padding)
            self._configure_widget("path_label", wraplength=layout.path_wraplength)
            self._configure_widget("source_status_label", wraplength=layout.status_wraplength, justify="right")
            self._configure_widget("progress_status_label", wraplength=layout.path_wraplength, justify="left")
            self._configure_widget("status_badge", wraplength=layout.status_wraplength)
            self._configure_widget("footer_credit", wraplength=layout.path_wraplength)
            self._configure_widget("rail_note", wraplength=layout.note_wraplength)
            self._configure_widget("header_subtitle", wraplength=layout.header_wraplength)
        finally:
            self._applying_responsive_layout = False

    def _choose_output(self) -> None:
        selected = filedialog.askdirectory(initialdir=self.output_dir.get())
        if selected:
            self.output_dir.set(selected)
            self.db_path.set(str(Path(selected) / "ib_audit.db"))
            self._log(f"Папка отчётов: {selected}")

    def _choose_reports(self) -> None:
        selected = filedialog.askopenfilenames(
            title="Выберите HTML-отчёты WinAudit или IB Audit Workstation",
            filetypes=[("HTML-отчёты", "*.html *.htm"), ("Все файлы", "*.*")],
        )
        if not selected:
            return
        selected = tuple(selected)
        token = self._begin_operation(f"Проверка HTML-отчётов: {len(selected)}")
        self._log("=== Пакетная проверка локальных HTML-отчётов ===")
        for path in selected:
            self._log(path)
        mode = self._selected_vulnerability_mode()
        self._log(f"Режим уязвимостей: {VULNERABILITY_MODE_TEXT[mode]}")
        thread = threading.Thread(
            target=self._run_reports_background,
            args=(selected, mode, token),
            daemon=True,
        )
        thread.start()

    def _start(self, online_sources: bool, network_only: bool = False) -> None:
        mode = self._selected_vulnerability_mode()
        network_scan = self._selected_network_scan_config()
        if network_only and network_scan is None:
            network_scan = self._build_default_network_only_scan_config()
        if self._handle_missing_capture_interface_for_network_scan(network_scan):
            return
        if self._handle_missing_npcap_for_network_scan(network_scan):
            return
        status = "Аудит сети" if network_only else "Полный аудит рабочей станции"
        token = self._begin_operation(status)
        self._log("=== Аудит сети ===" if network_only else "=== Полный аудит ===")
        self._log(f"Режим уязвимостей: {VULNERABILITY_MODE_TEXT[mode]}")
        if network_scan is not None and hasattr(self, "root"):
            self._start_network_scan_live_window(network_scan, network_only)
        if network_scan is not None or network_only:
            thread_args = (online_sources, mode, token, network_scan, network_only)
        else:
            thread_args = (online_sources, mode, token)
        thread = threading.Thread(
            target=self._run_background,
            args=thread_args,
            daemon=True,
        )
        thread.start()

    def _handle_missing_capture_interface_for_network_scan(self, network_scan: NetworkScanConfig | None) -> bool:
        if network_scan is None or not network_scan.capture_enabled or not hasattr(self, "root"):
            return False
        if network_scan.capture_interfaces or network_scan.capture_interface:
            return False
        messagebox.showwarning(
            "\u0412\u044b\u0431\u0435\u0440\u0438\u0442\u0435 \u0438\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441 \u0437\u0430\u0445\u0432\u0430\u0442\u0430",
            "\u0417\u0430\u0445\u0432\u0430\u0442 \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u0432\u043a\u043b\u044e\u0447\u0451\u043d, \u043d\u043e \u0441\u0435\u0442\u0435\u0432\u043e\u0439 \u0438\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441 \u043d\u0435 \u0432\u044b\u0431\u0440\u0430\u043d.\n\n"
            "\u0410\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u0438\u0439 \u0437\u0430\u0445\u0432\u0430\u0442 \u043f\u043e \u0432\u0441\u0435\u043c \u0438\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u0430\u043c \u043e\u0442\u043a\u043b\u044e\u0447\u0451\u043d \u0434\u043b\u044f \u0441\u0442\u0430\u0431\u0438\u043b\u044c\u043d\u043e\u0441\u0442\u0438 \u0441\u0438\u0441\u0442\u0435\u043c\u044b. "
            "Нажмите «Загрузить интерфейсы» и отметьте один активный интерфейс.",
        )
        return True

    def _handle_missing_npcap_for_network_scan(self, network_scan: NetworkScanConfig | None) -> bool:
        # Normal network audit uses safe Windows connection telemetry instead of
        # Npcap/tshark live packet capture. Npcap is therefore not required here:
        # repeated bugchecks showed that even one selected interface can crash in
        # the kernel driver path, which Python cannot catch safely.
        return False
        if network_scan is None or not network_scan.capture_enabled or not hasattr(self, "root"):
            return False
        status = query_npcap_status()
        if not status.install_required:
            return False

        installer = resolve_npcap_installer()
        if installer is not None:
            install_now = messagebox.askyesno(
                "Npcap требуется для захвата",
                "Для захвата сетевого трафика нужен драйвер Npcap.\n\n"
                "Установить Npcap сейчас? После установки потребуется повторно запустить аудит.",
            )
            if install_now:
                result = launch_npcap_installer(installer)
                if result.ok:
                    messagebox.showinfo(
                        "Npcap",
                        "Установка Npcap запущена. После установки повторно запустите аудит.",
                    )
                else:
                    messagebox.showwarning("Npcap", result.message)
            return True

        open_download = messagebox.askyesno(
            "Npcap требуется для захвата",
            "Для захвата сетевого трафика нужен драйвер Npcap, но встроенный установщик не найден.\n\n"
            "Открыть официальный сайт Npcap для ручной установки?",
        )
        if open_download:
            webbrowser.open(NPCAP_DOWNLOAD_URL)
        return True

    def _selected_vulnerability_mode(self) -> str:
        mode = self.vulnerability_mode.get()
        if mode in VULNERABILITY_MODE_TEXT:
            return mode
        return VULNERABILITY_MODE_FULL

    def _selected_network_scan_config(self) -> NetworkScanConfig | None:
        self._ensure_network_state()
        enabled = self._network_bool_value("network_scan_enabled") or self._network_bool_value("network_capture_enabled")
        if not enabled:
            return None
        targets = tuple(
            item.strip()
            for item in self._network_string_value("network_targets").replace(";", ",").split(",")
            if item.strip()
        )
        if not targets:
            targets = local_machine_nmap_targets()
        try:
            capture_duration = int(self._network_string_value("network_capture_duration", "20") or "20")
        except ValueError:
            capture_duration = 20
        capture_interfaces = self._network_capture_interface_tokens_from_ui()
        capture_interface = capture_interfaces[0] if capture_interfaces else None
        return NetworkScanConfig(
            enabled=True,
            nmap_enabled=self._network_bool_value("network_scan_enabled", False),
            targets=targets,
            ports=self._network_string_value("network_ports", DEFAULT_LOCAL_NMAP_PORTS) or DEFAULT_LOCAL_NMAP_PORTS,
            extra_args=self._network_string_value("network_extra_args"),
            nmap_no_dns=self._network_bool_value("network_nmap_no_dns", True),
            nmap_skip_host_discovery=self._network_bool_value("network_nmap_skip_host_discovery", True),
            nmap_timing=self._network_string_value("network_nmap_timing", "T2") or "T2",
            nmap_open_only=self._network_bool_value("network_nmap_open_only", True),
            nmap_os_detection=self._network_bool_value("network_nmap_os_detection", False),
            nmap_service_detection=self._network_bool_value("network_nmap_service_detection", True),
            capture_enabled=self._network_bool_value("network_capture_enabled"),
            capture_interfaces=capture_interfaces,
            capture_interface=capture_interface,
            capture_disabled_interfaces=self._network_capture_disabled_interfaces_from_ui(),
            capture_duration=max(1, capture_duration),
            capture_filter=self._network_string_value("network_capture_filter"),
            capture_no_name_resolution=self._network_bool_value("network_capture_no_name_resolution", True),
            capture_quiet=self._network_bool_value("network_capture_quiet", True),
        )

    def _build_default_network_only_scan_config(self) -> NetworkScanConfig:
        capture_interface = self._network_capture_interface_tokens_from_ui()
        capture_interfaces = capture_interface
        capture_enabled = bool(self._network_bool_value("network_capture_enabled"))
        return NetworkScanConfig(
            enabled=True,
            nmap_enabled=True,
            targets=local_machine_nmap_targets(),
            ports=self._network_string_value("network_ports", DEFAULT_LOCAL_NMAP_PORTS) or DEFAULT_LOCAL_NMAP_PORTS,
            extra_args=self._network_string_value("network_extra_args"),
            nmap_no_dns=self._network_bool_value("network_nmap_no_dns", True),
            nmap_skip_host_discovery=self._network_bool_value("network_nmap_skip_host_discovery", True),
            nmap_timing=self._network_string_value("network_nmap_timing", "T2") or "T2",
            nmap_open_only=self._network_bool_value("network_nmap_open_only", True),
            nmap_os_detection=self._network_bool_value("network_nmap_os_detection", False),
            nmap_service_detection=self._network_bool_value("network_nmap_service_detection", True),
            capture_enabled=capture_enabled,
            capture_interfaces=capture_interfaces,
            capture_interface=capture_interfaces[0] if capture_interfaces else None,
            capture_disabled_interfaces=self._network_capture_disabled_interfaces_from_ui(),
            capture_duration=max(1, int(self._network_string_value("network_capture_duration", "20") or "20")),
            capture_filter=self._network_string_value("network_capture_filter"),
            capture_no_name_resolution=self._network_bool_value("network_capture_no_name_resolution", True),
            capture_quiet=self._network_bool_value("network_capture_quiet", True),
        )

    def _start_network_scan_live_window(self, network_scan: NetworkScanConfig, network_only: bool) -> None:
        return self._start_network_scan_live_window_v2(network_scan, network_only)

    def _start_network_scan_live_window_legacy(self, network_scan: NetworkScanConfig, network_only: bool) -> None:
        if self._network_live_window:
            self._close_network_scan_live_window()
        window = Toplevel(self.root)
        window.title("Сетевой живой мониторинг")
        window.geometry("1024x700")
        window.minsize(860, 560)
        window.transient(self.root)
        window.configure(background=COLORS["canvas"])
        self._network_live_window = window
        self._network_live_text = None
        self._network_live_canvas = None
        self._network_topology_nodes = set()
        self._network_live_events = [
            f"Режим: {'только сеть' if network_only else 'полный аудит'}",
            f"Цели: {', '.join(network_scan.targets) or 'автоподбор'}",
            f"Порты nmap: {network_scan.ports or '1-65535'}",
            f"Захват трафика: {'включен' if network_scan.capture_enabled else 'выключен'}",
        ]
        if network_scan.capture_enabled and network_scan.capture_interfaces:
            self._network_live_events.append(f"Интерфейсы: {', '.join(network_scan.capture_interfaces)}")
        if network_scan.capture_disabled_interfaces:
            self._network_live_events.append(
                "Отключены: " + ", ".join(network_scan.capture_disabled_interfaces)
            )
        if network_scan.capture_enabled:
            self._network_live_events.append(f"Длительность захвата: {network_scan.capture_duration} сек")

        panel = ttk.Frame(window, style="Panel.TFrame", padding=(12, 10))
        panel.pack(fill=BOTH, expand=True)
        panel.grid_rowconfigure(0, weight=1)
        panel.grid_columnconfigure(0, weight=1)

        header = ttk.Frame(panel, style="Panel.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        ttk.Label(header, text="Сетевой монитор", style="Section.TLabel").pack(side=LEFT)
        ttk.Label(header, textvariable=self._network_live_status, style="Muted.TLabel").pack(
            side=LEFT, padx=(8, 0)
        )
        self._network_live_report_button = ttk.Button(
            header,
            text="Открыть итоговый отчёт",
            state="disabled",
            command=self._open_network_live_report,
            style="Primary.TButton",
            cursor="hand2",
        )
        self._network_live_report_button.pack(side=RIGHT)

        body = ttk.Frame(panel, style="Panel.TFrame")
        body.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)

        left_panel = ttk.Frame(body, style="Panel.TFrame")
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self._network_live_canvas = Canvas(left_panel, bg="#0f172a", height=190, highlightthickness=0)
        self._network_live_canvas.pack(fill=BOTH, expand=True)

        right_panel = ttk.Frame(body, style="Panel.TFrame")
        right_panel.grid(row=0, column=1, sticky="nsew")
        self._network_live_text = scrolledtext.ScrolledText(
            right_panel,
            wrap="word",
            font=("Consolas", 9),
            background="#F8FAFB",
            foreground=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=8,
            state="disabled",
        )
        self._network_live_text.pack(fill=BOTH, expand=True)
        for tag, options in {
            "risk_critical": {"foreground": "#7f1d1d", "background": "#fee2e2"},
            "risk_high": {"foreground": "#991b1b", "background": "#fef2f2"},
            "risk_medium": {"foreground": "#92400e", "background": "#fffbeb"},
            "risk_low": {"foreground": "#166534", "background": "#f0fdf4"},
            "risk_info": {"foreground": "#334155", "background": "#f8fafc"},
            "phase": {"foreground": "#1d4ed8"},
            "packet": {"foreground": "#0f766e"},
        }.items():
            try:
                self._network_live_text.tag_configure(tag, **options)
            except Exception:
                pass
        self._network_live_status.set("Запуск сетевого аудита…")
        self._render_network_scan_live_dashboard("Сканирование запущено")
        self._append_network_scan_event("Сетевой мониторинг активирован")

    def _start_network_scan_live_window_v2(self, network_scan: NetworkScanConfig, network_only: bool) -> None:
        if self._network_live_window:
            self._close_network_scan_live_window()
        window = Toplevel(self.root)
        window.title("\u0421\u0435\u0442\u0435\u0432\u043e\u0439 \u0436\u0438\u0432\u043e\u0439 \u043c\u043e\u043d\u0438\u0442\u043e\u0440: Wireshark + Nmap")
        window.geometry("1280x780")
        window.minsize(1060, 640)
        window.transient(self.root)
        window.configure(background=COLORS["canvas"])
        self._network_live_window = window
        self._network_live_text = None
        self._network_live_canvas = None
        self._network_live_packet_table = None
        self._network_live_packet_details_text = None
        self._network_live_packet_hex_text = None
        self._network_live_packet_detail_cache = {}
        self._network_live_nodes_table = None
        self._network_live_nmap_text = None
        self._network_live_security_text = None
        self._network_live_log_text = None
        self._network_live_capture_banner = None
        self._network_live_summary_vars = {}
        self._network_topology_nodes = set()
        self._network_live_events = [
            "\u0420\u0435\u0436\u0438\u043c: " + ("\u0442\u043e\u043b\u044c\u043a\u043e \u0441\u0435\u0442\u044c" if network_only else "\u043f\u043e\u043b\u043d\u044b\u0439 \u0430\u0443\u0434\u0438\u0442"),
            "\u0426\u0435\u043b\u0438: " + (", ".join(network_scan.targets) or "\u0430\u0432\u0442\u043e\u043f\u043e\u0434\u0431\u043e\u0440"),
            "\u041f\u043e\u0440\u0442\u044b Nmap: " + ((network_scan.ports or "1-65535") if network_scan.nmap_enabled else "\u0432\u044b\u043a\u043b\u044e\u0447\u0435\u043d"),
            "\u0417\u0430\u0445\u0432\u0430\u0442 \u0442\u0440\u0430\u0444\u0438\u043a\u0430: " + ("\u0432\u043a\u043b\u044e\u0447\u0435\u043d" if network_scan.capture_enabled else "\u0432\u044b\u043a\u043b\u044e\u0447\u0435\u043d"),
            "RAW Wireshark/Npcap: \u0432\u044b\u043a\u043b\u044e\u0447\u0435\u043d \u0432 \u0431\u0435\u0437\u043e\u043f\u0430\u0441\u043d\u043e\u043c \u0440\u0435\u0436\u0438\u043c\u0435",
        ]
        if network_scan.capture_enabled and network_scan.capture_interfaces:
            self._network_live_events.append("\u0418\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u044b: " + ", ".join(network_scan.capture_interfaces))
        if network_scan.capture_disabled_interfaces:
            self._network_live_events.append("\u041e\u0442\u043a\u043b\u044e\u0447\u0435\u043d\u044b: " + ", ".join(network_scan.capture_disabled_interfaces))
        if network_scan.capture_enabled:
            self._network_live_events.append("\u0414\u043b\u0438\u0442\u0435\u043b\u044c\u043d\u043e\u0441\u0442\u044c \u0437\u0430\u0445\u0432\u0430\u0442\u0430: " + str(network_scan.capture_duration) + " \u0441\u0435\u043a")

        panel = ttk.Frame(window, style="Panel.TFrame", padding=(12, 10))
        panel.pack(fill=BOTH, expand=True)
        panel.grid_rowconfigure(3, weight=1)
        panel.grid_columnconfigure(0, weight=1)

        header = ttk.Frame(panel, style="Panel.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        ttk.Label(header, text="\u0421\u0435\u0442\u0435\u0432\u043e\u0439 \u043c\u043e\u043d\u0438\u0442\u043e\u0440: Wireshark + Nmap", style="Section.TLabel").pack(side=LEFT)
        ttk.Label(header, textvariable=self._network_live_status, style="Muted.TLabel").pack(side=LEFT, padx=(8, 0))
        self._network_live_report_button = ttk.Button(
            header,
            text="\u041e\u0442\u043a\u0440\u044b\u0442\u044c \u0438\u0442\u043e\u0433\u043e\u0432\u044b\u0439 \u043e\u0442\u0447\u0451\u0442",
            state="disabled",
            command=self._open_network_live_report,
            style="Primary.TButton",
            cursor="hand2",
        )
        self._network_live_report_button.pack(side=RIGHT)

        capture_banner = Canvas(panel, height=50, bg="#064E3B", highlightthickness=0)
        capture_banner.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        self._network_live_capture_banner = capture_banner
        self._draw_network_live_capture_banner(
            self._network_live_capture_banner_text(network_scan),
            active=network_scan.capture_enabled,
        )

        summary = ttk.Frame(panel, style="Panel.TFrame")
        summary.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        for index in range(6):
            summary.grid_columnconfigure(index, weight=1)
        summary_items = [
            ("mode", "\u0420\u0435\u0436\u0438\u043c", "\u0422\u043e\u043b\u044c\u043a\u043e \u0441\u0435\u0442\u044c" if network_only else "\u041f\u043e\u043b\u043d\u044b\u0439 \u0430\u0443\u0434\u0438\u0442"),
            ("targets", "\u0426\u0435\u043b\u0438", ", ".join(network_scan.targets) or "\u0430\u0432\u0442\u043e"),
            ("ports", "Nmap", (network_scan.ports or "1-65535") if network_scan.nmap_enabled else "\u0432\u044b\u043a\u043b\u044e\u0447\u0435\u043d"),
            ("capture", "\u0417\u0430\u0445\u0432\u0430\u0442", "\u0431\u0435\u0437\u043e\u043f\u0430\u0441\u043d\u044b\u0439" if network_scan.capture_enabled else "\u0432\u044b\u043a\u043b\u044e\u0447\u0435\u043d"),
            ("packets", "\u041f\u0430\u043a\u0435\u0442\u044b", "0"),
            ("risks", "\u0418\u0411-\u0441\u043e\u0431\u044b\u0442\u0438\u044f", "0"),
        ]
        for index, (key, label, value) in enumerate(summary_items):
            card = ttk.Frame(summary, style="Panel.TFrame", padding=(10, 6))
            card.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 6, 0))
            ttk.Label(card, text=label, style="Muted.TLabel").pack(anchor="w")
            var = StringVar(value=value)
            self._network_live_summary_vars[key] = var
            ttk.Label(card, textvariable=var, style="Body.TLabel").pack(anchor="w")

        body = ttk.Frame(panel, style="Panel.TFrame")
        body.grid(row=3, column=0, sticky="nsew", pady=(10, 0))
        body.grid_rowconfigure(0, weight=3)
        body.grid_rowconfigure(1, weight=2)
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)

        packet_panel = ttk.LabelFrame(body, text="Wireshark: \u043f\u0430\u043a\u0435\u0442\u044b \u0438 \u0442\u0440\u0430\u0444\u0438\u043a")
        packet_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=(0, 10))
        packet_panel.grid_rowconfigure(0, weight=4)
        packet_panel.grid_rowconfigure(1, weight=2)
        packet_panel.grid_columnconfigure(0, weight=1)
        packet_columns = ("no", "time", "source", "destination", "protocol", "length", "info")
        packet_table = ttk.Treeview(packet_panel, columns=packet_columns, show="headings", height=12)
        for column, heading, width in (
            ("no", "No.", 58),
            ("time", "\u0412\u0440\u0435\u043c\u044f", 88),
            ("source", "\u0418\u0441\u0442\u043e\u0447\u043d\u0438\u043a", 160),
            ("destination", "\u041d\u0430\u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0435", 160),
            ("protocol", "\u041f\u0440\u043e\u0442\u043e\u043a\u043e\u043b", 92),
            ("length", "\u0414\u043b\u0438\u043d\u0430", 72),
            ("info", "Info", 520),
        ):
            packet_table.heading(column, text=heading)
            packet_table.column(column, width=width, minwidth=60, stretch=(column == "info"))
        for tag, background in {
            "critical": "#fee2e2",
            "high": "#fef2f2",
            "medium": "#fffbeb",
            "low": "#f0fdf4",
            "info": "#f8fafc",
        }.items():
            try:
                packet_table.tag_configure(tag, background=background)
            except Exception:
                pass
        packet_scroll = ttk.Scrollbar(packet_panel, orient="vertical", command=packet_table.yview)
        packet_table.configure(yscrollcommand=packet_scroll.set)
        packet_table.grid(row=0, column=0, sticky="nsew")
        packet_scroll.grid(row=0, column=1, sticky="ns")
        packet_detail_tabs = ttk.Notebook(packet_panel)
        packet_detail_tabs.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(6, 0))
        packet_details_tab = ttk.Frame(packet_detail_tabs, style="Panel.TFrame")
        packet_hex_tab = ttk.Frame(packet_detail_tabs, style="Panel.TFrame")
        packet_detail_tabs.add(packet_details_tab, text="\u0414\u0435\u0442\u0430\u043b\u0438 \u043f\u0430\u043a\u0435\u0442\u0430")
        packet_detail_tabs.add(packet_hex_tab, text="Hex / bytes")
        self._network_live_packet_details_text = scrolledtext.ScrolledText(
            packet_details_tab,
            wrap="word",
            font=("Consolas", 9),
            background="#F8FAFC",
            foreground=COLORS["text"],
            relief="flat",
            borderwidth=0,
            height=5,
            state="disabled",
        )
        self._network_live_packet_details_text.pack(fill=BOTH, expand=True)
        self._network_live_packet_hex_text = scrolledtext.ScrolledText(
            packet_hex_tab,
            wrap="word",
            font=("Consolas", 9),
            background="#0B1220",
            foreground="#DBEAFE",
            relief="flat",
            borderwidth=0,
            height=5,
            state="disabled",
        )
        self._network_live_packet_hex_text.pack(fill=BOTH, expand=True)
        packet_table.bind("<<TreeviewSelect>>", lambda _event: self._network_live_show_selected_packet_detail())
        self._network_live_packet_table = packet_table

        nmap_panel = ttk.LabelFrame(body, text="Nmap: \u0443\u0437\u043b\u044b, \u043f\u043e\u0440\u0442\u044b, \u0441\u0435\u0440\u0432\u0438\u0441\u044b")
        nmap_panel.grid(row=0, column=1, sticky="nsew", pady=(0, 10))
        nmap_panel.grid_rowconfigure(0, weight=1)
        nmap_panel.grid_columnconfigure(0, weight=1)
        self._network_live_nmap_text = scrolledtext.ScrolledText(
            nmap_panel,
            wrap="word",
            font=("Consolas", 9),
            background="#0B1220",
            foreground="#DBEAFE",
            insertbackground="#DBEAFE",
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=8,
            state="disabled",
        )
        self._network_live_nmap_text.grid(row=0, column=0, sticky="nsew")

        topology_panel = ttk.LabelFrame(body, text="\u0421\u0445\u0435\u043c\u0430 \u0441\u0435\u0442\u0438 \u0438 \u0443\u0437\u043b\u044b")
        topology_panel.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        topology_panel.grid_rowconfigure(0, weight=2)
        topology_panel.grid_rowconfigure(1, weight=1)
        topology_panel.grid_columnconfigure(0, weight=1)
        self._network_live_canvas = Canvas(topology_panel, bg="#0f172a", height=150, highlightthickness=0)
        self._network_live_canvas.grid(row=0, column=0, sticky="nsew")
        nodes_table = ttk.Treeview(topology_panel, columns=("role", "address", "severity"), show="headings", height=4)
        for column, heading, width in (("role", "\u0420\u043e\u043b\u044c", 100), ("address", "\u0410\u0434\u0440\u0435\u0441", 180), ("severity", "\u0420\u0438\u0441\u043a", 80)):
            nodes_table.heading(column, text=heading)
            nodes_table.column(column, width=width, minwidth=70, stretch=True)
        nodes_table.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        self._network_live_nodes_table = nodes_table

        lower_right = ttk.Notebook(body)
        lower_right.grid(row=1, column=1, sticky="nsew")
        security_tab = ttk.Frame(lower_right, style="Panel.TFrame")
        log_tab = ttk.Frame(lower_right, style="Panel.TFrame")
        lower_right.add(security_tab, text="\u0418\u0411-\u0430\u043d\u0430\u043b\u0438\u0437")
        lower_right.add(log_tab, text="\u0416\u0443\u0440\u043d\u0430\u043b")
        for tab in (security_tab, log_tab):
            tab.grid_rowconfigure(0, weight=1)
            tab.grid_columnconfigure(0, weight=1)
        self._network_live_security_text = scrolledtext.ScrolledText(
            security_tab,
            wrap="word",
            font=("Consolas", 9),
            background="#FFF7ED",
            foreground="#431407",
            insertbackground="#431407",
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=8,
            state="disabled",
        )
        self._network_live_security_text.grid(row=0, column=0, sticky="nsew")
        self._network_live_log_text = scrolledtext.ScrolledText(
            log_tab,
            wrap="word",
            font=("Consolas", 9),
            background="#F8FAFB",
            foreground=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=8,
            state="disabled",
        )
        self._network_live_log_text.grid(row=0, column=0, sticky="nsew")
        self._network_live_text = self._network_live_log_text
        for text_widget in (self._network_live_nmap_text, self._network_live_security_text, self._network_live_log_text):
            for tag, options in {
                "risk_critical": {"foreground": "#7f1d1d", "background": "#fee2e2"},
                "risk_high": {"foreground": "#991b1b", "background": "#fef2f2"},
                "risk_medium": {"foreground": "#92400e", "background": "#fffbeb"},
                "risk_low": {"foreground": "#166534", "background": "#f0fdf4"},
                "risk_info": {"foreground": "#334155", "background": "#f8fafc"},
                "phase": {"foreground": "#60A5FA"},
                "packet": {"foreground": "#0f766e"},
            }.items():
                try:
                    text_widget.tag_configure(tag, **options)
                except Exception:
                    pass
        self._network_live_status.set("\u0417\u0430\u043f\u0443\u0441\u043a \u0441\u0435\u0442\u0435\u0432\u043e\u0433\u043e \u0430\u0443\u0434\u0438\u0442\u0430...")
        self._render_network_scan_live_dashboard("\u0421\u043a\u0430\u043d\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u0435 \u0437\u0430\u043f\u0443\u0449\u0435\u043d\u043e")
        self._append_network_scan_event("\u0421\u0435\u0442\u0435\u0432\u043e\u0439 \u043c\u043e\u043d\u0438\u0442\u043e\u0440\u0438\u043d\u0433 \u0430\u043a\u0442\u0438\u0432\u0438\u0440\u043e\u0432\u0430\u043d")
        if network_scan.nmap_enabled:
            self._append_network_scan_event("Nmap: \u043e\u0436\u0438\u0434\u0430\u043d\u0438\u0435 \u0437\u0430\u043f\u0443\u0441\u043a\u0430 \u0441\u0435\u0442\u0435\u0432\u043e\u0433\u043e \u0441\u043a\u0430\u043d\u0435\u0440\u0430")
        else:
            self._append_network_scan_event("Nmap: \u043f\u0440\u043e\u043f\u0443\u0449\u0435\u043d, \u0432\u044b\u0431\u0440\u0430\u043d \u0442\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u0445\u0432\u0430\u0442 \u0442\u0440\u0430\u0444\u0438\u043a\u0430")
        if network_scan.capture_enabled:
            capture_interfaces = ", ".join(network_scan.capture_interfaces) or "\u043d\u0435 \u0432\u044b\u0431\u0440\u0430\u043d\u044b"
            self._append_network_scan_event(
                "CAPTURE_ACTIVE|info|"
                "\u0417\u0430\u0445\u0432\u0430\u0442 \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u0432\u044b\u043f\u043e\u043b\u043d\u044f\u0435\u0442\u0441\u044f: "
                f"\u0438\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u044b={capture_interfaces}; "
                f"\u0434\u043b\u0438\u0442\u0435\u043b\u044c\u043d\u043e\u0441\u0442\u044c={network_scan.capture_duration} \u0441\u0435\u043a; "
                "\u0440\u0435\u0436\u0438\u043c=safe Windows TCP/RX-TX telemetry"
            )
        else:
            self._append_network_scan_event("Traffic: \u043e\u0436\u0438\u0434\u0430\u043d\u0438\u0435 \u0431\u0435\u0437\u043e\u043f\u0430\u0441\u043d\u043e\u0439 TCP-\u0442\u0435\u043b\u0435\u043c\u0435\u0442\u0440\u0438\u0438")

    def _extract_topology_nodes(self, message: str) -> list[str]:
        event = (message or "").strip()
        if event.startswith(("TRAFFIC_RISK|", "TRAFFIC_FLOW|", "PACKET_SAMPLE|", "PACKET_ROW|")):
            payload = event.split("|", 2)[-1] if "|" in event else event
            if event.startswith("PACKET_ROW|"):
                try:
                    decoded = json.loads(payload)
                except Exception:
                    decoded = {}
                if isinstance(decoded, dict):
                    json_nodes = []
                    for key in ("Source", "Destination"):
                        endpoint = str(decoded.get(key) or "").strip()
                        match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", endpoint)
                        if match:
                            json_nodes.append(match.group(0))
                    if json_nodes:
                        return json_nodes
            nodes: list[str] = []
            for raw in payload.replace("->", " ").replace(";", " ").replace(",", " ").split():
                token = raw.strip("[]() ")
                if ":" in token:
                    token = token.split(":", 1)[0]
                parts = token.split(".")
                if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                    nodes.append(token)
            return nodes
        if event.lower().startswith("network hosts discovered:"):
            payload = event.split(":", 1)[1] if ":" in event else ""
            return [item.strip() for item in payload.replace("...", ",").replace("\n", ",").split(",") if item.strip()]
        generic_nodes: list[str] = []
        for match in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", event):
            parts = match.split(".")
            if all(part.isdigit() and 0 <= int(part) <= 255 for part in parts) and match not in generic_nodes:
                generic_nodes.append(match)
        return generic_nodes

    def _render_network_scan_live_topology(self) -> None:
        if not self._network_live_canvas:
            return
        canvas = self._network_live_canvas
        canvas.delete("all")
        width = int(canvas.winfo_width())
        height = int(canvas.winfo_height())
        if width <= 1:
            width = 720
        if height <= 1:
            height = 160
        nodes = sorted(self._network_topology_nodes)
        if not nodes:
            if self._network_live_capture_active():
                pulse_x = width / 2
                pulse_y = height / 2 - 18
                canvas.create_oval(
                    pulse_x - 54,
                    pulse_y - 54,
                    pulse_x + 54,
                    pulse_y + 54,
                    fill="#064E3B",
                    outline="#34D399",
                    width=3,
                )
                canvas.create_oval(
                    pulse_x - 30,
                    pulse_y - 30,
                    pulse_x + 30,
                    pulse_y + 30,
                    fill="#10B981",
                    outline="#A7F3D0",
                    width=2,
                )
                canvas.create_text(
                    pulse_x,
                    pulse_y,
                    text="\u25cf",
                    fill="#ECFDF5",
                    font=("Segoe UI", 22, "bold"),
                )
                canvas.create_text(
                    width / 2,
                    pulse_y + 70,
                    text="\u0417\u0430\u0445\u0432\u0430\u0442 \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u0432\u044b\u043f\u043e\u043b\u043d\u044f\u0435\u0442\u0441\u044f",
                    fill="#D1FAE5",
                    font=("Segoe UI", 11, "bold"),
                )
                canvas.create_text(
                    width / 2,
                    pulse_y + 92,
                    text="\u0421\u0431\u043e\u0440 TCP-\u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u0439 \u0438 RX/TX-\u0441\u0447\u0451\u0442\u0447\u0438\u043a\u043e\u0432 \u0432\u044b\u0431\u0440\u0430\u043d\u043d\u044b\u0445 \u0438\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u043e\u0432",
                    fill="#A7F3D0",
                    font=("Segoe UI", 9),
                )
                return
            canvas.create_text(
                width / 2,
                height / 2,
                text="Сеть ещё не распознана. Ожидайте события сканирования.",
                fill="#94A3B8",
                font=("Segoe UI", 10),
            )
            return
        center_x = width * 0.52
        center_y = height * 0.62
        canvas.create_oval(
            center_x - 58,
            center_y - 24,
            center_x + 58,
            center_y + 24,
            fill="#2563EB",
            outline="#93C5FD",
            width=2,
        )
        canvas.create_text(
            center_x,
            center_y,
            text="Gateway",
            fill="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
        )
        if nodes:
            limited_nodes = nodes[:12]
            for index, node in enumerate(limited_nodes):
                angle = ((index / max(1, len(limited_nodes))) * 2 * 3.141592653589793) - 1.45
                radius_x = width * 0.34
                radius_y = height * 0.23
                x = center_x + radius_x * (0.6 + index * 0.02) * (1 if index % 2 else -1) * 0.35
                y = center_y - radius_y
                if len(limited_nodes) > 1:
                    y = center_y - 40 + (radius_y * ((index % 2) * -2 + 1)) * (1 + (index / max(1, len(limited_nodes))))
                    x = center_x + ((index - len(limited_nodes) / 2) * (width - 120) / max(1, len(limited_nodes)))
                z = 1.0 - 0.02 * index
                blob = int(30 * (0.62 + max(0.0, z)))
                node_x = max(22, min(width - 22, x))
                node_y = max(22, min(height - 22, y))
                canvas.create_line(center_x, center_y, node_x, node_y, fill="#94A3B8", width=1, dash=(3, 2))
                canvas.create_oval(
                    node_x - blob,
                    node_y - int(blob * 0.55),
                    node_x + blob,
                    node_y + int(blob * 0.55),
                    fill="#0f766e" if index % 2 else "#15803d",
                    outline="#E2E8F0",
                    width=1,
                )
                canvas.create_text(
                    node_x,
                    node_y - 7,
                    text=node,
                    fill="#E5E7EB",
                    font=("Segoe UI", 7),
                    anchor="s",
                )
        else:
            canvas.create_text(width / 2, height / 2, text="Узлы не определены", fill="#94A3B8")

    def _render_network_scan_live_dashboard(self, status: str) -> None:
        if (
            self._network_live_packet_table
            or self._network_live_nmap_text
            or self._network_live_security_text
            or self._network_live_log_text
        ):
            self._render_network_scan_live_console(status)
            return
        if not self._network_live_text or not self._network_live_window:
            return
        self._network_live_status.set(status)
        self._network_live_text.configure(state="normal")
        self._network_live_text.delete("1.0", END)
        for event in self._network_live_events[-180:]:
            display_text, tag = self._network_live_event_display(event)
            if tag:
                self._network_live_text.insert(END, f"{display_text}\n", tag)
            else:
                self._network_live_text.insert(END, f"{display_text}\n")
        self._network_live_text.configure(state="disabled")
        self._network_live_text.see(END)
        self._render_network_scan_live_topology()

    def _render_network_scan_live_console(self, status: str) -> None:
        if not self._network_live_window:
            return
        self._network_live_status.set(status)
        events = self._network_live_events[-500:]
        packet_rows = []
        nmap_events = []
        security_events = []
        for event in events:
            packet_row = self._network_live_wireshark_packet_row(event)
            if packet_row:
                packet_rows.append(packet_row)
            if self._network_live_event_is_nmap(event):
                nmap_events.append(event)
            if self._network_live_event_is_security(event):
                security_events.append(event)
        self._network_live_update_summary(packet_rows, security_events)
        self._network_live_fill_packet_table(packet_rows[-250:])
        self._network_live_fill_nodes_table()
        self._network_live_fill_text(self._network_live_nmap_text, nmap_events[-180:], empty="Nmap \u0435\u0449\u0451 \u043d\u0435 \u0432\u0435\u0440\u043d\u0443\u043b \u0441\u043e\u0431\u044b\u0442\u0438\u044f.")
        self._network_live_fill_text(
            self._network_live_security_text,
            security_events[-180:],
            empty="\u0418\u0411-\u0440\u0438\u0441\u043a\u0438 \u043f\u043e\u043a\u0430 \u043d\u0435 \u043e\u0431\u043d\u0430\u0440\u0443\u0436\u0435\u043d\u044b.",
        )
        self._network_live_fill_text(self._network_live_log_text, events[-220:], empty="\u0416\u0443\u0440\u043d\u0430\u043b \u043f\u0443\u0441\u0442.")
        self._render_network_scan_live_topology()

    def _network_live_update_summary(self, packet_rows: list[tuple[str, str, str, str, str, str, str, str, str, str]], security_events: list[str]) -> None:
        nodes = sorted(self._network_topology_nodes)
        targets_value = f"{len(nodes)} \u0443\u0437\u043b." if nodes else None
        values = {
            "packets": str(len(packet_rows)),
            "risks": str(len(security_events)),
            "capture": "\u0431\u0435\u0437\u043e\u043f\u0430\u0441\u043d\u044b\u0439",
        }
        if targets_value:
            values["targets"] = targets_value
        for key, value in values.items():
            var = self._network_live_summary_vars.get(key)
            if var:
                var.set(value)

    def _network_live_fill_packet_table(self, rows: list[tuple[str, str, str, str, str, str, str, str, str, str]]) -> None:
        table = self._network_live_packet_table
        if not table:
            return
        try:
            table.delete(*table.get_children())
            self._network_live_packet_detail_cache = {}
            if not rows:
                if self._network_live_capture_active():
                    iid = table.insert(
                        "",
                        END,
                        values=(
                            "-",
                            "-",
                            "\u0432\u044b\u0431\u0440\u0430\u043d\u043d\u044b\u0435 \u0438\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u044b",
                            "safe telemetry",
                            "CAPTURE",
                            "-",
                            "\u0417\u0430\u0445\u0432\u0430\u0442 \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u0432\u044b\u043f\u043e\u043b\u043d\u044f\u0435\u0442\u0441\u044f: \u043e\u0436\u0438\u0434\u0430\u043d\u0438\u0435 TCP/RX/TX-\u0441\u043e\u0431\u044b\u0442\u0438\u0439",
                        ),
                        tags=("info",),
                    )
                    self._network_live_packet_detail_cache[str(iid)] = (
                        "\u0417\u0430\u0445\u0432\u0430\u0442 \u0430\u043a\u0442\u0438\u0432\u0435\u043d, \u043e\u0436\u0438\u0434\u0430\u044e\u0442\u0441\u044f \u0441\u0442\u0440\u043e\u043a\u0438 PACKET_ROW \u043e\u0442 tshark.",
                        "",
                    )
                    self._network_live_show_packet_detail(*self._network_live_packet_detail_cache[str(iid)])
                    return
                iid = table.insert("", END, values=("-", "-", "-", "-", "-", "-", "\u0421\u043e\u0431\u044b\u0442\u0438\u044f \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u0435\u0449\u0451 \u043d\u0435 \u043f\u043e\u043b\u0443\u0447\u0435\u043d\u044b"))
                self._network_live_packet_detail_cache[str(iid)] = ("", "")
                self._network_live_show_packet_detail("", "")
                return
            for row in rows:
                severity = row[7].lower()
                iid = table.insert("", END, values=row[:7], tags=(severity,))
                self._network_live_packet_detail_cache[str(iid)] = (row[8], row[9])
            children = table.get_children()
            if children:
                latest = children[-1]
                table.selection_set(latest)
                table.focus(latest)
                details, bytes_hex = self._network_live_packet_detail_cache.get(str(latest), ("", ""))
                self._network_live_show_packet_detail(details, bytes_hex)
        except Exception:
            return

    def _network_live_show_selected_packet_detail(self) -> None:
        table = self._network_live_packet_table
        if not table:
            return
        try:
            selected = table.selection()
            if not selected:
                return
            details, bytes_hex = self._network_live_packet_detail_cache.get(str(selected[0]), ("", ""))
            self._network_live_show_packet_detail(details, bytes_hex)
        except Exception:
            return

    def _network_live_show_packet_detail(self, details: str, bytes_hex: str) -> None:
        for widget, text, empty in (
            (
                self._network_live_packet_details_text,
                details,
                "\u0412\u044b\u0431\u0435\u0440\u0438\u0442\u0435 \u043f\u0430\u043a\u0435\u0442, \u0447\u0442\u043e\u0431\u044b \u0443\u0432\u0438\u0434\u0435\u0442\u044c \u0434\u0435\u0442\u0430\u043b\u0438.",
            ),
            (
                self._network_live_packet_hex_text,
                bytes_hex,
                "\u0411\u0430\u0439\u0442\u044b \u043f\u0430\u043a\u0435\u0442\u0430 \u043d\u0435 \u043f\u0435\u0440\u0435\u0434\u0430\u043d\u044b tshark \u0434\u043b\u044f \u044d\u0442\u043e\u0439 \u0441\u0442\u0440\u043e\u043a\u0438.",
            ),
        ):
            if not widget:
                continue
            try:
                widget.configure(state="normal")
                widget.delete("1.0", END)
                widget.insert(END, (text or empty) + "\n")
                widget.configure(state="disabled")
                widget.see("1.0")
            except Exception:
                continue

    def _network_live_fill_nodes_table(self) -> None:
        table = self._network_live_nodes_table
        if not table:
            return
        try:
            table.delete(*table.get_children())
            nodes = sorted(self._network_topology_nodes)
            if not nodes:
                table.insert("", END, values=("\u043e\u0436\u0438\u0434\u0430\u043d\u0438\u0435", "-", "\u0418\u041d\u0424\u041e"))
                return
            for node in nodes[:100]:
                role = self._network_live_node_role(node)
                severity = self._network_live_node_severity(node)
                table.insert("", END, values=(role, node, severity.upper()), tags=(severity,))
        except Exception:
            return

    def _network_live_fill_text(self, widget: scrolledtext.ScrolledText | None, events: list[str], empty: str) -> None:
        if not widget:
            return
        try:
            widget.configure(state="normal")
            widget.delete("1.0", END)
            if not events:
                widget.insert(END, empty + "\n", "risk_info")
            for event in events:
                display_text, tag = self._network_live_event_display(event)
                if tag:
                    widget.insert(END, f"{display_text}\n", tag)
                else:
                    widget.insert(END, f"{display_text}\n")
            widget.configure(state="disabled")
            widget.see(END)
        except Exception:
            return

    def _network_live_wireshark_packet_row(self, event: str) -> tuple[str, str, str, str, str, str, str, str, str, str] | None:
        value = str(event or "").strip()
        if value.startswith("PACKET_ROW|"):
            parts = value.split("|", 2)
            severity = parts[1].strip().upper() if len(parts) > 1 else "INFO"
            payload = parts[2].strip() if len(parts) > 2 else "{}"
            try:
                row = json.loads(payload)
            except Exception:
                row = {}
            if isinstance(row, dict):
                return (
                    str(row.get("No.") or row.get("No") or "-"),
                    str(row.get("Time") or "-"),
                    str(row.get("Source") or "-"),
                    str(row.get("Destination") or "-"),
                    str(row.get("Protocol") or "UNKNOWN"),
                    str(row.get("Length") or "-"),
                    str(row.get("Info") or "")[:900],
                    severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "INFO",
                    str(row.get("Details") or ""),
                    str(row.get("Bytes Hex") or row.get("Hex") or ""),
                )
        fallback = self._network_live_packet_row(value)
        if fallback is None:
            return None
        severity, protocol, source, destination, info = fallback
        number_match = re.search(r"#(?P<number>\d+)", info)
        time_match = re.search(r"\bt=(?P<time>[0-9.]+)", info)
        length_match = re.search(r"\blen=(?P<length>\d+)", info)
        return (
            number_match.group("number") if number_match else "-",
            time_match.group("time") if time_match else "-",
            source or "-",
            destination or "-",
            protocol or "UNKNOWN",
            length_match.group("length") if length_match else "-",
            info[:900],
            severity,
            info,
            "",
        )

    def _network_live_packet_row(self, event: str) -> tuple[str, str, str, str, str] | None:
        value = str(event or "").strip()
        tagged = value.startswith(("PACKET_SAMPLE|", "PACKET_ROW|", "TRAFFIC_RISK|", "TRAFFIC_FLOW|", "CAPTURE_ACTIVE|", "CAPTURE_PROGRESS|"))
        lowered = value.casefold()
        if not tagged and not any(marker in lowered for marker in ("traffic", "tcp", "udp", "packet", "connection", "get-nettcpconnection", "interface telemetry", "get-netadapterstatistics", "capture active", "\u0437\u0430\u0445\u0432\u0430\u0442 \u0442\u0440\u0430\u0444\u0438\u043a\u0430")):
            return None
        severity = self._network_live_event_severity(value).upper()
        payload = value.split("|", 2)[-1].strip() if tagged and "|" in value else value
        source, destination = self._network_live_endpoint_pair(payload)
        protocol = self._network_live_event_protocol(payload)
        return severity, protocol, source or "-", destination or "-", payload[:360]

    def _network_live_endpoint_pair(self, payload: str) -> tuple[str, str]:
        interface_match = re.search(r"interface telemetry\s*\[(?P<iface>[^\]]+)\]", payload, re.IGNORECASE)
        if interface_match:
            return interface_match.group("iface").strip(), "RX/TX counters"
        capture_match = re.search(r"(?:\u0438\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u044b|interfaces?)\s*=\s*(?P<iface>[^;]+)", payload, re.IGNORECASE)
        if capture_match:
            return capture_match.group("iface").strip(), "safe telemetry"
        match = re.search(
            r"(?P<src>\b\d{1,3}(?:\.\d{1,3}){3})(?::(?P<src_port>\d+))?\s*(?:->|=>|to)\s*"
            r"(?P<dst>\b\d{1,3}(?:\.\d{1,3}){3})(?::(?P<dst_port>\d+))?",
            payload,
            re.IGNORECASE,
        )
        if not match:
            return "", ""
        source = match.group("src")
        destination = match.group("dst")
        if match.group("src_port"):
            source += f":{match.group('src_port')}"
        if match.group("dst_port"):
            destination += f":{match.group('dst_port')}"
        return source, destination

    def _network_live_event_protocol(self, payload: str) -> str:
        upper = payload.upper()
        if (
            "CAPTURE" in upper
            or "\u0417\u0410\u0425\u0412\u0410\u0422 \u0422\u0420\u0410\u0424\u0418\u041A\u0410" in upper
            or "\u0417\u0410\u0425\u0412\u0410\u0422 \u041F\u0410\u041A\u0415\u0422\u041E\u0412" in upper
        ):
            return "CAPTURE"
        if "INTERFACE TELEMETRY" in upper or "GET-NETADAPTERSTATISTICS" in upper:
            return "INTERFACE"
        if "SAFE TRAFFIC TELEMETRY" in upper or "GET-NETTCPCONNECTION" in upper:
            return "TCP"
        for protocol in ("HTTP", "HTTPS", "TLS", "DNS", "SMB", "RDP", "SSH", "ICMP", "ARP", "DHCP", "LDAP", "KERBEROS", "FTP", "SMTP", "TCP", "UDP"):
            if re.search(rf"\b{protocol}\b", upper):
                return protocol
        port_map = {
            ":80": "HTTP",
            ":443": "TLS",
            ":53": "DNS",
            ":445": "SMB",
            ":3389": "RDP",
            ":22": "SSH",
            ":25": "SMTP",
            ":21": "FTP",
        }
        for marker, protocol in port_map.items():
            if marker in payload:
                return protocol
        return "TCP/UDP"

    def _network_live_event_severity(self, event: str) -> str:
        if event.startswith(("TRAFFIC_RISK|", "PACKET_SAMPLE|", "PACKET_ROW|", "TRAFFIC_FLOW|")):
            parts = event.split("|", 2)
            if len(parts) > 1:
                severity = parts[1].strip().lower()
                if severity in {"critical", "high", "medium", "low", "info"}:
                    return severity
        lowered = event.casefold()
        if any(marker in lowered for marker in ("critical", "clear-text", "exposed", "credential", "high")):
            return "high"
        if any(marker in lowered for marker in ("warning", "medium", "suspicious", "risk")):
            return "medium"
        return "info"

    def _network_live_event_is_nmap(self, event: str) -> bool:
        lowered = str(event or "").casefold()
        return any(
            marker in lowered
            for marker in (
                "nmap",
                "network_intelligence",
                "network hosts discovered",
                "critical service found",
                "open service",
                "open port",
                "service detection",
            )
        )

    def _network_live_event_is_security(self, event: str) -> bool:
        lowered = str(event or "").casefold()
        if str(event or "").startswith("PACKET_ROW|") and self._network_live_event_severity(str(event or "")) != "info":
            return True
        return str(event or "").startswith("TRAFFIC_RISK|") or any(
            marker in lowered
            for marker in (
                "critical service found",
                "clear-text",
                "credential",
                "suspicious",
                "risk",
                "exposed",
                "vulnerab",
            )
        )

    def _network_live_status_for_event(self, event: str) -> str | None:
        value = str(event or "").strip()
        lowered = value.casefold()
        if not value:
            return None
        if value.startswith("CAPTURE_ACTIVE|") or "\u0437\u0430\u0445\u0432\u0430\u0442 \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u0432\u044b\u043f\u043e\u043b\u043d\u044f\u0435\u0442\u0441\u044f" in lowered:
            return "\u0417\u0430\u0445\u0432\u0430\u0442 \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u0432\u044b\u043f\u043e\u043b\u043d\u044f\u0435\u0442\u0441\u044f"
        if value.startswith("CAPTURE_PROGRESS|") or "safe traffic telemetry started" in lowered:
            return "\u0417\u0430\u0445\u0432\u0430\u0442 \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u0432\u044b\u043f\u043e\u043b\u043d\u044f\u0435\u0442\u0441\u044f"
        if lowered.startswith("running collector:"):
            collector = value.split(":", 1)[1].strip() if ":" in value else value
            return f"\u042d\u0442\u0430\u043f: {collector}"
        if "network intelligence scan started" in lowered:
            return "\u0421\u0435\u0442\u0435\u0432\u043e\u0439 \u0438\u043d\u0442\u0435\u043b\u043b\u0435\u043a\u0442: \u0441\u0442\u0430\u0440\u0442"
        if "nmap" in lowered:
            return "Nmap: \u0432\u044b\u043f\u043e\u043b\u043d\u044f\u0435\u0442\u0441\u044f"
        if "traffic" in lowered or "get-nettcpconnection" in lowered:
            return "\u0422\u0440\u0430\u0444\u0438\u043a: \u0430\u043d\u0430\u043b\u0438\u0437 \u0432\u044b\u043f\u043e\u043b\u043d\u044f\u0435\u0442\u0441\u044f"
        if "audit completed" in lowered or "network intelligence completed" in lowered:
            return "\u0421\u043a\u0430\u043d\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u0435 \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u043e"
        return None

    def _network_live_node_role(self, node: str) -> str:
        if node.endswith(".1") or node.endswith(".254"):
            return "\u0448\u043b\u044e\u0437"
        return "\u0443\u0437\u0435\u043b"

    def _network_live_node_severity(self, node: str) -> str:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        selected = "info"
        for event in self._network_live_events:
            if node not in event:
                continue
            severity = self._network_live_event_severity(event)
            if order.get(severity, 0) > order.get(selected, 0):
                selected = severity
        return selected

    def _network_live_event_display(self, event: str) -> tuple[str, str]:
        value = str(event or "")
        if value.startswith("TRAFFIC_RISK|"):
            parts = value.split("|", 2)
            severity = parts[1].strip().lower() if len(parts) > 1 else "info"
            payload = parts[2].strip() if len(parts) > 2 else value
            if severity not in {"critical", "high", "medium", "low", "info"}:
                severity = "info"
            return f"[{severity.upper()}] {payload}", f"risk_{severity}"
        if value.startswith(("PACKET_SAMPLE|", "PACKET_ROW|")):
            parts = value.split("|", 2)
            payload = parts[2].strip() if len(parts) > 2 else value
            return f"[PACKET] {payload}", "packet"
        if value.startswith(("CAPTURE_ACTIVE|", "CAPTURE_PROGRESS|")):
            parts = value.split("|", 2)
            payload = parts[2].strip() if len(parts) > 2 else value
            return f"[CAPTURE] {payload}", "packet"
        lowered = value.casefold()
        if "nmap" in lowered or "traffic analysis phase" in lowered or "network intelligence" in lowered:
            return value, "phase"
        return value, ""

    def _network_live_capture_active(self) -> bool:
        events = [str(event or "") for event in getattr(self, "_network_live_events", [])[-80:]]
        for event in reversed(events):
            lowered = event.casefold()
            if (
                "\u0441\u043a\u0430\u043d\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u0435 \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u043e" in lowered
                or "network intelligence completed" in lowered
                or "audit completed" in lowered
            ):
                return False
            if (
                event.startswith(("CAPTURE_ACTIVE|", "CAPTURE_PROGRESS|"))
                or "\u0437\u0430\u0445\u0432\u0430\u0442 \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u0432\u044b\u043f\u043e\u043b\u043d\u044f\u0435\u0442\u0441\u044f" in lowered
                or "safe traffic telemetry started" in lowered
            ):
                return True
        return False

    def _network_live_capture_banner_text(self, network_scan: NetworkScanConfig) -> str:
        if not network_scan.capture_enabled:
            return "○ ЗАХВАТ ТРАФИКА ВЫКЛЮЧЕН | включите захват и выберите интерфейс"
        interfaces = ", ".join(network_scan.capture_interfaces)
        if not interfaces and network_scan.capture_interface:
            interfaces = str(network_scan.capture_interface)
        if not interfaces:
            interfaces = "не выбраны"
        nmap_note = "Nmap после первичного захвата" if network_scan.nmap_enabled else "Nmap выключен"
        return (
            f"● ЗАХВАТ ТРАФИКА ИДЁТ | интерфейсы: {interfaces} | "
            f"tshark/Wireshark live packets | {network_scan.capture_duration} сек | {nmap_note}"
        )

    def _draw_network_live_capture_banner(self, text: str, active: bool) -> None:
        banner = getattr(self, "_network_live_capture_banner", None)
        if not banner:
            return
        background = "#064E3B" if active else "#334155"
        foreground = "#ECFDF5" if active else "#E2E8F0"
        try:
            banner.configure(bg=background)
            banner.delete("all")
            banner.create_rectangle(0, 0, 5000, 80, fill=background, outline=background)
            banner.create_text(
                18,
                25,
                text=text,
                anchor="w",
                fill=foreground,
                font=("Segoe UI", 12, "bold"),
            )
        except Exception:
            return

    def _append_network_scan_event(self, message: str) -> None:
        event = str(message or "").strip()
        if not event:
            return
        self._network_live_events.append(event)
        if len(self._network_live_events) > 800:
            self._network_live_events = self._network_live_events[-800:]
        for host in self._extract_topology_nodes(event):
            if host:
                self._network_topology_nodes.add(host)
        status = self._network_live_status_for_event(event) or self._network_live_status.get()
        if status:
            self._network_live_status.set(status)
        self._render_network_scan_live_dashboard(status)

    def _set_network_live_report_path(self, path_value: str | None) -> None:
        if not self._network_live_report_button or not path_value:
            return
        self.last_report = path_value
        self._append_network_scan_event(f"Отчёт готов: {Path(path_value).name}")
        self._network_live_report_button.configure(state="normal")

    def _finish_network_scan_dashboard(self, final_status: str) -> None:
        if not self._network_live_window:
            return
        if final_status:
            self._append_network_scan_event(final_status)
        self._append_network_scan_event("Сканирование завершено")
        self._render_network_scan_live_topology()

    def _open_network_live_report(self) -> None:
        if self.last_report and Path(self.last_report).exists():
            webbrowser.open(Path(self.last_report).resolve().as_uri())
            return
        messagebox.showinfo("Отчёт", "Итоговый отчёт ещё не сформирован.")

    def _close_network_scan_live_window(self) -> None:
        if not self._network_live_window:
            return
        try:
            self._network_live_window.destroy()
        except Exception:
            pass
        self._network_live_window = None
        self._network_live_text = None
        self._network_live_canvas = None
        self._network_live_report_button = None
        self._network_live_packet_table = None
        self._network_live_packet_details_text = None
        self._network_live_packet_hex_text = None
        self._network_live_packet_detail_cache = {}

    def _run_background(
        self,
        online_sources: bool,
        vulnerability_mode: str = VULNERABILITY_MODE_FULL,
        cancel_token: CancellationToken | None = None,
        network_scan: NetworkScanConfig | None = None,
        network_only: bool = False,
    ) -> None:
        try:
            result = run_audit(
                db_path=None,
                output_dir=self.output_dir.get(),
                online_sources=online_sources,
                vulnerability_mode=vulnerability_mode,
                network_scan=network_scan,
                network_only=network_only,
                open_report=False,
                progress=self.messages.put,
                cancel_token=cancel_token,
            )
            self.last_report = str(result["report_path"])
            self.messages.put(format_result_message(result))
            if self._network_live_window:
                self.messages.put(f"__NETWORK_REPORT_PATH__:{self.last_report}")
            self.messages.put(f"Отчёт: {self.last_report}")
            self.messages.put("__STATUS__:success:Аудит завершён")
        except AuditCancelled:
            self.messages.put("Аудит отменён пользователем.")
            self.messages.put("__STATUS__:cancelled:Аудит отменён")
        except Exception as exc:
            self.messages.put(f"Ошибка аудита: {exc}")
            self.messages.put("__STATUS__:error:Ошибка аудита")

    def _run_reports_background(
        self,
        source_reports: tuple[str, ...],
        vulnerability_mode: str = VULNERABILITY_MODE_FULL,
        cancel_token: CancellationToken | None = None,
    ) -> None:
        try:
            result = analyze_reports(
                source_reports,
                db_path=None,
                output_dir=self.output_dir.get(),
                open_report=False,
                progress=self.messages.put,
                vulnerability_mode=vulnerability_mode,
                cancel_token=cancel_token,
            )
            if result.get("report_path"):
                self.last_report = str(result["report_path"])
                self.messages.put(f"Сводный отчёт: {self.last_report}")
            self.messages.put(
                "Пакет: обработано "
                f"{result.get('processed_count', 0)} из {result.get('selected_count', 0)}, "
                f"ошибок файлов={result.get('failed_count', 0)}. "
                f"{format_result_message(result)}"
            )
            if result.get("status") == "cancelled":
                self.messages.put("__STATUS__:cancelled:Проверка отменена")
            else:
                self.messages.put("__STATUS__:success:Проверка HTML завершена")
        except AuditCancelled:
            self.messages.put("__STATUS__:cancelled:Проверка отменена")
        except Exception as exc:
            self.messages.put(f"Ошибка проверки HTML-отчётов: {exc}")
            self.messages.put("__STATUS__:error:Ошибка проверки отчётов")

    def _begin_operation(self, text: str) -> CancellationToken:
        token = CancellationToken()
        self.active_cancel_token = token
        self._set_busy(True, text)
        if hasattr(self, "cancel_button"):
            self.cancel_button.configure(state="normal", text="Отменить")
        return token

    def _finish_operation(self, text: str, tone: str) -> None:
        self._set_busy(False, text, tone=tone)
        self.active_cancel_token = None
        if hasattr(self, "cancel_button"):
            self.cancel_button.configure(state="disabled", text="Отменить")

    def _cancel_active(self) -> None:
        token = self.active_cancel_token
        if token is None or not token.cancel():
            return
        self._log("Запрошена отмена. Ожидание безопасной точки остановки…")
        if hasattr(self, "cancel_button"):
            self.cancel_button.configure(state="disabled", text="Отмена…")
        self._set_progress_status("Прогресс: выполняется отмена…")

    def _update_sources(self) -> None:
        token = self._begin_operation("Обновление баз")
        threading.Thread(target=self._run_source_update, args=(token,), daemon=True).start()

    def _run_source_update(self, cancel_token: CancellationToken | None = None) -> None:
        try:
            result = update_vulnerability_database(
                output_dir=Path(self.output_dir.get()) / "vulnerability-database",
                project_root=Path.cwd(),
                progress=self.messages.put,
                include_cpe=True,
                cancel_token=cancel_token,
            )
            self.messages.put("__SOURCES__:" + format_database_update_status(result))
            self.messages.put("__STATUS__:Базы обновлены")
        except AuditCancelled:
            self.messages.put("Обновление баз отменено пользователем.")
            self.messages.put("__STATUS__:cancelled:Обновление баз отменено")
        except Exception as exc:
            self.messages.put(f"Ошибка обновления баз: {exc}")
            self.messages.put("__STATUS__:Ошибка обновления")

    def _set_busy(self, busy: bool, text: str, tone: str = "busy") -> None:
        presentation = presentation_for("busy" if busy else tone, text)
        self.status.set(presentation.text)
        self.status_badge.configure(style=presentation.tone)
        button_state = "disabled" if presentation.busy else "normal"
        for button in self.action_buttons:
            button.configure(state=button_state)
        if presentation.busy:
            self._set_progress_status(f"Прогресс: {text}")
            self.progress.stop()
            self.progress.configure(value=0)
        else:
            self.progress.stop()
            if tone == "success":
                self._set_progress_status("Прогресс: завершено")
                self.progress.configure(value=100)
            elif tone == "error":
                self._set_progress_status(f"Прогресс: остановлено — {text}")
            else:
                self._set_progress_status(f"Прогресс: {text}")

    def _set_progress_status(self, text: str) -> None:
        if hasattr(self, "progress_status"):
            self.progress_status.set(text)

    def _current_progress_value(self) -> int:
        try:
            return int(float(self.progress["value"]))
        except Exception:
            return 0

    def _drain_messages(self) -> None:
        self._ensure_network_state()
        while True:
            try:
                message = self.messages.get_nowait()
            except queue.Empty:
                break
            if isinstance(message, BatchProgress):
                finished = message.stage in {"completed", "failed"}
                completed = message.index if finished else message.index - 1
                value = round((completed / message.total) * 100) if message.total else 0
                self.progress.configure(value=value)
                name = message.hostname or message.source_path.name
                stage = {
                    "import": "импорт",
                    "assessment": "оценка",
                    "completed": "завершён",
                    "failed": "ошибка файла",
                }.get(message.stage, message.stage)
                status_text = (
                    f"Документ {message.index} из {message.total} · {name} · {stage}"
                )
                self._set_progress_status(status_text)
                self._log(status_text)
                continue
            if message.startswith("__STATUS__:"):
                self.progress.configure(
                    value=progress_value_for_message(message, self._current_progress_value())
                )
                payload = message.split(":", 1)[1]
                explicit_tone, separator, status_text = payload.partition(":")
                if self._network_live_window and explicit_tone in {"success", "error", "cancelled"}:
                    self._finish_network_scan_dashboard(f"Scan result: {payload}")
                elif self._network_live_window:
                    self._append_network_scan_event(f"STATUS: {payload}")
                if separator and explicit_tone in {"success", "error", "cancelled"}:
                    tone = explicit_tone
                else:
                    status_text = payload
                    tone = "error" if "Ошибка" in status_text else "success"
                self._finish_operation(status_text, tone)
            elif message.startswith("__NETWORK_REPORT_PATH__:"):
                path_value = message.split(":", 1)[1].strip()
                if path_value and self._network_live_window:
                    self._set_network_live_report_path(path_value)
            elif message.startswith("__SOURCES__:"):
                self.source_status.set(message.split(":", 1)[1])
            else:
                self.progress.configure(
                    value=progress_value_for_message(message, self._current_progress_value())
                )
                if self._network_live_window:
                    self._append_network_scan_event(message)
                progress_status = progress_status_for_message(message)
                if progress_status:
                    self._set_progress_status(progress_status)
                self._log(message)
        self.root.after(200, self._drain_messages)

    def _log(self, message: str) -> None:
        self.log.configure(state="normal")
        self.log.insert(END, message + "\n")
        self.log.see(END)
        self.log.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", END)
        self.log.configure(state="disabled")

    def _open_report(self) -> None:
        if self.last_report and Path(self.last_report).exists():
            webbrowser.open(Path(self.last_report).resolve().as_uri())
        else:
            messagebox.showinfo("Отчёт", "Сначала сформируйте отчёт.")

    def _open_folder(self) -> None:
        path = Path(self.output_dir.get())
        path.mkdir(parents=True, exist_ok=True)
        webbrowser.open(path.resolve().as_uri())

    def run(self) -> None:
        _frozen_startup_log("mainloop enter")
        self.root.mainloop()
        _frozen_startup_log("mainloop exit")


def main() -> None:
    AuditWindow().run()
