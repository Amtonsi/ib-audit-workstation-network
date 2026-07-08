from __future__ import annotations

import queue
import re
import sys
import threading
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, X, Y, BooleanVar, StringVar, Tk, Toplevel, filedialog, messagebox, scrolledtext, ttk

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
from .network_scan import NETWORK_COMMAND_OPTIONS, NetworkScanConfig


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
        _enable_high_dpi_awareness()
        self.root = Tk()
        self.root.title("IB Audit Workstation")
        self.window_bounds = window_bounds_for_screen(
            self.root.winfo_screenwidth(),
            self.root.winfo_screenheight(),
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
        self.network_ports = StringVar(value="1-65535")
        self.network_extra_args = StringVar(value="")
        self.network_capture_interface = StringVar(value="")
        self.network_capture_duration = StringVar(value="20")
        self.network_capture_filter = StringVar(value="")
        self.network_nmap_no_dns = BooleanVar(value=True)
        self.network_nmap_skip_host_discovery = BooleanVar(value=True)
        self.network_nmap_timing = StringVar(value="T2")
        self.network_nmap_open_only = BooleanVar(value=True)
        self.network_nmap_os_detection = BooleanVar(value=True)
        self.network_nmap_service_detection = BooleanVar(value=True)
        self.network_capture_no_name_resolution = BooleanVar(value=True)
        self.network_capture_quiet = BooleanVar(value=True)
        self.last_report: str | None = None
        self.messages: queue.Queue[object] = queue.Queue()
        self.action_buttons: list[ttk.Button] = []
        self.active_cancel_token: CancellationToken | None = None
        self._last_responsive_layout: ResponsiveLayout | None = None
        self._applying_responsive_layout = False
        self._configure_styles()
        self._build()
        self.root.after(200, self._drain_messages)

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
        self.action_buttons = [live_button, import_button, update_button]

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
        ttk.Label(network_options_row, text="Интерфейс", style="Muted.TLabel").pack(side=LEFT)
        ttk.Entry(network_options_row, textvariable=self.network_capture_interface, width=12).pack(side=LEFT, padx=(12, 14))
        ttk.Label(network_options_row, text="Сек", style="Muted.TLabel").pack(side=LEFT)
        ttk.Entry(network_options_row, textvariable=self.network_capture_duration, width=6).pack(side=LEFT, padx=(8, 0))

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
            ("Интерфейс tshark", self.network_capture_interface, "Номер интерфейса из tshark -D. Если пусто, программа попробует выбрать первый доступный."),
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

    def _start(self, online_sources: bool) -> None:
        status = "Полный аудит компьютера"
        token = self._begin_operation(status)
        self._log("=== Новый аудит ===")
        mode = self._selected_vulnerability_mode()
        self._log(f"Режим уязвимостей: {VULNERABILITY_MODE_TEXT[mode]}")
        network_scan = self._selected_network_scan_config()
        thread_args = (
            (online_sources, mode, token, network_scan)
            if network_scan is not None
            else (online_sources, mode, token)
        )
        thread = threading.Thread(
            target=self._run_background,
            args=thread_args,
            daemon=True,
        )
        thread.start()

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
        try:
            capture_duration = int(self._network_string_value("network_capture_duration", "20") or "20")
        except ValueError:
            capture_duration = 20
        return NetworkScanConfig(
            enabled=True,
            targets=targets,
            ports=self._network_string_value("network_ports", "1-65535") or "1-65535",
            extra_args=self._network_string_value("network_extra_args"),
            nmap_no_dns=self._network_bool_value("network_nmap_no_dns", True),
            nmap_skip_host_discovery=self._network_bool_value("network_nmap_skip_host_discovery", True),
            nmap_timing=self._network_string_value("network_nmap_timing", "T2") or "T2",
            nmap_open_only=self._network_bool_value("network_nmap_open_only", True),
            nmap_os_detection=self._network_bool_value("network_nmap_os_detection", True),
            nmap_service_detection=self._network_bool_value("network_nmap_service_detection", True),
            capture_enabled=self._network_bool_value("network_capture_enabled"),
            capture_interface=self._network_string_value("network_capture_interface") or None,
            capture_duration=max(1, capture_duration),
            capture_filter=self._network_string_value("network_capture_filter"),
            capture_no_name_resolution=self._network_bool_value("network_capture_no_name_resolution", True),
            capture_quiet=self._network_bool_value("network_capture_quiet", True),
        )

    def _run_background(
        self,
        online_sources: bool,
        vulnerability_mode: str = VULNERABILITY_MODE_FULL,
        cancel_token: CancellationToken | None = None,
        network_scan: NetworkScanConfig | None = None,
    ) -> None:
        try:
            result = run_audit(
                db_path=None,
                output_dir=self.output_dir.get(),
                online_sources=online_sources,
                vulnerability_mode=vulnerability_mode,
                network_scan=network_scan,
                open_report=False,
                progress=self.messages.put,
                cancel_token=cancel_token,
            )
            self.last_report = str(result["report_path"])
            self.messages.put(format_result_message(result))
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
                if separator and explicit_tone in {"success", "error", "cancelled"}:
                    tone = explicit_tone
                else:
                    status_text = payload
                    tone = "error" if "Ошибка" in status_text else "success"
                self._finish_operation(status_text, tone)
            elif message.startswith("__SOURCES__:"):
                self.source_status.set(message.split(":", 1)[1])
            else:
                self.progress.configure(
                    value=progress_value_for_message(message, self._current_progress_value())
                )
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
        self.root.mainloop()


def main() -> None:
    AuditWindow().run()
