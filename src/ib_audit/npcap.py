from __future__ import annotations

import ctypes
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .commands import run_command


NPCAP_DOWNLOAD_URL = "https://npcap.com/#download"


@dataclass(frozen=True)
class NpcapStatus:
    installed: bool
    install_required: bool
    message: str
    detail: str = ""


@dataclass(frozen=True)
class NpcapInstallLaunchResult:
    ok: bool
    message: str
    download_url: str = NPCAP_DOWNLOAD_URL


ShellExecute = Callable[[object, str, str, str, object, int], int]


def query_npcap_status() -> NpcapStatus:
    if os.name != "nt":
        return NpcapStatus(
            installed=True,
            install_required=False,
            message="Npcap is only required on Windows.",
            detail="non-windows",
        )

    result = run_command(["sc", "query", "npcap"], timeout=5)
    text = f"{result.stdout}\n{result.stderr}".strip()
    if result.ok:
        detail = _service_state_detail(text)
        return NpcapStatus(
            installed=True,
            install_required=False,
            message="Npcap driver service is installed.",
            detail=detail or text,
        )

    lowered = text.casefold()
    if result.returncode == 1060 or "does not exist" in lowered or "1060" in lowered:
        return NpcapStatus(
            installed=False,
            install_required=True,
            message="Npcap is not installed. Packet capture and Nmap OS detection need the Npcap Windows driver.",
            detail=text,
        )
    return NpcapStatus(
        installed=False,
        install_required=False,
        message="Npcap driver status could not be determined.",
        detail=text,
    )


def resolve_npcap_installer() -> Path | None:
    for root in _installer_search_roots():
        installer_dir = root / "tools" / "npcap"
        if not installer_dir.exists():
            continue
        candidates = sorted(
            (
                path
                for path in installer_dir.iterdir()
                if path.is_file() and path.suffix.lower() == ".exe" and "npcap" in path.name.lower()
            ),
            key=_installer_priority,
        )
        if candidates:
            return _persistent_meipass_installer(candidates[0], root) or candidates[0]
    return None


def launch_npcap_installer(
    installer: str | Path,
    shell_execute: ShellExecute | None = None,
) -> NpcapInstallLaunchResult:
    installer_path = Path(installer)
    if not installer_path.exists():
        return NpcapInstallLaunchResult(False, f"Npcap installer was not found: {installer_path}")
    if os.name != "nt":
        return NpcapInstallLaunchResult(False, "Npcap installer can only be launched on Windows.")

    shell_execute_fn = shell_execute or ctypes.windll.shell32.ShellExecuteW  # type: ignore[attr-defined]
    result = int(shell_execute_fn(None, "runas", str(installer_path), "", None, 1))
    if result > 32:
        return NpcapInstallLaunchResult(True, "Npcap installer was launched with administrator privileges.")
    return NpcapInstallLaunchResult(False, f"Npcap installer launch failed with ShellExecute code {result}.")


def _service_state_detail(output: str) -> str:
    for line in output.splitlines():
        if "STATE" in line.upper():
            return line.strip()
    return ""


def _installer_search_roots() -> list[Path]:
    roots: list[Path] = []
    seen: set[Path] = set()

    def add(path: str | Path | None) -> None:
        if not path:
            return
        try:
            resolved = Path(path).resolve()
        except OSError:
            return
        if resolved not in seen:
            seen.add(resolved)
            roots.append(resolved)

    add(getattr(sys, "_MEIPASS", ""))
    module_dir = Path(__file__).resolve()
    for parent in module_dir.parents[:4]:
        add(parent)
    add(Path(sys.executable).resolve().parent)
    return roots


def _installer_priority(path: Path) -> tuple[int, str]:
    name = path.name.lower()
    if "oem" in name:
        return (0, name)
    if "installer" in name:
        return (1, name)
    return (2, name)


def _persistent_meipass_installer(installer: Path, root: Path) -> Path | None:
    meipass = getattr(sys, "_MEIPASS", "")
    if not meipass:
        return None
    try:
        if root.resolve() != Path(meipass).resolve():
            return None
    except OSError:
        return None

    target_dir = _installer_cache_root()
    target = target_dir / installer.name
    marker = target_dir / ".ib-audit-npcap-installer-ready"
    expected_marker = _cache_key(installer)
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        if not target.exists() or not _marker_matches(marker, expected_marker):
            shutil.copy2(installer, target)
            marker.write_text(expected_marker + "\n", encoding="utf-8")
        return target
    except OSError:
        return None


def _installer_cache_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "IBAuditWorkstation" / "installers" / "npcap"
    return Path.home() / "AppData" / "Local" / "IBAuditWorkstation" / "installers" / "npcap"


def _cache_key(path: Path) -> str:
    stat = path.stat()
    return f"{path.name}:{stat.st_size}"


def _marker_matches(marker: Path, expected_marker: str) -> bool:
    try:
        return marker.read_text(encoding="utf-8").strip() == expected_marker
    except OSError:
        return False


__all__ = [
    "NPCAP_DOWNLOAD_URL",
    "NpcapInstallLaunchResult",
    "NpcapStatus",
    "launch_npcap_installer",
    "query_npcap_status",
    "resolve_npcap_installer",
]
