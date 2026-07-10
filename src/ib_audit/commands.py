from __future__ import annotations

import atexit
import json
import locale
import os
import shutil
import subprocess
import sys
import threading
import zipfile
from pathlib import Path
from dataclasses import dataclass
from typing import Any


_NETWORK_TOOL_EXECUTABLES = {
    "nmap",
    "nmap.exe",
    "tshark",
    "tshark.exe",
    "dumpcap",
    "dumpcap.exe",
}
_ACTIVE_NETWORK_TOOL_PROCESSES: dict[int, Any] = {}
_ACTIVE_NETWORK_TOOL_LOCK = threading.RLock()


def _is_network_tool_command(command: list[str] | tuple[str, ...]) -> bool:
    if not command:
        return False
    return Path(str(command[0])).name.lower() in _NETWORK_TOOL_EXECUTABLES


def register_network_tool_process(process: Any, command: list[str] | tuple[str, ...] | None = None) -> None:
    """Register an app-owned Nmap/Wireshark process for deterministic shutdown."""
    if command is not None and not _is_network_tool_command(command):
        return
    pid = int(getattr(process, "pid", 0) or 0)
    if pid <= 0:
        return
    with _ACTIVE_NETWORK_TOOL_LOCK:
        _ACTIVE_NETWORK_TOOL_PROCESSES[pid] = process


def unregister_network_tool_process(process: Any) -> None:
    pid = int(getattr(process, "pid", 0) or 0)
    if pid <= 0:
        return
    with _ACTIVE_NETWORK_TOOL_LOCK:
        _ACTIVE_NETWORK_TOOL_PROCESSES.pop(pid, None)


def _terminate_process_tree(process: Any) -> None:
    try:
        if process.poll() is not None:
            return
    except Exception:
        return

    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                shell=False,
                **hidden_subprocess_kwargs(),
            )
        except Exception:
            pass

    try:
        if process.poll() is not None:
            return
        process.terminate()
        process.wait(timeout=3)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass


def terminate_network_tool_processes() -> None:
    """Stop only Nmap/Wireshark process trees launched by this application."""
    with _ACTIVE_NETWORK_TOOL_LOCK:
        processes = list(_ACTIVE_NETWORK_TOOL_PROCESSES.values())
    for process in processes:
        try:
            _terminate_process_tree(process)
        finally:
            unregister_network_tool_process(process)


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def _tool_search_roots() -> list[Path]:
    meipass = getattr(sys, "_MEIPASS", "")
    roots: list[Path] = []
    seen: set[Path] = set()

    if meipass:
        roots.append(Path(meipass))

    module_dir = Path(__file__).resolve()
    for level in (1, 2, 3):
        if len(module_dir.parents) >= level:
            parent = module_dir.parents[level - 1]
            if parent not in seen:
                seen.add(parent)
                roots.append(parent)

    exe_dir = Path(sys.executable).resolve().parent
    if exe_dir not in seen:
        roots.append(exe_dir)

    return roots


def _tool_executables(tool: str) -> list[str]:
    normalized = tool.strip().lower()
    if normalized == "nmap":
        return ["nmap.exe", "nmap"]
    if normalized == "tshark":
        return ["tshark.exe", "tshark"]
    if os.name == "nt":
        return [f"{tool}.exe", tool]
    return [tool]


def resolve_tool_command(tool: str) -> str:
    candidate_names = _tool_executables(tool)
    tool_dir = normalized_tool_dir(tool)

    for root in _tool_search_roots():
        bundled_candidate = _cached_pyinstaller_tool_bundle_command(root, tool_dir, candidate_names)
        if bundled_candidate is not None:
            return str(bundled_candidate)
        for name in candidate_names:
            candidate = (root / "tools" / tool_dir / name)
            if candidate.exists():
                cached_candidate = _cached_pyinstaller_tool_command(root, tool_dir, name)
                if cached_candidate is not None:
                    return str(cached_candidate)
                return str(candidate)

    for name in candidate_names:
        system_path = shutil.which(name)
        if system_path:
            return system_path

    return candidate_names[0]


def command_exists(command: str) -> bool:
    command_path = Path(command)
    if command_path.is_absolute() or str(command_path).find("\\") >= 0 or str(command_path).find("/") >= 0:
        return command_path.exists()
    return shutil.which(str(command_path)) is not None


def normalized_tool_dir(tool: str) -> str:
    return {"nmap": "nmap", "tshark": "wireshark"}.get(tool.strip().lower(), tool.strip().lower())


def _cached_pyinstaller_tool_bundle_command(bundle_root: Path, tool_dir: str, executable_names: list[str]) -> Path | None:
    if not _is_pyinstaller_bundle_root(bundle_root):
        return None
    bundle_path = bundle_root / "tools-bundles" / f"{tool_dir}.zip"
    if not bundle_path.exists():
        return None

    cache_dir = _bundled_tool_cache_root() / tool_dir
    marker = cache_dir / ".ib-audit-tool-cache-ready"
    expected_marker = _tool_cache_key(bundle_path)
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        if not _tool_cache_marker_matches(marker, expected_marker) or not any(
            (cache_dir / name).exists() for name in executable_names
        ):
            with zipfile.ZipFile(bundle_path) as archive:
                archive.extractall(cache_dir)
            marker.write_text(expected_marker + "\n", encoding="utf-8")
        for name in executable_names:
            candidate = cache_dir / name
            if candidate.exists():
                return candidate
    except (OSError, zipfile.BadZipFile):
        return None
    return None


def _cached_pyinstaller_tool_command(bundle_root: Path, tool_dir: str, executable_name: str) -> Path | None:
    if not _is_pyinstaller_bundle_root(bundle_root):
        return None

    source_dir = bundle_root / "tools" / tool_dir
    source_executable = source_dir / executable_name
    if not source_executable.exists():
        return None

    cache_dir = _bundled_tool_cache_root() / tool_dir
    cache_executable = cache_dir / executable_name
    marker = cache_dir / ".ib-audit-tool-cache-ready"
    expected_marker = _tool_cache_key(source_executable)
    try:
        if _tool_cache_needs_refresh(source_executable, cache_executable, marker, expected_marker):
            cache_dir.mkdir(parents=True, exist_ok=True)
            if marker.exists():
                marker.unlink()
            shutil.copytree(source_dir, cache_dir, dirs_exist_ok=True)
            marker.write_text(expected_marker + "\n", encoding="utf-8")
        if cache_executable.exists():
            return cache_executable
    except OSError:
        return None
    return None


def _is_pyinstaller_bundle_root(bundle_root: Path) -> bool:
    meipass = getattr(sys, "_MEIPASS", "")
    if not meipass:
        return False
    try:
        return bundle_root.resolve() == Path(meipass).resolve()
    except OSError:
        return False


def _bundled_tool_cache_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "IBAuditWorkstation" / "bundled-tools"
    if os.name == "nt":
        return Path.home() / "AppData" / "Local" / "IBAuditWorkstation" / "bundled-tools"
    return Path.home() / ".cache" / "IBAuditWorkstation" / "bundled-tools"


def _tool_cache_needs_refresh(
    source_executable: Path, cache_executable: Path, marker: Path, expected_marker: str
) -> bool:
    if not cache_executable.exists() or not marker.exists():
        return True
    if not _tool_cache_marker_matches(marker, expected_marker):
        return True
    try:
        return source_executable.stat().st_size != cache_executable.stat().st_size
    except OSError:
        return True


def _tool_cache_marker_matches(marker: Path, expected_marker: str) -> bool:
    try:
        return marker.read_text(encoding="utf-8").strip() == expected_marker
    except OSError:
        return False


def _tool_cache_key(path: Path) -> str:
    stat = path.stat()
    return f"{path.name}:{stat.st_size}"


def _decode_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if value.startswith((b"\xff\xfe", b"\xfe\xff")):
        return value.decode("utf-16", errors="replace")

    encodings = (
        "utf-8-sig",
        "utf-8",
        locale.getpreferredencoding(False),
        "mbcs",
        "oem",
        "cp866",
        "cp1251",
    )
    candidates: list[tuple[tuple[int, int, int, int], str]] = []
    for encoding in dict.fromkeys(encodings):
        try:
            decoded = value.decode(encoding, errors="replace")
        except LookupError:
            continue
        candidates.append((_decode_quality_score(decoded), decoded))
    if candidates:
        return min(candidates, key=lambda item: item[0])[1]
    return value.decode(locale.getpreferredencoding(False), errors="replace")


def _decode_quality_score(text: str) -> tuple[int, int, int, int]:
    replacements = text.count("\ufffd")
    box_drawing = sum(1 for char in text if "\u2500" <= char <= "\u259f")
    controls = sum(1 for char in text if ord(char) < 32 and char not in "\r\n\t")
    latin1_mojibake = sum(1 for char in text if 0x00A0 <= ord(char) <= 0x00BF)
    rare_cyrillic = sum(
        1
        for char in text
        if ("\u0400" <= char <= "\u040f" or "\u0490" <= char <= "\u04ff") and char not in "\u0401\u0451"
    )
    normal_cyrillic = sum(1 for char in text if "\u0410" <= char <= "\u044f" or char in "\u0401\u0451")
    return (replacements, box_drawing + controls + latin1_mojibake, rare_cyrillic, -normal_cyrillic)


def hidden_subprocess_kwargs() -> dict[str, object]:
    if os.name != "nt":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return {
        "creationflags": subprocess.CREATE_NO_WINDOW,
        "startupinfo": startupinfo,
    }


def run_command(command: list[str], timeout: int = 20) -> CommandResult:
    if _is_network_tool_command(command):
        return _run_tracked_network_tool_command(command, timeout)
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=False,
            timeout=timeout,
            shell=False,
            **hidden_subprocess_kwargs(),
        )
        return CommandResult(command, proc.returncode, _decode_output(proc.stdout), _decode_output(proc.stderr))
    except subprocess.TimeoutExpired as exc:
        return CommandResult(command, 124, _decode_output(exc.stdout), _decode_output(exc.stderr), timed_out=True)
    except Exception as exc:
        return CommandResult(command, 1, "", str(exc))


def _run_tracked_network_tool_command(command: list[str], timeout: int) -> CommandResult:
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            shell=False,
            **hidden_subprocess_kwargs(),
        )
    except Exception as exc:
        return CommandResult(command, 1, "", str(exc))

    register_network_tool_process(proc, command)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return CommandResult(command, int(proc.returncode or 0), _decode_output(stdout), _decode_output(stderr))
    except subprocess.TimeoutExpired as exc:
        _terminate_process_tree(proc)
        try:
            stdout, stderr = proc.communicate(timeout=2)
        except Exception:
            stdout, stderr = exc.stdout, exc.stderr
        return CommandResult(command, 124, _decode_output(stdout), _decode_output(stderr), timed_out=True)
    except Exception as exc:
        _terminate_process_tree(proc)
        return CommandResult(command, 1, "", str(exc))
    finally:
        unregister_network_tool_process(proc)


atexit.register(terminate_network_tool_processes)


def run_powershell_json(script: str, timeout: int = 30) -> tuple[list[dict[str, Any]], CommandResult]:
    command = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        f"[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); {script} | ConvertTo-Json -Depth 6",
    ]
    result = run_command(command, timeout=timeout)
    if not result.ok or not result.stdout.strip():
        return [], result
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError:
        return [], result
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)], result
    if isinstance(parsed, dict):
        return [parsed], result
    return [], result
