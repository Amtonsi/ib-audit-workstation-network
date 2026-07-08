from __future__ import annotations

import json
import locale
import os
import shutil
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Any


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

    for root in _tool_search_roots():
        for name in candidate_names:
            candidate = (root / "tools" / normalized_tool_dir(tool) / name)
            if candidate.exists():
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


def _decode_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if value.startswith((b"\xff\xfe", b"\xfe\xff")):
        return value.decode("utf-16", errors="replace")
    encodings = ("utf-8-sig", "oem", locale.getpreferredencoding(False))
    for encoding in dict.fromkeys(encodings):
        try:
            return value.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return value.decode(locale.getpreferredencoding(False), errors="replace")


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
