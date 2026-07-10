import os
import sys
import traceback
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)


def _startup_log_path() -> str | None:
    if not getattr(sys, "frozen", False):
        return None
    base_dir = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    log_dir = os.path.join(base_dir, "IBAuditWorkstation", "logs")
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, "startup.log")


def _startup_log(message: str) -> None:
    path = _startup_log_path()
    if path is None:
        return
    timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(f"{timestamp} {message}\n")
    except OSError:
        return


def _install_startup_exception_logging() -> None:
    if not getattr(sys, "frozen", False):
        return

    def _log_unhandled_exception(exc_type, exc_value, exc_traceback):
        details = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        _startup_log("unhandled_exception\n" + details)
        sys.__excepthook__(exc_type, exc_value, exc_traceback)

    sys.excepthook = _log_unhandled_exception


_install_startup_exception_logging()
_startup_log(
    "startup "
    f"executable={sys.executable!r} "
    f"root={ROOT!r} "
    f"meipass={getattr(sys, '_MEIPASS', '')!r}"
)

try:
    from ib_audit.gui_tk import main
    _startup_log("imported ib_audit.gui_tk.main")
except Exception:
    _startup_log("import_failed\n" + traceback.format_exc())
    raise


if __name__ == "__main__":
    _startup_log("enter main")
    try:
        main()
    except Exception:
        _startup_log("main_failed\n" + traceback.format_exc())
        raise
    finally:
        try:
            from ib_audit.commands import terminate_network_tool_processes

            terminate_network_tool_processes()
            _startup_log("network_tools_stopped")
        except Exception:
            _startup_log("network_tool_cleanup_failed\n" + traceback.format_exc())
    _startup_log("main_returned")
