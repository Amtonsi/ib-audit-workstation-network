from __future__ import annotations

import threading


class AuditCancelled(RuntimeError):
    """Raised when cooperative cancellation reaches a safe checkpoint."""


class CancellationToken:
    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> bool:
        if self._event.is_set():
            return False
        self._event.set()
        return True

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self.is_cancelled():
            raise AuditCancelled("Audit cancelled by user.")
