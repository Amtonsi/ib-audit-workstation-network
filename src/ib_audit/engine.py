from __future__ import annotations

import socket
import time
from dataclasses import asdict
from typing import Callable

from .admin import is_admin
from .cancellation import AuditCancelled, CancellationToken
from .collectors import get_collectors
from .models import AuditRun, CollectorDiagnostic, InventoryObject, utc_now
from .normalization import detect_windows_profile
from .repository import SQLiteRepository
from .security_collectors import ensure_category_diagnostics
from .network_scan import NetworkScanConfig


ProgressCallback = Callable[[str], None]


class AuditEngine:
    def __init__(
        self,
        repository: SQLiteRepository,
        progress: ProgressCallback | None = None,
        cancel_token: CancellationToken | None = None,
        network_scan_config: NetworkScanConfig | None = None,
        only_network: bool = False,
    ):
        self.repository = repository
        self.progress = progress or (lambda message: None)
        self.cancel_token = cancel_token or CancellationToken()
        self.network_scan_config = network_scan_config
        self.only_network = only_network

    def run(self) -> tuple[AuditRun, list[InventoryObject], list[CollectorDiagnostic]]:
        run = AuditRun.create(socket.gethostname(), is_admin())
        self.repository.save_run(run)
        inventory: list[InventoryObject] = []
        diagnostics: list[CollectorDiagnostic] = []
        self.progress(f"Audit started for {run.hostname}; admin={run.is_admin}")
        try:
            for collector in get_collectors(self.network_scan_config, only_network=self.only_network):
                self.cancel_token.raise_if_cancelled()
                start = time.perf_counter()
                self.progress(f"Running collector: {collector.name}")
                try:
                    objects, diag = collector.func(self.progress)
                    self.cancel_token.raise_if_cancelled()
                    inventory.extend(objects)
                    diagnostics.extend(diag)
                    elapsed = time.perf_counter() - start
                    diagnostics.append(
                        CollectorDiagnostic(
                            collector.name,
                            "info",
                            f"Collected {len(objects)} records in {elapsed:.1f}s",
                            collector.category_name,
                        )
                    )
                except AuditCancelled:
                    raise
                except Exception as exc:
                    diagnostics.append(
                        CollectorDiagnostic(
                            collector.name, "error", str(exc), collector.category_name
                        )
                    )
                    self.progress(f"Collector failed: {collector.name}: {exc}")
            diagnostics = ensure_category_diagnostics(inventory, diagnostics)
            run.finished_at = utc_now()
            run.status = "completed"
            run.summary = {
                "inventory_objects": len(inventory),
                "diagnostics": len(diagnostics),
                "warnings": sum(1 for d in diagnostics if d.severity in {"warning", "error"}),
                "windows_profile": asdict(detect_windows_profile(inventory)),
            }
            self.repository.save_run(run)
            self.repository.save_inventory_objects(run.id, inventory)
            self.repository.save_diagnostics(run.id, diagnostics)
            self.progress(f"Audit completed: {len(inventory)} inventory objects")
            return run, inventory, diagnostics
        except AuditCancelled:
            run.finished_at = utc_now()
            run.status = "cancelled"
            run.summary = {
                "inventory_objects": len(inventory),
                "diagnostics": len(diagnostics),
                "warnings": sum(
                    1 for item in diagnostics if item.severity in {"warning", "error"}
                ),
            }
            self.repository.save_run(run)
            self.repository.save_inventory_objects(run.id, inventory)
            self.repository.save_diagnostics(run.id, diagnostics)
            self.progress(
                f"Audit cancelled: {len(inventory)} inventory objects collected"
            )
            raise
