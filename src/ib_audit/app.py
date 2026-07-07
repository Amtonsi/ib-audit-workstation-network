from __future__ import annotations

import os
import ssl
import subprocess
import tempfile
import urllib.error
import webbrowser
import zipfile
from dataclasses import asdict
from pathlib import Path

from .assessment import AssessmentService
from .batch import (
    BatchAssessment,
    BatchDocumentFailure,
    BatchDocumentResult,
    BatchProgress,
    normalize_report_paths,
)
from .cancellation import AuditCancelled, CancellationToken
from .engine import AuditEngine
from .fstec import FstecBduClient
from .models import AuditRun, ReportRecord, utc_now
from .report_import import ReportImportError, import_audit_report
from .repository import SQLiteRepository
from .report import HtmlReportBuilder
from .vulnerabilities import VulnerabilityCorrelator, VulnerabilityDatabaseSourceClient
from .vulnerabilities import VulnerabilitySourceClient
from .source_cache import SnapshotCache
from .vulnerability_database import (
    VULNERABILITY_DB_NAME,
    VulnerabilityDatabaseBuilder,
    find_vulnerability_database,
)
from .network_scan import NetworkScanConfig


VULNERABILITY_MODE_FULL = "full"
VULNERABILITY_MODE_FAST = "fast"
VULNERABILITY_MODES = {VULNERABILITY_MODE_FULL, VULNERABILITY_MODE_FAST}
FSTEC_BDU_XLSX_URL = "https://bdu.fstec.ru/files/documents/vullist.xlsx"
FSTEC_BDU_XLSX_NAMES = {
    "vullist.xlsx",
    "fstec-vullist.xlsx",
    "bdu-vullist.xlsx",
}
FSTEC_ASUTP_XLSX_MARKERS = (
    "уязвимости по",
    "asutp",
    "асутп",
    "bduasutp",
)


def default_output_dir() -> Path:
    return Path.cwd() / "outputs"


def normalize_vulnerability_mode(mode: str | None) -> str:
    return mode if mode in VULNERABILITY_MODES else VULNERABILITY_MODE_FULL


def update_vulnerability_sources(
    cache_dir: str | Path | None = None,
    progress=None,
    client: VulnerabilitySourceClient | None = None,
) -> dict[str, object]:
    cache = SnapshotCache(cache_dir or default_output_dir() / "cache")
    source_client = client or VulnerabilitySourceClient(cache=cache, online=True)
    if progress:
        progress("Updating CISA KEV catalog")
    _records, diagnostics = source_client.fetch_cisa_kev()
    return {"snapshots": source_client.used_snapshots, "diagnostics": diagnostics}


def _fstec_source_for_xlsx(path: Path) -> str | None:
    name = path.name.casefold()
    stem = path.stem.casefold()
    if name in FSTEC_BDU_XLSX_NAMES:
        return "fstec-bdu"
    if any(marker in stem for marker in FSTEC_ASUTP_XLSX_MARKERS):
        return "fstec-asutp"
    return None


def _iter_existing_search_roots(*roots: Path) -> list[Path]:
    result: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        try:
            candidate = root.resolve()
        except OSError:
            candidate = root
        if candidate in seen or not candidate.exists():
            continue
        seen.add(candidate)
        result.append(candidate)
    return result


def discover_fstec_xlsx_sources(
    project_root: str | Path,
    output_dir: str | Path,
    db_path: str | Path,
) -> list[tuple[str, Path]]:
    roots = _iter_existing_search_roots(
        Path(project_root),
        Path(output_dir),
        Path(db_path).parent,
    )
    discovered: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    for root in roots:
        try:
            paths = sorted(root.rglob("*.xlsx"))
        except OSError:
            continue
        for path in paths:
            source = _fstec_source_for_xlsx(path)
            if source is None:
                continue
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if resolved in seen:
                continue
            seen.add(resolved)
            discovered.append((source, path))
    return sorted(discovered, key=lambda item: (0 if item[0] == "fstec-asutp" else 1, str(item[1]).casefold()))


def _merge_fstec_xlsx_sources(
    explicit_paths: list[tuple[str, Path]] | tuple[tuple[str, Path], ...] | None,
    discovered_paths: list[tuple[str, Path]],
) -> list[tuple[str, Path]]:
    merged: list[tuple[str, Path]] = []
    seen: set[tuple[str, Path]] = set()
    for source, path in [*(explicit_paths or ()), *discovered_paths]:
        candidate = Path(path)
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate
        key = (source, resolved)
        if key in seen:
            continue
        seen.add(key)
        merged.append((source, candidate))
    return merged


def _is_valid_xlsx(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0 and zipfile.is_zipfile(path)
    except OSError:
        return False


def _has_valid_fstec_bdu_xlsx(paths: list[tuple[str, Path]]) -> bool:
    return any(source == "fstec-bdu" and _is_valid_xlsx(Path(path)) for source, path in paths)


def _is_ssl_certificate_error(exc: BaseException) -> bool:
    reason = getattr(exc, "reason", None)
    return isinstance(reason, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(exc)


def _download_with_windows_cert_store(url: str, path: Path, timeout: int = 30) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        (
            "$ProgressPreference='SilentlyContinue'; "
            "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
            "Invoke-WebRequest -UseBasicParsing -Uri $env:IB_AUDIT_DOWNLOAD_URL "
            "-OutFile $env:IB_AUDIT_DOWNLOAD_PATH"
        ),
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={
                **os.environ,
                "IB_AUDIT_DOWNLOAD_URL": url,
                "IB_AUDIT_DOWNLOAD_PATH": str(target),
            },
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"PowerShell download timed out after {timeout} seconds") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(f"PowerShell download failed: {detail}")


def _download_official_fstec_bdu_xlsx(
    snapshot_dir: Path,
    progress=None,
    download_progress=None,
    cancel_token: CancellationToken | None = None,
) -> Path:
    target = snapshot_dir / "fstec-bdu" / "vullist.xlsx"
    if progress:
        progress(f"Downloading FSTEC BDU XLSX: {FSTEC_BDU_XLSX_URL}")
    try:
        VulnerabilityDatabaseBuilder._download_to_file(
            FSTEC_BDU_XLSX_URL,
            target,
            attempts=1,
            timeout=30,
            label="FSTEC BDU vullist.xlsx",
            progress=download_progress,
            cancel_token=cancel_token,
        )
    except urllib.error.URLError as exc:
        if not _is_ssl_certificate_error(exc) or os.name != "nt":
            raise
        if progress:
            progress("Python TLS validation failed for FSTEC BDU; retrying via Windows certificate store")
        _download_with_windows_cert_store(FSTEC_BDU_XLSX_URL, target)
    if not _is_valid_xlsx(target):
        try:
            target.unlink()
        except OSError:
            pass
        raise ValueError(f"Downloaded FSTEC BDU XLSX is not a valid XLSX file: {target}")
    return target


def update_vulnerability_database(
    output_dir: str | Path | None = None,
    project_root: str | Path | None = None,
    start_year: int = 2002,
    end_year: int | None = None,
    include_delta: bool = True,
    include_cpe: bool = True,
    include_cpe_match: bool = False,
    fstec_xlsx_paths: list[tuple[str, Path]] | tuple[tuple[str, Path], ...] | None = None,
    progress=None,
    download_progress=None,
    cancel_token: CancellationToken | None = None,
) -> dict[str, object]:
    output = Path(output_dir or default_output_dir() / "vulnerability-database")
    root = Path(project_root or Path.cwd())
    db_path = find_vulnerability_database(root) or output / VULNERABILITY_DB_NAME
    snapshot_dir = db_path.parent / "snapshots"
    builder = VulnerabilityDatabaseBuilder(snapshot_dir, db_path)
    local_fstec_xlsx_paths = _merge_fstec_xlsx_sources(
        fstec_xlsx_paths,
        discover_fstec_xlsx_sources(root, output, db_path),
    )
    fstec_download_errors = 0
    if not _has_valid_fstec_bdu_xlsx(local_fstec_xlsx_paths):
        try:
            downloaded_bdu = _download_official_fstec_bdu_xlsx(
                snapshot_dir,
                progress=progress,
                download_progress=download_progress,
                cancel_token=cancel_token,
            )
            local_fstec_xlsx_paths = _merge_fstec_xlsx_sources(
                local_fstec_xlsx_paths,
                [("fstec-bdu", downloaded_bdu)],
            )
        except AuditCancelled:
            raise
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            fstec_download_errors += 1
            if progress:
                progress(f"FSTEC BDU XLSX download skipped: {exc}")
    stats = builder.update_database(
        start_year=start_year,
        end_year=end_year,
        include_delta=include_delta,
        include_cpe=include_cpe,
        include_cpe_match=include_cpe_match,
        progress=progress,
        download_progress=download_progress,
        cancel_token=cancel_token,
    )
    if local_fstec_xlsx_paths:
        fstec_records = 0
        fstec_products = 0
        fstec_import_errors = 0
        for source, xlsx_path in local_fstec_xlsx_paths:
            token_path = Path(xlsx_path)
            if progress:
                progress(f"Indexing FSTEC XLSX {source}: {token_path}")
            try:
                imported = builder.import_fstec_xlsx(
                    token_path,
                    source,
                    progress=progress,
                    cancel_token=cancel_token,
                )
            except AuditCancelled:
                raise
            except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
                fstec_import_errors += 1
                if progress:
                    progress(f"Skipping FSTEC XLSX {token_path}: {exc}")
                continue
            fstec_records += int(imported.get("fstec_records", 0))
            fstec_products += int(imported.get("fstec_products", 0))
        stats["fstec_records"] = fstec_records
        stats["fstec_products"] = fstec_products
        stats["fstec_import_errors"] = fstec_import_errors
    stats["fstec_download_errors"] = fstec_download_errors
    return {"db_path": db_path, "snapshot_dir": snapshot_dir, "stats": stats}


def _create_vulnerability_correlator(
    cache: SnapshotCache | None = None,
    online_sources: bool = True,
    vulnerability_mode: str = VULNERABILITY_MODE_FULL,
    vulnerability_db_path: str | Path | None = None,
) -> VulnerabilityCorrelator:
    mode = normalize_vulnerability_mode(vulnerability_mode)
    source_online = online_sources and mode == VULNERABILITY_MODE_FULL
    use_live_fstec = online_sources and mode == VULNERABILITY_MODE_FULL
    if use_live_fstec:
        fstec_client = FstecBduClient() if cache is None else FstecBduClient(cache=cache, online=True)
    else:
        fstec_client = None
    if vulnerability_db_path:
        return VulnerabilityCorrelator(
            fstec_client=fstec_client,
            source_client=VulnerabilityDatabaseSourceClient(vulnerability_db_path),
        )
    if cache is None and source_online:
        return VulnerabilityCorrelator(fstec_client=fstec_client)
    return VulnerabilityCorrelator(
        fstec_client=fstec_client,
        source_client=VulnerabilitySourceClient(cache=cache, online=source_online),
    )


def _audit_database_path(db_path: str | Path | None) -> tuple[Path, str, tempfile.TemporaryDirectory | None]:
    if db_path is not None:
        path = Path(db_path)
        return path, str(path), None
    temp_dir = tempfile.TemporaryDirectory(prefix="ib-audit-db-")
    return Path(temp_dir.name) / "ib_audit.db", "temporary", temp_dir


def _cleanup_audit_database(temp_db: tempfile.TemporaryDirectory | None) -> None:
    if temp_db is not None:
        temp_db.cleanup()


def run_audit(
    db_path: str | Path | None = None,
    output_dir: str | Path | None = None,
    enrich: bool = False,
    online_sources: bool = True,
    vulnerability_mode: str = VULNERABILITY_MODE_FULL,
    network_scan: NetworkScanConfig | None = None,
    open_report: bool = False,
    progress=None,
    cancel_token: CancellationToken | None = None,
) -> dict[str, object]:
    token = cancel_token or CancellationToken()
    output = Path(output_dir or default_output_dir())
    output.mkdir(parents=True, exist_ok=True)
    db, db_label, _temp_db = _audit_database_path(db_path)
    repo = SQLiteRepository(db)
    engine = AuditEngine(
        repo,
        progress=progress,
        cancel_token=token,
        network_scan_config=network_scan,
    )
    run, inventory, diagnostics = engine.run()
    if progress:
        progress("Assessing vulnerabilities, configuration, and exposure")
    service = AssessmentService(
        _create_vulnerability_correlator(
            SnapshotCache(output / "cache"),
            online_sources,
            vulnerability_mode=vulnerability_mode,
            vulnerability_db_path=find_vulnerability_database(output) or find_vulnerability_database(Path.cwd()),
        )
    )
    try:
        assessment = service.assess(
            inventory,
            progress=progress,
            cancel_token=token,
        )
    except AuditCancelled:
        run.finished_at = utc_now()
        run.status = "cancelled"
        repo.save_run(run)
        _cleanup_audit_database(_temp_db)
        raise
    diagnostics.extend(assessment.diagnostics)
    repo.save_diagnostics(run.id, assessment.diagnostics)
    repo.save_vulnerability_matches(run.id, assessment.vulnerabilities)
    repo.save_vulnerability_coverage(run.id, assessment.vulnerability_coverage)
    repo.save_assessment_bundle(run.id, assessment.rule_results, assessment.assessments, assessment.coverage)
    for snapshot in assessment.snapshots:
        repo.save_source_snapshot(run.id, snapshot)
    run.summary.update({
        "risk_count": assessment.coverage.risk,
        "coverage_percent": assessment.coverage.document_percent,
        "rule_checked_percent": assessment.coverage.rule_checked_percent,
        "insufficient_count": assessment.coverage.insufficient_data,
        "windows_profile": asdict(assessment.profile),
    })
    repo.save_run(run)
    report_path = HtmlReportBuilder().build(output, run, inventory, diagnostics, assessment)
    repo.save_report(ReportRecord(run.id, report_path, "html"))
    batch_report_path = None
    try:
        batch_report_path = _build_single_run_batch_report(
            output,
            run,
            inventory,
            diagnostics,
            assessment,
        )
        repo.save_report(ReportRecord(run.id, batch_report_path, "batch-html"))
    except Exception as exc:
        if progress:
            progress(f"Batch report build failed, fallback to standard HTML report: {exc}")
        batch_report_path = None

    if open_report:
        webbrowser.open(Path(batch_report_path or report_path).resolve().as_uri())
    _cleanup_audit_database(_temp_db)
    return {
        "run": run,
        "db_path": db_label,
        "report_path": report_path,
        "single_report_path": report_path,
        "batch_report_path": batch_report_path,
        "inventory_count": len(inventory),
        "diagnostic_count": len(diagnostics),
        "vulnerability_count": len(assessment.vulnerabilities),
        "risk_count": assessment.coverage.risk,
        "coverage_percent": assessment.coverage.document_percent,
        "rule_checked_percent": assessment.coverage.rule_checked_percent,
        "insufficient_count": assessment.coverage.insufficient_data,
    }


def _analyze_imported_document(
    source_path: Path,
    repo: SQLiteRepository,
    service: AssessmentService,
    progress=None,
    cancel_token: CancellationToken | None = None,
) -> BatchDocumentResult:
    token = cancel_token or CancellationToken()
    token.raise_if_cancelled()
    if progress:
        progress(f"Importing local HTML report: {source_path.name}")
    imported = import_audit_report(source_path)
    token.raise_if_cancelled()
    run = AuditRun.create(hostname=imported.hostname, is_admin=False)
    run.summary = {
        "mode": "imported_report_analysis",
        "source_report": str(source_path.resolve()),
        "source_format": imported.report_format,
        "inventory_count": len(imported.inventory),
    }
    repo.save_run(run)

    try:
        repo.save_source_document(run.id, imported.document)
        repo.save_inventory_objects(run.id, imported.inventory)
        if progress:
            progress(
                f"Imported {len(imported.inventory)} objects from {imported.report_format}. "
                "Checking CISA KEV and NVD."
            )
        assessment = service.assess(
            imported.inventory,
            progress=progress,
            cancel_token=token,
        )
        token.raise_if_cancelled()
        vulnerabilities = assessment.vulnerabilities
        diagnostics = [*imported.diagnostics, *assessment.diagnostics]
        repo.save_diagnostics(run.id, diagnostics)
        repo.save_vulnerability_matches(run.id, vulnerabilities)
        repo.save_vulnerability_coverage(run.id, assessment.vulnerability_coverage)
        repo.save_assessment_bundle(run.id, assessment.rule_results, assessment.assessments, assessment.coverage)
        for snapshot in assessment.snapshots:
            repo.save_source_snapshot(run.id, snapshot)

        run.finished_at = utc_now()
        run.status = "completed"
        run.summary.update(
            {
                "diagnostic_count": len(diagnostics),
                "vulnerability_count": len(vulnerabilities),
                "risk_count": assessment.coverage.risk,
                "coverage_percent": assessment.coverage.document_percent,
                "rule_checked_percent": assessment.coverage.rule_checked_percent,
                "insufficient_count": assessment.coverage.insufficient_data,
                "windows_profile": asdict(assessment.profile),
            }
        )
        repo.save_run(run)
    except AuditCancelled:
        run.finished_at = utc_now()
        run.status = "cancelled"
        repo.save_run(run)
        raise
    except Exception as exc:
        run.finished_at = utc_now()
        run.status = "failed"
        run.summary["error"] = str(exc)
        repo.save_run(run)
        raise

    return BatchDocumentResult(
        source_path=source_path,
        source_format=imported.report_format,
        run=run,
        inventory=imported.inventory,
        diagnostics=diagnostics,
        assessment=assessment,
    )


def _build_single_run_batch_report(
    output: Path,
    run: AuditRun,
    inventory: list[InventoryObject],
    diagnostics: list[CollectorDiagnostic],
    assessment: AssessmentBundle,
) -> str:
    synthetic_source = output / f"{run.hostname}-live-system.html"
    document = BatchDocumentResult(
        source_path=synthetic_source,
        source_format="live-system",
        run=run,
        inventory=inventory,
        diagnostics=diagnostics,
        assessment=assessment,
    )
    from .batch_report import BatchHtmlReportBuilder

    batch = BatchAssessment.create(
        selected_paths=[synthetic_source],
        completed=[document],
        failures=[],
        status="completed",
        started_at=run.started_at,
    )
    return BatchHtmlReportBuilder().build(output, batch)


def _analysis_service(
    output: Path,
    online_sources: bool,
    vulnerability_mode: str,
    correlator: VulnerabilityCorrelator | None = None,
    assessment_service: AssessmentService | None = None,
) -> AssessmentService:
    vulnerability_db_path = find_vulnerability_database(output) or find_vulnerability_database(Path.cwd())
    return assessment_service or AssessmentService(
        correlator
        or _create_vulnerability_correlator(
            SnapshotCache(output / "cache"),
            online_sources,
            vulnerability_mode=vulnerability_mode,
            vulnerability_db_path=vulnerability_db_path,
        )
    )


def analyze_report(
    report_path: str | Path,
    db_path: str | Path | None = None,
    output_dir: str | Path | None = None,
    open_report: bool = False,
    progress=None,
    correlator: VulnerabilityCorrelator | None = None,
    assessment_service: AssessmentService | None = None,
    online_sources: bool = True,
    vulnerability_mode: str = VULNERABILITY_MODE_FULL,
    cancel_token: CancellationToken | None = None,
) -> dict[str, object]:
    source_path = Path(report_path)
    output = Path(output_dir or default_output_dir())
    output.mkdir(parents=True, exist_ok=True)
    db, db_label, _temp_db = _audit_database_path(db_path)
    repo = SQLiteRepository(db)
    service = _analysis_service(
        output,
        online_sources,
        vulnerability_mode,
        correlator=correlator,
        assessment_service=assessment_service,
    )
    document = _analyze_imported_document(
        source_path,
        repo,
        service,
        progress=progress,
        cancel_token=cancel_token,
    )
    report_output = HtmlReportBuilder().build(
        output,
        document.run,
        document.inventory,
        document.diagnostics,
        document.assessment,
    )
    repo.save_report(ReportRecord(document.run.id, report_output, "html"))
    if open_report:
        webbrowser.open(Path(report_output).resolve().as_uri())
    _cleanup_audit_database(_temp_db)
    return {
        "run": document.run,
        "db_path": db_label,
        "report_path": report_output,
        "source_format": document.source_format,
        "source_report": str(source_path.resolve()),
        "inventory_count": len(document.inventory),
        "diagnostic_count": len(document.diagnostics),
        "vulnerability_count": len(document.assessment.vulnerabilities),
        "risk_count": document.assessment.coverage.risk,
        "coverage_percent": document.assessment.coverage.document_percent,
        "rule_checked_percent": document.assessment.coverage.rule_checked_percent,
        "insufficient_count": document.assessment.coverage.insufficient_data,
    }


def analyze_reports(
    report_paths,
    db_path: str | Path | None = None,
    output_dir: str | Path | None = None,
    open_report: bool = False,
    progress=None,
    assessment_service: AssessmentService | None = None,
    online_sources: bool = True,
    vulnerability_mode: str = VULNERABILITY_MODE_FULL,
    cancel_token: CancellationToken | None = None,
    report_builder=None,
) -> dict[str, object]:
    paths = normalize_report_paths(report_paths)
    if not paths:
        raise ValueError("Select at least one HTML report.")
    token = cancel_token or CancellationToken()
    output = Path(output_dir or default_output_dir())
    output.mkdir(parents=True, exist_ok=True)
    db, db_label, _temp_db = _audit_database_path(db_path)
    repo = SQLiteRepository(db)
    service = _analysis_service(
        output,
        online_sources,
        vulnerability_mode,
        assessment_service=assessment_service,
    )
    completed: list[BatchDocumentResult] = []
    failures: list[BatchDocumentFailure] = []
    started_at = utc_now()
    for index, path in enumerate(paths, 1):
        if token.is_cancelled():
            break
        if progress:
            progress(BatchProgress(index, len(paths), "import", path))
        try:
            document = _analyze_imported_document(
                path,
                repo,
                service,
                progress=progress,
                cancel_token=token,
            )
        except AuditCancelled:
            break
        except (ReportImportError, OSError, ValueError) as exc:
            failures.append(BatchDocumentFailure(path, str(exc)))
            if progress:
                progress(BatchProgress(index, len(paths), "failed", path))
            continue
        completed.append(document)
        if progress:
            progress(
                BatchProgress(
                    index,
                    len(paths),
                    "completed",
                    path,
                    document.run.hostname,
                )
            )
    status = (
        "cancelled"
        if token.is_cancelled()
        else "completed_with_errors"
        if failures
        else "completed"
    )
    batch = BatchAssessment.create(
        paths,
        completed,
        failures,
        status,
        started_at=started_at,
    )
    report_output = None
    if completed or failures:
        if report_builder is None:
            from .batch_report import BatchHtmlReportBuilder

            report_builder = BatchHtmlReportBuilder()
        report_output = report_builder.build(output, batch)
        for document in completed:
            repo.save_report(
                ReportRecord(document.run.id, report_output, "batch-html")
            )
    if open_report and report_output:
        webbrowser.open(Path(report_output).resolve().as_uri())
    _cleanup_audit_database(_temp_db)
    return {
        "status": batch.status,
        "db_path": db_label,
        "report_path": report_output,
        "selected_count": batch.selected_count,
        "processed_count": batch.processed_count,
        "failed_count": batch.failed_count,
        "hostnames": [item.run.hostname for item in batch.completed],
        "inventory_count": sum(len(item.inventory) for item in batch.completed),
        "risk_count": batch.coverage.risk,
        "coverage_percent": batch.coverage.document_percent,
        "batch": batch,
    }


def ensure_src_path() -> None:
    src = str(Path(__file__).resolve().parents[1])
    if src not in os.sys.path:
        os.sys.path.insert(0, src)
