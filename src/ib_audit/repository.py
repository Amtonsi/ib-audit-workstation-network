from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from .models import (
    AuditRun,
    CollectorDiagnostic,
    CoverageSummary,
    InventoryObject,
    ObjectAssessment,
    ReportRecord,
    RuleResult,
    SourceDocument,
    SourceSnapshot,
    VulnerabilityCoverage,
    VulnerabilityMatch,
)


class SQLiteRepository:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit_runs (
                    id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    status TEXT NOT NULL,
                    is_admin INTEGER NOT NULL,
                    summary_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS inventory_objects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    category_id TEXT NOT NULL,
                    category_name TEXT NOT NULL,
                    object_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    fields_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    collected_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS collector_diagnostics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    module TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    source TEXT NOT NULL,
                    collected_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS vulnerability_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    cve TEXT NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cvss REAL,
                    kev INTEGER NOT NULL,
                    affected_title TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    references_json TEXT NOT NULL,
                    matched_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS vulnerability_coverage(
                    run_id TEXT NOT NULL,
                    object_uid TEXT NOT NULL,
                    state TEXT NOT NULL,
                    cpe_status TEXT NOT NULL,
                    sources_checked_json TEXT NOT NULL,
                    candidate_count INTEGER NOT NULL,
                    evaluated_count INTEGER NOT NULL,
                    truncated INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    trace_json TEXT NOT NULL,
                    PRIMARY KEY(run_id, object_uid)
                );
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    path TEXT NOT NULL,
                    report_type TEXT NOT NULL,
                    generated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS source_documents (
                    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, report_format TEXT NOT NULL,
                    title TEXT NOT NULL, path TEXT NOT NULL, size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL, imported_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS source_snapshots (
                    id TEXT PRIMARY KEY, source TEXT NOT NULL, cache_key TEXT NOT NULL,
                    path TEXT NOT NULL, sha256 TEXT NOT NULL, fetched_at TEXT NOT NULL,
                    status TEXT NOT NULL, metadata_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_source_snapshots (
                    run_id TEXT NOT NULL, snapshot_id TEXT NOT NULL,
                    PRIMARY KEY (run_id, snapshot_id)
                );
                CREATE TABLE IF NOT EXISTS rule_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL,
                    object_uid TEXT NOT NULL, rule_id TEXT NOT NULL, rule_version TEXT NOT NULL,
                    kind TEXT NOT NULL, status TEXT NOT NULL, severity TEXT NOT NULL,
                    title TEXT NOT NULL, actual TEXT NOT NULL, expected TEXT NOT NULL,
                    evidence TEXT NOT NULL, confidence TEXT NOT NULL, remediation TEXT NOT NULL,
                    references_json TEXT NOT NULL, evaluated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS object_assessments (
                    run_id TEXT NOT NULL, object_uid TEXT NOT NULL, status TEXT NOT NULL,
                    applied_rules INTEGER NOT NULL, passed_rules INTEGER NOT NULL,
                    failed_rules INTEGER NOT NULL, insufficient_rules INTEGER NOT NULL,
                    PRIMARY KEY (run_id, object_uid)
                );
                CREATE TABLE IF NOT EXISTS coverage_summaries (
                    run_id TEXT PRIMARY KEY, total_objects INTEGER NOT NULL,
                    risk INTEGER NOT NULL, passed INTEGER NOT NULL,
                    insufficient_data INTEGER NOT NULL, not_applicable INTEGER NOT NULL
                );
                """
            )
            self._ensure_column(conn, "inventory_objects", "object_uid", "TEXT")
            self._ensure_column(conn, "inventory_objects", "source_section", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "inventory_objects", "source_position", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "inventory_objects", "source_document_id", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "vulnerability_matches", "object_uid", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "vulnerability_matches", "applicability", "TEXT NOT NULL DEFAULT 'confirmed'")
            self._ensure_column(conn, "vulnerability_matches", "cpe", "TEXT NOT NULL DEFAULT ''")
            rows = conn.execute(
                "SELECT id FROM inventory_objects WHERE object_uid IS NULL OR object_uid = ''"
            ).fetchall()
            conn.executemany(
                "UPDATE inventory_objects SET object_uid = ? WHERE id = ?",
                [(str(uuid4()), row["id"]) for row in rows],
            )

    @staticmethod
    def _ensure_column(conn: sqlite3.Connection, table: str, name: str, definition: str) -> None:
        columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if name not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")

    def save_run(self, run: AuditRun) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO audit_runs
                (id, hostname, started_at, finished_at, status, is_admin, summary_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.id,
                    run.hostname,
                    run.started_at,
                    run.finished_at,
                    run.status,
                    int(run.is_admin),
                    json.dumps(run.summary, ensure_ascii=False),
                ),
            )

    def save_inventory_objects(self, run_id: str, objects: list[InventoryObject]) -> None:
        with self._connection() as conn:
            conn.executemany(
                """
                INSERT INTO inventory_objects
                (run_id, category_id, category_name, object_type, title, fields_json, source,
                 confidence, raw_json, collected_at, object_uid, source_section,
                 source_position, source_document_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        obj.category_id,
                        obj.category_name,
                        obj.object_type,
                        obj.title,
                        json.dumps(obj.fields, ensure_ascii=False),
                        obj.source,
                        obj.confidence,
                        json.dumps(obj.raw, ensure_ascii=False),
                        obj.collected_at,
                        obj.uid,
                        obj.source_section,
                        obj.source_position,
                        obj.source_document_id,
                    )
                    for obj in objects
                ],
            )

    def save_diagnostics(self, run_id: str, diagnostics: list[CollectorDiagnostic]) -> None:
        with self._connection() as conn:
            conn.executemany(
                """
                INSERT INTO collector_diagnostics
                (run_id, module, severity, message, source, collected_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [(run_id, d.module, d.severity, d.message, d.source, d.collected_at) for d in diagnostics],
            )

    def save_vulnerability_matches(self, run_id: str, matches: list[VulnerabilityMatch]) -> None:
        with self._connection() as conn:
            conn.execute("DELETE FROM vulnerability_matches WHERE run_id = ?", (run_id,))
            conn.executemany(
                """
                INSERT INTO vulnerability_matches
                (run_id, cve, source, severity, cvss, kev, affected_title, evidence,
                 confidence, remediation, references_json, matched_at, object_uid, applicability, cpe)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        m.cve,
                        m.source,
                        m.severity,
                        m.cvss,
                        int(m.kev),
                        m.affected_title,
                        m.evidence,
                        m.confidence,
                        m.remediation,
                        json.dumps(m.references, ensure_ascii=False),
                        m.matched_at,
                        m.object_uid,
                        m.applicability,
                        m.cpe,
                    )
                    for m in matches
            ],
        )

    def save_vulnerability_coverage(
        self,
        run_id: str,
        coverage: dict[str, VulnerabilityCoverage],
    ) -> None:
        with self._connection() as conn:
            conn.execute("DELETE FROM vulnerability_coverage WHERE run_id = ?", (run_id,))
            conn.executemany(
                """
                INSERT INTO vulnerability_coverage(
                    run_id, object_uid, state, cpe_status, sources_checked_json,
                    candidate_count, evaluated_count, truncated, reason, trace_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        item.object_uid,
                        item.state,
                        item.cpe_status,
                        json.dumps(list(item.sources_checked), ensure_ascii=False),
                        item.candidate_count,
                        item.evaluated_count,
                        int(item.truncated),
                        item.reason,
                        json.dumps(item.trace, ensure_ascii=False, sort_keys=True),
                    )
                    for item in coverage.values()
                ],
            )

    def save_source_document(self, run_id: str, document: SourceDocument) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO source_documents
                (id, run_id, report_format, title, path, size_bytes, sha256, imported_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    document.id, run_id, document.report_format, document.title,
                    document.path, document.size_bytes, document.sha256, document.imported_at,
                ),
            )

    def save_source_snapshot(self, run_id: str, snapshot: SourceSnapshot) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO source_snapshots
                (id, source, cache_key, path, sha256, fetched_at, status, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot.id, snapshot.source, snapshot.cache_key, snapshot.path,
                    snapshot.sha256, snapshot.fetched_at, snapshot.status,
                    json.dumps(snapshot.metadata, ensure_ascii=False),
                ),
            )
            conn.execute(
                "INSERT OR IGNORE INTO audit_source_snapshots (run_id, snapshot_id) VALUES (?, ?)",
                (run_id, snapshot.id),
            )

    def save_assessment_bundle(
        self,
        run_id: str,
        results: list[RuleResult],
        assessments: list[ObjectAssessment],
        coverage: CoverageSummary,
    ) -> None:
        with self._connection() as conn:
            conn.execute("DELETE FROM rule_results WHERE run_id = ?", (run_id,))
            conn.execute("DELETE FROM object_assessments WHERE run_id = ?", (run_id,))
            conn.execute("DELETE FROM coverage_summaries WHERE run_id = ?", (run_id,))
            conn.executemany(
                """
                INSERT INTO rule_results
                (run_id, object_uid, rule_id, rule_version, kind, status, severity, title,
                 actual, expected, evidence, confidence, remediation, references_json, evaluated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id, item.object_uid, item.rule_id, item.rule_version, item.kind,
                        item.status, item.severity, item.title, item.actual, item.expected,
                        item.evidence, item.confidence, item.remediation,
                        json.dumps(item.references, ensure_ascii=False), item.evaluated_at,
                    )
                    for item in results
                ],
            )
            conn.executemany(
                """
                INSERT INTO object_assessments
                (run_id, object_uid, status, applied_rules, passed_rules, failed_rules, insufficient_rules)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id, item.object_uid, item.status, item.applied_rules,
                        item.passed_rules, item.failed_rules, item.insufficient_rules,
                    )
                    for item in assessments
                ],
            )
            conn.execute(
                """
                INSERT INTO coverage_summaries
                (run_id, total_objects, risk, passed, insufficient_data, not_applicable)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id, coverage.total_objects, coverage.risk, coverage.passed,
                    coverage.insufficient_data, coverage.not_applicable,
                ),
            )

    def save_report(self, report: ReportRecord) -> None:
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO reports (run_id, path, report_type, generated_at) VALUES (?, ?, ?, ?)",
                (report.run_id, report.path, report.report_type, report.generated_at),
            )

    def list_runs(self) -> list[AuditRun]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM audit_runs ORDER BY started_at DESC").fetchall()
        return [self._row_to_run(row) for row in rows]

    def latest_run(self) -> AuditRun | None:
        runs = self.list_runs()
        return runs[0] if runs else None

    def load_run_bundle(self, run_id: str) -> dict[str, Any]:
        with self._connection() as conn:
            run_row = conn.execute("SELECT * FROM audit_runs WHERE id = ?", (run_id,)).fetchone()
            if run_row is None:
                raise KeyError(f"Audit run not found: {run_id}")
            inventory_rows = conn.execute("SELECT * FROM inventory_objects WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()
            diagnostic_rows = conn.execute(
                "SELECT * FROM collector_diagnostics WHERE run_id = ? ORDER BY id", (run_id,)
            ).fetchall()
            vuln_rows = conn.execute("SELECT * FROM vulnerability_matches WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()
            vulnerability_coverage_rows = conn.execute(
                "SELECT * FROM vulnerability_coverage WHERE run_id = ? ORDER BY object_uid",
                (run_id,),
            ).fetchall()
            report_rows = conn.execute("SELECT * FROM reports WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()
            document_rows = conn.execute(
                "SELECT * FROM source_documents WHERE run_id = ? ORDER BY imported_at", (run_id,)
            ).fetchall()
            snapshot_rows = conn.execute(
                """SELECT s.* FROM source_snapshots s
                   JOIN audit_source_snapshots a ON a.snapshot_id = s.id
                   WHERE a.run_id = ? ORDER BY s.fetched_at""",
                (run_id,),
            ).fetchall()
            rule_rows = conn.execute("SELECT * FROM rule_results WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()
            assessment_rows = conn.execute(
                "SELECT * FROM object_assessments WHERE run_id = ? ORDER BY object_uid", (run_id,)
            ).fetchall()
            coverage_row = conn.execute("SELECT * FROM coverage_summaries WHERE run_id = ?", (run_id,)).fetchone()

        return {
            "run": self._row_to_run(run_row),
            "inventory": [self._row_to_inventory(row) for row in inventory_rows],
            "diagnostics": [self._row_to_diagnostic(row) for row in diagnostic_rows],
            "vulnerabilities": [self._row_to_vulnerability(row) for row in vuln_rows],
            "vulnerability_coverage": {
                item.object_uid: item
                for item in (self._row_to_vulnerability_coverage(row) for row in vulnerability_coverage_rows)
            },
            "reports": [self._row_to_report(row) for row in report_rows],
            "source_documents": [self._row_to_source_document(row) for row in document_rows],
            "source_snapshots": [self._row_to_source_snapshot(row) for row in snapshot_rows],
            "rule_results": [self._row_to_rule_result(row) for row in rule_rows],
            "assessments": [self._row_to_assessment(row) for row in assessment_rows],
            "coverage": self._row_to_coverage(coverage_row) if coverage_row else None,
        }

    @staticmethod
    def _loads(text: str) -> Any:
        return json.loads(text) if text else {}

    def _row_to_run(self, row: sqlite3.Row) -> AuditRun:
        return AuditRun(
            id=row["id"],
            hostname=row["hostname"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            status=row["status"],
            is_admin=bool(row["is_admin"]),
            summary=self._loads(row["summary_json"]),
        )

    def _row_to_inventory(self, row: sqlite3.Row) -> InventoryObject:
        return InventoryObject(
            category_id=row["category_id"],
            category_name=row["category_name"],
            object_type=row["object_type"],
            title=row["title"],
            fields=self._loads(row["fields_json"]),
            source=row["source"],
            confidence=row["confidence"],
            raw=self._loads(row["raw_json"]),
            collected_at=row["collected_at"],
            uid=row["object_uid"],
            source_section=row["source_section"],
            source_position=row["source_position"],
            source_document_id=row["source_document_id"],
        )

    def _row_to_diagnostic(self, row: sqlite3.Row) -> CollectorDiagnostic:
        return CollectorDiagnostic(
            module=row["module"],
            severity=row["severity"],
            message=row["message"],
            source=row["source"],
            collected_at=row["collected_at"],
        )

    def _row_to_vulnerability(self, row: sqlite3.Row) -> VulnerabilityMatch:
        return VulnerabilityMatch(
            cve=row["cve"],
            source=row["source"],
            severity=row["severity"],
            cvss=row["cvss"],
            kev=bool(row["kev"]),
            affected_title=row["affected_title"],
            evidence=row["evidence"],
            confidence=row["confidence"],
            remediation=row["remediation"],
            references=self._loads(row["references_json"]),
            matched_at=row["matched_at"],
            object_uid=row["object_uid"],
            applicability=row["applicability"],
            cpe=row["cpe"],
        )

    def _row_to_vulnerability_coverage(self, row: sqlite3.Row) -> VulnerabilityCoverage:
        return VulnerabilityCoverage(
            object_uid=row["object_uid"],
            state=row["state"],
            cpe_status=row["cpe_status"],
            sources_checked=tuple(self._loads(row["sources_checked_json"])),
            candidate_count=row["candidate_count"],
            evaluated_count=row["evaluated_count"],
            truncated=bool(row["truncated"]),
            reason=row["reason"],
            trace=self._loads(row["trace_json"]),
        )

    def _row_to_report(self, row: sqlite3.Row) -> ReportRecord:
        return ReportRecord(
            run_id=row["run_id"],
            path=row["path"],
            report_type=row["report_type"],
            generated_at=row["generated_at"],
        )

    def _row_to_source_document(self, row: sqlite3.Row) -> SourceDocument:
        return SourceDocument(
            row["id"], row["report_format"], row["title"], row["path"],
            row["size_bytes"], row["sha256"], row["imported_at"],
        )

    def _row_to_source_snapshot(self, row: sqlite3.Row) -> SourceSnapshot:
        return SourceSnapshot(
            row["id"], row["source"], row["cache_key"], row["path"], row["sha256"],
            row["fetched_at"], row["status"], self._loads(row["metadata_json"]),
        )

    def _row_to_rule_result(self, row: sqlite3.Row) -> RuleResult:
        return RuleResult(
            row["object_uid"], row["rule_id"], row["rule_version"], row["kind"],
            row["status"], row["severity"], row["title"], row["actual"], row["expected"],
            row["evidence"], row["confidence"], row["remediation"],
            self._loads(row["references_json"]), row["evaluated_at"],
        )

    @staticmethod
    def _row_to_assessment(row: sqlite3.Row) -> ObjectAssessment:
        return ObjectAssessment(
            row["object_uid"], row["status"], row["applied_rules"],
            row["passed_rules"], row["failed_rules"], row["insufficient_rules"],
        )

    @staticmethod
    def _row_to_coverage(row: sqlite3.Row) -> CoverageSummary:
        return CoverageSummary(
            row["total_objects"], row["risk"], row["passed"],
            row["insufficient_data"], row["not_applicable"],
        )
