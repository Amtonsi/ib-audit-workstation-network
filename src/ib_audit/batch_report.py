from __future__ import annotations

import html
import urllib.parse
from collections import defaultdict
from pathlib import Path

from .batch import BatchAssessment, BatchDocumentResult, SEVERITY_ORDER
from .category_catalog import WINAUDIT_CATEGORY_ORDER
from .report import FIELD_LABELS


STATUS_LABELS = {
    "completed": "Проверка завершена",
    "completed_with_errors": "Завершено с ошибками файлов",
    "cancelled": "Проверка отменена",
}


class BatchHtmlReportBuilder:
    def build(self, output_dir: str | Path, batch: BatchAssessment) -> str:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        stamp = batch.started_at.replace(":", "-").replace("+", "Z")
        path = output / f"{stamp}-batch-ib-audit-report.html"
        path.write_text(self.render(batch), encoding="utf-8")
        return str(path)

    def render(self, batch: BatchAssessment) -> str:
        return "\n".join(
            [
                "<!doctype html><html lang='ru'><head><meta charset='utf-8'>",
                "<meta name='viewport' content='width=device-width,initial-scale=1'>",
                "<title>Сводный отчёт IB Audit</title>",
                self._styles(),
                "</head><body>",
                self._navigation(batch),
                "<main>",
                self._summary(batch),
                self._computer_comparison(batch),
                self._common_findings(batch),
                self._coverage(batch),
                self._failures(batch),
                self._document_details(batch),
                f"<footer>Сформировано: {html.escape(batch.finished_at)}. "
                "Исходные документы не изменялись.</footer>",
                self._script(),
                "</main></body></html>",
            ]
        )

    def _navigation(self, batch: BatchAssessment) -> str:
        links = [
            ("summary", "Сводка"),
            ("computers", "Компьютеры"),
            ("common-findings", "Общие риски"),
            ("coverage", "Покрытие"),
        ]
        if batch.failures:
            links.append(("import-errors", "Ошибки импорта"))
        overview = "".join(
            f"<a href='#{anchor}'>{html.escape(label)}</a>"
            for anchor, label in links
        )
        hosts = "".join(
            f"{self._computer_link(item, html.escape(item.run.hostname), 'nav-host')}"
            for item in self._ranked_documents(batch)
        )
        return (
            "<aside><div class='brand'>IB Audit</div>"
            "<div class='brand-subtitle'>Сводный отчёт</div>"
            "<div class='nav-title'>ОБЗОР</div>"
            f"{overview}"
            "<div class='nav-title'>КОМПЬЮТЕРЫ</div>"
            f"{hosts or '<span class=\"nav-empty\">Нет завершённых документов</span>'}"
            "</aside>"
        )

    def _summary(self, batch: BatchAssessment) -> str:
        status_label = STATUS_LABELS.get(batch.status, batch.status)
        banner = ""
        if batch.status == "cancelled":
            banner = (
                "<div class='banner cancelled'><strong>Проверка отменена.</strong> "
                f"Полностью обработано {batch.processed_count} из {batch.selected_count} документов. "
                "Незавершённые и не запущенные документы не включены в показатели.</div>"
            )
        elif batch.failures:
            banner = (
                "<div class='banner warning'><strong>Есть ошибки входных файлов.</strong> "
                "Они перечислены отдельно и не уменьшают показатели обработанных документов.</div>"
            )
        snapshot_pills = self._snapshot_pills(batch)
        return (
            "<section id='summary' class='hero'>"
            "<div class='hero-head'><div><p class='eyebrow'>ПАКЕТНАЯ ПРОВЕРКА WINAUDIT</p>"
            "<h1>Сводный отчёт</h1>"
            f"<p class='meta'>Начало: {html.escape(batch.started_at)} · "
            f"Окончание: {html.escape(batch.finished_at)}</p></div>"
            f"<span class='batch-status {html.escape(batch.status)}'>{html.escape(status_label)}</span>"
            "</div>"
            f"{banner}"
            "<div class='kpis'>"
            f"{self._kpi(f'{batch.processed_count} из {batch.selected_count}', 'документов обработано')}"
            f"{self._kpi(str(batch.severity_counts.get('critical', 0)), 'критических рисков', 'critical')}"
            f"{self._kpi(str(batch.severity_counts.get('high', 0)), 'высоких рисков', 'high')}"
            f"{self._kpi(str(batch.coverage.document_percent) + '%', 'взвешенное покрытие')}"
            f"{self._kpi(str(batch.failed_count), 'ошибок файлов', 'warning')}"
            "</div>"
            "<h2 class='subheading'>Источники уязвимостей</h2>"
            f"<div class='pills'>{snapshot_pills}</div>"
            "</section>"
        )

    def _computer_comparison(self, batch: BatchAssessment) -> str:
        rows = []
        for item in self._ranked_documents(batch):
            counts = self._document_severity_counts(item)
            coverage = item.assessment.coverage
            tone = (
                "critical"
                if counts["critical"]
                else "high"
                if counts["high"]
                else "warning"
                if coverage.risk
                else "ok"
            )
            status = "Риск" if coverage.risk else "Проверен"
            anchor = self._document_anchor(item)
            rows.append(
                "<tr>"
                f"<td><a class='host-link' href='#{anchor}-risks' "
                f"onclick=\"return openComputerSection('{anchor}','risks')\">"
                f"{html.escape(item.run.hostname)}</a>"
                f"<div class='cell-meta'>{html.escape(item.source_path.name)}</div></td>"
                f"<td><span class='count critical'>{counts['critical']}</span></td>"
                f"<td><span class='count high'>{counts['high']}</span></td>"
                f"<td>{coverage.risk}</td>"
                f"<td>{len(item.inventory)}</td>"
                f"<td>{coverage.document_percent}%</td>"
                f"<td><span class='status-dot {tone}'>{status}</span></td>"
                "</tr>"
            )
        table = (
            "<table class='comparison'><thead><tr>"
            "<th>Компьютер</th><th>Крит.</th><th>Выс.</th><th>Риски</th>"
            "<th>Объекты</th><th>Покрытие</th><th>Статус</th>"
            "</tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
            if rows
            else "<p class='empty'>Нет полностью обработанных документов.</p>"
        )
        return (
            "<section id='computers'><div class='section-head'>"
            "<div><p class='eyebrow'>ПРИОРИТЕТЫ</p><h2>Компьютеры по приоритету</h2></div>"
            "<input id='hostSearch' class='search' type='search' "
            "placeholder='Найти компьютер' oninput='filterHosts()'></div>"
            f"{table}</section>"
        )

    def _common_findings(self, batch: BatchAssessment) -> str:
        cards = []
        anchors_by_host = {
            item.run.hostname: self._document_anchor(item)
            for item in batch.completed
        }
        for finding in batch.common_findings:
            hosts = "".join(
                self._host_pill(host, anchors_by_host.get(host))
                for host in finding.hostnames
            )
            cards.append(
                f"<article class='finding-card {html.escape(finding.severity)}' "
                f"data-severity='{html.escape(finding.severity)}'>"
                "<div class='finding-head'>"
                f"<span class='severity {html.escape(finding.severity)}'>"
                f"{html.escape(self._severity_label(finding.severity))}</span>"
                f"<strong>{html.escape(finding.key)}</strong>"
                f"<span class='affected'>{len(finding.hostnames)} комп.</span></div>"
                f"<h3>{html.escape(finding.title)}</h3>"
                f"<p>{html.escape(finding.evidence)}</p>"
                f"<p><strong>Рекомендация:</strong> {html.escape(finding.remediation)}</p>"
                f"{self._reference_links(finding.references)}"
                f"<div class='host-list'>{hosts}</div></article>"
            )
        content = "".join(cards) or (
            "<p class='empty'>Общие подтверждённые риски не найдены.</p>"
        )
        return (
            "<section id='common-findings'><div class='section-head'>"
            "<div><p class='eyebrow'>МАСШТАБ ПРОБЛЕМ</p><h2>Общие проблемы</h2></div>"
            "<div class='filter-row'>"
            "<button type='button' onclick=\"filterCommon('all')\">Все</button>"
            "<button type='button' onclick=\"filterCommon('critical')\">Критические</button>"
            "<button type='button' onclick=\"filterCommon('high')\">Высокие</button>"
            "</div></div>"
            f"<div class='finding-grid'>{content}</div></section>"
        )

    def _coverage(self, batch: BatchAssessment) -> str:
        coverage = batch.coverage
        classified = coverage.classified_objects
        return (
            "<section id='coverage'><p class='eyebrow'>КАЧЕСТВО ДАННЫХ</p>"
            "<h2>Покрытие</h2>"
            "<div class='kpis compact'>"
            f"{self._kpi(str(coverage.total_objects), 'всего объектов')}"
            f"{self._kpi(str(coverage.risk), 'с риском', 'critical')}"
            f"{self._kpi(str(coverage.passed), 'проверено', 'ok')}"
            f"{self._kpi(str(coverage.insufficient_data), 'недостаточно данных', 'warning')}"
            f"{self._kpi(str(coverage.not_applicable), 'не применимо')}"
            "</div>"
            "<div class='coverage-bar' role='img' "
            f"aria-label='Классифицировано {classified} из {coverage.total_objects}'>"
            f"<span style='width:{coverage.document_percent}%'></span></div>"
            f"<p class='meta'>Классифицировано {classified} из {coverage.total_objects} "
            "объектов полностью обработанных документов. Проценты не усредняются "
            "по компьютерам, а рассчитываются по суммарному числу объектов.</p>"
            "</section>"
        )

    def _failures(self, batch: BatchAssessment) -> str:
        if not batch.failures:
            return ""
        rows = "".join(
            "<tr>"
            f"<td>{html.escape(item.source_path.name)}</td>"
            f"<td>{html.escape(str(item.source_path))}</td>"
            f"<td>{html.escape(item.stage)}</td>"
            f"<td>{html.escape(item.message)}</td>"
            "</tr>"
            for item in batch.failures
        )
        return (
            "<section id='import-errors'><p class='eyebrow'>ВХОДНЫЕ ФАЙЛЫ</p>"
            "<h2>Ошибки импорта</h2>"
            "<table><thead><tr><th>Файл</th><th>Путь</th><th>Этап</th>"
            f"<th>Причина</th></tr></thead><tbody>{rows}</tbody></table></section>"
        )

    def _document_details(self, batch: BatchAssessment) -> str:
        if not batch.completed:
            return ""
        return "\n".join(
            self._document_section(item) for item in self._ranked_documents(batch)
        )

    def _document_section(self, item: BatchDocumentResult) -> str:
        anchor = self._document_anchor(item)
        coverage = item.assessment.coverage
        findings = [
            result
            for result in item.assessment.rule_results
            if result.status == "risk"
        ]
        finding_entries = [
            (result, self._finding_anchor(anchor, result.rule_id, index))
            for index, result in enumerate(findings, 1)
        ]
        risks_by_object: dict[str, list] = defaultdict(list)
        for result, target_id in finding_entries:
            risks_by_object[result.object_uid].append((result, target_id))
        findings_html = "".join(
            f"<article id='{target_id}' class='host-finding "
            f"{html.escape(result.severity.casefold())}'>"
            f"<span class='severity {html.escape(result.severity.casefold())}'>"
            f"{html.escape(self._severity_label(result.severity))}</span>"
            f"<h4>{html.escape(result.rule_id)} · {html.escape(result.title)}</h4>"
            f"<p>{html.escape(result.evidence)}</p>"
            f"<p><strong>Рекомендация:</strong> {html.escape(result.remediation)}</p>"
            f"{self._reference_links(result.references)}"
            "</article>"
            for result, target_id in finding_entries
        ) or "<p class='empty'>Подтверждённые риски не найдены.</p>"
        categories: dict[str, list] = defaultdict(list)
        for obj in item.inventory:
            categories[obj.category_name].append(obj)
        known = list(WINAUDIT_CATEGORY_ORDER)
        ordered = [
            *[name for name in known if categories.get(name)],
            *sorted(name for name in categories if name not in set(known)),
        ]
        inventory_html = "".join(
            self._inventory_category(item, category, categories[category], risks_by_object)
            for category in ordered
        )
        diagnostics = "".join(
            "<tr>"
            f"<td>{html.escape(diag.module)}</td>"
            f"<td>{html.escape(diag.severity)}</td>"
            f"<td>{html.escape(diag.message)}</td>"
            f"<td>{html.escape(diag.source)}</td>"
            "</tr>"
            for diag in item.diagnostics
        ) or "<tr><td colspan='4'>Диагностических сообщений нет.</td></tr>"
        return (
            f"<section id='{anchor}' class='document-section' "
            f"data-host='{html.escape(item.run.hostname, quote=True)}'>"
            "<details><summary>"
            f"<span><strong>{html.escape(item.run.hostname)}</strong>"
            f"<small>{html.escape(item.source_path.name)} · {len(item.inventory)} объектов</small></span>"
            f"<span class='summary-risk'>{coverage.risk} рисков · {coverage.document_percent}%</span>"
            "</summary><div class='document-body'>"
            f"<p class='meta'>Формат: {html.escape(item.source_format)} · "
            f"Исходный файл: {html.escape(str(item.source_path.resolve(strict=False)))}</p>"
            "<nav class='document-tools'>"
            f"<a href='#{anchor}-risks' onclick=\"return openComputerSection('{anchor}','risks')\">К рискам</a>"
            f"<a href='#{anchor}-inventory' onclick=\"return openComputerSection('{anchor}','inventory')\">К полному инвентарю</a>"
            "<a href='#common-findings'>Вернуться к общим рискам</a>"
            "</nav>"
            "<div class='kpis compact'>"
            f"{self._kpi(str(coverage.risk), 'риски', 'critical')}"
            f"{self._kpi(str(coverage.passed), 'проверено', 'ok')}"
            f"{self._kpi(str(coverage.insufficient_data), 'недостаточно данных', 'warning')}"
            f"{self._kpi(str(coverage.document_percent) + '%', 'покрытие')}"
            "</div>"
            f"<h3 id='{anchor}-risks'>Риски и рекомендации</h3>"
            f"<div class='host-findings'>{findings_html}</div>"
            f"<h3 id='{anchor}-inventory'>Полный инвентарь</h3>"
            f"{inventory_html or '<p class=\"empty\">Инвентарь отсутствует.</p>'}"
            f"<h3 id='{anchor}-diagnostics'>Диагностика</h3>"
            "<table><thead><tr><th>Модуль</th><th>Уровень</th>"
            f"<th>Сообщение</th><th>Источник</th></tr></thead><tbody>{diagnostics}</tbody></table>"
            "</div></details></section>"
        )

    def _inventory_category(
        self,
        document: BatchDocumentResult,
        category: str,
        objects: list,
        risks_by_object: dict[str, list],
    ) -> str:
        assessments = {
            item.object_uid: item.status for item in document.assessment.assessments
        }
        cards = []
        for obj in objects:
            rows = "".join(
                f"<tr><td>{html.escape(FIELD_LABELS.get(str(key), str(key)))}</td>"
                f"<td>{html.escape(self._short(value))}</td></tr>"
                for key, value in obj.fields.items()
            )
            status = assessments.get(obj.uid, "not_applicable")
            risk_links = self._object_risk_links(
                self._document_anchor(document),
                risks_by_object.get(obj.uid, []),
            )
            cards.append(
                f"<article class='object-card' data-status='{html.escape(status)}'>"
                f"<div class='object-head'><h4>{html.escape(obj.title)}</h4>"
                f"<span class='object-status {html.escape(status)}'>"
                f"{html.escape(self._object_status_label(status))}</span></div>"
                f"<p class='cell-meta'>Источник: {html.escape(obj.source)} · "
                f"Уверенность: {html.escape(obj.confidence)}</p>"
                "<table class='item-value'><thead><tr><th>Параметр</th>"
                f"<th>Значение</th></tr></thead><tbody>{rows}</tbody></table>"
                f"{risk_links}</article>"
            )
        return (
            f"<details class='category'><summary>{html.escape(category)}"
            f"<span>{len(objects)}</span></summary>{''.join(cards)}</details>"
        )

    def _ranked_documents(
        self, batch: BatchAssessment
    ) -> list[BatchDocumentResult]:
        return sorted(
            batch.completed,
            key=lambda item: (
                -self._document_severity_counts(item)["critical"],
                -self._document_severity_counts(item)["high"],
                -item.assessment.coverage.risk,
                item.run.hostname.casefold(),
            ),
        )

    @staticmethod
    def _document_severity_counts(
        item: BatchDocumentResult,
    ) -> dict[str, int]:
        counts = {name: 0 for name in SEVERITY_ORDER}
        for result in item.assessment.rule_results:
            if result.status != "risk":
                continue
            severity = result.severity.casefold()
            counts[severity if severity in counts else "info"] += 1
        return counts

    @staticmethod
    def _document_anchor(item: BatchDocumentResult) -> str:
        return "computer-" + "".join(
            char if char.isalnum() else "-" for char in item.run.id.casefold()
        )

    @staticmethod
    def _finding_anchor(document_anchor: str, rule_id: str, index: int) -> str:
        slug = "".join(
            char if char.isalnum() else "-"
            for char in str(rule_id).casefold()
        ).strip("-")
        return f"{document_anchor}-finding-{slug or 'risk'}-{index}"

    @classmethod
    def _computer_link(cls, item: BatchDocumentResult, label_html: str, class_name: str = "") -> str:
        anchor = cls._document_anchor(item)
        class_attr = f" class='{html.escape(class_name)}'" if class_name else ""
        return (
            f"<a{class_attr} href='#{anchor}-risks' "
            f"onclick=\"return openComputerSection('{anchor}','risks')\">{label_html}</a>"
        )

    @staticmethod
    def _host_pill(hostname: str, anchor: str | None) -> str:
        label = html.escape(hostname)
        if not anchor:
            return f"<span class='host-pill'>{label}</span>"
        return (
            f"<a class='host-pill' href='#{anchor}-risks' "
            f"onclick=\"return openComputerSection('{anchor}','risks')\">{label}</a>"
        )

    def _object_risk_links(self, document_anchor: str, results: list) -> str:
        if not results:
            return ""
        links = []
        for result, target_id in sorted(
            results,
            key=lambda item: (
                SEVERITY_ORDER.get(
                    str(item[0].severity).casefold(),
                    SEVERITY_ORDER["info"],
                ),
                str(item[0].rule_id).casefold(),
                item[1],
            ),
        ):
            severity = str(result.severity).casefold()
            links.append(
                f"<a class='object-risk-link {html.escape(severity)}' "
                f"href='#{html.escape(target_id, quote=True)}' "
                f"onclick=\"return openComputerFinding('{document_anchor}',"
                f"'{target_id}')\">{html.escape(result.rule_id)}</a>"
            )
        return (
            "<div class='object-risk-links'><strong>Риски:</strong>"
            + "".join(links)
            + "</div>"
        )

    @staticmethod
    def _snapshot_pills(batch: BatchAssessment) -> str:
        unique = {}
        for document in batch.completed:
            for snapshot in document.assessment.snapshots:
                unique[(snapshot.source, snapshot.sha256)] = snapshot
        if not unique:
            return (
                "<span class='pill warning'>Базы не использованы, недоступны "
                "или проверка выполнена из локального кэша без метаданных</span>"
            )
        return "".join(
            f"<span class='pill'>{html.escape(snapshot.source)} · "
            f"{html.escape(snapshot.fetched_at[:10])} · "
            f"{html.escape(snapshot.sha256[:12])}</span>"
            for snapshot in unique.values()
        )

    @staticmethod
    def _severity_label(severity: str) -> str:
        return {
            "critical": "Критический",
            "high": "Высокий",
            "medium": "Средний",
            "low": "Низкий",
            "info": "Информация",
        }.get(severity.casefold(), severity)

    @staticmethod
    def _object_status_label(status: str) -> str:
        return {
            "risk": "Риск",
            "passed": "Проверено",
            "insufficient_data": "Недостаточно данных",
            "not_applicable": "Не применимо",
        }.get(status, status)

    @staticmethod
    def _kpi(value: str, label: str, tone: str = "") -> str:
        tone_class = f" {html.escape(tone)}" if tone else ""
        return (
            f"<div class='kpi{tone_class}'><strong>{html.escape(value)}</strong>"
            f"<span>{html.escape(label)}</span></div>"
        )

    @staticmethod
    def _short(value: object) -> str:
        text = str(value)
        return text if len(text) <= 4000 else text[:4000] + "…"

    @staticmethod
    def _reference_links(references: list[str]) -> str:
        links = []
        for ref in references:
            parsed = urllib.parse.urlparse(ref)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                safe = html.escape(ref, quote=True)
                label = "Эксплойт" if BatchHtmlReportBuilder._is_exploit_reference(ref) else "Источник"
                links.append(
                    f"<a class='reference-link' href='{safe}' rel='noreferrer'>"
                    f"<span>{html.escape(label)}</span> {safe}</a>"
                )
        return "<div class='reference-list'>" + "".join(links) + "</div>" if links else ""

    @staticmethod
    def _is_exploit_reference(ref: str) -> bool:
        lowered = ref.casefold()
        return any(
            marker in lowered
            for marker in ("exploit", "exploit-db", "metasploit", "packetstormsecurity", "0day.today")
        ) or "packetstormsecurity.com" in lowered or "securityfocus.com/bid" in lowered

    @staticmethod
    def _styles() -> str:
        return """<style>
:root{--ink:#172126;--muted:#62727a;--canvas:#f3f6f8;--panel:#fff;--line:#dce3e7;--teal:#0f766e;--red:#b91c1c;--amber:#b45309;--green:#15803d;--blue:#2563eb}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--canvas);color:var(--ink);font-family:Segoe UI,Arial,sans-serif;line-height:1.45}
aside{position:fixed;inset:0 auto 0 0;width:250px;background:#172126;color:#d7e0e3;padding:24px 18px;overflow:auto;z-index:2}
.brand{font-size:24px;font-weight:800;color:#fff}.brand-subtitle{color:#9fb0b6;margin-bottom:28px}.nav-title{font-size:11px;font-weight:700;letter-spacing:.12em;color:#83969d;margin:20px 9px 7px}
aside a{display:block;color:#d7e0e3;text-decoration:none;padding:8px 10px;border-radius:7px;font-size:13px}aside a:hover{background:#24353c;color:#fff}.nav-empty{display:block;color:#83969d;padding:8px 10px;font-size:12px}
main{margin-left:250px;padding:24px;max-width:1500px}section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 5px 18px rgba(23,33,38,.035)}
h1{font-size:30px;margin:2px 0 4px}h2{margin:2px 0 15px}h3{margin:20px 0 10px}h4{margin:0}.eyebrow{font-size:11px;font-weight:800;letter-spacing:.12em;color:var(--teal);margin:0}.meta,.cell-meta{color:var(--muted);font-size:13px}.cell-meta{margin-top:3px}.subheading{font-size:15px;margin-top:18px}
.hero-head,.section-head,.finding-head,.object-head{display:flex;justify-content:space-between;gap:15px;align-items:flex-start}.batch-status,.status-dot,.severity,.object-status{display:inline-block;border-radius:999px;padding:5px 9px;font-size:12px;font-weight:700;white-space:nowrap}
.batch-status.completed,.status-dot.ok,.object-status.passed{background:#dcfce7;color:#166534}.batch-status.completed_with_errors,.status-dot.warning,.object-status.insufficient_data{background:#ffedd5;color:#9a3412}.batch-status.cancelled{background:#fff1e7;color:#9a3412}.status-dot.critical,.object-status.risk{background:#fee2e2;color:#991b1b}.status-dot.high{background:#ffedd5;color:#9a3412}.object-status.not_applicable{background:#e2e8f0;color:#475569}
.banner{padding:12px 14px;border-radius:9px;margin:14px 0}.banner.cancelled{background:#fff7ed;border:1px solid #fdba74;color:#9a3412}.banner.warning{background:#fffbeb;border:1px solid #fcd34d;color:#92400e}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:9px}.kpis.compact{grid-template-columns:repeat(auto-fit,minmax(125px,1fr))}
.kpi{background:#f8fafb;border:1px solid #e4e9ec;border-radius:9px;padding:13px}.kpi strong{display:block;font-size:25px}.kpi span{color:var(--muted);font-size:12px}.kpi.critical strong{color:var(--red)}.kpi.high strong,.kpi.warning strong{color:var(--amber)}.kpi.ok strong{color:var(--green)}
.pills{display:flex;flex-wrap:wrap;gap:6px}.pill,.host-pill{display:inline-block;background:#eef2ff;color:#3730a3;border-radius:999px;padding:4px 8px;font-size:12px;text-decoration:none}.pill.warning{background:#fff7ed;color:#9a3412}
table{border-collapse:collapse;width:100%;table-layout:fixed}th,td{padding:9px;border-bottom:1px solid #e5eaed;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{color:#53636b;font-size:12px;background:#f8fafb}.comparison th:first-child,.comparison td:first-child{width:31%}
.host-link{color:var(--teal);font-weight:700;text-decoration:none}.count{font-weight:800}.count.critical{color:var(--red)}.count.high{color:var(--amber)}.search{border:1px solid var(--line);border-radius:8px;padding:9px 11px;min-width:220px}
.filter-row{display:flex;gap:6px;flex-wrap:wrap}.filter-row button{border:1px solid var(--line);background:#fff;padding:7px 10px;border-radius:7px;cursor:pointer}.filter-row button:hover{border-color:var(--teal);color:var(--teal)}
.finding-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:10px}.finding-card{border:1px solid var(--line);border-left:5px solid #64748b;border-radius:9px;padding:14px;min-width:0;overflow:hidden}.finding-card.critical,.host-finding.critical{border-left-color:var(--red)}.finding-card.high,.host-finding.high{border-left-color:var(--amber)}
.finding-head{align-items:center;justify-content:flex-start}.affected{margin-left:auto;color:var(--muted);font-size:12px}.severity{background:#e2e8f0;color:#475569}.severity.critical{background:#fee2e2;color:#991b1b}.severity.high{background:#ffedd5;color:#9a3412}.severity.medium{background:#dbeafe;color:#1d4ed8}.host-list{display:flex;gap:5px;flex-wrap:wrap}
.reference-list{margin:8px 0;display:flex;flex-direction:column;gap:6px;min-width:0}.reference-link{display:block;max-width:100%;min-width:0;color:#1d4ed8;overflow-wrap:anywhere;word-break:break-word;white-space:normal;line-height:1.35}.reference-link span{display:inline-block;background:#fee2e2;color:#991b1b;border-radius:999px;padding:2px 6px;margin-right:4px;font-size:11px;font-weight:700}
.coverage-bar{height:12px;background:#e7edef;border-radius:999px;overflow:hidden;margin:14px 0}.coverage-bar span{display:block;height:100%;background:var(--teal);border-radius:999px}
.document-section{padding:0;overflow:hidden}.document-section>details>summary{display:flex;justify-content:space-between;gap:15px;align-items:center;cursor:pointer;padding:17px 20px;background:#f8fafb}.document-section>details>summary::marker{color:var(--teal)}.document-section summary strong{font-size:18px}.document-section summary small{display:block;color:var(--muted);margin-top:3px}.summary-risk{color:var(--red);font-weight:700}.document-body{padding:4px 20px 20px}.document-tools{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}.document-tools a{border:1px solid var(--line);border-radius:999px;padding:7px 10px;text-decoration:none;color:var(--teal);font-size:13px;font-weight:700}.document-tools a:hover{border-color:var(--teal);background:#ecfdf5}
.host-findings{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:8px}.host-finding{border:1px solid var(--line);border-left:5px solid #64748b;border-radius:8px;padding:12px;min-width:0}.host-finding .severity{float:right}.category{border:1px solid var(--line);border-radius:8px;margin:8px 0}.category>summary{cursor:pointer;font-weight:700;padding:11px 13px;background:#f8fafb}.category>summary span{float:right;background:#e2e8f0;border-radius:999px;padding:2px 7px;font-size:11px}
.object-card{margin:10px;border:1px solid #e5eaed;border-radius:8px;padding:12px}.object-risk-links{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:9px;border-top:1px solid #e5eaed;padding-top:9px;min-width:0}.object-risk-links>strong{color:var(--red);font-size:12px;margin-right:2px}.object-risk-link{display:inline-block;max-width:100%;border-radius:999px;padding:3px 8px;background:#e2e8f0;color:#475569;font-size:12px;font-weight:700;text-decoration:none;overflow-wrap:anywhere}.object-risk-link.critical{background:#fee2e2;color:#991b1b}.object-risk-link.high{background:#ffedd5;color:#9a3412}.object-risk-link.medium{background:#dbeafe;color:#1d4ed8}.object-risk-link:hover{outline:2px solid currentColor;outline-offset:1px}.host-finding.risk-target{outline:3px solid var(--teal);outline-offset:3px;background:#ecfdf5}.item-value td:first-child{width:260px;font-weight:600}.empty{color:var(--muted);padding:8px 0}footer{color:var(--muted);font-size:12px;padding:5px 2px 24px}
@media(max-width:900px){aside{position:static;width:auto}.nav-title,aside a,.nav-empty{display:inline-block;margin:4px}.brand-subtitle{margin-bottom:8px}main{margin:0;padding:12px}.hero-head,.section-head{display:block}.batch-status{margin-top:8px}.search{min-width:0;width:100%;margin-top:10px}.comparison{font-size:12px}.item-value td:first-child{width:38%}}
</style>"""

    @staticmethod
    def _script() -> str:
        return """<script>
function filterHosts(){
  var query=(document.getElementById('hostSearch').value||'').toLocaleLowerCase();
  document.querySelectorAll('.comparison tbody tr').forEach(function(row){
    row.style.display=row.textContent.toLocaleLowerCase().includes(query)?'':'none';
  });
}
function filterCommon(severity){
  document.querySelectorAll('.finding-card').forEach(function(card){
    card.style.display=(severity==='all'||card.dataset.severity===severity)?'block':'none';
  });
}
function openComputerSection(anchor,target){
  var section=document.getElementById(anchor);
  if(!section){return true;}
  var details=section.querySelector('details');
  if(details){details.open=true;}
  var targetId=target?anchor+'-'+target:anchor;
  var node=document.getElementById(targetId)||section;
  node.scrollIntoView({behavior:'smooth',block:'start'});
  if(window.history&&window.history.replaceState){window.history.replaceState(null,'','#'+targetId);}
  return false;
}
function openComputerFinding(anchor,targetId){
  var section=document.getElementById(anchor);
  if(!section){return true;}
  var details=section.querySelector('details');
  if(details){details.open=true;}
  var node=document.getElementById(targetId)||document.getElementById(anchor+'-risks')||section;
  document.querySelectorAll('.host-finding.risk-target').forEach(function(item){
    item.classList.remove('risk-target');
  });
  if(node.classList&&node.classList.contains('host-finding')){
    node.classList.add('risk-target');
    window.setTimeout(function(){node.classList.remove('risk-target');},5000);
  }
  node.scrollIntoView({behavior:'smooth',block:'center'});
  if(window.history&&window.history.replaceState){
    window.history.replaceState(null,'','#'+targetId);
  }
  return false;
}
function openSectionForHash(){
  var hash=(window.location.hash||'').replace(/^#/,'');
  if(!hash){return;}
  var node=document.getElementById(hash);
  var section=node&&node.closest?node.closest('.document-section'):null;
  if(!section){
    var anchor=hash.replace(/-(risks|inventory|diagnostics)$/,'');
    section=document.getElementById(anchor);
  }
  if(section&&section.classList.contains('document-section')){
    var details=section.querySelector('details');
    if(details){details.open=true;}
  }
}
window.addEventListener('hashchange', openSectionForHash);
window.addEventListener('DOMContentLoaded', openSectionForHash);
</script>"""


__all__ = ["BatchHtmlReportBuilder"]
