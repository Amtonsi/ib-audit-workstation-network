from __future__ import annotations

import html
import urllib.parse
from collections import defaultdict
from pathlib import Path

from .assessment import AssessmentBundle
from .category_catalog import WINAUDIT_CATEGORY_ORDER
from .models import (
    AuditRun, CollectorDiagnostic, CoverageSummary, InventoryObject,
    ObjectAssessment, ReportRecord, RuleResult, VulnerabilityMatch, WindowsProfile, utc_now,
)


FIELD_LABELS = {
    "DisplayName": "Name", "DisplayVersion": "Version", "Publisher": "Vendor",
    "InstallDate": "Install Date", "InstallLocation": "Install Location",
    "UninstallString": "Uninstall Command", "HotFixID": "Update ID",
    "ProcessId": "Process ID", "ExecutablePath": "Executable Path",
    "CommandLine": "Command Line", "DeviceLocator": "Device Locator",
    "BankLabel": "Bank Locator", "PartNumber": "Part Number",
    "SerialNumber": "Serial Number", "IPAddress": "IP Address",
    "IPSubnet": "IP Subnet", "DefaultIPGateway": "Default IP Gateway",
    "DNSServerSearchOrder": "DNS Servers",
}


class HtmlReportBuilder:
    def __init__(self, report_max_records: int | None = None):
        self.report_max_records = report_max_records

    def build(
        self,
        output_dir: str | Path,
        run: AuditRun,
        inventory: list[InventoryObject],
        diagnostics: list[CollectorDiagnostic],
        assessment: AssessmentBundle | list[VulnerabilityMatch],
    ) -> str:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        filename = f"{run.started_at.replace(':', '-').replace('+', 'Z')}-{run.hostname}-ib-audit-report.html"
        path = output / filename
        path.write_text(self.render(run, inventory, diagnostics, assessment), encoding="utf-8")
        return str(path)

    def render(
        self,
        run: AuditRun,
        inventory: list[InventoryObject],
        diagnostics: list[CollectorDiagnostic],
        assessment: AssessmentBundle | list[VulnerabilityMatch],
    ) -> str:
        bundle = self._coerce_assessment(inventory, assessment)
        categories: dict[str, list[InventoryObject]] = defaultdict(list)
        for obj in inventory:
            categories[obj.category_name].append(obj)
        known = list(WINAUDIT_CATEGORY_ORDER)
        ordered = [*known, *sorted(name for name in categories if name not in set(known))]
        inventory_by_uid = {obj.uid: obj for obj in inventory}
        assessment_by_uid = {item.object_uid: item for item in bundle.assessments}
        results_by_uid: dict[str, list[RuleResult]] = defaultdict(list)
        for result in bundle.rule_results:
            results_by_uid[result.object_uid].append(result)

        nav = ["Сводка рисков", "Уязвимости", "План устранения", "Покрытие", *ordered, "Диагностика сбора"]
        body = [
            "<!doctype html><html lang='ru'><head><meta charset='utf-8'>",
            f"<title>ИБ-аудит {html.escape(run.hostname)}</title>",
            self._styles(), "</head><body>",
            "<aside><h1>IB Audit</h1>",
            "".join(f"<a href='#{self._anchor(item)}'>{html.escape(item)}</a>" for item in nav),
            "</aside><main>",
            self._summary(run, bundle),
            self._findings(bundle, inventory_by_uid),
            self._remediation(bundle),
            self._coverage(bundle),
            self._object_filters(ordered, categories),
        ]
        for category in ordered:
            body.append(self._inventory_section(
                category, categories.get(category, []), assessment_by_uid, results_by_uid,
            ))
        body.append(self._diagnostics_section(diagnostics))
        body.append(f"<footer>Сформировано: {html.escape(utc_now())}. Исходный документ не изменён.</footer>")
        body.append(self._script())
        body.append("</main></body></html>")
        return "\n".join(body)

    @staticmethod
    def _coerce_assessment(
        inventory: list[InventoryObject],
        value: AssessmentBundle | list[VulnerabilityMatch],
    ) -> AssessmentBundle:
        if isinstance(value, AssessmentBundle):
            return value
        assessments = [ObjectAssessment(obj.uid, "not_applicable", 0, 0, 0, 0) for obj in inventory]
        coverage = CoverageSummary(len(inventory), 0, 0, 0, len(inventory))
        profile = WindowsProfile("legacy", "Unknown Windows", "", "", "", "", "workstation", None)
        return AssessmentBundle(profile, list(value), [], assessments, coverage, [], [])

    def _summary(self, run: AuditRun, bundle: AssessmentBundle) -> str:
        vulnerabilities = bundle.vulnerabilities
        high = sum(1 for item in vulnerabilities if item.severity.upper() in {"CRITICAL", "HIGH"})
        kev = sum(1 for item in vulnerabilities if item.kev)
        snapshots = "".join(
            f"<span class='pill'>{html.escape(item.source)} · {html.escape(item.fetched_at)} · {html.escape(item.sha256[:12])}</span>"
            for item in bundle.snapshots
        ) or "<span class='pill warning'>Базы не использованы или недоступны</span>"
        return (
            "<section id='s-сводка-рисков'><h2>Сводка рисков</h2>"
            f"<p class='meta'>Компьютер: <strong>{html.escape(run.hostname)}</strong> · "
            f"Профиль: {html.escape(bundle.profile.profile_id)} · Администратор: {'да' if run.is_admin else 'нет'}</p>"
            "<div class='kpis'>"
            f"{self._kpi(str(bundle.coverage.risk), 'объектов с риском')}"
            f"{self._kpi(str(high), 'критичных/высоких CVE')}"
            f"{self._kpi(str(kev), 'в CISA KEV')}"
            f"{self._kpi(str(bundle.coverage.document_percent) + '%', 'объектов обработано')}"
            f"{self._kpi(str(bundle.coverage.rule_checked_percent) + '%', 'проверено правилами')}"
            f"{self._kpi(str(bundle.coverage.insufficient_data), 'недостаточно данных')}"
            "</div><h3>Источники уязвимостей</h3>"
            f"{snapshots}</section>"
        )

    def _findings(
        self,
        bundle: AssessmentBundle,
        inventory_by_uid: dict[str, InventoryObject],
    ) -> str:
        findings = [item for item in bundle.rule_results if item.status == "risk"]
        vulnerability_index = self._vulnerability_index(bundle.vulnerabilities)
        items = ["<section id='s-уязвимости'><h2>Уязвимости</h2>",
                 "<div class='filters'><button onclick=\"filterFindings('all')\">Все</button>"
                 "<button onclick=\"filterFindings('vulnerability')\">CVE/БДУ</button>"
                 "<button onclick=\"filterFindings('configuration')\">Настройки</button>"
                 "<button onclick=\"filterFindings('exposure')\">Автозапуск/экспозиция</button></div>"]
        items.append(
            "<div class='filters'>"
            "<label>Kind <select id='findingKindFilter' onchange='applyFilters()'>"
            "<option value='all'>All</option><option value='vulnerability'>CVE/BDU</option>"
            "<option value='configuration'>Configuration</option><option value='exposure'>Exposure</option>"
            "</select></label>"
            "<label>Severity <select id='findingSeverityFilter' onchange='applyFilters()'>"
            "<option value='all'>All</option><option value='critical'>Critical</option>"
            "<option value='high'>High</option><option value='medium'>Medium</option>"
            "<option value='low'>Low</option><option value='info'>Info</option>"
            "</select></label></div>"
        )
        if not findings and not bundle.vulnerabilities:
            items.append("<p>Подтверждённые риски не найдены. Проверьте покрытие и недостаточные данные.</p>")
        for result in findings:
            vulnerability = self._vulnerability_for_result(result, vulnerability_index)
            evidence_details = self._vulnerability_evidence(
                vulnerability,
                inventory_by_uid.get(result.object_uid),
            )
            items.append(
                f"<div class='card finding' data-kind='{html.escape(result.kind, quote=True)}' "
                f"data-severity='{html.escape(result.severity.lower(), quote=True)}'>"
                f"<h3>{html.escape(result.rule_id)} — {html.escape(result.title)}</h3>"
                f"<p>{html.escape(result.evidence)}</p>"
                f"{evidence_details}"
                f"<a href='#object-{html.escape(result.object_uid, quote=True)}'>Перейти к исходному объекту</a>"
                f"<p><strong>Рекомендация:</strong> {html.escape(result.remediation)}</p>"
                f"{self._reference_links(result.references)}</div>"
            )
        known_rule_ids = {item.rule_id for item in findings}
        for vuln in bundle.vulnerabilities:
            if vuln.cve in known_rule_ids:
                continue
            items.append(
                f"<div class='card finding' data-kind='vulnerability' "
                f"data-severity='{html.escape(vuln.severity.lower(), quote=True)}'><h3>{html.escape(vuln.cve)} — "
                f"{html.escape(vuln.affected_title)}</h3><p>{html.escape(vuln.evidence)}</p>"
                f"{self._vulnerability_evidence(vuln, inventory_by_uid.get(vuln.object_uid))}"
                f"<p><strong>Устранение:</strong> {html.escape(vuln.remediation)}</p>"
                f"{self._reference_links(vuln.references)}</div>"
            )
        items.append("</section>")
        return "\n".join(items)

    def _remediation(self, bundle: AssessmentBundle) -> str:
        findings = [item for item in bundle.rule_results if item.status == "risk"]
        items = ["<section id='s-план-устранения'><h2>План устранения</h2>"]
        if not findings and bundle.vulnerabilities:
            for vuln in bundle.vulnerabilities:
                items.append(f"<div class='card'><strong>{html.escape(vuln.affected_title)}</strong><p>{html.escape(vuln.remediation)}</p></div>")
        elif not findings:
            items.append("<p>Автоматические изменения не выполняются. Подтверждённых действий нет.</p>")
        else:
            items.append("<table><tr><th>Уровень</th><th>Правило</th><th>Объект</th><th>Рекомендация</th></tr>")
            for result in findings:
                items.append(
                    f"<tr><td>{html.escape(result.severity)}</td><td>{html.escape(result.rule_id)}</td>"
                    f"<td><a href='#object-{html.escape(result.object_uid, quote=True)}'>{html.escape(result.title)}</a></td>"
                    f"<td>{html.escape(result.remediation)}</td></tr>"
                )
            items.append("</table>")
        items.append("</section>")
        return "\n".join(items)

    def _coverage(self, bundle: AssessmentBundle) -> str:
        c = bundle.coverage
        return (
            "<section id='s-покрытие'><h2>Покрытие</h2><div class='kpis'>"
            f"{self._kpi(str(c.total_objects), 'всего объектов')}"
            f"{self._kpi(str(c.document_percent) + '%', 'объектов обработано')}"
            f"{self._kpi(str(c.rule_checked_percent) + '%', 'проверено правилами')}"
            f"{self._kpi(str(c.risk), 'Риск')}{self._kpi(str(c.passed), 'Проверено')}"
            f"{self._kpi(str(c.insufficient_data), 'Недостаточно данных')}"
            f"{self._kpi(str(c.not_applicable), 'Не применимо')}</div>"
            "<p>«Объектов обработано» показывает, что каждый объект документа получил итоговый статус. "
            "«Проверено правилами» показывает долю объектов с автоматическим pass/risk. "
            "Недостаточно данных и не применимо остаются отдельными статусами, а не потерянными объектами.</p></section>"
        )

    def _object_filters(self, ordered: list[str], categories: dict[str, list[InventoryObject]]) -> str:
        sources = sorted({obj.source for objects in categories.values() for obj in objects if obj.source})
        visible_categories = [category for category in ordered if categories.get(category)]
        source_options = "".join(
            f"<option value='{html.escape(source, quote=True)}'>{html.escape(source)}</option>"
            for source in sources
        )
        category_options = "".join(
            f"<option value='{html.escape(category, quote=True)}'>{html.escape(category)}</option>"
            for category in visible_categories
        )
        return (
            "<section id='s-object-filters' class='filter-panel'><h2>Object filters</h2>"
            "<div class='filters'>"
            "<label>Status <select id='objectStatusFilter' onchange='applyFilters()'>"
            "<option value='all'>All</option><option value='risk'>Risk</option>"
            "<option value='passed'>Passed</option><option value='insufficient_data'>Insufficient data</option>"
            "<option value='not_applicable'>Not applicable</option></select></label>"
            "<label>Source <select id='objectSourceFilter' onchange='applyFilters()'>"
            f"<option value='all'>All</option>{source_options}</select></label>"
            "<label>Category <select id='objectCategoryFilter' onchange='applyFilters()'>"
            f"<option value='all'>All</option>{category_options}</select></label>"
            "</div></section>"
        )

    def _inventory_section(
        self,
        category: str,
        objects: list[InventoryObject],
        assessments: dict[str, ObjectAssessment],
        results: dict[str, list[RuleResult]],
    ) -> str:
        items = [f"<section id='{self._anchor(category)}'><h2>{html.escape(category)}</h2>"]
        if not objects:
            items.append("<p class='unavailable'>Данные недоступны. Причина указана в диагностике сбора.</p></section>")
            return "\n".join(items)
        shown = objects if self.report_max_records is None else objects[:self.report_max_records]
        if len(shown) < len(objects):
            items.append(f"<p class='limit-note'>Показаны первые {len(shown)} из {len(objects)} записей.</p>")
        for obj in shown:
            status = assessments.get(obj.uid, ObjectAssessment(obj.uid, "not_applicable", 0, 0, 0, 0)).status
            items.append(
                f"<div class='card object-card' id='object-{html.escape(obj.uid, quote=True)}' "
                f"data-status='{html.escape(status, quote=True)}' "
                f"data-source='{html.escape(obj.source, quote=True)}' "
                f"data-category='{html.escape(category, quote=True)}'><h3>{html.escape(obj.title)}</h3>"
                f"<span class='status {html.escape(status)}'>{html.escape(self._status_label(status))}</span>"
                f"<p class='meta'>Источник: {html.escape(obj.source)} · Уверенность: {html.escape(obj.confidence)}</p>"
                "<table class='item-value'><tr><th>Item</th><th>Value</th></tr>"
            )
            for key, value in list(obj.fields.items())[:200]:
                items.append(f"<tr><td>{html.escape(FIELD_LABELS.get(str(key), str(key)))}</td><td>{html.escape(self._short(value))}</td></tr>")
            items.append("</table>")
            for result in results.get(obj.uid, []):
                items.append(
                    f"<div class='rule {html.escape(result.status)}'><strong>{html.escape(result.rule_id)}</strong> — "
                    f"{html.escape(self._status_label(result.status))}: {html.escape(result.evidence)}</div>"
                )
            items.append("</div>")
        items.append("</section>")
        return "\n".join(items)

    def _diagnostics_section(self, diagnostics: list[CollectorDiagnostic]) -> str:
        items = ["<section id='s-диагностика-сбора'><h2>Диагностика сбора</h2>"]
        if not diagnostics:
            items.append("<p>Диагностических сообщений нет.</p>")
        else:
            items.append("<table><tr><th>Модуль</th><th>Уровень</th><th>Сообщение</th><th>Источник</th></tr>")
            for item in diagnostics:
                items.append(f"<tr><td>{html.escape(item.module)}</td><td>{html.escape(item.severity)}</td><td>{html.escape(item.message)}</td><td>{html.escape(item.source)}</td></tr>")
            items.append("</table>")
        items.append("</section>")
        return "\n".join(items)

    @staticmethod
    def _reference_links(references: list[str]) -> str:
        links = []
        for ref in references:
            parsed = urllib.parse.urlparse(ref)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                safe = html.escape(ref, quote=True)
                label = "Эксплойт" if HtmlReportBuilder._is_exploit_reference(ref) else "Источник"
                links.append(
                    f"<a class='reference-link' href='{safe}' rel='noreferrer'>"
                    f"<span>{html.escape(label)}</span> {safe}</a>"
                )
        return " ".join(links)

    @staticmethod
    def _vulnerability_index(
        vulnerabilities: list[VulnerabilityMatch],
    ) -> dict[tuple[str, str], VulnerabilityMatch]:
        indexed: dict[tuple[str, str], VulnerabilityMatch] = {}
        for item in vulnerabilities:
            indexed[(item.object_uid, item.cve)] = item
            indexed.setdefault(("", item.cve), item)
        return indexed

    @staticmethod
    def _vulnerability_for_result(
        result: RuleResult,
        vulnerability_index: dict[tuple[str, str], VulnerabilityMatch],
    ) -> VulnerabilityMatch | None:
        return (
            vulnerability_index.get((result.object_uid, result.rule_id))
            or vulnerability_index.get(("", result.rule_id))
        )

    @classmethod
    def _vulnerability_evidence(
        cls,
        vulnerability: VulnerabilityMatch | None,
        inventory_object: InventoryObject | None,
    ) -> str:
        if vulnerability is None:
            return ""
        installed_version = cls._installed_version(inventory_object) or "не определена"
        applicability = vulnerability.applicability.casefold() or "confirmed"
        label = "Подтверждено" if applicability == "confirmed" else "Потенциальный риск"
        cpe = (
            f"<p><strong>CPE:</strong> <code>{html.escape(vulnerability.cpe)}</code></p>"
            if vulnerability.cpe
            else ""
        )
        return (
            "<div class='vulnerability-evidence'>"
            f"<span class='applicability-badge {html.escape(applicability, quote=True)}'>"
            f"{html.escape(label)}</span>"
            f"<p><strong>Установленная версия:</strong> {html.escape(installed_version)}</p>"
            f"{cpe}"
            f"<p><strong>Доказательство:</strong> {html.escape(vulnerability.evidence)}</p>"
            f"{cls._human_vulnerability_reason(vulnerability)}</div>"
        )

    @staticmethod
    def _installed_version(inventory_object: InventoryObject | None) -> str:
        if inventory_object is None:
            return ""
        for key in (
            "DisplayVersion",
            "Version",
            "FileVersion",
            "Executable Version",
            "Driver Version",
            "DriverVersion",
            "Firmware Revision",
            "FirmwareVersion",
            "BIOS Version",
            "SMBIOSBIOSVersion",
        ):
            value = inventory_object.fields.get(key)
            if value not in (None, ""):
                return str(value)
        return ""

    @staticmethod
    def _human_vulnerability_reason(vulnerability: VulnerabilityMatch) -> str:
        evidence = vulnerability.evidence.casefold()
        if (
            vulnerability.applicability.casefold() == "potential"
            and "firmware version is unknown" in evidence
        ):
            return "<p><strong>Причина:</strong> Версия прошивки не подтверждена</p>"
        if vulnerability.applicability.casefold() == "potential":
            return "<p><strong>Причина:</strong> Нужна ручная проверка применимости</p>"
        return ""

    @staticmethod
    def _is_exploit_reference(ref: str) -> bool:
        lowered = ref.casefold()
        return any(
            marker in lowered
            for marker in ("exploit", "exploit-db", "metasploit", "packetstormsecurity", "0day.today")
        ) or "packetstormsecurity.com" in lowered or "securityfocus.com/bid" in lowered

    @staticmethod
    def _status_label(status: str) -> str:
        return {
            "risk": "Риск", "passed": "Проверено",
            "insufficient_data": "Недостаточно данных", "not_applicable": "Не применимо",
        }.get(status, status)

    @staticmethod
    def _anchor(text: str) -> str:
        return "s-" + "".join(ch.lower() if ch.isalnum() else "-" for ch in text).strip("-")

    @staticmethod
    def _kpi(value: str, label: str) -> str:
        return f"<div class='kpi'><strong>{html.escape(value)}</strong><span>{html.escape(label)}</span></div>"

    @staticmethod
    def _short(value: object) -> str:
        text = str(value)
        return text if len(text) <= 4000 else text[:4000] + "…"

    @staticmethod
    def _styles() -> str:
        return """<style>
*{box-sizing:border-box}
body{margin:0;background:#f4f6fa;color:#111827;font-family:Segoe UI,Arial,sans-serif}
aside{position:fixed;inset:0 auto 0 0;width:270px;background:#111827;color:#d1d5db;overflow:auto;padding:18px}
aside h1{color:#fff}aside a{display:block;color:#d1d5db;text-decoration:none;padding:7px 9px;border-radius:6px;font-size:13px}
aside a:hover{background:#1f2937;color:#fff}main{margin-left:306px;padding:24px;max-width:1300px;min-width:0}
section{background:#fff;border:1px solid #d8dee9;border-radius:9px;margin-bottom:18px;padding:18px}
main,section,.card{max-width:100%;min-width:0;overflow-wrap:anywhere}
h2{margin:0 0 12px}.meta{color:#4b5563}.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px}
.kpi{background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:12px}.kpi strong{display:block;font-size:24px}
.card{border:1px solid #e5e7eb;border-radius:8px;padding:14px;margin:10px 0}.finding{border-left:5px solid #dc2626}
.pill,.status{display:inline-block;border-radius:999px;padding:4px 8px;margin:3px;font-size:12px;background:#eef2ff}
.status.risk{background:#fee2e2;color:#991b1b}.status.passed{background:#dcfce7;color:#166534}
.status.insufficient_data{background:#ffedd5;color:#9a3412}.status.not_applicable{background:#e2e8f0;color:#475569}
.warning,.unavailable{color:#9a3412}.rule{padding:8px;margin-top:7px;background:#f8fafc;border-radius:6px}
.vulnerability-evidence{margin:10px 0;padding:10px;background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;min-width:0;overflow-wrap:anywhere;word-break:break-word}
.vulnerability-evidence p{margin:6px 0}.vulnerability-evidence code{white-space:normal;overflow-wrap:anywhere;word-break:break-word}
.applicability-badge{display:inline-block;border-radius:999px;padding:3px 8px;margin-bottom:4px;font-size:12px;font-weight:700;background:#eef2ff;color:#3730a3}.applicability-badge.confirmed{background:#dcfce7;color:#166534}.applicability-badge.potential{background:#ffedd5;color:#9a3412}
.reference-link{display:inline-block;max-width:100%;min-width:0;margin:4px 6px 0 0;color:#1d4ed8;overflow-wrap:anywhere;word-break:break-word;white-space:normal}.reference-link span{background:#fee2e2;color:#991b1b;border-radius:999px;padding:2px 6px;font-size:11px;font-weight:700}
.limit-note{background:#fff7ed;color:#9a3412;padding:8px}table{border-collapse:collapse;width:100%;table-layout:fixed}
td,th{border:1px solid #e5e7eb;padding:8px;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-break:break-word}.item-value td:first-child{width:260px;font-weight:600}
.item-value td:last-child{overflow-wrap:anywhere;word-break:break-word}.filters{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0}.filters button,.filters select{max-width:100%;margin:0 6px 8px 0}footer{color:#6b7280;font-size:12px}
@media(max-width:820px){aside{position:static;width:auto}main{margin:0;padding:12px}}
</style>"""

    @staticmethod
    def _script() -> str:
        return """<script>
function selected(id){
  var element=document.getElementById(id);
  return element ? element.value : 'all';
}
function applyFilters(){
  var findingKind=selected('findingKindFilter');
  var findingSeverity=selected('findingSeverityFilter');
  document.querySelectorAll('.finding').forEach(function(card){
    var kindOk=(findingKind==='all'||card.dataset.kind===findingKind);
    var severityOk=(findingSeverity==='all'||card.dataset.severity===findingSeverity);
    card.style.display=(kindOk&&severityOk)?'block':'none';
  });
  var objectStatus=selected('objectStatusFilter');
  var objectSource=selected('objectSourceFilter');
  var objectCategory=selected('objectCategoryFilter');
  document.querySelectorAll('.object-card').forEach(function(card){
    var statusOk=(objectStatus==='all'||card.dataset.status===objectStatus);
    var sourceOk=(objectSource==='all'||card.dataset.source===objectSource);
    var categoryOk=(objectCategory==='all'||card.dataset.category===objectCategory);
    card.style.display=(statusOk&&sourceOk&&categoryOk)?'block':'none';
  });
}
function filterFindings(kind){
  var element=document.getElementById('findingKindFilter');
  if(element){element.value=kind;}
  applyFilters();
}
document.addEventListener('DOMContentLoaded', applyFilters);
</script>"""


__all__ = ["HtmlReportBuilder", "ReportRecord"]
