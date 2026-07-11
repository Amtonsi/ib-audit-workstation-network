from __future__ import annotations

from .design_system import REPORT_THEME_STYLE

import html
import json
import re
import ipaddress
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
        network_objects = [
            obj for obj in inventory
            if obj.object_type in {"network_service", "network_capture"}
        ]
        if network_objects:
            ordered = [
                category for category in ordered
                if self._anchor(category) != "s-network-intelligence"
            ]

        nav = ["Сводка рисков", "Уязвимости", "План устранения", "Покрытие", *ordered, "Диагностика сбора"]
        if network_objects:
            nav.insert(4, "Network Intelligence")

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
            self._network_intelligence_section(network_objects, inventory, bundle),
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
                f"data-severity='{html.escape(result.severity.lower(), quote=True)}' "
                f"id='{html.escape(self._finding_anchor(result.object_uid, result.rule_id), quote=True)}'>"
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
                f"data-severity='{html.escape(vuln.severity.lower(), quote=True)}' "
                f"id='{html.escape(self._finding_anchor(vuln.object_uid, vuln.cve), quote=True)}'><h3>{html.escape(vuln.cve)} — "
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

    def _network_intelligence_section(
        self,
        network_objects: list[InventoryObject],
        inventory: list[InventoryObject],
        bundle: AssessmentBundle,
    ) -> str:
        if not network_objects:
            return ""
        services = [obj for obj in network_objects if obj.object_type == "network_service"]
        flows = [obj for obj in network_objects if obj.object_type == "network_capture"]
        adapters = [obj for obj in inventory if obj.object_type == "network_adapter"]
        topology = self._build_network_topology(services, flows, adapters)
        external_flows = [
            obj for obj in flows
            if str(obj.fields.get("Destination Scope") or "").casefold() == "external"
            or str(obj.fields.get("Source Scope") or "").casefold() == "external"
        ]
        applications = sorted({
            str(obj.fields.get("Local Application") or "").strip()
            for obj in flows
            if str(obj.fields.get("Local Application") or "").strip()
        })
        traffic_severity_counts: defaultdict[str, int] = defaultdict(int)
        for obj in flows:
            severity = self._traffic_severity_class(obj.fields.get("Traffic Severity"))
            traffic_severity_counts[severity] += 1
        packet_rows = self._packet_rows_from_flows(flows)

        dashboard = topology.get("dashboard", {})
        protocols = dashboard.get("protocols", [])
        talkers = dashboard.get("talkers", [])
        top_apps = dashboard.get("applications", [])

        protocol_items = [
            f"<li>{self._protocol_badge(str(item.get('name', '')))} "
            f"{html.escape(str(item.get('value', 0)))} packets</li>"
            for item in protocols[:6]
        ]
        talker_items = [
            f"<li>{html.escape(str(item.get('label', '')))}: {self._human_readable_bytes(int(item.get('bytes', 0)))}</li>"
            for item in talkers[:6]
        ]
        app_items = [
            f"<li>{html.escape(str(item.get('name', '')))}: {self._human_readable_bytes(int(item.get('bytes', 0)))}</li>"
            for item in top_apps[:6]
        ]

        if not protocol_items:
            protocol_items = ["<li>No data</li>"]
        if not talker_items:
            talker_items = ["<li>No traffic links</li>"]
        if not app_items:
            app_items = ["<li>No local application traffic</li>"]
        risk_items = [
            f"<span class='traffic-badge {html.escape(severity)}'>{html.escape(severity.upper())}: {count}</span>"
            for severity, count in sorted(
                traffic_severity_counts.items(),
                key=lambda item: (-self._traffic_severity_rank(item[0]), item[0]),
            )
        ]
        if not risk_items:
            risk_items = ["<span class='muted'>No traffic risk data</span>"]

        summary = topology.get("summary", {})
        role_summary = summary.get("roles", {})
        role_items = [
            f"<li><span class='muted'>{html.escape(str(role))}:</span> {int(count)}</li>"
            for role, count in sorted(role_summary.items(), key=lambda item: item[0].casefold())
        ]
        if not role_items:
            role_items = ["<li><span class='muted'>No role data yet</span></li>"]

        items = [
            "<section id='s-network-intelligence' class='network-intelligence'>",
            "<h2>Network Intelligence</h2>",
            "<div class='kpis'>",
            self._kpi(str(len(services)), "Open services"),
            self._kpi(str(len(flows)), "Traffic flows"),
            self._kpi(str(len(packet_rows)), "Captured packets"),
            self._kpi(str(len(external_flows)), "External flows"),
            self._kpi(str(len(applications)), "Local applications"),
            "</div>",
            self._network_overview_html(
                services,
                flows,
                packet_rows,
                topology,
                traffic_severity_counts,
                protocols,
            ),
            "<div class='network-dashboard'>",
            "<div class='network-dashboard-card'>",
            "<h3>Traffic dashboard</h3>",
            "<div class='dashboard-mini'>",
            "<div class='compact-list'><strong>Top protocols</strong><ul>" + "".join(protocol_items) + "</ul></div>",
            "<div class='compact-list'><strong>Top talkers</strong><ul>" + "".join(talker_items) + "</ul></div>",
            "<div class='compact-list'><strong>Top local applications</strong><ul>" + "".join(app_items) + "</ul></div>",
            "</div>",
            "</div>",
            "<div class='network-dashboard-card'>",
            "<h3>Topology summary</h3>",
            "<p>" +
            f"<span class='muted'>Total packets:</span> {self._human_readable_bytes(int(summary.get('total_packets', 0)))} " +
            f"<span class='muted'>Total bytes:</span> {self._human_readable_bytes(int(summary.get('total_bytes', 0)))} " +
            f"<span class='muted'>Nodes:</span> {int(summary.get('node_count', 0))} " +
            f"<span class='muted'>Links:</span> {int(summary.get('edge_count', 0))}" +
            "</p><ul class='compact-list'>" + "".join(role_items) + "</ul>",
            "</div>",
            "<div class='network-dashboard-card'>",
            "<h3>Traffic risk analysis</h3>",
            "<p class='muted'>Rows are color-marked from packet metadata, protocol context, TCP analysis flags, external direction and Wireshark expert indicators.</p>",
            "<div class='traffic-risk-legend'>" + "".join(risk_items) + "</div>",
            "</div>",
            "</div>",
            self._network_topology_panel_html(topology),
            "<div class='topology-legend'>",
            "<span class='legend-gateway'>Gateway</span>",
            "<span class='legend-router'>Router (estimated)</span>",
            "<span class='legend-server'>Server/Endpoint</span>",
            "<span class='legend-switch'>Switch (estimated)</span>",
            "<span class='legend-endpoint'>Endpoint</span>",
            "<span class='legend-external'>External</span>",
            "</div>",
        ]

        if packet_rows:
            items.extend(self._packet_list_html(packet_rows))
        if flows:
            items.append("<h3>Traffic flows</h3>")
            items.append(
                "<table class='network-table'><tr>"
                "<th>Local application</th><th>Direction</th><th>Source</th><th>Destination</th>"
                "<th>Protocol</th><th>Packets</th><th>Bytes</th><th>Risk</th><th>Findings</th>"
                "<th>Captured packet samples</th><th>Vulnerability links</th></tr>"
            )
            for obj in flows[:200]:
                fields = obj.fields
                source = self._endpoint(fields, "Source", "Source Port")
                destination = self._endpoint(fields, "Destination", "Destination Port")
                application = str(fields.get("Local Application") or fields.get("Local PID") or "unknown")
                severity = self._traffic_severity_class(fields.get("Traffic Severity"))
                findings = str(fields.get("Traffic Findings") or "No notable traffic risk indicators")
                packet_samples = str(fields.get("Packet Samples") or "")
                sample_count = str(fields.get("Packet Sample Count") or "")
                if packet_samples:
                    escaped_samples = html.escape(packet_samples)
                    packet_html = (
                        "<details class='packet-samples'><summary>Captured packet samples"
                        + (f" ({html.escape(sample_count)})" if sample_count else "")
                        + f"</summary><pre>{escaped_samples}</pre></details>"
                    )
                else:
                    packet_html = "<span class='muted'>No packet sample metadata</span>"
                items.append(
                    f"<tr class='traffic-row {html.escape(severity)}'>"
                    f"<td>{html.escape(application)}</td>"
                    f"<td><span class='pill'>{html.escape(str(fields.get('Direction') or 'unknown'))}</span></td>"
                    f"<td>{html.escape(source)}</td>"
                    f"<td>{html.escape(destination)}</td>"
                    f"<td>{self._protocol_badge(str(fields.get('Protocol') or ''))}</td>"
                    f"<td>{html.escape(str(fields.get('Packets') or ''))}</td>"
                    f"<td>{html.escape(str(fields.get('Bytes') or ''))}</td>"
                    f"<td><span class='traffic-badge {html.escape(severity)}'>{html.escape(severity.upper())}</span></td>"
                    f"<td>{html.escape(findings)}</td>"
                    f"<td>{packet_html}</td>"
                    f"<td>{self._risk_links(obj.uid, bundle.vulnerabilities)}</td>"
                    "</tr>"
                )
            items.append("</table>")
        if services:
            items.append("<h3>Open services</h3>")
            items.append(
                "<table class='network-table'><tr>"
                "<th>Host</th><th>Port</th><th>Service</th><th>Product/version</th><th>OS</th><th>Risks</th></tr>"
            )
            for obj in services[:200]:
                fields = obj.fields
                product = " ".join(
                    part for part in (
                        str(fields.get("Service Product") or ""),
                        str(fields.get("Service Version") or ""),
                    )
                    if part
                ) or str(fields.get("Service") or "")
                port = "/".join(
                    part for part in (str(fields.get("Port") or ""), str(fields.get("Protocol") or ""))
                    if part
                )
                host = " ".join(
                    part for part in (str(fields.get("Host IP") or ""), str(fields.get("Host Name") or ""))
                    if part
                )
                items.append(
                    "<tr>"
                    f"<td>{html.escape(host)}</td>"
                    f"<td>{html.escape(port)}</td>"
                    f"<td>{html.escape(str(fields.get('Service') or ''))}</td>"
                    f"<td>{html.escape(product)}</td>"
                    f"<td>{html.escape(str(fields.get('Host OS') or ''))}</td>"
                    f"<td>{self._risk_links(obj.uid, bundle.vulnerabilities)}</td>"
                    "</tr>"
                )
            items.append("</table>")
        items.append("</section>")
        return "\n".join(items)

    def _network_overview_html(
        self,
        services: list[InventoryObject],
        flows: list[InventoryObject],
        packet_rows: list[dict[str, str]],
        topology: dict[str, object],
        traffic_severity_counts: dict[str, int],
        protocols: list[dict[str, object]],
    ) -> str:
        summary = topology.get("summary", {}) if isinstance(topology, dict) else {}
        node_count = int(summary.get("node_count", 0) or 0)
        edge_count = int(summary.get("edge_count", 0) or 0)
        total_packets = int(summary.get("total_packets", 0) or 0)
        total_bytes = int(summary.get("total_bytes", 0) or 0)
        high_or_worse = sum(
            count
            for severity, count in traffic_severity_counts.items()
            if self._traffic_severity_rank(severity) >= self._traffic_severity_rank("high")
        )
        protocol_badges = "".join(
            f"{self._protocol_badge(str(item.get('name') or 'UNKNOWN'))}"
            f"<span class='protocol-count'>{html.escape(str(item.get('value') or 0))}</span>"
            for item in protocols[:8]
        ) or "<span class='muted'>No protocol data</span>"
        notable = []
        if services:
            notable.append(f"open services: {len(services)}")
        if high_or_worse:
            notable.append(f"high-risk flows: {high_or_worse}")
        if packet_rows:
            notable.append(f"packet rows: {len(packet_rows)}")
        if not notable:
            notable.append("no critical traffic indicators")
        return (
            "<div class='network-overview'>"
            "<h3>Обобщенное описание трафика</h3>"
            "<p>"
            f"Обнаружено {len(flows)} потоков, {len(packet_rows)} строк пакетов, "
            f"{node_count} узлов и {edge_count} связей. "
            f"Суммарно по потокам: {total_packets} пакетов, {self._human_readable_bytes(total_bytes)}. "
            f"Ключевые признаки: {html.escape('; '.join(notable))}."
            "</p>"
            "<div class='protocol-summary'><strong>Протоколы:</strong> "
            f"{protocol_badges}</div>"
            "</div>"
        )

    def _network_topology_panel_html(self, topology: dict[str, object]) -> str:
        nodes = topology.get("nodes", []) if isinstance(topology, dict) else []
        if not isinstance(nodes, list) or not nodes:
            return (
                "<div class='network-map-panel'><h3>Схема сети и узлы</h3>"
                "<p class='muted'>Сеть еще не распознана. Запустите сетевую проверку с захватом трафика.</p></div>"
            )
        rows = []
        for node in nodes[:16]:
            if not isinstance(node, dict):
                continue
            role = str(node.get("role") or "Endpoint")
            address = str(node.get("ip") or node.get("id") or "")
            scope = str(node.get("scope") or "")
            severity = "high" if scope == "external" else "info"
            risk = "ВНЕШНИЙ" if scope == "external" else "ИНФО"
            rows.append(
                "<tr>"
                f"<td>{html.escape(role)}</td>"
                f"<td>{html.escape(address)}</td>"
                f"<td><span class='traffic-badge {severity}'>{risk}</span></td>"
                "</tr>"
            )
        return (
            "<div class='network-map-panel'>"
            "<h3>Схема сети и узлы</h3>"
            f"{self._network_topology_svg(topology)}"
            "<table class='network-node-table'><thead><tr><th>Роль</th><th>Адрес</th><th>Риск</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            "</div>"
        )

    def _network_topology_svg(self, topology: dict[str, object]) -> str:
        nodes_raw = topology.get("nodes", []) if isinstance(topology, dict) else []
        edges_raw = topology.get("edges", []) if isinstance(topology, dict) else []
        nodes = [node for node in nodes_raw if isinstance(node, dict)][:12]
        if not nodes:
            return ""
        center = max(
            nodes,
            key=lambda node: (
                self._to_int(node.get("neighbor_count")),
                self._to_int(node.get("bytes")),
                self._to_int(node.get("packets")),
            ),
        )
        center_id = str(center.get("id") or center.get("ip"))
        positions: dict[str, tuple[int, int]] = {center_id: (610, 118)}
        slots = [
            (160, 56), (330, 56), (500, 56), (705, 56), (875, 56), (1045, 56),
            (110, 148), (280, 148), (455, 148), (745, 148), (920, 148), (1080, 148),
        ]
        slot_index = 0
        for node in nodes:
            node_id = str(node.get("id") or node.get("ip"))
            if node_id == center_id:
                continue
            positions[node_id] = slots[slot_index % len(slots)]
            slot_index += 1

        edge_svg = []
        rendered_edges: set[tuple[str, str, str]] = set()
        for edge in edges_raw:
            if not isinstance(edge, dict):
                continue
            source = str(edge.get("source") or "")
            target = str(edge.get("target") or "")
            if source not in positions or target not in positions:
                continue
            protocol = str(edge.get("protocol") or "UNKNOWN")
            key = (source, target, protocol)
            if key in rendered_edges:
                continue
            rendered_edges.add(key)
            x1, y1 = positions[source]
            x2, y2 = positions[target]
            severity = self._traffic_severity_class(edge.get("severity"))
            edge_svg.append(
                f"<line class='network-map-edge {html.escape(severity)} {html.escape(self._protocol_class(protocol))}' "
                f"x1='{x1}' y1='{y1}' x2='{x2}' y2='{y2}' />"
            )
        if not edge_svg:
            for node_id, (x2, y2) in positions.items():
                if node_id == center_id:
                    continue
                edge_svg.append(
                    f"<line class='network-map-edge info' x1='610' y1='118' x2='{x2}' y2='{y2}' />"
                )

        node_svg = []
        for node in nodes:
            node_id = str(node.get("id") or node.get("ip"))
            x, y = positions.get(node_id, (610, 118))
            label = str(node.get("ip") or node.get("label") or node_id)
            role = str(node.get("role") or "Endpoint")
            scope = str(node.get("scope") or "")
            node_class = "central" if node_id == center_id else self._role_class(role, scope)
            node_role = self._safe_name(role.replace(" (estimated)", ""))
            node_svg.append(
                f"<g class='network-map-node {html.escape(node_class)}'>"
                f"<ellipse cx='{x}' cy='{y}' rx='70' ry='30' />"
                f"<text class='network-map-label' x='{x}' y='{y - 2}'>{html.escape(self._safe_name(label))}</text>"
                f"<text class='network-map-role' x='{x}' y='{y + 15}'>{html.escape(node_role)}</text>"
                "</g>"
            )
        return (
            "<svg class='network-map-svg' viewBox='0 0 1200 210' role='img' "
            "aria-label='Network topology model'>"
            "<defs>"
            "<radialGradient id='networkMapBg' cx='50%' cy='42%' r='78%'>"
            "<stop offset='0%' stop-color='#ffffff'/><stop offset='46%' stop-color='#e0f2fe'/>"
            "<stop offset='100%' stop-color='#cbd5e1'/></radialGradient>"
            "<linearGradient id='nodeEndpoint' x1='0%' x2='100%'><stop offset='0%' stop-color='#16a34a'/><stop offset='100%' stop-color='#047857'/></linearGradient>"
            "<linearGradient id='nodeCentral' x1='0%' x2='100%'><stop offset='0%' stop-color='#38bdf8'/><stop offset='100%' stop-color='#2563eb'/></linearGradient>"
            "<linearGradient id='nodeExternal' x1='0%' x2='100%'><stop offset='0%' stop-color='#ef4444'/><stop offset='100%' stop-color='#991b1b'/></linearGradient>"
            "<linearGradient id='nodeAmber' x1='0%' x2='100%'><stop offset='0%' stop-color='#f59e0b'/><stop offset='100%' stop-color='#92400e'/></linearGradient>"
            "<filter id='nodeGlow' x='-40%' y='-60%' width='180%' height='220%'><feGaussianBlur stdDeviation='4' result='blur'/><feMerge><feMergeNode in='blur'/><feMergeNode in='SourceGraphic'/></feMerge></filter>"
            "<filter id='linkGlow' x='-20%' y='-40%' width='140%' height='180%'><feGaussianBlur stdDeviation='1.8' result='blur'/><feMerge><feMergeNode in='blur'/><feMergeNode in='SourceGraphic'/></feMerge></filter>"
            "</defs>"
            "<rect class='network-map-bg' x='0' y='0' width='1200' height='210' />"
            "<path class='network-map-grid' d='M0 42H1200M0 84H1200M0 126H1200M0 168H1200M120 0V210M240 0V210M360 0V210M480 0V210M600 0V210M720 0V210M840 0V210M960 0V210M1080 0V210' />"
            + "".join(edge_svg)
            + "".join(node_svg)
            + "</svg>"
        )

    @staticmethod
    def _role_class(role: str, scope: str) -> str:
        value = role.casefold()
        if scope == "external" or "external" in value:
            return "external"
        if "gateway" in value:
            return "gateway"
        if "router" in value:
            return "router"
        if "switch" in value:
            return "switch"
        if "server" in value:
            return "server"
        return "endpoint"

    def _packet_rows_from_flows(self, flows: list[InventoryObject]) -> list[dict[str, str]]:
        packet_rows: list[dict[str, str]] = []
        for obj in flows:
            raw = str(obj.fields.get("Packet Rows JSON") or "").strip()
            if not raw:
                continue
            try:
                parsed = json.loads(raw)
            except (TypeError, ValueError):
                continue
            if not isinstance(parsed, list):
                continue
            flow_severity = self._traffic_severity_class(obj.fields.get("Traffic Severity"))
            for item in parsed:
                if not isinstance(item, dict):
                    continue
                packet = {str(key): str(value) for key, value in item.items()}
                packet.setdefault("Risk", flow_severity)
                packet_rows.append(packet)
        return packet_rows

    def _packet_list_html(self, packet_rows: list[dict[str, str]]) -> list[str]:
        limit = 2000
        items = [
            "<details class='packet-list-collapsed'>",
            f"<summary><span>Wireshark packet list</span><span>{len(packet_rows)} packets</span></summary>",
            "<p class='muted'>Packet-level rows captured from tshark. Select details in the table to inspect decoded fields and byte preview.</p>",
            "<table class='network-table packet-list'><tr>"
            "<th>No.</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info / details</th><th>Risk</th></tr>",
        ]
        for row in packet_rows[:limit]:
            severity = self._traffic_severity_class(row.get("Risk"))
            details = str(row.get("Details") or "")
            bytes_hex = str(row.get("Bytes Hex") or "")
            details_html = ""
            if details or bytes_hex:
                details_html = (
                    "<details class='packet-samples'><summary>Packet details / bytes</summary>"
                    f"<pre>{html.escape(details or 'No decoded details')}</pre>"
                    f"<pre class='packet-hex'>{html.escape(bytes_hex or 'No byte preview')}</pre>"
                    "</details>"
                )
            items.append(
                f"<tr class='packet-row {html.escape(severity)}'>"
                f"<td>{html.escape(str(row.get('No.') or row.get('No') or ''))}</td>"
                f"<td>{html.escape(str(row.get('Time') or ''))}</td>"
                f"<td>{html.escape(str(row.get('Source') or ''))}</td>"
                f"<td>{html.escape(str(row.get('Destination') or ''))}</td>"
                f"<td>{self._protocol_badge(str(row.get('Protocol') or ''))}</td>"
                f"<td>{html.escape(str(row.get('Length') or ''))}</td>"
                f"<td>{html.escape(str(row.get('Info') or ''))}{details_html}</td>"
                f"<td><span class='traffic-badge {html.escape(severity)}'>{html.escape(severity.upper())}</span></td>"
                "</tr>"
            )
        items.append("</table>")
        if len(packet_rows) > limit:
            items.append(f"<p class='limit-note'>Shown first {limit} packet rows out of {len(packet_rows)} captured rows.</p>")
        items.append("</details>")
        return items

    @staticmethod
    def _split_values(raw: str) -> list[str]:
        if not raw:
            return []
        return [part.strip() for part in re.split(r"[,;\n\r\t]+", str(raw)) if part.strip()]

    @staticmethod
    def _parse_ipv4(raw: str | object) -> str:
        text = str(raw or "").strip()
        if not text:
            return ""
        text = text.split("/")[0].strip()
        match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
        if not match:
            return ""
        candidate = match.group(1)
        try:
            ipaddress.IPv4Address(candidate)
            return candidate
        except ValueError:
            return ""

    @staticmethod
    def _to_int(value: object, default: int = 0) -> int:
        try:
            return int(str(value).replace(" ", ""))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _ip_scope(value: str) -> str:
        try:
            ip_value = ipaddress.ip_address(value)
        except ValueError:
            return "unknown"
        if ip_value.is_private:
            return "private"
        if ip_value.is_loopback:
            return "loopback"
        if ip_value.is_multicast:
            return "multicast"
        if ip_value.is_link_local:
            return "link-local"
        return "external"

    @staticmethod
    def _safe_name(value: str) -> str:
        text = str(value or "").strip()
        return text if len(text) <= 42 else f"{text[:39]}..."

    def _human_readable_bytes(self, value: int) -> str:
        units = ("B", "KB", "MB", "GB", "TB")
        current = float(value)
        for unit in units:
            if current < 1024.0 or unit == "TB":
                if unit == "B":
                    return f"{int(current)} {unit}"
                return f"{current:.2f} {unit}"
            current = current / 1024.0
        return f"{current:.2f} PB"

    def _build_network_topology(
        self,
        services: list[InventoryObject],
        flows: list[InventoryObject],
        adapters: list[InventoryObject],
    ) -> dict[str, object]:
        gateway_ips: set[str] = set()
        local_ips: set[str] = set()

        def _infer_subnet(value: str) -> str:
            parsed = self._parse_ipv4(value)
            if not parsed:
                return "unknown"
            try:
                parts = parsed.split(".")
                return ".".join(parts[:3])
            except Exception:
                return "unknown"

        def _infer_node_role(
            address: str,
            node: dict[str, object],
            local_neighbors: int,
            external_neighbors: int,
            subnet_count: int,
        ) -> str:
            label = str(node.get("label", "")).casefold()
            scope = self._ip_scope(address)
            degree = len(set(node.get("neighbors", [])))
            if address in gateway_ips or "gateway" in label or "default gateway" in label:
                return "Gateway"
            if ("router" in label or "rtr" in label) and degree >= 3:
                return "Router (estimated)"
            if scope == "external":
                if degree >= 8:
                    return "Switch (estimated)"
                return "External"
            if degree >= 10 or (degree >= 6 and subnet_count >= 4):
                return "Switch (estimated)"
            if (external_neighbors > 0 and local_neighbors > 0 and degree >= 4) or degree >= 8:
                return "Router (estimated)"
            if local_neighbors >= 4 and subnet_count >= 2 and degree >= 5:
                return "Switch (estimated)"
            if local_neighbors == 0 and external_neighbors > 0:
                return "Endpoint"
            if degree <= 1 and scope == "private":
                return "Endpoint"
            if scope == "private" and address in local_ips:
                return "Server/Endpoint"
            return "Endpoint"

        for adapter in adapters:
            for item in self._split_values(str(adapter.fields.get("Default Gateways", ""))):
                parsed = self._parse_ipv4(item)
                if parsed:
                    gateway_ips.add(parsed)
            for item in self._split_values(str(adapter.fields.get("IP Addresses", ""))):
                parsed = self._parse_ipv4(item)
                if parsed:
                    local_ips.add(parsed)

        service_count: dict[str, int] = defaultdict(int)
        service_name: dict[str, str] = {}
        for service in services:
            host = self._parse_ipv4(service.fields.get("Host IP"))
            if not host:
                continue
            service_count[host] += 1
            host_name = str(service.fields.get("Host Name") or "").strip()
            if host_name:
                service_name[host] = self._safe_name(host_name)

        nodes: dict[str, dict[str, object]] = {}

        def make_node(ip: str) -> dict[str, object]:
            node = nodes.setdefault(
                ip,
                {
                    "id": ip,
                    "ip": ip,
                    "label": service_name.get(ip, ip),
                    "scope": self._ip_scope(ip),
                    "packets": 0,
                    "bytes": 0,
                    "service_count": 0,
                    "neighbors": set(),
                    "ports": set(),
                    "apps": set(),
                    "apps_count": 0,
                },
            )
            return node

        edges_map: dict[tuple[str, str, str], dict[str, object]] = {}
        protocol_summary: defaultdict[str, dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})
        app_summary: dict[str, int] = defaultdict(int)
        total_packets = 0
        total_bytes = 0

        for flow in flows:
            fields = flow.fields
            source = self._parse_ipv4(fields.get("Source"))
            destination = self._parse_ipv4(fields.get("Destination"))
            if not source or not destination:
                continue
            packets = self._to_int(fields.get("Packets"), 0)
            bytes_total = self._to_int(fields.get("Bytes"), 0)
            total_packets += packets
            total_bytes += bytes_total
            source_port = str(fields.get("Source Port") or "")
            destination_port = str(fields.get("Destination Port") or "")
            protocol = str(fields.get("Protocol") or "unknown").strip().upper() or "unknown"
            application = str(fields.get("Local Application") or "").strip()
            traffic_severity = self._traffic_severity_class(fields.get("Traffic Severity"))

            source_node = make_node(source)
            destination_node = make_node(destination)

            source_node["packets"] = self._to_int(source_node.get("packets")) + packets
            source_node["bytes"] = self._to_int(source_node.get("bytes")) + bytes_total
            destination_node["packets"] = self._to_int(destination_node.get("packets")) + packets
            destination_node["bytes"] = self._to_int(destination_node.get("bytes")) + bytes_total
            source_node["neighbors"] = set(source_node["neighbors"]) | {destination}  # type: ignore[arg-type]
            destination_node["neighbors"] = set(destination_node["neighbors"]) | {source}  # type: ignore[arg-type]
            if source_port:
                source_node["ports"] = set(source_node["ports"]) | {source_port}  # type: ignore[arg-type]
            if destination_port:
                destination_node["ports"] = set(destination_node["ports"]) | {destination_port}  # type: ignore[arg-type]
            if application:
                source_node["apps"] = set(source_node["apps"]) | {application}  # type: ignore[arg-type]
                destination_node["apps"] = set(destination_node["apps"]) | {application}  # type: ignore[arg-type]
                source_node["apps_count"] = self._to_int(source_node.get("apps_count")) + 1
                destination_node["apps_count"] = self._to_int(destination_node.get("apps_count")) + 1
                app_summary[application] += bytes_total
            key = (source, destination, protocol)
            edge = edges_map.setdefault(
                key,
                {
                    "source": source,
                    "target": destination,
                    "protocol": protocol,
                    "direction": str(fields.get("Direction") or ""),
                    "severity": traffic_severity,
                    "ports": set(),
                    "packets": 0,
                    "bytes": 0,
                },
            )
            edge["packets"] = self._to_int(edge.get("packets")) + packets
            edge["bytes"] = self._to_int(edge.get("bytes")) + bytes_total
            if self._traffic_severity_rank(traffic_severity) > self._traffic_severity_rank(str(edge.get("severity") or "info")):
                edge["severity"] = traffic_severity
            if source_port and destination_port:
                edge["ports"] = set(edge["ports"]) | {f"{source_port}:{destination_port}"}  # type: ignore[arg-type]
            protocol_summary[protocol]["packets"] += packets
            protocol_summary[protocol]["bytes"] += bytes_total

        for ip, count in service_count.items():
            node = make_node(ip)
            node["service_count"] = count

        for address, node in nodes.items():
            neighbors = set(node.get("neighbors") or set())
            local_neighbors = 0
            external_neighbors = 0
            subnet_hits = set()
            for item in neighbors:
                scope = self._ip_scope(str(item))
                if scope in {"private", "loopback", "link-local"}:
                    local_neighbors += 1
                    subnet_hits.add(_infer_subnet(str(item)))
                elif scope == "external":
                    external_neighbors += 1
            degree = len(neighbors)
            node["role"] = _infer_node_role(
                address,
                node,
                local_neighbors=local_neighbors,
                external_neighbors=external_neighbors,
                subnet_count=len(subnet_hits),
            )
            if address in local_ips and node["role"] == "Endpoint":
                node["role"] = "Server/Endpoint"
            node["neighbor_count"] = degree
            node["local_neighbor_count"] = local_neighbors
            node["external_neighbor_count"] = external_neighbors
            node["scope_subnet"] = _infer_subnet(address)
            node["ports"] = sorted(node["ports"])  # type: ignore[index]
            node["apps"] = sorted(node["apps"])  # type: ignore[index]

        topology_nodes = []
        for node in nodes.values():
            safe_node = dict(node)
            safe_node["neighbors"] = sorted(str(item) for item in safe_node.get("neighbors", []))
            safe_node["ports"] = ", ".join([str(item) for item in safe_node["ports"]])  # type: ignore[index]
            safe_node["apps"] = ", ".join([str(item) for item in safe_node["apps"]])  # type: ignore[index]
            safe_node["role"] = str(safe_node.get("role") or "Endpoint")
            safe_node["ip"] = str(safe_node.get("id"))
            if safe_node.get("label") != safe_node.get("ip"):
                safe_node["label"] = f"{safe_node.get('label', '')} [{safe_node.get('ip')}]"
            topology_nodes.append(safe_node)

        topology_edges = []
        for edge in edges_map.values():
            topology_edges.append({
                "source": str(edge["source"]),
                "target": str(edge["target"]),
                "protocol": str(edge["protocol"]),
                "direction": str(edge["direction"] or ""),
                "severity": str(edge.get("severity") or "info"),
                "packets": int(edge["packets"]),
                "bytes": int(edge["bytes"]),
                "ports": ", ".join(str(item) for item in sorted(edge["ports"])),  # type: ignore[index]
            })

        protocols = [{"name": key, "value": value["packets"], "bytes": value["bytes"]} for key, value in protocol_summary.items()]
        protocols.sort(key=lambda item: (-(item["bytes"] or 0), -(item["value"] or 0)))
        applications = [{"name": key, "bytes": value} for key, value in app_summary.items()]
        applications.sort(key=lambda item: -(item["bytes"] or 0))
        talkers = sorted(
            (
                {
                    "label": f"{item['source']} -> {item['target']} ({item['protocol']})",
                    "packets": item["packets"],
                    "bytes": item["bytes"],
                }
                for item in topology_edges
            ),
            key=lambda item: (-(item["bytes"] or 0), -(item["packets"] or 0)),
        )

        role_summary = defaultdict(int)
        for item in topology_nodes:
            role_summary[str(item.get("role", "Endpoint"))] += 1

        topology_nodes.sort(
            key=lambda item: (-(int(item.get("neighbor_count", 0))), str(item.get("role", "")), str(item.get("ip", "")))
        )
        topology_edges.sort(key=lambda item: (-(item.get("bytes", 0)), -(item.get("packets", 0)), str(item.get("source"))))

        return {
            "summary": {
                "node_count": len(topology_nodes),
                "edge_count": len(topology_edges),
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "roles": dict(sorted(role_summary.items())),
            },
            "nodes": topology_nodes,
            "edges": topology_edges,
            "dashboard": {
                "protocols": protocols[:10],
                "talkers": talkers[:20],
                "applications": applications[:20],
            },
        }

    def _protocol_badge(self, protocol: str) -> str:
        label = str(protocol or "UNKNOWN").strip().upper() or "UNKNOWN"
        return (
            f"<span class='protocol-badge {html.escape(self._protocol_class(label))}'>"
            f"{html.escape(label)}</span>"
        )

    @staticmethod
    def _protocol_class(protocol: str) -> str:
        value = str(protocol or "unknown").strip().casefold()
        if "http" in value:
            return "protocol-http"
        if value in {"tls", "ssl"} or "tls" in value:
            return "protocol-tls"
        if "dns" in value:
            return "protocol-dns"
        if "quic" in value:
            return "protocol-quic"
        if "udp" in value:
            return "protocol-udp"
        if "tcp" in value:
            return "protocol-tcp"
        if "arp" in value:
            return "protocol-arp"
        return "protocol-other"

    @staticmethod
    def _endpoint(fields: dict[str, object], address_key: str, port_key: str) -> str:
        address = str(fields.get(address_key) or "")
        port = str(fields.get(port_key) or "")
        return f"{address}:{port}" if port else address

    @staticmethod
    def _traffic_severity_class(value: object) -> str:
        severity = str(value or "info").strip().casefold()
        return severity if severity in {"critical", "high", "medium", "low", "info"} else "info"

    @staticmethod
    def _traffic_severity_rank(value: str) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value.casefold(), 0)

    @staticmethod
    def _risk_links(object_uid: str, vulnerabilities: list[VulnerabilityMatch]) -> str:
        links = [
            f"<a class='risk-link' href='#{html.escape(HtmlReportBuilder._finding_anchor(object_uid, item.cve), quote=True)}'>{html.escape(item.cve)}</a>"
            for item in vulnerabilities
            if item.object_uid == object_uid
        ]
        return " ".join(links) if links else "<span class='muted'>none</span>"

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
    def _finding_anchor(object_uid: str, rule_id: str) -> str:
        safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in f"{object_uid}-{rule_id}")
        return "finding-" + safe.strip("-")

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
.network-intelligence h3{margin:18px 0 8px}.network-table th{background:#f8fafc}.risk-link{display:inline-block;margin:2px 4px 2px 0;color:#1d4ed8;font-weight:600}.muted{color:#6b7280}
.limit-note{background:#fff7ed;color:#9a3412;padding:8px}table{border-collapse:collapse;width:100%;table-layout:fixed}
td,th{border:1px solid #e5e7eb;padding:8px;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-break:break-word}.item-value td:first-child{width:260px;font-weight:600}
.item-value td:last-child{overflow-wrap:anywhere;word-break:break-word}.filters{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0}.filters button,.filters select{max-width:100%;margin:0 6px 8px 0}footer{color:#6b7280;font-size:12px}
.network-dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px;margin:10px 0}
.network-dashboard-card{border:1px solid #e5e7eb;border-radius:8px;padding:10px;background:#ffffff}
.network-dashboard-card h3{margin-top:0}
.dashboard-mini{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px}
.compact-list{background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:8px}
.compact-list ul{margin:0;padding-left:18px}
.compact-list li{margin-bottom:4px}
.traffic-risk-legend{display:flex;flex-wrap:wrap;gap:8px}
.traffic-badge{display:inline-block;border-radius:999px;padding:3px 8px;font-size:12px;font-weight:800;background:#e2e8f0;color:#334155}
.traffic-badge.info{background:#e2e8f0;color:#334155}.traffic-badge.low{background:#dcfce7;color:#166534}.traffic-badge.medium{background:#fef3c7;color:#92400e}.traffic-badge.high{background:#fee2e2;color:#991b1b}.traffic-badge.critical{background:#7f1d1d;color:#fff}
.network-overview{border:1px solid #dbeafe;border-left:5px solid #2563eb;background:#eff6ff;border-radius:10px;padding:12px;margin:12px 0}.network-overview h3{margin-top:0}.protocol-summary{display:flex;align-items:center;flex-wrap:wrap;gap:6px}.protocol-count{font-size:12px;color:#475569;margin-right:6px}
.protocol-badge{display:inline-block;border-radius:999px;padding:3px 8px;font-size:12px;font-weight:900;letter-spacing:.02em;color:#fff;background:#64748b}.protocol-http{background:#ef4444}.protocol-tls{background:#2563eb}.protocol-dns{background:#8b5cf6}.protocol-quic{background:#06b6d4}.protocol-tcp{background:#16a34a}.protocol-udp{background:#f59e0b}.protocol-arp{background:#64748b}.protocol-other{background:#475569}
.traffic-row.low td{background:#f0fdf4}.traffic-row.medium td{background:#fffbeb}.traffic-row.high td{background:#fef2f2}.traffic-row.critical td{background:#fff1f2;border-color:#fecdd3}
.packet-samples summary{cursor:pointer;color:#1d4ed8;font-weight:700}.packet-samples pre{white-space:pre-wrap;max-height:280px;overflow:auto;background:#0f172a;color:#dbeafe;border-radius:8px;padding:8px;font-size:12px}
.packet-list-collapsed{border:1px solid #cbd5e1;border-radius:10px;margin:14px 0;background:#fff}.packet-list-collapsed>summary{cursor:pointer;display:flex;justify-content:space-between;align-items:center;gap:12px;padding:12px 14px;font-weight:800;background:#f8fafc}.packet-list-collapsed>p,.packet-list-collapsed>table,.packet-list-collapsed>.limit-note{margin-left:12px;margin-right:12px}.packet-list th{position:sticky;top:0;background:#e5e7eb;z-index:1}.packet-list td{font-family:Consolas,monospace;font-size:12px}.packet-row.info td{background:#ffffff}.packet-row.low td{background:#ecfdf5}.packet-row.medium td{background:#fffbeb}.packet-row.high td{background:#fef2f2}.packet-row.critical td{background:#fee2e2}.packet-hex{color:#bfdbfe!important}
.topology-wrapper{position:relative;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden;background:radial-gradient(circle at 30% 20%, #eef2ff, #f8fafc)}
.network-map-panel{border:1px solid #c7d2fe;border-radius:18px;overflow:hidden;background:#ffffff;margin:16px 0;box-shadow:0 18px 42px rgba(37,99,235,.13)}.network-map-panel h3{margin:0;padding:13px 16px;background:linear-gradient(90deg,#eff6ff,#dbeafe 52%,#ccfbf1);color:#0f172a;font-size:15px;letter-spacing:.03em}.network-map-svg{display:block;width:100%;height:auto;background:#eff6ff}.network-map-bg{fill:url(#networkMapBg)}.network-map-grid{stroke:rgba(71,85,105,.16);stroke-width:1}.network-map-edge{stroke:#64748b;stroke-width:1.7;stroke-dasharray:6 7;opacity:.58;filter:url(#linkGlow)}.network-map-edge.high,.network-map-edge.critical{stroke:#dc2626;stroke-width:2.5;opacity:.9}.network-map-edge.protocol-http{stroke:#ef4444}.network-map-edge.protocol-tls{stroke:#2563eb}.network-map-edge.protocol-dns{stroke:#7c3aed}.network-map-edge.protocol-quic{stroke:#0891b2}.network-map-node ellipse{stroke:rgba(255,255,255,.96);stroke-width:1.6;fill:url(#nodeEndpoint);filter:url(#nodeGlow)}.network-map-node text{font-family:Segoe UI,Arial,sans-serif;text-anchor:middle;dominant-baseline:middle;paint-order:stroke;stroke:rgba(15,23,42,.32);stroke-width:2.2px}.network-map-label{font-size:13px;font-weight:900;fill:#ffffff}.network-map-role{font-size:9px;font-weight:800;fill:#ecfeff;letter-spacing:.06em;text-transform:uppercase}.network-map-node.central ellipse{fill:url(#nodeCentral);stroke:#1d4ed8;stroke-width:3.2}.network-map-node.central .network-map-label{font-size:15px}.network-map-node.external ellipse{fill:url(#nodeExternal);stroke:#dc2626}.network-map-node.gateway ellipse{fill:url(#nodeCentral);stroke:#2563eb}.network-map-node.router ellipse,.network-map-node.switch ellipse{fill:url(#nodeAmber);stroke:#d97706}.network-map-node.server ellipse{fill:linear-gradient(90deg,#14b8a6,#0f766e);stroke:#0f766e}.network-node-table{margin:10px;width:calc(100% - 20px);border-radius:10px;overflow:hidden;background:#fff}
#network-topology-canvas{display:block;width:100%;height:430px;min-height:400px}
.topology-status{padding:8px 10px;color:#374151;font-size:12px;background:#fff;border-top:1px solid #e5e7eb}
.topology-legend{display:flex;flex-wrap:wrap;gap:8px;padding-top:8px}
.topology-legend span{padding:4px 8px;border-radius:999px;font-size:12px}
.legend-gateway{background:#dbeafe;color:#1d4ed8}
.legend-router{background:#fde68a;color:#92400e}
.legend-server{background:#dcfce7;color:#166534}
.legend-switch{background:#fef3c7;color:#b45309}
.legend-endpoint{background:#d1fae5;color:#065f46}
.legend-external{background:#fee2e2;color:#991b1b}
@media(max-width:820px){aside{position:static;width:auto}main{margin:0;padding:12px}}
</style>""" + REPORT_THEME_STYLE

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
function projectPoint(point, angles, width, height){
  var x=point.x, y=point.y, z=point.z || 0;
  var cosy=Math.cos(angles.y), siny=Math.sin(angles.y);
  var cosx=Math.cos(angles.x), sinx=Math.sin(angles.x);
  var tx=x*cosy + z*siny;
  var tz=-x*siny + z*cosy;
  var ty=y*cosx - tz*sinx;
  var pz=500/(500+tz);
  return {
    x: width/2 + tx*pz*4,
    y: height/2 + ty*pz*4,
    depth: pz
  };
}
function initNetworkTopology(){
  var dataTag=document.getElementById('network-topology-data');
  if(!dataTag){return;}
  var payload={};
  try{payload=JSON.parse(dataTag.textContent || '{}');}catch(error){}
  var canvas=document.getElementById('network-topology-canvas');
  var status=document.getElementById('network-topology-status');
  if(!canvas || !payload || !payload.nodes || !payload.nodes.length){
    if(status){status.textContent='No topology data available yet. Run network scan with traffic capture enabled.';}
    return;
  }
  var context=canvas.getContext('2d');
  if(!context){return;}
  var width=canvas.clientWidth;
  var height=canvas.clientHeight;
  var dpr=window.devicePixelRatio || 1;
  function refreshCanvas(){
    width=canvas.clientWidth;
    height=canvas.clientHeight;
    canvas.width=Math.max(1,width*dpr);
    canvas.height=Math.max(1,height*dpr);
    context.setTransform(dpr,0,0,dpr,0,0);
  }
  window.addEventListener('resize', refreshCanvas);
  refreshCanvas();
  if(status){status.textContent='Topology loaded: '+payload.nodes.length+' nodes, '+payload.edges.length+' links';}
  var angles={x:0.35, y:0.25};
  var nodeList=payload.nodes.map(function(node, index){
    var angle=(index/payload.nodes.length)*Math.PI*2;
    var ring=Math.floor(index/6)+1;
    return {
      id:node.id,
      x:Math.cos(angle)*90*ring + (Math.random()*10-5),
      y:Math.sin(angle)*55*ring + (Math.random()*10-5),
      z:((index%3)-1)*25 + (Math.random()*10-5),
      label:node.label || node.id,
      role:node.role || 'Endpoint',
      packets:node.packets || 0,
      bytes:node.bytes || 0
    };
  });
  var edgeList=(payload.edges || []);
  function roleColor(role){
    var value=(role || '').toLowerCase();
    if(value.indexOf('gateway')>=0){return '#2563eb';}
    if(value.indexOf('router')>=0){return '#ca8a04';}
    if(value.indexOf('external')>=0){return '#dc2626';}
    if(value.indexOf('server')>=0){return '#10b981';}
    if(value.indexOf('endpoint')>=0){return '#22c55e';}
    if(value.indexOf('switch')>=0){return '#b45309';}
    return '#16a34a';
  }
  function riskColor(severity, alpha){
    var value=(severity || 'info').toLowerCase();
    var colors={critical:'127,29,29', high:'239,68,68', medium:'245,158,11', low:'34,197,94', info:'71,85,105'};
    return 'rgba('+(colors[value] || colors.info)+','+alpha+')';
  }
  function drawDashboardSummary(context2d){
    context2d.fillStyle='#111827';
    context2d.font='10px Segoe UI, Arial, sans-serif';
  }
  function draw(){
    context.clearRect(0,0,width,height);
    context.fillStyle='#f8fafc';
    context.fillRect(0,0,width,height);
    angles.y += 0.002;
    angles.x += 0.001;
    var rendered=[];
    for(var i=0;i<edgeList.length;i++){
      var edge=edgeList[i];
      var from=nodeList.find(function(node){return node.id===edge.source;});
      var to=nodeList.find(function(node){return node.id===edge.target;});
      if(!from || !to){continue;}
      var p1=projectPoint(from, angles, width, height);
      var p2=projectPoint(to, angles, width, height);
      context.strokeStyle=riskColor(edge.severity, 0.25+Math.min(p1.depth,p2.depth)*0.5);
      context.lineWidth=Math.max(1,p1.depth*2);
      context.beginPath();
      context.moveTo(p1.x,p1.y);
      context.lineTo(p2.x,p2.y);
      context.stroke();
      if(p1.depth>0.5 && edge.packets){
        context.fillStyle='rgba(17,24,39,'+(0.2+Math.min(0.6,p1.depth)+0.2)+')';
        context.fillText((edge.protocol || '') + ': ' + edge.bytes + ' B', (p1.x+p2.x)/2+2, (p1.y+p2.y)/2-2);
      }
    }
    for(var j=0;j<nodeList.length;j++){
      var node=nodeList[j];
      var projected=projectPoint(node, angles, width, height);
      var base=Math.max(7, Math.min(22, Math.sqrt(Math.max(1,node.bytes||1))*0.35));
      context.beginPath();
      context.fillStyle='rgba(99,102,241,'+(0.2+projected.depth*0.2)+')';
      context.arc(projected.x, projected.y, base*1.35,0,Math.PI*2);
      context.fill();
      context.beginPath();
      context.fillStyle=roleColor(node.role);
      context.arc(projected.x, projected.y, base,0,Math.PI*2);
      context.fill();
      context.fillStyle='#fff';
      context.font='bold 11px Segoe UI, Arial, sans-serif';
      context.textAlign='center';
      context.textBaseline='middle';
      context.fillText(node.label, projected.x, projected.y+base+12);
      context.fillStyle='#1e293b';
      context.font='9px Segoe UI, Arial, sans-serif';
      context.fillText(node.role, projected.x, projected.y+base+24);
      context.fillStyle='#111827';
      context.font='10px Segoe UI, Arial, sans-serif';
      context.fillText('p '+node.packets+' b '+node.bytes, projected.x, projected.y+base+36);
    }
    drawDashboardSummary(context);
    requestAnimationFrame(draw);
  }
  requestAnimationFrame(draw);
}
document.addEventListener('DOMContentLoaded', function(){
  applyFilters();
  initNetworkTopology();
});
</script>"""


__all__ = ["HtmlReportBuilder", "ReportRecord"]

