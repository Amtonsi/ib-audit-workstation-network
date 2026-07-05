from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from .models import CoverageSummary, InventoryObject, ObjectAssessment, RuleResult, WindowsProfile


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    version: str
    object_types: tuple[str, ...]
    profiles: tuple[str, ...]
    evaluator: str
    field: str
    expected: object
    title: str
    severity: str
    remediation: str
    references: tuple[str, ...]


def load_rule_pack(file_name: str) -> list[RuleDefinition]:
    path = Path(__file__).with_name("rulepacks") / file_name
    data = json.loads(path.read_text(encoding="utf-8"))
    version = str(data["version"])
    definitions = [
        RuleDefinition(
            str(raw["rule_id"]), version, tuple(raw["object_types"]), tuple(raw["profiles"]),
            str(raw["evaluator"]), str(raw["field"]), raw["expected"], str(raw["title"]),
            str(raw["severity"]), str(raw["remediation"]), tuple(map(str, raw.get("references", []))),
        )
        for raw in data["rules"]
    ]
    if len({item.rule_id for item in definitions}) != len(definitions):
        raise ValueError(f"{path.name} contains duplicate rule IDs")
    return definitions


def load_rules_for_profile(role: str) -> list[RuleDefinition]:
    profile_file = "windows_server.json" if role == "server" else "windows_workstation.json"
    rules = [*load_rule_pack("windows_base.json"), *load_rule_pack(profile_file)]
    if len({item.rule_id for item in rules}) != len(rules):
        raise ValueError(f"Duplicate rule ID for profile {role}")
    return rules


def _bool(value: object) -> bool | None:
    text = str(value).strip().casefold()
    if text in {"true", "1", "yes", "on", "enabled", "да", "включено"}:
        return True
    if text in {"false", "0", "no", "off", "disabled", "нет", "отключено"}:
        return False
    return None


def _executable(command: str) -> str:
    expanded = os.path.expandvars(command.strip())
    if expanded.startswith('"'):
        end = expanded.find('"', 1)
        return expanded[1:end] if end > 1 else expanded.strip('"')
    match = re.match(r"(?i)(.*?\.(?:exe|com|bat|cmd|ps1|vbs|js|dll|sys))(?:\s|$)", expanded)
    return match.group(1).strip() if match else expanded.split()[0] if expanded else ""


def _unsafe_path(value: object) -> bool | None:
    path = _executable(str(value))
    if not path:
        return None
    normalized = path.replace("/", "\\").casefold()
    if not PureWindowsPath(path).is_absolute():
        return True
    unsafe = ("\\users\\public\\", "\\appdata\\local\\temp\\", "\\windows\\temp\\", "%temp%", "%tmp%")
    return any(marker in normalized for marker in unsafe)


def _rule_field_value(rule: RuleDefinition, obj: InventoryObject) -> tuple[str, object | None]:
    value = obj.fields.get(rule.field)
    if value not in (None, ""):
        return rule.field, value
    if obj.object_type == "active_setup" and rule.field == "Command":
        return "StubPath", obj.fields.get("StubPath")
    return rule.field, value


def _password_age_days(value: object) -> int | None:
    match = re.search(r"\d+", str(value))
    return int(match.group()) if match else None


def _password_age_thresholds(rule: RuleDefinition) -> tuple[int, int]:
    expected = rule.expected if isinstance(rule.expected, dict) else {}
    warning_days = int(expected.get("warning_days", 60))
    critical_days = int(expected.get("critical_days", 90))
    return warning_days, critical_days


def _industrial_protocol_exposed(obj: InventoryObject, value: object) -> bool:
    port = str(value).strip()
    protocol = str(obj.fields.get("Port Protocol", obj.fields.get("Protocol", "TCP"))).strip().upper()
    address = str(obj.fields.get("Local Address", obj.fields.get("LocalAddress", ""))).strip()
    industrial_tcp_ports = {
        "102",     # Siemens S7 / ISO-TSAP
        "502",     # Modbus TCP
        "1089",    # Foundation Fieldbus HSE
        "1091",    # Foxboro
        "1911",    # Tridium Niagara Fox
        "1962",    # PCWorx
        "20000",   # DNP3
        "2404",    # IEC 60870-5-104
        "44818",   # EtherNet/IP
        "47808",   # BACnet/IP
    }
    industrial_udp_ports = {"47808"}
    if protocol == "UDP":
        industrial = port in industrial_udp_ports
    else:
        industrial = port in industrial_tcp_ports
    if not industrial:
        return False
    return address in {"0.0.0.0", "::", "*", ""}


def _rule_severity(rule: RuleDefinition, value: object, status: str) -> str:
    if rule.evaluator != "password_age_threshold" or status != "risk":
        return rule.severity
    _, critical_days = _password_age_thresholds(rule)
    age_days = _password_age_days(value)
    return "critical" if age_days is not None and age_days > critical_days else "warning"


class RuleEngine:
    def __init__(self, rules: list[RuleDefinition]):
        self.rules = rules

    def evaluate(self, inventory: list[InventoryObject], profile: WindowsProfile) -> list[RuleResult]:
        results: list[RuleResult] = []
        for obj in inventory:
            for rule in self.rules:
                if obj.object_type not in rule.object_types or profile.role not in rule.profiles:
                    continue
                results.append(self._evaluate(rule, obj))
        return results

    def _evaluate(self, rule: RuleDefinition, obj: InventoryObject) -> RuleResult:
        field_name, value = _rule_field_value(rule, obj)
        if value in (None, ""):
            status, actual = "insufficient_data", "missing"
        elif rule.evaluator == "password_age_threshold" and _password_age_days(value) is None:
            status, actual = "insufficient_data", str(value)
        else:
            verdict = self._verdict(rule, obj, value)
            status, actual = ("passed" if verdict else "risk"), str(value)
        severity = _rule_severity(rule, value, status)
        return RuleResult(
            object_uid=obj.uid,
            rule_id=rule.rule_id,
            rule_version=rule.version,
            kind="configuration" if rule.rule_id.startswith("CFG-") else "exposure",
            status=status,
            severity=severity,
            title=rule.title,
            actual=actual,
            expected=str(rule.expected),
            evidence=f"{obj.category_name} / {obj.title} / {field_name}={actual}",
            confidence="high" if status != "insufficient_data" else "low",
            remediation=rule.remediation,
            references=list(rule.references),
        )

    @staticmethod
    def _verdict(rule: RuleDefinition, obj: InventoryObject, value: object) -> bool:
        if rule.evaluator == "equals":
            return str(value).strip().casefold() == str(rule.expected).strip().casefold()
        if rule.evaluator == "bool_true":
            return _bool(value) is True
        if rule.evaluator == "bool_false":
            return _bool(value) is False
        if rule.evaluator == "numeric_min":
            return int(re.search(r"\d+", str(value)).group()) >= int(rule.expected)
        if rule.evaluator == "numeric_range":
            number = int(re.search(r"\d+", str(value)).group())
            return int(rule.expected[0]) <= number <= int(rule.expected[1])
        if rule.evaluator == "safe_executable_path":
            unsafe = _unsafe_path(value)
            return unsafe is False
        if rule.evaluator == "quoted_service_path":
            text = str(value).strip()
            executable = _executable(text)
            return " " not in executable or text.startswith('"')
        if rule.evaluator == "guest_disabled":
            sid = str(obj.fields.get("SID", ""))
            return not sid.endswith("-501") or _bool(value) is True
        if rule.evaluator == "audit_enabled":
            return str(value).strip().casefold() not in {"no auditing", "нет аудита", "none", "disabled"}
        if rule.evaluator == "rdp_nla":
            rdp_disabled = str(obj.fields.get("fDenyTSConnections", "")).strip() == "1"
            return rdp_disabled or str(value).strip() in {"1", "True", "true"}
        if rule.evaluator == "sensitive_port_exposure":
            port = str(value).strip()
            address = str(obj.fields.get("Local Address", obj.fields.get("LocalAddress", ""))).strip()
            return port not in {"135", "139", "445", "3389", "5985", "5986"} or address not in {"0.0.0.0", "::", "*"}
        if rule.evaluator == "safe_path_entries":
            entries = [entry for entry in str(value).split(";") if entry.strip()]
            return bool(entries) and all(_unsafe_path(entry) is False for entry in entries)
        if rule.evaluator == "password_age_threshold":
            age_days = _password_age_days(value)
            warning_days, _ = _password_age_thresholds(rule)
            return age_days is not None and age_days <= warning_days
        if rule.evaluator == "industrial_protocol_exposure":
            return not _industrial_protocol_exposed(obj, value)
        raise ValueError(f"Unknown evaluator: {rule.evaluator}")


def aggregate_assessments(
    inventory: list[InventoryObject],
    results: list[RuleResult],
) -> tuple[list[ObjectAssessment], CoverageSummary]:
    grouped: dict[str, list[RuleResult]] = {obj.uid: [] for obj in inventory}
    for result in results:
        grouped.setdefault(result.object_uid, []).append(result)
    assessments: list[ObjectAssessment] = []
    for obj in inventory:
        statuses = [item.status for item in grouped[obj.uid]]
        if "risk" in statuses:
            status = "risk"
        elif "insufficient_data" in statuses:
            status = "insufficient_data"
        elif "passed" in statuses:
            status = "passed"
        else:
            status = "not_applicable"
        assessments.append(
            ObjectAssessment(
                obj.uid, status, len(statuses), statuses.count("passed"),
                statuses.count("risk"), statuses.count("insufficient_data"),
            )
        )
    coverage = CoverageSummary(
        len(inventory),
        sum(item.status == "risk" for item in assessments),
        sum(item.status == "passed" for item in assessments),
        sum(item.status == "insufficient_data" for item in assessments),
        sum(item.status == "not_applicable" for item in assessments),
    )
    return assessments, coverage
