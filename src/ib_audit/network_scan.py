from __future__ import annotations

import csv
import ipaddress
import re
import shlex
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass

from .commands import command_exists, resolve_tool_command, run_command, run_powershell_json
from .models import CollectorDiagnostic


ProgressCallback = Callable[[str], None] | None


def _emit_progress(progress: ProgressCallback, message: str) -> None:
    if progress is None:
        return
    try:
        progress(message)
    except Exception:
        pass


def _parse_int(value: str | int | None, default: int) -> int:
    try:
        parsed = int(value) if value is not None else default
        return parsed if parsed > 0 else default
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class NetworkScanConfig:
    enabled: bool = False
    targets: tuple[str, ...] = ()
    ports: str = "1-65535"
    extra_args: str = ""
    nmap_timeout: int = 600
    nmap_no_dns: bool = True
    nmap_skip_host_discovery: bool = True
    nmap_timing: str = "T2"
    nmap_open_only: bool = True
    nmap_os_detection: bool = True
    nmap_service_detection: bool = True
    capture_enabled: bool = False
    capture_interface: str | None = None
    capture_duration: int = 20
    capture_timeout: int = 130
    capture_filter: str = ""
    capture_no_name_resolution: bool = True
    capture_quiet: bool = True
    capture_disabled_interfaces: tuple[str, ...] = ()


@dataclass(frozen=True)
class NetworkCommandOption:
    id: str
    group: str
    label: str
    command_preview: str
    description_ru: str
    config_field: str


@dataclass(frozen=True)
class NetworkScanService:
    object_type: str
    title: str
    fields: dict[str, str]


NETWORK_COMMAND_OPTIONS = (
    NetworkCommandOption(
        "nmap_no_dns",
        "nmap",
        "Не выполнять DNS-разрешение",
        "-n",
        "Отключает обратное DNS-разрешение. Сканирование обычно быстрее, в отчёте остаются IP-адреса без попытки получить имена.",
        "nmap_no_dns",
    ),
    NetworkCommandOption(
        "nmap_skip_host_discovery",
        "nmap",
        "Считать цели доступными",
        "-Pn",
        "Пропускает ping/host discovery и проверяет цели как доступные. Полезно, если ICMP блокируется firewall.",
        "nmap_skip_host_discovery",
    ),
    NetworkCommandOption(
        "nmap_open_only",
        "nmap",
        "Показывать только открытые порты",
        "-open",
        "Оставляет в XML только открытые порты, чтобы отчёт не раздувался закрытыми и отфильтрованными портами.",
        "nmap_open_only",
    ),
    NetworkCommandOption(
        "nmap_service_detection",
        "nmap",
        "Определять сервисы и версии",
        "-sV",
        "Пытается определить сервис, продукт и версию. Эти данные используются для поиска уязвимостей.",
        "nmap_service_detection",
    ),
    NetworkCommandOption(
        "nmap_os_detection",
        "nmap",
        "Определять ОС хоста",
        "-O",
        "Пытается определить операционную систему удалённого узла. Может требовать прав администратора и занимать больше времени.",
        "nmap_os_detection",
    ),
    NetworkCommandOption(
        "capture_no_name_resolution",
        "tshark",
        "Не выполнять разрешение имён",
        "-n",
        "Отключает DNS/сервисное разрешение имён при захвате, чтобы не создавать лишний сетевой шум и ускорить обработку.",
        "capture_no_name_resolution",
    ),
    NetworkCommandOption(
        "capture_quiet",
        "tshark",
        "Тихий режим захвата",
        "-q",
        "Убирает интерактивную статистику tshark из вывода. В отчёт попадают только выбранные поля пакетов.",
        "capture_quiet",
    ),
)


TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "_ws.col.Protocol",
    "frame.len",
]


def _normalize_interface_token(value: object) -> str:
    return str(value or "").strip().lower()


def _disabled_interface_tokens(raw_interfaces: tuple[str, ...] | list[str] | set[str] | None) -> set[str]:
    return {_normalize_interface_token(item) for item in (raw_interfaces or ()) if _normalize_interface_token(item)}


def _is_candidate_disabled(candidate: dict[str, str], disabled_tokens: set[str]) -> bool:
    if not disabled_tokens:
        return False
    for value in (
        candidate.get("index", ""),
        candidate.get("name", ""),
        candidate.get("description", ""),
    ):
        if _normalize_interface_token(value) in disabled_tokens:
            return True
    return False


def _diagnostic(message: str, source: str = "nmap / tshark") -> CollectorDiagnostic:
    return CollectorDiagnostic("network_scan", "info", message, source)


def _warning(message: str, source: str = "nmap / tshark") -> CollectorDiagnostic:
    return CollectorDiagnostic("network_scan", "warning", message, source)


def build_nmap_command(
    config: NetworkScanConfig,
    targets: list[str],
    command: str | None = None,
) -> list[str]:
    command_path = command or "nmap"
    command_list = [command_path]
    if config.nmap_no_dns:
        command_list.append("-n")
    if config.nmap_skip_host_discovery:
        command_list.append("-Pn")
    timing = str(config.nmap_timing or "").strip()
    if timing:
        command_list.append(timing if timing.startswith("-") else f"-{timing}")
    if config.nmap_open_only:
        command_list.append("-open")
    command_list.extend(["-oX", "-", "-p", _normalize_ports(config.ports)])
    if config.nmap_service_detection:
        command_list.append("-sV")
    if config.nmap_os_detection:
        command_list.append("-O")
    if config.extra_args:
        try:
            command_list.extend(shlex.split(config.extra_args))
        except ValueError:
            command_list.extend(config.extra_args.split())
    command_list.extend(targets)
    return command_list


def build_tshark_command(
    config: NetworkScanConfig,
    interface: str,
    fields: list[str] | None = None,
    command: str | None = None,
) -> list[str]:
    selected_fields = list(fields or TSHARK_FIELDS)
    command_path = command or "tshark"
    command_list = [command_path, "-i", interface]
    if config.capture_no_name_resolution:
        command_list.append("-n")
    if config.capture_quiet:
        command_list.append("-q")
    command_list.extend(
        [
            "-a",
            f"duration:{max(1, _parse_int(config.capture_duration, 20))}",
            "-T",
            "fields",
            "-E",
            "separator=,",
            "-E",
            "quote=d",
            "-E",
            "header=y",
        ]
    )
    command_list.extend(item for field in selected_fields for item in ("-e", field))
    if config.capture_filter:
        command_list.extend(["-f", config.capture_filter])
    return command_list


def parse_local_network_targets(
    raw_targets: str | tuple[str, ...] | list[str] | None = None,
) -> list[str]:
    explicit: list[str] = []
    if raw_targets:
        if isinstance(raw_targets, (list, tuple)):
            values = [str(item).strip() for item in raw_targets]
        else:
            values = [part.strip() for part in str(raw_targets).replace(";", ",").split(",")]
        for value in values:
            explicit.extend(_expand_local_target(value))
    discovered = list(explicit)
    if not discovered:
        discovered.extend(_local_networks_from_powershell())
    if not discovered:
        discovered.extend(_local_networks_from_ipconfig())
    deduped: list[str] = []
    seen: set[str] = set()
    for value in discovered:
        normalized = value.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


def _expand_local_target(value: str) -> list[str]:
    raw = value.strip()
    if not raw:
        return []
    if "/" in raw:
        return [_normalize_network_range(raw)]
    if raw.lower().startswith("host:"):
        raw = raw[5:].strip()
    if " " in raw:
        return [_normalize_network_range(part) for part in re.split(r"\s+", raw) if part]
    if _is_ipv4(raw):
        return [_normalize_network_range(raw)]
    if _is_hostname(raw):
        return [raw]
    return []


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return "." in value
    except ValueError:
        return False


def _is_hostname(value: str) -> bool:
    return bool(re.match(r"^[a-z0-9_.-]+$", value, re.IGNORECASE))


def _normalize_network_range(value: str) -> str:
    trimmed = value.strip()
    try:
        if "/" in trimmed:
            network = ipaddress.ip_network(trimmed, strict=False)
            if isinstance(network, ipaddress.IPv4Network):
                return str(network)
            return ""
        if _is_ipv4(trimmed):
            return f"{trimmed}/32"
        return trimmed
    except ValueError:
        return ""


def _local_networks_from_powershell() -> list[str]:
    result, _cmd_result = run_powershell_json(
        "Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred -ErrorAction SilentlyContinue | "
        "Where-Object { $_.IPAddress -and $_.PrefixLength -gt 0 -and $_.IPAddress -ne '127.0.0.1' -and -not $_.IPAddress.StartsWith('169.254.') } | "
        "Select-Object IPAddress, PrefixLength | ForEach-Object { @{IPAddress = $_.IPAddress; PrefixLength = $_.PrefixLength} }",
        timeout=20,
    )
    networks: list[str] = []
    for row in result:
        ip_value = str(row.get("IPAddress") or "").strip()
        prefix = row.get("PrefixLength")
        if not ip_value or not prefix:
            continue
        normalized = _normalize_network_range(f"{ip_value}/{_parse_int(prefix, 32)}")
        if normalized:
            networks.append(normalized)
    return networks


def _local_networks_from_ipconfig() -> list[str]:
    result = run_command(["ipconfig", "/all"], timeout=20)
    if not result.ok:
        return []
    text = result.stdout
    ipv4 = re.compile(r"IPv4[^:]*:\s*([0-9.]+)", re.IGNORECASE)
    subnet = re.compile(r"(Subnet|Subnet Mask|Маска подсети)[:\s]+([0-9.]+)", re.IGNORECASE)
    candidate_ips: list[str] = []
    candidate_masks: list[str] = []
    subnet_ru = re.compile(r"(Маска подсети)[:\s]+([0-9.]+)", re.IGNORECASE)
    for line in text.splitlines():
        ip_match = ipv4.search(line)
        if ip_match:
            candidate_ips.append(ip_match.group(1).strip())
            continue
        mask_match = subnet.search(line) or subnet_ru.search(line)
        if mask_match:
            candidate_masks.append(mask_match.group(2).strip())
    networks: list[str] = []
    for index, ip_value in enumerate(candidate_ips):
        mask_value = candidate_masks[index] if index < len(candidate_masks) else "255.255.255.0"
        try:
            ipaddress.ip_address(ip_value)
        except ValueError:
            continue
        if ip_value.startswith("127.") or ip_value.startswith("169.254."):
            continue
        try:
            network = ipaddress.IPv4Network((ip_value, mask_value), strict=False)
        except (ValueError, ipaddress.AddressValueError):
            continue
        if network.prefixlen >= 31:
            continue
        networks.append(f"{network.network_address}/{network.prefixlen}")
    return networks


def collect_network_services(
    config: NetworkScanConfig,
    progress: ProgressCallback = None,
) -> tuple[list[NetworkScanService], list[CollectorDiagnostic]]:
    diagnostics: list[CollectorDiagnostic] = []
    if not config.enabled:
        return [], [_diagnostic("Network scan is disabled")]
    if not config.ports:
        return [], [_warning("Nmap ports are not set")]
    targets = parse_local_network_targets(config.targets)
    if not targets:
        return [], [_warning("No network targets discovered")]
    _emit_progress(progress, f"Nmap scan started on {len(targets)} target(s)")
    nmap_command = resolve_tool_command("nmap")
    if not command_exists(nmap_command):
        return [], [_warning("Nmap executable not found. Place nmap.exe in tools/nmap or install Nmap in PATH.")]
    command = build_nmap_command(config, targets, command=nmap_command)
    _emit_progress(progress, "Running Nmap service discovery")
    result = run_command(command, timeout=max(60, int(config.nmap_timeout)))
    if not result.ok:
        fail_message = result.stderr or result.stdout
        if config.nmap_os_detection and _is_npcap_os_detection_error(fail_message):
            fallback_command = _strip_nmap_arg(command, "-O")
            fallback_result = run_command(fallback_command, timeout=max(60, int(config.nmap_timeout)))
            if fallback_result.ok:
                services = _parse_nmap_xml(fallback_result.stdout)
                diagnostics.append(
                    _warning("Nmap OS detection is unavailable in this environment; retrying without OS detection")
                )
                _emit_progress(progress, "Nmap OS detection skipped (Npcap not available)")
                if services:
                    diagnostics.append(
                        _diagnostic(
                            f"Completed Nmap scan on {len(targets)} target(s) without OS detection, found {len(services)} ports/services",
                            source="nmap",
                        )
                    )
                else:
                    diagnostics.append(_warning("Fallback Nmap scan completed, but no service data was parsed"))
                return services, diagnostics
            diagnostics.append(_warning(f"Fallback Nmap scan failed: {fallback_result.stderr or fallback_result.stdout}"))
            return [], diagnostics
        return [], [_warning(f"Nmap execution failed: {fail_message}")]
    services = _parse_nmap_xml(result.stdout)
    if not services:
        diagnostics.append(_warning("Nmap executed, but no service data was parsed"))
        _emit_progress(progress, "Nmap completed but no services were discovered")
    else:
        _emit_progress(progress, f"Nmap completed: found {len(services)} ports/services")
        diagnostics.append(
            _diagnostic(
                f"Completed Nmap scan on {len(targets)} target(s), found {len(services)} ports/services",
                source="nmap",
            )
        )
    return services, diagnostics


def _normalize_ports(ports: str | None) -> str:
    if not ports:
        return "1-65535"
    clean = re.sub(r"\s+", "", str(ports))
    if not clean:
        return "1-65535"
    return clean[:512]


def _normalize_text(value: object) -> str:
    value = "" if value is None else str(value)
    value = value.replace("\r", " ").replace("\n", " ").strip()
    return re.sub(r"\s+", " ", value)


def _strip_nmap_arg(command: list[str], target_arg: str) -> list[str]:
    return [item for item in command if item != target_arg]


def _is_npcap_os_detection_error(message: str) -> bool:
    lowered = (message or "").casefold()
    return (
        "npcap" in lowered
        and (
            "could not import all necessary npcap functions" in lowered
            or "tcp/ip fingerprinting (for os scan) requires npcap" in lowered
            or "npcap driver service must be started" in lowered
            or "resorting to connect() mode" in lowered
            or "for os scan" in lowered
        )
    )


def _parse_nmap_xml(raw: str) -> list[NetworkScanService]:
    raw = (raw or "").strip()
    if not raw:
        return []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return []
    services: list[NetworkScanService] = []
    for host in root.findall("host"):
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            address = host.find("address[@addrtype='ipv6']")
        if address is None:
            continue
        host_ip = str(address.attrib.get("addr") or "").strip()
        if not host_ip:
            continue
        host_names = [node.attrib.get("name", "") for node in host.findall("hostnames/hostname") if node.attrib.get("name")]
        host_name = ", ".join(item for item in host_names if item)
        host_status_node = host.find("status")
        host_status = host_status_node.attrib.get("state", "") if host_status_node is not None else ""
        os_entry = host.find("os")
        os_names: list[str] = []
        if os_entry is not None:
            for os_match in os_entry.findall("osmatch"):
                name = str(os_match.attrib.get("name") or "").strip()
                if name:
                    os_names.append(name)
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state_node = port.find("state")
            state = state_node.attrib.get("state", "") if state_node is not None else ""
            if state.casefold() != "open":
                continue
            protocol = str(port.attrib.get("protocol") or "").strip().upper()
            port_number = str(port.attrib.get("portid") or "").strip()
            if not port_number:
                continue
            service = port.find("service")
            service_name = str(service.attrib.get("name") or "").strip() if service is not None else ""
            service_product = str(service.attrib.get("product") or "").strip() if service is not None else ""
            service_version = str(service.attrib.get("version") or "").strip() if service is not None else ""
            service_extra = str(service.attrib.get("extrainfo") or "").strip() if service is not None else ""
            service_method = str(service.attrib.get("method") or "").strip() if service is not None else ""
            cpes = [str(item.text or "").strip() for item in (service.findall("cpe") if service is not None else [])]
            cpe = " | ".join(item for item in cpes if item)
            fields = {
                "Host IP": host_ip,
                "Host Name": host_name,
                "Port": port_number,
                "Protocol": protocol,
                "State": state,
                "Service": service_name,
                "Service Product": service_product,
                "Service Version": service_version,
                "Service Discovery Method": service_method,
                "Service Extra": service_extra,
                "Service CPE": cpe,
                "Host OS": ", ".join(os_names),
                "Host State": host_status or "unknown",
            }
            if not fields["Service Product"]:
                fields["Service Product"] = service_name
            fields = {key: value for key, value in fields.items() if value != ""}
            title_parts = [
                host_ip,
                host_name,
                f"{port_number}/{protocol}",
                service_name or "service",
                service_product or service_version,
            ]
            title = " ".join(part for part in title_parts if part)
            services.append(
                NetworkScanService(
                    object_type="network_service",
                    title=title.strip(),
                    fields={key: _normalize_text(value) for key, value in fields.items()},
                )
            )
    return services


def collect_network_capture(
    config: NetworkScanConfig,
    progress: ProgressCallback = None,
) -> tuple[list[NetworkScanService], list[CollectorDiagnostic]]:
    diagnostics: list[CollectorDiagnostic] = []
    if not config.enabled or not config.capture_enabled:
        return [], [_diagnostic("Network traffic capture is disabled")]
    tshark_command = resolve_tool_command("tshark")
    disabled_interfaces = _disabled_interface_tokens(config.capture_disabled_interfaces)
    interface = (config.capture_interface or "").strip()
    if not command_exists(tshark_command):
        return [], [_warning("tshark executable not found. Place tshark.exe in tools/wireshark or tools/tshark and install Wireshark/tshark in PATH.")]
    if interface and _normalize_interface_token(interface) in disabled_interfaces:
        return [], [_warning(f"Capture interface '{interface}' is disabled in settings. Capture skipped.")]
    if not interface:
        candidates, interface_error = _detect_tshark_interfaces(tshark_command=tshark_command)
        if not candidates:
            return [], [_warning(interface_error or "tshark interfaces are not available")]
        for candidate in candidates:
            if not _is_candidate_disabled(candidate, disabled_interfaces):
                interface = candidate["name"]
                break
        if not interface:
            return [], [_warning("All discovered tshark interfaces are disabled in settings.")]
        if disabled_interfaces:
            _emit_progress(
                progress,
                "Selected capture interface avoids disabled interfaces list",
            )
    fields = list(TSHARK_FIELDS)
    _emit_progress(
        progress,
        f"Starting traffic capture on interface '{interface}' for {config.capture_duration} second(s)",
    )
    command = build_tshark_command(config, interface, fields, command=tshark_command)
    result = run_command(command, timeout=max(5, _parse_int(config.capture_timeout, 120)))
    if not result.ok:
        return [], [_warning(f"tshark execution failed: {result.stderr or result.stdout}")]
    flows = _parse_tshark_csv(result.stdout, fields)
    local_addresses = _local_ipv4_addresses()
    process_index = _tcp_connection_process_index()
    if not flows:
        diagnostics.append(_warning("Capture was executed but no packets were parsed"))
        _emit_progress(progress, "Traffic capture completed: no packets captured")
    else:
        _emit_progress(progress, f"Traffic capture completed: {len(flows)} flow row(s)")
        diagnostics.append(
            _diagnostic(
                f"Captured {len(flows)} traffic flow(s) via {interface}",
                source="tshark",
            )
        )
    objects: list[NetworkScanService] = []
    for flow in flows:
        _apply_local_context(flow, local_addresses, interface, process_index)
        source = flow["Source"]
        destination = flow["Destination"]
        protocol = flow["Protocol"]
        source_port = flow["Source Port"]
        destination_port = flow["Destination Port"]
        packets = str(flow["Packets"])
        bytes_total = str(flow["Bytes"])
        objects.append(
            NetworkScanService(
                object_type="network_capture",
                title=f"{source}:{source_port} -> {destination}:{destination_port} ({protocol})",
                fields={
                    "Source": source,
                    "Destination": destination,
                    "Protocol": protocol,
                    "Source Port": source_port,
                    "Destination Port": destination_port,
                    "Direction": str(flow.get("Direction", "")),
                    "Source Scope": str(flow.get("Source Scope", "")),
                    "Destination Scope": str(flow.get("Destination Scope", "")),
                    "Local Endpoint": str(flow.get("Local Endpoint", "")),
                    "Local PID": str(flow.get("Local PID", "")),
                    "Local Application": str(flow.get("Local Application", "")),
                    "Packets": packets,
                    "Bytes": bytes_total,
                    "Last Seen": flow["LastSeen"],
                    "Interface": flow["Interface"],
                },
            )
        )
    return objects, diagnostics


def detect_tshark_interfaces(
    tshark_command: str | None = None,
) -> tuple[list[dict[str, str]], str | None]:
    command = resolve_tool_command("tshark") if tshark_command is None else tshark_command
    if not command_exists(command):
        return [], "tshark executable not found. Place tshark.exe in tools/wireshark or tools/tshark and install Wireshark/tshark in PATH."
    return _detect_tshark_interfaces(tshark_command=command)


def _detect_tshark_interfaces(tshark_command: str = "tshark") -> tuple[list[dict[str, str]], str | None]:
    result = run_command([tshark_command, "-D"], timeout=10)
    if not result.ok:
        message = (result.stderr or result.stdout or "tshark interface discovery failed").strip()
        return [], f"tshark -D failed: {message}"
    interfaces: list[dict[str, str]] = []
    for raw_line in result.stdout.splitlines():
        line = (raw_line or "").strip()
        if not line:
            continue
        parts = line.split(" ", 2)
        if len(parts) < 2:
            continue
        index = parts[0].rstrip(".")
        if not index or not index[0].isdigit():
            continue
        description = parts[2] if len(parts) > 2 else line
        if description:
            interfaces.append({"index": index, "name": index, "description": description})
    if not interfaces:
        return [], "tshark interfaces are not available"
    return interfaces, None


def _parse_tshark_csv(raw: str, fields: list[str] | None = None) -> list[dict[str, str]]:
    del fields
    text = (raw or "").strip()
    if not text:
        return []
    try:
        reader = csv.DictReader(text.splitlines())
    except Exception:
        return []
    if reader.fieldnames is None:
        return []
    flows: dict[tuple[str, str, str, str, str, str], dict[str, int | str]] = {}
    for row in reader:
        source = str(row.get("ip.src") or "").strip()
        destination = str(row.get("ip.dst") or "").strip()
        if not source or not destination:
            continue
        protocol = str(row.get("_ws.col.Protocol") or "").strip().upper()
        if not protocol:
            continue
        source_port = str(row.get("tcp.srcport") or row.get("udp.srcport") or "").strip()
        destination_port = str(row.get("tcp.dstport") or row.get("udp.dstport") or "").strip()
        frame_len = _parse_int(row.get("frame.len"), 0)
        seen_at = str(row.get("frame.time_epoch") or "").strip()
        interface = row.get("interface", "")
        direction, source_scope, destination_scope = _classify_flow(source, destination)
        key = (source, destination, protocol, source_port, destination_port, str(interface))
        bucket = flows.setdefault(
            key,
            {
                "Source": source,
                "Destination": destination,
                "Protocol": protocol,
                "Source Port": source_port,
                "Destination Port": destination_port,
                "Direction": direction,
                "Source Scope": source_scope,
                "Destination Scope": destination_scope,
                "Packets": 0,
                "Bytes": 0,
                "LastSeen": seen_at,
                "Interface": str(interface),
            },
        )
        bucket["Packets"] = int(bucket["Packets"]) + 1  # type: ignore[index]
        bucket["Bytes"] = int(bucket["Bytes"]) + frame_len  # type: ignore[index]
        if seen_at:
            bucket["LastSeen"] = seen_at
    normalized: list[dict[str, str]] = []
    for item in flows.values():
        normalized.append({
            "Source": str(item["Source"]),
            "Destination": str(item["Destination"]),
            "Protocol": str(item["Protocol"]),
            "Source Port": str(item["Source Port"]),
            "Destination Port": str(item["Destination Port"]),
            "Direction": str(item["Direction"]),
            "Source Scope": str(item["Source Scope"]),
            "Destination Scope": str(item["Destination Scope"]),
            "Packets": int(item["Packets"]),
            "Bytes": int(item["Bytes"]),
            "LastSeen": str(item["LastSeen"]),
            "Interface": str(item["Interface"]),
        })
    normalized.sort(key=lambda item: (-(item["Packets"] or 0), -(item["Bytes"] or 0)))
    return normalized


def _ip_scope(value: str) -> str:
    try:
        ip_value = ipaddress.ip_address(value)
    except ValueError:
        return "unknown"
    if ip_value.is_loopback:
        return "loopback"
    if ip_value.is_link_local:
        return "link-local"
    if ip_value.is_private:
        return "private"
    if ip_value.is_multicast:
        return "multicast"
    return "external"


def _classify_flow(
    source: str,
    destination: str,
    local_addresses: set[str] | tuple[str, ...] | list[str] | None = None,
) -> tuple[str, str, str]:
    local_set = {str(item) for item in (local_addresses or []) if item}
    source_scope = _ip_scope(source)
    destination_scope = _ip_scope(destination)
    if local_set:
        source_is_local = source in local_set
        destination_is_local = destination in local_set
        if source_is_local and destination_is_local:
            return "local", source_scope, destination_scope
        if source_is_local:
            return "outbound", source_scope, destination_scope
        if destination_is_local:
            return "inbound", source_scope, destination_scope
    if source_scope == "private" and destination_scope == "external":
        return "outbound", source_scope, destination_scope
    if source_scope == "external" and destination_scope == "private":
        return "inbound", source_scope, destination_scope
    if source_scope == "private" and destination_scope == "private":
        return "internal", source_scope, destination_scope
    return "external", source_scope, destination_scope


def _local_ipv4_addresses() -> set[str]:
    rows, _cmd_result = run_powershell_json(
        "Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred -ErrorAction SilentlyContinue | "
        "Where-Object { $_.IPAddress -and $_.IPAddress -ne '127.0.0.1' -and -not $_.IPAddress.StartsWith('169.254.') } | "
        "Select-Object IPAddress",
        timeout=20,
    )
    values = {str(row.get("IPAddress") or "").strip() for row in rows}
    return {value for value in values if value}


def _tcp_connection_process_index() -> dict[tuple[str, str, str, str], dict[str, str]]:
    rows, _cmd_result = run_powershell_json(
        "$processes = @{}; "
        "Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $processes[[string]$_.Id] = $_.ProcessName }; "
        "Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object { "
        "[pscustomobject]@{"
        "LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort; RemoteAddress=$_.RemoteAddress; "
        "RemotePort=$_.RemotePort; State=$_.State; OwningProcess=$_.OwningProcess; "
        "ProcessName=$processes[[string]$_.OwningProcess]"
        "} }",
        timeout=30,
    )
    index: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for row in rows:
        local_address = str(row.get("LocalAddress") or "").strip()
        local_port = str(row.get("LocalPort") or "").strip()
        remote_address = str(row.get("RemoteAddress") or "").strip()
        remote_port = str(row.get("RemotePort") or "").strip()
        if not local_port:
            continue
        data = {
            "Local PID": str(row.get("OwningProcess") or "").strip(),
            "Local Application": str(row.get("ProcessName") or "").strip(),
            "Connection State": str(row.get("State") or "").strip(),
        }
        index[(local_address, local_port, remote_address, remote_port)] = data
        index[(local_address, local_port, "", "")] = data
        index[("", local_port, "", remote_port)] = data
    return index


def _apply_local_context(
    flow: dict[str, str],
    local_addresses: set[str],
    interface: str,
    process_index: dict[tuple[str, str, str, str], dict[str, str]],
) -> None:
    source = str(flow.get("Source") or "")
    destination = str(flow.get("Destination") or "")
    source_port = str(flow.get("Source Port") or "")
    destination_port = str(flow.get("Destination Port") or "")
    direction, source_scope, destination_scope = _classify_flow(source, destination, local_addresses)
    flow["Direction"] = direction
    flow["Source Scope"] = source_scope
    flow["Destination Scope"] = destination_scope
    flow["Interface"] = interface
    if source in local_addresses:
        local_address, local_port, remote_address, remote_port = source, source_port, destination, destination_port
    elif destination in local_addresses:
        local_address, local_port, remote_address, remote_port = destination, destination_port, source, source_port
    else:
        local_address, local_port, remote_address, remote_port = "", source_port, "", destination_port
    if local_address or local_port:
        flow["Local Endpoint"] = f"{local_address}:{local_port}" if local_address else local_port
    process = (
        process_index.get((local_address, local_port, remote_address, remote_port))
        or process_index.get((local_address, local_port, "", ""))
        or process_index.get(("", local_port, "", remote_port))
        or {}
    )
    if process:
        flow["Local PID"] = process.get("Local PID", "")
        flow["Local Application"] = process.get("Local Application", "")


def collect_network_intelligence(
    config: NetworkScanConfig,
    progress: ProgressCallback = None,
) -> tuple[list[NetworkScanService], list[NetworkScanService], list[CollectorDiagnostic]]:
    if not config.enabled:
        return [], [], [_diagnostic("Network scan is disabled")]
    _emit_progress(progress, "Network intelligence scan started")
    services, diagnostics_services = collect_network_services(config, progress=progress)
    captures, diagnostics_capture = collect_network_capture(config, progress=progress)
    _emit_progress(progress, f"Network intelligence completed: {len(services)} services, {len(captures)} captured flows")
    return services, captures, [*diagnostics_services, *diagnostics_capture]


__all__ = [
    "NETWORK_COMMAND_OPTIONS",
    "NetworkScanConfig",
    "NetworkCommandOption",
    "NetworkScanService",
    "build_nmap_command",
    "build_tshark_command",
    "collect_network_intelligence",
    "collect_network_capture",
    "collect_network_services",
    "detect_tshark_interfaces",
    "parse_local_network_targets",
    "_parse_nmap_xml",
    "_parse_tshark_csv",
]
