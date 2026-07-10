from __future__ import annotations

import csv
import ipaddress
import json
import re
import shlex
import socket
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass

from .commands import (
    command_exists,
    hidden_subprocess_kwargs,
    register_network_tool_process,
    resolve_tool_command,
    run_command,
    run_powershell_json,
    unregister_network_tool_process,
)
from .models import CollectorDiagnostic
from .npcap import NPCAP_DOWNLOAD_URL, query_npcap_status


ProgressCallback = Callable[[str], None] | None
DEFAULT_LOCAL_NMAP_TARGETS = ("127.0.0.1",)
DEFAULT_LOCAL_NMAP_PORTS = "22,80,135,139,443,445,3389,5985,5986,8080,8443"


def local_machine_nmap_targets() -> tuple[str, ...]:
    """Return IPv4 addresses belonging to this machine, never a subnet."""
    targets = list(DEFAULT_LOCAL_NMAP_TARGETS)
    try:
        addresses = socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET)
    except OSError:
        addresses = []
    for address in addresses:
        value = str(address[4][0]).strip()
        if value and value not in targets and value != "0.0.0.0":
            targets.append(value)
    return tuple(targets)


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
    nmap_enabled: bool = True
    targets: tuple[str, ...] = DEFAULT_LOCAL_NMAP_TARGETS
    ports: str = DEFAULT_LOCAL_NMAP_PORTS
    extra_args: str = ""
    nmap_timeout: int = 120
    nmap_no_dns: bool = True
    nmap_skip_host_discovery: bool = True
    nmap_timing: str = "T3"
    nmap_open_only: bool = True
    nmap_os_detection: bool = False
    nmap_service_detection: bool = True
    capture_enabled: bool = False
    capture_interface: str | None = None
    capture_duration: int = 20
    capture_timeout: int = 130
    capture_filter: str = ""
    capture_no_name_resolution: bool = True
    capture_quiet: bool = True
    capture_interfaces: tuple[str, ...] = ()
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
    "frame.number",
    "frame.time_epoch",
    "frame.time_relative",
    "frame.protocols",
    "_ws.col.Info",
    "_ws.expert.severity",
    "_ws.expert.message",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.ttl",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.lost_segment",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.out_of_order",
    "tcp.analysis.zero_window",
    "tcp.analysis.window_full",
    "udp.srcport",
    "udp.dstport",
    "icmp.type",
    "arp.opcode",
    "_ws.col.Protocol",
    "dns.qry.name",
    "http.host",
    "http.request.method",
    "http.request.uri",
    "tls.handshake.extensions_server_name",
    "frame.len",
    "frame.cap_len",
    "data.data",
]


TRAFFIC_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
TRAFFIC_SEVERITY_COLORS = {
    "info": "#64748b",
    "low": "#22c55e",
    "medium": "#f59e0b",
    "high": "#ef4444",
    "critical": "#7f1d1d",
}


def _normalize_interface_token(value: object) -> str:
    return str(value or "").strip().lower()

def _normalize_capture_interfaces(raw: tuple[str, ...] | list[str] | str | None) -> tuple[str, ...]:
    values = raw or ()
    if isinstance(values, str):
        values = values.replace(";", ",").split(",")
    tokens: list[str] = []
    seen_tokens: set[str] = set()
    for item in values:
        token = str(item or "").strip()
        normalized = _normalize_interface_token(token)
        if normalized and normalized not in seen_tokens:
            tokens.append(token)
            seen_tokens.add(normalized)
    return tuple(tokens)


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
    command_list.append("-sT")
    if config.nmap_open_only:
        command_list.append("-open")
    command_list.extend(["-oX", "-", "-p", _normalize_ports(config.ports)])
    if config.nmap_service_detection:
        command_list.append("-sV")
    if config.extra_args:
        try:
            extra_args = shlex.split(config.extra_args)
        except ValueError:
            extra_args = config.extra_args.split()
        command_list.extend(_safe_nmap_extra_args(extra_args))
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
    command_list = [command_path, "-l", "-i", interface]
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
    if not config.nmap_enabled:
        return [], [_diagnostic("Nmap service discovery is disabled")]
    if not config.ports:
        return [], [_warning("Nmap ports are not set")]
    targets = parse_local_network_targets(config.targets) if config.targets else list(local_machine_nmap_targets())
    if not targets:
        return [], [_warning("No network targets discovered")]
    if config.nmap_os_detection:
        diagnostics.append(
            _warning(
                "Nmap OS detection is disabled in safe mode because it can use Npcap raw packets and trigger driver-level crashes",
                source="nmap",
            )
        )
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
                    discovered_hosts = sorted({str(s.fields.get("Host IP") or "") for s in services})
                    if discovered_hosts:
                        _emit_progress(
                            progress,
                            "Network hosts discovered: " + ", ".join(discovered_hosts[:20]),
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
        discovered_hosts = sorted({str(service.fields.get("Host IP") or "") for service in services})
        if discovered_hosts:
            _emit_progress(
                progress,
                "Network hosts discovered: " + ", ".join(discovered_hosts[:20]),
            )
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


def _safe_nmap_extra_args(args: list[str]) -> list[str]:
    raw_packet_args = {
        "-O",
        "-A",
        "-sS",
        "-sU",
        "-sY",
        "-sZ",
        "-sO",
        "--osscan-guess",
        "--osscan-limit",
        "--privileged",
    }
    return [item for item in args if item not in raw_packet_args]


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
    if not config.enabled or not config.capture_enabled:
        return [], [_diagnostic("Network traffic capture is disabled")]

    disabled_interfaces = _disabled_interface_tokens(config.capture_disabled_interfaces)
    selected_interfaces: list[str] = []
    selected_set: set[str] = set()

    def _append_interface(value: str) -> None:
        token = _normalize_interface_token(value)
        if not token or token in selected_set or token in disabled_interfaces:
            return
        selected_set.add(token)
        selected_interfaces.append(value)

    for item in _normalize_capture_interfaces(config.capture_interfaces):
        _append_interface(item)
    configured_interface = _normalize_capture_interfaces(config.capture_interface)
    for item in configured_interface:
        _append_interface(item)
    if not selected_interfaces:
        return [], [
            _warning(
                "Select at least one capture interface before starting traffic capture. "
                "Automatic all-interface capture and Npcap live packet capture are disabled for stability."
            )
        ]

    all_flows, diagnostics = _collect_tshark_live_traffic(config, selected_interfaces, progress=progress)
    if not all_flows:
        _emit_progress(
            progress,
            "CAPTURE_PROGRESS|info|tshark live packet capture did not return packet rows; switching to safe Windows telemetry",
        )
        safe_flows, safe_diagnostics = _collect_safe_network_traffic(config, selected_interfaces, progress=progress)
        all_flows = safe_flows
        diagnostics = diagnostics + safe_diagnostics
    objects: list[NetworkScanService] = []
    for flow in all_flows:
        source = flow["Source"]
        destination = flow["Destination"]
        protocol = flow["Protocol"]
        source_port = flow["Source Port"]
        destination_port = flow["Destination Port"]
        packets = str(flow["Packets"])
        bytes_total = str(flow["Bytes"])
        title = f"{source}:{source_port} -> {destination}:{destination_port} ({protocol})"
        if protocol == "INTERFACE":
            title = f"{source} -> {destination} ({protocol})"
        objects.append(
            NetworkScanService(
                object_type="network_capture",
                title=title,
                fields={
                    "Source": source,
                    "Destination": destination,
                    "Protocol": protocol,
                    "Source Port": source_port,
                    "Destination Port": destination_port,
                    "Frame Protocols": str(flow.get("Frame Protocols", "")),
                    "Packet Info": str(flow.get("Packet Info", "")),
                    "Protocol Details": str(flow.get("Protocol Details", "")),
                    "Ethernet Source": str(flow.get("Ethernet Source", "")),
                    "Ethernet Destination": str(flow.get("Ethernet Destination", "")),
                    "IP TTL": str(flow.get("IP TTL", "")),
                    "TCP Flags": str(flow.get("TCP Flags", "")),
                    "TCP Retransmission": str(flow.get("TCP Retransmission", "")),
                    "TCP Lost Segment": str(flow.get("TCP Lost Segment", "")),
                    "ICMP Type": str(flow.get("ICMP Type", "")),
                    "ARP Opcode": str(flow.get("ARP Opcode", "")),
                    "DNS Query": str(flow.get("DNS Query", "")),
                    "HTTP Host": str(flow.get("HTTP Host", "")),
                    "HTTP Method": str(flow.get("HTTP Method", "")),
                    "HTTP URI": str(flow.get("HTTP URI", "")),
                    "TLS SNI": str(flow.get("TLS SNI", "")),
                    "Direction": str(flow.get("Direction", "")),
                    "Source Scope": str(flow.get("Source Scope", "")),
                    "Destination Scope": str(flow.get("Destination Scope", "")),
                    "Traffic Severity": str(flow.get("Traffic Severity", "")),
                    "Traffic Color": str(flow.get("Traffic Color", "")),
                    "Traffic Findings": str(flow.get("Traffic Findings", "")),
                    "Packet Samples": str(flow.get("Packet Samples", "")),
                    "Packet Sample Count": str(flow.get("Packet Sample Count", "")),
                    "Packet Rows JSON": str(flow.get("Packet Rows JSON", "")),
                    "Packet Row Count": str(flow.get("Packet Row Count", "")),
                    "Expert Severity": str(flow.get("Expert Severity", "")),
                    "Expert Message": str(flow.get("Expert Message", "")),
                    "Connection State": str(flow.get("Connection State", "")),
                    "Capture Mode": str(flow.get("Capture Mode", "")),
                    "Traffic Evidence Type": str(flow.get("Traffic Evidence Type", "")),
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


def _collect_tshark_live_traffic(
    config: NetworkScanConfig,
    selected_interfaces: list[str],
    progress: ProgressCallback = None,
) -> tuple[list[dict[str, str]], list[CollectorDiagnostic]]:
    command = resolve_tool_command("tshark")
    if not command_exists(command):
        return [], [_warning("tshark executable not found; falling back to safe Windows telemetry", source="tshark")]

    diagnostics: list[CollectorDiagnostic] = []
    all_flows: list[dict[str, str]] = []
    for interface in selected_interfaces:
        _emit_progress(
            progress,
            "CAPTURE_ACTIVE|info|"
            "\u0417\u0430\u0445\u0432\u0430\u0442 \u043f\u0430\u043a\u0435\u0442\u043e\u0432 tshark \u0432\u044b\u043f\u043e\u043b\u043d\u044f\u0435\u0442\u0441\u044f: "
            f"\u0438\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u044b={interface}; "
            f"\u0434\u043b\u0438\u0442\u0435\u043b\u044c\u043d\u043e\u0441\u0442\u044c={max(1, _parse_int(config.capture_duration, 20))} \u0441\u0435\u043a; "
            "\u0440\u0435\u0436\u0438\u043c=tshark live packet capture",
        )
        tshark_command = build_tshark_command(config, interface, command=command)
        _emit_progress(progress, "CAPTURE_PROGRESS|info|tshark command: " + " ".join(tshark_command[:12]))
        try:
            process = subprocess.Popen(
                tshark_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                **hidden_subprocess_kwargs(),
            )
            register_network_tool_process(process, tshark_command)
        except Exception as exc:
            diagnostics.append(_warning(f"tshark live packet capture failed to start on {interface}: {exc}", source="tshark"))
            continue

        header: list[str] | None = None
        csv_lines: list[str] = []
        packet_rows = 0
        emitted_rows = 0
        try:
            assert process.stdout is not None
            for raw_line in process.stdout:
                line = raw_line.rstrip("\r\n")
                if not line:
                    continue
                if header is None:
                    try:
                        parsed_header = next(csv.reader([line]))
                    except Exception:
                        continue
                    header = [str(item) for item in parsed_header]
                    csv_lines.append(line)
                    continue
                row = _tshark_csv_row(header, line)
                if not row:
                    continue
                row["interface"] = interface
                csv_lines.append(line)
                packet_rows += 1
                sample_event = _packet_progress_event(row)
                if sample_event and emitted_rows < 2000:
                    _emit_progress(progress, sample_event)
                    emitted_rows += 1
        finally:
            stderr_text = ""
            try:
                if process.stderr is not None:
                    stderr_text = process.stderr.read() or ""
            except Exception:
                stderr_text = ""
            try:
                returncode = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                returncode = 124
            try:
                if process.stdout is not None:
                    process.stdout.close()
            except Exception:
                pass
            try:
                if process.stderr is not None:
                    process.stderr.close()
            except Exception:
                pass
            unregister_network_tool_process(process)

        if header and csv_lines:
            interface_flows = _parse_tshark_csv("\n".join(csv_lines))
            for flow in interface_flows:
                flow["Interface"] = interface
                flow["Capture Mode"] = "tshark-live-capture"
                flow["Traffic Evidence Type"] = "Live tshark packet capture"
            all_flows.extend(interface_flows)
        if returncode != 0:
            diagnostics.append(
                _warning(
                    f"tshark live packet capture exited with code {returncode} on {interface}: {stderr_text.strip()[:500]}",
                    source="tshark",
                )
            )
        elif packet_rows:
            diagnostics.append(
                _diagnostic(
                    f"Captured {packet_rows} packet row(s) on {interface} using tshark live packet capture",
                    source="tshark",
                )
            )
        else:
            diagnostics.append(
                _warning(
                    f"tshark live packet capture completed on {interface}, but no packet rows were returned",
                    source="tshark",
                )
            )
    return all_flows, diagnostics


def _tshark_csv_row(header: list[str], line: str) -> dict[str, str]:
    try:
        values = next(csv.reader([line]))
    except Exception:
        return {}
    row: dict[str, str] = {}
    for index, field in enumerate(header):
        row[field] = values[index] if index < len(values) else ""
    return row


def _packet_progress_event(row: dict[str, str]) -> str:
    source = _packet_source_address(row)
    destination = _packet_destination_address(row)
    protocol = _application_protocol(row) or "UNKNOWN"
    source_port = str(row.get("tcp.srcport") or row.get("udp.srcport") or "").strip()
    destination_port = str(row.get("tcp.dstport") or row.get("udp.dstport") or "").strip()
    if not source and not destination:
        return ""
    direction, source_scope, destination_scope = _classify_flow(source, destination)
    _findings, score = _traffic_findings_for_packet(
        row,
        protocol,
        source_scope,
        destination_scope,
        source_port,
        destination_port,
    )
    severity = _traffic_severity_from_score(score)
    packet_row = _packet_row_payload(
        row,
        protocol,
        source or "-",
        destination or "-",
        source_port,
        destination_port,
        severity,
    )
    if not packet_row:
        return ""
    return "PACKET_ROW|{}|{}".format(
        severity,
        json.dumps(packet_row, ensure_ascii=False, separators=(",", ":")),
    )


def _collect_safe_network_traffic(
    config: NetworkScanConfig,
    selected_interfaces: list[str],
    progress: ProgressCallback = None,
) -> tuple[list[dict[str, str]], list[CollectorDiagnostic]]:
    del config
    interface_label = ", ".join(selected_interfaces) or "selected interfaces"
    _emit_progress(
        progress,
        "CAPTURE_ACTIVE|info|"
        "\u0417\u0430\u0445\u0432\u0430\u0442 \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u0432\u044b\u043f\u043e\u043b\u043d\u044f\u0435\u0442\u0441\u044f: "
        f"\u0438\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u044b={interface_label}; "
        "\u0440\u0435\u0436\u0438\u043c=safe Windows TCP/RX-TX telemetry",
    )
    _emit_progress(
        progress,
        "Safe traffic telemetry started: using Windows TCP connection tables; Npcap/tshark live capture is disabled",
    )
    rows, result = run_powershell_json(
        "$processes=@{}; "
        "Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $processes[[string]$_.Id]=$_.ProcessName }; "
        "Get-NetTCPConnection -ErrorAction SilentlyContinue | "
        "Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notin @('0.0.0.0','::','') -and $_.State -ne 'Listen' } | "
        "ForEach-Object { @{"
        "Protocol='TCP'; LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort; "
        "RemoteAddress=$_.RemoteAddress; RemotePort=$_.RemotePort; State=[string]$_.State; "
        "OwningProcess=$_.OwningProcess; ProcessName=$processes[[string]$_.OwningProcess]"
        "} }",
        timeout=20,
    )
    if not result.ok:
        return [], [_warning(f"Safe Windows traffic telemetry failed: {result.stderr or result.stdout}", source="PowerShell Get-NetTCPConnection")]
    counter_flows, counter_diagnostics = _collect_selected_interface_counter_traffic(selected_interfaces)
    if not rows:
        if counter_flows:
            _emit_progress(
                progress,
                f"Safe traffic telemetry completed: {len(counter_flows)} selected interface counter row(s), no active TCP connections found",
            )
            return counter_flows, counter_diagnostics + [
                _diagnostic(
                    "Safe Windows traffic telemetry completed with selected adapter counters; no active TCP connections were found",
                    source="PowerShell Get-NetTCPConnection",
                )
            ]
        _emit_progress(progress, "Safe traffic telemetry completed: no active TCP connections found")
        return [], [_diagnostic("Safe Windows traffic telemetry completed, but no active TCP connections were found", source="PowerShell Get-NetTCPConnection")]

    local_addresses = _local_ipv4_addresses()
    flows: list[dict[str, str]] = []
    for row in rows[:500]:
        protocol = str(row.get("Protocol") or "TCP").strip().upper()
        local_address = str(row.get("LocalAddress") or "").strip()
        local_port = str(row.get("LocalPort") or "").strip()
        remote_address = str(row.get("RemoteAddress") or "").strip()
        remote_port = str(row.get("RemotePort") or "").strip()
        if not local_address or not remote_address:
            continue
        source = local_address
        destination = remote_address
        source_port = local_port
        destination_port = remote_port
        direction, source_scope, destination_scope = _classify_flow(source, destination, local_addresses)
        findings, score = _traffic_findings_for_packet(
            {},
            protocol,
            source_scope,
            destination_scope,
            source_port,
            destination_port,
        )
        state = str(row.get("State") or "").strip()
        if state.casefold() in {"synsent", "synreceived"}:
            findings.append(f"TCP connection is not fully established ({state})")
            score = max(score, 2)
        severity = _traffic_severity_from_score(score)
        process_name = str(row.get("ProcessName") or "").strip()
        process_id = str(row.get("OwningProcess") or "").strip()
        sample = _normalize_text(
            f"#connection TCP {source}:{source_port} -> {destination}:{destination_port} "
            f"state={state or 'unknown'} app={process_name or 'unknown'} pid={process_id or 'unknown'} "
            "source=Get-NetTCPConnection safe-mode"
        )
        flows.append(
            {
                "Source": source,
                "Destination": destination,
                "Protocol": protocol,
                "Source Port": source_port,
                "Destination Port": destination_port,
                "Frame Protocols": "windows:tcp-connection-table",
                "Packet Info": sample,
                "Protocol Details": sample,
                "Ethernet Source": "",
                "Ethernet Destination": "",
                "IP TTL": "",
                "TCP Flags": "",
                "TCP Retransmission": "",
                "TCP Lost Segment": "",
                "ICMP Type": "",
                "ARP Opcode": "",
                "DNS Query": "",
                "HTTP Host": "",
                "HTTP Method": "",
                "HTTP URI": "",
                "TLS SNI": "",
                "Direction": direction,
                "Source Scope": source_scope,
                "Destination Scope": destination_scope,
                "Traffic Severity": severity,
                "Traffic Color": TRAFFIC_SEVERITY_COLORS[severity],
                "Traffic Findings": "; ".join(sorted(set(findings))) if findings else "Safe connection metadata observed",
                "Packet Samples": sample,
                "Packet Sample Count": 1,
                "Expert Severity": "",
                "Expert Message": "",
                "Local Endpoint": f"{local_address}:{local_port}",
                "Local PID": process_id,
                "Local Application": process_name,
                "Connection State": state,
                "Capture Mode": "safe-windows-telemetry",
                "Traffic Evidence Type": "Windows TCP connection snapshot",
                "Packets": 0,
                "Bytes": 0,
                "LastSeen": "",
                "Interface": interface_label,
            }
        )
    flows.sort(key=lambda item: (-TRAFFIC_SEVERITY_ORDER.get(item["Traffic Severity"], 0), item["Destination"], item["Destination Port"]))
    if counter_flows:
        flows.extend(counter_flows)
        flows.sort(key=lambda item: (-TRAFFIC_SEVERITY_ORDER.get(item["Traffic Severity"], 0), item["Destination"], item["Destination Port"]))
    _emit_progress(progress, f"Safe traffic telemetry completed: {len(flows)} traffic evidence row(s)")
    return flows, [
        _diagnostic(
            f"Collected {len(flows)} traffic evidence row(s) using safe Windows telemetry; Npcap/tshark live capture was not used",
            source="PowerShell Get-NetTCPConnection",
        )
    ] + counter_diagnostics


def _collect_selected_interface_counter_traffic(
    selected_interfaces: list[str],
) -> tuple[list[dict[str, str]], list[CollectorDiagnostic]]:
    selected_tokens = {_normalize_interface_token(item) for item in selected_interfaces}
    selected_tokens.discard("")
    if not selected_tokens:
        return [], []

    rows, result = run_powershell_json(
        "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | ForEach-Object { "
        "$adapter=$_; $stats=Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction SilentlyContinue; "
        "@{Name=$adapter.Name; InterfaceDescription=$adapter.InterfaceDescription; ifIndex=$adapter.ifIndex; "
        "Status=[string]$adapter.Status; LinkSpeed=[string]$adapter.LinkSpeed; "
        "ReceivedBytes=$(if ($stats) { $stats.ReceivedBytes } else { 0 }); "
        "SentBytes=$(if ($stats) { $stats.SentBytes } else { 0 })} }",
        timeout=15,
    )
    if not result.ok:
        return [], [
            _warning(
                f"Safe Windows adapter counter telemetry failed: {result.stderr or result.stdout}",
                source="PowerShell Get-NetAdapterStatistics",
            )
        ]

    flows: list[dict[str, str]] = []
    for row in rows:
        name = _normalize_text(row.get("Name"))
        description = _normalize_text(row.get("InterfaceDescription"))
        if_index = _normalize_text(row.get("ifIndex"))
        row_tokens = {
            _normalize_interface_token(name),
            _normalize_interface_token(description),
            _normalize_interface_token(if_index),
        }
        row_tokens.discard("")
        if not row_tokens.intersection(selected_tokens):
            continue

        received = _safe_counter_int(row.get("ReceivedBytes"))
        sent = _safe_counter_int(row.get("SentBytes"))
        total_bytes = received + sent
        if total_bytes <= 0:
            continue

        status = _normalize_text(row.get("Status")) or "unknown"
        link_speed = _normalize_text(row.get("LinkSpeed")) or "unknown"
        interface_label = name or description or if_index or "selected interface"
        sample = _normalize_text(
            f"interface telemetry [{interface_label}] RX={received} TX={sent} "
            f"status={status} link={link_speed} source=Get-NetAdapterStatistics safe-mode"
        )
        findings = (
            "Selected adapter counters show RX/TX traffic; packet payload is not captured in safe mode"
        )
        flows.append(
            {
                "Source": interface_label,
                "Destination": "local-network",
                "Protocol": "INTERFACE",
                "Source Port": "",
                "Destination Port": "",
                "Frame Protocols": "windows:adapter-statistics",
                "Packet Info": sample,
                "Protocol Details": sample,
                "Ethernet Source": "",
                "Ethernet Destination": "",
                "IP TTL": "",
                "TCP Flags": "",
                "TCP Retransmission": "",
                "TCP Lost Segment": "",
                "ICMP Type": "",
                "ARP Opcode": "",
                "DNS Query": "",
                "HTTP Host": "",
                "HTTP Method": "",
                "HTTP URI": "",
                "TLS SNI": "",
                "Direction": "interface-counter",
                "Source Scope": "local-interface",
                "Destination Scope": "local-network",
                "Traffic Severity": "info",
                "Traffic Color": TRAFFIC_SEVERITY_COLORS["info"],
                "Traffic Findings": findings,
                "Packet Samples": sample,
                "Packet Sample Count": "1",
                "Expert Severity": "",
                "Expert Message": "",
                "Local Endpoint": interface_label,
                "Local PID": "",
                "Local Application": "",
                "Connection State": status,
                "Capture Mode": "safe-windows-interface-counters",
                "Traffic Evidence Type": "Windows adapter RX/TX counter snapshot",
                "Packets": "0",
                "Bytes": str(total_bytes),
                "LastSeen": "",
                "Interface": f"{interface_label} ({description})" if description and description != interface_label else interface_label,
            }
        )

    if not flows:
        return [], []
    return flows, [
        _diagnostic(
            f"Collected {len(flows)} selected adapter counter row(s) using safe Windows telemetry",
            source="PowerShell Get-NetAdapterStatistics",
        )
    ]


def _safe_counter_int(value: object) -> int:
    try:
        return max(0, int(str(value or "0").strip()))
    except (TypeError, ValueError):
        return 0


def detect_tshark_interfaces(
    tshark_command: str | None = None,
) -> tuple[list[dict[str, str]], str | None]:
    if tshark_command is None:
        windows_interfaces = _windows_capture_interfaces_from_adapters()
        if windows_interfaces:
            return windows_interfaces, None
    command = resolve_tool_command("tshark") if tshark_command is None else tshark_command
    if not command_exists(command):
        return [], "tshark executable not found. Place tshark.exe in tools/wireshark or tools/tshark and install Wireshark/tshark in PATH."
    return _detect_tshark_interfaces(tshark_command=command)


def _detect_tshark_interfaces(tshark_command: str = "tshark") -> tuple[list[dict[str, str]], str | None]:
    result = run_command([tshark_command, "-D"], timeout=10)
    if not result.ok:
        message = (result.stderr or result.stdout or "tshark interface discovery failed").strip()
        return [], f"tshark -D failed: {message}"
    adapter_status = _windows_adapter_status_index()
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
            candidate = {"index": index, "name": index, "device": parts[1], "description": description}
            _apply_tshark_interface_metadata(candidate, adapter_status)
            interfaces.append(candidate)
    if not interfaces:
        return [], "tshark interfaces are not available"
    return interfaces, None


def _windows_capture_interfaces_from_adapters() -> list[dict[str, str]]:
    adapter_status = _windows_adapter_status_index()
    interfaces: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in adapter_status.values():
        if_index = str(row.get("ifIndex") or "").strip()
        name = str(row.get("Name") or "").strip()
        interface_description = str(row.get("InterfaceDescription") or "").strip()
        identity = if_index or name or interface_description
        if not identity or identity.casefold() in seen:
            continue
        seen.add(identity.casefold())
        friendly_name = name or interface_description or identity
        description = friendly_name
        if interface_description and interface_description.casefold() != friendly_name.casefold():
            description = f"{friendly_name} ({interface_description})"
        kind = _interface_kind(description, friendly_name, name)
        status = str(row.get("Status") or "").strip() or ("service" if kind == "extcap" else "unknown")
        active = _interface_active_flag(status, kind)
        traffic_active = _interface_traffic_active_flag(row)
        interfaces.append(
            {
                "index": if_index or identity,
                "name": name or identity,
                "device": name or identity,
                "description": description,
                "friendly_name": friendly_name,
                "kind": kind,
                "status": status,
                "link_speed": str(row.get("LinkSpeed") or "").strip(),
                "mac_address": str(row.get("MacAddress") or "").strip(),
                "received_bytes": str(row.get("ReceivedBytes") or "0").strip(),
                "sent_bytes": str(row.get("SentBytes") or "0").strip(),
                "traffic_active": traffic_active,
                "active": active,
                "capture_recommended": "yes" if active == "yes" and kind == "physical" else "no",
            }
        )
    interfaces.sort(
        key=lambda item: (
            item.get("active") != "yes",
            item.get("kind") != "physical",
            str(item.get("friendly_name") or "").casefold(),
        )
    )
    return interfaces


def _windows_adapter_status_index() -> dict[str, dict[str, str]]:
    rows, _cmd_result = run_powershell_json(
        "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | "
        "ForEach-Object { $adapter=$_; $stats=Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction SilentlyContinue; "
        "@{Name=$adapter.Name; InterfaceDescription=$adapter.InterfaceDescription; Status=$adapter.Status; "
        "LinkSpeed=$adapter.LinkSpeed; MacAddress=$adapter.MacAddress; ifIndex=$adapter.ifIndex; "
        "ReceivedBytes=if($stats){$stats.ReceivedBytes}else{0}; SentBytes=if($stats){$stats.SentBytes}else{0}} }",
        timeout=12,
    )
    index: dict[str, dict[str, str]] = {}
    for row in rows:
        normalized = {str(key): str(value or "").strip() for key, value in row.items()}
        for key in ("Name", "InterfaceDescription", "MacAddress", "ifIndex"):
            value = normalized.get(key, "")
            if value:
                index[_normalize_interface_token(value)] = normalized
    return index


def _apply_tshark_interface_metadata(candidate: dict[str, str], adapter_status: dict[str, dict[str, str]]) -> None:
    description = candidate.get("description", "")
    friendly_name = _friendly_interface_name(description)
    status_row = _find_adapter_status(candidate, friendly_name, adapter_status)
    kind = _interface_kind(description, friendly_name, candidate.get("device", ""))
    status = status_row.get("Status", "") if status_row else ""
    candidate["friendly_name"] = friendly_name
    candidate["kind"] = kind
    candidate["status"] = status or ("service" if kind == "extcap" else "unknown")
    candidate["link_speed"] = status_row.get("LinkSpeed", "") if status_row else ""
    candidate["mac_address"] = status_row.get("MacAddress", "") if status_row else ""
    candidate["received_bytes"] = status_row.get("ReceivedBytes", "0") if status_row else "0"
    candidate["sent_bytes"] = status_row.get("SentBytes", "0") if status_row else "0"
    candidate["traffic_active"] = _interface_traffic_active_flag(status_row)
    candidate["active"] = _interface_active_flag(candidate["status"], kind)
    candidate["capture_recommended"] = "yes" if candidate["active"] == "yes" and kind == "physical" else "no"


def _friendly_interface_name(description: str) -> str:
    match = re.search(r"\(([^()]+)\)\s*$", description or "")
    if match:
        return match.group(1).strip()
    return (description or "").strip()


def _find_adapter_status(
    candidate: dict[str, str],
    friendly_name: str,
    adapter_status: dict[str, dict[str, str]],
) -> dict[str, str]:
    for value in (
        friendly_name,
        candidate.get("description", ""),
        candidate.get("name", ""),
        candidate.get("index", ""),
    ):
        token = _normalize_interface_token(value)
        if token in adapter_status:
            return adapter_status[token]
    description = _normalize_interface_token(candidate.get("description", ""))
    for key, row in adapter_status.items():
        if key and key in description:
            return row
    return {}


def _interface_kind(description: str, friendly_name: str = "", name: str = "") -> str:
    value = f"{description} {friendly_name} {name}".casefold()
    if "ciscodump" in value or "sshdump" in value or "udpdump" in value or "etwdump" in value or "randpkt" in value or "wifidump" in value:
        return "extcap"
    if "loopback" in value or "npf_loopback" in value:
        return "loopback"
    if "vmware" in value or "virtualbox" in value or "hyper-v" in value or "virtual" in value:
        return "virtual"
    if "vpn" in value or "wireguard" in value or "amnezia" in value or "tap" in value or "tun" in value:
        return "vpn"
    if "bluetooth" in value:
        return "bluetooth"
    return "physical"


def _interface_traffic_active_flag(row: dict[str, str] | None) -> str:
    if not row:
        return "unknown"
    received = _interface_counter_value(row.get("ReceivedBytes") or row.get("received_bytes"))
    sent = _interface_counter_value(row.get("SentBytes") or row.get("sent_bytes"))
    if received is None and sent is None:
        return "unknown"
    return "yes" if (received or 0) > 0 or (sent or 0) > 0 else "no"


def _interface_counter_value(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _interface_active_flag(status: str, kind: str) -> str:
    normalized = (status or "").strip().casefold()
    if kind == "extcap":
        return "no"
    if normalized in {"up", "running", "connected"}:
        return "yes"
    if normalized in {"down", "disconnected", "not present", "disabled"}:
        return "no"
    return "unknown"


def _parse_tshark_csv(raw: str, fields: list[str] | None = None) -> list[dict[str, str]]:
    del fields
    text = (raw or "").strip()
    if not text:
        return []
    try:
        reader = csv.DictReader(text.splitlines(), skipinitialspace=True)
    except Exception:
        return []
    if reader.fieldnames is None:
        return []
    flows: dict[tuple[str, str, str, str, str, str], dict[str, object]] = {}
    for row in reader:
        source = _packet_source_address(row)
        destination = _packet_destination_address(row)
        if not source or not destination:
            continue
        protocol = _application_protocol(row) or "UNKNOWN"
        source_port = str(row.get("tcp.srcport") or row.get("udp.srcport") or "").strip()
        destination_port = str(row.get("tcp.dstport") or row.get("udp.dstport") or "").strip()
        frame_len = _parse_int(row.get("frame.len"), 0)
        seen_at = str(row.get("frame.time_epoch") or "").strip()
        interface = row.get("interface", "")
        direction, source_scope, destination_scope = _classify_flow(source, destination)
        key = (source, destination, protocol, source_port, destination_port, str(interface))
        packet_findings, packet_score = _traffic_findings_for_packet(
            row,
            protocol,
            source_scope,
            destination_scope,
            source_port,
            destination_port,
        )
        packet_sample = _packet_sample(row, protocol, source, destination, source_port, destination_port)
        bucket = flows.setdefault(
            key,
            {
                "Source": source,
                "Destination": destination,
                "Protocol": protocol,
                "Source Port": source_port,
                "Destination Port": destination_port,
                "Frame Protocols": _csv_value(row, "frame.protocols"),
                "Packet Info": _csv_value(row, "_ws.col.Info"),
                "Protocol Details": _protocol_details(row, protocol),
                "Ethernet Source": _csv_value(row, "eth.src"),
                "Ethernet Destination": _csv_value(row, "eth.dst"),
                "IP TTL": _csv_value(row, "ip.ttl"),
                "TCP Flags": _csv_value(row, "tcp.flags"),
                "TCP Retransmission": _flag_value(row, "tcp.analysis.retransmission"),
                "TCP Lost Segment": _flag_value(row, "tcp.analysis.lost_segment"),
                "ICMP Type": _csv_value(row, "icmp.type"),
                "ARP Opcode": _csv_value(row, "arp.opcode"),
                "DNS Query": _csv_value(row, "dns.qry.name"),
                "HTTP Host": _csv_value(row, "http.host"),
                "HTTP Method": _csv_value(row, "http.request.method"),
                "HTTP URI": _csv_value(row, "http.request.uri"),
                "TLS SNI": _csv_value(row, "tls.handshake.extensions_server_name"),
                "Direction": direction,
                "Source Scope": source_scope,
                "Destination Scope": destination_scope,
                "Packets": 0,
                "Bytes": 0,
                "Traffic Score": 0,
                "Traffic Findings": set(),
                "Packet Samples": [],
                "Packet Sample Count": 0,
                "Packet Rows": [],
                "Packet Row Count": 0,
                "Expert Severity": _csv_value(row, "_ws.expert.severity"),
                "Expert Message": _csv_value(row, "_ws.expert.message"),
                "LastSeen": seen_at,
                "Interface": str(interface),
            },
        )
        bucket["Packets"] = int(bucket["Packets"]) + 1  # type: ignore[index]
        bucket["Bytes"] = int(bucket["Bytes"]) + frame_len  # type: ignore[index]
        bucket["Traffic Score"] = max(int(bucket["Traffic Score"]), packet_score)  # type: ignore[index]
        findings = set(bucket["Traffic Findings"])  # type: ignore[arg-type]
        findings.update(packet_findings)
        bucket["Traffic Findings"] = findings
        if packet_sample:
            samples = list(bucket["Packet Samples"])  # type: ignore[arg-type]
            bucket["Packet Sample Count"] = int(bucket["Packet Sample Count"]) + 1  # type: ignore[index]
            if len(samples) < 50:
                samples.append(packet_sample)
            bucket["Packet Samples"] = samples
        packet_row = _packet_row_payload(
            row,
            protocol,
            source,
            destination,
            source_port,
            destination_port,
            _traffic_severity_from_score(packet_score),
        )
        if packet_row:
            packet_rows = list(bucket["Packet Rows"])  # type: ignore[arg-type]
            bucket["Packet Row Count"] = int(bucket["Packet Row Count"]) + 1  # type: ignore[index]
            if len(packet_rows) < 2000:
                packet_rows.append(packet_row)
            bucket["Packet Rows"] = packet_rows
        if not bucket.get("Expert Severity"):
            bucket["Expert Severity"] = _csv_value(row, "_ws.expert.severity")
        if not bucket.get("Expert Message"):
            bucket["Expert Message"] = _csv_value(row, "_ws.expert.message")
        if seen_at:
            bucket["LastSeen"] = seen_at
    normalized: list[dict[str, str]] = []
    for item in flows.values():
        traffic_severity = _traffic_severity_from_score(int(item["Traffic Score"]))
        traffic_findings = sorted(str(value) for value in set(item["Traffic Findings"]) if str(value))  # type: ignore[arg-type]
        packet_samples = [str(value) for value in list(item["Packet Samples"])]  # type: ignore[arg-type]
        packet_rows = [value for value in list(item["Packet Rows"]) if isinstance(value, dict)]  # type: ignore[arg-type]
        normalized.append({
            "Source": str(item["Source"]),
            "Destination": str(item["Destination"]),
            "Protocol": str(item["Protocol"]),
            "Source Port": str(item["Source Port"]),
            "Destination Port": str(item["Destination Port"]),
            "Frame Protocols": str(item["Frame Protocols"]),
            "Packet Info": str(item["Packet Info"]),
            "Protocol Details": str(item["Protocol Details"]),
            "Ethernet Source": str(item["Ethernet Source"]),
            "Ethernet Destination": str(item["Ethernet Destination"]),
            "IP TTL": str(item["IP TTL"]),
            "TCP Flags": str(item["TCP Flags"]),
            "TCP Retransmission": str(item["TCP Retransmission"]),
            "TCP Lost Segment": str(item["TCP Lost Segment"]),
            "ICMP Type": str(item["ICMP Type"]),
            "ARP Opcode": str(item["ARP Opcode"]),
            "DNS Query": str(item["DNS Query"]),
            "HTTP Host": str(item["HTTP Host"]),
            "HTTP Method": str(item["HTTP Method"]),
            "HTTP URI": str(item["HTTP URI"]),
            "TLS SNI": str(item["TLS SNI"]),
            "Direction": str(item["Direction"]),
            "Source Scope": str(item["Source Scope"]),
            "Destination Scope": str(item["Destination Scope"]),
            "Traffic Severity": traffic_severity,
            "Traffic Color": TRAFFIC_SEVERITY_COLORS[traffic_severity],
            "Traffic Findings": "; ".join(traffic_findings) if traffic_findings else "No notable traffic risk indicators",
            "Packet Samples": "\n".join(packet_samples),
            "Packet Sample Count": int(item["Packet Sample Count"]),
            "Packet Rows JSON": json.dumps(packet_rows, ensure_ascii=False),
            "Packet Row Count": int(item["Packet Row Count"]),
            "Expert Severity": str(item["Expert Severity"]),
            "Expert Message": str(item["Expert Message"]),
            "Packets": int(item["Packets"]),
            "Bytes": int(item["Bytes"]),
            "LastSeen": str(item["LastSeen"]),
            "Interface": str(item["Interface"]),
        })
    normalized.sort(key=lambda item: (-(item["Packets"] or 0), -(item["Bytes"] or 0)))
    return normalized


def _csv_value(row: dict[str, str], field: str) -> str:
    return _normalize_text(row.get(field) or "")


def _packet_source_address(row: dict[str, str]) -> str:
    return (
        _csv_value(row, "ip.src")
        or _csv_value(row, "ipv6.src")
        or _csv_value(row, "eth.src")
    )


def _packet_destination_address(row: dict[str, str]) -> str:
    return (
        _csv_value(row, "ip.dst")
        or _csv_value(row, "ipv6.dst")
        or _csv_value(row, "eth.dst")
    )


def _flag_value(row: dict[str, str], field: str) -> str:
    value = _csv_value(row, field).casefold()
    if value and value not in {"0", "false", "no"}:
        return "yes"
    return ""


def _traffic_severity_from_score(score: int) -> str:
    if score >= 4:
        return "critical"
    if score == 3:
        return "high"
    if score == 2:
        return "medium"
    if score == 1:
        return "low"
    return "info"


def _traffic_findings_for_packet(
    row: dict[str, str],
    protocol: str,
    source_scope: str,
    destination_scope: str,
    source_port: str,
    destination_port: str,
) -> tuple[list[str], int]:
    findings: list[str] = []
    score = 0
    protocol_upper = (protocol or "").upper()
    ports = {source_port, destination_port}

    if protocol_upper in {"TELNET", "FTP"} or ports & {"21", "23"}:
        findings.append("Clear-text administrative protocol observed")
        score = max(score, 4)
    if protocol_upper == "HTTP" or "80" in ports:
        findings.append("Clear-text HTTP request observed")
        score = max(score, 3)

    external_boundary = (
        source_scope in {"private", "link-local"} and destination_scope == "external"
    ) or (
        source_scope == "external" and destination_scope in {"private", "link-local"}
    )
    if external_boundary:
        findings.append("External boundary traffic observed")
        score = max(score, 2)
        if ports & {"22", "23", "3389", "445", "139", "3306", "5432", "5985", "5900"}:
            findings.append("High-value service traffic crossed the network boundary")
            score = max(score, 3)

    if _flag_value(row, "tcp.analysis.retransmission") or _flag_value(row, "tcp.analysis.fast_retransmission"):
        findings.append("TCP retransmission observed")
        score = max(score, 2)
    if _flag_value(row, "tcp.analysis.lost_segment"):
        findings.append("TCP lost segment observed")
        score = max(score, 2)
    if _flag_value(row, "tcp.analysis.duplicate_ack"):
        findings.append("TCP duplicate ACK observed")
        score = max(score, 1)
    if _flag_value(row, "tcp.analysis.out_of_order"):
        findings.append("TCP out-of-order segment observed")
        score = max(score, 2)
    if _flag_value(row, "tcp.analysis.zero_window") or _flag_value(row, "tcp.analysis.window_full"):
        findings.append("TCP receive-window pressure observed")
        score = max(score, 2)

    dns_query = _csv_value(row, "dns.qry.name")
    if dns_query:
        findings.append(f"DNS query observed: {dns_query}")
        score = max(score, 1)
    tls_sni = _csv_value(row, "tls.handshake.extensions_server_name")
    if tls_sni:
        findings.append(f"TLS SNI observed: {tls_sni}")
        score = max(score, 1)

    expert_severity = _csv_value(row, "_ws.expert.severity").casefold()
    expert_message = _csv_value(row, "_ws.expert.message")
    if expert_message:
        findings.append(f"Wireshark expert {expert_severity or 'note'}: {expert_message}")
        score = max(score, {"error": 4, "warn": 3, "warning": 3, "note": 2, "chat": 1}.get(expert_severity, 2))

    return findings, score


def _packet_sample(
    row: dict[str, str],
    protocol: str,
    source: str,
    destination: str,
    source_port: str,
    destination_port: str,
) -> str:
    frame_number = _csv_value(row, "frame.number") or "?"
    timestamp = _csv_value(row, "frame.time_relative") or _csv_value(row, "frame.time_epoch")
    frame_len = _csv_value(row, "frame.len")
    endpoint_source = f"{source}:{source_port}" if source_port else source
    endpoint_destination = f"{destination}:{destination_port}" if destination_port else destination
    details = _protocol_details(row, protocol)
    parts = [
        f"#{frame_number}",
        f"t={timestamp}" if timestamp else "",
        protocol,
        f"{endpoint_source} -> {endpoint_destination}",
        f"len={frame_len}" if frame_len else "",
        f"info={details}" if details else "",
    ]
    return _normalize_text(" ".join(part for part in parts if part))[:700]


def _packet_row_payload(
    row: dict[str, str],
    protocol: str,
    source: str,
    destination: str,
    source_port: str,
    destination_port: str,
    severity: str,
) -> dict[str, str]:
    frame_number = _csv_value(row, "frame.number") or "?"
    timestamp = _csv_value(row, "frame.time_relative") or _csv_value(row, "frame.time_epoch")
    frame_len = _csv_value(row, "frame.len") or _csv_value(row, "frame.cap_len")
    source_endpoint = f"{source}:{source_port}" if source_port else source
    destination_endpoint = f"{destination}:{destination_port}" if destination_port else destination
    info = _protocol_details(row, protocol) or _csv_value(row, "_ws.col.Info") or _csv_value(row, "frame.protocols")
    protocol_stack = _csv_value(row, "frame.protocols")
    hex_preview = _packet_hex_preview(row)
    detail_lines = [
        f"Frame {frame_number}: {frame_len or '?'} bytes captured",
        f"Time: {timestamp}" if timestamp else "",
        f"Interface: {_csv_value(row, 'interface')}" if _csv_value(row, "interface") else "",
        f"Source: {source_endpoint}",
        f"Destination: {destination_endpoint}",
        f"Protocol: {protocol or 'UNKNOWN'}",
        f"Protocol stack: {protocol_stack}" if protocol_stack else "",
        f"Info: {info}" if info else "",
        f"Ethernet: {_csv_value(row, 'eth.src')} -> {_csv_value(row, 'eth.dst')}" if _csv_value(row, "eth.src") or _csv_value(row, "eth.dst") else "",
        f"IP TTL: {_csv_value(row, 'ip.ttl')}" if _csv_value(row, "ip.ttl") else "",
        f"TCP flags: {_csv_value(row, 'tcp.flags')}" if _csv_value(row, "tcp.flags") else "",
        f"Wireshark expert: {_csv_value(row, '_ws.expert.severity')} {_csv_value(row, '_ws.expert.message')}".strip()
        if _csv_value(row, "_ws.expert.severity") or _csv_value(row, "_ws.expert.message") else "",
    ]
    return {
        "No.": frame_number,
        "Time": timestamp,
        "Source": source_endpoint,
        "Destination": destination_endpoint,
        "Protocol": protocol or "UNKNOWN",
        "Length": frame_len,
        "Info": info,
        "Risk": severity.upper(),
        "Details": "\n".join(line for line in detail_lines if line),
        "Bytes Hex": hex_preview,
    }


def _packet_hex_preview(row: dict[str, str], limit_bytes: int = 256) -> str:
    raw = _csv_value(row, "data.data")
    if not raw:
        return ""
    hex_chars = re.sub(r"[^0-9a-fA-F]", "", raw)
    if not hex_chars:
        return ""
    octets = [hex_chars[index:index + 2].lower() for index in range(0, min(len(hex_chars), limit_bytes * 2), 2)]
    octets = [item for item in octets if len(item) == 2]
    suffix = " ..." if len(hex_chars) > limit_bytes * 2 else ""
    return " ".join(octets) + suffix


def _application_protocol(row: dict[str, str]) -> str:
    if _csv_value(row, "dns.qry.name"):
        return "DNS"
    if _csv_value(row, "http.host") or _csv_value(row, "http.request.method"):
        return "HTTP"
    if _csv_value(row, "tls.handshake.extensions_server_name"):
        return "TLS"
    protocol = _csv_value(row, "_ws.col.Protocol").upper()
    if protocol:
        return protocol
    protocols = _csv_value(row, "frame.protocols")
    if protocols:
        return protocols.split(":")[-1].upper()
    return ""


def _protocol_details(row: dict[str, str], protocol: str) -> str:
    dns_query = _csv_value(row, "dns.qry.name")
    if dns_query:
        return f"DNS query {dns_query}"

    http_method = _csv_value(row, "http.request.method")
    http_host = _csv_value(row, "http.host")
    http_uri = _csv_value(row, "http.request.uri")
    if http_method or http_host:
        target = f"{http_host}{http_uri}" if http_host else http_uri
        return _normalize_text(f"HTTP {http_method} {target}")

    tls_sni = _csv_value(row, "tls.handshake.extensions_server_name")
    if tls_sni:
        return f"{protocol or 'TLS'} SNI {tls_sni}"

    details: list[str] = []
    packet_info = _csv_value(row, "_ws.col.Info")
    if packet_info:
        details.append(packet_info)
    if _flag_value(row, "tcp.analysis.retransmission"):
        details.append("TCP retransmission")
    if _flag_value(row, "tcp.analysis.lost_segment"):
        details.append("TCP lost segment")
    if details:
        return "; ".join(details)
    return _csv_value(row, "frame.protocols")


def _looks_like_npcap_capture_error(message: str) -> bool:
    lowered = (message or "").casefold()
    return (
        "npcap" in lowered
        or "npf" in lowered
        or "winpcap" in lowered
        or "packet.dll" in lowered
    )


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
    if config.capture_enabled:
        _emit_progress(progress, "Traffic analysis phase enabled: safe Windows connection telemetry; Npcap/tshark live capture disabled")
        captures, diagnostics_capture = collect_network_capture(config, progress=progress)
    else:
        captures, diagnostics_capture = [], [_diagnostic("Network traffic capture is disabled")]
    if config.nmap_enabled:
        _emit_progress(progress, "Nmap phase enabled: service discovery and topology mapping")
        services, diagnostics_services = collect_network_services(config, progress=progress)
    else:
        _emit_progress(progress, "Nmap phase skipped: capture-only mode")
        services, diagnostics_services = [], [
            _diagnostic("Nmap phase skipped because only traffic capture is enabled", source="nmap")
        ]
    _emit_progress(progress, "Evaluating security posture from discovered services and captures")
    security_diagnostics: list[CollectorDiagnostic] = []

    critical_service_ports = {
        "21": "FTP",
        "23": "TELNET",
        "22": "SSH",
        "3389": "RDP",
        "5900": "VNC",
        "3306": "MySQL",
        "5432": "PostgreSQL",
        "6379": "Redis",
        "445": "SMB",
        "139": "NetBIOS/SMB",
        "5986": "WinRM HTTPS",
        "5985": "WinRM HTTP",
    }
    sensitive_protocols = {"FTP", "TELNET", "VNC", "RDP", "SMB", "SMB-CLIENT", "NETBIOS"}
    seen_service_diagnostics: set[str] = set()
    seen_flow_diagnostics: set[str] = set()
    for service in services:
        host = str(service.fields.get("Host IP") or "").strip()
        port = str(service.fields.get("Port") or "").strip()
        protocol = str(service.fields.get("Protocol") or "").strip().upper()
        service_name = str(service.fields.get("Service") or "").strip().lower()
        if port in critical_service_ports:
            key = f"service-{host}:{port}"
            if key not in seen_service_diagnostics:
                seen_service_diagnostics.add(key)
                security_diagnostics.append(
                    _warning(
                        f"Critical service found: {critical_service_ports[port]} (port {port}) on {host}"
                    )
                )
        if protocol and protocol in sensitive_protocols:
            key = f"proto-{host}:{port}:{protocol}"
            if key not in seen_service_diagnostics:
                seen_service_diagnostics.add(key)
                security_diagnostics.append(
                    _warning(
                        f"Potentially insecure protocol {protocol} found on {host}:{port}"
                    )
                )
        if "kerberos" not in service_name and port in {"139", "445"}:
            key = f"smb-{host}:{port}"
            if key not in seen_service_diagnostics:
                seen_service_diagnostics.add(key)
                security_diagnostics.append(_warning(f"SMB/NetBIOS exposure on {host}:{port}"))

    for flow in captures:
        source = str(flow.fields.get("Source") or "").strip()
        destination = str(flow.fields.get("Destination") or "").strip()
        source_scope = str(flow.fields.get("Source Scope") or "").strip().lower()
        destination_scope = str(flow.fields.get("Destination Scope") or "").strip().lower()
        source_port = str(flow.fields.get("Source Port") or "").strip()
        destination_port = str(flow.fields.get("Destination Port") or "").strip()
        protocol = str(flow.fields.get("Protocol") or "").strip().upper()
        interface = str(flow.fields.get("Interface") or "").strip()
        packets = _parse_int(str(flow.fields.get("Packets") or ""), 0)
        traffic_severity = str(flow.fields.get("Traffic Severity") or "info").strip().lower()
        traffic_findings = str(flow.fields.get("Traffic Findings") or "").strip()
        if traffic_severity in {"low", "medium", "high", "critical"} or traffic_findings:
            _emit_progress(
                progress,
                f"TRAFFIC_RISK|{traffic_severity or 'info'}|"
                f"{source}:{source_port} -> {destination}:{destination_port} {protocol}; "
                f"{traffic_findings or 'packet metadata analyzed'}",
            )
        packet_samples = str(flow.fields.get("Packet Samples") or "").strip()
        if packet_samples:
            first_sample = packet_samples.splitlines()[0]
            _emit_progress(progress, f"PACKET_SAMPLE|{traffic_severity or 'info'}|{first_sample}")

        suspicious_outbound = source_scope in {"private", "link-local"} and destination_scope == "external"
        suspicious_inbound = source_scope == "external" and destination_scope in {"private", "link-local"}
        if suspicious_outbound or suspicious_inbound:
            remote_host = destination if suspicious_outbound else source
            remote_port = destination_port if suspicious_outbound else source_port
            direction = "egress" if suspicious_outbound else "ingress"
            flow_key = f"flow-{source}:{source_port}-{destination}:{destination_port}-{protocol}-{interface}"
            if flow_key not in seen_flow_diagnostics:
                seen_flow_diagnostics.add(flow_key)
                security_diagnostics.append(
                    _warning(
                        f"External boundary traffic ({direction}): {source}:{source_port} -> {destination}:{destination_port} "
                        f"({protocol}/{remote_host}:{remote_port}) on {interface}"
                    )
                )
            critical_port_flow = remote_port
            if critical_port_flow in {"22", "23", "3389", "445", "139", "3306", "5432"} and packets > 0:
                high_value_key = f"highvalue-{direction}-{interface}-{remote_host}:{critical_port_flow}:{protocol}"
                if high_value_key not in seen_flow_diagnostics:
                    seen_flow_diagnostics.add(high_value_key)
                    security_diagnostics.append(
                        _warning(
                            f"High-value service access likely on external traffic via {interface}: {protocol} {remote_host}:{critical_port_flow}"
                        )
                    )

    _emit_progress(progress, f"Network intelligence completed: {len(services)} services, {len(captures)} captured flows")
    return services, captures, [*diagnostics_services, *diagnostics_capture, *security_diagnostics]


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
