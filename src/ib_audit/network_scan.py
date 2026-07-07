from __future__ import annotations

import csv
import ipaddress
import re
import shlex
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from .commands import run_command, run_powershell_json
from .models import CollectorDiagnostic


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
    nmap_os_detection: bool = True
    nmap_service_detection: bool = True
    capture_enabled: bool = False
    capture_interface: str | None = None
    capture_duration: int = 20
    capture_timeout: int = 130
    capture_filter: str = ""


@dataclass(frozen=True)
class NetworkScanService:
    object_type: str
    title: str
    fields: dict[str, str]


def _diagnostic(message: str, source: str = "nmap / tshark") -> CollectorDiagnostic:
    return CollectorDiagnostic("network_scan", "info", message, source)


def _warning(message: str, source: str = "nmap / tshark") -> CollectorDiagnostic:
    return CollectorDiagnostic("network_scan", "warning", message, source)


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
) -> tuple[list[NetworkScanService], list[CollectorDiagnostic]]:
    diagnostics: list[CollectorDiagnostic] = []
    if not config.enabled:
        return [], [_diagnostic("Network scan is disabled")]
    if not config.ports:
        return [], [_warning("Nmap ports are not set")]
    targets = parse_local_network_targets(config.targets)
    if not targets:
        return [], [_warning("No network targets discovered")]
    command = [
        "nmap",
        "-n",
        "-Pn",
        "-T2",
        "-open",
        "-oX",
        "-",
        "-p",
        _normalize_ports(config.ports),
    ]
    if config.nmap_service_detection:
        command.append("-sV")
    if config.nmap_os_detection:
        command.append("-O")
    if config.extra_args:
        try:
            command.extend(shlex.split(config.extra_args))
        except ValueError:
            command.extend(config.extra_args.split())
    command.extend(targets)
    result = run_command(command, timeout=max(60, int(config.nmap_timeout)))
    if not result.ok:
        return [], [_warning(f"Nmap execution failed: {result.stderr or result.stdout}")]
    services = _parse_nmap_xml(result.stdout)
    if not services:
        diagnostics.append(_warning("Nmap executed, but no service data was parsed"))
    else:
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
) -> tuple[list[NetworkScanService], list[CollectorDiagnostic]]:
    diagnostics: list[CollectorDiagnostic] = []
    if not config.enabled or not config.capture_enabled:
        return [], [_diagnostic("Network traffic capture is disabled")]
    interface = (config.capture_interface or "").strip()
    if not interface:
        candidates = _detect_tshark_interfaces()
        if candidates:
            interface = candidates[0]["name"]
        else:
            return [], [_warning("tshark interfaces are not available")]
    fields = [
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
    command = [
        "tshark",
        "-i",
        interface,
        "-n",
        "-q",
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
        *[item for field in fields for item in ("-e", field)],
    ]
    if config.capture_filter:
        command.extend(["-f", config.capture_filter])
    result = run_command(command, timeout=max(5, _parse_int(config.capture_timeout, 120)))
    if not result.ok:
        return [], [_warning(f"tshark execution failed: {result.stderr or result.stdout}")]
    flows = _parse_tshark_csv(result.stdout, fields)
    local_addresses = _local_ipv4_addresses()
    process_index = _tcp_connection_process_index()
    if not flows:
        diagnostics.append(_warning("Capture was executed but no packets were parsed"))
    else:
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


def _detect_tshark_interfaces() -> list[dict[str, str]]:
    result = run_command(["tshark", "-D"], timeout=10)
    if not result.ok:
        return []
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
    return interfaces


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
) -> tuple[list[NetworkScanService], list[NetworkScanService], list[CollectorDiagnostic]]:
    if not config.enabled:
        return [], [], [_diagnostic("Network scan is disabled")]
    services, diagnostics_services = collect_network_services(config)
    captures, diagnostics_capture = collect_network_capture(config)
    return services, captures, [*diagnostics_services, *diagnostics_capture]


__all__ = [
    "NetworkScanConfig",
    "NetworkScanService",
    "collect_network_intelligence",
    "collect_network_capture",
    "collect_network_services",
    "parse_local_network_targets",
    "_parse_nmap_xml",
    "_parse_tshark_csv",
]
