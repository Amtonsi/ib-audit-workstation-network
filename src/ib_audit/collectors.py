from __future__ import annotations

import csv
import os
import platform
import re
import socket
import tempfile
import winreg
from dataclasses import dataclass
from datetime import date, datetime
from io import StringIO
from pathlib import Path
from typing import Callable

from .commands import run_command, run_powershell_json
from .models import CollectorDiagnostic, InventoryObject
from .network_scan import NetworkScanConfig, collect_network_intelligence as collect_network_intelligence_data


ProgressCallback = Callable[[str], None] | None
CollectorExecutor = Callable[[ProgressCallback], tuple[list[InventoryObject], list[CollectorDiagnostic]]]


@dataclass(frozen=True)
class Collector:
    name: str
    category_id: str
    category_name: str
    func: CollectorExecutor


def _collector_without_progress(
    func: Callable[[], tuple[list[InventoryObject], list[CollectorDiagnostic]]],
) -> CollectorExecutor:
    return lambda _progress=None: func()


def parse_wmic_list(text: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    blank_run = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            blank_run += 1
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            key = key.strip()
            if current and (blank_run >= 2 or key in current):
                records.append(current)
                current = {}
            current[key.strip()] = value.strip()
            blank_run = 0
    if current:
        records.append(current)
    return records


def parse_wmic_table(text: str) -> list[dict[str, str]]:
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if len(lines) < 2:
        return []
    header = re.split(r"\s{2,}", lines[0].strip())
    records: list[dict[str, str]] = []
    for line in lines[1:]:
        values = re.split(r"\s{2,}", line.strip(), maxsplit=max(len(header) - 1, 0))
        if values:
            records.append({header[i]: values[i] if i < len(values) else "" for i in range(len(header))})
    return records


def parse_wmic_csv(text: str) -> list[dict[str, str]]:
    cleaned = "\n".join(line for line in text.splitlines() if line.strip())
    if not cleaned:
        return []
    try:
        reader = csv.DictReader(StringIO(cleaned))
        return [{k: v for k, v in row.items() if k} for row in reader]
    except csv.Error:
        return []


def parse_csv_table(text: str) -> list[dict[str, str]]:
    cleaned = "\n".join(line for line in text.splitlines() if line.strip())
    if not cleaned:
        return []
    try:
        reader = csv.DictReader(StringIO(cleaned))
        return [{str(k): str(v or "") for k, v in row.items() if k} for row in reader]
    except csv.Error:
        return []


def parse_reg_query_values(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    current_key = ""
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(r"^(HKEY_|HKLM\\|HKCU\\|HKCR\\|HKU\\)", stripped, re.I):
            current_key = stripped
            continue
        match = re.match(r"^\s+(.+?)\s+(REG_[A-Z0-9_]+)\s+(.*)$", line, re.I)
        if not match or not current_key:
            continue
        name, value_type, setting = (part.strip() for part in match.groups())
        setting = _normalize_registry_setting(value_type, setting)
        subkey = _relative_registry_path(current_key)
        if name and name != "(Default)":
            subkey = f"{subkey}\\{name}" if subkey else name
        rows.append({"Subkey": subkey, "Type": value_type, "Setting": setting})
    return rows


def parse_route_print(text: str) -> list[dict[str, str]]:
    routes: list[dict[str, str]] = []
    in_routes = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("Network Destination"):
            in_routes = True
            continue
        if not in_routes:
            continue
        if not line or line.startswith("=") or line.startswith("Persistent Routes"):
            if routes and line.startswith("="):
                break
            continue
        parts = line.split()
        if len(parts) >= 5 and re.match(r"^[0-9.]+$", parts[0]):
            routes.append(
                {
                    "Destination": parts[0],
                    "Netmask": parts[1],
                    "Next Hop": parts[2],
                    "Interface": parts[3],
                    "Metric": parts[4],
                }
            )
    return routes


def parse_netstat_ano(
    text: str,
    process_names: dict[str, str] | None = None,
    limit: int | None = None,
) -> tuple[list[dict[str, str]], bool]:
    process_names = process_names or {}
    rows: list[dict[str, str]] = []
    capped = False
    for line in text.splitlines():
        if not re.match(r"\s*(TCP|UDP)\s+", line):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        protocol = parts[0]
        local = parts[1]
        remote = parts[2]
        if protocol == "TCP" and len(parts) >= 5:
            state = _friendly_netstat_state(parts[3])
            pid = parts[4]
        else:
            state = ""
            pid = parts[-1]
        local_address, local_port = _split_endpoint(local)
        remote_address, remote_port = _split_endpoint(remote)
        rows.append(
            {
                "Port Protocol": protocol,
                "Local Address": local_address,
                "Local Port": local_port,
                "Remote Address": remote_address,
                "Remote Port": remote_port,
                "Connection State": state,
                "Process ID": pid,
                "Service Name": process_names.get(pid, ""),
            }
        )
        if limit is not None and len(rows) >= limit:
            capped = True
            break
    return rows, capped


def _normalize_registry_setting(value_type: str, setting: str) -> str:
    if value_type.upper() == "REG_DWORD" and setting.lower().startswith("0x"):
        try:
            return str(int(setting, 16))
        except ValueError:
            return setting
    return setting


def _relative_registry_path(path: str) -> str:
    replacements = (
        ("HKEY_LOCAL_MACHINE\\", ""),
        ("HKEY_CURRENT_USER\\", ""),
        ("HKEY_CLASSES_ROOT\\", ""),
        ("HKEY_USERS\\", ""),
        ("HKLM\\", ""),
        ("HKCU\\", ""),
        ("HKCR\\", ""),
        ("HKU\\", ""),
    )
    for prefix, replacement in replacements:
        if path.upper().startswith(prefix.upper()):
            return replacement + path[len(prefix) :]
    return path


def _split_endpoint(endpoint: str) -> tuple[str, str]:
    endpoint = endpoint.strip("[]")
    if endpoint in {"*", "*:*"}:
        return endpoint, ""
    if ":" not in endpoint:
        return endpoint, ""
    address, port = endpoint.rsplit(":", 1)
    return address.strip("[]") or "0.0.0.0", port  # nosec B104


def _friendly_netstat_state(state: str) -> str:
    return " ".join(part.capitalize() for part in state.replace("_", " ").split())


def parse_net_user_detail(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.rstrip()
        if not stripped or stripped.startswith("The command completed"):
            continue
        match = re.match(r"^(.+?)\s{2,}(.+)$", stripped)
        if match:
            fields[match.group(1).strip()] = match.group(2).strip()
    return fields


def annotate_user_password_age(fields: dict[str, object], today: date | None = None) -> None:
    today = today or date.today()
    source_value = _first_field(
        fields,
        [
            "Password last set",
            "PasswordLastSet",
            "Пароль задан",
            "Последняя установка пароля",
            "Дата последней установки пароля",
        ],
    )
    if not source_value:
        return
    password_date = _parse_local_date(str(source_value))
    if password_date is None:
        return
    fields["PasswordAgeDays"] = max(0, (today - password_date).days)
    fields["PasswordLastSetSource"] = str(source_value)


def _first_field(fields: dict[str, object], names: list[str]) -> object | None:
    casefold_map = {str(key).casefold(): value for key, value in fields.items()}
    for name in names:
        value = casefold_map.get(name.casefold())
        if value not in (None, ""):
            return value
    return None


def _parse_local_date(value: str) -> date | None:
    text = " ".join(value.replace(",", " ").split())
    if not text or text.casefold() in {"never", "never set", "никогда", "не задан"}:
        return None
    for pattern in (
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %I:%M %p",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%d.%m.%Y %H:%M:%S",
        "%d.%m.%Y %H:%M",
        "%d.%m.%Y",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(text, pattern).date()
        except ValueError:
            continue
    return None


def parse_ipconfig_all(text: str) -> list[dict[str, str]]:
    adapters: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    last_key: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        adapter_match = re.match(r"^(.+?) adapter (.+?):$", line)
        if adapter_match:
            if current:
                adapters.append(current)
            current = {"Adapter": adapter_match.group(2).strip()}
            last_key = None
            continue
        if current is None:
            continue
        field_match = re.match(r"^\s*([^:]+?)\s*(?:\.+\s*)?:\s*(.*)$", line)
        if field_match:
            key = re.sub(r"(?:\s*\.)+\s*$", "", field_match.group(1)).strip()
            key = " ".join(key.split())
            value = field_match.group(2).strip()
            value = value.replace("(Preferred)", "").strip()
            current[key] = value
            last_key = key
            continue
        continuation = line.strip()
        if continuation and last_key:
            current[last_key] = (current[last_key] + ", " + continuation).strip(", ")
    if current:
        adapters.append(current)
    return adapters


def _join_field(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value if item not in (None, ""))
    return str(value)


def _network_adapter_from_cim(record: dict[str, object]) -> dict[str, object]:
    return {
        "Description": record.get("Description") or record.get("Caption"),
        "MAC Address": record.get("MACAddress"),
        "DHCP Enabled": record.get("DHCPEnabled"),
        "IP Addresses": _join_field(record.get("IPAddress")),
        "Subnets": _join_field(record.get("IPSubnet")),
        "Default Gateways": _join_field(record.get("DefaultIPGateway")),
        "DNS Servers": _join_field(record.get("DNSServerSearchOrder")),
    }


def safe_title(obj: InventoryObject, preferred_fields: list[str]) -> str:
    if obj.title:
        return obj.title
    for field in preferred_fields:
        value = obj.fields.get(field)
        if value:
            return str(value)
    return obj.object_type


def _diagnostic(module: str, severity: str, message: str, source: str) -> CollectorDiagnostic:
    return CollectorDiagnostic(module=module, severity=severity, message=message, source=source)


def _object(
    category_id: str,
    category_name: str,
    object_type: str,
    title: str,
    fields: dict[str, object],
    source: str,
    confidence: str = "high",
    raw: dict[str, object] | None = None,
) -> InventoryObject:
    return InventoryObject(
        category_id=category_id,
        category_name=category_name,
        object_type=object_type,
        title=title or object_type,
        fields={k: v for k, v in fields.items() if v not in (None, "")},
        source=source,
        confidence=confidence,
        raw=raw or {},
    )


def _objects_from_wmic(
    command: list[str],
    category_id: str,
    category_name: str,
    object_type: str,
    module: str,
    title_fields: list[str],
    timeout: int = 20,
) -> tuple[list[InventoryObject], list[CollectorDiagnostic]]:
    result = run_command(command, timeout=timeout)
    diagnostics: list[CollectorDiagnostic] = []
    if not result.ok:
        diagnostics.append(_diagnostic(module, "warning", result.stderr or "Command unavailable", " ".join(command)))
        return [], diagnostics
    records = parse_wmic_list(result.stdout) or parse_wmic_table(result.stdout)
    objects = []
    for record in records:
        title = next((record.get(field, "") for field in title_fields if record.get(field)), object_type)
        objects.append(_object(category_id, category_name, object_type, title, record, "WMIC", raw=record))
    if not objects:
        diagnostics.append(_diagnostic(module, "info", "No records returned", " ".join(command)))
    return objects, diagnostics


def collect_system_hardware() -> tuple[list[InventoryObject], list[CollectorDiagnostic]]:
    objects: list[InventoryObject] = []
    diagnostics: list[CollectorDiagnostic] = []
    hostname = socket.gethostname()
    objects.append(
        _object(
            "g",
            "System Overview",
            "system",
            hostname,
            {
                "Computer Name": hostname,
                "Platform": platform.platform(),
                "Python": platform.python_version(),
                "Architecture": platform.machine(),
                "Processor": platform.processor(),
            },
            "Python platform/socket",
        )
    )
    commands = [
        (["wmic", "os", "get", "/format:list"], "o", "Operating System", "operating_system", "os", ["Caption", "Name"]),
        (["wmic", "computersystem", "get", "/format:list"], "g", "System Overview", "computer_system", "system", ["Name", "Model"]),
        (["wmic", "bios", "get", "/format:list"], "b", "BIOS Version", "bios", "bios", ["Name", "SMBIOSBIOSVersion"]),
        (["wmic", "cpu", "get", "/format:list"], "p", "Processor", "processor", "processor", ["Name"]),
        (["wmic", "memorychip", "get", "/format:list"], "m", "Memory", "memory_module", "memory", ["DeviceLocator", "BankLabel", "PartNumber"]),
        (["wmic", "diskdrive", "get", "/format:list"], "i", "Physical Disks", "physical_disk", "disk", ["Model", "Caption"]),
        (["wmic", "logicaldisk", "get", "/format:list"], "d", "Drives", "drive", "drive", ["DeviceID", "Name"]),
        (["wmic", "path", "Win32_DesktopMonitor", "get", "/format:list"], "D", "Display Capabilities", "display", "display", ["Name", "PNPDeviceID"]),
        (["wmic", "path", "Win32_PnPEntity", "get", "/format:list"], "z", "Devices", "device", "device", ["Name", "DeviceID"]),
        (["wmic", "printer", "get", "/format:list"], "I", "Installed Printers", "printer", "printer", ["Name"]),
    ]
    for command, category_id, category_name, object_type, module, title_fields in commands:
        found, diag = _objects_from_wmic(command, category_id, category_name, object_type, module, title_fields, timeout=25)
        objects.extend(found)
        diagnostics.extend(diag)
    ports, result = run_powershell_json("Get-CimInstance Win32_SerialPort | Select-Object Name,DeviceID,Description", timeout=20)
    if ports:
        for port in ports:
            objects.append(_object("c", "Communication Ports", "communication_port", str(port.get("Name") or port.get("DeviceID")), port, "PowerShell CIM", raw=port))
    elif not result.ok:
        diagnostics.append(_diagnostic("communication_ports", "info", result.stderr or "No serial ports", "PowerShell CIM"))
    smbios_queries = [
        ("Base Board", "base_board", "Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,SerialNumber,Version", ["Product", "Manufacturer"]),
        ("Chassis", "chassis", "Get-CimInstance Win32_SystemEnclosure | Select-Object Manufacturer,ChassisTypes,SerialNumber,SMBIOSAssetTag", ["Manufacturer", "SerialNumber"]),
        ("Cache", "cache", "Get-CimInstance Win32_CacheMemory | Select-Object Name,BlockSize,CacheSpeed,CacheType,InstalledSize,Level", ["Name", "Level"]),
        ("Memory Array", "memory_array", "Get-CimInstance Win32_PhysicalMemoryArray | Select-Object MemoryDevices,MaxCapacity,Use,Location,MemoryErrorCorrection", ["Location", "Use"]),
        ("Port Connector", "port_connector", "Get-CimInstance Win32_PortConnector | Select-Object Tag,ConnectorType,ExternalReferenceDesignator,InternalReferenceDesignator,PortType", ["Tag", "ExternalReferenceDesignator"]),
        ("System Slots", "system_slot", "Get-CimInstance Win32_SystemSlot | Select-Object SlotDesignation,ConnectorPinout,CurrentUsage,Status,SupportsHotPlug", ["SlotDesignation", "Status"]),
    ]
    for category_name, object_type, script, title_fields in smbios_queries:
        records, result = run_powershell_json(script, timeout=25)
        if records:
            for record in records:
                title = next((str(record.get(field)) for field in title_fields if record.get(field)), object_type)
                objects.append(_object("M", category_name, object_type, title, record, "PowerShell CIM", raw=record))
        elif not result.ok:
            diagnostics.append(_diagnostic(object_type, "info", result.stderr or f"{category_name} unavailable", "PowerShell CIM"))
    return objects, diagnostics


def _registry_software() -> tuple[list[InventoryObject], list[CollectorDiagnostic]]:
    objects: list[InventoryObject] = []
    diagnostics: list[CollectorDiagnostic] = []
    roots = [(winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")]
    views = [0]
    for flag in ("KEY_WOW64_64KEY", "KEY_WOW64_32KEY"):
        value = getattr(winreg, flag, None)
        if value and value not in views:
            views.append(value)
    base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    for root, root_name in roots:
        for view in views:
            try:
                with winreg.OpenKey(root, base, 0, winreg.KEY_READ | view) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            sub_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, sub_name) as sub:
                                fields: dict[str, str] = {}
                                for name in ("DisplayName", "DisplayVersion", "Publisher", "InstallDate", "InstallLocation", "UninstallString"):
                                    try:
                                        fields[name] = str(winreg.QueryValueEx(sub, name)[0])
                                    except OSError:
                                        pass
                                if fields.get("DisplayName"):
                                    title = fields["DisplayName"]
                                    fields["RegistryView"] = "32-bit" if view == getattr(winreg, "KEY_WOW64_32KEY", -1) else "64-bit/default"
                                    fields["RegistryRoot"] = root_name
                                    objects.append(_object("s", "Installed Software", "software", title, fields, "Registry Uninstall", raw=fields))
                        except OSError:
                            continue
            except OSError as exc:
                diagnostics.append(_diagnostic("installed_software", "info", f"{root_name} uninstall view unavailable: {exc}", "Registry"))
    dedup: dict[tuple[str, str, str], InventoryObject] = {}
    for obj in objects:
        key = (
            str(obj.fields.get("DisplayName", obj.title)).lower(),
            str(obj.fields.get("DisplayVersion", "")).lower(),
            str(obj.fields.get("Publisher", "")).lower(),
        )
        dedup.setdefault(key, obj)
    return list(dedup.values()), diagnostics


def _registry_active_setup() -> tuple[list[InventoryObject], list[CollectorDiagnostic]]:
    objects: list[InventoryObject] = []
    diagnostics: list[CollectorDiagnostic] = []
    roots = [(winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")]
    views = _registry_views()
    base = r"SOFTWARE\Microsoft\Active Setup\Installed Components"
    for root, root_name in roots:
        for view in views:
            try:
                with winreg.OpenKey(root, base, 0, winreg.KEY_READ | view) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            sub_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, sub_name) as sub:
                                fields = _registry_values(sub)
                                fields["Component Key"] = sub_name
                                fields["RegistryRoot"] = root_name
                                fields["RegistryView"] = _registry_view_name(view)
                                title = str(fields.get("ComponentID") or fields.get("Name") or fields.get("(Default)") or sub_name)
                                objects.append(_object("s", "Active Setup", "active_setup", title, fields, "Registry Active Setup", raw=fields))
                        except OSError:
                            continue
            except OSError as exc:
                diagnostics.append(_diagnostic("active_setup", "info", f"{root_name} active setup view unavailable: {exc}", "Registry"))
    return objects, diagnostics


def _registry_odbc_data_sources() -> tuple[list[InventoryObject], list[CollectorDiagnostic]]:
    objects: list[InventoryObject] = []
    diagnostics: list[CollectorDiagnostic] = []
    roots = [(winreg.HKEY_LOCAL_MACHINE, "System"), (winreg.HKEY_CURRENT_USER, "User")]
    base = r"SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources"
    for root, scope in roots:
        for view in _registry_views():
            try:
                with winreg.OpenKey(root, base, 0, winreg.KEY_READ | view) as key:
                    for name, value, value_type in _registry_enum_values(key):
                        fields = {"Name": name, "Driver": _registry_value_to_str(value), "Scope": scope, "RegistryView": _registry_view_name(view)}
                        objects.append(_object("C", "ODBC Data Sources", "odbc_data_source", name, fields, "Registry ODBC", raw=fields))
            except OSError as exc:
                diagnostics.append(_diagnostic("odbc_data_sources", "info", f"{scope} ODBC data sources unavailable: {exc}", "Registry"))
    return objects, diagnostics


def _registry_views() -> list[int]:
    views = [0]
    for flag in ("KEY_WOW64_64KEY", "KEY_WOW64_32KEY"):
        value = getattr(winreg, flag, None)
        if value and value not in views:
            views.append(value)
    return views


def _registry_view_name(view: int) -> str:
    if view == getattr(winreg, "KEY_WOW64_32KEY", -1):
        return "32-bit"
    if view == getattr(winreg, "KEY_WOW64_64KEY", -1):
        return "64-bit"
    return "default"


def _registry_enum_values(key) -> list[tuple[str, object, int]]:
    values: list[tuple[str, object, int]] = []
    for i in range(winreg.QueryInfoKey(key)[1]):
        try:
            name, value, value_type = winreg.EnumValue(key, i)
            values.append((name or "(Default)", value, value_type))
        except OSError:
            continue
    return values


def _registry_values(key) -> dict[str, str]:
    return {name: _registry_value_to_str(value) for name, value, _value_type in _registry_enum_values(key)}


def _registry_value_to_str(value: object) -> str:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    return str(value)


def collect_software_execution() -> tuple[list[InventoryObject], list[CollectorDiagnostic]]:
    objects, diagnostics = _registry_software()
    active_setup, diag = _registry_active_setup()
    objects.extend(active_setup)
    diagnostics.extend(diag)
    updates, diag = _objects_from_wmic(["wmic", "qfe", "get", "/format:list"], "s", "Software Updates", "software_update", "updates", ["HotFixID", "Caption"])
    objects.extend(updates)
    diagnostics.extend(diag)
    wua_updates, result = run_powershell_json(
        "$s=New-Object -ComObject Microsoft.Update.Session; $q=$s.CreateUpdateSearcher(); "
        "$n=[Math]::Min($q.GetTotalHistoryCount(),100); if($n -gt 0){$q.QueryHistory(0,$n) | "
        "Select-Object Title,Date,ResultCode,Operation,ClientApplicationID}",
        timeout=45,
    )
    if wua_updates:
        for update in wua_updates:
            title = str(update.get("Title") or "Windows Update history item")
            objects.append(_object("s", "Software Updates", "wua_update", title, update, "Windows Update Agent", raw=update))
    elif not result.ok:
        diagnostics.append(_diagnostic("software_updates", "info", result.stderr or "Windows Update Agent history unavailable", "PowerShell COM"))
    services, diag = _objects_from_wmic(["wmic", "service", "get", "/format:list"], "A", "Services and Drivers", "service", "services", ["DisplayName", "Name"], timeout=30)
    objects.extend(services)
    diagnostics.extend(diag)
    signed_drivers, result = run_powershell_json(
        "Get-CimInstance Win32_PnPSignedDriver | "
        "Select-Object DeviceName,DriverProviderName,DriverVersion,IsSigned,Signer,InfName,DriverDate,Manufacturer",
        timeout=45,
    )
    if signed_drivers:
        for driver in signed_drivers:
            title = str(driver.get("DeviceName") or driver.get("InfName") or "Driver")
            objects.append(_object("A", "Services and Drivers", "driver", title, driver, "PowerShell CIM", raw=driver))
    else:
        if not result.ok:
            diagnostics.append(_diagnostic("drivers", "info", result.stderr or "Signed driver query unavailable", "PowerShell CIM"))
        drivers, diag = _objects_from_wmic(["wmic", "sysdriver", "get", "/format:list"], "A", "Services and Drivers", "driver", "drivers", ["DisplayName", "Name"], timeout=30)
        objects.extend(drivers)
        diagnostics.extend(diag)
    processes, diag = _objects_from_wmic(["wmic", "process", "get", "Name,ProcessId,ExecutablePath,CommandLine", "/format:list"], "r", "Running Programs", "process", "processes", ["Name"], timeout=30)
    objects.extend(processes)
    diagnostics.extend(diag)
    tasks, result = run_powershell_json(
        "Get-ScheduledTask | ForEach-Object { "
        "$executes = @($_.Actions | ForEach-Object { $_.Execute }) -join '; '; "
        "$arguments = @($_.Actions | ForEach-Object { $_.Arguments }) -join '; '; "
        "[pscustomobject]@{TaskName=$_.TaskName;TaskPath=$_.TaskPath;State=$_.State;Execute=$executes;Arguments=$arguments} "
        "}",
        timeout=45,
    )
    if tasks:
        for task in tasks:
            objects.append(_object("T", "Scheduled Tasks", "scheduled_task", str(task.get("TaskName", "Task")), task, "PowerShell ScheduledTasks", raw=task))
    elif not result.ok:
        diagnostics.append(_diagnostic("scheduled_tasks", "warning", result.stderr or "Scheduled task query unavailable", "PowerShell"))
    startups, result = run_powershell_json(
        "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User", timeout=20
    )
    if startups:
        for item in startups:
            objects.append(_object("S", "Startup Programs", "startup_program", str(item.get("Name", "Startup")), item, "PowerShell CIM", raw=item))
    return objects, diagnostics


def collect_accounts_security() -> tuple[list[InventoryObject], list[CollectorDiagnostic]]:
    objects: list[InventoryObject] = []
    diagnostics: list[CollectorDiagnostic] = []
    users, diag = _objects_from_wmic(["wmic", "useraccount", "get", "/format:list"], "u", "Users", "user", "users", ["Name", "SID"], timeout=25)
    diagnostics.extend(diag)
    for user in users:
        detail = run_command(["net", "user", user.title], timeout=15)
        fields = dict(user.fields)
        if detail.ok:
            fields.update(parse_net_user_detail(detail.stdout))
        annotate_user_password_age(fields)
        objects.append(_object("u", "Users", "user", user.title, fields, "WMIC + net user", raw=fields))
    groups, diag = _objects_from_wmic(["wmic", "group", "get", "/format:list"], "u", "Groups", "group", "groups", ["Name"], timeout=20)
    objects.extend(groups)
    diagnostics.extend(diag)
    net_accounts = run_command(["net", "accounts"], timeout=15)
    if net_accounts.ok:
        fields = parse_net_user_detail(net_accounts.stdout.replace(":", "  "))
        if not fields:
            fields = {"Policy": net_accounts.stdout.strip()}
        objects.append(_object("x", "Security", "password_policy", "Password and lockout policy", fields, "net accounts"))
    else:
        diagnostics.append(_diagnostic("password_policy", "warning", net_accounts.stderr or "net accounts failed", "net accounts"))
    audit = run_command(["auditpol", "/get", "/category:*"], timeout=20)
    if audit.ok:
        objects.append(_object("x", "Security", "audit_policy", "Audit Policy", {"Policy": audit.stdout.strip()}, "auditpol"))
    else:
        diagnostics.append(_diagnostic("audit_policy", "info", audit.stderr or "auditpol unavailable", "auditpol"))
    reg_security = run_command(
        [
            "reg",
            "query",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System",
        ],
        timeout=15,
    )
    if reg_security.ok:
        objects.append(_object("x", "Security", "uac_policy", "UAC and system policies", {"Registry": reg_security.stdout.strip()}, "Registry"))
    registry_security_paths = [
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application",
        r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security",
        r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    ]
    for path in registry_security_paths:
        result = run_command(["reg", "query", path], timeout=15)
        if result.ok:
            for row in parse_reg_query_values(result.stdout):
                objects.append(_object("x", "Registry Security Values", "registry_security_value", row["Subkey"], row, "Registry", raw=row))
        else:
            diagnostics.append(_diagnostic("registry_security", "info", result.stderr or f"{path} unavailable", "Registry"))
    ntp = run_command(["w32tm", "/query", "/configuration"], timeout=20)
    if ntp.ok:
        objects.append(_object("x", "Network Time Protocol", "network_time_protocol", "Windows Time configuration", {"Configuration": ntp.stdout.strip()}, "w32tm"))
    else:
        diagnostics.append(_diagnostic("network_time_protocol", "info", ntp.stderr or "w32tm unavailable", "w32tm"))
    firewall = run_command(["netsh", "advfirewall", "show", "allprofiles"], timeout=25)
    if firewall.ok:
        objects.append(_object("x", "Windows Firewall", "windows_firewall", "Windows Firewall profiles", {"Profiles": firewall.stdout.strip()}, "netsh advfirewall"))
    else:
        diagnostics.append(_diagnostic("windows_firewall", "warning", firewall.stderr or "Firewall query failed", "netsh advfirewall"))
    privileges = run_command(["whoami", "/priv", "/fo", "csv"], timeout=15)
    if privileges.ok:
        for row in parse_csv_table(privileges.stdout):
            title = str(row.get("Privilege Name") or row.get("Privilege") or "Privilege")
            objects.append(_object("x", "User Privileges", "user_privilege", title, row, "whoami /priv", raw=row))
    else:
        diagnostics.append(_diagnostic("user_privileges", "info", privileges.stderr or "whoami privileges unavailable", "whoami"))
    objects.extend(_secedit_user_rights(diagnostics))
    restore_points, result = run_powershell_json("Get-ComputerRestorePoint | Select-Object SequenceNumber,Description,CreationTime,RestorePointType", timeout=30)
    if restore_points:
        for restore_point in restore_points:
            title = str(restore_point.get("Description") or restore_point.get("SequenceNumber") or "Restore point")
            objects.append(_object("x", "System Restore", "system_restore_point", title, restore_point, "PowerShell Get-ComputerRestorePoint", raw=restore_point))
    elif not result.ok:
        diagnostics.append(_diagnostic("system_restore", "info", result.stderr or "System restore points unavailable", "PowerShell"))
    return objects, diagnostics


def _secedit_user_rights(diagnostics: list[CollectorDiagnostic]) -> list[InventoryObject]:
    objects: list[InventoryObject] = []
    cfg_path = Path(tempfile.gettempdir()) / f"ib_audit_user_rights_{os.getpid()}.inf"
    result = run_command(["secedit", "/export", "/cfg", str(cfg_path), "/areas", "USER_RIGHTS"], timeout=30)
    if not result.ok or not cfg_path.exists():
        diagnostics.append(_diagnostic("user_rights", "info", result.stderr or "secedit user rights export unavailable", "secedit"))
        return objects
    try:
        data = cfg_path.read_bytes()
        try:
            text = data.decode("utf-16")
        except UnicodeError:
            text = data.decode("utf-8", errors="replace")
        for line in text.splitlines():
            if not line.startswith("Se") or "=" not in line:
                continue
            policy, setting = (part.strip() for part in line.split("=", 1))
            fields = {"Policy": policy, "Security Setting": setting}
            objects.append(_object("x", "User Rights Assignment", "user_right", policy, fields, "secedit", raw=fields))
    finally:
        try:
            cfg_path.unlink()
        except OSError:
            pass
    return objects


def collect_network_resources() -> tuple[list[InventoryObject], list[CollectorDiagnostic]]:
    objects: list[InventoryObject] = []
    diagnostics: list[CollectorDiagnostic] = []
    ipconfig = run_command(["ipconfig", "/all"], timeout=20)
    if ipconfig.ok:
        adapters = parse_ipconfig_all(ipconfig.stdout)
        for adapter in adapters:
            title = str(adapter.get("Description") or adapter.get("Adapter") or "Network adapter")
            objects.append(_object("t", "Network TCP/IP", "network_adapter", title, adapter, "ipconfig /all", raw=adapter))
        if not adapters:
            diagnostics.append(_diagnostic("network", "info", "ipconfig returned no parseable adapters; using CIM fallback", "ipconfig /all"))
    else:
        diagnostics.append(_diagnostic("network", "warning", ipconfig.stderr or "ipconfig failed", "ipconfig"))
    if not any(obj.category_name == "Network TCP/IP" for obj in objects):
        adapter_configs, result = run_powershell_json(
            "Get-CimInstance Win32_NetworkAdapterConfiguration | "
            "Where-Object {$_.IPEnabled -eq $true} | "
            "Select-Object Description,Caption,MACAddress,DHCPEnabled,IPAddress,IPSubnet,DefaultIPGateway,DNSServerSearchOrder",
            timeout=30,
        )
        if adapter_configs:
            for record in adapter_configs:
                fields = _network_adapter_from_cim(record)
                title = str(fields.get("Description") or "Network adapter")
                objects.append(_object("t", "Network TCP/IP", "network_adapter", title, fields, "PowerShell CIM", raw=record))
        elif not result.ok:
            diagnostics.append(_diagnostic("network", "warning", result.stderr or "CIM network adapter query failed", "PowerShell CIM"))
        else:
            diagnostics.append(_diagnostic("network", "info", "No IP-enabled network adapters returned by CIM", "PowerShell CIM"))
    process_names = _process_name_map(diagnostics)
    netstat = run_command(["netstat", "-ano"], timeout=20)
    if netstat.ok:
        ports, capped = parse_netstat_ano(netstat.stdout, process_names, limit=100000)
        for fields in ports:
            local = f"{fields.get('Local Address')}:{fields.get('Local Port')}".strip(":")
            title = f"{fields.get('Port Protocol')} {local}".strip()
            objects.append(_object("t", "Open Ports", "open_port", title, fields, "netstat -ano + Win32_Process", raw=fields))
        if capped:
            diagnostics.append(_diagnostic("open_ports", "warning", "Open port list capped at 100000 records", "netstat -ano"))
    else:
        diagnostics.append(_diagnostic("open_ports", "warning", netstat.stderr or "netstat failed", "netstat -ano"))
    route = run_command(["route", "print", "-4"], timeout=20)
    if route.ok:
        for fields in parse_route_print(route.stdout):
            title = f"{fields.get('Destination')} via {fields.get('Next Hop')}"
            objects.append(_object("t", "Routing Table", "route", title, fields, "route print -4", raw=fields))
    else:
        diagnostics.append(_diagnostic("routing_table", "info", route.stderr or "route print failed", "route print"))
    shares = run_command(["net", "share"], timeout=15)
    if shares.ok:
        objects.append(_object("N", "Windows Network", "network_shares", "Network Shares", {"Shares": shares.stdout.strip()}, "net share"))
    else:
        diagnostics.append(_diagnostic("network_shares", "info", shares.stderr or "net share unavailable", "net share"))
    sessions = run_command(["net", "session"], timeout=15)
    if sessions.ok:
        objects.append(_object("N", "Windows Network", "network_sessions", "Network Sessions", {"Sessions": sessions.stdout.strip()}, "net session"))
    else:
        diagnostics.append(_diagnostic("network_sessions", "info", sessions.stderr or "net session requires admin", "net session"))
    return objects, diagnostics


def collect_network_intelligence(
    config: NetworkScanConfig,
    progress: ProgressCallback = None,
) -> tuple[list[InventoryObject], list[CollectorDiagnostic]]:
    services, captures, diagnostics = collect_network_intelligence_data(config, progress=progress)
    if not services and not captures:
        return [], diagnostics
    objects: list[InventoryObject] = []
    for service in services:
        fields = dict(service.fields)
        title = str(service.title or "Unknown service")
        objects.append(
            _object(
                "N",
                "Network Service Discovery",
                "network_service",
                title,
                fields,
                "nmap",
                raw=fields,
                confidence="medium",
            )
        )
    for capture in captures:
        fields = dict(capture.fields)
        source = str(fields.get("Source") or "")
        destination = str(fields.get("Destination") or "")
        source_port = str(fields.get("Source Port") or "")
        destination_port = str(fields.get("Destination Port") or "")
        protocol = str(fields.get("Protocol") or "")
        packets = str(fields.get("Packets") or "")
        title = f"{source}:{source_port} -> {destination}:{destination_port} ({protocol}) [{packets} pkt]"
        objects.append(
            _object(
                "N",
                "Network Traffic Capture",
                "network_capture",
                title,
                fields,
                "tshark",
                raw=fields,
                confidence="medium",
            )
        )
    return objects, diagnostics


def _process_name_map(diagnostics: list[CollectorDiagnostic]) -> dict[str, str]:
    processes, result = run_powershell_json("Get-CimInstance Win32_Process | Select-Object ProcessId,Name", timeout=30)
    if not processes:
        if not result.ok:
            diagnostics.append(_diagnostic("process_map", "info", result.stderr or "Process map unavailable", "PowerShell CIM"))
        return {}
    return {str(item.get("ProcessId")): str(item.get("Name", "")) for item in processes if item.get("ProcessId") is not None}


def _ps_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def collect_events_environment() -> tuple[list[InventoryObject], list[CollectorDiagnostic]]:
    objects: list[InventoryObject] = []
    diagnostics: list[CollectorDiagnostic] = []
    objects.append(_object("E", "Environment Variables", "environment", "Process environment", dict(os.environ), "Python os.environ", confidence="medium"))
    objects.append(
        _object(
            "R",
            "Regional Settings",
            "regional_settings",
            "Locale and time",
            {"Locale": ".".join(filter(None, platform.locale.getlocale())) if hasattr(platform, "locale") else "", "Timezone": os.environ.get("TZ", "")},
            "Python platform",
            confidence="medium",
        )
    )
    uptime = run_command(["net", "statistics", "workstation"], timeout=15)
    if uptime.ok:
        objects.append(_object("U", "Uptime Statistics", "uptime", "Workstation statistics", {"Statistics": uptime.stdout.strip()}, "net statistics workstation"))
    else:
        diagnostics.append(_diagnostic("uptime", "info", uptime.stderr or "uptime unavailable", "net statistics"))
    for log_name in ("System", "Application", "Security"):
        script = (
            f"Get-WinEvent -LogName {_ps_single_quote(log_name)} -MaxEvents 10 | ForEach-Object {{ "
            "$time = if ($_.TimeCreated) { $_.TimeCreated.ToString('o') } else { $null }; "
            "[pscustomobject]@{LogName=$_.LogName;ProviderName=$_.ProviderName;TimeCreated=$time;"
            "Id=$_.Id;LevelDisplayName=$_.LevelDisplayName;Message=$_.Message} "
            "}"
        )
        events, result = run_powershell_json(
            script,
            timeout=30,
        )
        if events:
            category = "Security Log" if log_name == "Security" else "Error Logs"
            category_id = "x" if log_name == "Security" else "e"
            for event in events[:10]:
                fields = {
                    "LogName": event.get("LogName") or log_name,
                    "ProviderName": event.get("ProviderName"),
                    "TimeCreated": event.get("TimeCreated"),
                    "Event ID": event.get("Id"),
                    "Level": event.get("LevelDisplayName"),
                    "Message": event.get("Message"),
                }
                title = f"{fields.get('LogName')} {fields.get('Event ID') or 'event'} {fields.get('TimeCreated') or ''}".strip()
                objects.append(_object(category_id, category, "event_log_event", title, fields, "Get-WinEvent", raw=event))
        elif not result.ok:
            diagnostics.append(_diagnostic("event_logs", "info", f"{log_name}: {result.stderr or 'unavailable'}", "Get-WinEvent"))
        else:
            diagnostics.append(_diagnostic("event_logs", "info", f"{log_name}: no events returned", "Get-WinEvent"))
    return objects, diagnostics


def collect_data_providers() -> tuple[list[InventoryObject], list[CollectorDiagnostic]]:
    objects: list[InventoryObject] = []
    diagnostics: list[CollectorDiagnostic] = []
    data_sources, diag = _registry_odbc_data_sources()
    objects.extend(data_sources)
    diagnostics.extend(diag)
    odbc = run_command(["reg", "query", r"HKLM\SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers"], timeout=15)
    if odbc.ok:
        rows = parse_reg_query_values(odbc.stdout)
        if rows:
            for row in rows:
                title = row["Subkey"].split("\\")[-1]
                objects.append(_object("C", "ODBC Drivers", "odbc_driver", title, row, "Registry", raw=row))
        else:
            objects.append(_object("C", "ODBC Drivers", "odbc_drivers", "ODBC Drivers", {"Drivers": odbc.stdout.strip()}, "Registry"))
    else:
        diagnostics.append(_diagnostic("odbc", "info", odbc.stderr or "ODBC registry unavailable", "Registry"))
    oledb = run_command(["reg", "query", r"HKCR\CLSID", "/s", "/f", "OLE DB Provider"], timeout=25)
    if oledb.ok:
        objects.append(_object("O", "OLE DB Drivers", "oledb_providers", "OLE DB Providers", {"Providers": oledb.stdout[:12000]}, "Registry search", confidence="medium"))
    else:
        diagnostics.append(_diagnostic("oledb", "info", oledb.stderr or "OLE DB provider search unavailable", "Registry"))
    return objects, diagnostics


def get_collectors(
    network_scan_config: NetworkScanConfig | None = None, *, only_network: bool = False
) -> list[Collector]:
    from .security_collectors import collect_security_inventory

    collectors: list[Collector] = []
    network_intelligence_collector = (
        Collector(
            "network_intelligence",
            "N",
            "Network Intelligence",
            lambda progress=None: collect_network_intelligence(network_scan_config, progress=progress),
        )
        if network_scan_config and network_scan_config.enabled
        else None
    )

    if only_network and network_intelligence_collector is not None:
        collectors.append(network_intelligence_collector)

    collectors.append(
        Collector("network_resources", "t", "Network and Local Resources", _collector_without_progress(collect_network_resources))
    )

    if not only_network:
        collectors.extend(
            [
                Collector("system_hardware", "g", "System and Hardware", _collector_without_progress(collect_system_hardware)),
                Collector("software_execution", "s", "Software, Updates, and Execution", _collector_without_progress(collect_software_execution)),
                Collector("accounts_security", "u", "Accounts and Security", _collector_without_progress(collect_accounts_security)),
                Collector("events_environment", "e", "Events and Activity", _collector_without_progress(collect_events_environment)),
                Collector("data_providers", "C", "Data Providers", _collector_without_progress(collect_data_providers)),
                Collector("security_posture", "x", "Structured Security Posture", _collector_without_progress(collect_security_inventory)),
            ]
        )

    if not only_network and network_intelligence_collector is not None:
        collectors.append(network_intelligence_collector)
    return collectors
