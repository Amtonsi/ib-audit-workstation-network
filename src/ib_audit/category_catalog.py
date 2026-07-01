from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class CategoryDefinition:
    name: str
    object_type: str


_CATEGORY_PAIRS = [
    ("System Overview", "system"), ("Installed Software", "software"),
    ("Active Setup", "active_setup"), ("Software Updates", "software_update"),
    ("Operating System", "operating_system"), ("Security", "security"),
    ("Kerberos Tickets", "kerberos_ticket"), ("Network Time Protocol", "network_time_protocol"),
    ("Permissions", "permission"), ("Registry Security Values", "registry_security_value"),
    ("Security Settings", "security_setting"), ("System Restore", "system_restore"),
    ("User Privileges", "user_privilege"), ("User Rights Assignment", "user_right"),
    ("Windows Firewall", "windows_firewall"), ("Groups", "group"), ("Users", "user"),
    ("Scheduled Tasks", "scheduled_task"), ("Uptime Statistics", "uptime"),
    ("Environment Variables", "environment_variable"), ("Regional Settings", "regional_settings"),
    ("Windows Network", "windows_network"), ("Network TCP/IP", "network_adapter"),
    ("Open Ports", "open_port"), ("Routing Table", "route"), ("Devices", "device"),
    ("Display Capabilities", "display"), ("Display Adapters", "display_adapter"),
    ("Installed Printers", "printer"), ("BIOS Version", "bios"), ("Base Board", "base_board"),
    ("Chassis", "chassis"), ("Processor", "processor"), ("Cache", "cache"),
    ("Memory Array", "memory_array"), ("Memory", "memory_module"),
    ("Physical Disks", "physical_disk"), ("Drives", "drive"),
    ("Communication Ports", "communication_port"), ("Startup Programs", "startup_program"),
    ("Services and Drivers", "service_or_driver"), ("Running Programs", "process"),
    ("ODBC Information", "odbc_information"), ("ODBC Data Sources", "odbc_data_source"),
    ("ODBC Drivers", "odbc_driver"), ("OLE DB Drivers", "oledb_provider"),
]

WINAUDIT_CATEGORIES = tuple(CategoryDefinition(*pair) for pair in _CATEGORY_PAIRS)
WINAUDIT_CATEGORY_ORDER = tuple(item.name for item in WINAUDIT_CATEGORIES)
_BY_NAME = {item.name.casefold(): item for item in WINAUDIT_CATEGORIES}
_ALIASES = {
    "installed programs": "Installed Software",
    "установленные программы": "Installed Software",
    "обзор системы": "System Overview",
    "операционная система": "Operating System",
    "службы и драйвера": "Services and Drivers",
    "службы и драйверы": "Services and Drivers",
}


def category_for_name(name: str) -> CategoryDefinition:
    cleaned = re.sub(r"^\s*\d+\)\s*", "", name).strip()
    canonical = _ALIASES.get(cleaned.casefold(), cleaned)
    return _BY_NAME.get(canonical.casefold(), CategoryDefinition(canonical or "Unknown", "unknown"))


def category_id_for_name(name: str) -> str:
    canonical = category_for_name(name).name
    return re.sub(r"[^a-z0-9]+", "-", canonical.casefold()).strip("-") or "unknown"
