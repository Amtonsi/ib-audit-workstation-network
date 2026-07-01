from __future__ import annotations

from .category_catalog import WINAUDIT_CATEGORIES, category_id_for_name
from .commands import run_powershell_json
from .models import CollectorDiagnostic, InventoryObject


def _objects(
    category: str,
    object_type: str,
    title_key: str,
    rows: list[dict[str, object]],
    source: str,
) -> list[InventoryObject]:
    return [
        InventoryObject(
            category_id_for_name(category), category, object_type,
            str(row.get(title_key) or object_type), row, source, raw=row.copy(),
        )
        for row in rows
    ]


def parse_firewall_profiles(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {
            "Name": row.get("Name", "Unknown"),
            "Enabled": row.get("Enabled"),
            "DefaultInboundAction": row.get("DefaultInboundAction", ""),
            "DefaultOutboundAction": row.get("DefaultOutboundAction", ""),
        }
        for row in rows
    ]


def collect_security_posture() -> tuple[list[InventoryObject], list[CollectorDiagnostic]]:
    queries = [
        ("Security Settings", "uac_setting", "UAC",
         "Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System | "
         "Select-Object EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop"),
        ("Security Settings", "defender_status", "Microsoft Defender",
         "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
         "BehaviorMonitorEnabled,IoavProtectionEnabled,IsTamperProtected"),
        ("Security Settings", "smb_configuration", "SMB server",
         "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,"
         "EncryptData,RequireSecuritySignature"),
        ("Security Settings", "remote_desktop", "Remote Desktop",
         "$r=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server';"
         "$n=Get-CimInstance -Namespace root\\cimv2\\terminalservices -ClassName Win32_TSGeneralSetting "
         "-Filter \"TerminalName='RDP-tcp'\";[pscustomobject]@{fDenyTSConnections=$r.fDenyTSConnections;"
         "UserAuthentication=$n.UserAuthenticationRequired}"),
    ]
    objects: list[InventoryObject] = []
    diagnostics: list[CollectorDiagnostic] = []
    for category, object_type, title, script in queries:
        rows, result = run_powershell_json(script, timeout=30)
        if result.ok and rows:
            for row in rows:
                objects.append(
                    InventoryObject(
                        category_id_for_name(category), category, object_type, title,
                        row, "PowerShell", raw=row.copy(),
                    )
                )
        else:
            diagnostics.append(
                CollectorDiagnostic(object_type, "warning", result.stderr or "No records returned", "PowerShell")
            )
    firewall_rows, result = run_powershell_json(
        "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction",
        timeout=30,
    )
    if result.ok and firewall_rows:
        objects.extend(_objects(
            "Windows Firewall", "windows_firewall", "Name",
            parse_firewall_profiles(firewall_rows), "PowerShell Get-NetFirewallProfile",
        ))
    else:
        diagnostics.append(
            CollectorDiagnostic("windows_firewall", "warning", result.stderr or "No profiles returned", "PowerShell")
        )
    return objects, diagnostics


def collect_security_inventory() -> tuple[list[InventoryObject], list[CollectorDiagnostic]]:
    objects, diagnostics = collect_security_posture()
    extra_queries = [
        ("Services and Drivers", "driver", "DeviceName",
         "Get-CimInstance Win32_PnPSignedDriver | Select-Object DeviceName,DriverProviderName,"
         "DriverVersion,IsSigned,InfName,DeviceID"),
        ("Display Adapters", "display_adapter", "Name",
         "Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,VideoProcessor,AdapterRAM,Status"),
        ("Scheduled Tasks", "scheduled_task", "TaskName",
         "Get-ScheduledTask | ForEach-Object {$t=$_;$a=$t.Actions|Select-Object -First 1;"
         "[pscustomobject]@{TaskName=$t.TaskName;TaskPath=$t.TaskPath;State=$t.State;"
         "Execute=$a.Execute;Arguments=$a.Arguments;UserId=$t.Principal.UserId;RunLevel=$t.Principal.RunLevel}}"),
        ("Groups", "group_member", "Name",
         "Get-LocalGroup | ForEach-Object {$g=$_;Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue | "
         "ForEach-Object {[pscustomobject]@{Group=$g.Name;Name=$_.Name;ObjectClass=$_.ObjectClass;"
         "PrincipalSource=$_.PrincipalSource}}}"),
    ]
    for category, object_type, title_key, script in extra_queries:
        rows, result = run_powershell_json(script, timeout=45)
        if result.ok and rows:
            objects.extend(_objects(category, object_type, title_key, rows, "PowerShell"))
        else:
            diagnostics.append(
                CollectorDiagnostic(object_type, "info", result.stderr or "No records returned", "PowerShell")
            )
    return objects, diagnostics


def ensure_category_diagnostics(
    inventory: list[InventoryObject],
    diagnostics: list[CollectorDiagnostic],
) -> list[CollectorDiagnostic]:
    seen = {obj.category_name for obj in inventory}
    return [
        *diagnostics,
        *[
            CollectorDiagnostic(
                "category_coverage", "warning",
                "No inventory object was returned for this WinAudit category.",
                category.name,
            )
            for category in WINAUDIT_CATEGORIES
            if category.name not in seen
        ],
    ]
