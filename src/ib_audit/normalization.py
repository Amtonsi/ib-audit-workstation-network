from __future__ import annotations

from .models import InventoryObject, ProductIdentity, WindowsProfile


IDENTITY_VENDOR_KEYS = ("Vendor", "Publisher", "Manufacturer", "CompanyName", "DriverProviderName", "Provider")
IDENTITY_PRODUCT_KEYS = (
    "DisplayName", "ProductName", "Product", "Model", "Board Number",
    "Caption", "Name", "DeviceName", "Device ID",
)
IDENTITY_VERSION_KEYS = (
    "DisplayVersion", "Version", "FileVersion", "DriverVersion", "SMBIOSBIOSVersion",
    "FirmwareVersion", "BIOS Version", "BuildNumber",
)


def _first(fields: dict[str, object], keys: tuple[str, ...]) -> str:
    return next((str(fields[key]).strip() for key in keys if fields.get(key)), "")


def product_identity(obj: InventoryObject) -> ProductIdentity:
    return ProductIdentity(
        vendor=_first(obj.fields, IDENTITY_VENDOR_KEYS),
        product=_first(obj.fields, IDENTITY_PRODUCT_KEYS) or obj.title.strip(),
        version=_first(obj.fields, IDENTITY_VERSION_KEYS),
        kind=obj.object_type,
    )


def _bool_or_none(value: object) -> bool | None:
    normalized = str(value).strip().casefold()
    if normalized in {"true", "1", "yes", "да"}:
        return True
    if normalized in {"false", "0", "no", "нет"}:
        return False
    return None


def detect_windows_profile(inventory: list[InventoryObject]) -> WindowsProfile:
    os_obj = next((item for item in inventory if item.object_type == "operating_system"), None)
    if os_obj is None:
        return WindowsProfile("windows-unknown-workstation", "Unknown Windows", "", "", "", "", "workstation", None)
    fields = os_obj.fields
    caption = str(fields.get("Caption") or fields.get("Operating System") or os_obj.title)
    version = str(fields.get("Version") or "")
    build = str(fields.get("BuildNumber") or (version.rsplit(".", 1)[-1] if version.count(".") >= 2 else ""))
    product_type = str(fields.get("ProductType") or "")
    role = "server" if product_type in {"2", "3"} or "server" in caption.casefold() else "workstation"
    return WindowsProfile(
        profile_id=f"windows-{build or version or 'unknown'}-{role}",
        caption=caption,
        version=version,
        build=build,
        edition=str(fields.get("OperatingSystemSKU") or fields.get("EditionID") or ""),
        architecture=str(fields.get("OSArchitecture") or fields.get("Architecture") or ""),
        role=role,
        domain_joined=_bool_or_none(fields.get("PartOfDomain")),
    )
