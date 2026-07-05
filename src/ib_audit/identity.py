from __future__ import annotations

import re
from dataclasses import dataclass

from .models import InventoryObject


@dataclass(frozen=True)
class InventoryIdentity:
    object_uid: str
    object_type: str
    vendor: str
    product: str
    version: str
    model: str
    variants: tuple[str, ...]
    hardware_ids: tuple[str, ...]

    @property
    def group_key(self) -> tuple[str, str, str, str, tuple[str, ...]]:
        return (
            self.object_type,
            self.vendor,
            self.product,
            self.version,
            self.hardware_ids,
        )


def first_value(fields: dict[str, object], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = fields.get(key)
        if value not in (None, ""):
            text = str(value).strip()
            if text:
                return text
    return ""


def _normalize_text(value: str) -> str:
    value = re.sub(r"\((?:r|tm|c)\)", " ", value, flags=re.IGNORECASE)
    value = value.replace("®", " ").replace("™", " ").replace("©", " ")
    value = re.sub(r"[/_\\]+", " ", value)
    value = re.sub(r"[^a-zA-Z0-9.+-]+", " ", value)
    return re.sub(r"\s+", " ", value).strip().casefold()


def normalize_vendor(value: str) -> str:
    text = _normalize_text(value)
    suffixes = (
        "corporation",
        "corp",
        "incorporated",
        "inc",
        "company",
        "co",
        "limited",
        "ltd",
        "llc",
    )
    tokens = [token.strip(".") for token in text.split()]
    tokens = [token for token in tokens if token and token not in suffixes]
    if len(tokens) > 1 and tokens[-1] == "project":
        tokens = tokens[:-1]
    normalized = " ".join(tokens)
    if (
        "fisher-rosemount" in tokens
        or normalized.startswith("fisher rosemount")
        or normalized.startswith("fisher-rosemount")
        or normalized.startswith("rosemount")
        or normalized.startswith("emerson process management")
        or normalized.startswith("emerson electric")
    ):
        return "emerson"
    if "intel" in tokens:
        return "intel"
    if tokens[:3] == ["advanced", "micro", "devices"]:
        return "advanced micro devices"
    return normalized


def normalize_product(value: str) -> str:
    text = _normalize_text(value)
    text = re.sub(r"\b(?:cpu|processor|processors|ata device)\b", " ", text)
    text = re.sub(r"@\s*\d+(?:\.\d+)?\s*(?:ghz|mhz)", " ", text)
    text = re.sub(r"\b\d+(?:\.\d+)?\s*(?:ghz|mhz)\b", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def derive_product_version(object_type: str, product: str, installed_version: str) -> str:
    if object_type != "software":
        return installed_version
    deltav_version = _deltav_version_from_text(product)
    if deltav_version:
        return deltav_version
    return installed_version


def _deltav_version_from_text(value: str) -> str:
    text = normalize_product(value)
    if "deltav" not in text:
        return ""
    dotted = re.search(r"\bdeltav\s+(\d{1,2})\.(\d{1,2})(?:\.(\d{1,2}))?\b", text)
    if dotted:
        major, minor, patch = dotted.groups()
        parts = [str(int(major)), str(int(minor))]
        if patch is not None:
            parts.append(str(int(patch)))
        return ".".join(parts)
    packed = re.search(r"\bdeltav\s+(\d{4})\b", text)
    if packed:
        digits = packed.group(1)
        return f"{int(digits[:2])}.{int(digits[2])}.{int(digits[3])}"
    return ""


def extract_model(object_type: str, product: str, fields: dict[str, object]) -> str:
    raw = " ".join(
        item
        for item in (
            product,
            str(fields.get("Model") or ""),
            str(fields.get("Processor Description") or ""),
            str(fields.get("Description") or ""),
            str(fields.get("Name") or ""),
        )
        if item
    )
    text = normalize_product(raw)
    if object_type == "processor":
        match = re.search(r"\b(?:e\d{4}|e\d-\d{4}|silver\s+\d{4}|gold\s+\d{4}|platinum\s+\d{4})\b", text)
        if match:
            return match.group(0).replace(" ", "_")
    model = first_value(fields, ("Model", "Board Number", "Product", "ProductName"))
    return normalize_product(model)


def parse_hardware_ids(value: str) -> tuple[str, ...]:
    ids: list[str] = []
    pci = re.search(
        r"VEN_([0-9A-Fa-f]{4}).*?DEV_([0-9A-Fa-f]{4})(?:.*?SUBSYS_([0-9A-Fa-f]{8}))?",
        value,
        flags=re.IGNORECASE,
    )
    if pci:
        vendor, device, subsys = (part.lower() if part else "" for part in pci.groups())
        ids.append(":".join(part for part in ("pci", vendor, device, subsys) if part))
    usb = re.search(
        r"VID_([0-9A-Fa-f]{4}).*?PID_([0-9A-Fa-f]{4})",
        value,
        flags=re.IGNORECASE,
    )
    if usb:
        vendor, product = (part.lower() for part in usb.groups())
        ids.append(f"usb:{vendor}:{product}")
    return tuple(dict.fromkeys(ids))


def build_identity_variants(
    object_type: str,
    vendor: str,
    product: str,
    model: str,
    inventory: list[InventoryObject],
) -> tuple[str, ...]:
    del inventory
    variants: list[str] = []

    def add(value: str) -> None:
        value = normalize_product(value)
        if value and value not in variants:
            variants.append(value)

    add(product)
    deltav_version = _deltav_version_from_text(product)
    if deltav_version:
        add(f"deltav {deltav_version}")
    if vendor == "acronis" and "backup" in product:
        add("acronis cyber backup")
        add("cyber backup")
    if vendor and model:
        add(f"{vendor} {model.replace('_', ' ')}")
    if object_type == "processor" and model:
        if "xeon" in product:
            add(f"xeon {model.replace('_', ' ')}")
        add(f"{model.replace('_', ' ')} firmware")
        add(f"{model.replace('_', ' ')} microcode")
    if object_type in {"bios", "base_board", "device", "display_adapter", "network_adapter", "physical_disk"} and model:
        add(model.replace("_", " "))
        add(f"{model.replace('_', ' ')} firmware")
    return tuple(variants)


class InventoryIdentityResolver:
    FIELD_MAP = {
        "software": {
            "vendor": ("Vendor", "Publisher", "Manufacturer", "CompanyName"),
            "product": ("DisplayName", "Name", "ProductName"),
            "version": ("DisplayVersion", "Version", "FileVersion", "Executable Version"),
        },
        "operating_system": {
            "vendor": ("Manufacturer", "Vendor", "CompanyName"),
            "product": ("Caption", "Operating System", "ProductName", "Name"),
            "version": ("Version", "BuildNumber", "DisplayVersion"),
        },
        "bios": {
            "vendor": ("BIOS Vendor", "Manufacturer", "Vendor"),
            "product": ("ProductName", "Name", "Caption"),
            "version": ("BIOS Version", "SMBIOSBIOSVersion", "FirmwareVersion"),
        },
        "base_board": {
            "vendor": ("Manufacturer", "Vendor"),
            "product": ("Product", "ProductName", "Board Number", "Model", "Name"),
            "version": ("Version", "Revision", "Firmware Revision", "FirmwareVersion"),
        },
        "processor": {
            "vendor": ("Manufacturer", "Vendor"),
            "product": ("Processor Description", "Name", "Description", "Model"),
            "version": ("Microcode Version", "Firmware Revision", "Driver Version"),
        },
        "driver": {
            "vendor": ("Driver Provider", "DriverProviderName", "Provider", "Manufacturer", "Vendor"),
            "product": ("Device Name", "DisplayName", "Name", "Description"),
            "version": ("Driver Version", "DriverVersion", "FileVersion", "Version"),
        },
        "device": {
            "vendor": ("Manufacturer", "Driver Provider", "DriverProviderName"),
            "product": ("Device Name", "Description", "Name"),
            "version": ("Driver Version", "DriverVersion", "Firmware Revision"),
        },
        "display_adapter": {
            "vendor": ("Manufacturer", "Driver Provider", "DriverProviderName"),
            "product": ("Adapter Name", "Device Name", "Description", "Name"),
            "version": ("Driver Version", "DriverVersion", "Firmware Revision"),
        },
        "network_adapter": {
            "vendor": ("Manufacturer", "Driver Provider", "DriverProviderName"),
            "product": ("Adapter Name", "Device Name", "Description", "Name"),
            "version": ("Driver Version", "DriverVersion", "Firmware Revision"),
        },
        "physical_disk": {
            "vendor": ("Manufacturer", "Vendor"),
            "product": ("Model", "Name", "Description"),
            "version": ("Firmware Revision", "FirmwareVersion", "Version"),
        },
    }

    def resolve(
        self,
        obj: InventoryObject,
        inventory: list[InventoryObject],
    ) -> InventoryIdentity:
        mapping = self.FIELD_MAP.get(obj.object_type, self.FIELD_MAP["device"])
        vendor = normalize_vendor(first_value(obj.fields, mapping["vendor"]))
        product = normalize_product(first_value(obj.fields, mapping["product"]) or obj.title)
        version = derive_product_version(obj.object_type, product, first_value(obj.fields, mapping["version"]).strip())
        model = extract_model(obj.object_type, product, obj.fields)
        hardware_ids = parse_hardware_ids(
            " ".join(
                str(obj.fields.get(key) or "")
                for key in ("Device ID", "PNPDeviceID", "Hardware ID", "Hardware IDs")
            )
        )
        variants = build_identity_variants(obj.object_type, vendor, product, model, inventory)
        return InventoryIdentity(
            obj.uid,
            obj.object_type,
            vendor,
            product,
            version,
            model,
            variants,
            hardware_ids,
        )
