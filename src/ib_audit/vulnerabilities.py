from __future__ import annotations

import json
import hashlib
import re
import urllib.parse
import urllib.request
from typing import Any

from .cancellation import CancellationToken
from .models import CollectorDiagnostic, InventoryObject, SourceSnapshot, VulnerabilityMatch
from .normalization import product_identity
from .source_cache import SnapshotCache


class VulnerabilitySourceClient:
    cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, cache: SnapshotCache | None = None, online: bool = True):
        self.cache = cache
        self.online = online
        self.used_snapshots: list[SourceSnapshot] = []

    def fetch_json(self, url: str, timeout: int = 25) -> dict[str, Any]:
        request = urllib.request.Request(url, headers={"User-Agent": "IB-Audit-Desktop/0.1"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))

    def fetch_cisa_kev(self) -> tuple[list[dict[str, Any]], list[CollectorDiagnostic]]:
        try:
            if self.cache is None:
                if not self.online:
                    raise OSError("offline and no cache configured")
                data = self.fetch_json(self.cisa_kev_url)
                state = "updated"
            else:
                data, snapshot, state = self.cache.get_or_fetch_json(
                    "cisa-kev", "catalog", self.online,
                    lambda: self.fetch_json(self.cisa_kev_url),
                )
                self.used_snapshots.append(snapshot)
            return list(data.get("vulnerabilities", [])), [
                CollectorDiagnostic("vulnerability_sources", "info", state, self.cisa_kev_url)
            ]
        except Exception as exc:
            return [], [CollectorDiagnostic("vulnerability_sources", "warning", f"CISA KEV unavailable: {exc}", self.cisa_kev_url)]

    def fetch_nvd_keyword(self, keyword: str, limit: int = 2000) -> tuple[list[dict[str, Any]], list[CollectorDiagnostic]]:
        query = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": str(limit)})
        url = f"{self.nvd_url}?{query}"
        try:
            if self.cache is None:
                if not self.online:
                    raise OSError("offline and no cache configured")
                data = self.fetch_json(url)
                state = "updated"
            else:
                cache_key = hashlib.sha256(keyword.strip().casefold().encode("utf-8")).hexdigest()
                data, snapshot, state = self.cache.get_or_fetch_json(
                    "nvd", cache_key, self.online, lambda: self.fetch_json(url),
                )
                self.used_snapshots.append(snapshot)
            return [item.get("cve", {}) for item in data.get("vulnerabilities", [])], [
                CollectorDiagnostic("vulnerability_sources", "info", f"{state}: {keyword}", url)
            ]
        except Exception as exc:
            return [], [CollectorDiagnostic("vulnerability_sources", "warning", f"NVD unavailable for {keyword}: {exc}", url)]


class VulnerabilityCorrelator:
    candidate_types = {
        "software", "operating_system", "service", "driver",
        "odbc_driver", "oledb_provider", "bios", "device",
    }
    def __init__(self, fstec_client=None, source_client=None):
        self.fstec_client = fstec_client
        self.source_client = source_client
        self.used_snapshots: list[SourceSnapshot] = []

    def match_inventory(
        self,
        inventory: list[InventoryObject],
        kev_records: list[dict[str, Any]],
        nvd_records: list[dict[str, Any]],
    ) -> list[VulnerabilityMatch]:
        matches: list[VulnerabilityMatch] = []
        seen: set[tuple[str, str]] = set()
        for obj in inventory:
            haystack = self._inventory_text(obj)
            for record in kev_records:
                vendor = str(record.get("vendorProject", ""))
                product = str(record.get("product", ""))
                vulnerability_name = str(record.get("vulnerabilityName", ""))
                cve = str(record.get("cveID", ""))
                if cve and self._contains_product(obj, vendor, product, vulnerability_name):
                    key = (cve, obj.title)
                    if key not in seen:
                        seen.add(key)
                        matches.append(
                            VulnerabilityMatch(
                                cve=cve,
                                source="CISA KEV",
                                severity="HIGH",
                                cvss=None,
                                kev=True,
                                affected_title=obj.title,
                                evidence=f"Matched KEV vendor/product '{vendor} {product}' against '{obj.title}'",
                                confidence="Medium",
                                remediation=str(record.get("requiredAction") or "Apply vendor remediation and updates."),
                                references=[str(record.get("notes"))] if record.get("notes") else [],
                                object_uid=obj.uid,
                            )
                        )
            for record in nvd_records:
                cve = str(record.get("id", ""))
                description = self._description(record)
                configuration_match = self._matches_configurations(obj, record)
                matches_record = configuration_match is True or (
                    configuration_match is None and self._matches_description(obj, description)
                )
                if cve and matches_record:
                    key = (cve, obj.title)
                    if key not in seen:
                        seen.add(key)
                        cvss, severity = self._cvss(record)
                        matches.append(
                            VulnerabilityMatch(
                                cve=cve,
                                source="NVD",
                                severity=severity,
                                cvss=cvss,
                                kev=False,
                                affected_title=obj.title,
                                evidence=f"NVD description matched '{obj.title}' with version/vendor evidence.",
                                confidence="Medium" if self._version(obj) else "Low",
                                remediation=self._generic_remediation(obj),
                                references=self._references(record),
                                object_uid=obj.uid,
                            )
                        )
        return sorted(matches, key=lambda item: (not item.kev, -(item.cvss or 0), item.cve))

    def enrich_from_sources(
        self,
        inventory: list[InventoryObject],
        client: VulnerabilitySourceClient | None = None,
        max_nvd_queries: int | None = None,
        max_matches: int | None = None,
        progress=None,
        cancel_token: CancellationToken | None = None,
    ) -> tuple[list[VulnerabilityMatch], list[CollectorDiagnostic]]:
        token = cancel_token or CancellationToken()
        token.raise_if_cancelled()
        client = client or self.source_client or VulnerabilitySourceClient()
        kev, diagnostics = client.fetch_cisa_kev()
        token.raise_if_cancelled()
        candidate_inventory = [obj for obj in inventory if obj.object_type in self.candidate_types]
        matches = self.match_inventory(candidate_inventory, kev, [])
        keyword_objects = self._keyword_objects(candidate_inventory)
        if max_nvd_queries is not None:
            keyword_objects = keyword_objects[:max_nvd_queries]
        for keyword, obj in keyword_objects:
            token.raise_if_cancelled()
            records, diag = client.fetch_nvd_keyword(keyword)
            token.raise_if_cancelled()
            diagnostics.extend(diag)
            matches.extend(self.match_inventory([obj], [], records))
        if self.fstec_client is not None:
            fstec_matches, fstec_diagnostics = self.fstec_client.match_inventory(
                candidate_inventory,
                progress=progress,
                cancel_token=token,
            )
            matches.extend(fstec_matches)
            diagnostics.extend(fstec_diagnostics)
        deduped: list[VulnerabilityMatch] = []
        seen: set[tuple[str, str, str]] = set()
        for match in sorted(matches, key=lambda item: (not item.kev, -(item.cvss or 0), item.cve, item.affected_title)):
            token.raise_if_cancelled()
            key = (match.cve, match.affected_title, match.source)
            if key not in seen:
                seen.add(key)
                deduped.append(match)
            if max_matches is not None and len(deduped) >= max_matches:
                diagnostics.append(
                    CollectorDiagnostic(
                        "vulnerability_correlation",
                        "warning",
                        f"Match list capped at {max_matches} records to avoid noisy output.",
                        "correlator",
                    )
                )
                break
        self.used_snapshots = list(getattr(client, "used_snapshots", []))
        return deduped, diagnostics

    @staticmethod
    def _inventory_text(obj: InventoryObject) -> str:
        return " ".join([obj.title, obj.object_type, *[str(v) for v in obj.fields.values()]]).lower()

    @classmethod
    def _contains_product(cls, obj: InventoryObject, vendor: str, product: str, vulnerability_name: str = "") -> bool:
        identity_terms = set(cls._match_terms(cls._identity_text(obj)))
        vendor_terms = cls._match_terms(vendor)
        product_terms = cls._match_terms(product)
        if product_terms and vendor_terms and set(product_terms).issubset(set(vendor_terms)):
            product_terms = cls._product_terms_from_vulnerability_name(vulnerability_name, vendor_terms)
        if not product_terms:
            return False
        if vendor_terms and not any(term in identity_terms for term in vendor_terms):
            return False
        if vendor_terms == ["microsoft"] and product_terms == ["windows"]:
            return obj.object_type == "operating_system" and "windows" in identity_terms
        return all(term in identity_terms for term in product_terms)

    @staticmethod
    def _identity_text(obj: InventoryObject) -> str:
        identity_fields = ("DisplayName", "Name", "Caption", "ProductName", "Vendor", "Publisher", "Manufacturer", "CompanyName")
        values = [obj.title, *[str(obj.fields.get(key, "")) for key in identity_fields]]
        return " ".join(value for value in values if value).lower()

    @classmethod
    def _product_terms_from_vulnerability_name(cls, vulnerability_name: str, vendor_terms: list[str]) -> list[str]:
        vulnerability_words = {
            "arbitrary",
            "authentication",
            "bypass",
            "code",
            "command",
            "corruption",
            "cross",
            "day",
            "denial",
            "disclosure",
            "elevation",
            "escalation",
            "execution",
            "feature",
            "file",
            "improper",
            "injection",
            "memory",
            "overflow",
            "privilege",
            "read",
            "remote",
            "scripting",
            "security",
            "site",
            "spoofing",
            "validation",
            "vulnerability",
            "write",
            "zero",
        }
        blocked = vulnerability_words | set(vendor_terms)
        return [term for term in cls._match_terms(vulnerability_name) if term not in blocked][:3]

    @staticmethod
    def _match_terms(text: str) -> list[str]:
        stop_words = {"and", "for", "the", "with", "multiple", "product", "products", "software", "application", "apps"}
        return [word for word in re.findall(r"[a-z0-9]+", text.lower()) if len(word) >= 3 and word not in stop_words]

    @staticmethod
    def _description(record: dict[str, Any]) -> str:
        for item in record.get("descriptions", []):
            if item.get("lang") == "en":
                return str(item.get("value", ""))
        return " ".join(str(item.get("value", "")) for item in record.get("descriptions", []))

    def _matches_description(self, obj: InventoryObject, description: str) -> bool:
        text = self._inventory_text(obj)
        description_l = description.lower()
        title_words = [word for word in re.split(r"\W+", obj.title.lower()) if len(word) >= 4]
        if title_words and all(word in description_l for word in title_words[:2]):
            return True
        vendor = str(obj.fields.get("Vendor") or obj.fields.get("Publisher") or "").lower()
        product = obj.title.lower()
        version = self._version(obj)
        return bool(product and product in description_l and (not vendor or vendor in description_l) and (not version or version in description_l or version in text))

    @staticmethod
    def _version(obj: InventoryObject) -> str:
        for key in ("Version", "DisplayVersion", "FileVersion", "DriverVersion", "SMBIOSBIOSVersion"):
            if obj.fields.get(key):
                return str(obj.fields[key])
        return ""

    @classmethod
    def _matches_configurations(cls, obj: InventoryObject, record: dict[str, Any]) -> bool | None:
        cpe_matches: list[dict[str, Any]] = []
        for configuration in record.get("configurations", []):
            for node in configuration.get("nodes", []):
                cpe_matches.extend(node.get("cpeMatch", []))
        if not cpe_matches:
            return None
        identity = product_identity(obj)
        vendor_tokens = set(cls._match_terms(identity.vendor))
        product_tokens = set(cls._match_terms(identity.product))
        compatible_seen = False
        for item in cpe_matches:
            if not item.get("vulnerable", False):
                continue
            parts = str(item.get("criteria", "")).split(":")
            if len(parts) < 6:
                continue
            cpe_vendor = set(cls._match_terms(parts[3].replace("_", " ")))
            cpe_product = set(cls._match_terms(parts[4].replace("_", " ")))
            if cpe_vendor and vendor_tokens and not cpe_vendor.issubset(vendor_tokens):
                continue
            if cpe_product and not cpe_product.issubset(product_tokens):
                continue
            compatible_seen = True
            if not identity.version:
                return True
            if cls._version_in_range(identity.version, item):
                return True
        return False if compatible_seen else None

    @classmethod
    def _version_in_range(cls, version: str, item: dict[str, Any]) -> bool:
        current = cls._version_tuple(version)
        if current is None:
            return True
        checks = (
            ("versionStartIncluding", lambda value: current >= value),
            ("versionStartExcluding", lambda value: current > value),
            ("versionEndIncluding", lambda value: current <= value),
            ("versionEndExcluding", lambda value: current < value),
        )
        for key, predicate in checks:
            if item.get(key):
                boundary = cls._version_tuple(str(item[key]))
                if boundary is not None and not predicate(boundary):
                    return False
        return True

    @staticmethod
    def _version_tuple(value: str) -> tuple[int, ...] | None:
        numbers = re.findall(r"\d+", value)
        return tuple(map(int, numbers)) if numbers else None

    @staticmethod
    def _cvss(record: dict[str, Any]) -> tuple[float | None, str]:
        metrics = record.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key)
            if values:
                data = values[0].get("cvssData", {})
                return data.get("baseScore"), str(data.get("baseSeverity") or values[0].get("baseSeverity") or "UNKNOWN")
        return None, "UNKNOWN"

    @staticmethod
    def _references(record: dict[str, Any]) -> list[str]:
        references = record.get("references", {})
        if isinstance(references, dict):
            refs = references.get("referenceData", [])
        elif isinstance(references, list):
            refs = references
        else:
            refs = []
        return [str(ref.get("url")) for ref in refs if ref.get("url")][:5]

    @staticmethod
    def _generic_remediation(obj: InventoryObject) -> str:
        if obj.object_type in {"service", "open_port"}:
            return "Update the owning product, restrict exposure with firewall rules, or disable the service if it is not required."
        if obj.category_id == "s":
            return "Update the affected software to a fixed version or remove it if it is not required."
        return "Apply vendor security updates and verify the finding manually."

    @staticmethod
    def _keywords(inventory: list[InventoryObject]) -> list[str]:
        return [keyword for keyword, _obj in VulnerabilityCorrelator._keyword_objects(inventory)]

    @staticmethod
    def _keyword_objects(inventory: list[InventoryObject]) -> list[tuple[str, InventoryObject]]:
        keywords: list[tuple[str, InventoryObject]] = []
        seen: set[str] = set()
        for obj in inventory:
            title = obj.title.strip()
            version = str(obj.fields.get("DisplayVersion") or obj.fields.get("Version") or "").strip()
            keyword = f"{title} {version}".strip()
            if len(keyword) >= 4 and keyword.lower() not in seen:
                seen.add(keyword.lower())
                keywords.append((keyword, obj))
        return keywords
