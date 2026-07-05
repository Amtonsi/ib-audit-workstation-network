from __future__ import annotations

import json
import hashlib
import re
import sqlite3
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .applicability import CpeApplicabilityEvaluator
from .cancellation import CancellationToken
from .cpe_catalog import CpeCandidate, CpeCatalog, CpeResolution
from .identity import InventoryIdentity, InventoryIdentityResolver
from .models import (
    CollectorDiagnostic,
    InventoryObject,
    SourceSnapshot,
    VulnerabilityCoverage,
    VulnerabilityCorrelationResult,
    VulnerabilityMatch,
)
from .normalization import product_identity
from .source_cache import SnapshotCache
from .vulnerability_database import is_vulnerability_database


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


class VulnerabilityDatabaseSourceClient:
    hardware_types = {
        "bios",
        "base_board",
        "device",
        "display_adapter",
        "network_adapter",
        "physical_disk",
        "processor",
    }
    operating_system_types = {"operating_system"}

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.used_snapshots: list[SourceSnapshot] = []
        self._usable_fts: bool | None = None
        self._cpe_catalog = CpeCatalog(self.db_path)
        self._nvd_candidates_cache: dict[
            tuple[str, ...],
            tuple[list[dict[str, Any]], bool, list[CollectorDiagnostic]],
        ] = {}
        self._nvd_product_cache: dict[tuple[str, str, str], dict[str, dict[str, Any]]] = {}
        self._term_query_cache: dict[
            tuple[str, tuple[str, ...], tuple[str, ...], int],
            tuple[list[dict[str, Any]], list[CollectorDiagnostic]],
        ] = {}
        self._affected_alias_cache: dict[
            tuple[tuple[tuple[str, str, str], ...], int],
            list[dict[str, Any]],
        ] = {}
        if not is_vulnerability_database(self.db_path):
            raise ValueError(f"Not a vulnerability database: {self.db_path}")

    def resolve_cpe(self, identity: InventoryIdentity) -> CpeResolution:
        return self._cpe_catalog.resolve(identity)

    def fetch_cisa_kev(self) -> tuple[list[dict[str, Any]], list[CollectorDiagnostic]]:
        try:
            rows = self._fetch_rows("select raw_json from cisa_kev")
            self._record_snapshot()
            return [json.loads(str(row[0])) for row in rows], [
                CollectorDiagnostic("vulnerability_sources", "info", "database: CISA KEV", str(self.db_path))
            ]
        except Exception as exc:
            return [], [
                CollectorDiagnostic("vulnerability_sources", "warning", f"CISA KEV database unavailable: {exc}", str(self.db_path))
            ]

    def fetch_nvd_keyword(self, keyword: str, limit: int = 2000) -> tuple[list[dict[str, Any]], list[CollectorDiagnostic]]:
        terms = self._query_terms(keyword)
        return self._fetch_nvd_by_terms(keyword, terms[:2], (), limit=limit)

    def fetch_nvd_for_object(
        self,
        obj: InventoryObject,
        limit: int = 2000,
    ) -> tuple[list[dict[str, Any]], list[CollectorDiagnostic]]:
        identity = InventoryIdentityResolver().resolve(obj, [obj])
        aliases = self._affected_product_aliases(identity)
        if aliases:
            records = self._query_nvd_affected_product_aliases(aliases, limit)
            if records:
                return records, [
                    CollectorDiagnostic(
                        "vulnerability_sources",
                        "info",
                        f"database affected-product aliases: {obj.title}",
                        str(self.db_path),
                    )
                ]
        terms = self._terms_for_object_query(obj)
        parts = self._cpe_parts_for_object(obj.object_type)
        return self._fetch_nvd_by_terms(obj.title, terms, parts, limit=limit)

    def _terms_for_object_query(self, obj: InventoryObject) -> list[str]:
        identity = InventoryIdentityResolver().resolve(obj, [obj])
        vendor_terms = self._query_terms(identity.vendor)
        product_terms = self._query_terms(" ".join([identity.product, obj.title, *identity.variants]))
        model_terms = self._query_terms(identity.model.replace("_", " "))
        terms: list[str] = []

        def add(value: str) -> None:
            if value and value not in terms:
                terms.append(value)

        for term in vendor_terms[:1]:
            add(term)
        if obj.object_type in self.hardware_types:
            preferred = model_terms or [term for term in product_terms if term not in vendor_terms]
            for term in preferred[:3]:
                add(term)
        else:
            if identity.vendor == "acronis" and "backup" in product_terms and "cyber" in product_terms:
                add("cyber")
                add("backup")
            for term in product_terms:
                add(term)
                if len(terms) >= 3:
                    break
        return terms

    def fetch_nvd_for_candidates(
        self,
        candidates: tuple[CpeCandidate, ...],
    ) -> tuple[list[dict[str, Any]], bool, list[CollectorDiagnostic]]:
        cache_key = tuple(sorted(candidate.cpe.uri for candidate in candidates))
        cached = self._nvd_candidates_cache.get(cache_key)
        if cached is not None:
            return cached
        records: dict[str, dict[str, Any]] = {}
        try:
            self._record_snapshot()
            queried_products: set[tuple[str, str, str]] = set()
            for candidate in candidates:
                product_key = (
                    candidate.cpe.part,
                    candidate.cpe.vendor.replace("_", " "),
                    candidate.cpe.product.replace("_", " "),
                )
                if product_key in queried_products:
                    continue
                queried_products.add(product_key)
                product_records = self._nvd_product_cache.get(product_key)
                if product_records is None:
                    rows = self._fetch_rows(
                        """
                        select distinct c.cve_id, c.raw_json
                        from nvd_cves c
                        join nvd_affected_products p on p.cve_id = c.cve_id
                        where p.part = ? and p.vendor = ? and p.product = ?
                        order by coalesce(c.cvss, 0) desc, c.cve_id
                        """,
                        product_key,
                    )
                    product_records = {}
                    for row in rows:
                        record = json.loads(str(row["raw_json"]))
                        record["_ib_match_requires_configuration"] = True
                        product_records[str(row["cve_id"])] = record
                    self._nvd_product_cache[product_key] = product_records
                records.update(product_records)
            result = list(records.values()), False, [
                CollectorDiagnostic(
                    "vulnerability_sources",
                    "info",
                    f"database CPE candidates: {len(candidates)}, CVE: {len(records)}",
                    str(self.db_path),
                )
            ]
            self._nvd_candidates_cache[cache_key] = result
            return result
        except Exception as exc:
            return [], False, [
                CollectorDiagnostic(
                    "vulnerability_sources",
                    "warning",
                    f"NVD database unavailable for CPE candidates: {exc}",
                    str(self.db_path),
                )
            ]

    def fetch_fstec_matches(
        self,
        inventory: list[InventoryObject],
        progress=None,
        cancel_token: CancellationToken | None = None,
        limit_per_object: int = 200,
    ) -> tuple[list[VulnerabilityMatch], list[CollectorDiagnostic]]:
        token = cancel_token or CancellationToken()
        if not self._has_table("fstec_vulnerabilities") or not self._has_table("fstec_vulnerability_products"):
            return [], [
                CollectorDiagnostic("vulnerability_sources", "info", "database: no local FSTEC tables", str(self.db_path))
            ]
        resolver = InventoryIdentityResolver()
        matches: list[VulnerabilityMatch] = []
        diagnostics: list[CollectorDiagnostic] = []
        seen: set[tuple[str, str, str]] = set()
        grouped: dict[
            tuple[str, str, str, str, tuple[str, ...]],
            list[tuple[InventoryObject, InventoryIdentity]],
        ] = {}
        for obj in inventory:
            identity = resolver.resolve(obj, inventory)
            grouped.setdefault(identity.group_key, []).append((obj, identity))
        processed = 0
        next_progress = 100
        for group in grouped.values():
            token.raise_if_cancelled()
            obj, identity = group[0]
            processed += len(group)
            if progress and processed >= next_progress:
                progress(f"Local FSTEC database: {processed}/{len(inventory)}")
                next_progress = ((processed // 100) + 1) * 100
            terms = self._terms_for_fstec_identity(identity, obj)
            if not terms:
                continue
            rows = self._query_fstec_products(terms, limit=limit_per_object)
            for row in rows:
                token.raise_if_cancelled()
                if not self._fstec_product_matches(identity, obj, str(row["product"])):
                    continue
                version_state = self._fstec_version_matches(identity.version, str(row["version_expression"]))
                if version_state is False:
                    continue
                for grouped_obj, _grouped_identity in group:
                    key = (str(row["code"]), grouped_obj.uid, str(row["source"]))
                    if key in seen:
                        continue
                    seen.add(key)
                    matches.append(self._fstec_row_to_match(row, grouped_obj, version_state))
        diagnostics.append(
            CollectorDiagnostic(
                "vulnerability_sources",
                "info",
                f"database: local FSTEC matches={len(matches)} candidates={len(inventory)}",
                str(self.db_path),
            )
        )
        if matches:
            self._record_snapshot()
        return matches, diagnostics

    def _fetch_nvd_by_terms(
        self,
        label: str,
        terms: list[str],
        parts: tuple[str, ...],
        limit: int,
    ) -> tuple[list[dict[str, Any]], list[CollectorDiagnostic]]:
        if not terms:
            return [], [
                CollectorDiagnostic("vulnerability_sources", "info", f"database skipped: {label}", str(self.db_path))
            ]
        cache_key = (label, tuple(terms), parts, limit)
        cached = self._term_query_cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            self._record_snapshot()
            if self._has_usable_fts():
                records = self._query_nvd_affected_products_fts(terms, parts, limit)
            elif self._has_table("nvd_affected_products"):
                records = self._query_nvd_affected_products(terms, parts, limit)
            else:
                records = self._query_nvd_raw_text(terms, limit)
            result = records, [
                CollectorDiagnostic("vulnerability_sources", "info", f"database: {label}", str(self.db_path))
            ]
            self._term_query_cache[cache_key] = result
            return result
        except Exception as exc:
            return [], [
                CollectorDiagnostic("vulnerability_sources", "warning", f"NVD database unavailable for {label}: {exc}", str(self.db_path))
            ]

    def _query_nvd_affected_products(
        self,
        terms: list[str],
        parts: tuple[str, ...],
        limit: int,
    ) -> list[dict[str, Any]]:
        where = ["p.vulnerable = 1"]
        params: list[object] = []
        if parts:
            where.append("p.part in (" + ",".join("?" for _ in parts) + ")")
            params.extend(parts)
        for term in terms:
            where.append("p.search_text like ?")
            params.append(f"%{term.casefold()}%")
        params.append(limit)
        rows = self._fetch_rows(
            f"""
            select distinct c.raw_json
            from nvd_cves c
            join nvd_affected_products p on p.cve_id = c.cve_id
            where {' and '.join(where)}
            order by coalesce(c.cvss, 0) desc, c.cve_id
            limit ?
            """,
            params,
        )
        return self._nvd_records_from_rows(rows, require_configuration=True)

    def _query_nvd_affected_products_fts(
        self,
        terms: list[str],
        parts: tuple[str, ...],
        limit: int,
    ) -> list[dict[str, Any]]:
        where = ["f.search_text match ?"]
        params: list[object] = [self._fts_query(terms)]
        if parts:
            where.append("f.part in (" + ",".join("?" for _ in parts) + ")")
            params.extend(parts)
        params.append(limit)
        rows = self._fetch_rows(
            f"""
            select distinct c.raw_json
            from nvd_affected_products_fts f
            join nvd_cves c on c.cve_id = f.cve_id
            where {' and '.join(where)}
            order by coalesce(c.cvss, 0) desc, c.cve_id
            limit ?
            """,
            params,
        )
        return self._nvd_records_from_rows(rows, require_configuration=True)

    def _query_fstec_products(self, terms: list[str], limit: int) -> list[sqlite3.Row]:
        if not terms:
            return []
        where = []
        params: list[object] = []
        for term in terms[:4]:
            where.append("p.search_text like ?")
            params.append(f"%{term.casefold()}%")
        params.append(limit)
        return self._fetch_rows(
            f"""
            select
                v.source,v.code,v.name,v.description,v.severity_text,v.cvss,
                v.exploit_status,v.exploit_available,v.references_json,
                v.external_ids,v.remediation,v.version_info,
                p.product,p.vendor,p.version_expression,p.normalized_product,
                p.normalized_vendor,p.search_text
            from fstec_vulnerability_products p
            join fstec_vulnerabilities v
              on v.source = p.source and v.code = p.code
            where {' and '.join(where)}
            order by coalesce(v.cvss, 0) desc, v.code
            limit ?
            """,
            params,
        )

    def _query_nvd_affected_product_aliases(
        self,
        aliases: tuple[tuple[str, str, str], ...],
        limit: int,
    ) -> list[dict[str, Any]]:
        cache_key = (aliases, limit)
        cached = self._affected_alias_cache.get(cache_key)
        if cached is not None:
            return cached
        where = ["p.vulnerable = 1"]
        params: list[object] = []
        alias_clauses = []
        for part, vendor, product in aliases:
            alias_clauses.append("(p.part = ? and p.vendor = ? and p.product = ?)")
            params.extend([part, vendor, product])
        where.append("(" + " or ".join(alias_clauses) + ")")
        params.append(limit)
        rows = self._fetch_rows(
            f"""
            select distinct c.raw_json
            from nvd_cves c
            join nvd_affected_products p on p.cve_id = c.cve_id
            where {' and '.join(where)}
            order by coalesce(c.cvss, 0) desc, c.cve_id
            limit ?
            """,
            params,
        )
        records = self._nvd_records_from_rows(rows, require_configuration=True)
        self._affected_alias_cache[cache_key] = records
        if records:
            self._record_snapshot()
        return records

    def _query_nvd_raw_text(self, terms: list[str], limit: int) -> list[dict[str, Any]]:
        where = []
        params: list[object] = []
        for term in terms:
            where.append("(descriptions_json like ? or configurations_json like ?)")
            params.extend([f"%{term}%", f"%{term}%"])
        params.append(limit)
        rows = self._fetch_rows(
            f"""
            select raw_json
            from nvd_cves
            where {' and '.join(where)}
            order by coalesce(cvss, 0) desc, cve_id
            limit ?
            """,
            params,
        )
        return self._nvd_records_from_rows(rows, require_configuration=True)

    def _fetch_rows(self, sql: str, params: list[object] | tuple[object, ...] = ()) -> list[sqlite3.Row]:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        try:
            return list(con.execute(sql, params).fetchall())
        finally:
            con.close()

    @staticmethod
    def _nvd_records_from_rows(
        rows: list[sqlite3.Row],
        require_configuration: bool,
    ) -> list[dict[str, Any]]:
        records = [json.loads(str(row[0])) for row in rows]
        if require_configuration:
            for record in records:
                record["_ib_match_requires_configuration"] = True
        return records

    def _has_table(self, name: str) -> bool:
        rows = self._fetch_rows(
            "select name from sqlite_master where type='table' and name=?",
            (name,),
        )
        return bool(rows)

    def _has_usable_fts(self) -> bool:
        if self._usable_fts is not None:
            return self._usable_fts
        if not self._has_table("nvd_affected_products_fts"):
            self._usable_fts = False
            return False
        rows = self._fetch_rows("select count(*) from nvd_affected_products_fts")
        self._usable_fts = bool(rows and int(rows[0][0]) > 0)
        return self._usable_fts

    def _record_snapshot(self) -> None:
        if self.used_snapshots:
            return
        stat = self.db_path.stat()
        stamp = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).replace(microsecond=0).isoformat()
        digest = hashlib.sha256(f"{self.db_path.resolve()}:{stat.st_size}:{stamp}".encode("utf-8")).hexdigest()
        self.used_snapshots.append(
            SourceSnapshot(
                id=digest,
                source="vulnerability-db",
                cache_key=self.db_path.name,
                path=str(self.db_path),
                sha256=digest,
                fetched_at=stamp,
                status="active",
                metadata={"size_bytes": stat.st_size},
            )
        )

    @staticmethod
    def _query_terms(text: str) -> list[str]:
        blocked = {
            "inc",
            "corp",
            "corporation",
            "company",
            "limited",
            "ltd",
            "driver",
            "drivers",
            "cpu",
            "processor",
            "processors",
            "software",
            "version",
        }
        return [
            item
            for item in re.findall(r"[a-z0-9]+", text.casefold())
            if len(item) >= 3 and item not in blocked
        ]

    @staticmethod
    def _fts_query(terms: list[str]) -> str:
        unique_terms = []
        for term in terms:
            if term not in unique_terms:
                unique_terms.append(term)
        return " ".join(unique_terms)

    @classmethod
    def _terms_for_fstec_identity(cls, identity: InventoryIdentity, obj: InventoryObject) -> list[str]:
        text = " ".join(
            [
                identity.vendor,
                identity.product,
                identity.model.replace("_", " "),
                obj.title,
                *identity.variants,
            ]
        )
        terms: list[str] = []
        for term in cls._query_terms(text):
            if term not in terms:
                terms.append(term)
        return terms[:5]

    @classmethod
    def _fstec_product_matches(cls, identity: InventoryIdentity, obj: InventoryObject, product: str) -> bool:
        product_terms = set(cls._query_terms(product))
        if not product_terms:
            return False
        identity_terms = set(
            cls._query_terms(
                " ".join([identity.product, obj.title, identity.model.replace("_", " "), *identity.variants])
            )
        )
        return product_terms.issubset(identity_terms)

    @classmethod
    def _fstec_version_matches(cls, installed: str, expression: str) -> bool | None:
        installed = str(installed or "").strip()
        expression = str(expression or "").strip()
        if not installed:
            return None
        installed_value = cls._version_tuple(installed)
        if installed_value is None:
            return None
        normalized = " ".join(expression.casefold().replace(",", ".").split())
        if normalized in {"", "-", "данные уточняются"}:
            return None
        range_match = re.search(r"от\s+([0-9][\w.-]*)\s+до\s+([0-9][\w.-]*)", normalized)
        if range_match:
            lower = cls._version_tuple(range_match.group(1))
            upper = cls._version_tuple(range_match.group(2))
            if lower is None or upper is None:
                return None
            inclusive = "включительно" in normalized
            return installed_value >= lower and (installed_value <= upper if inclusive else installed_value < upper)
        before_match = re.search(r"до\s+([0-9][\w.-]*)", normalized)
        if before_match:
            upper = cls._version_tuple(before_match.group(1))
            if upper is None:
                return None
            return installed_value <= upper if "включительно" in normalized else installed_value < upper
        below_match = re.search(r"([0-9][\w.-]*)\s+и\s+ниже", normalized)
        if below_match:
            upper = cls._version_tuple(below_match.group(1))
            return None if upper is None else installed_value <= upper
        above_match = re.search(r"([0-9][\w.-]*)\s+и\s+выше", normalized)
        if above_match:
            lower = cls._version_tuple(above_match.group(1))
            return None if lower is None else installed_value >= lower
        exact = cls._version_tuple(normalized)
        return None if exact is None else installed_value == exact

    @classmethod
    def _fstec_row_to_match(
        cls,
        row: sqlite3.Row,
        obj: InventoryObject,
        version_state: bool | None,
    ) -> VulnerabilityMatch:
        applicability = "confirmed" if version_state is True else "potential"
        installed = InventoryIdentityResolver().resolve(obj, [obj]).version
        version_note = (
            "affected version confirmed"
            if version_state is True
            else "version requires manual confirmation"
        )
        try:
            references = json.loads(str(row["references_json"] or "[]"))
            if not isinstance(references, list):
                references = []
        except json.JSONDecodeError:
            references = []
        return VulnerabilityMatch(
            cve=str(row["code"]),
            source="ФСТЭК БДУ",
            severity=cls._fstec_severity(str(row["severity_text"]), row["cvss"]),
            cvss=row["cvss"],
            kev=False,
            affected_title=obj.title,
            evidence=(
                f"FSTEC local product '{row['product']}' version '{row['version_expression']}' "
                f"matched '{obj.title}' version '{installed or 'unknown'}'; {version_note}."
            ),
            confidence="High" if version_state is True else "Medium",
            remediation=str(row["remediation"] or "") or cls._generic_remediation(obj),
            references=[str(item) for item in references if item][:8],
            object_uid=obj.uid,
            applicability=applicability,
        )

    @staticmethod
    def _fstec_severity(text: str, cvss: object) -> str:
        lowered = text.casefold()
        if "крит" in lowered:
            return "CRITICAL"
        if "высок" in lowered:
            return "HIGH"
        if "сред" in lowered:
            return "MEDIUM"
        if "низк" in lowered:
            return "LOW"
        try:
            value = float(cvss)
        except (TypeError, ValueError):
            return "UNKNOWN"
        if value >= 9:
            return "CRITICAL"
        if value >= 7:
            return "HIGH"
        if value >= 4:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _version_tuple(value: str) -> tuple[int, ...] | None:
        match = re.search(r"\d+(?:[._-]\d+)*", value)
        if not match:
            return None
        return tuple(int(part) for part in re.split(r"[._-]", match.group(0)))

    @staticmethod
    def _affected_product_aliases(identity: InventoryIdentity) -> tuple[tuple[str, str, str], ...]:
        variants = " ".join((identity.product, *identity.variants))
        if identity.object_type == "software" and identity.vendor == "acronis" and "backup" in variants:
            return (("a", "acronis", "cyber backup"),)
        return ()

    @classmethod
    def _cpe_parts_for_object(cls, object_type: str) -> tuple[str, ...]:
        if object_type in cls.operating_system_types:
            return ("o",)
        if object_type in cls.hardware_types:
            return ("h", "o")
        return ("a",)


class VulnerabilityCorrelator:
    candidate_types = {
        "software", "operating_system", "service", "driver",
        "odbc_driver", "oledb_provider", "bios", "device",
        "base_board", "display_adapter", "network_adapter", "physical_disk", "processor",
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
        seen: set[tuple[str, str, str]] = set()
        for obj in inventory:
            haystack = self._inventory_text(obj)
            for record in kev_records:
                vendor = str(record.get("vendorProject", ""))
                product = str(record.get("product", ""))
                vulnerability_name = str(record.get("vulnerabilityName", ""))
                cve = str(record.get("cveID", ""))
                if cve and self._contains_product(obj, vendor, product, vulnerability_name):
                    key = (cve, obj.title, obj.uid)
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
                require_configuration = bool(record.get("_ib_match_requires_configuration"))
                matches_record = configuration_match is True or (
                    not require_configuration
                    and configuration_match is None
                    and self._matches_description(obj, description)
                )
                if cve and matches_record:
                    key = (cve, obj.title, obj.uid)
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
    ) -> VulnerabilityCorrelationResult:
        token = cancel_token or CancellationToken()
        token.raise_if_cancelled()
        client = client or self.source_client or VulnerabilitySourceClient()
        kev, diagnostics = client.fetch_cisa_kev()
        token.raise_if_cancelled()
        candidate_inventory = [obj for obj in inventory if obj.object_type in self.candidate_types]
        matches = self.match_inventory(candidate_inventory, kev, [])
        coverage: dict[str, VulnerabilityCoverage] = {}
        cpe_handled_uids: set[str] = set()
        cpe_result = self._enrich_from_cpe_sources(
            candidate_inventory,
            client,
            token,
            progress=progress,
        )
        if cpe_result is not None:
            matches.extend(cpe_result.matches)
            diagnostics.extend(cpe_result.diagnostics)
            coverage.update(cpe_result.coverage)
            cpe_handled_uids = set(cpe_result.coverage)

        keyword_groups = [
            (keyword, objects)
            for keyword, objects in self._keyword_groups(candidate_inventory)
            if not all(obj.uid in cpe_handled_uids for obj in objects)
        ]
        if max_nvd_queries is not None:
            keyword_groups = keyword_groups[:max_nvd_queries]
        for keyword, objects in keyword_groups:
            token.raise_if_cancelled()
            first = objects[0]
            if hasattr(client, "fetch_nvd_for_object"):
                records, diag = client.fetch_nvd_for_object(first)
            else:
                records, diag = client.fetch_nvd_keyword(keyword)
            token.raise_if_cancelled()
            diagnostics.extend(diag)
            matches.extend(self.match_inventory(objects, [], records))
        if hasattr(client, "fetch_fstec_matches"):
            fstec_db_matches, fstec_db_diagnostics = client.fetch_fstec_matches(
                candidate_inventory,
                progress=progress,
                cancel_token=token,
            )
            matches.extend(fstec_db_matches)
            diagnostics.extend(fstec_db_diagnostics)
        if self.fstec_client is not None:
            fstec_matches, fstec_diagnostics = self.fstec_client.match_inventory(
                candidate_inventory,
                progress=progress,
                cancel_token=token,
            )
            matches.extend(fstec_matches)
            diagnostics.extend(fstec_diagnostics)
        deduped: list[VulnerabilityMatch] = []
        seen: set[tuple[str, str, str, str]] = set()
        for match in sorted(matches, key=lambda item: (not item.kev, -(item.cvss or 0), item.cve, item.affected_title)):
            token.raise_if_cancelled()
            key = (match.cve, match.affected_title, match.source, match.object_uid)
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
        return VulnerabilityCorrelationResult(
            deduped,
            diagnostics,
            coverage,
            list(self.used_snapshots),
        )

    def _enrich_from_cpe_sources(
        self,
        inventory: list[InventoryObject],
        client: object,
        token: CancellationToken,
        progress=None,
    ) -> VulnerabilityCorrelationResult | None:
        if not (hasattr(client, "resolve_cpe") and hasattr(client, "fetch_nvd_for_candidates")):
            return None
        if not inventory:
            return VulnerabilityCorrelationResult([], [], {}, [])
        resolver = InventoryIdentityResolver()
        identities_by_uid = {obj.uid: resolver.resolve(obj, inventory) for obj in inventory}
        host_identities = list(identities_by_uid.values())
        grouped: dict[
            tuple[str, str, str, str, tuple[str, ...]],
            list[tuple[InventoryObject, InventoryIdentity]],
        ] = {}
        for obj in inventory:
            identity = identities_by_uid[obj.uid]
            grouped.setdefault(identity.group_key, []).append((obj, identity))

        evaluator = CpeApplicabilityEvaluator()
        matches: list[VulnerabilityMatch] = []
        diagnostics: list[CollectorDiagnostic] = []
        coverage: dict[str, VulnerabilityCoverage] = {}
        total_groups = len(grouped)
        for index, group in enumerate(grouped.values(), 1):
            token.raise_if_cancelled()
            if progress and (index == 1 or index == total_groups or index % 25 == 0):
                progress(f"Local NVD/CPE database: {index}/{total_groups}")
            representative = group[0][1]
            resolution = client.resolve_cpe(representative)
            if resolution.status == "catalog_unavailable":
                return None
            group_uids = [obj.uid for obj, _identity in group]
            if resolution.status not in {"resolved", "ambiguous"}:
                if representative.object_type in self._direct_affected_product_fallback_types() and hasattr(client, "fetch_nvd_for_object"):
                    records, source_diagnostics = client.fetch_nvd_for_object(group[0][0])
                    diagnostics.extend(source_diagnostics)
                    group_matches = self._matches_from_cpe_records(
                        records,
                        group,
                        representative,
                        host_identities,
                        evaluator,
                        token,
                    )
                    matches.extend(group_matches)
                    coverage_state = "complete" if records else "incomplete"
                    coverage_reason = (
                        "direct NVD affected-product fallback evaluated"
                        if records
                        else "direct NVD affected-product fallback found no candidates"
                    )
                    for uid in group_uids:
                        coverage[uid] = self._coverage(
                            uid,
                            coverage_state,
                            resolution.status,
                            candidate_count=len(resolution.candidates),
                            evaluated_count=len(records),
                            truncated=False,
                            reason=coverage_reason,
                            trace={"identity": representative.group_key},
                        )
                    continue
                for uid in group_uids:
                    coverage[uid] = self._coverage(
                        uid,
                        "incomplete",
                        resolution.status,
                        candidate_count=len(resolution.candidates),
                        evaluated_count=0,
                        truncated=False,
                        reason=resolution.reason,
                        trace={"identity": representative.group_key},
                    )
                continue

            records, truncated, source_diagnostics = client.fetch_nvd_for_candidates(resolution.candidates)
            diagnostics.extend(source_diagnostics)
            used_direct_fallback = False
            if (
                not records
                and hasattr(client, "fetch_nvd_for_object")
                and representative.object_type in self._direct_affected_product_fallback_types()
            ):
                direct_records, direct_diagnostics = client.fetch_nvd_for_object(group[0][0])
                diagnostics.extend(direct_diagnostics)
                if direct_records:
                    records = direct_records
                    used_direct_fallback = True
            group_matches = self._matches_from_cpe_records(
                records,
                group,
                representative,
                host_identities,
                evaluator,
                token,
                fallback_cpe=resolution.candidates[0].cpe.uri if resolution.status == "resolved" else "",
            )
            matches.extend(group_matches)
            coverage_state = "incomplete" if truncated else "complete"
            coverage_reason = "query truncated" if truncated else "CPE candidates evaluated"
            if used_direct_fallback:
                coverage_reason = "direct NVD affected-product fallback evaluated"
            if resolution.status == "ambiguous":
                if not records:
                    coverage_reason = "ambiguous CPE candidates evaluated, but no CVE records were found"
                elif not used_direct_fallback:
                    coverage_reason = "ambiguous CPE candidates evaluated"
                if not records and not group_matches:
                    coverage_state = "incomplete"
            for uid in group_uids:
                coverage[uid] = self._coverage(
                    uid,
                    coverage_state,
                    resolution.status,
                    candidate_count=len(resolution.candidates),
                    evaluated_count=len(records),
                    truncated=truncated,
                    reason=coverage_reason,
                    trace={
                        "candidates": [candidate.cpe.uri for candidate in resolution.candidates],
                    },
                )
        return VulnerabilityCorrelationResult(matches, diagnostics, coverage, list(getattr(client, "used_snapshots", [])))

    def _matches_from_cpe_records(
        self,
        records: list[dict[str, Any]],
        group: list[tuple[InventoryObject, InventoryIdentity]],
        representative: InventoryIdentity,
        host_identities: list[InventoryIdentity],
        evaluator: CpeApplicabilityEvaluator,
        token: CancellationToken,
        fallback_cpe: str = "",
    ) -> list[VulnerabilityMatch]:
        group_matches: list[VulnerabilityMatch] = []
        for record in records:
            token.raise_if_cancelled()
            decision = evaluator.evaluate(
                list(record.get("configurations", [])),
                target=representative,
                host_identities=host_identities,
            )
            if decision.state not in {"confirmed", "potential"}:
                continue
            cvss, severity = self._cvss(record)
            cpe = decision.criteria[0] if decision.criteria else fallback_cpe
            for obj, _identity in group:
                group_matches.append(
                    VulnerabilityMatch(
                        cve=str(record.get("id", "")),
                        source="NVD",
                        severity=severity,
                        cvss=cvss,
                        kev=False,
                        affected_title=obj.title,
                        evidence=f"NVD applicability {decision.state}: {decision.reason}",
                        confidence="High" if decision.state == "confirmed" else "Medium",
                        remediation=self._generic_remediation(obj),
                        references=self._references(record),
                        object_uid=obj.uid,
                        applicability=decision.state,
                        cpe=cpe,
                    )
                )
        return group_matches

    @staticmethod
    def _hardware_cpe_object_types() -> set[str]:
        return {
            "bios",
            "base_board",
            "device",
            "display_adapter",
            "network_adapter",
            "physical_disk",
            "processor",
        }

    @staticmethod
    def _direct_hardware_fallback_types() -> set[str]:
        return {
            "bios",
            "base_board",
            "display_adapter",
            "network_adapter",
            "physical_disk",
            "processor",
        }

    @staticmethod
    def _direct_affected_product_fallback_types() -> set[str]:
        return {
            "software",
            "service",
            "driver",
            "odbc_driver",
            "oledb_provider",
            "operating_system",
        }

    @staticmethod
    def _coverage(
        object_uid: str,
        state: str,
        cpe_status: str,
        candidate_count: int,
        evaluated_count: int,
        truncated: bool,
        reason: str,
        trace: dict[str, Any] | None = None,
    ) -> VulnerabilityCoverage:
        return VulnerabilityCoverage(
            object_uid=object_uid,
            state=state,
            cpe_status=cpe_status,
            sources_checked=("NVD",),
            candidate_count=candidate_count,
            evaluated_count=evaluated_count,
            truncated=truncated,
            reason=reason,
            trace=trace or {},
        )

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
        return [word for word in re.findall(r"[a-z0-9]+", text.lower()) if len(word) >= 2 and word not in stop_words]

    @staticmethod
    def _description(record: dict[str, Any]) -> str:
        for item in record.get("descriptions", []):
            if item.get("lang") == "en":
                return str(item.get("value", ""))
        return " ".join(str(item.get("value", "")) for item in record.get("descriptions", []))

    def _matches_description(self, obj: InventoryObject, description: str) -> bool:
        text = self._inventory_text(obj)
        description_l = description.lower()
        version = self._version(obj)
        if not version:
            return False
        title_words = [word for word in re.split(r"\W+", obj.title.lower()) if len(word) >= 4]
        if title_words and all(word in description_l for word in title_words[:2]):
            return True
        vendor = str(obj.fields.get("Vendor") or obj.fields.get("Publisher") or "").lower()
        product = obj.title.lower()
        return bool(product and product in description_l and (not vendor or vendor in description_l) and (not version or version in description_l or version in text))

    @staticmethod
    def _version(obj: InventoryObject) -> str:
        for key in ("Version", "DisplayVersion", "FileVersion", "DriverVersion", "SMBIOSBIOSVersion"):
            if obj.fields.get(key):
                return str(obj.fields[key])
        return ""

    @classmethod
    def _matches_configurations(cls, obj: InventoryObject, record: dict[str, Any]) -> bool | None:
        cpe_matches = cls._cpe_matches(record)
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
                return False
            cpe_version = parts[5].replace("_", " ")
            if cls._is_generic_os_cpe_without_version(obj, cpe_product, cpe_version, item):
                continue
            if not cls._version_matches_cpe(identity.version, cpe_version):
                continue
            if cls._version_in_range(identity.version, item):
                return True
        return False if compatible_seen else None

    @staticmethod
    def _is_generic_os_cpe_without_version(
        obj: InventoryObject,
        cpe_product: set[str],
        cpe_version: str,
        item: dict[str, Any],
    ) -> bool:
        has_range = any(
            item.get(key)
            for key in (
                "versionStartIncluding",
                "versionStartExcluding",
                "versionEndIncluding",
                "versionEndExcluding",
            )
        )
        return (
            obj.object_type == "operating_system"
            and cpe_product <= {"windows"}
            and cpe_version.strip() in {"", "*", "-"}
            and not has_range
        )

    @classmethod
    def _cpe_matches(cls, record: dict[str, Any]) -> list[dict[str, Any]]:
        cpe_matches: list[dict[str, Any]] = []

        def visit(node: dict[str, Any]) -> None:
            cpe_matches.extend(item for item in node.get("cpeMatch", []) if isinstance(item, dict))
            for child in node.get("children", []):
                if isinstance(child, dict):
                    visit(child)

        for configuration in record.get("configurations", []):
            for node in configuration.get("nodes", []):
                if isinstance(node, dict):
                    visit(node)
        return cpe_matches

    @classmethod
    def _version_matches_cpe(cls, version: str, cpe_version: str) -> bool:
        cpe_version = cpe_version.strip()
        if cpe_version in {"", "*", "-"}:
            return True
        current = cls._version_tuple(version)
        required = cls._version_tuple(cpe_version)
        if current is not None and required is not None:
            return current == required
        return version.casefold() == cpe_version.casefold()

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
        return [keyword for keyword, _objects in VulnerabilityCorrelator._keyword_groups(inventory)]

    @staticmethod
    def _keyword_objects(inventory: list[InventoryObject]) -> list[tuple[str, InventoryObject]]:
        return [(keyword, objects[0]) for keyword, objects in VulnerabilityCorrelator._keyword_groups(inventory)]

    @staticmethod
    def _keyword_groups(inventory: list[InventoryObject]) -> list[tuple[str, list[InventoryObject]]]:
        groups: dict[str, tuple[str, list[InventoryObject]]] = {}
        for obj in inventory:
            title = obj.title.strip()
            version = str(obj.fields.get("DisplayVersion") or obj.fields.get("Version") or "").strip()
            if not version:
                version = VulnerabilityCorrelator._version(obj).strip()
            if not version:
                continue
            keyword = f"{title} {version}".strip()
            if len(keyword) < 4:
                continue
            key = keyword.casefold()
            groups.setdefault(key, (keyword, []))[1].append(obj)
        return list(groups.values())
