from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from itertools import zip_longest
from pathlib import Path
from typing import Literal

from .cpe import CpeName
from .identity import InventoryIdentity, normalize_vendor


@dataclass(frozen=True)
class CpeCandidate:
    cpe: CpeName
    cpe_name_id: str
    title: str
    score: int
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class CpeResolution:
    status: Literal["resolved", "ambiguous", "not_found", "catalog_unavailable"]
    candidates: tuple[CpeCandidate, ...]
    reason: str


class CpeCatalog:
    threshold = 70
    ambiguity_margin = 20

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self._active_generation_cache: int | None | bool = False
        self._resolution_cache: dict[tuple[str, str, str, str, tuple[str, ...]], CpeResolution] = {}
        self._fts_available_cache: dict[int, bool] = {}

    def resolve(self, identity: InventoryIdentity, limit: int = 200) -> CpeResolution:
        cached = self._resolution_cache.get(identity.group_key)
        if cached is not None:
            return cached
        generation_id = self._active_generation_id()
        if generation_id is None:
            result = CpeResolution("catalog_unavailable", (), "active CPE catalog generation is not available")
            self._resolution_cache[identity.group_key] = result
            return result

        rows = self._candidate_rows(generation_id, identity, limit=limit)
        candidates = [
            candidate
            for candidate in (
                self._score_row(identity, row)
                for row in rows
            )
            if candidate is not None and candidate.score >= self.threshold
        ]
        candidates.sort(key=lambda item: (-item.score, item.cpe.uri, item.cpe_name_id))
        if not candidates:
            result = CpeResolution("not_found", (), "no CPE candidate passed the confidence threshold")
            self._resolution_cache[identity.group_key] = result
            return result
        if len(candidates) > 1 and candidates[0].score - candidates[1].score < self.ambiguity_margin:
            ambiguous_candidates = tuple(
                candidate
                for candidate in candidates
                if candidates[0].score - candidate.score < self.ambiguity_margin
            )[:25]
            result = CpeResolution(
                "ambiguous",
                ambiguous_candidates,
                "top CPE candidates are too close to choose safely",
            )
            self._resolution_cache[identity.group_key] = result
            return result
        result = CpeResolution("resolved", (candidates[0],), "resolved to the highest scoring CPE candidate")
        self._resolution_cache[identity.group_key] = result
        return result

    def _active_generation_id(self) -> int | None:
        if self._active_generation_cache is not False:
            return self._active_generation_cache
        if not self.db_path.is_file():
            self._active_generation_cache = None
            return None
        con = sqlite3.connect(self.db_path)
        try:
            row = con.execute(
                "select active_generation_id from source_sync_state where source='nvd-cpe-catalog'"
            ).fetchone()
        except sqlite3.Error:
            self._active_generation_cache = None
            return None
        finally:
            con.close()
        self._active_generation_cache = int(row[0]) if row and row[0] is not None else None
        return self._active_generation_cache

    def _candidate_rows(
        self,
        generation_id: int,
        identity: InventoryIdentity,
        limit: int,
    ) -> list[sqlite3.Row]:
        rows = self._fts_candidate_rows(generation_id, identity, limit=limit)
        if rows is not None:
            return rows
        return self._indexed_candidate_rows(generation_id, identity, limit=limit)

    def _fts_candidate_rows(
        self,
        generation_id: int,
        identity: InventoryIdentity,
        limit: int,
    ) -> list[sqlite3.Row] | None:
        parts = self._parts_for_identity(identity)
        queries = self._fts_queries(identity)
        if not queries:
            return []
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        try:
            if not self._has_table(con, "nvd_cpe_fts"):
                return None
            if not self._fts_available(con, generation_id):
                return None
            results: dict[str, sqlite3.Row] = {}
            part_filter = ",".join("?" for _ in parts)
            for query in queries:
                rows = con.execute(
                    f"""
                    select n.cpe_name_id,n.cpe_name,n.part,n.vendor,n.product,n.version,n.title
                    from nvd_cpe_fts
                    join nvd_cpe_names n
                      on n.generation_id = nvd_cpe_fts.generation_id
                     and n.cpe_name_id = nvd_cpe_fts.cpe_name_id
                    where nvd_cpe_fts match ?
                      and nvd_cpe_fts.generation_id = ?
                      and nvd_cpe_fts.part in ({part_filter})
                    order by bm25(nvd_cpe_fts), n.vendor, n.product, n.version
                    limit ?
                    """,
                    (query, generation_id, *parts, limit),
                ).fetchall()
                for row in rows:
                    results.setdefault(str(row["cpe_name_id"]), row)
                    if len(results) >= limit:
                        return list(results.values())
            return list(results.values())
        finally:
            con.close()

    def _indexed_candidate_rows(
        self,
        generation_id: int,
        identity: InventoryIdentity,
        limit: int,
    ) -> list[sqlite3.Row]:
        parts = self._parts_for_identity(identity)
        params: list[object] = [generation_id, *parts]
        where = [
            "generation_id = ?",
            "part in (" + ",".join("?" for _ in parts) + ")",
        ]
        probes = self._candidate_probes(identity)
        if identity.vendor:
            where.append("vendor = ?")
            params.append(identity.vendor)
        text_filters = []
        for probe in probes:
            text_filters.append("(product like ? or title like ?)")
            params.extend([f"%{probe.replace(' ', '_')}%", f"%{probe}%"])
        if text_filters:
            where.append("(" + " or ".join(text_filters) + ")")
        params.append(limit)
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        try:
            return list(
                con.execute(
                    f"""
                    select cpe_name_id,cpe_name,part,vendor,product,version,title
                    from nvd_cpe_names
                    where {' and '.join(where)}
                    order by vendor, product, version
                    limit ?
                    """,
                    params,
                ).fetchall()
            )
        finally:
            con.close()

    def _score_row(self, identity: InventoryIdentity, row: sqlite3.Row) -> CpeCandidate | None:
        cpe = CpeName.parse(str(row["cpe_name"]))
        cpe_vendor = normalize_vendor(cpe.vendor.replace("_", " "))
        cpe_product = cpe.product.replace("_", " ")
        cpe_version = cpe.version.replace("_", " ")
        title = str(row["title"] or "")
        reasons: list[str] = []
        score = 0

        if cpe.part not in self._parts_for_identity(identity):
            return None
        score += 20
        reasons.append(f"compatible part {cpe.part}")

        if identity.vendor:
            if identity.vendor == cpe_vendor:
                score += 35
                reasons.append("vendor exact")
            else:
                return None

        identity_tokens = self._tokens(" ".join((identity.product, *identity.variants)))
        cpe_product_tokens = self._tokens(cpe_product)
        title_tokens = self._tokens(title)
        vendor_tokens = self._tokens(identity.vendor)
        identity_product_tokens = identity_tokens - vendor_tokens
        cpe_product_tokens_scoped = cpe_product_tokens - vendor_tokens
        title_tokens_scoped = title_tokens - vendor_tokens
        product_overlap = cpe_product_tokens_scoped & identity_product_tokens
        title_overlap = title_tokens_scoped & identity_product_tokens
        model = identity.model.replace("_", " ")
        cpe_blob = " ".join((cpe_product, cpe_version, title)).casefold()
        if identity.object_type == "processor" and model and model not in cpe_blob:
            return None
        if cpe_product_tokens_scoped and cpe_product_tokens_scoped <= identity_product_tokens:
            score += 35
            reasons.append("product tokens exact")
        elif product_overlap:
            score += 20
            reasons.append("product family overlap")
        elif title_overlap:
            score += 10
            reasons.append("title overlap")
        else:
            return None

        if identity.model:
            if model == cpe_version or model in cpe_product or model in title.casefold():
                score += 35
                reasons.append("model exact")

        if identity.version:
            if cpe_version in {"", "*", "-"}:
                score += 10
                reasons.append("installed version present")
            elif self._versions_equal(identity.version, cpe_version):
                score += 35
                reasons.append("version exact")

        if title_overlap:
            score += min(15, len(title_overlap) * 5)
            reasons.append("official title overlap")

        if (
            identity.vendor == "acronis"
            and cpe_vendor == "acronis"
            and "backup" in identity_tokens
            and "backup" in (cpe_product_tokens | title_tokens)
        ):
            score += 25
            reasons.append("vendor scoped backup family")

        return CpeCandidate(
            cpe=cpe,
            cpe_name_id=str(row["cpe_name_id"]),
            title=title,
            score=score,
            reasons=tuple(reasons),
        )

    @staticmethod
    def _parts_for_identity(identity: InventoryIdentity) -> tuple[str, ...]:
        if identity.object_type == "operating_system":
            return ("o",)
        if identity.object_type in {
            "bios",
            "base_board",
            "device",
            "display_adapter",
            "network_adapter",
            "physical_disk",
            "processor",
        }:
            return ("h", "o")
        return ("a",)

    @staticmethod
    def _tokens(text: str) -> set[str]:
        blocked = {"and", "for", "the", "with", "core", "agent", "common", "file", "files"}
        return {
            token
            for token in re.findall(r"[a-z0-9]+", text.casefold().replace("_", " "))
            if len(token) >= 2 and token not in blocked
        }

    @classmethod
    def _versions_equal(cls, left: str, right: str) -> bool:
        left = left.strip()
        right = right.strip()
        if left.casefold() == right.casefold():
            return True
        left_numbers = cls._numeric_version(left)
        right_numbers = cls._numeric_version(right)
        if left_numbers is None or right_numbers is None:
            return False
        for left_item, right_item in zip_longest(left_numbers, right_numbers, fillvalue=0):
            if left_item != right_item:
                return False
        return True

    @staticmethod
    def _numeric_version(value: str) -> tuple[int, ...] | None:
        numbers = re.findall(r"\d+", value)
        if not numbers:
            return None
        return tuple(int(item) for item in numbers)

    @classmethod
    def _ordered_tokens(cls, text: str, *, drop_numeric: bool = False) -> list[str]:
        blocked = {"and", "for", "the", "with", "core", "agent", "common", "file", "files"}
        result: list[str] = []
        for token in re.findall(r"[a-z0-9]+", text.casefold().replace("_", " ")):
            if len(token) < 2 or token in blocked:
                continue
            if drop_numeric and token.isdigit():
                continue
            if token not in result:
                result.append(token)
        return result

    @classmethod
    def _candidate_probes(cls, identity: InventoryIdentity) -> list[str]:
        probes: list[str] = []

        def add(value: str) -> None:
            value = value.strip().casefold().replace("_", " ")
            if value and value not in probes:
                probes.append(value)

        add(identity.model.replace("_", " "))
        for token in cls._identity_product_terms(identity, drop_numeric=True)[:5]:
            add(token)
        return probes

    @classmethod
    def _fts_queries(cls, identity: InventoryIdentity) -> list[str]:
        vendor_terms = cls._ordered_tokens(identity.vendor, drop_numeric=True)
        model_terms = cls._ordered_tokens(identity.model.replace("_", " "), drop_numeric=False)
        product_terms = cls._identity_product_terms(identity, drop_numeric=True)
        queries: list[str] = []

        def add(tokens: list[str]) -> None:
            clean = [token for token in tokens if token]
            if not clean:
                return
            query = " ".join(f'"{token}"' for token in clean[:5])
            if query not in queries:
                queries.append(query)

        if model_terms:
            add(vendor_terms + model_terms[:2])
            add(model_terms[:2])
        if product_terms:
            add(vendor_terms + product_terms[:3])
            add(product_terms[:3])
        if vendor_terms and product_terms:
            add(vendor_terms + product_terms[:1])
        return queries

    @classmethod
    def _identity_product_terms(cls, identity: InventoryIdentity, *, drop_numeric: bool) -> list[str]:
        vendor_terms = set(cls._ordered_tokens(identity.vendor, drop_numeric=True))
        return [
            term
            for term in cls._ordered_tokens(" ".join((identity.product, *identity.variants)), drop_numeric=drop_numeric)
            if term not in vendor_terms
        ]

    @staticmethod
    def _has_table(con: sqlite3.Connection, name: str) -> bool:
        row = con.execute(
            "select 1 from sqlite_master where type in ('table','virtual table') and name=?",
            (name,),
        ).fetchone()
        return row is not None

    def _fts_available(self, con: sqlite3.Connection, generation_id: int) -> bool:
        cached = self._fts_available_cache.get(generation_id)
        if cached is not None:
            return cached
        row = con.execute(
            "select 1 from nvd_cpe_fts where generation_id=? limit 1",
            (generation_id,),
        ).fetchone()
        self._fts_available_cache[generation_id] = row is not None
        return self._fts_available_cache[generation_id]
