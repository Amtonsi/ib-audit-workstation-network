from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .cpe import CpeName
from .identity import InventoryIdentity


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

    def resolve(self, identity: InventoryIdentity, limit: int = 200) -> CpeResolution:
        generation_id = self._active_generation_id()
        if generation_id is None:
            return CpeResolution("catalog_unavailable", (), "active CPE catalog generation is not available")

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
            return CpeResolution("not_found", (), "no CPE candidate passed the confidence threshold")
        if len(candidates) > 1 and candidates[0].score - candidates[1].score < self.ambiguity_margin:
            return CpeResolution(
                "ambiguous",
                tuple(candidates[:5]),
                "top CPE candidates are too close to choose safely",
            )
        return CpeResolution("resolved", (candidates[0],), "resolved to the highest scoring CPE candidate")

    def _active_generation_id(self) -> int | None:
        if not self.db_path.is_file():
            return None
        con = sqlite3.connect(self.db_path)
        try:
            row = con.execute(
                "select active_generation_id from source_sync_state where source='nvd-cpe-catalog'"
            ).fetchone()
        except sqlite3.Error:
            return None
        finally:
            con.close()
        return int(row[0]) if row and row[0] is not None else None

    def _candidate_rows(
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
        tokens = sorted(self._tokens(" ".join((identity.vendor, identity.product, *identity.variants))))
        probes = [identity.vendor, identity.model, *tokens[:4]]
        text_filters = []
        for probe in probes:
            if probe:
                text_filters.append("(vendor = ? or product like ? or title like ?)")
                params.extend([probe, f"%{probe.replace(' ', '_')}%", f"%{probe}%"])
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
        cpe_vendor = cpe.vendor.replace("_", " ")
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
        product_overlap = cpe_product_tokens & identity_tokens
        title_overlap = title_tokens & identity_tokens
        if cpe_product_tokens and cpe_product_tokens <= identity_tokens:
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
            model = identity.model.replace("_", " ")
            if model == cpe_version or model in cpe_product or model in title.casefold():
                score += 35
                reasons.append("model exact")

        if identity.version:
            if cpe_version in {"", "*", "-"}:
                score += 10
                reasons.append("installed version present")
            elif identity.version.casefold() == cpe_version.casefold():
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
        blocked = {"and", "for", "the", "with", "core", "agent", "common", "files"}
        return {
            token
            for token in re.findall(r"[a-z0-9]+", text.casefold().replace("_", " "))
            if len(token) >= 2 and token not in blocked
        }
