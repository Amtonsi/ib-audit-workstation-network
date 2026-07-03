from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from .cpe import CpeName, VersionDecision, compare_version
from .identity import InventoryIdentity


@dataclass(frozen=True)
class ApplicabilityDecision:
    state: Literal["confirmed", "potential", "not_affected", "not_applicable"]
    criteria: tuple[str, ...]
    reason: str
    version_decision: VersionDecision | None


class CpeApplicabilityEvaluator:
    def evaluate(
        self,
        configurations: list[dict[str, Any]],
        target: InventoryIdentity,
        host_identities: list[InventoryIdentity],
    ) -> ApplicabilityDecision:
        decisions = [
            self._evaluate_operator(
                str(configuration.get("operator") or "OR"),
                [
                    self._evaluate_node(node, target, host_identities)
                    for node in configuration.get("nodes", [])
                    if isinstance(node, dict)
                ],
            )
            for configuration in configurations
            if isinstance(configuration, dict)
        ]
        return self._evaluate_operator("OR", decisions)

    def _evaluate_node(
        self,
        node: dict[str, Any],
        target: InventoryIdentity,
        host_identities: list[InventoryIdentity],
    ) -> ApplicabilityDecision:
        decisions: list[ApplicabilityDecision] = []
        decisions.extend(
            self._evaluate_cpe_match(item, target, host_identities)
            for item in node.get("cpeMatch", [])
            if isinstance(item, dict)
        )
        decisions.extend(
            self._evaluate_node(child, target, host_identities)
            for child in node.get("children", [])
            if isinstance(child, dict)
        )
        decision = self._evaluate_operator(str(node.get("operator") or "OR"), decisions)
        if bool(node.get("negate")):
            return self._negate(decision)
        return decision

    def _evaluate_cpe_match(
        self,
        item: dict[str, Any],
        target: InventoryIdentity,
        host_identities: list[InventoryIdentity],
    ) -> ApplicabilityDecision:
        criteria = str(item.get("criteria") or "")
        if not criteria:
            return self._decision("not_applicable", (), "CPE criteria is missing")
        try:
            cpe = CpeName.parse(criteria)
        except ValueError as exc:
            return self._decision("not_applicable", (criteria,), str(exc))

        vulnerable = bool(item.get("vulnerable", False))
        identities = [target] if vulnerable else host_identities
        for identity in identities:
            if not self._identity_matches_cpe(identity, cpe):
                continue
            if not vulnerable:
                return self._decision("confirmed", (criteria,), "context CPE matched")
            version_decision = compare_version(
                identity.version,
                cpe_version=cpe.version,
                version_start_including=str(item.get("versionStartIncluding") or ""),
                version_start_excluding=str(item.get("versionStartExcluding") or ""),
                version_end_including=str(item.get("versionEndIncluding") or ""),
                version_end_excluding=str(item.get("versionEndExcluding") or ""),
            )
            if version_decision.state in {"affected", "product_wide"}:
                return self._decision(
                    "confirmed",
                    (criteria,),
                    version_decision.reason,
                    version_decision,
                )
            if version_decision.state in {"unknown_version", "not_comparable"}:
                reason = (
                    "hardware matched; firmware version is unknown"
                    if self._is_firmware_cpe(cpe) or identity.object_type in self._hardware_types()
                    else version_decision.reason
                )
                return self._decision("potential", (criteria,), reason, version_decision)
            return self._decision("not_affected", (criteria,), version_decision.reason, version_decision)
        return self._decision("not_applicable", (criteria,), "CPE did not match target inventory")

    def _evaluate_operator(
        self,
        operator: str,
        decisions: list[ApplicabilityDecision],
    ) -> ApplicabilityDecision:
        if not decisions:
            return self._decision("not_applicable", (), "no applicability decisions")
        operator = operator.upper()
        if operator == "AND":
            for state in ("not_affected", "not_applicable", "potential"):
                matching = [decision for decision in decisions if decision.state == state]
                if matching:
                    return self._combine(state, matching[0].reason, decisions)
            return self._combine("confirmed", "all applicability branches matched", decisions)
        for state in ("confirmed", "potential", "not_affected", "not_applicable"):
            matching = [decision for decision in decisions if decision.state == state]
            if matching:
                return self._combine(state, matching[0].reason, matching)
        return self._decision("not_applicable", (), "no applicable CPE branch")

    def _negate(self, decision: ApplicabilityDecision) -> ApplicabilityDecision:
        if decision.state in {"confirmed", "potential"}:
            return self._decision(
                "not_affected",
                decision.criteria,
                f"negated applicability branch matched: {decision.reason}",
                decision.version_decision,
            )
        return self._decision(
            "confirmed",
            decision.criteria,
            "negated applicability branch did not match",
            decision.version_decision,
        )

    @staticmethod
    def _combine(
        state: Literal["confirmed", "potential", "not_affected", "not_applicable"],
        reason: str,
        decisions: list[ApplicabilityDecision],
    ) -> ApplicabilityDecision:
        criteria: list[str] = []
        version_decision = None
        for decision in decisions:
            criteria.extend(decision.criteria)
            if version_decision is None and decision.version_decision is not None:
                version_decision = decision.version_decision
        return ApplicabilityDecision(state, tuple(dict.fromkeys(criteria)), reason, version_decision)

    @staticmethod
    def _decision(
        state: Literal["confirmed", "potential", "not_affected", "not_applicable"],
        criteria: tuple[str, ...],
        reason: str,
        version_decision: VersionDecision | None = None,
    ) -> ApplicabilityDecision:
        return ApplicabilityDecision(state, criteria, reason, version_decision)

    def _identity_matches_cpe(self, identity: InventoryIdentity, cpe: CpeName) -> bool:
        if not self._part_is_compatible(identity, cpe):
            return False
        cpe_vendor = cpe.vendor.replace("_", " ")
        if identity.vendor and cpe_vendor and identity.vendor != cpe_vendor:
            return False
        identity_tokens = self._tokens(
            " ".join((identity.vendor, identity.product, identity.model, *identity.variants))
        )
        cpe_product_tokens = self._tokens(cpe.product)
        cpe_version_tokens = self._tokens(cpe.version)
        if cpe_product_tokens and cpe_product_tokens <= identity_tokens:
            return True
        if identity.model and identity.model.replace("_", " ") in self._tokens(" ".join((cpe.product, cpe.version))):
            return True
        return bool((cpe_product_tokens | cpe_version_tokens) & identity_tokens)

    def _part_is_compatible(self, identity: InventoryIdentity, cpe: CpeName) -> bool:
        if cpe.part in self._parts_for_identity(identity):
            return True
        return identity.object_type in self._hardware_types() and cpe.part == "o" and self._is_firmware_cpe(cpe)

    @staticmethod
    def _is_firmware_cpe(cpe: CpeName) -> bool:
        tokens = CpeApplicabilityEvaluator._tokens(" ".join((cpe.product, cpe.version)))
        return bool(tokens & {"firmware", "microcode", "bios", "uefi"})

    @staticmethod
    def _parts_for_identity(identity: InventoryIdentity) -> tuple[str, ...]:
        if identity.object_type == "operating_system":
            return ("o",)
        if identity.object_type in CpeApplicabilityEvaluator._hardware_types():
            return ("h",)
        return ("a",)

    @staticmethod
    def _hardware_types() -> set[str]:
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
    def _tokens(text: str) -> set[str]:
        return {
            token
            for token in re.findall(r"[a-z0-9]+", text.casefold().replace("_", " "))
            if len(token) >= 2
        }
