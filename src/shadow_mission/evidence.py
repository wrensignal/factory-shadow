"""Typed, externally pinned observations for protected feasibility transitions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .protocol import canonical_json

SCHEMA_VERSION = "0.1"

PROTECTED_TRANSITIONS = (
    "identity",
    "direct_evidence",
    "probe_confirmation",
    "correction",
    "blocker_create",
    "blocker_clear",
    "intervention_resolve",
    "release_acceptance",
)

_TRANSITION_REQUIREMENTS: dict[str, dict[str, str]] = {
    "identity": {"identity": "identified"},
    "direct_evidence": {"direct_evidence": "observed"},
    "probe_confirmation": {"probe_confirmation": "confirmed"},
    "correction": {"correction": "corrected"},
    "blocker_create": {
        "direct_evidence": "observed",
        "probe_confirmation": "confirmed",
    },
    "blocker_clear": {"correction": "corrected"},
    "intervention_resolve": {"correction": "corrected"},
    "release_acceptance": {"release_acceptance": "accepted"},
}
_RECORD_FIELDS = {
    "observation_id",
    "run_id",
    "target_id",
    "risk_id",
    "transition",
    "kind",
    "status",
    "source_class",
}


_FROZEN_EVIDENCE_FIELDS = {
    "evidence_id",
    "run_id",
    "session_alias",
    "kind",
    "source",
    "locator",
    "digest",
    "redaction_status",
    "observed_at",
}

class EvidenceRegistryError(ValueError):
    """Raised when frozen evidence cannot authorize a protected transition."""


@dataclass(frozen=True)
class FrozenObservation:
    observation_id: str
    run_id: str
    target_id: str
    risk_id: str
    transition: str
    kind: str
    status: str
    source_class: str


@dataclass(frozen=True)
class FrozenEvidenceBinding:
    """Exact immutable identity for one independently captured evidence record."""

    evidence_id: str
    run_id: str
    session_alias: str
    kind: str
    source: str
    locator: str
    digest: str
    redaction_status: str
    observed_at: int


def _binding_payload(record: Any) -> dict[str, Any]:
    return {
        "evidence_id": record.evidence_id,
        "run_id": record.run_id,
        "session_alias": record.session_alias,
        "kind": record.kind,
        "source": record.source,
        "locator": record.locator,
        "digest": record.digest,
        "redaction_status": record.redaction_status,
        "observed_at": record.observed_at,
    }


def _frozen_evidence_payload(
    bindings: Iterable[FrozenEvidenceBinding],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "evidence": [
            _binding_payload(binding)
            for binding in sorted(bindings, key=lambda item: item.evidence_id)
        ],
    }


class FrozenEvidenceRegistry:
    """Evidence identities bound to one externally approved manifest digest."""

    def __init__(
        self,
        bindings: Mapping[str, FrozenEvidenceBinding],
        *,
        source_digest: str,
    ) -> None:
        self._bindings = dict(bindings)
        self.source_digest = source_digest

    @classmethod
    def from_records(
        cls,
        records: Iterable[Any],
        *,
        expected_digest: str,
    ) -> FrozenEvidenceRegistry:
        bindings: dict[str, FrozenEvidenceBinding] = {}
        for record in records:
            if (
                record.provenance_status != "independent_frozen"
                or record.source
                not in {"factory_observation", "factory_transcript"}
            ):
                raise EvidenceRegistryError(
                    "frozen evidence record has an unapproved source"
                )
            binding = FrozenEvidenceBinding(**_binding_payload(record))
            if binding.evidence_id in bindings:
                raise EvidenceRegistryError("duplicate frozen evidence ID")
            bindings[binding.evidence_id] = binding
        if not bindings:
            raise EvidenceRegistryError("frozen evidence registry is empty")
        payload = canonical_json(_frozen_evidence_payload(bindings.values()))
        actual_digest = hashlib.sha256(payload).hexdigest()
        if actual_digest != expected_digest:
            raise EvidenceRegistryError("frozen evidence registry digest mismatch")
        return cls(bindings, source_digest=actual_digest)

    def bind(self, record: Any) -> Any:
        """Attach this registry digest after exact record verification."""
        binding = self._bindings.get(record.evidence_id)
        if binding != FrozenEvidenceBinding(**_binding_payload(record)):
            raise EvidenceRegistryError("evidence does not match frozen registry")
        return record.model_copy(update={"registry_digest": self.source_digest})

    def verify(self, record: Any) -> None:
        if (
            record.provenance_status != "independent_frozen"
            or record.registry_digest != self.source_digest
            or record.source
            not in {"factory_observation", "factory_transcript"}
        ):
            raise EvidenceRegistryError(
                "evidence is not bound to the frozen registry"
            )
        binding = self._bindings.get(record.evidence_id)
        if binding != FrozenEvidenceBinding(**_binding_payload(record)):
            raise EvidenceRegistryError("evidence does not match frozen registry")


class FrozenObservationRegistry:
    """Read-only observations loaded from one externally pinned JSON artifact."""

    def __init__(
        self, records: Mapping[str, FrozenObservation], *, source_digest: str
    ) -> None:
        self._records = dict(records)
        self.source_digest = source_digest

    def observation_ids_for(self, transition: str) -> tuple[str, ...]:
        return tuple(
            sorted(
                observation_id
                for observation_id, record in self._records.items()
                if record.transition == transition
            )
        )

    def authorize(
        self,
        *,
        provenance_status: str,
        transition: str,
        observation_ids: tuple[str, ...],
        run_id: str,
        target_id: str,
        risk_id: str,
    ) -> None:
        if transition not in _TRANSITION_REQUIREMENTS:
            raise EvidenceRegistryError("unknown protected transition")
        if provenance_status not in {"hook_authenticated", "untrusted_provenance"}:
            raise EvidenceRegistryError("unknown provenance status")
        if not observation_ids or len(set(observation_ids)) != len(observation_ids):
            raise EvidenceRegistryError("observation IDs must be nonempty and unique")
        try:
            records = [self._records[observation_id] for observation_id in observation_ids]
        except KeyError as error:
            raise EvidenceRegistryError("observation is not in the frozen registry") from error
        for record in records:
            if (
                record.run_id != run_id
                or record.target_id != target_id
                or record.risk_id != risk_id
                or record.transition != transition
            ):
                raise EvidenceRegistryError("observation context does not match transition")
            if (
                provenance_status == "untrusted_provenance"
                and record.source_class != "external_frozen"
            ):
                raise EvidenceRegistryError(
                    "untrusted provenance requires external frozen observations"
                )
        observed_requirements = {record.kind: record.status for record in records}
        if observed_requirements != _TRANSITION_REQUIREMENTS[transition]:
            raise EvidenceRegistryError(
                "observation kinds or statuses do not match transition"
            )


def authorize_protected_transition(
    *,
    registry: FrozenObservationRegistry,
    provenance_status: str,
    transition: str,
    observation_ids: tuple[str, ...],
    run_id: str,
    target_id: str,
    risk_id: str,
) -> None:
    registry.authorize(
        provenance_status=provenance_status,
        transition=transition,
        observation_ids=observation_ids,
        run_id=run_id,
        target_id=target_id,
        risk_id=risk_id,
    )



def load_frozen_evidence_registry(
    path: Path,
    *,
    expected_digest: str,
) -> FrozenEvidenceRegistry:
    """Load one canonical evidence manifest through its external digest pin."""
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise EvidenceRegistryError("cannot read frozen evidence registry") from error
    actual_digest = hashlib.sha256(payload).hexdigest()
    if actual_digest != expected_digest:
        raise EvidenceRegistryError("frozen evidence registry digest mismatch")
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceRegistryError("invalid frozen evidence registry JSON") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "evidence"}
        or value["schema_version"] != SCHEMA_VERSION
        or not isinstance(value["evidence"], list)
        or canonical_json(value) != payload
    ):
        raise EvidenceRegistryError("frozen evidence registry is not canonical")
    bindings: dict[str, FrozenEvidenceBinding] = {}
    for raw_record in value["evidence"]:
        if (
            not isinstance(raw_record, dict)
            or set(raw_record) != _FROZEN_EVIDENCE_FIELDS
            or not isinstance(raw_record["observed_at"], int)
            or isinstance(raw_record["observed_at"], bool)
            or any(
                not isinstance(raw_record[field], str) or not raw_record[field]
                for field in _FROZEN_EVIDENCE_FIELDS - {"observed_at"}
            )
            or raw_record["source"]
            not in {"factory_observation", "factory_transcript"}
            or raw_record["redaction_status"] not in {"clean", "redacted"}
            or len(raw_record["digest"]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in raw_record["digest"]
            )
        ):
            raise EvidenceRegistryError("frozen evidence binding is malformed")
        binding = FrozenEvidenceBinding(**raw_record)
        if binding.evidence_id in bindings:
            raise EvidenceRegistryError("duplicate frozen evidence ID")
        bindings[binding.evidence_id] = binding
    if not bindings:
        raise EvidenceRegistryError("frozen evidence registry is empty")
    return FrozenEvidenceRegistry(bindings, source_digest=actual_digest)

def load_frozen_observation_registry(
    path: Path, *, expected_digest: str
) -> FrozenObservationRegistry:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise EvidenceRegistryError("cannot read frozen observation registry") from error
    actual_digest = hashlib.sha256(payload).hexdigest()
    if actual_digest != expected_digest:
        raise EvidenceRegistryError("frozen observation registry digest mismatch")
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceRegistryError("invalid frozen observation registry JSON") from error
    if not isinstance(value, dict) or set(value) != {"schema_version", "observations"}:
        raise EvidenceRegistryError("frozen observation registry fields differ")
    if value["schema_version"] != SCHEMA_VERSION or not isinstance(
        value["observations"], list
    ):
        raise EvidenceRegistryError("unsupported frozen observation registry")
    records: dict[str, FrozenObservation] = {}
    for raw_record in value["observations"]:
        if not isinstance(raw_record, dict) or set(raw_record) != _RECORD_FIELDS:
            raise EvidenceRegistryError("frozen observation fields differ")
        if not all(isinstance(raw_record[field], str) and raw_record[field] for field in _RECORD_FIELDS):
            raise EvidenceRegistryError("frozen observation values must be nonempty strings")
        record = FrozenObservation(**raw_record)
        if record.observation_id in records:
            raise EvidenceRegistryError("duplicate frozen observation ID")
        records[record.observation_id] = record
    if not records:
        raise EvidenceRegistryError("frozen observation registry is empty")
    return FrozenObservationRegistry(records, source_digest=actual_digest)
