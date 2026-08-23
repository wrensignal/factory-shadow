"""Deterministic review rules over the derived Mission graph."""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from dataclasses import dataclass, field
from enum import IntEnum
from typing import (
    Any,
    Callable,
    Collection,
    Iterable,
    Literal,
    Mapping,
    Protocol,
)

from .graph import MissionGraph
from .protocol import (
    CapabilityFlags,
    ClaimRecord,
    EvidenceRecord,
    HookEnvelope,
    HookExchangeRecord,
    canonical_json,
)
from .storage import ResponsePlan, review_state_component

RuleName = Literal[
    "cross_worker_conflict", "shared_assumption", "validation_overlap"
]
FindingLevel = Literal["note", "concern", "blocker"]
RiskCategory = Literal[
    "none", "money", "security", "data_loss", "public_contract", "explicit_acceptance"
]
ProbeStatus = Literal[
    "missing",
    "pending",
    "rejected",
    "not_confirmed",
    "inconclusive",
    "confirmed",
]
ValidationOverlapStatus = Literal["active", "disabled_by_role_fallback"]
AuthorityStatus = Literal[
    "absent", "non_authoritative", "resolved", "unresolved_same_authority"
]

_HIGH_CONFIDENCE = 0.8
_CRITICAL_RISKS = frozenset(
    {"money", "security", "data_loss", "public_contract", "explicit_acceptance"}
)
_RULE_PRIORITY = {
    "cross_worker_conflict": 0,
    "shared_assumption": 1,
    "validation_overlap": 2,
}
_LEVEL_PRIORITY = {"blocker": 0, "concern": 1, "note": 2}
_LEVEL_SEVERITY = {"note": 0, "concern": 1, "blocker": 2}

_UNIT_ALIASES = {
    "cent": "cents",
    "cents": "cents",
    "usd cent": "cents",
    "usd cents": "cents",
    "usd-cent": "cents",
    "usd-cents": "cents",
    "dollar": "usd",
    "dollars": "usd",
    "usd": "usd",
    "millisecond": "milliseconds",
    "milliseconds": "milliseconds",
    "ms": "milliseconds",
    "second": "seconds",
    "seconds": "seconds",
    "sec": "seconds",
    "s": "seconds",
    "byte": "bytes",
    "bytes": "bytes",
    "kilobyte": "kilobytes",
    "kilobytes": "kilobytes",
    "kb": "kilobytes",
    "percent": "percent",
    "percentage": "percent",
    "%": "percent",
    "count": "count",
    "item": "count",
    "items": "count",
    "boolean": "boolean",
    "bool": "boolean",
}

_AUTHORITATIVE_EVIDENCE = frozenset(
    {
        ("repository_contract", "repository_contract"),
        ("database_schema", "database_schema"),
        ("mission_criterion", "mission_criterion"),
    }
)
_INTEGRATION_SOURCES = frozenset({"integration_test", "user_flow_test"})
_ISOLATED_SOURCES = frozenset({"isolated_test", "mock_test", "unit_test"})
_USE_KINDS = frozenset(
    {
        "claim_source",
        "code_use",
        "test_use",
        "feature_decision",
        "milestone_decision",
        "changed_file",
    }
)
_DIRECT_EVIDENCE_KINDS = _USE_KINDS | frozenset(
    {
        "transcript",
        "file",
        "tool",
        "test",
        "diff",
        "command",
        "repository_contract",
        "database_schema",
        "mission_criterion",
        "integration_test",
        "user_flow_test",
        "isolated_test",
        "mock_test",
        "unit_test",
    }
)
_COMPARISON_EVIDENCE_KINDS = frozenset(
    {
        "claim_source",
        "code_use",
        "test_use",
        "changed_file",
        "file",
        "test",
        "diff",
        "command",
        "repository_contract",
        "database_schema",
        "integration_test",
        "user_flow_test",
        "isolated_test",
        "mock_test",
        "unit_test",
    }
)


class EvidenceAuthority(IntEnum):
    """Explicit evidence precedence. Equal levels never break a tie."""

    UNKNOWN = 0
    ISOLATED_VALIDATION = 1
    INTEGRATION_VALIDATION = 2
    AUTHORITATIVE = 3


@dataclass(frozen=True)
class AuthorityResolution:
    status: AuthorityStatus
    authority: EvidenceAuthority
    normalized_value: str | None = None


@dataclass(frozen=True)
class ProbeAssessment:
    """One immutable independent-probe result bound to an exact snapshot."""

    probe_id: str
    run_id: str
    finding_dedup_key: str
    claim_ids: tuple[str, ...]
    evidence_digests: tuple[str, ...]
    risk_category: RiskCategory
    recommended_level: FindingLevel
    status: ProbeStatus
    authoritative_value: str | None
    snapshot_digest: str
    boundary_digest: str
    boundary_policy_digest: str
    observed_at: int
    record_digest: str
    signature: str
    source: Literal["independent_probe"] = "independent_probe"
    redaction_status: Literal["clean"] = "clean"
    zero_tools: Literal[True] = True

    @classmethod
    def create(
        cls,
        *,
        probe_id: str,
        run_id: str,
        finding_dedup_key: str,
        claim_ids: Iterable[str],
        evidence_digests: Iterable[str],
        risk_category: RiskCategory,
        recommended_level: FindingLevel,
        status: ProbeStatus,
        authoritative_value: str | None,
        snapshot_digest: str,
        boundary_digest: str,
        boundary_policy_digest: str,
        signing_key: bytes,
        observed_at: int,
    ) -> ProbeAssessment:
        values = {
            "probe_id": probe_id,
            "run_id": run_id,
            "finding_dedup_key": finding_dedup_key,
            "claim_ids": tuple(sorted(set(claim_ids))),
            "evidence_digests": tuple(sorted(set(evidence_digests))),
            "risk_category": risk_category,
            "recommended_level": recommended_level,
            "status": status,
            "authoritative_value": authoritative_value,
            "snapshot_digest": snapshot_digest,
            "boundary_digest": boundary_digest,
            "boundary_policy_digest": boundary_policy_digest,
            "observed_at": observed_at,
            "source": "independent_probe",
            "redaction_status": "clean",
            "zero_tools": True,
        }
        digest = hashlib.sha256(canonical_json(values)).hexdigest()
        signature = hmac.new(
            signing_key,
            canonical_json({**values, "record_digest": digest}),
            hashlib.sha256,
        ).hexdigest()
        return cls(**values, record_digest=digest, signature=signature)

    def __post_init__(self) -> None:
        if not self.probe_id or not self.run_id:
            raise ValueError("probe identity must not be empty")
        if (
            self.source != "independent_probe"
            or self.redaction_status != "clean"
            or self.zero_tools is not True
        ):
            raise ValueError("probe boundary metadata is invalid")
        if (
            len(self.finding_dedup_key) != 64
            or any(item not in "0123456789abcdef" for item in self.finding_dedup_key)
        ):
            raise ValueError("probe finding binding is invalid")
        normalized_claims = tuple(sorted(set(self.claim_ids)))
        normalized_digests = tuple(sorted(set(self.evidence_digests)))
        if not normalized_claims or normalized_claims != self.claim_ids:
            raise ValueError("probe claim binding is invalid")
        if not normalized_digests or normalized_digests != self.evidence_digests:
            raise ValueError("probe evidence binding is invalid")
        if any(
            len(item) != 64
            or any(character not in "0123456789abcdef" for character in item)
            for item in (
                *self.evidence_digests,
                self.snapshot_digest,
                self.boundary_digest,
                self.boundary_policy_digest,
            )
        ):
            raise ValueError("probe digest binding is invalid")
        if (
            len(self.signature) != 64
            or any(character not in "0123456789abcdef" for character in self.signature)
        ):
            raise ValueError("probe signature is invalid")
        if self.risk_category not in _CRITICAL_RISKS | {"none"}:
            raise ValueError("unknown risk category")
        if self.recommended_level not in _LEVEL_SEVERITY:
            raise ValueError("unknown probe recommendation")
        if self.status not in {
            "missing",
            "pending",
            "rejected",
            "not_confirmed",
            "inconclusive",
            "confirmed",
        }:
            raise ValueError("unknown probe status")
        if self.status == "confirmed" and not self.authoritative_value:
            raise ValueError("confirmed probe lacks an authoritative value")
        if self.status != "confirmed" and self.authoritative_value is not None:
            raise ValueError("unconfirmed probe cannot assert a value")
        values = {
            "probe_id": self.probe_id,
            "run_id": self.run_id,
            "finding_dedup_key": self.finding_dedup_key,
            "claim_ids": self.claim_ids,
            "evidence_digests": self.evidence_digests,
            "risk_category": self.risk_category,
            "recommended_level": self.recommended_level,
            "status": self.status,
            "authoritative_value": self.authoritative_value,
            "snapshot_digest": self.snapshot_digest,
            "boundary_digest": self.boundary_digest,
            "boundary_policy_digest": self.boundary_policy_digest,
            "observed_at": self.observed_at,
            "source": self.source,
            "redaction_status": self.redaction_status,
            "zero_tools": self.zero_tools,
        }
        expected = hashlib.sha256(canonical_json(values)).hexdigest()
        if self.record_digest != expected:
            raise ValueError("probe record digest does not match")

    def signature_payload(self) -> bytes:
        values = {
            "probe_id": self.probe_id,
            "run_id": self.run_id,
            "finding_dedup_key": self.finding_dedup_key,
            "claim_ids": self.claim_ids,
            "evidence_digests": self.evidence_digests,
            "risk_category": self.risk_category,
            "recommended_level": self.recommended_level,
            "status": self.status,
            "authoritative_value": self.authoritative_value,
            "snapshot_digest": self.snapshot_digest,
            "boundary_digest": self.boundary_digest,
            "boundary_policy_digest": self.boundary_policy_digest,
            "observed_at": self.observed_at,
            "source": self.source,
            "redaction_status": self.redaction_status,
            "zero_tools": self.zero_tools,
            "record_digest": self.record_digest,
        }
        return canonical_json(values)


class ProbeVerifier:
    """Authenticate probe records from one approved independent-boundary policy."""

    def __init__(self, signing_key: bytes, *, boundary_digest: str) -> None:
        if len(signing_key) < 32:
            raise ValueError("probe signing key is too short")
        if (
            len(boundary_digest) != 64
            or any(
                character not in "0123456789abcdef"
                for character in boundary_digest
            )
        ):
            raise ValueError("approved probe boundary policy digest is invalid")
        self._signing_key = bytes(signing_key)
        self._boundary_policy_digest = boundary_digest

    def verify(
        self,
        assessment: ProbeAssessment,
        *,
        snapshot_digest: str | None = None,
    ) -> bool:
        if assessment.boundary_policy_digest != self._boundary_policy_digest:
            return False
        if snapshot_digest is not None and assessment.snapshot_digest != snapshot_digest:
            return False
        expected = hmac.new(
            self._signing_key,
            assessment.signature_payload(),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, assessment.signature)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    dedup_key: str
    rule: RuleName
    level: FindingLevel
    target_sessions: tuple[str, ...]
    claim_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    evidence_digests: tuple[str, ...]
    normalized_locators: tuple[str, ...]
    normalized_properties: tuple[str, ...]
    normalized_units: tuple[str | None, ...]
    normalized_values: tuple[str, ...]
    authority: AuthorityResolution
    risk_category: RiskCategory
    probe_status: ProbeStatus
    probe_id: str | None = None
    milestone_ids: tuple[str, ...] = ()
    related_declarations: tuple[tuple[str, str, str], ...] = ()


@dataclass(frozen=True)
class Delivery:
    delivery_id: str
    target_session: str
    stored_update: int
    finding: Finding


@dataclass(frozen=True)
class RuleEvaluation:
    matches: tuple[Finding, ...]
    deliveries: tuple[Delivery, ...]
    validation_overlap_status: ValidationOverlapStatus
    review_state: Mapping[str, Any]
    _commit: Callable[[], None] = field(compare=False, repr=False)

    def commit(self) -> None:
        """Commit the selector state after a durable response append."""
        self._commit()

    def response_plan(
        self,
        body: Mapping[str, Any],
        *,
        transition_ids: tuple[str, ...] = (),
    ) -> ResponsePlan:
        """Bind selected delivery IDs and state to one durable response."""
        return ResponsePlan(
            body=body,
            guidance_ids=tuple(
                delivery.delivery_id for delivery in self.deliveries
            ),
            transition_ids=transition_ids,
            review_state=self.review_state,
            commit=self._commit,
        )


def _normalize_text(value: str, *, lowercase: bool) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    normalized = " ".join(normalized.strip().split())
    return normalized.lower() if lowercase else normalized


def normalize_locator(value: str) -> str:
    return _normalize_text(value, lowercase=True)


def normalize_property(value: str) -> str:
    return _normalize_text(value, lowercase=True)


def normalize_unit(value: str | None) -> str | None:
    """Normalize only fixed aliases. None remains distinct from unknown text."""
    if value is None:
        return None
    return _UNIT_ALIASES.get(_normalize_text(value, lowercase=True))


def normalize_value(value: Any) -> str:
    """Preserve string case and JSON type while producing a stable token."""
    if isinstance(value, str):
        normalized = _normalize_text(value, lowercase=False)
        return canonical_json({"type": "string", "value": normalized}).decode("utf-8")
    return canonical_json({"type": "json", "value": value}).decode("utf-8")


def classify_evidence_authority(record: EvidenceRecord) -> EvidenceAuthority:
    source = _normalize_text(record.source, lowercase=True)
    kind = _normalize_text(record.kind, lowercase=True)
    if (
        record.provenance_status == "authoritative_input"
        and (source, kind) == ("mission_criterion", "mission_criterion")
    ):
        return EvidenceAuthority.AUTHORITATIVE
    if record.provenance_status != "hook_authenticated":
        return EvidenceAuthority.UNKNOWN
    if (source, kind) in _AUTHORITATIVE_EVIDENCE:
        return EvidenceAuthority.AUTHORITATIVE
    if source in _INTEGRATION_SOURCES and kind in {
        "test",
        "test_use",
        "integration_test",
        "user_flow_test",
    }:
        return EvidenceAuthority.INTEGRATION_VALIDATION
    if source in _ISOLATED_SOURCES and kind in {
        "test",
        "test_use",
        "isolated_test",
        "mock_test",
        "unit_test",
    }:
        return EvidenceAuthority.ISOLATED_VALIDATION
    return EvidenceAuthority.UNKNOWN


def resolve_evidence_authority(
    values_and_evidence: Iterable[tuple[str, EvidenceRecord]],
) -> AuthorityResolution:
    """Resolve a unique top authoritative value, but never an equal-level conflict."""
    items = tuple(values_and_evidence)
    if not items:
        return AuthorityResolution("absent", EvidenceAuthority.UNKNOWN)
    highest = max(classify_evidence_authority(record) for _, record in items)
    top_values = {
        value
        for value, record in items
        if classify_evidence_authority(record) == highest
    }
    if len(top_values) > 1:
        return AuthorityResolution("unresolved_same_authority", highest)
    value = next(iter(top_values))
    if highest == EvidenceAuthority.AUTHORITATIVE:
        return AuthorityResolution("resolved", highest, value)
    return AuthorityResolution("non_authoritative", highest)


def _valid_normalized_unit(claim: ClaimRecord) -> tuple[bool, str | None]:
    normalized = normalize_unit(claim.unit)
    return claim.unit is None or normalized is not None, normalized


def _trusted_claim_evidence(
    graph: MissionGraph, claim: ClaimRecord
) -> tuple[EvidenceRecord, ...]:
    if (
        claim.provenance_status
        not in {
            "hook_authenticated",
            "independent_frozen",
            "collector_observed",
        }
        or claim.redaction_status not in {"clean", "redacted"}
    ):
        return ()
    return tuple(
        record
        for record in graph.evidence_for_claim(claim.claim_id)
        if record.redaction_status in {"clean", "redacted"}
        and record.session_alias == claim.session_alias
        and (
            (
                record.provenance_status == claim.provenance_status
                and (
                    record.provenance_status != "independent_frozen"
                    or record.source
                    in {"factory_observation", "factory_transcript"}
                )
            )
            or (
                record.provenance_status == "authoritative_input"
                and (
                    (
                        record.source == "mission_criterion"
                        and record.kind == "mission_criterion"
                    )
                    or (
                        record.source == "repository_change"
                        and record.kind == "changed_file"
                    )
                )
            )
        )
    )


def _direct_evidence(
    graph: MissionGraph, claim: ClaimRecord
) -> tuple[EvidenceRecord, ...]:
    locator = normalize_locator(claim.subject_locator)
    return tuple(
        record
        for record in _trusted_claim_evidence(graph, claim)
        if _normalize_text(record.kind, lowercase=True)
        in _DIRECT_EVIDENCE_KINDS
        and normalize_locator(record.locator) == locator
    )


def _comparison_evidence(
    graph: MissionGraph, claim: ClaimRecord
) -> tuple[EvidenceRecord, ...]:
    return tuple(
        record
        for record in _trusted_claim_evidence(graph, claim)
        if _normalize_text(record.kind, lowercase=True)
        in _COMPARISON_EVIDENCE_KINDS
    )


def _target_evidence(
    graph: MissionGraph, claim: ClaimRecord
) -> tuple[EvidenceRecord, ...]:
    target_ids = {target.evidence_id for target in claim.targets}
    return tuple(
        record
        for record in _trusted_claim_evidence(graph, claim)
        if record.evidence_id in target_ids
    )


def _evidence_signature(record: EvidenceRecord) -> tuple[str, str, str]:
    return (
        _normalize_text(record.kind, lowercase=True),
        _normalize_text(record.source, lowercase=True),
        normalize_locator(record.locator),
    )

def _verified_independent_evidence(
    graph: MissionGraph, claim: ClaimRecord
) -> tuple[EvidenceRecord, ...]:
    return tuple(
        record
        for record in _trusted_claim_evidence(graph, claim)
        if classify_evidence_authority(record)
        >= EvidenceAuthority.INTEGRATION_VALIDATION
    )

def _validation_evidence(
    graph: MissionGraph,
    claim: ClaimRecord,
) -> tuple[EvidenceRecord, ...]:
    records = {
        record.evidence_id: record
        for record in (
            *_direct_evidence(graph, claim),
            *_comparison_evidence(graph, claim),
            *_target_evidence(graph, claim),
            *_verified_independent_evidence(graph, claim),
        )
    }
    return tuple(records[item] for item in sorted(records))


def _assessment_index(
    assessments: Iterable[ProbeAssessment],
    *,
    run_id: str,
    verifier: ProbeVerifier | None,
) -> dict[str, ProbeAssessment]:
    result: dict[str, ProbeAssessment] = {}
    for assessment in assessments:
        if verifier is None or not verifier.verify(assessment):
            raise ValueError("probe assessment is not authenticated")
        if assessment.run_id != run_id:
            raise ValueError("probe assessment belongs to another run")
        prior = result.get(assessment.finding_dedup_key)
        if prior is not None and prior != assessment:
            raise ValueError("finding has conflicting probe assessments")
        result[assessment.finding_dedup_key] = assessment
    return result


def _level_for(assessment: ProbeAssessment | None) -> FindingLevel:
    if assessment is None:
        return "concern"
    deterministic_level: FindingLevel = (
        "blocker"
        if (
            assessment.risk_category in _CRITICAL_RISKS
            and assessment.status == "confirmed"
        )
        else "concern"
    )
    if _LEVEL_SEVERITY[assessment.recommended_level] < _LEVEL_SEVERITY[
        deterministic_level
    ]:
        return assessment.recommended_level
    return deterministic_level


def _finding(
    *,
    rule: RuleName,
    identity: tuple[str, ...],
    claims: Iterable[ClaimRecord],
    evidence_by_claim: Mapping[str, tuple[EvidenceRecord, ...]],
    targets: Iterable[str],
    assessments: Mapping[str, ProbeAssessment],
    milestone_ids: Iterable[str] = (),
    related_declarations: Iterable[str] = (),
) -> Finding:
    ordered_claims = tuple(sorted(claims, key=lambda item: item.claim_id))
    claim_ids = tuple(item.claim_id for item in ordered_claims)
    sessions = tuple(sorted(set(targets)))
    records_by_id = {
        record.evidence_id: record
        for claim in ordered_claims
        for record in evidence_by_claim[claim.claim_id]
    }
    records = tuple(records_by_id[item] for item in sorted(records_by_id))
    locators = tuple(
        sorted(
            {
                *(normalize_locator(item.subject_locator) for item in ordered_claims),
                *(normalize_locator(record.locator) for record in records),
            }
        )
    )
    properties = tuple(
        sorted({normalize_property(item.property) for item in ordered_claims})
    )
    units = tuple(
        sorted(
            {normalize_unit(item.unit) for item in ordered_claims},
            key=lambda item: item or "",
        )
    )
    values = tuple(sorted({normalize_value(item.value) for item in ordered_claims}))
    digests = tuple(sorted({item.digest for item in records}))
    if not identity:
        raise ValueError("finding identity must not be empty")
    key_body = {"rule": rule, "identity": tuple(identity)}
    dedup_key = hashlib.sha256(canonical_json(key_body)).hexdigest()
    assessment = assessments.get(dedup_key)
    if assessment is not None and not (
        set(assessment.claim_ids) <= set(claim_ids)
        and set(assessment.evidence_digests) <= set(digests)
    ):
        raise ValueError("probe assessment does not bind this finding")
    authority = resolve_evidence_authority(
        (normalize_value(claim.value), record)
        for claim in ordered_claims
        for record in evidence_by_claim[claim.claim_id]
    )
    if assessment is not None and assessment.status == "confirmed":
        authority = AuthorityResolution(
            "resolved",
            EvidenceAuthority.AUTHORITATIVE,
            assessment.authoritative_value,
        )
    return Finding(
        finding_id=f"finding-{dedup_key[:24]}",
        dedup_key=dedup_key,
        rule=rule,
        level=_level_for(assessment),
        target_sessions=sessions,
        claim_ids=claim_ids,
        evidence_ids=tuple(sorted(records_by_id)),
        evidence_digests=digests,
        normalized_locators=locators,
        normalized_properties=properties,
        normalized_units=units,
        normalized_values=values,
        authority=authority,
        risk_category=assessment.risk_category if assessment else "none",
        probe_status=assessment.status if assessment else "missing",
        probe_id=assessment.probe_id if assessment else None,
        milestone_ids=tuple(sorted(set(milestone_ids))),
        related_declarations=tuple(sorted(set(related_declarations))),
    )


def _finding_order(finding: Finding) -> tuple[int, int, str]:
    return (
        _LEVEL_PRIORITY[finding.level],
        _RULE_PRIORITY[finding.rule],
        finding.dedup_key,
    )


@dataclass(frozen=True)
class DeliverySelectorState:
    """Durable noise-control state reconstructed from the authoritative ledger."""

    last_updates: tuple[tuple[str, int], ...] = ()
    cooldown_remaining: tuple[tuple[str, int], ...] = ()
    delivered_severity: tuple[tuple[str, str, int], ...] = ()

    def __post_init__(self) -> None:
        if tuple(sorted(self.last_updates)) != self.last_updates:
            raise ValueError("delivery update state is not canonical")
        if tuple(sorted(self.cooldown_remaining)) != self.cooldown_remaining:
            raise ValueError("delivery cooldown state is not canonical")
        if tuple(sorted(self.delivered_severity)) != self.delivered_severity:
            raise ValueError("delivery severity state is not canonical")
        if (
            len(dict(self.last_updates)) != len(self.last_updates)
            or len(dict(self.cooldown_remaining)) != len(self.cooldown_remaining)
            or len(
                {
                    (session, dedup_key)
                    for session, dedup_key, _ in self.delivered_severity
                }
            )
            != len(self.delivered_severity)
        ):
            raise ValueError("delivery state contains duplicate identities")
        if any(not session or update < 1 for session, update in self.last_updates):
            raise ValueError("delivery update state is invalid")
        if any(
            not session or remaining < 1
            for session, remaining in self.cooldown_remaining
        ):
            raise ValueError("delivery cooldown state is invalid")
        if any(
            not session
            or len(dedup_key) != 64
            or severity not in _LEVEL_SEVERITY.values()
            for session, dedup_key, severity in self.delivered_severity
        ):
            raise ValueError("delivery severity state is invalid")

    def to_record(self, *, run_id: str) -> dict[str, Any]:
        if not run_id:
            raise ValueError("delivery state run ID must not be empty")
        return {
            "schema_version": "0.1",
            "record_type": "delivery_selector_state",
            "run_id": run_id,
            "last_updates": self.last_updates,
            "cooldown_remaining": self.cooldown_remaining,
            "delivered_severity": self.delivered_severity,
        }

    @classmethod
    def from_record(
        cls, value: Mapping[str, Any], *, run_id: str
    ) -> DeliverySelectorState:
        expected_keys = {
            "schema_version",
            "record_type",
            "run_id",
            "last_updates",
            "cooldown_remaining",
            "delivered_severity",
        }
        if (
            set(value) != expected_keys
            or value.get("schema_version") != "0.1"
            or value.get("record_type") != "delivery_selector_state"
            or value.get("run_id") != run_id
        ):
            raise ValueError("delivery state binding is invalid")
        try:
            return cls(
                last_updates=tuple(
                    (str(session), int(update))
                    for session, update in value["last_updates"]
                ),
                cooldown_remaining=tuple(
                    (str(session), int(remaining))
                    for session, remaining in value["cooldown_remaining"]
                ),
                delivered_severity=tuple(
                    (str(session), str(dedup_key), int(severity))
                    for session, dedup_key, severity
                    in value["delivered_severity"]
                ),
            )
        except (TypeError, ValueError) as error:
            raise ValueError("delivery state record is invalid") from error


class DeliverySelector:
    """Select one delivery from an authoritative stored session update."""

    def __init__(self, state: DeliverySelectorState | None = None) -> None:
        state = state or DeliverySelectorState()
        self._last_updates = dict(state.last_updates)
        self._cooldown_remaining = dict(state.cooldown_remaining)
        self._delivered_severity = {
            (session, dedup_key): severity
            for session, dedup_key, severity in state.delivered_severity
        }

    @classmethod
    def from_exchanges(
        cls,
        exchanges: Iterable[HookExchangeRecord],
        *,
        run_id: str,
    ) -> DeliverySelector:
        state = DeliverySelectorState()
        expected_sequence = 1
        for exchange in exchanges:
            if (
                exchange.ledger_sequence != expected_sequence
                or exchange.envelope.run_id != run_id
                or exchange.response.run_id != run_id
            ):
                raise ValueError("delivery state exchange sequence is invalid")
            expected_sequence += 1
            if exchange.response.review_state is not None:
                component = review_state_component(
                    exchange.response.review_state,
                    run_id=run_id,
                    record_type="delivery_selector_state",
                )
                if component is not None:
                    state = DeliverySelectorState.from_record(
                        component,
                        run_id=run_id,
                    )
        return cls(state)

    def snapshot(self) -> DeliverySelectorState:
        return DeliverySelectorState(
            last_updates=tuple(sorted(self._last_updates.items())),
            cooldown_remaining=tuple(sorted(self._cooldown_remaining.items())),
            delivered_severity=tuple(
                sorted(
                    (session, dedup_key, severity)
                    for (session, dedup_key), severity
                    in self._delivered_severity.items()
                )
            ),
        )
    def plan(
        self,
        findings: Iterable[Finding],
        *,
        updated_session: str,
        stored_update: int,
        graph: MissionGraph | None = None,
        repeatable_keys: frozenset[tuple[str, str]] = frozenset(),
    ) -> tuple[
        tuple[Delivery, ...],
        DeliverySelectorState,
        DeliverySelectorState,
    ]:
        """Evaluate one update without mutating state before ledger fsync."""
        expected = self.snapshot()
        working = DeliverySelector(expected)
        deliveries = working.select(
            findings,
            updated_session=updated_session,
            stored_update=stored_update,
            graph=graph,
            repeatable_keys=repeatable_keys,
        )
        return deliveries, expected, working.snapshot()

    def commit(
        self,
        expected: DeliverySelectorState,
        next_state: DeliverySelectorState,
    ) -> None:
        current = self.snapshot()
        if current == next_state:
            return
        if current != expected:
            raise ValueError("delivery state changed before durable commit")
        self._last_updates = dict(next_state.last_updates)
        self._cooldown_remaining = dict(next_state.cooldown_remaining)
        self._delivered_severity = {
            (session, dedup_key): severity
            for session, dedup_key, severity in next_state.delivered_severity
        }

    def _coverage_order(
        self,
        finding: Finding,
        *,
        session_claim_values: Mapping[str, str],
    ) -> tuple[int, int, int, int, str]:
        """Rank by level, rule, dissent, coverage, and stable identity."""

        covered = sum(
            1
            for session, dedup_key in self._delivered_severity
            if dedup_key == finding.dedup_key
        )
        authority = finding.authority.normalized_value
        own_values = tuple(
            session_claim_values[claim_id]
            for claim_id in finding.claim_ids
            if claim_id in session_claim_values
        )
        dissent = (
            0
            if authority is not None
            and any(value != authority for value in own_values)
            else 1
        )
        level, rule, key = _finding_order(finding)
        return (
            level,
            rule,
            dissent,
            len(finding.target_sessions) - covered,
            key,
        )

    def select(
        self,
        findings: Iterable[Finding],
        *,
        updated_session: str,
        stored_update: int,
        graph: MissionGraph | None = None,
        repeatable_keys: frozenset[tuple[str, str]] = frozenset(),
    ) -> tuple[Delivery, ...]:
        if not updated_session or stored_update < 1:
            raise ValueError("stored session update identity is invalid")
        prior_update = self._last_updates.get(updated_session, 0)
        if stored_update < prior_update:
            raise ValueError("stored session update moved backwards")
        if stored_update == prior_update:
            return ()
        self._last_updates[updated_session] = stored_update
        remaining = self._cooldown_remaining.get(updated_session, 0)
        if remaining:
            if remaining == 1:
                self._cooldown_remaining.pop(updated_session)
            else:
                self._cooldown_remaining[updated_session] = remaining - 1
            return ()

        candidates = []
        repeats = []
        for finding in findings:
            if updated_session not in finding.target_sessions:
                continue
            delivered = self._delivered_severity.get(
                (updated_session, finding.dedup_key), -1
            )
            if delivered >= _LEVEL_SEVERITY[finding.level]:
                if (updated_session, finding.dedup_key) in repeatable_keys:
                    repeats.append(finding)
                continue
            candidates.append(finding)
        session_claim_values = (
            {}
            if graph is None
            else {
                claim.claim_id: normalize_value(claim.value)
                for claim in graph.claims()
                if claim.session_alias == updated_session
            }
        )
        order_key = lambda finding: self._coverage_order(
            finding,
            session_claim_values=session_claim_values,
        )
        # After level, rule, and dissent, finish the widest-covered finding.
        # This closes more findings than one delivery across every finding.
        candidates.sort(key=order_key)
        if not candidates:
            # An unacknowledged delivery repeats after its own cooldown.
            repeats.sort(key=order_key)
            if not repeats:
                return ()
            candidates = repeats[:1]

        selected = candidates[0]
        self._delivered_severity[(updated_session, selected.dedup_key)] = (
            _LEVEL_SEVERITY[selected.level]
        )
        if selected.level in {"concern", "blocker"}:
            self._cooldown_remaining[updated_session] = 3
        delivery_body = {
            "finding": selected.dedup_key,
            "session": updated_session,
            "stored_update": stored_update,
            "level": selected.level,
        }
        delivery_id = hashlib.sha256(canonical_json(delivery_body)).hexdigest()
        return (
            Delivery(
                delivery_id=f"delivery-{delivery_id[:24]}",
                target_session=updated_session,
                stored_update=stored_update,
                finding=selected,
            ),
        )

class ReviewLedger(Protocol):
    """Authoritative response history used to resume review state."""

    run_id: str

    def exchanges(self) -> tuple[HookExchangeRecord, ...]: ...


class DeterministicRules:
    """Evaluate all sealed-replay rules and select bounded live deliveries."""

    def __init__(
        self,
        *,
        capabilities: CapabilityFlags | None = None,
        live_validation_overlap: bool | None = None,
        selector: DeliverySelector | None = None,
        probe_verifier: ProbeVerifier | None = None,
    ) -> None:
        if capabilities is not None and live_validation_overlap is not None:
            raise ValueError("provide capabilities or an explicit overlap flag, not both")
        if live_validation_overlap is None:
            live_validation_overlap = (
                capabilities is not None
                and capabilities.live_validation_overlap == "pass"
            )
        self._live_validation_overlap = live_validation_overlap
        self._selector = selector or DeliverySelector()
        self._probe_verifier = probe_verifier
    @classmethod
    def from_ledger(
        cls,
        ledger: ReviewLedger,
        *,
        capabilities: CapabilityFlags | None = None,
        live_validation_overlap: bool | None = None,
        probe_verifier: ProbeVerifier | None = None,
    ) -> DeterministicRules:
        """Resume the production review engine from durable responses."""
        return cls(
            capabilities=capabilities,
            live_validation_overlap=live_validation_overlap,
            selector=DeliverySelector.from_exchanges(
                ledger.exchanges(), run_id=ledger.run_id
            ),
            probe_verifier=probe_verifier,
        )

    def detect(
        self,
        graph: MissionGraph,
        *,
        probes: Iterable[ProbeAssessment] = (),
    ) -> tuple[Finding, ...]:
        assessments = _assessment_index(
            probes, run_id=graph.run_id, verifier=self._probe_verifier
        )
        findings = [
            *self._cross_worker_conflicts(graph, assessments),
            *self._shared_assumptions(graph, assessments),
            *self._validation_overlaps(graph, assessments),
        ]
        by_key: dict[str, Finding] = {}
        for finding in findings:
            prior = by_key.get(finding.dedup_key)
            if prior is not None and prior != finding:
                raise ValueError("deterministic finding key collision")
            by_key[finding.dedup_key] = finding
        return tuple(sorted(by_key.values(), key=_finding_order))

    def evaluate(
        self,
        graph: MissionGraph,
        *,
        updated_session: str,
        stored_update: int,
        probes: Iterable[ProbeAssessment] = (),
        repeatable_keys: frozenset[tuple[str, str]] = frozenset(),
    ) -> RuleEvaluation:
        matches = self.detect(graph, probes=probes)
        deliverable = matches
        status: ValidationOverlapStatus = "active"
        if not self._live_validation_overlap:
            status = "disabled_by_role_fallback"
            deliverable = tuple(
                item for item in matches if item.rule != "validation_overlap"
            )
        deliveries, expected_state, next_state = self._selector.plan(
            deliverable,
            updated_session=updated_session,
            stored_update=stored_update,
            repeatable_keys=repeatable_keys,
            graph=graph,
        )
        return RuleEvaluation(
            matches=matches,
            deliveries=deliveries,
            validation_overlap_status=status,
            review_state=next_state.to_record(run_id=graph.run_id),
            _commit=lambda: self._selector.commit(expected_state, next_state),
        )

    def response_decider(
        self,
        graph: MissionGraph,
        *,
        probes: Iterable[ProbeAssessment] = (),
        body: Mapping[str, Any] | None = None,
    ) -> Callable[[HookEnvelope], ResponsePlan]:
        """Plan review state only inside the ledger's serialized callback."""
        frozen_probes = tuple(probes)
        response_body = dict(body or {})

        def decide(envelope: HookEnvelope) -> ResponsePlan:
            if envelope.run_id != graph.run_id:
                raise ValueError("review graph belongs to another run")
            updates = dict(self._selector.snapshot().last_updates)
            evaluation = self.evaluate(
                graph,
                updated_session=envelope.session_alias,
                stored_update=updates.get(envelope.session_alias, 0) + 1,
                probes=frozen_probes,
            )
            return evaluation.response_plan(response_body)

        return decide

    def _eligible_workers(
        self, graph: MissionGraph
    ) -> tuple[
        tuple[ClaimRecord, tuple[EvidenceRecord, ...], str | None, str], ...
    ]:
        eligible = []
        for claim in graph.claims():
            valid_unit, unit = _valid_normalized_unit(claim)
            role_id = graph.role_id_for_session(claim.session_alias)
            if (
                graph.role_for_session(claim.session_alias) != "worker"
                or role_id is None
                or claim.confidence < _HIGH_CONFIDENCE
                or not valid_unit
            ):
                continue
            direct = _direct_evidence(graph, claim)
            if direct:
                eligible.append((claim, direct, unit, role_id))
        return tuple(eligible)

    @staticmethod
    def _related_declarations(
        graph: MissionGraph, sessions: Collection[str], exclude: str
    ) -> tuple[tuple[str, str, str], ...]:
        """Name the repository files these sessions declared for this subject.

        A unit conflict is recorded where the disagreement is visible, which is
        rarely the file that must change. Each conflicting session's own claims
        already name the source files it owns, so the guidance can point at the
        code instead of only at the record.
        """

        found: set[tuple[str, str, str]] = set()
        for claim in graph.claims():
            if claim.session_alias not in sessions:
                continue
            locator = normalize_locator(claim.subject_locator)
            if not locator or locator == exclude:
                continue
            if not any(
                target.kind == "file"
                and normalize_locator(target.target_id) == locator
                for target in claim.targets
            ):
                continue
            found.add(
                (
                    locator,
                    normalize_property(claim.property),
                    normalize_value(claim.value),
                )
            )
        return tuple(sorted(found))

    def _cross_worker_conflicts(
        self,
        graph: MissionGraph,
        assessments: Mapping[str, ProbeAssessment],
    ) -> tuple[Finding, ...]:
        groups: dict[
            tuple[str, str, str | None],
            list[tuple[ClaimRecord, tuple[EvidenceRecord, ...], str]],
        ] = {}
        for claim, direct, unit, role_id in self._eligible_workers(graph):
            key = (
                normalize_locator(claim.subject_locator),
                normalize_property(claim.property),
                unit,
            )
            groups.setdefault(key, []).append((claim, direct, role_id))

        findings = []
        for group_key, items in groups.items():
            sessions = {claim.session_alias for claim, _, _ in items}
            role_ids = {role_id for _, _, role_id in items}
            values = {normalize_value(claim.value) for claim, _, _ in items}
            if len(sessions) < 2 or len(role_ids) < 2 or len(values) < 2:
                continue
            orchestrators = graph.sessions_for_role("orchestrator")
            targets = sessions | (
                set(orchestrators) if len(orchestrators) == 1 else set()
            )
            claims = tuple(claim for claim, _, _ in items)
            evidence = {claim.claim_id: direct for claim, direct, _ in items}
            findings.append(
                _finding(
                    rule="cross_worker_conflict",
                    identity=(group_key[0], group_key[1], group_key[2] or ""),
                    claims=claims,
                    evidence_by_claim=evidence,
                    targets=targets,
                    assessments=assessments,
                    related_declarations=self._related_declarations(
                        graph, sessions, group_key[0]
                    ),
                )
            )
        return tuple(findings)

    def _shared_assumptions(
        self,
        graph: MissionGraph,
        assessments: Mapping[str, ProbeAssessment],
    ) -> tuple[Finding, ...]:
        item_type = tuple[
            ClaimRecord,
            tuple[EvidenceRecord, ...],
            tuple[EvidenceRecord, ...],
            str,
        ]
        groups: dict[
            tuple[str, str, str | None, str],
            list[item_type],
        ] = {}
        for claim, direct, unit, role_id in self._eligible_workers(graph):
            if not graph.claim_targets(claim.claim_id):
                continue
            use_evidence = tuple(
                record
                for record in direct
                if _normalize_text(record.kind, lowercase=True) in _USE_KINDS
            )
            key = (
                normalize_locator(claim.subject_locator),
                normalize_property(claim.property),
                unit,
                normalize_value(claim.value),
            )
            groups.setdefault(key, []).append(
                (claim, direct, use_evidence, role_id)
            )

        findings = []
        for group_key, items in groups.items():
            non_authoritative = tuple(
                item
                for item in items
                if not any(
                    classify_evidence_authority(record)
                    == EvidenceAuthority.AUTHORITATIVE
                    for record in item[1]
                )
            )
            subgroups: list[tuple[tuple[item_type, ...], str]] = []
            absent = tuple(item for item in non_authoritative if not item[2])
            if absent:
                subgroups.append((absent, ""))
            by_source: dict[tuple[str, str], list[item_type]] = {}
            for item in non_authoritative:
                sources = {
                    (
                        _normalize_text(record.source, lowercase=True),
                        normalize_locator(record.locator),
                    )
                    for record in item[2]
                }
                for source in sources:
                    by_source.setdefault(source, []).append(item)
            for source_key, source_items in by_source.items():
                subgroups.append(
                    (
                        tuple(source_items),
                        f"{source_key[0]}|{source_key[1]}",
                    )
                )

            for subgroup, marker in subgroups:
                sessions = {item[0].session_alias for item in subgroup}
                role_ids = {item[3] for item in subgroup}
                if len(sessions) < 2 or len(role_ids) < 2:
                    continue
                claims = tuple(item[0] for item in subgroup)
                evidence = {
                    item[0].claim_id: tuple(
                        sorted(
                            {
                                record.evidence_id: record
                                for record in (
                                    *item[1],
                                    *_target_evidence(graph, item[0]),
                                )
                            }.values(),
                            key=lambda record: record.evidence_id,
                        )
                    )
                    for item in subgroup
                }
                material_targets = sorted(
                    {
                        f"{kind}|{target_id}"
                        for item in subgroup
                        for kind, target_id in graph.claim_targets(
                            item[0].claim_id
                        )
                    }
                )
                findings.append(
                    _finding(
                        rule="shared_assumption",
                        identity=(
                            group_key[0],
                            group_key[1],
                            group_key[2] or "",
                            group_key[3],
                            f"src:{marker}",
                            *(f"tgt:{target}" for target in material_targets),
                        ),
                        claims=claims,
                        evidence_by_claim=evidence,
                        targets=sessions,
                        assessments=assessments,
                    )
                )
        return tuple(findings)

    def _validation_overlaps(
        self,
        graph: MissionGraph,
        assessments: Mapping[str, ProbeAssessment],
    ) -> tuple[Finding, ...]:
        overlaps: dict[
            str,
            tuple[
                dict[str, ClaimRecord],
                dict[str, tuple[EvidenceRecord, ...]],
                set[str],
            ],
        ] = {}
        for milestone_id in graph.milestones():
            claims = graph.claims_for_milestone(milestone_id)
            workers: list[tuple[ClaimRecord, tuple[EvidenceRecord, ...]]] = []
            validators: dict[
                str, list[tuple[ClaimRecord, tuple[EvidenceRecord, ...]]]
            ] = {}
            for claim in claims:
                valid_unit, _ = _valid_normalized_unit(claim)
                if claim.confidence < _HIGH_CONFIDENCE or not valid_unit:
                    continue
                direct = _direct_evidence(graph, claim)
                if not direct:
                    continue
                role = graph.role_for_session(claim.session_alias)
                if role == "worker":
                    workers.append((claim, direct))
                elif role == "validator":
                    validators.setdefault(claim.session_alias, []).append(
                        (claim, direct)
                    )
            if not workers:
                continue
            worker_signatures = {
                _evidence_signature(record)
                for claim, _ in workers
                for record in _comparison_evidence(graph, claim)
            }
            worker_independent_signatures = {
                _evidence_signature(record)
                for claim, _ in workers
                for record in _verified_independent_evidence(graph, claim)
            }
            worker_targets = {
                target
                for claim, _ in workers
                for target in graph.claim_targets(claim.claim_id)
            }
            for validator_session, validator_items in validators.items():
                validator_signatures = {
                    _evidence_signature(record)
                    for claim, _ in validator_items
                    for record in _comparison_evidence(graph, claim)
                }
                validator_independent_signatures = {
                    _evidence_signature(record)
                    for claim, _ in validator_items
                    for record in _verified_independent_evidence(graph, claim)
                }
                if (
                    validator_independent_signatures
                    - worker_independent_signatures
                ):
                    continue
                validator_targets = {
                    target
                    for claim, _ in validator_items
                    for target in graph.claim_targets(claim.claim_id)
                }
                independent_targets = {
                    target
                    for target in validator_targets - worker_targets
                    if target[0] == "feature"
                }
                if independent_targets:
                    continue
                if (
                    not validator_signatures
                    or not validator_signatures <= worker_signatures
                ):
                    continue
                combined = tuple(
                    sorted(
                        [claim for claim, _ in workers]
                        + [claim for claim, _ in validator_items],
                        key=lambda item: item.claim_id,
                    )
                )
                evidence = {
                    claim.claim_id: _validation_evidence(graph, claim)
                    for claim, _ in [*workers, *validator_items]
                }
                prior = overlaps.get(validator_session)
                if prior is None:
                    overlaps[validator_session] = (
                        {claim.claim_id: claim for claim in combined},
                        evidence,
                        {milestone_id},
                    )
                else:
                    prior[0].update(
                        {claim.claim_id: claim for claim in combined}
                    )
                    prior[1].update(evidence)
                    prior[2].add(milestone_id)

        return tuple(
            _finding(
                rule="validation_overlap",
                identity=(validator_session,),
                claims=claims_by_id.values(),
                evidence_by_claim=evidence,
                targets=(validator_session,),
                assessments=assessments,
                milestone_ids=milestone_ids,
            )
            for validator_session, (
                claims_by_id,
                evidence,
                milestone_ids,
            ) in sorted(overlaps.items())
        )
