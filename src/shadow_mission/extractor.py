"""Deterministic claim triggers and the recorded extraction boundary.

This module does not start Droid, a model, a VM, or a network client. A future
live broker can implement :class:`ExtractionBroker` and return the same raw
output that the recorded broker returns here.
"""

from __future__ import annotations

import hashlib
import math
import posixpath
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Protocol, Sequence, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


from .evidence import EvidenceRegistryError, FrozenEvidenceRegistry
from .protocol import (
    ClaimRecord,
    ClaimTarget,
    EvidenceRecord,
    HookEnvelope,
    canonical_json,
    is_edit_tool,
    tool_input_paths,
    tool_result_failed,
    walk_values,
)
from .redaction import sanitize_value

TriggerKind = Literal[
    "contract_or_schema_edit",
    "test_edit",
    "failed_command_or_test",
    "cross_session_edit",
    "completion_attempt",
]
QuarantineReason = Literal[
    "missing_output",
    "malformed_output",
    "timeout",
    "unsafe_boundary",
    "self_observed",
    "unanchored_locator",
    "unknown_evidence",
    "cross_run_evidence",
    "cross_session_evidence",
    "unredacted_output",
    "untrusted_provenance",
    "criterion_mismatch",
]

_TRIGGER_ORDER: tuple[TriggerKind, ...] = (
    "contract_or_schema_edit",
    "test_edit",
    "failed_command_or_test",
    "cross_session_edit",
    "completion_attempt",
)
_CONTRACT_PATH = re.compile(
    r"(?:^|/)(?:contracts?|schemas?|migrations?)(?:/|$)|"
    r"(?:^|[./_-])(?:contracts?|openapi|swagger|graphql|schema)(?:[./_-]|$)|"
    r"\.(?:avsc|graphqls?|proto|sql)$|"
    r"(?:^|/)(?:src/)?(?:webhook|invoice_export|payment_api|money)\.py$|"
    r"(?:^|/)(?:docs/)?stale-guide\.md$",
    re.IGNORECASE,
)
_TEST_PATH = re.compile(
    r"(?:^|/)(?:tests?|specs?)(?:/|$)|"
    r"(?:^|[._-])(?:test|spec)(?:[._-]|$)",
    re.IGNORECASE,
)
_FORBIDDEN_ENVIRONMENT_KEYS = frozenset(
    {
        "SHADOW_MISSION_RUN_FILE",
        "SHADOW_MISSION_RUN_DESCRIPTOR",
        "SHADOW_MISSION_RUN_SECRET",
        "SHADOW_MISSION_COLLECTOR_URL",
        "SHADOW_MISSION_CORRELATION_ID",
        "SHADOW_MISSION_LOG_GROUP_ID",
    }
)
_MATERIAL_TARGET_KINDS = {
    "file": frozenset({"changed_file", "diff"}),
    "test": frozenset(
        {"test", "test_use", "unit_test", "integration_test", "user_flow_test"}
    ),
    "feature": frozenset({"feature_decision"}),
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExtractedClaim(_StrictModel):
    """The one schema accepted from both recorded and future live brokers."""

    subject: str = Field(min_length=1)
    subject_locator: str = Field(min_length=1)
    property: str = Field(min_length=1)
    value: Any
    unit: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    targets: tuple[ClaimTarget, ...] = ()

    @field_validator("subject", "subject_locator", "property")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("claim text must not be blank")
        return value

    @field_validator("unit")
    @classmethod
    def reject_blank_unit(cls, value: str | None) -> str | None:
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ValueError("unit must be absent or non-blank")
        return value

    @field_validator("confidence", mode="before")
    @classmethod
    def require_numeric_confidence(cls, value: Any) -> Any:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("confidence must be a JSON number")
        if not math.isfinite(float(value)):
            raise ValueError("confidence must be finite")
        return value

    @field_validator("evidence_ids")
    @classmethod
    def reject_blank_or_duplicate_evidence(
        cls, value: tuple[str, ...]
    ) -> tuple[str, ...]:
        if any(not isinstance(item, str) or not item.strip() for item in value):
            raise ValueError("evidence IDs must not be blank")
        if len(set(value)) != len(value):
            raise ValueError("evidence IDs must be unique")
        return value

    @field_validator("targets")
    @classmethod
    def normalize_targets(
        cls, value: tuple[ClaimTarget, ...]
    ) -> tuple[ClaimTarget, ...]:
        value = tuple(
            item.model_copy(update={"attributes": {}})
            if item.kind == "file" and item.attributes
            else item
            for item in value
        )
        ordered = tuple(
            sorted(
                value,
                key=lambda item: (
                    item.kind,
                    _normalize_locator(item.target_id),
                    canonical_json(item.attributes),
                ),
            )
        )
        identities = {
            (item.kind, _normalize_locator(item.target_id)) for item in ordered
        }
        if len(identities) != len(ordered):
            raise ValueError("claim targets must be unique")
        return ordered

    @field_validator("value")
    @classmethod
    def require_json_value(cls, value: Any) -> Any:
        value = _normalize_json_value(value)
        _validate_json_value(value)
        canonical_json({"value": value})
        return value


class BoundaryMetadata(_StrictModel):
    """Recorded proof that extraction ran outside the observed Mission."""

    factory_home: Literal["clean"]
    enabled_tools: tuple[str, ...] = ()
    timeout_seconds: Literal[30]
    shadow_activation_stripped: Literal[True]
    mission_correlation_stripped: Literal[True]
    internal_session_alias: str = Field(min_length=1)
    environment_keys: tuple[str, ...] = ()

    @field_validator("factory_home", mode="before")
    @classmethod
    def require_clean_home_marker(cls, value: Any) -> Any:
        if type(value) is not str or value != "clean":
            raise ValueError("extractor boundary must use a clean Factory home")
        return value

    @field_validator("timeout_seconds", mode="before")
    @classmethod
    def require_exact_timeout(cls, value: Any) -> Any:
        if type(value) is not int or value != 30:
            raise ValueError("extractor boundary timeout must be exactly 30 seconds")
        return value

    @field_validator(
        "shadow_activation_stripped",
        "mission_correlation_stripped",
        mode="before",
    )
    @classmethod
    def require_stripped_environment_marker(cls, value: Any) -> Any:
        if value is not True:
            raise ValueError("extractor boundary retained Mission activation")
        return value


    @field_validator("enabled_tools")
    @classmethod
    def require_no_tools(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value:
            raise ValueError("extractor boundary must have no enabled tools")
        return value

    @field_validator("environment_keys")
    @classmethod
    def reject_shadow_environment(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = {item.upper() for item in value}
        if normalized & _FORBIDDEN_ENVIRONMENT_KEYS:
            raise ValueError("extractor boundary retained Mission environment")
        return value


class ApprovedMissionCriterion(_StrictModel):
    """One immutable intended-behavior value approved for a Mission run."""

    run_id: str = Field(min_length=1)
    criterion_id: str = Field(min_length=1)
    locator: str = Field(min_length=1)
    property: str = Field(min_length=1)
    value: Any
    unit: str | None = None
    observed_at: int

    @field_validator("value")
    @classmethod
    def validate_json_value(cls, value: Any) -> Any:
        canonical_json({"value": value})
        return value


class ApprovedMilestoneLink(_StrictModel):
    """One trusted locator-to-milestone relation from the Mission plan."""

    run_id: str = Field(min_length=1)
    relation_id: str = Field(min_length=1)
    locator: str = Field(min_length=1)
    milestone_ids: tuple[str, ...] = Field(min_length=1)

    @field_validator("milestone_ids")
    @classmethod
    def validate_milestones(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("milestone IDs must be sorted and unique")
        return value


class ApprovedRepositoryChange(_StrictModel):
    """One immutable changed-file observation from the repository boundary."""
    session_alias: str = Field(min_length=1)
    event_id: str = Field(min_length=1)

    run_id: str = Field(min_length=1)
    change_id: str = Field(min_length=1)
    locator: str = Field(min_length=1)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: int


class ExtractionRequest(_StrictModel):
    """Sanitized trigger and evidence metadata supplied to a broker."""

    run_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    source_session_alias: str = Field(min_length=1)
    trigger_kinds: tuple[TriggerKind, ...] = Field(min_length=1)
    trigger_payload: dict[str, Any]
    evidence: tuple[EvidenceRecord, ...]
    approved_criteria: tuple[ApprovedMissionCriterion, ...]
    approved_milestone_links: tuple[ApprovedMilestoneLink, ...] = ()
    approved_repository_changes: tuple[ApprovedRepositoryChange, ...] = ()

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            canonical_json(self.model_dump(mode="json"))
        ).hexdigest()


@dataclass(frozen=True)
class BrokerAttempt:
    """One broker observation. Raw rejected output is never copied elsewhere."""

    boundary: object
    output: object | None
    timed_out: bool = False


@runtime_checkable
class ExtractionBroker(Protocol):
    """Boundary for recorded extraction now and a live implementation later."""

    def extract(self, request: ExtractionRequest) -> BrokerAttempt:
        """Return one bounded attempt without persisting rejected output."""
        ...

    def abort(self) -> bool:
        """Acknowledge that no extraction boundary remains active."""
        ...


class RecordedExtractionBroker:
    """Replay one fixed broker attempt without any external call."""

    def __init__(self, attempt: BrokerAttempt) -> None:
        self._attempt = attempt
        self.requests: list[ExtractionRequest] = []

    def extract(self, request: ExtractionRequest) -> BrokerAttempt:
        self.requests.append(request)
        return self._attempt

    def abort(self) -> bool:
        return True


class QuarantineRecord(_StrictModel):
    """A bounded reason. It intentionally contains no rejected broker output."""

    reason: QuarantineReason


@dataclass(frozen=True)
class ExtractionOutcome:
    trigger_kinds: tuple[TriggerKind, ...]
    claims: tuple[ClaimRecord, ...] = ()
    quarantine: QuarantineRecord | None = None
    derived_evidence: tuple[EvidenceRecord, ...] = ()


class TriggerClassifier:
    """Classify high-signal events and remember which session edited each path."""

    def __init__(self) -> None:
        self._editing_sessions: dict[str, str] = {}

    def observe(
        self,
        envelope: HookEnvelope,
        *,
        repository_changes: Sequence[ApprovedRepositoryChange] = (),
    ) -> tuple[TriggerKind, ...]:
        triggers: set[TriggerKind] = set()
        paths = {
            *_edited_paths(envelope),
            *(
                posixpath.normpath(item.locator.strip().replace("\\", "/"))
                for item in repository_changes
                if item.event_id == envelope.event_id
            ),
        }
        if any(_CONTRACT_PATH.search(path) for path in paths):
            triggers.add("contract_or_schema_edit")
        if any(_TEST_PATH.search(path) for path in paths):
            triggers.add("test_edit")
        if _failed_command_or_test(envelope):
            triggers.add("failed_command_or_test")
        for path in paths:
            prior_session = self._editing_sessions.get(path)
            if prior_session is not None and prior_session != envelope.session_alias:
                triggers.add("cross_session_edit")
            self._editing_sessions[path] = envelope.session_alias
        if envelope.hook_event_name in {"Stop", "SubagentStop"}:
            triggers.add("completion_attempt")
        return tuple(kind for kind in _TRIGGER_ORDER if kind in triggers)


class ClaimExtractor:
    """Validate one recorded or live broker result and convert accepted claims."""

    def __init__(
        self,
        broker: ExtractionBroker,
        *,
        classifier: TriggerClassifier | None = None,
        frozen_evidence_registry: FrozenEvidenceRegistry | None = None,
    ) -> None:
        self._broker = broker
        self._classifier = classifier or TriggerClassifier()
        self._frozen_evidence_registry = frozen_evidence_registry

    def abort(self) -> bool:
        """Stop the broker boundary before controller shutdown."""

        try:
            return self._broker.abort() is True
        except Exception:
            return False

    def extract(
        self,
        envelope: HookEnvelope,
        evidence: Sequence[EvidenceRecord],
        *,
        approved_criteria: Sequence[ApprovedMissionCriterion] = (),
        approved_milestone_links: Sequence[ApprovedMilestoneLink] = (),
        approved_repository_changes: Sequence[ApprovedRepositoryChange] = (),
    ) -> ExtractionOutcome:
        current_changes = tuple(
            ApprovedRepositoryChange.model_validate_json(item.model_dump_json())
            for item in approved_repository_changes
            if item.run_id == envelope.run_id
            and item.session_alias == envelope.session_alias
            and item.observed_at <= envelope.observed_at
        )
        triggers = self._classifier.observe(
            envelope,
            repository_changes=current_changes,
        )
        if not triggers:
            return ExtractionOutcome(trigger_kinds=())

        current_criteria = tuple(
            ApprovedMissionCriterion.model_validate_json(item.model_dump_json())
            for item in approved_criteria
            if item.run_id == envelope.run_id
        )
        current_links = tuple(
            ApprovedMilestoneLink.model_validate_json(item.model_dump_json())
            for item in approved_milestone_links
            if item.run_id == envelope.run_id
        )
        if not _approved_inputs_are_unambiguous(
            current_criteria,
            current_links,
            current_changes,
        ):
            return _quarantined(triggers, "malformed_output")
        if any(item.run_id != envelope.run_id for item in evidence):
            return _quarantined(triggers, "cross_run_evidence")
        if any(item.session_alias != envelope.session_alias for item in evidence):
            return _quarantined(triggers, "cross_session_evidence")
        if envelope.provenance_status == "hook_authenticated":
            accepted_provenance = "hook_authenticated"
            provenance_valid = all(
                item.provenance_status == "hook_authenticated"
                for item in evidence
            )
        elif envelope.provenance_status == "untrusted_provenance":
            live_sources = {"transcript", "hook_fallback"}
            if evidence and all(item.source in live_sources for item in evidence):
                accepted_provenance = "collector_observed"
                provenance_valid = True
            else:
                accepted_provenance = "independent_frozen"
                provenance_valid = (
                    bool(evidence)
                    and self._frozen_evidence_registry is not None
                )
                if provenance_valid:
                    try:
                        for item in evidence:
                            self._frozen_evidence_registry.verify(item)
                    except EvidenceRegistryError:
                        provenance_valid = False
        else:
            accepted_provenance = "untrusted_provenance"
            provenance_valid = False
        if not provenance_valid:
            return _quarantined(triggers, "untrusted_provenance")
        projected = _project_repository_evidence(current_changes)
        evidence_by_id: dict[str, EvidenceRecord] = {}
        for item in evidence:
            prior = evidence_by_id.get(item.evidence_id)
            if prior is not None and prior != item:
                return _quarantined(triggers, "malformed_output")
            evidence_by_id[item.evidence_id] = item
        for item in projected:
            prior = evidence_by_id.get(item.evidence_id)
            if prior is not None and prior != item:
                return _quarantined(triggers, "malformed_output")
            evidence_by_id[item.evidence_id] = item
        request = ExtractionRequest(
            run_id=envelope.run_id,
            event_id=envelope.event_id,
            source_session_alias=envelope.session_alias,
            trigger_kinds=triggers,
            trigger_payload=dict(envelope.payload),
            evidence=tuple(
                evidence_by_id[item] for item in sorted(evidence_by_id)
            ),
            approved_criteria=tuple(
                sorted(current_criteria, key=lambda item: item.criterion_id)
            ),
            approved_milestone_links=tuple(
                sorted(current_links, key=lambda item: item.relation_id)
            ),
            approved_repository_changes=tuple(
                sorted(current_changes, key=lambda item: item.change_id)
            ),
        )
        request = ExtractionRequest.model_validate_json(request.model_dump_json())
        request_digest = request.digest
        attempt = self._broker.extract(request)
        if request.digest != request_digest:
            return _quarantined(triggers, "malformed_output")
        if attempt.timed_out:
            return _quarantined(triggers, "timeout")
        try:
            boundary = BoundaryMetadata.model_validate(attempt.boundary)
        except ValidationError:
            return _quarantined(triggers, "unsafe_boundary")
        if boundary.internal_session_alias == envelope.session_alias:
            return _quarantined(triggers, "self_observed")
        if attempt.output is None:
            return _quarantined(triggers, "missing_output")
        if isinstance(attempt.output, list) and not attempt.output:
            return ExtractionOutcome(trigger_kinds=triggers)
        try:
            claims = _validate_output(attempt.output)
        except (ValidationError, TypeError, ValueError, RecursionError):
            return _quarantined(triggers, "malformed_output")
        _, redaction_status = sanitize_value(
            [claim.model_dump(mode="json") for claim in claims]
        )
        if redaction_status != "clean":
            return _quarantined(triggers, "unredacted_output")

        criteria_by_locator: dict[str, list[ApprovedMissionCriterion]] = {}
        for item in current_criteria:
            criteria_by_locator.setdefault(
                _normalize_locator(item.locator), []
            ).append(item)
        reason = _validate_anchors(
            claims,
            evidence_by_id,
            criteria_by_locator,
            run_id=envelope.run_id,
            session_alias=envelope.session_alias,
        )
        if reason is not None:
            return _quarantined(triggers, reason)

        derived_by_id: dict[str, EvidenceRecord] = {
            item.evidence_id: item for item in projected
        }
        records: list[ClaimRecord] = []
        for claim in claims:
            criterion = _matching_criterion(
                claim,
                criteria_by_locator.get(
                    _normalize_locator(claim.subject_locator), ()
                ),
            )
            criterion_evidence = (
                _criterion_evidence(criterion, envelope.session_alias)
                if criterion is not None
                else None
            )
            if criterion_evidence is not None:
                derived_by_id[criterion_evidence.evidence_id] = criterion_evidence
            milestone_ids = tuple(
                sorted(
                    {
                        milestone_id
                        for item in current_links
                        if _normalize_locator(item.locator)
                        == _normalize_locator(claim.subject_locator)
                        for milestone_id in item.milestone_ids
                    }
                )
            )
            records.append(
                _to_claim_record(
                    claim,
                    envelope,
                    {**evidence_by_id, **derived_by_id},
                    criterion_evidence=criterion_evidence,
                    milestone_ids=milestone_ids,
                    provenance_status=accepted_provenance,
                )
            )
        return ExtractionOutcome(
            trigger_kinds=triggers,
            claims=tuple(records),
            derived_evidence=tuple(
                derived_by_id[item] for item in sorted(derived_by_id)
            ),
        )


def classify_triggers(envelope: HookEnvelope) -> tuple[TriggerKind, ...]:
    """Classify one event when cross-session history is not required."""
    return TriggerClassifier().observe(envelope)


def _normalize_json_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 32:
        raise ValueError("claim value is too deeply nested")
    if isinstance(value, tuple):
        return [
            _normalize_json_value(item, depth=depth + 1)
            for item in value
        ]
    if isinstance(value, list):
        return [
            _normalize_json_value(item, depth=depth + 1)
            for item in value
        ]
    if isinstance(value, dict):
        return {
            key: _normalize_json_value(item, depth=depth + 1)
            for key, item in value.items()
        }
    return value


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    if depth > 32:
        raise ValueError("claim value is too deeply nested")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("claim value must be finite")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("claim object keys must be strings")
        for item in value.values():
            _validate_json_value(item, depth=depth + 1)
        return
    raise ValueError("claim value must be JSON")


def _edited_paths(envelope: HookEnvelope) -> tuple[str, ...]:
    if envelope.hook_event_name != "PostToolUse":
        return ()
    if not is_edit_tool(envelope.payload.get("tool_name")):
        return ()
    return tool_input_paths(envelope.payload.get("tool_input", {}))


def _failed_command_or_test(envelope: HookEnvelope) -> bool:
    if envelope.hook_event_name != "PostToolUse":
        return False
    return tool_result_failed(envelope.payload.get("tool_response"))


def _project_repository_evidence(
    changes: Sequence[ApprovedRepositoryChange],
) -> tuple[EvidenceRecord, ...]:
    records: list[EvidenceRecord] = []
    for change in changes:
        identity = hashlib.sha256(
            canonical_json(change.model_dump(mode="json"))
        ).hexdigest()
        records.append(
            EvidenceRecord(
                provenance_status="authoritative_input",
                redaction_status="clean",
                evidence_id=f"repository-{identity}",
                run_id=change.run_id,
                session_alias=change.session_alias,
                kind="changed_file",
                source="repository_change",
                locator=change.locator,
                digest=change.digest,
                observed_at=change.observed_at,
            )
        )
    return tuple(records)


def _approved_inputs_are_unambiguous(
    criteria: Sequence[ApprovedMissionCriterion],
    links: Sequence[ApprovedMilestoneLink],
    changes: Sequence[ApprovedRepositoryChange],
) -> bool:
    criterion_ids = [item.criterion_id for item in criteria]
    relation_ids = [item.relation_id for item in links]
    change_ids = [item.change_id for item in changes]
    if (
        len(set(criterion_ids)) != len(criterion_ids)
        or len(set(relation_ids)) != len(relation_ids)
        or len(set(change_ids)) != len(change_ids)
    ):
        return False
    values_by_authority: dict[tuple[str, str, str | None], bytes] = {}
    for item in criteria:
        key = (
            _normalize_locator(item.locator),
            _normalize_locator(item.property),
            _normalize_locator(item.unit) if item.unit is not None else None,
        )
        value = canonical_json({"value": item.value})
        prior = values_by_authority.get(key)
        if prior is not None and prior != value:
            return False
        values_by_authority[key] = value
    return True




def _normalize_locator(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    return " ".join(normalized.strip().split()).lower()


def _validate_output(value: object) -> tuple[ExtractedClaim, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError("broker output must be a non-empty claim list")
    return tuple(ExtractedClaim.model_validate(item) for item in value)


def _matching_criterion(
    claim: ExtractedClaim,
    criteria: Sequence[ApprovedMissionCriterion],
) -> ApprovedMissionCriterion | None:
    normalized_property = _normalize_locator(claim.property)
    normalized_unit = (
        _normalize_locator(claim.unit) if claim.unit is not None else None
    )
    value_bytes = canonical_json({"value": claim.value})
    for criterion in criteria:
        criterion_unit = (
            _normalize_locator(criterion.unit)
            if criterion.unit is not None
            else None
        )
        if (
            _normalize_locator(criterion.property) == normalized_property
            and criterion_unit == normalized_unit
            and canonical_json({"value": criterion.value}) == value_bytes
        ):
            return criterion
    return None


def _validate_anchors(
    claims: Sequence[ExtractedClaim],
    evidence_by_id: Mapping[str, EvidenceRecord],
    criteria_by_locator: Mapping[str, Sequence[ApprovedMissionCriterion]],
    *,
    run_id: str,
    session_alias: str,
) -> QuarantineReason | None:
    for claim in claims:
        cited: list[EvidenceRecord] = []
        for evidence_id in claim.evidence_ids:
            item = evidence_by_id.get(evidence_id)
            if item is None:
                return "unknown_evidence"
            cited.append(item)
        if any(item.run_id != run_id for item in cited):
            return "cross_run_evidence"
        if any(item.session_alias != session_alias for item in cited):
            return "cross_session_evidence"
        cited_locators = {_normalize_locator(item.locator) for item in cited}
        subject_locator = _normalize_locator(claim.subject_locator)
        criteria = criteria_by_locator.get(subject_locator, ())
        if subject_locator not in cited_locators:
            if not criteria:
                return "unanchored_locator"
            if _matching_criterion(claim, criteria) is None:
                return "criterion_mismatch"
        for target in claim.targets:
            if target.evidence_id not in claim.evidence_ids:
                return "unknown_evidence"
            evidence = evidence_by_id.get(target.evidence_id)
            if evidence is None:
                return "unknown_evidence"
            if (
                _normalize_locator(evidence.locator)
                != _normalize_locator(target.target_id)
                or evidence.kind.strip().lower()
                not in _MATERIAL_TARGET_KINDS[target.kind]
            ):
                return "unanchored_locator"
    return None


def _criterion_evidence(
    criterion: ApprovedMissionCriterion, session_alias: str
) -> EvidenceRecord:
    criterion_body = criterion.model_dump(mode="json")
    digest = hashlib.sha256(canonical_json(criterion_body)).hexdigest()
    identity = hashlib.sha256(
        canonical_json(
            {
                **criterion_body,
                "session_alias": session_alias,
            }
        )
    ).hexdigest()
    return EvidenceRecord(
        provenance_status="authoritative_input",
        redaction_status="clean",
        evidence_id=f"criterion-{identity}",
        run_id=criterion.run_id,
        session_alias=session_alias,
        kind="mission_criterion",
        source="mission_criterion",
        locator=criterion.locator,
        digest=digest,
        observed_at=criterion.observed_at,
    )


def _to_claim_record(
    claim: ExtractedClaim,
    envelope: HookEnvelope,
    evidence_by_id: Mapping[str, EvidenceRecord],
    *,
    criterion_evidence: EvidenceRecord | None = None,
    milestone_ids: tuple[str, ...] = (),
    provenance_status: Literal["hook_authenticated", "independent_frozen"],
) -> ClaimRecord:
    evidence_ids = tuple(
        sorted(
            {
                *claim.evidence_ids,
                *(
                    (criterion_evidence.evidence_id,)
                    if criterion_evidence is not None
                    else ()
                ),
            }
        )
    )
    targets = tuple(claim.targets)
    payload = {
        "schema_version": "0.1",
        "run_id": envelope.run_id,
        "session_alias": envelope.session_alias,
        **claim.model_dump(mode="json"),
        "evidence_ids": evidence_ids,
        "targets": [item.model_dump(mode="json") for item in targets],
        "milestone_ids": milestone_ids,
    }
    observed_at = max(evidence_by_id[item].observed_at for item in evidence_ids)
    claim_id = "claim-" + hashlib.sha256(canonical_json(payload)).hexdigest()
    return ClaimRecord(
        provenance_status=provenance_status,
        redaction_status="clean",
        claim_id=claim_id,
        run_id=envelope.run_id,
        session_alias=envelope.session_alias,
        subject=claim.subject,
        subject_locator=claim.subject_locator,
        property=claim.property,
        value=claim.value,
        unit=claim.unit,
        confidence=claim.confidence,
        evidence_ids=evidence_ids,
        targets=targets,
        milestone_ids=milestone_ids,
        observed_at=observed_at,
    )


def _quarantined(
    triggers: tuple[TriggerKind, ...], reason: QuarantineReason
) -> ExtractionOutcome:
    return ExtractionOutcome(
        trigger_kinds=triggers,
        quarantine=QuarantineRecord(reason=reason),
    )
