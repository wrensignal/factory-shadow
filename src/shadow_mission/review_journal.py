"""Strict append-only journal for durable Mission review derivations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
from pathlib import Path
from typing import Annotated, Any, Iterable, Literal, Mapping, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationInfo, model_validator

from .probe import ProbeUsage
from .protocol import ClaimRecord, EvidenceRecord, canonical_json
from .router import InterventionRouterDelta, InterventionRouterState
from .roles import RoleDecision
from .rules import AuthorityResolution, EvidenceAuthority, Finding, ProbeAssessment

ZERO_DIGEST = "0" * 64
MAX_JOURNAL_LINE_BYTES = 2 << 20
MAX_JOURNAL_BYTES = 32 << 20
_DIGEST = r"^[0-9a-f]{64}$"


class ReviewJournalError(RuntimeError):
    """Base error for the authoritative derived-review journal."""


class ReviewJournalCorruptionError(ReviewJournalError):
    """The derived-review journal cannot be replayed exactly."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class JournalFinding(_StrictModel):
    """Strict JSON representation of one deterministic finding."""

    finding_id: str = Field(min_length=1)
    dedup_key: str = Field(pattern=_DIGEST)
    rule: Literal[
        "cross_worker_conflict", "shared_assumption", "validation_overlap"
    ]
    level: Literal["note", "concern", "blocker"]
    target_sessions: tuple[str, ...]
    claim_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    evidence_digests: tuple[str, ...]
    normalized_locators: tuple[str, ...]
    normalized_properties: tuple[str, ...]
    normalized_units: tuple[str | None, ...]
    normalized_values: tuple[str, ...]
    authority_status: Literal[
        "absent", "non_authoritative", "resolved", "unresolved_same_authority"
    ]
    authority_level: int = Field(ge=0, le=3)
    authority_value: str | None = None
    risk_category: Literal[
        "none", "money", "security", "data_loss", "public_contract", "explicit_acceptance"
    ]
    probe_status: Literal[
        "missing", "pending", "rejected", "not_confirmed", "inconclusive", "confirmed"
    ]
    probe_id: str | None = None
    milestone_ids: tuple[str, ...] = ()
    # `Finding.related_declarations` is deliberately not journaled. Adding a
    # field changes every record digest and would break the frozen Phase 6
    # evidence. Guidance after a restart therefore omits that sentence until
    # the finding is re-derived from the graph. The field never enters
    # `dedup_key`, so no identity, intervention, or ledger digest depends on it.

    @classmethod
    def from_finding(cls, finding: Finding) -> "JournalFinding":
        return cls(
            finding_id=finding.finding_id,
            dedup_key=finding.dedup_key,
            rule=finding.rule,
            level=finding.level,
            target_sessions=finding.target_sessions,
            claim_ids=finding.claim_ids,
            evidence_ids=finding.evidence_ids,
            evidence_digests=finding.evidence_digests,
            normalized_locators=finding.normalized_locators,
            normalized_properties=finding.normalized_properties,
            normalized_units=finding.normalized_units,
            normalized_values=finding.normalized_values,
            authority_status=finding.authority.status,
            authority_level=int(finding.authority.authority),
            authority_value=finding.authority.normalized_value,
            risk_category=finding.risk_category,
            probe_status=finding.probe_status,
            probe_id=finding.probe_id,
            milestone_ids=finding.milestone_ids,
        )

    def to_finding(self) -> Finding:
        return Finding(
            finding_id=self.finding_id,
            dedup_key=self.dedup_key,
            rule=self.rule,
            level=self.level,
            target_sessions=self.target_sessions,
            claim_ids=self.claim_ids,
            evidence_ids=self.evidence_ids,
            evidence_digests=self.evidence_digests,
            normalized_locators=self.normalized_locators,
            normalized_properties=self.normalized_properties,
            normalized_units=self.normalized_units,
            normalized_values=self.normalized_values,
            authority=AuthorityResolution(
                self.authority_status,
                EvidenceAuthority(self.authority_level),
                self.authority_value,
            ),
            risk_category=self.risk_category,
            probe_status=self.probe_status,
            probe_id=self.probe_id,
            milestone_ids=self.milestone_ids,
        )


class JournalProbeAssessment(_StrictModel):
    """Strict JSON representation of one signed probe assessment."""

    probe_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    finding_dedup_key: str = Field(pattern=_DIGEST)
    claim_ids: tuple[str, ...]
    evidence_digests: tuple[str, ...]
    risk_category: Literal[
        "none", "money", "security", "data_loss", "public_contract", "explicit_acceptance"
    ]
    recommended_level: Literal["note", "concern", "blocker"]
    status: Literal[
        "missing", "pending", "rejected", "not_confirmed", "inconclusive", "confirmed"
    ]
    authoritative_value: str | None = None
    snapshot_digest: str = Field(pattern=_DIGEST)
    boundary_digest: str = Field(pattern=_DIGEST)
    boundary_policy_digest: str = Field(pattern=_DIGEST)
    observed_at: int
    record_digest: str = Field(pattern=_DIGEST)
    signature: str = Field(pattern=_DIGEST)
    source: Literal["independent_probe"] = "independent_probe"
    redaction_status: Literal["clean"] = "clean"
    zero_tools: Literal[True] = True

    @classmethod
    def from_assessment(cls, value: ProbeAssessment) -> "JournalProbeAssessment":
        return cls(**value.__dict__)

    def to_assessment(self) -> ProbeAssessment:
        return ProbeAssessment(**self.model_dump(mode="python"))


class _JournalRecord(_StrictModel):
    schema_version: Literal["0.1"] = "0.1"
    record_type: str
    run_id: str = Field(min_length=1)
    journal_sequence: int = Field(ge=1)
    previous_digest: str = Field(pattern=_DIGEST)
    record_digest: str = Field(pattern=_DIGEST)

    @model_validator(mode="after")
    def validate_digest(self, info: ValidationInfo) -> "_JournalRecord":
        if info.context and info.context.get("building_journal_record") is True:
            return self
        value = self.model_dump(mode="json")
        supplied = value.pop("record_digest")
        expected = hashlib.sha256(canonical_json(value)).hexdigest()
        if supplied != expected:
            raise ValueError("review journal record digest does not match")
        return self


class ExchangeProjectionRecord(_JournalRecord):
    record_type: Literal["exchange_projection"] = "exchange_projection"
    ledger_sequence: int = Field(ge=1)
    event_id: str = Field(min_length=1)
    exchange_id: str = Field(min_length=1)
    response_digest: str = Field(pattern=_DIGEST)


class RoleDecisionRecord(_JournalRecord):
    record_type: Literal["role_decision"] = "role_decision"
    ledger_sequence: int = Field(ge=1)
    event_id: str = Field(min_length=1)
    relations_digest: str = Field(pattern=_DIGEST)
    session_alias: str = Field(min_length=1)
    role_id: str | None = None
    kind: Literal["orchestrator", "worker", "validator", "unknown"]
    confidence: Literal["high", "low", "none"]
    status: Literal["assigned", "candidate", "ignored", "quarantined"]
    reason: str = Field(min_length=1, max_length=512)
    evidence_digests: tuple[str, ...]

    @classmethod
    def decision_fields(cls, decision: RoleDecision) -> dict[str, Any]:
        return {
            "session_alias": decision.session_alias,
            "role_id": decision.role_id,
            "kind": decision.kind,
            "confidence": decision.confidence,
            "status": decision.status,
            "reason": decision.reason,
            "evidence_digests": decision.evidence_digests,
        }

    def to_decision(self) -> RoleDecision:
        return RoleDecision(
            session_alias=self.session_alias,
            role_id=self.role_id,
            kind=self.kind,
            confidence=self.confidence,
            status=self.status,
            reason=self.reason,
            evidence_digests=self.evidence_digests,
        )


class TranscriptBatchRecord(_JournalRecord):
    record_type: Literal["transcript_batch"] = "transcript_batch"
    ledger_sequence: int = Field(ge=1)
    event_id: str = Field(min_length=1)
    session_alias: str = Field(min_length=1)
    transcript_alias: str = Field(min_length=1)
    cursor_before: int = Field(ge=0)
    cursor_after: int = Field(ge=0)
    status: Literal["read", "empty", "missing", "rejected"]
    failure_reason: Literal[
        "none", "missing_ephemeral_context", "transcript_rejected", "fallback_disabled"
    ] = "none"
    evidence: tuple[EvidenceRecord, ...] = ()

    @model_validator(mode="after")
    def validate_cursor(self) -> "TranscriptBatchRecord":
        if self.cursor_after < self.cursor_before:
            raise ValueError("transcript cursor moved backwards")
        if self.status in {"read", "empty"} and self.failure_reason != "none":
            raise ValueError("successful transcript read has a failure reason")
        if self.status in {"missing", "rejected"} and self.failure_reason == "none":
            raise ValueError("failed transcript read lacks a reason")
        return self


class ExtractionOutcomeRecord(_JournalRecord):
    record_type: Literal["extraction_outcome"] = "extraction_outcome"
    ledger_sequence: int = Field(ge=1)
    event_id: str = Field(min_length=1)
    trigger_kinds: tuple[
        Literal[
            "contract_or_schema_edit",
            "test_edit",
            "failed_command_or_test",
            "cross_session_edit",
            "completion_attempt",
        ],
        ...,
    ] = ()
    status: Literal["not_triggered", "accepted", "quarantined", "failed"]
    quarantine_reason: str | None = Field(default=None, max_length=128)
    claims: tuple[ClaimRecord, ...] = ()
    derived_evidence: tuple[EvidenceRecord, ...] = ()

    @model_validator(mode="after")
    def validate_outcome(self) -> "ExtractionOutcomeRecord":
        if self.status == "not_triggered" and self.trigger_kinds:
            raise ValueError("untriggered extraction contains triggers")
        if self.status == "accepted" and self.quarantine_reason is not None:
            raise ValueError("accepted extraction contains quarantine")
        if self.status in {"quarantined", "failed"} and not self.quarantine_reason:
            raise ValueError("failed extraction lacks a bounded reason")
        if self.status != "accepted" and (self.claims or self.derived_evidence):
            raise ValueError("non-accepted extraction contains projected output")
        return self


class FindingSnapshotRecord(_JournalRecord):
    record_type: Literal["finding_snapshot"] = "finding_snapshot"
    ledger_sequence: int = Field(ge=1)
    event_id: str = Field(min_length=1)
    graph_digest: str = Field(pattern=_DIGEST)
    findings: tuple[JournalFinding, ...]
    validation_overlap_status: Literal["active", "disabled_by_role_fallback"]


class ProbeJobRecord(_JournalRecord):
    record_type: Literal["probe_job"] = "probe_job"
    ledger_sequence: int = Field(ge=1)
    event_id: str = Field(min_length=1)
    probe_id: str = Field(min_length=1)
    finding_dedup_key: str = Field(pattern=_DIGEST)
    snapshot_digest: str = Field(pattern=_DIGEST)
    risk_category: Literal[
        "none", "money", "security", "data_loss", "public_contract", "explicit_acceptance"
    ]
    observed_at: int


class ProbeSnapshotRejectionRecord(_JournalRecord):
    record_type: Literal["probe_snapshot_rejection"] = "probe_snapshot_rejection"
    ledger_sequence: int = Field(ge=1)
    event_id: str = Field(min_length=1)
    finding_dedup_key: str = Field(pattern=_DIGEST)
    risk_category: Literal[
        "none", "money", "security", "data_loss", "public_contract", "explicit_acceptance"
    ]
    reason: str = Field(pattern=r"^[a-z0-9_]{1,64}$")


class ProbeOutcomeRecord(_JournalRecord):
    record_type: Literal["probe_outcome"] = "probe_outcome"
    ledger_sequence: int = Field(ge=1)
    event_id: str = Field(min_length=1)
    probe_id: str = Field(min_length=1)
    finding_dedup_key: str = Field(pattern=_DIGEST)
    snapshot_digest: str = Field(pattern=_DIGEST)
    assessment: JournalProbeAssessment | None = None
    usage: ProbeUsage
    quarantine_reason: Literal[
        "malformed_output",
        "missing_output",
        "snapshot_mismatch",
        "timeout",
        "unsafe_boundary",
        "unsafe_output",
        "uncited_output",
        "over_escalated_output",
    ] | None = None

    @model_validator(mode="after")
    def validate_probe_outcome(self) -> "ProbeOutcomeRecord":
        if (self.assessment is None) == (self.quarantine_reason is None):
            raise ValueError("probe outcome must contain one assessment or quarantine")
        if self.assessment is not None and (
            self.assessment.probe_id != self.probe_id
            or self.assessment.run_id != self.run_id
            or self.assessment.finding_dedup_key != self.finding_dedup_key
            or self.assessment.snapshot_digest != self.snapshot_digest
        ):
            raise ValueError("probe assessment binding differs")
        return self


class ProbeCancellationRecord(_JournalRecord):
    record_type: Literal["probe_cancellation"] = "probe_cancellation"
    ledger_sequence: int = Field(ge=1)
    event_id: str = Field(min_length=1)
    probe_id: str = Field(min_length=1)
    finding_dedup_key: str = Field(pattern=_DIGEST)
    snapshot_digest: str = Field(pattern=_DIGEST)
    reason: Literal[
        "restart_pending",
        "shutdown_timeout",
        "scheduler_rejected",
        "probe_pending_at_completion",
    ]


class BoundaryDisabledRecord(_JournalRecord):
    record_type: Literal["probe_boundary_disabled"] = "probe_boundary_disabled"
    ledger_sequence: int = Field(ge=1)
    event_id: str = Field(min_length=1)
    boundary_digest: str = Field(pattern=_DIGEST)
    stopped_at: int
    reason: Literal["unsafe_boundary"] = "unsafe_boundary"


class InterventionLineageRecord(_JournalRecord):
    record_type: Literal["intervention_lineage"] = "intervention_lineage"
    ledger_sequence: int = Field(ge=1)
    event_id: str = Field(min_length=1)
    response_digest: str = Field(pattern=_DIGEST)
    delta: InterventionRouterDelta

class OutageReconciliationRecord(_JournalRecord):
    record_type: Literal["outage_reconciliation"] = "outage_reconciliation"
    observed_at: int
    delta: InterventionRouterDelta

    @model_validator(mode="after")
    def validate_delta_binding(self) -> "OutageReconciliationRecord":
        if self.delta.run_id != self.run_id:
            raise ValueError("outage reconciliation belongs to another run")
        return self



class ControllerDegradedRecord(_JournalRecord):
    record_type: Literal["controller_degraded"] = "controller_degraded"
    reason: str = Field(min_length=1, max_length=128)
    observed_at: int


JournalRecord: TypeAlias = Annotated[
    ExchangeProjectionRecord
    | RoleDecisionRecord
    | TranscriptBatchRecord
    | ExtractionOutcomeRecord
    | FindingSnapshotRecord
    | ProbeJobRecord
    | ProbeSnapshotRejectionRecord
    | ProbeOutcomeRecord
    | ProbeCancellationRecord
    | BoundaryDisabledRecord
    | InterventionLineageRecord
    | OutageReconciliationRecord
    | ControllerDegradedRecord,
    Field(discriminator="record_type"),
]
_RECORD_ADAPTER = TypeAdapter(JournalRecord)
_RECORD_TYPES: dict[str, type[_JournalRecord]] = {
    model.model_fields["record_type"].default: model
    for model in (
        ExchangeProjectionRecord,
        RoleDecisionRecord,
        TranscriptBatchRecord,
        ExtractionOutcomeRecord,
        FindingSnapshotRecord,
        ProbeJobRecord,
        ProbeSnapshotRejectionRecord,
        ProbeOutcomeRecord,
        ProbeCancellationRecord,
        BoundaryDisabledRecord,
        InterventionLineageRecord,
        OutageReconciliationRecord,
        ControllerDegradedRecord,
    )
}


def project_intervention_router_state(
    run_id: str,
    records: Iterable[JournalRecord],
) -> InterventionRouterState:
    """Apply every persisted router delta in journal order."""

    state = InterventionRouterState.empty(run_id)
    for record in records:
        if isinstance(
            record,
            (InterventionLineageRecord, OutageReconciliationRecord),
        ):
            state = record.delta.apply(state)
    return state


def load_journal_records(
    payload: bytes,
    *,
    run_id: str,
    max_bytes: int = MAX_JOURNAL_BYTES,
) -> tuple[JournalRecord, ...]:
    """Replay one immutable canonical review-journal snapshot."""

    if len(payload) > max_bytes:
        raise ReviewJournalCorruptionError("review journal exceeds its spool bound")
    records: list[JournalRecord] = []
    expected_sequence = 1
    previous_digest = ZERO_DIGEST
    try:
        for raw_line in payload.splitlines(keepends=True):
            if len(raw_line) > MAX_JOURNAL_LINE_BYTES:
                raise ReviewJournalCorruptionError(
                    "review journal record exceeds its byte bound"
                )
            if not raw_line.endswith(b"\n"):
                raise ReviewJournalCorruptionError(
                    "review journal has an incomplete final record"
                )
            body = raw_line[:-1]
            value = json.loads(body)
            if not isinstance(value, Mapping) or canonical_json(value) != body:
                raise ReviewJournalCorruptionError(
                    "review journal record is not canonical JSON"
                )
            record = _RECORD_ADAPTER.validate_python(value)
            if record.run_id != run_id:
                raise ReviewJournalCorruptionError(
                    "review journal contains another run"
                )
            if record.journal_sequence != expected_sequence:
                raise ReviewJournalCorruptionError(
                    "review journal sequence is not contiguous"
                )
            if not re.fullmatch(_DIGEST, record.previous_digest) or (
                record.previous_digest != previous_digest
            ):
                raise ReviewJournalCorruptionError(
                    "review journal digest chain diverges"
                )
            records.append(record)
            expected_sequence += 1
            previous_digest = record.record_digest
    except ReviewJournalCorruptionError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ReviewJournalCorruptionError("review journal replay failed") from error
    return tuple(records)


class ReviewJournal:
    """Append and replay canonical derived records with a contiguous digest chain."""

    def __init__(
        self,
        path: Path,
        *,
        run_id: str,
        max_bytes: int = MAX_JOURNAL_BYTES,
    ) -> None:
        if not run_id or max_bytes <= 0:
            raise ValueError("review journal configuration is invalid")
        self.run_id = run_id
        self.path = path.expanduser().absolute()
        self._max_bytes = max_bytes
        self._lock = threading.Lock()
        self._records: list[JournalRecord] = []
        self._prepare_path()
        self._recover()

    @property
    def size_bytes(self) -> int:
        try:
            return self.path.stat().st_size
        except FileNotFoundError:
            return 0

    def records(self) -> tuple[JournalRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def append(self, record_type: str, **fields: Any) -> JournalRecord:
        model = _RECORD_TYPES.get(record_type)
        if model is None:
            raise ValueError("unknown review journal record type")
        with self._lock:
            previous = self._records[-1].record_digest if self._records else ZERO_DIGEST
            values = {
                "schema_version": "0.1",
                "record_type": record_type,
                "run_id": self.run_id,
                "journal_sequence": len(self._records) + 1,
                "previous_digest": previous,
                **fields,
            }
            if fields.get("run_id", self.run_id) != self.run_id:
                raise ValueError("review journal append belongs to another run")
            values["run_id"] = self.run_id
            draft = model.model_validate(
                {**values, "record_digest": ZERO_DIGEST},
                context={"building_journal_record": True},
            )
            material = draft.model_dump(mode="json")
            material.pop("record_digest")
            material["record_digest"] = hashlib.sha256(
                canonical_json(material)
            ).hexdigest()
            record = model.model_validate(material)
            line = canonical_json(record.model_dump(mode="json")) + b"\n"
            if len(line) > MAX_JOURNAL_LINE_BYTES:
                raise ReviewJournalError("review journal record exceeds its byte bound")
            flags = os.O_WRONLY | os.O_APPEND
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(self.path, flags)
                try:
                    file_metadata = os.fstat(descriptor)
                    path_metadata = self.path.lstat()
                    if (
                        not stat.S_ISREG(file_metadata.st_mode)
                        or stat.S_IMODE(file_metadata.st_mode) != 0o600
                        or (
                            hasattr(os, "getuid")
                            and file_metadata.st_uid != os.getuid()
                        )
                        or not stat.S_ISREG(path_metadata.st_mode)
                        or (file_metadata.st_dev, file_metadata.st_ino)
                        != (path_metadata.st_dev, path_metadata.st_ino)
                    ):
                        raise ReviewJournalError(
                            "review journal append target is unsafe"
                        )
                    if file_metadata.st_size + len(line) > self._max_bytes:
                        raise ReviewJournalError(
                            "review journal exceeds its spool bound"
                        )
                    written = 0
                    while written < len(line):
                        count = os.write(descriptor, line[written:])
                        if count == 0:
                            raise ReviewJournalError(
                                "review journal append made no progress"
                            )
                        written += count
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            except ReviewJournalError:
                raise
            except OSError as error:
                raise ReviewJournalError("review journal append failed") from error
            self._records.append(record)
            return record

    def _prepare_path(self) -> None:
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        metadata = parent.lstat()
        if parent.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise ReviewJournalError("review journal parent is not a private directory")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ReviewJournalError("review journal parent owner differs")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            os.chmod(parent, 0o700)
        if self.path.exists() and self.path.is_symlink():
            raise ReviewJournalError("review journal path must not be a symlink")
        if not self.path.exists():
            self.path.touch(mode=0o600)
            directory = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        file_metadata = self.path.lstat()
        if (
            not stat.S_ISREG(file_metadata.st_mode)
            or (hasattr(os, "getuid") and file_metadata.st_uid != os.getuid())
        ):
            raise ReviewJournalError("review journal file owner or type differs")
        os.chmod(self.path, 0o600)

    def _recover(self) -> None:
        if not self.path.is_file() or self.path.is_symlink():
            raise ReviewJournalCorruptionError("review journal is not a regular file")
        try:
            payload = self.path.read_bytes()
        except OSError as error:
            raise ReviewJournalCorruptionError("review journal replay failed") from error
        self._records.extend(
            load_journal_records(
                payload,
                run_id=self.run_id,
                max_bytes=self._max_bytes,
            )
        )
