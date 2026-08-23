"""Small protocol primitives shared by the feasibility harness."""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from collections import deque
from threading import Condition
from typing import Any, Deque, Generic, Literal, Mapping, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

T = TypeVar("T")

COMPLETION_EVENTS = frozenset({"Stop", "SubagentStop"})

DIGEST_PATTERN = r"^[0-9a-f]{64}$"
IMAGE_DIGEST_PATTERN = r"^(?:sha256:)?[0-9a-f]{64}$"
CapabilityStatus = Literal["pass", "fallback", "stop"]


class _ReleaseReportableRuntimeOutcomes(frozenset[str]):
    def __contains__(self, value: object) -> bool:
        if not isinstance(value, str):
            return False
        return super().__contains__(value) or (
            re.fullmatch(r"mission-exit--?[0-9]+", value) is not None
        )


RELEASE_REPORTABLE_RUNTIME_OUTCOMES = _ReleaseReportableRuntimeOutcomes(
    {"mission-terminated", "completion-blocked"}
)

ProvenanceStatus = Literal[
    "hook_authenticated",
    "independent_frozen",
    "authoritative_input",
    "collector_observed",
    "untrusted_provenance",
]
RedactionStatus = Literal["clean", "redacted"]
RoleName = Literal["orchestrator", "worker", "validator", "unknown"]

EDIT_TOOL_NAMES = frozenset(
    {
        "apply_patch",
        "applypatch",
        "ast_edit",
        "create",
        "edit",
        "multiedit",
        "patch",
        "replace",
        "str_replace",
        "strreplace",
        "write",
        "write_file",
    }
)
PATH_KEYS = frozenset(
    {
        "file",
        "file_path",
        "filename",
        "files",
        "path",
        "paths",
        "target",
        "targets",
    }
)
FAILURE_KEYS = frozenset(
    {"error", "failed", "failure", "success", "exit_code", "returncode", "status"}
)
FAILED_TEXT = re.compile(
    r"(?:\bexit(?:ed)?(?:\s+with)?(?:\s+code)?\s*[:=]?\s*[1-9]\d*\b|"
    r"\b(?:command|tests?|pytest|jest|vitest)\s+(?:failed|failure)\b|"
    r"\b[1-9]\d*\s+(?:failed|failures?|errors?)\b)",
    re.IGNORECASE,
)
TEST_COMMAND = re.compile(
    r"\b(?:pytest|jest|vitest|unittest|tox|nox|rspec|phpunit|mocha)\b|"
    r"\b(?:go|cargo|dotnet|swift|mvn|gradle)\s+test\b|"
    r"\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test\b|"
    r"\bmake\s+(?:test|check)\b",
    re.IGNORECASE,
)
# Redaction collapses transcript whitespace, so patch headers must be matched
# without line anchors.
_PATCH_FILE = re.compile(r"\*\*\* (?:Update|Add|Delete) File:\s*(\S+)")
_COMMAND_KEYS = frozenset({"command", "cmd", "script", "args"})
_COMMAND_PATH = re.compile(
    r"[A-Za-z0-9_.\-/]*\.(?:py|pyi|ts|tsx|js|jsx|go|rs|rb|java|kt|swift|sql|"
    r"json|ya?ml|md|proto|graphql|avsc)\b"
)


def walk_values(value: Any) -> list[tuple[str | None, Any]]:
    """Return every (key, value) pair inside one nested JSON structure."""
    output: list[tuple[str | None, Any]] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            output.append((str(key), item))
            output.extend(walk_values(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            output.append((None, item))
            output.extend(walk_values(item))
    return output


def normalized_tool_name(value: object) -> str:
    """Return one comparable tool name for both Factory and fixture records."""
    name = str(value or "").strip().lower()
    return name.rsplit(".", 1)[-1].replace("_", "").replace("-", "")


def is_edit_tool(value: object) -> bool:
    """Report whether one tool name changes repository source."""
    return normalized_tool_name(value) in {
        normalized_tool_name(name) for name in EDIT_TOOL_NAMES
    }


def is_test_command(tool_input: object) -> bool:
    """Report whether one tool input runs a recognized test command."""
    if isinstance(tool_input, str):
        return TEST_COMMAND.search(tool_input) is not None
    for key, value in walk_values(tool_input):
        if key is None or not isinstance(value, str):
            continue
        if key.lower() not in {"command", "cmd", "script", "args"}:
            continue
        if TEST_COMMAND.search(value) is not None:
            return True
    return False


def tool_input_paths(tool_input: object) -> tuple[str, ...]:
    """Return every repository-relative path one tool input names."""
    paths: set[str] = set()
    if isinstance(tool_input, Mapping):
        patch_text = tool_input.get("input")
        if isinstance(patch_text, str):
            for match in _PATCH_FILE.finditer(patch_text):
                candidate = match.group(1).strip()
                if candidate:
                    normalized = posixpath.normpath(candidate.replace("\\", "/"))
                    if normalized != ".":
                        paths.add(normalized)
    for key, value in walk_values(tool_input):
        if key is None or key.lower() not in PATH_KEYS:
            continue
        candidates = value if isinstance(value, (list, tuple)) else (value,)
        for candidate in candidates:
            if isinstance(candidate, str) and candidate.strip():
                normalized = posixpath.normpath(
                    candidate.strip().replace("\\", "/")
                )
                if normalized != ".":
                    paths.add(normalized)
    return tuple(sorted(paths))


def command_paths(tool_input: object) -> tuple[str, ...]:
    """Return every repository path one recorded command names."""
    paths: set[str] = set()
    values = (
        [(None, tool_input)]
        if isinstance(tool_input, str)
        else walk_values(tool_input)
    )
    for key, value in values:
        if not isinstance(value, str):
            continue
        if key is not None and key.lower() not in _COMMAND_KEYS:
            continue
        for match in _COMMAND_PATH.finditer(value):
            normalized = posixpath.normpath(match.group(0).replace("\\", "/"))
            if normalized not in {".", ".."}:
                paths.add(normalized)
    return tuple(sorted(paths))


def tool_observation_paths(content: Mapping[str, Any]) -> tuple[str, ...]:
    """Return every repository path one recorded tool observation names."""
    tool_input = content.get("tool_input")
    if is_edit_tool(content.get("tool_name")):
        return tool_input_paths(tool_input)
    return tuple(sorted(set(command_paths(tool_input))))


def tool_result_failed(response: object) -> bool:
    """Report whether one recorded tool result states a failure."""
    if response is None:
        return False
    if isinstance(response, str):
        return FAILED_TEXT.search(response) is not None
    for key, value in walk_values(response):
        if key is None or key.lower() not in FAILURE_KEYS:
            continue
        normalized_key = key.lower()
        if normalized_key in {"exit_code", "returncode"}:
            if isinstance(value, int) and not isinstance(value, bool) and value != 0:
                return True
        elif normalized_key == "success" and value is False:
            return True
        elif (
            normalized_key in {"failed", "failure", "error"}
            and value not in (False, None, "", 0)
        ):
            return True
        elif (
            normalized_key == "status"
            and isinstance(value, str)
            and value.lower() in {"error", "failed", "failure"}
        ):
            return True
    return FAILED_TEXT.search(str(response)) is not None


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Return the canonical JSON encoding used for hashes and the ledger."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def hook_response_digest(
    *,
    response_body: str,
    guidance_ids: tuple[str, ...],
    transition_ids: tuple[str, ...],
    review_state: Mapping[str, Any] | None,
) -> str:
    """Bind response bytes and every durable response side effect."""
    return hashlib.sha256(
        canonical_json(
            {
                "response_body": response_body,
                "guidance_ids": guidance_ids,
                "transition_ids": transition_ids,
                "review_state": review_state,
            }
        )
    ).hexdigest()


class StrictModel(BaseModel):
    """Reject fields that are not part of the frozen protocol."""

    model_config = ConfigDict(extra="forbid")


class PersistedRecord(StrictModel):
    """Fields carried by every independently persisted protocol record."""

    schema_version: Literal["0.1"] = "0.1"
    provenance_status: ProvenanceStatus
    redaction_status: RedactionStatus


class HookRequest(StrictModel):
    """Authenticated in-memory request. Raw identifiers must not persist."""

    schema_version: Literal["0.1"] = "0.1"
    run_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    observed_at: int
    hook_event_name: Literal[
        "SessionStart",
        "UserPromptSubmit",
        "PostToolUse",
        "Stop",
        "SubagentStop",
        "SessionEnd",
    ]
    session_id: str
    transcript_path: str
    cwd: str
    payload: dict[str, Any] = Field(default_factory=dict)


class HookEnvelope(PersistedRecord):
    event_id: str = Field(min_length=1)
    source_fingerprint: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    session_alias: str = Field(min_length=1)
    transcript_alias: str = Field(min_length=1)
    cwd_alias: str | None = None
    hook_event_name: Literal[
        "SessionStart",
        "UserPromptSubmit",
        "PostToolUse",
        "Stop",
        "SubagentStop",
        "SessionEnd",
    ]
    observed_at: int
    message_digest: str = Field(pattern=DIGEST_PATTERN)
    payload: dict[str, Any] = Field(default_factory=dict)


def hook_envelope_digest(envelope: HookEnvelope) -> str:
    """Hash the complete canonical sanitized hook envelope."""

    return hashlib.sha256(
        canonical_json(envelope.model_dump(mode="json"))
    ).hexdigest()


class HookResponseRecord(PersistedRecord):
    response_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    request_digest: str = Field(pattern=DIGEST_PATTERN)
    response_body: str
    response_digest: str = Field(pattern=DIGEST_PATTERN)
    guidance_ids: tuple[str, ...] = ()
    transition_ids: tuple[str, ...] = ()
    review_state: dict[str, Any] | None = None
    decided_at: int

    @field_validator("response_body")
    @classmethod
    def validate_canonical_response(cls, value: str) -> str:
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as error:
            raise ValueError("response_body must be JSON") from error
        if not isinstance(decoded, Mapping):
            raise ValueError("response_body must encode an object")
        if canonical_json(decoded).decode("utf-8") != value:
            raise ValueError("response_body must use canonical JSON")
        return value

    @field_validator("review_state")
    @classmethod
    def validate_review_state(
        cls, value: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        if value is not None:
            canonical_json(value)
        return value

    @model_validator(mode="after")
    def validate_response_digest(self) -> HookResponseRecord:
        digest = hook_response_digest(
            response_body=self.response_body,
            guidance_ids=self.guidance_ids,
            transition_ids=self.transition_ids,
            review_state=self.review_state,
        )
        if digest != self.response_digest:
            raise ValueError("response_digest does not match response decision")
        return self


class HookExchangeRecord(PersistedRecord):
    ledger_sequence: int = Field(ge=1)
    exchange_id: str = Field(min_length=1)
    recorded_at: int
    envelope: HookEnvelope
    response: HookResponseRecord

    @model_validator(mode="after")
    def validate_binding(self) -> HookExchangeRecord:
        if (
            self.envelope.run_id != self.response.run_id
            or self.envelope.event_id != self.response.event_id
        ):
            raise ValueError("exchange event and response identities differ")
        if (
            self.provenance_status != self.envelope.provenance_status
            or self.provenance_status != self.response.provenance_status
        ):
            raise ValueError("exchange provenance differs")
        if self.response.request_digest != hook_envelope_digest(self.envelope):
            raise ValueError("exchange request digest differs from envelope")
        return self


class EvidenceRecord(PersistedRecord):
    evidence_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    session_alias: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    source: str = Field(min_length=1)
    locator: str = Field(min_length=1)
    digest: str = Field(pattern=DIGEST_PATTERN)
    registry_digest: str | None = Field(default=None, pattern=DIGEST_PATTERN)
    intervention_id: str | None = Field(default=None, min_length=1)
    observed_at: int


class ClaimTarget(StrictModel):
    """One persisted material dependency for a claim."""

    kind: Literal["file", "test", "feature"]
    target_id: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    attributes: dict[str, Any] = Field(default_factory=dict)


class ClaimRecord(PersistedRecord):
    claim_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    session_alias: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    subject_locator: str = Field(min_length=1)
    property: str = Field(min_length=1)
    value: Any
    unit: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    targets: tuple[ClaimTarget, ...] = ()
    milestone_ids: tuple[str, ...] = ()
    observed_at: int

    @field_validator("value")
    @classmethod
    def validate_json_value(cls, value: Any) -> Any:
        canonical_json({"value": value})
        return value

    @field_validator("evidence_ids", "milestone_ids")
    @classmethod
    def validate_sorted_unique_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("claim record IDs must be sorted and unique")
        return value


class InterventionTransition(StrictModel):
    """One ordered intervention mutation. Generations, not clocks, define order."""

    transition_id: str = Field(min_length=1)
    generation: int = Field(ge=1)
    state: Literal[
        "queued",
        "delivered",
        "acknowledged",
        "corrected",
        "resolved",
        "expired",
        "quarantined",
        "repair_requested",
        "repair_assigned",
        "termination_acknowledged",
    ]
    action: str = Field(min_length=1)
    observed_at: int
    @field_validator("generation", "observed_at", mode="before")
    @classmethod
    def reject_boolean_integers(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("transition integers must not be booleans")
        return value


class RepairAssignment(StrictModel):
    """Authoritative assignment of one fresh worker to one original feature."""

    assignment_id: str = Field(min_length=1)
    intervention_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    original_feature: str = Field(
        min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$"
    )
    worker_session: str = Field(
        min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$"
    )
    worker_role_id: str = Field(min_length=1)
    assigned_at: int
    @field_validator("assigned_at", mode="before")
    @classmethod
    def reject_boolean_time(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("assignment time must not be a boolean")
        return value


class InterventionRecord(PersistedRecord):
    """One strict digest-bound durable intervention and its complete lineage."""

    record_type: Literal["intervention_record"] = "intervention_record"
    intervention_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    finding_id: str = Field(min_length=1)
    finding_dedup_key: str = Field(pattern=DIGEST_PATTERN)
    target_session: str = Field(min_length=1)
    completion_session_alias: str = Field(
        min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$"
    )
    rule: str = Field(min_length=1)
    level: Literal["concern", "blocker"]
    risk_category: str = Field(min_length=1)
    claim_ids: tuple[str, ...] = Field(min_length=1)
    direct_evidence_ids: tuple[str, ...] = Field(min_length=1)
    direct_evidence_digests: tuple[str, ...] = Field(min_length=1)
    correction_evidence_ids: tuple[str, ...] = ()
    correction_evidence_digests: tuple[str, ...] = ()
    generation: int = Field(ge=1)
    state: Literal[
        "queued",
        "delivered",
        "acknowledged",
        "corrected",
        "resolved",
        "expired",
        "quarantined",
        "repair_requested",
        "repair_assigned",
        "termination_acknowledged",
    ]
    transition_history: tuple[InterventionTransition, ...] = Field(min_length=1)
    probe_id: str | None = None
    probe_digest: str | None = Field(default=None, pattern=DIGEST_PATTERN)
    probe_status: str = Field(min_length=1)
    probe_snapshot_digest: str | None = Field(default=None, pattern=DIGEST_PATTERN)
    blocking_scope: Literal["worker", "mission"]
    original_feature: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$"
    )
    repair_assignment: RepairAssignment | None = None
    repair_guidance_delivered_at: int | None = None
    probe_pending_at_completion: int | None = None
    attempts: int = Field(default=0, ge=0, le=2)
    deadline: int | None = None
    terminal_outcome: str | None = None
    termination_acknowledgment_evidence_id: str | None = None
    termination_acknowledgment_evidence_digest: str | None = Field(
        default=None, pattern=DIGEST_PATTERN
    )
    record_digest: str = Field(pattern=DIGEST_PATTERN)
    @field_validator(
        "generation",
        "attempts",
        "deadline",
        "repair_guidance_delivered_at",
        "probe_pending_at_completion",
        mode="before",
    )
    @classmethod
    def reject_boolean_integers(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("intervention integers must not be booleans")
        return value

    @model_validator(mode="after")
    def validate_contract(self) -> InterventionRecord:
        canonical_fields = (
            "claim_ids",
            "direct_evidence_ids",
            "direct_evidence_digests",
            "correction_evidence_ids",
            "correction_evidence_digests",
        )
        for name in canonical_fields:
            value = getattr(self, name)
            if tuple(sorted(set(value))) != value:
                raise ValueError(f"{name} must be sorted and unique")
        if (
            self.blocking_scope == "worker"
            and self.completion_session_alias != self.target_session
        ):
            raise ValueError("worker completion alias differs from its target")
        probe_fields = (
            self.probe_id,
            self.probe_digest,
            self.probe_snapshot_digest,
        )
        if any(value is None for value in probe_fields) != all(
            value is None for value in probe_fields
        ):
            raise ValueError("probe binding is incomplete")
        if self.level == "blocker" and (
            self.risk_category
            not in {
                "money",
                "security",
                "data_loss",
                "public_contract",
                "explicit_acceptance",
            }
            or self.probe_status != "confirmed"
            or any(value is None for value in probe_fields)
        ):
            raise ValueError("blocker lacks a critical authenticated probe binding")
        if (self.attempts == 0) != (self.deadline is None):
            raise ValueError("attempt and deadline binding is incomplete")
        if self.state in {"corrected", "resolved"} and not self.correction_evidence_ids:
            raise ValueError("corrected intervention lacks correction evidence")
        if self.state == "repair_assigned" and self.repair_assignment is None:
            raise ValueError("repair assignment is missing")
        if self.repair_assignment is not None:
            if (
                self.repair_assignment.intervention_id != self.intervention_id
                or self.repair_assignment.run_id != self.run_id
                or self.repair_assignment.original_feature != self.original_feature
            ):
                raise ValueError("repair assignment binding is invalid")
        if self.repair_guidance_delivered_at is not None and self.repair_assignment is None:
            raise ValueError("repair guidance lacks an assignment")
        acknowledgment_fields = (
            self.termination_acknowledgment_evidence_id,
            self.termination_acknowledgment_evidence_digest,
        )
        if (acknowledgment_fields[0] is None) != (acknowledgment_fields[1] is None):
            raise ValueError("termination acknowledgment binding is incomplete")
        if self.state == "termination_acknowledged" and acknowledgment_fields[0] is None:
            raise ValueError("termination acknowledgment evidence is missing")
        if self.state in {"expired", "quarantined", "termination_acknowledged"} and not self.terminal_outcome:
            raise ValueError("terminal intervention lacks an outcome")
        if self.transition_history[-1].state != self.state:
            raise ValueError("transition history does not end at current state")
        generations = tuple(item.generation for item in self.transition_history)
        if generations != tuple(sorted(set(generations))):
            raise ValueError("transition generations are not strictly ordered")
        if generations[-1] != self.generation:
            raise ValueError("intervention generation does not match its history")
        transition_ids = tuple(item.transition_id for item in self.transition_history)
        if len(set(transition_ids)) != len(transition_ids):
            raise ValueError("transition identities are not unique")
        allowed_transitions = {
            "queued": {"delivered", "quarantined", "expired"},
            "delivered": {"acknowledged", "corrected", "repair_requested", "quarantined", "expired"},
            "acknowledged": {"corrected", "repair_requested", "quarantined", "expired"},
            "corrected": {"resolved", "quarantined"},
            "repair_requested": {"repair_assigned", "quarantined", "expired"},
            "repair_assigned": {"acknowledged", "corrected", "quarantined", "expired"},
            "expired": {"termination_acknowledged"},
            "quarantined": {"termination_acknowledged"},
            "resolved": set(),
            "termination_acknowledged": set(),
        }
        for prior, current in zip(self.transition_history, self.transition_history[1:]):
            if current.state != prior.state and current.state not in allowed_transitions[prior.state]:
                raise ValueError("intervention transition history is invalid")
        value = self.model_dump(mode="json")
        supplied = value.pop("record_digest")
        if supplied != hashlib.sha256(canonical_json(value)).hexdigest():
            raise ValueError("intervention record digest does not match")
        return self


class CapabilityFlags(StrictModel):
    core_feasibility_verdict: Literal["pass", "stop"]
    release_gate_verdict: Literal["primary-pass", "fallback-pass", "stop"]
    droid_version: str = Field(min_length=1)
    plugin_version: str = Field(min_length=1)
    droid_sdk_version: str = Field(min_length=1)
    lima_version: str = Field(min_length=1)
    vm_image_digest: str = Field(pattern=IMAGE_DIGEST_PATTERN)
    factory_profile_digest: str = Field(pattern=DIGEST_PATTERN)
    isolation_digest: str = Field(pattern=DIGEST_PATTERN)
    gate_surface_digest: str = Field(pattern=DIGEST_PATTERN)
    installed_plugin_artifact_digest: str = Field(pattern=DIGEST_PATTERN)
    transport_integrity: CapabilityStatus
    hook_provenance: CapabilityStatus
    session_hooks: CapabilityStatus
    identity: CapabilityStatus
    transcript: CapabilityStatus
    guidance: CapabilityStatus
    worker_block: CapabilityStatus
    mission_block: CapabilityStatus
    worker_roles: CapabilityStatus
    validator_roles: CapabilityStatus
    self_session_exclusion: CapabilityStatus
    sandbox_isolation: CapabilityStatus
    probe_boundary: CapabilityStatus
    live_validation_overlap: CapabilityStatus


class BoundRunRecord(PersistedRecord):
    droid_version: str = Field(min_length=1)
    plugin_version: str = Field(min_length=1)
    droid_sdk_version: str = Field(min_length=1)
    lima_version: str = Field(min_length=1)
    droid_installation_channel: str = Field(min_length=1)
    droid_binary_digest: str = Field(pattern=DIGEST_PATTERN)
    droid_auto_update_control: Literal["env-false", "npm-build-disabled"]
    gate_surface_digest: str = Field(pattern=DIGEST_PATTERN)
    installed_plugin_artifact_digest: str = Field(pattern=DIGEST_PATTERN)
    full_run_artifact_digest: str = Field(pattern=DIGEST_PATTERN)
    historical_launch_artifact_digest: str = Field(pattern=DIGEST_PATTERN)
    resolved_plugin_source: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    release_preflight_digest: str = Field(pattern=DIGEST_PATTERN)
    factory_profile_digest: str = Field(pattern=DIGEST_PATTERN)
    vm_image_digest: str = Field(pattern=IMAGE_DIGEST_PATTERN)
    isolation_digest: str = Field(pattern=DIGEST_PATTERN)
    mission_digest: str = Field(pattern=DIGEST_PATTERN)
    mission_role_config_digest: str = Field(pattern=DIGEST_PATTERN)
    mission_relation_source_digest: str = Field(pattern=DIGEST_PATTERN)
    mission_relation_record_digest: str | None = Field(
        default=None, pattern=DIGEST_PATTERN
    )
    mission_outcome: str = Field(min_length=1)
    approved_evaluator_digest: str = Field(pattern=DIGEST_PATTERN)
    source_exporter_digest: str = Field(pattern=DIGEST_PATTERN)
    initial_commit: str = Field(min_length=1)
    final_commit: str | None = None
    final_source_archive_digest: str | None = Field(
        default=None, pattern=DIGEST_PATTERN
    )
    started_at: int
    ended_at: int | None = None
    duration_seconds: float | None = Field(default=None, ge=0.0)
    changed_files: tuple[str, ...] = ()
    evaluator_outcome: str | dict[str, Any] | None = None
    usage_data: dict[str, Any] = Field(default_factory=dict)
    budget_ledger: dict[str, Any]
    record_digest: str = Field(pattern=DIGEST_PATTERN)

    @model_validator(mode="after")
    def validate_record_digest(self) -> BoundRunRecord:
        value = self.model_dump(mode="json")
        supplied = value.pop("record_digest")
        expected = hashlib.sha256(canonical_json(value)).hexdigest()
        if supplied != expected:
            raise ValueError("record_digest does not match the record")
        return self
class PreEvaluationRecord(StrictModel):
    """Host record persisted after Mission process stop and before evaluation."""

    schema_version: Literal["0.1"] = "0.1"
    run_id: str = Field(min_length=1)
    pre_evaluation_run_record_digest: str = Field(pattern=DIGEST_PATTERN)
    event_ledger_digest: str = Field(pattern=DIGEST_PATTERN)
    event_ledger_record_count: int = Field(ge=0)
    review_journal_digest: str = Field(pattern=DIGEST_PATTERN)
    source_archive_digest: str = Field(pattern=DIGEST_PATTERN)
    source_manifest_digest: str = Field(pattern=DIGEST_PATTERN)
    source_working_tree_digest: str = Field(pattern=DIGEST_PATTERN)
    evaluator_digest: str = Field(pattern=DIGEST_PATTERN)
    mission_process_stopped: Literal[True]
    record_digest: str = Field(pattern=DIGEST_PATTERN)

    @model_validator(mode="after")
    def validate_record_digest(self) -> PreEvaluationRecord:
        value = self.model_dump(mode="json")
        supplied = value.pop("record_digest")
        if hashlib.sha256(canonical_json(value)).hexdigest() != supplied:
            raise ValueError("pre-evaluation record digest differs")
        return self






class BaselineRunRecord(BoundRunRecord):
    baseline_id: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_evaluation_archive_binding(self) -> BaselineRunRecord:
        if (
            isinstance(self.evaluator_outcome, dict)
            and self.evaluator_outcome.get("archive_digest")
            != self.final_source_archive_digest
        ):
            raise ValueError("baseline evaluation archive binding differs")
        return self


class RunRecord(BoundRunRecord):
    run_id: str = Field(min_length=1)
    mission_outcome: Literal["mission-complete", "mission-failed"]
    runtime_outcome: str = Field(min_length=1)
    mission_process_stopped: bool = Field(strict=True)
    models: dict[str, str]
    reasoning: dict[str, str]
    baseline_id: str | None = None
    baseline_record_digest: str | None = Field(default=None, pattern=DIGEST_PATTERN)
    pre_evaluation_record_digest: str | None = Field(
        default=None, pattern=DIGEST_PATTERN
    )
    final_source_manifest_digest: str | None = Field(
        default=None, pattern=DIGEST_PATTERN
    )
    final_source_working_tree_digest: str | None = Field(
        default=None, pattern=DIGEST_PATTERN
    )
    evaluator_digest: str | None = Field(default=None, pattern=DIGEST_PATTERN)
    evaluation_record_digest: str | None = Field(
        default=None, pattern=DIGEST_PATTERN
    )
    evaluator_vm_deleted: Literal[True] | None = None
    capabilities: CapabilityFlags

    @model_validator(mode="after")
    def validate_finalization_bindings(self) -> RunRecord:
        if (self.baseline_id is None) != (self.baseline_record_digest is None):
            raise ValueError("run baseline binding is incomplete")
        finalization_values = (
            self.pre_evaluation_record_digest,
            self.final_source_manifest_digest,
            self.final_source_working_tree_digest,
            self.evaluator_digest,
            self.evaluation_record_digest,
            self.evaluator_vm_deleted,
        )
        has_all_finalization = all(value is not None for value in finalization_values)
        has_any_finalization = any(value is not None for value in finalization_values)
        if has_any_finalization != has_all_finalization:
            raise ValueError("run finalization binding is incomplete")
        if isinstance(self.evaluator_outcome, dict) != has_all_finalization:
            raise ValueError("run evaluation binding is incomplete")
        if has_all_finalization and not self.mission_process_stopped:
            raise ValueError("stopped Mission process binding is incomplete")
        if not has_all_finalization and self.evaluator_outcome != self.runtime_outcome:
            raise ValueError("runtime outcome binding differs")
        expected_mission_outcome = (
            "mission-complete"
            if self.runtime_outcome == "mission-terminated"
            else "mission-failed"
        )
        if self.mission_outcome != expected_mission_outcome:
            raise ValueError("coarse Mission outcome differs from runtime outcome")
        if has_all_finalization and self.mission_relation_record_digest is None:
            raise ValueError("final run relation record binding is incomplete")
        return self


class QueueCapacityError(BufferError):
    """Raised before an item would exceed a queue boundary."""


class ByteBoundedQueue(Generic[T]):
    """FIFO bounded by item count and serialized byte count."""

    def __init__(self, *, max_items: int, max_bytes: int) -> None:
        if max_items <= 0 or max_bytes <= 0:
            raise ValueError("queue limits must be positive")
        self._max_items = max_items
        self._max_bytes = max_bytes
        self._items: Deque[tuple[T, int]] = deque()
        self._byte_count = 0
        self._condition = Condition()

    @property
    def item_count(self) -> int:
        with self._condition:
            return len(self._items)

    @property
    def byte_count(self) -> int:
        with self._condition:
            return self._byte_count

    def put(self, item: T, serialized: bytes) -> None:
        size = len(serialized)
        with self._condition:
            if len(self._items) >= self._max_items:
                raise QueueCapacityError("queue item limit exceeded")
            if size > self._max_bytes or self._byte_count + size > self._max_bytes:
                raise QueueCapacityError("queue byte limit exceeded")
            self._items.append((item, size))
            self._byte_count += size
            self._condition.notify()

    def get(self, *, timeout: float | None = 0.0) -> T:
        with self._condition:
            if timeout is None:
                while not self._items:
                    self._condition.wait()
            elif timeout > 0:
                if not self._condition.wait_for(lambda: bool(self._items), timeout):
                    raise TimeoutError("queue get timed out")
            elif not self._items:
                raise IndexError("queue is empty")
            item, size = self._items.popleft()
            self._byte_count -= size
            return item
