"""Tool-free independent probes over bounded, repository-confined snapshots.

This module never starts Droid, a model, a VM, or a network client. Live work
must remain behind :class:`ProbeBroker`; version 0.1 ships only the recorded
broker used by replay tests.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import re
import stat
import threading
from collections import deque
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Mapping, Protocol, Sequence, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .graph import GraphError, MissionGraph
from .protocol import DIGEST_PATTERN, ClaimRecord, EvidenceRecord, canonical_json
from .redaction import sanitize_value
from .rules import (
    EvidenceAuthority,
    Finding,
    FindingLevel,
    ProbeAssessment,
    classify_evidence_authority,
    normalize_value,
)

ProbeResultStatus = Literal["confirmed", "not_confirmed", "inconclusive"]
QuarantineReason = Literal[
    "malformed_output",
    "missing_output",
    "snapshot_mismatch",
    "timeout",
    "unsafe_boundary",
    "unsafe_output",
    "uncited_output",
    "over_escalated_output",
]
MaterialKind = Literal["excerpt", "diff", "test_result"]
UsageStatus = Literal["reported", "unavailable"]

MAX_CLAIMS = 32
MAX_EVIDENCE = 128
MAX_MATERIALS = 128
MAX_REPOSITORY_FILES = 64
MAX_TEXT_BYTES = 128 * 1024
MAX_SNAPSHOT_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
MAX_QUEUE_ITEMS = 32
MAX_QUEUE_BYTES = 4 * 1024 * 1024

_LEVEL_SEVERITY: dict[FindingLevel, int] = {"note": 0, "concern": 1, "blocker": 2}
_CRITICAL_RISKS = frozenset(
    {"money", "security", "data_loss", "public_contract", "explicit_acceptance"}
)
_FILE_EVIDENCE_KINDS = frozenset(
    {
        "changed_file",
        "claim_source",
        "code_use",
        "database_schema",
        "diff",
        "file",
        "repository_contract",
    }
)
_TEST_EVIDENCE_KINDS = frozenset(
    {
        "integration_test",
        "isolated_test",
        "mock_test",
        "test",
        "test_use",
        "unit_test",
        "user_flow_test",
    }
)
_PROTECTED_PATH_PARTS = frozenset(
    {".aws", ".git", ".shadow-mission", ".ssh", "credential", "credentials"}
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
_SHADOW_MARKER = re.compile(r"\[shadow:[A-Za-z0-9._:-]{1,160}\]")
_LINE_SUFFIX = re.compile(r":\d+(?:-\d+)?$")
_STRUCTURED_CREDENTIAL = re.compile(
    r"""(?im)(?<![A-Za-z0-9_-])["']?"""
    r"""(?:authorization|api[_-]?key|access[_-]?key(?:[_-]?id)?|"""
    r"""aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key|"""
    r"""session[_-]?token)|client[_-]?secret|credential(?:s)?|password|"""
    r"""passwd|private[_-]?key|pwd|secret(?:[_-]?access[_-]?key)?|"""
    r"""(?:[a-z0-9]+[_-])?token)"""
    r"""["']?\s*(?::|=)\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}\]\r\n]+)"""
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ProbeSnapshotError(ValueError):
    """A bounded snapshot rejection raised before the broker can run."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class DuplicateProbeError(ValueError):
    """A risk already has a queued, running, or completed probe."""


class ProbeQueueFullError(BufferError):
    """A probe would exceed the scheduler's fixed queue bounds."""


class ProbeBusyError(RuntimeError):
    """Another caller is already running the scheduler's single probe."""


class ProbeClaim(_StrictModel):
    claim_id: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    subject_locator: str = Field(min_length=1)
    property: str = Field(min_length=1)
    value: Any
    unit: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: tuple[str, ...] = Field(min_length=1)

    @field_validator("evidence_ids")
    @classmethod
    def require_sorted_unique_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("probe claim evidence IDs must be sorted and unique")
        return value

    @field_validator("value")
    @classmethod
    def require_json_value(cls, value: Any) -> Any:
        canonical_json({"value": value})
        return value


class ProbeEvidenceMetadata(_StrictModel):
    evidence_id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    source: str = Field(min_length=1)
    locator: str = Field(min_length=1)
    digest: str = Field(pattern=DIGEST_PATTERN)
    provenance_status: str = Field(min_length=1)
    redaction_status: Literal["clean", "redacted"]
    observed_at: int
    authoritative: bool


class ProbeMaterial(_StrictModel):
    evidence_id: str = Field(min_length=1)
    kind: MaterialKind
    content: str = Field(max_length=MAX_TEXT_BYTES)
    content_digest: str = Field(pattern=DIGEST_PATTERN)
    @model_validator(mode="after")
    def bind_content_digest(self) -> "ProbeMaterial":
        expected = hashlib.sha256(self.content.encode("utf-8")).hexdigest()
        if self.content_digest != expected:
            raise ValueError("probe material digest does not match")
        return self



class ProbeRepositoryFile(_StrictModel):
    path: str = Field(min_length=1)
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    content: str = Field(max_length=MAX_TEXT_BYTES)
    content_digest: str = Field(pattern=DIGEST_PATTERN)

    @field_validator("evidence_ids")
    @classmethod
    def require_sorted_unique_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("probe file evidence IDs must be sorted and unique")
        return value
    @model_validator(mode="after")
    def bind_content_digest(self) -> "ProbeRepositoryFile":
        expected = hashlib.sha256(self.content.encode("utf-8")).hexdigest()
        if self.content_digest != expected:
            raise ValueError("probe repository file digest does not match")
        return self



class ProbeSnapshot(_StrictModel):
    """An exact, canonical finding projection safe to send to one probe."""

    schema_version: Literal["0.1"] = "0.1"
    run_id: str = Field(min_length=1)
    finding_id: str = Field(min_length=1)
    finding_dedup_key: str = Field(pattern=DIGEST_PATTERN)
    rule: Literal[
        "cross_worker_conflict", "shared_assumption", "validation_overlap"
    ]
    risk_category: Literal[
        "none",
        "money",
        "security",
        "data_loss",
        "public_contract",
        "explicit_acceptance",
    ]
    maximum_level: FindingLevel
    claims: tuple[ProbeClaim, ...] = Field(min_length=1, max_length=MAX_CLAIMS)
    evidence: tuple[ProbeEvidenceMetadata, ...] = Field(
        min_length=1, max_length=MAX_EVIDENCE
    )
    materials: tuple[ProbeMaterial, ...] = Field(default=(), max_length=MAX_MATERIALS)
    repository_files: tuple[ProbeRepositoryFile, ...] = Field(
        default=(), max_length=MAX_REPOSITORY_FILES
    )

    @field_validator("claims")
    @classmethod
    def require_ordered_claims(cls, value: tuple[ProbeClaim, ...]) -> tuple[ProbeClaim, ...]:
        if tuple(item.claim_id for item in value) != tuple(
            sorted({item.claim_id for item in value})
        ):
            raise ValueError("probe claims must be sorted and unique")
        return value

    @field_validator("evidence")
    @classmethod
    def require_ordered_evidence(
        cls, value: tuple[ProbeEvidenceMetadata, ...]
    ) -> tuple[ProbeEvidenceMetadata, ...]:
        if tuple(item.evidence_id for item in value) != tuple(
            sorted({item.evidence_id for item in value})
        ):
            raise ValueError("probe evidence must be sorted and unique")
        return value
    @model_validator(mode="after")
    def require_bounded_safe_payload(self) -> "ProbeSnapshot":
        try:
            for item in self.materials:
                _validate_safe_text(item.content, secret_canaries=())
            for item in self.repository_files:
                _validate_relative_path(item.path)
                _validate_safe_text(item.content, secret_canaries=())
        except ProbeSnapshotError as error:
            raise ValueError("probe snapshot contains unsafe content") from error
        if self.encoded_size > MAX_SNAPSHOT_BYTES:
            raise ValueError("probe snapshot exceeds its byte limit")
        return self


    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.model_dump(mode="json"))).hexdigest()

    @property
    def encoded_size(self) -> int:
        return len(canonical_json(self.model_dump(mode="json")))

    @classmethod
    def from_finding(
        cls,
        finding: Finding,
        graph: MissionGraph,
        repository_root: Path,
        *,
        excerpts: Mapping[str, str] | None = None,
        diffs: Mapping[str, str] | None = None,
        test_results: Mapping[str, str] | None = None,
        repository_paths: Mapping[str, str] | None = None,
        secret_canaries: Sequence[str] = (),
    ) -> "ProbeSnapshot":
        """Build one confined snapshot or reject before any broker call."""

        claims, evidence = _exact_finding_records(finding, graph)
        canaries = _validated_canaries(secret_canaries)
        materials = _build_materials(
            evidence,
            excerpts=excerpts or {},
            diffs=diffs or {},
            test_results=test_results or {},
            secret_canaries=canaries,
        )
        files = _build_repository_files(
            repository_root,
            evidence,
            repository_paths=repository_paths,
            secret_canaries=canaries,
        )
        maximum_level = _maximum_level(finding)
        try:
            snapshot = cls(
                run_id=graph.run_id,
                finding_id=finding.finding_id,
                finding_dedup_key=finding.dedup_key,
                rule=finding.rule,
                risk_category=finding.risk_category,
                maximum_level=maximum_level,
                claims=tuple(_snapshot_claim(item) for item in claims),
                evidence=tuple(_snapshot_evidence(item) for item in evidence),
                materials=materials,
                repository_files=files,
            )
        except ValidationError as error:
            raise ProbeSnapshotError("snapshot_bounds") from error
        if snapshot.encoded_size > MAX_SNAPSHOT_BYTES:
            raise ProbeSnapshotError("snapshot_too_large")
        return snapshot


class ToolCatalogEntry(_StrictModel):
    tool_id: str = Field(min_length=1)
    allowed: Literal[False]


class ProbeBoundary(_StrictModel):
    """Recorded proof of the complete tool-free independent boundary."""

    schema_version: Literal["0.1"] = "0.1"
    factory_home: Literal["clean"]
    timeout_seconds: Literal[90]
    shadow_activation_stripped: Literal[True]
    mission_correlation_stripped: Literal[True]
    internal_session_alias: str = Field(min_length=1)
    environment_keys: tuple[str, ...] = ()
    list_tools_observed: Literal[True]
    observed_tools: tuple[ToolCatalogEntry, ...] = ()
    enabled_tools: tuple[str, ...] = ()
    collector_event_count: Literal[0] = 0
    collector_events: tuple[str, ...] = ()

    @field_validator("factory_home", mode="before")
    @classmethod
    def require_clean_home(cls, value: Any) -> Any:
        if type(value) is not str or value != "clean":
            raise ValueError("probe boundary must use a clean Factory home")
        return value

    @field_validator("timeout_seconds", mode="before")
    @classmethod
    def require_exact_timeout(cls, value: Any) -> Any:
        if type(value) is not int or value != 90:
            raise ValueError("probe timeout must be exactly 90 seconds")
        return value

    @field_validator(
        "shadow_activation_stripped",
        "mission_correlation_stripped",
        "list_tools_observed",
        mode="before",
    )
    @classmethod
    def require_true_proof(cls, value: Any) -> Any:
        if value is not True:
            raise ValueError("probe boundary proof is false")
        return value

    @field_validator("environment_keys")
    @classmethod
    def reject_mission_environment(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = {item.upper() for item in value}
        if normalized & _FORBIDDEN_ENVIRONMENT_KEYS or any(
            item.startswith(("SHADOW_", "MISSION_", "FACTORY_MISSION_"))
            or "_MISSION_" in item
            or item.endswith("_MISSION")
            for item in normalized
        ):
            raise ValueError("probe boundary retained Mission environment")
        return tuple(sorted(normalized))

    @field_validator("observed_tools")
    @classmethod
    def require_unique_catalog(
        cls, value: tuple[ToolCatalogEntry, ...]
    ) -> tuple[ToolCatalogEntry, ...]:
        identities = tuple(item.tool_id for item in value)
        if len(set(identities)) != len(identities):
            raise ValueError("probe tool catalog contains duplicate IDs")
        return tuple(sorted(value, key=lambda item: item.tool_id))

    @field_validator("enabled_tools", "collector_events")
    @classmethod
    def require_empty_observations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value:
            raise ValueError("probe boundary leaked a tool or collector event")
        return value

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.model_dump(mode="json"))).hexdigest()

    @property
    def policy_digest(self) -> str:
        values = self.model_dump(mode="json")
        del values["internal_session_alias"]
        return hashlib.sha256(canonical_json(values)).hexdigest()


class ProbeBoundaryState(_StrictModel):
    """Strict durable state for the approved independent-probe boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    record_type: Literal["probe_boundary_state"]
    schema_version: Literal["0.1"]
    boundary_digest: str = Field(pattern=DIGEST_PATTERN)
    status: Literal["enabled", "disabled"]
    stopped_at: int | None = Field(default=None, ge=0)
    stop_reason: Literal["unsafe_boundary"] | None = None

    @model_validator(mode="after")
    def require_consistent_status(self) -> "ProbeBoundaryState":
        if self.status == "enabled":
            if self.stopped_at is not None or self.stop_reason is not None:
                raise ValueError("enabled probe boundary contains stop metadata")
        elif self.stopped_at is None or self.stop_reason != "unsafe_boundary":
            raise ValueError("disabled probe boundary lacks stop metadata")
        return self

    @classmethod
    def enabled(cls, boundary_digest: str) -> "ProbeBoundaryState":
        return cls(
            record_type="probe_boundary_state",
            schema_version="0.1",
            boundary_digest=boundary_digest,
            status="enabled",
        )

    def stop(self, *, stopped_at: int) -> "ProbeBoundaryState":
        if self.status == "disabled":
            return self
        return ProbeBoundaryState(
            record_type="probe_boundary_state",
            schema_version="0.1",
            boundary_digest=self.boundary_digest,
            status="disabled",
            stopped_at=stopped_at,
            stop_reason="unsafe_boundary",
        )


@runtime_checkable
class ProbeBoundaryStateStore(Protocol):
    """Authoritative durable storage API for the probe boundary latch."""

    def load(self) -> object | None: ...

    def save(self, state: ProbeBoundaryState) -> None: ...


class InMemoryProbeBoundaryStateStore:
    """Thread-safe state store for tests and one-process recorded probes."""

    def __init__(self, state: ProbeBoundaryState) -> None:
        self._state = ProbeBoundaryState.model_validate(state)
        self._lock = threading.Lock()

    def load(self) -> ProbeBoundaryState:
        with self._lock:
            return self._state

    def save(self, state: ProbeBoundaryState) -> None:
        validated = ProbeBoundaryState.model_validate(state)
        with self._lock:
            if validated.boundary_digest != self._state.boundary_digest:
                raise ValueError("probe boundary state cannot change its binding")
            if self._state.status == "disabled" and validated != self._state:
                raise ValueError("disabled probe boundary state is immutable")
            self._state = validated
class FileProbeBoundaryStateStore:
    """Persist one fail-closed probe boundary state in a private directory."""

    def __init__(self, path: Path, state: ProbeBoundaryState) -> None:
        initial = ProbeBoundaryState.model_validate(state)
        root = path.parent.resolve(strict=True)
        metadata = root.lstat()
        if (
            path.parent.resolve() != root
            or path.name in {"", ".", ".."}
            or root.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.geteuid()
        ):
            raise ValueError("probe boundary state root is not private")
        self.path = root / path.name
        self._lock = threading.Lock()
        if self.path.exists():
            current = self.load()
            if current.boundary_digest != initial.boundary_digest:
                raise ValueError("probe boundary state binding differs")
        else:
            self._write(initial)

    def load(self) -> ProbeBoundaryState:
        try:
            metadata = self.path.lstat()
            payload = self.path.read_bytes()
            value = json.loads(payload)
            state = ProbeBoundaryState.model_validate(value)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise ValueError("probe boundary state is invalid") from error
        if (
            self.path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
            or canonical_json(state.model_dump(mode="json")) + b"\n" != payload
        ):
            raise ValueError("probe boundary state is invalid")
        return state

    def save(self, state: ProbeBoundaryState) -> None:
        validated = ProbeBoundaryState.model_validate(state)
        with self._lock:
            current = self.load()
            if validated.boundary_digest != current.boundary_digest:
                raise ValueError("probe boundary state cannot change its binding")
            if current.status == "disabled" and validated != current:
                raise ValueError("disabled probe boundary state is immutable")
            if current.status == "disabled" and validated == current:
                return
            self._write(validated)

    def _write(self, state: ProbeBoundaryState) -> None:
        temporary = self.path.parent / (
            f".{self.path.name}.{secrets.token_hex(8)}.tmp"
        )
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                handle.write(
                    canonical_json(state.model_dump(mode="json")) + b"\n"
                )
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            directory = os.open(
                self.path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)




class ProbeResult(_StrictModel):
    """The only result schema accepted from recorded and future live brokers."""

    status: ProbeResultStatus
    authoritative_evidence: tuple[str, ...]
    affected_claim_ids: tuple[str, ...] = Field(min_length=1)
    recommended_level: FindingLevel
    reason: str = Field(min_length=1, max_length=512)
    authoritative_value: Any | None = None

    @field_validator("authoritative_evidence", "affected_claim_ids")
    @classmethod
    def require_sorted_unique_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("probe result IDs must be sorted and unique")
        return value

    @model_validator(mode="after")
    def require_status_value(self) -> "ProbeResult":
        if self.status == "confirmed" and self.authoritative_value is None:
            raise ValueError("confirmed result lacks an authoritative value")
        if self.status != "confirmed" and self.authoritative_value is not None:
            raise ValueError("unconfirmed result cannot assert an authoritative value")
        if self.authoritative_value is not None:
            canonical_json({"value": self.authoritative_value})
        return self


class ProbeUsage(_StrictModel):
    """Reported fields only. Missing cost remains explicitly unavailable."""

    status: UsageStatus
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    cost_usd: str | None = None

    @model_validator(mode="after")
    def validate_availability(self) -> "ProbeUsage":
        values = (self.input_tokens, self.output_tokens, self.cost_usd)
        if self.status == "unavailable" and any(item is not None for item in values):
            raise ValueError("unavailable usage cannot contain invented values")
        if self.status == "reported" and all(item is None for item in values):
            raise ValueError("reported usage must contain an observation")
        if self.cost_usd is not None and not re.fullmatch(
            r"(?:0|[1-9]\d*)(?:\.\d+)?", self.cost_usd
        ):
            raise ValueError("reported cost must be a non-negative decimal string")
        return self


@dataclass(frozen=True)
class ProbeAttempt:
    """Raw broker output bound to the exact snapshot digest."""

    snapshot_digest: str
    output: bytes | str | None
    timed_out: bool = False
    usage: object | None = None


@dataclass(frozen=True)
class RecordedProbe:
    """One prepared boundary and the attempt recorded after snapshot send."""

    boundary: object
    attempt: ProbeAttempt


@runtime_checkable
class ProbeBroker(Protocol):
    """Fail-closed two-step boundary for one independent probe."""

    def prepare(self) -> object: ...

    def send(self, snapshot: ProbeSnapshot) -> ProbeAttempt: ...

    def abort(self) -> bool:
        """Release a prepared boundary and acknowledge that it stopped."""
        ...


class RecordedProbeBroker:
    """Replay fixed two-step probes without starting a process or making a call."""

    def __init__(self, probes: RecordedProbe | Sequence[RecordedProbe]) -> None:
        if isinstance(probes, RecordedProbe):
            probes = (probes,)
        if not probes:
            raise ValueError("recorded broker requires at least one probe")
        self._probes = deque(probes)
        self._prepared: RecordedProbe | None = None
        self.prepared_count = 0
        self.requests: list[ProbeSnapshot] = []

    def prepare(self) -> object:
        if self._prepared is not None:
            raise RuntimeError("recorded probe already prepared")
        if not self._probes:
            raise RuntimeError("recorded probes are exhausted")
        self._prepared = self._probes.popleft()
        self.prepared_count += 1
        return self._prepared.boundary

    def send(self, snapshot: ProbeSnapshot) -> ProbeAttempt:
        if self._prepared is None:
            raise RuntimeError("recorded probe was not prepared")
        probe = self._prepared
        self._prepared = None
        self.requests.append(snapshot)
        return probe.attempt

    def abort(self) -> bool:
        self._prepared = None
        return True


class ProbeQuarantine(_StrictModel):
    """A bounded reason which never stores rejected broker output."""

    reason: QuarantineReason


@dataclass(frozen=True)
class ProbeOutcome:
    snapshot_digest: str
    assessment: ProbeAssessment | None
    usage: ProbeUsage
    quarantine: ProbeQuarantine | None = None


class ProbeRunner:
    """Rebuild, prepare, validate, send, and sign one accepted probe."""

    def __init__(
        self,
        broker: ProbeBroker,
        *,
        signing_key: bytes,
        approved_boundary_digest: str,
        boundary_state_store: ProbeBoundaryStateStore,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("probe signing key is too short")
        if not re.fullmatch(DIGEST_PATTERN, approved_boundary_digest):
            raise ValueError("approved probe boundary policy digest is invalid")
        if not isinstance(boundary_state_store, ProbeBoundaryStateStore):
            raise TypeError("probe boundary state store does not implement its API")
        self._broker = broker
        self._signing_key = bytes(signing_key)
        self._approved_boundary_policy_digest = approved_boundary_digest
        self._boundary_state_store = boundary_state_store
        self._boundary_lock = threading.Lock()
        self._boundary_disabled = False

    def run(
        self,
        snapshot: ProbeSnapshot,
        finding: Finding,
        graph: MissionGraph,
        repository_root: Path,
        *,
        probe_id: str,
        observed_at: int,
        excerpts: Mapping[str, str] | None = None,
        diffs: Mapping[str, str] | None = None,
        test_results: Mapping[str, str] | None = None,
        repository_paths: Mapping[str, str] | None = None,
        secret_canaries: Sequence[str] = (),
    ) -> ProbeOutcome:
        """Reject a supplied snapshot unless the canonical rebuild is exact."""

        canonical = ProbeSnapshot.from_finding(
            finding,
            graph,
            repository_root,
            excerpts=excerpts,
            diffs=diffs,
            test_results=test_results,
            repository_paths=repository_paths,
            secret_canaries=secret_canaries,
        )
        if not hmac.compare_digest(snapshot.digest, canonical.digest):
            return _quarantined(
                snapshot.digest,
                "snapshot_mismatch",
                ProbeUsage(status="unavailable"),
            )
        return self._run_canonical(
            canonical,
            probe_id=probe_id,
            observed_at=observed_at,
            secret_canaries=secret_canaries,
        )

    def run_finding(
        self,
        finding: Finding,
        graph: MissionGraph,
        repository_root: Path,
        *,
        probe_id: str,
        observed_at: int,
        excerpts: Mapping[str, str] | None = None,
        diffs: Mapping[str, str] | None = None,
        test_results: Mapping[str, str] | None = None,
        repository_paths: Mapping[str, str] | None = None,
        secret_canaries: Sequence[str] = (),
    ) -> ProbeOutcome:
        snapshot = ProbeSnapshot.from_finding(
            finding,
            graph,
            repository_root,
            excerpts=excerpts,
            diffs=diffs,
            test_results=test_results,
            repository_paths=repository_paths,
            secret_canaries=secret_canaries,
        )
        return self._run_canonical(
            snapshot,
            probe_id=probe_id,
            observed_at=observed_at,
            secret_canaries=secret_canaries,
        )

    def _run_canonical(
        self,
        snapshot: ProbeSnapshot,
        *,
        probe_id: str,
        observed_at: int,
        secret_canaries: Sequence[str],
    ) -> ProbeOutcome:
        unavailable = ProbeUsage(status="unavailable")
        snapshot_digest = snapshot.digest
        if not self._boundary_allows_probes():
            return _quarantined(snapshot_digest, "unsafe_boundary", unavailable)
        try:
            raw_boundary = self._broker.prepare()
        except Exception:
            self._disable_boundary(observed_at=observed_at)
            return _quarantined(snapshot_digest, "unsafe_boundary", unavailable)
        try:
            boundary = ProbeBoundary.model_validate(raw_boundary)
        except (TypeError, ValidationError):
            self._abort_prepared()
            self._disable_boundary(observed_at=observed_at)
            return _quarantined(snapshot_digest, "unsafe_boundary", unavailable)
        if boundary.policy_digest != self._approved_boundary_policy_digest:
            self._abort_prepared()
            self._disable_boundary(observed_at=observed_at)
            return _quarantined(snapshot_digest, "unsafe_boundary", unavailable)

        try:
            attempt = self._broker.send(snapshot)
        except Exception:
            self._abort_prepared()
            self._disable_boundary(observed_at=observed_at)
            return _quarantined(snapshot_digest, "unsafe_boundary", unavailable)
        usage = _validated_usage(attempt.usage)
        if attempt.snapshot_digest != snapshot_digest:
            return _quarantined(snapshot_digest, "snapshot_mismatch", usage)
        if attempt.timed_out:
            return _quarantined(snapshot_digest, "timeout", usage)
        if attempt.output is None:
            return _quarantined(snapshot_digest, "missing_output", usage)
        raw_output, rejection = _decode_probe_output(
            attempt.output,
            secret_canaries=secret_canaries,
        )
        if rejection is not None:
            return _quarantined(snapshot_digest, rejection, usage)
        try:
            result = ProbeResult.model_validate(raw_output)
        except (TypeError, ValueError, ValidationError):
            return _quarantined(snapshot_digest, "malformed_output", usage)
        if not _result_claims_match(result, snapshot):
            return _quarantined(snapshot_digest, "uncited_output", usage)
        if not _result_citations_are_authoritative(result, snapshot):
            return _quarantined(snapshot_digest, "uncited_output", usage)
        if _LEVEL_SEVERITY[result.recommended_level] > _LEVEL_SEVERITY[
            snapshot.maximum_level
        ]:
            return _quarantined(snapshot_digest, "over_escalated_output", usage)
        authoritative_value = (
            normalize_value(result.authoritative_value)
            if result.status == "confirmed"
            else None
        )
        assessment = ProbeAssessment.create(
            probe_id=probe_id,
            run_id=snapshot.run_id,
            finding_dedup_key=snapshot.finding_dedup_key,
            claim_ids=(item.claim_id for item in snapshot.claims),
            evidence_digests=(item.digest for item in snapshot.evidence),
            risk_category=snapshot.risk_category,
            recommended_level=result.recommended_level,
            status=result.status,
            authoritative_value=authoritative_value,
            snapshot_digest=snapshot_digest,
            boundary_digest=boundary.digest,
            boundary_policy_digest=boundary.policy_digest,
            signing_key=self._signing_key,
            observed_at=observed_at,
        )
        return ProbeOutcome(
            snapshot_digest=snapshot_digest,
            assessment=assessment,
            usage=usage,
        )

    def abort(self) -> bool:
        """Stop the broker boundary before controller shutdown."""

        try:
            return self._broker.abort() is True
        except Exception:
            return False


    def _abort_prepared(self) -> None:
        try:
            self._broker.abort()
        except Exception:
            pass

    def _boundary_allows_probes(self) -> bool:
        with self._boundary_lock:
            if self._boundary_disabled:
                return False
            try:
                state = ProbeBoundaryState.model_validate(
                    self._boundary_state_store.load()
                )
            except (TypeError, ValueError):
                self._boundary_disabled = True
                return False
            if (
                state.boundary_digest != self._approved_boundary_policy_digest
                or state.status != "enabled"
            ):
                self._boundary_disabled = True
                return False
            return True

    def _disable_boundary(self, *, observed_at: int) -> None:
        with self._boundary_lock:
            self._boundary_disabled = True
            try:
                loaded = ProbeBoundaryState.model_validate(
                    self._boundary_state_store.load()
                )
            except (TypeError, ValueError):
                loaded = ProbeBoundaryState.enabled(
                    self._approved_boundary_policy_digest
                )
            if loaded.boundary_digest != self._approved_boundary_policy_digest:
                loaded = ProbeBoundaryState.enabled(
                    self._approved_boundary_policy_digest
                )
            self._boundary_state_store.save(loaded.stop(stopped_at=observed_at))


@dataclass(frozen=True)
class ProbeJob:
    snapshot: ProbeSnapshot
    finding: Finding
    probe_id: str
    observed_at: int
    graph: MissionGraph
    repository_root: Path
    excerpts: Mapping[str, str] | None = None
    diffs: Mapping[str, str] | None = None
    test_results: Mapping[str, str] | None = None
    repository_paths: Mapping[str, str] | None = None
    secret_canaries: tuple[str, ...] = ()


class ProbeScheduler:
    """A bounded FIFO which permits only one probe to execute at a time."""

    def __init__(
        self,
        runner: ProbeRunner,
        *,
        max_items: int = MAX_QUEUE_ITEMS,
        max_bytes: int = MAX_QUEUE_BYTES,
    ) -> None:
        if max_items <= 0 or max_bytes <= 0:
            raise ValueError("probe queue bounds must be positive")
        self._runner = runner
        self._max_items = max_items
        self._max_bytes = max_bytes
        self._queued_bytes = 0
        self._queue: deque[ProbeJob] = deque()
        self._known_risks: set[str] = set()
        self._running = False
        self._lock = threading.Lock()

    def enqueue(self, job: ProbeJob) -> None:
        canonical = ProbeSnapshot.from_finding(
            job.finding,
            job.graph,
            job.repository_root,
            excerpts=job.excerpts,
            diffs=job.diffs,
            test_results=job.test_results,
            repository_paths=job.repository_paths,
            secret_canaries=job.secret_canaries,
        )
        if not hmac.compare_digest(job.snapshot.digest, canonical.digest):
            raise ProbeSnapshotError("snapshot_mismatch")
        size = canonical.encoded_size
        with self._lock:
            risk = job.finding.dedup_key
            if risk in self._known_risks:
                raise DuplicateProbeError("duplicate_probe_risk")
            if len(self._queue) >= self._max_items or self._queued_bytes + size > self._max_bytes:
                raise ProbeQueueFullError("probe_queue_full")
            self._queue.append(job)
            self._known_risks.add(risk)
            self._queued_bytes += size

    def run_next(self) -> ProbeOutcome | None:
        with self._lock:
            if self._running:
                raise ProbeBusyError("probe_already_running")
            if not self._queue:
                return None
            job = self._queue.popleft()
            self._queued_bytes -= job.snapshot.encoded_size
            self._running = True
        try:
            return self._runner.run(
                job.snapshot,
                job.finding,
                job.graph,
                job.repository_root,
                probe_id=job.probe_id,
                observed_at=job.observed_at,
                excerpts=job.excerpts,
                diffs=job.diffs,
                test_results=job.test_results,
                repository_paths=job.repository_paths,
                secret_canaries=job.secret_canaries,
            )
        finally:
            with self._lock:
                self._running = False

    def abort(self) -> bool:
        """Stop the runner's broker boundary."""

        return self._runner.abort()


def _exact_finding_records(
    finding: Finding, graph: MissionGraph
) -> tuple[tuple[ClaimRecord, ...], tuple[EvidenceRecord, ...]]:
    if not re.fullmatch(DIGEST_PATTERN, finding.dedup_key):
        raise ProbeSnapshotError("invalid_finding_identity")
    if (
        len(finding.claim_ids) > MAX_CLAIMS
        or len(finding.evidence_ids) > MAX_EVIDENCE
        or len(finding.evidence_digests) > MAX_EVIDENCE
    ):
        raise ProbeSnapshotError("snapshot_count_limit")
    claims_by_id = {item.claim_id: item for item in graph.claims()}
    if not finding.claim_ids or tuple(sorted(set(finding.claim_ids))) != finding.claim_ids:
        raise ProbeSnapshotError("missing_claim_references")
    try:
        claims = tuple(claims_by_id[item] for item in finding.claim_ids)
    except KeyError as error:
        raise ProbeSnapshotError("missing_claim_references") from error
    evidence_by_id: dict[str, EvidenceRecord] = {}
    for claim in claims:
        try:
            records = graph.evidence_for_claim(claim.claim_id)
        except GraphError as error:
            raise ProbeSnapshotError("missing_evidence_references") from error
        for record in records:
            evidence_by_id[record.evidence_id] = record
    if not finding.evidence_ids or tuple(sorted(set(finding.evidence_ids))) != finding.evidence_ids:
        raise ProbeSnapshotError("missing_evidence_references")
    if any(item not in evidence_by_id for item in finding.evidence_ids):
        raise ProbeSnapshotError("missing_evidence_references")
    evidence = tuple(evidence_by_id[item] for item in finding.evidence_ids)
    expected_digests = tuple(sorted({item.digest for item in evidence}))
    if expected_digests != finding.evidence_digests:
        raise ProbeSnapshotError("evidence_digest_mismatch")
    if len(claims) > MAX_CLAIMS or len(evidence) > MAX_EVIDENCE:
        raise ProbeSnapshotError("snapshot_count_limit")
    return claims, evidence


def _snapshot_claim(claim: ClaimRecord) -> ProbeClaim:
    return ProbeClaim(
        claim_id=claim.claim_id,
        subject=claim.subject,
        subject_locator=claim.subject_locator,
        property=claim.property,
        value=claim.value,
        unit=claim.unit,
        confidence=claim.confidence,
        evidence_ids=claim.evidence_ids,
    )


def _snapshot_evidence(record: EvidenceRecord) -> ProbeEvidenceMetadata:
    return ProbeEvidenceMetadata(
        evidence_id=record.evidence_id,
        kind=record.kind,
        source=record.source,
        locator=record.locator,
        digest=record.digest,
        provenance_status=record.provenance_status,
        redaction_status=record.redaction_status,
        observed_at=record.observed_at,
        authoritative=(
            classify_evidence_authority(record) == EvidenceAuthority.AUTHORITATIVE
        ),
    )


def _validated_canaries(values: Sequence[str]) -> tuple[str, ...]:
    if any(not isinstance(item, str) or not item for item in values):
        raise ProbeSnapshotError("invalid_secret_canary")
    return tuple(values)


def _validate_safe_text(text: str, *, secret_canaries: Sequence[str]) -> None:
    if not isinstance(text, str):
        raise ProbeSnapshotError("non_text_material")
    if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        raise ProbeSnapshotError("material_too_large")
    if "\x00" in text or _SHADOW_MARKER.search(text):
        raise ProbeSnapshotError("unsafe_material")
    if _STRUCTURED_CREDENTIAL.search(text):
        raise ProbeSnapshotError("unsafe_material")
    if any(canary in text for canary in secret_canaries):
        raise ProbeSnapshotError("secret_canary")
    _, redaction_status = sanitize_value(text)
    if redaction_status != "clean":
        raise ProbeSnapshotError("unsafe_material")


def _build_materials(
    evidence: Sequence[EvidenceRecord],
    *,
    excerpts: Mapping[str, str],
    diffs: Mapping[str, str],
    test_results: Mapping[str, str],
    secret_canaries: Sequence[str],
) -> tuple[ProbeMaterial, ...]:
    evidence_by_id = {item.evidence_id: item for item in evidence}
    entries: list[ProbeMaterial] = []
    for kind, supplied in (
        ("excerpt", excerpts),
        ("diff", diffs),
        ("test_result", test_results),
    ):
        if not isinstance(supplied, Mapping):
            raise ProbeSnapshotError("malformed_materials")
        for evidence_id, content in supplied.items():
            record = evidence_by_id.get(evidence_id)
            if record is None:
                raise ProbeSnapshotError("missing_evidence_references")
            if kind == "diff" and record.kind.casefold() not in _FILE_EVIDENCE_KINDS:
                raise ProbeSnapshotError("material_kind_mismatch")
            if kind == "test_result" and record.kind.casefold() not in _TEST_EVIDENCE_KINDS:
                raise ProbeSnapshotError("material_kind_mismatch")
            _validate_safe_text(content, secret_canaries=secret_canaries)
            entries.append(
                ProbeMaterial(
                    evidence_id=evidence_id,
                    kind=kind,
                    content=content,
                    content_digest=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                )
            )
    entries.sort(key=lambda item: (item.evidence_id, item.kind))
    if len(entries) > MAX_MATERIALS:
        raise ProbeSnapshotError("snapshot_count_limit")
    return tuple(entries)


def _locator_path(locator: str) -> str:
    value = locator.split("#", 1)[0]
    value = _LINE_SUFFIX.sub("", value)
    if ":" in value:
        prefix, _ = value.split(":", 1)
        if Path(prefix).suffix:
            value = prefix
    return value


def _path_is_named(path: str, locator: str) -> bool:
    return _locator_path(locator) == PurePosixPath(path).as_posix()


def _validate_relative_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ProbeSnapshotError("invalid_repository_path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ProbeSnapshotError("repository_path_escape")
    for part in path.parts:
        lowered = part.casefold()
        if (
            lowered in _PROTECTED_PATH_PARTS
            or lowered.startswith(".env")
            or "credential" in lowered
        ):
            raise ProbeSnapshotError("protected_repository_path")
    return path


def _read_repository_file(
    repository_root: Path,
    relative_path: str,
    *,
    secret_canaries: Sequence[str],
) -> tuple[str, str]:
    path = _validate_relative_path(relative_path)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW
    try:
        root_descriptor = os.open(repository_root, directory_flags)
    except OSError as error:
        raise ProbeSnapshotError("invalid_repository_root") from error

    directory_descriptors = [root_descriptor]
    descriptor: int | None = None
    try:
        for component in path.parts[:-1]:
            try:
                next_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=directory_descriptors[-1],
                )
            except FileNotFoundError as error:
                raise ProbeSnapshotError("missing_repository_file") from error
            except OSError as error:
                raise ProbeSnapshotError("nonregular_repository_file") from error
            directory_descriptors.append(next_descriptor)
        try:
            descriptor = os.open(
                path.parts[-1],
                file_flags,
                dir_fd=directory_descriptors[-1],
            )
        except FileNotFoundError as error:
            raise ProbeSnapshotError("missing_repository_file") from error
        except OSError as error:
            raise ProbeSnapshotError("nonregular_repository_file") from error
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ProbeSnapshotError("nonregular_repository_file")
        if metadata.st_size > MAX_TEXT_BYTES:
            raise ProbeSnapshotError("repository_file_too_large")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_TEXT_BYTES + 1)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory_descriptor in reversed(directory_descriptors):
            os.close(directory_descriptor)
    if len(raw) > MAX_TEXT_BYTES:
        raise ProbeSnapshotError("repository_file_too_large")
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProbeSnapshotError("non_text_repository_file") from error
    _validate_safe_text(content, secret_canaries=secret_canaries)
    return content, hashlib.sha256(raw).hexdigest()


def _build_repository_files(
    repository_root: Path,
    evidence: Sequence[EvidenceRecord],
    *,
    repository_paths: Mapping[str, str] | None,
    secret_canaries: Sequence[str],
) -> tuple[ProbeRepositoryFile, ...]:
    evidence_by_id = {item.evidence_id: item for item in evidence}
    selected: dict[str, list[str]] = {}
    if repository_paths is None:
        for record in evidence:
            if record.kind.casefold() not in _FILE_EVIDENCE_KINDS:
                continue
            path = _locator_path(record.locator)
            _validate_relative_path(path)
            selected.setdefault(path, []).append(record.evidence_id)
    else:
        if not isinstance(repository_paths, Mapping):
            raise ProbeSnapshotError("invalid_repository_paths")
        for evidence_id, path in repository_paths.items():
            record = evidence_by_id.get(evidence_id)
            if record is None:
                raise ProbeSnapshotError("missing_evidence_references")
            if record.kind.casefold() not in _FILE_EVIDENCE_KINDS:
                raise ProbeSnapshotError("repository_file_not_direct_evidence")
            normalized = _validate_relative_path(path).as_posix()
            if not _path_is_named(normalized, record.locator):
                raise ProbeSnapshotError("repository_file_not_direct_evidence")
            selected.setdefault(normalized, []).append(evidence_id)
    if len(selected) > MAX_REPOSITORY_FILES:
        raise ProbeSnapshotError("snapshot_count_limit")
    result: list[ProbeRepositoryFile] = []
    for path in sorted(selected):
        content, digest = _read_repository_file(
            repository_root,
            path,
            secret_canaries=secret_canaries,
        )
        result.append(
            ProbeRepositoryFile(
                path=path,
                evidence_ids=tuple(sorted(set(selected[path]))),
                content=content,
                content_digest=digest,
            )
        )
    return tuple(result)


def _maximum_level(finding: Finding) -> FindingLevel:
    if finding.risk_category in _CRITICAL_RISKS:
        return "blocker"
    return finding.level




def _decode_probe_output(
    output: bytes | str,
    *,
    secret_canaries: Sequence[str],
) -> tuple[object | None, QuarantineReason | None]:
    if not isinstance(output, (bytes, str)):
        return None, "malformed_output"
    if isinstance(output, bytes):
        if len(output) > MAX_OUTPUT_BYTES:
            return None, "unsafe_output"
        try:
            text = output.decode("utf-8")
        except UnicodeDecodeError:
            return None, "malformed_output"
    else:
        if len(output) > MAX_OUTPUT_BYTES:
            return None, "unsafe_output"
        try:
            encoded = output.encode("utf-8")
        except UnicodeEncodeError:
            return None, "malformed_output"
        if len(encoded) > MAX_OUTPUT_BYTES:
            return None, "unsafe_output"
        text = output
    unsafe_string_found = False

    def retain_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        nonlocal unsafe_string_found
        keys = tuple(key for key, _ in pairs)
        if len(set(keys)) != len(keys):
            raise ValueError("probe output contains a duplicate JSON key")
        if any(
            _contains_unsafe_string(key, secret_canaries=secret_canaries)
            or _contains_unsafe_string(item, secret_canaries=secret_canaries)
            for key, item in pairs
        ):
            unsafe_string_found = True
        return dict(pairs)

    try:
        value = json.loads(text, object_pairs_hook=retain_object)
    except (TypeError, ValueError):
        return None, "malformed_output"
    if unsafe_string_found or _contains_unsafe_string(
        value, secret_canaries=secret_canaries
    ):
        return None, "unsafe_output"
    _, redaction_status = sanitize_value(value)
    if redaction_status != "clean":
        return None, "unsafe_output"
    return value, None


def _contains_unsafe_string(
    value: object,
    *,
    secret_canaries: Sequence[str],
) -> bool:
    if isinstance(value, str):
        return bool(_SHADOW_MARKER.search(value)) or any(
            canary in value for canary in secret_canaries
        )
    if isinstance(value, Mapping):
        return any(
            _contains_unsafe_string(key, secret_canaries=secret_canaries)
            or _contains_unsafe_string(item, secret_canaries=secret_canaries)
            for key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(
            _contains_unsafe_string(item, secret_canaries=secret_canaries)
            for item in value
        )
    return False


def _result_claims_match(result: ProbeResult, snapshot: ProbeSnapshot) -> bool:
    return result.affected_claim_ids == tuple(item.claim_id for item in snapshot.claims)


def _result_citations_are_authoritative(
    result: ProbeResult, snapshot: ProbeSnapshot
) -> bool:
    if result.status == "inconclusive" and not result.authoritative_evidence:
        return True
    if not result.authoritative_evidence:
        return False
    evidence = {item.evidence_id: item for item in snapshot.evidence}
    return all(
        evidence_id in evidence and evidence[evidence_id].authoritative
        for evidence_id in result.authoritative_evidence
    )


def _validated_usage(value: object | None) -> ProbeUsage:
    if value is None:
        return ProbeUsage(status="unavailable")
    try:
        raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
        return ProbeUsage.model_validate(raw)
    except (TypeError, ValueError, ValidationError):
        return ProbeUsage(status="unavailable")


def _quarantined(
    snapshot_digest: str, reason: QuarantineReason, usage: ProbeUsage
) -> ProbeOutcome:
    return ProbeOutcome(
        snapshot_digest=snapshot_digest,
        assessment=None,
        usage=usage,
        quarantine=ProbeQuarantine(reason=reason),
    )
