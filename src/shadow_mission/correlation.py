"""Factory-side Mission correlation bound to authoritative relation evidence."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .auth import make_alias
from .collector import MissionCorrelationRegistry
from .protocol import DIGEST_PATTERN, canonical_json
from .roles import (
    ConfiguredRole,
    FrozenMissionRelations,
    LiveMissionRelations,
    MissionRelation,
    MissionRelations,
    RoleMapper,
)

MAX_CORRELATION_RECORD_BYTES = 1 << 20
PINNED_FACTORY_RELATION_DROID_VERSION = "0.197.0"
FACTORY_VALIDATOR_SKILLS = frozenset(
    {"scrutiny-validator", "user-testing-validator"}
)
_FACTORY_RELATION_CONTRACT = {
    "droid_version": PINNED_FACTORY_RELATION_DROID_VERSION,
    "mission_files": ("state.json", "features.json", "progress_log.jsonl"),
    "worker_events": ("worker_selected_feature", "worker_started"),
    "validator_skills": tuple(sorted(FACTORY_VALIDATOR_SKILLS)),
}
HOST_FACTORY_HOME_NAME = ".factory"
HOST_FACTORY_MISSIONS_NAME = "missions"
HOST_FACTORY_SESSIONS_NAME = "sessions"


def host_factory_home(home: Path | None = None) -> Path:
    """Return the host Factory home bound to HOME."""

    if home is None:
        raw = os.environ.get("HOME")
        if not raw:
            raise MissionCorrelationError("HOME is unset")
        home = Path(raw)
    return home.resolve(strict=True) / HOST_FACTORY_HOME_NAME


def host_factory_mission_root(home: Path | None = None) -> Path:
    """Return the host Factory Mission directory root."""

    return host_factory_home(home) / HOST_FACTORY_MISSIONS_NAME


def require_host_factory_mission_root(mission_root: Path) -> Path:
    """Admit only a `.factory/missions` root with a sibling sessions directory."""

    resolved = mission_root.resolve(strict=True)
    if (
        resolved.name != HOST_FACTORY_MISSIONS_NAME
        or resolved.parent.name != HOST_FACTORY_HOME_NAME
    ):
        raise MissionCorrelationError(
            "Factory Mission root must be the host Factory missions directory"
        )
    sessions = resolved.parent / HOST_FACTORY_SESSIONS_NAME
    try:
        session_metadata = sessions.lstat()
    except OSError as error:
        raise MissionCorrelationError(
            "Factory session root is unavailable"
        ) from error
    if (
        sessions.is_symlink()
        or not stat.S_ISDIR(session_metadata.st_mode)
        or session_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(session_metadata.st_mode) & 0o022
    ):
        raise MissionCorrelationError("Factory session root is unsafe")
    return resolved



def snapshot_factory_mission_names(mission_root: Path | int) -> frozenset[str]:
    """Return the current child names under one Factory Mission root."""

    try:
        return frozenset(os.listdir(mission_root))
    except OSError as error:
        raise MissionCorrelationError(
            "Factory Mission root is unavailable"
        ) from error



class MissionCorrelationError(ValueError):
    """Authoritative Factory Mission relation evidence is invalid."""


class FactorySessionRelation(BaseModel):
    """One Factory-observed session and its Mission disposition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: str = Field(min_length=1, max_length=512)
    disposition: Literal["mission_role", "shadow_owned", "same_project_decoy"]
    role_id: str | None = Field(default=None, min_length=1, max_length=128)
    role_kind: Literal["orchestrator", "worker", "validator"] | None = None
    assignment_id: str | None = Field(default=None, min_length=1, max_length=256)
    source_digest: str = Field(pattern=DIGEST_PATTERN)
    relation_kind: Literal["mission_relation", "assignment"]
    confidence: Literal["high", "low", "none"]
    corroborating_role_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def require_authoritative_role_identity(self) -> FactorySessionRelation:
        if self.disposition == "mission_role":
            if self.role_id is None or self.role_kind is None or self.assignment_id is None:
                raise ValueError("Mission role relation is incomplete")
            if self.confidence != "high":
                raise ValueError("Mission role relation is not high confidence")
            if self.role_id not in self.corroborating_role_ids:
                raise ValueError("Mission role relation lacks authoritative corroboration")
        elif any(
            value is not None
            for value in (self.role_id, self.role_kind, self.assignment_id)
        ) or self.corroborating_role_ids:
            raise ValueError("excluded session cannot claim a Mission role")
        return self


class FactoryMissionRoleCounts(BaseModel):
    """Expected or observed Factory Mission role counts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    orchestrator: int = Field(ge=0, strict=True)
    worker: int = Field(ge=0, strict=True)
    validator: int = Field(ge=0, strict=True)


class FactoryMissionRoleInventory(BaseModel):
    """Digest-bound role inventory and completeness verdict."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    expected: FactoryMissionRoleCounts
    observed: FactoryMissionRoleCounts
    shortfalls: list[Literal["orchestrator", "worker", "validator"]]
    complete: bool = Field(strict=True)

    @model_validator(mode="after")
    def validate_verdict(self) -> FactoryMissionRoleInventory:
        expected = self.expected.model_dump(mode="json")
        observed = self.observed.model_dump(mode="json")
        shortfalls = sorted(
            role for role in expected if observed[role] < expected[role]
        )
        if self.shortfalls != shortfalls:
            raise ValueError("Factory role inventory shortfalls differ")
        if self.complete != (not shortfalls):
            raise ValueError("Factory role inventory completeness differs")
        return self


class FactoryMissionCorrelationRecord(BaseModel):
    """Host-held output from an authoritative Factory Mission relation surface."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    source_class: Literal["factory_mission_relations"]
    mission_id: str = Field(min_length=1, max_length=256)
    observed_at: int = Field(ge=0)
    sessions: tuple[FactorySessionRelation, ...] = Field(min_length=1)
    role_inventory: FactoryMissionRoleInventory
    record_digest: str = Field(pattern=DIGEST_PATTERN)

    @model_validator(mode="after")
    def validate_correlation(self) -> FactoryMissionCorrelationRecord:
        raw_ids = [session.session_id for session in self.sessions]
        if len(raw_ids) != len(set(raw_ids)):
            raise ValueError("Factory relation record repeats a session")
        mission_roles = [
            session for session in self.sessions if session.disposition == "mission_role"
        ]
        role_ids = [session.role_id for session in mission_roles]
        if len(role_ids) != len(set(role_ids)):
            raise ValueError("Factory relation record repeats a configured role")
        observed = {
            role: sum(session.role_kind == role for session in mission_roles)
            for role in ("orchestrator", "worker", "validator")
        }
        if self.role_inventory.observed.model_dump(mode="json") != observed:
            raise ValueError("Factory relation record role inventory differs")
        if not any(
            session.disposition == "shadow_owned" for session in self.sessions
        ):
            raise ValueError("Factory relation record lacks a Shadow-owned exclusion")
        if not any(
            session.disposition == "same_project_decoy" for session in self.sessions
        ):
            raise ValueError("Factory relation record lacks a same-project decoy")
        expected = correlation_record_digest(self.model_dump(mode="json"))
        if self.record_digest != expected:
            raise ValueError("Factory relation record digest differs")
        return self


def correlation_record_digest(value: Mapping[str, Any]) -> str:
    """Hash the canonical correlation record without its self-digest."""

    payload = {key: item for key, item in value.items() if key != "record_digest"}
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def correlation_wrapper_digest(value: Mapping[str, Any]) -> str:
    """Hash the canonical correlation wrapper without its self-digest."""

    payload = {key: item for key, item in value.items() if key != "record_digest"}
    return hashlib.sha256(canonical_json(payload)).hexdigest()


class FactoryMissionCorrelationWrapper(BaseModel):
    """One strict run-bound wrapper around Factory relation evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    source_digest: str = Field(pattern=DIGEST_PATTERN)
    mission_id: str = Field(min_length=1, max_length=256)
    record: FactoryMissionCorrelationRecord
    role_counts: FactoryMissionRoleCounts
    role_assignments: dict[str, str]
    record_digest: str = Field(pattern=DIGEST_PATTERN)

    @model_validator(mode="after")
    def validate_wrapper(self) -> FactoryMissionCorrelationWrapper:
        expected_assignments = {
            relation.role_id: relation.session_id
            for relation in self.record.sessions
            if relation.disposition == "mission_role"
            and relation.role_id is not None
        }
        if self.role_counts != self.record.role_inventory.observed:
            raise ValueError("Factory relation wrapper role counts differ")
        if self.role_assignments != expected_assignments:
            raise ValueError("Factory relation wrapper role assignments differ")
        if any(
            not role_id or not session_id
            for role_id, session_id in self.role_assignments.items()
        ):
            raise ValueError("Factory relation wrapper role assignment is invalid")
        expected_digest = correlation_wrapper_digest(self.model_dump(mode="json"))
        if self.record_digest != expected_digest:
            raise ValueError("Factory relation wrapper digest differs")
        return self


@dataclass
class MissionCorrelationBinding:
    """One secret-derived registry and matching role evidence for a live run."""

    mission_id: str
    source_digest: str
    registry: MissionCorrelationRegistry
    relations: MissionRelations
    roles: tuple[ConfiguredRole, ...]
    excluded_session_aliases: frozenset[str]
    role_assignments: Mapping[str, str]
    role_mapper: RoleMapper = field(init=False)

    def __post_init__(self) -> None:
        self.role_mapper = RoleMapper(
            self.roles,
            self.relations,
            excluded_session_aliases=self.excluded_session_aliases,
        )

    def allow_relation(
        self,
        *,
        relation: MissionRelation,
        role: ConfiguredRole,
        evidence_digest: str,
    ) -> None:
        """Atomically expose one append-only Factory relation to live review."""

        if not isinstance(self.relations, LiveMissionRelations):
            raise MissionCorrelationError("frozen Mission relations cannot change")
        prior = self.role_assignments.get(role.role_id)
        if prior is not None and prior != relation.session_alias:
            raise MissionCorrelationError("Factory role assignment changed")
        self.relations.allow(relation)
        self.role_mapper.register_role(role)
        self.registry.allow(relation.session_alias, evidence_digest)
        roles = {item.role_id: item for item in self.roles}
        roles[role.role_id] = role
        assignments = dict(self.role_assignments)
        assignments[role.role_id] = relation.session_alias
        self.roles = tuple(sorted(roles.values(), key=lambda item: item.role_id))
        self.role_assignments = dict(sorted(assignments.items()))

    def exclude_session(self, session_alias: str) -> None:
        self.registry.exclude(session_alias)
        self.role_mapper.exclude_session(session_alias)
        self.excluded_session_aliases = frozenset(
            (*self.excluded_session_aliases, session_alias)
        )


class _FactoryMissionState(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    mission_id: str = Field(alias="missionId", min_length=1, max_length=256)
    working_directory: str = Field(
        alias="workingDirectory", min_length=1, max_length=4_096
    )


class _FactoryMissionFeature(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    feature_id: str = Field(alias="id", min_length=1, max_length=256)
    skill_name: str | None = Field(
        default=None, alias="skillName", min_length=1, max_length=256
    )
    worker_session_ids: tuple[str, ...] = Field(
        default=(), alias="workerSessionIds"
    )

    @field_validator("worker_session_ids")
    @classmethod
    def validate_worker_session_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not session_id or len(session_id) > 512 for session_id in value):
            raise ValueError("Factory worker session ID is invalid")
        if len(value) != len(set(value)):
            raise ValueError("Factory feature repeats a worker session")
        return value


class _FactoryMissionFeatures(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    features: tuple[_FactoryMissionFeature, ...]

    @field_validator("features")
    @classmethod
    def validate_features(
        cls, value: tuple[_FactoryMissionFeature, ...]
    ) -> tuple[_FactoryMissionFeature, ...]:
        identifiers = [feature.feature_id for feature in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Factory Mission repeats a feature")
        return value


def factory_relation_source_digest(droid_binary_digest: str) -> str:
    """Bind the unsupported Mission-file contract to one pinned Droid binary."""

    if not _is_digest(droid_binary_digest):
        raise MissionCorrelationError("Droid binary digest is invalid")
    value = {
        "schema_version": "0.1",
        "source_class": "pinned_factory_mission_files",
        "droid_binary_digest": droid_binary_digest,
        "contract": _FACTORY_RELATION_CONTRACT,
    }
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )

def _configured_role_inventory(
    role_configuration: Mapping[str, Any],
) -> Mapping[str, int]:
    requirements: dict[str, int] = {}
    for role_kind, field_name in (
        ("orchestrator", "count"),
        ("worker", "minimum"),
        ("validator", "count"),
    ):
        role_config = role_configuration.get(role_kind)
        if not isinstance(role_config, Mapping) or field_name not in role_config:
            raise MissionCorrelationError(
                f"{role_kind} role configuration is incomplete"
            )
        value = role_config[field_name]
        minimum = 0 if role_kind == "validator" else 1
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < minimum
        ):
            raise MissionCorrelationError(
                f"{role_kind} role {field_name} is invalid"
            )
        requirements[role_kind] = value
    return requirements


def _secure_read(
    path: Path,
    *,
    required: bool,
    directory_descriptor: int | None = None,
) -> bytes | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise MissionCorrelationError("secure Factory relation reads are unavailable")
    try:
        descriptor = os.open(
            path.name if directory_descriptor is not None else path,
            flags | nofollow,
            dir_fd=directory_descriptor,
        )
    except FileNotFoundError:
        if required:
            raise MissionCorrelationError(f"Factory relation file is missing: {path.name}")
        return None
    except OSError as error:
        raise MissionCorrelationError(
            f"cannot open Factory relation file: {path.name}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size > MAX_CORRELATION_RECORD_BYTES
        ):
            raise MissionCorrelationError(
                f"Factory relation file is unsafe: {path.name}"
            )
        chunks: list[bytes] = []
        remaining = MAX_CORRELATION_RECORD_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1 << 16, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) > MAX_CORRELATION_RECORD_BYTES
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise MissionCorrelationError(
                f"Factory relation file changed during read: {path.name}"
            )
        return payload
    finally:
        os.close(descriptor)


def _parse_json_file(
    path: Path,
    *,
    required: bool,
    directory_descriptor: int | None = None,
) -> Any | None:
    payload = _secure_read(
        path,
        required=required,
        directory_descriptor=directory_descriptor,
    )
    if payload is None:
        return None
    try:
        return json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise MissionCorrelationError(
            f"Factory relation file is invalid: {path.name}"
        ) from error


class PinnedFactoryMissionRelationProducer:
    """Observe Factory 0.197.0 Mission files and admit only corroborated sessions."""

    def __init__(
        self,
        *,
        mission_root: Path,
        project_root: Path,
        droid_binary_digest: str,
        expected_source_digest: str,
        secret: str,
        correlation_id: str,
        role_configuration: Mapping[str, Any],
        clock: Callable[[], float],
        historical_names: frozenset[str] | None = None,
    ) -> None:
        if not secret or not correlation_id:
            raise MissionCorrelationError("live Mission correlation is unbound")
        source_digest = factory_relation_source_digest(droid_binary_digest)
        if source_digest != expected_source_digest:
            raise MissionCorrelationError("Factory relation source binding differs")
        self.mission_root = mission_root.resolve(strict=True)
        self.project_root = project_root.resolve(strict=True)
        self.expected_role_counts = _configured_role_inventory(role_configuration)
        root_metadata = mission_root.lstat()
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if (
            nofollow is None
            or directory is None
            or mission_root.is_symlink()
            or not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(root_metadata.st_mode) & 0o022
        ):
            raise MissionCorrelationError("Factory Mission root is unsafe")
        try:
            root_descriptor = os.open(
                mission_root,
                os.O_RDONLY
                | nofollow
                | directory
                | getattr(os, "O_CLOEXEC", 0),
            )
            opened_metadata = os.fstat(root_descriptor)
            if (
                opened_metadata.st_dev != root_metadata.st_dev
                or opened_metadata.st_ino != root_metadata.st_ino
            ):
                raise MissionCorrelationError("Factory Mission root is not clean")
            current_names = snapshot_factory_mission_names(root_descriptor)
            if historical_names is None:
                historical_names = current_names
            elif current_names != historical_names:
                raise MissionCorrelationError("Factory Mission root is not clean")
            for name in historical_names:
                if not name or len(name) > 512 or Path(name).name != name:
                    raise MissionCorrelationError("Factory Mission directory is unsafe")
        except BaseException:
            if "root_descriptor" in locals():
                os.close(root_descriptor)
            raise
        if self.mission_root == self.project_root or (
            self.project_root in self.mission_root.parents
        ):
            os.close(root_descriptor)
            raise MissionCorrelationError(
                "Factory Mission root must remain outside the repository"
            )
        self._root_descriptor = root_descriptor
        self._historical_names = historical_names
        self._selected_directory: Path | None = None
        self._selected_descriptor: int | None = None
        self._secret = secret
        self._clock = clock
        self._factory_mission_id: str | None = None
        self._raw_relations: dict[str, FactorySessionRelation] = {}
        self._lock = threading.RLock()
        self.binding = MissionCorrelationBinding(
            mission_id=correlation_id,
            source_digest=source_digest,
            registry=MissionCorrelationRegistry(),
            relations=LiveMissionRelations(correlation_id),
            roles=(),
            excluded_session_aliases=frozenset(),
            role_assignments={},
        )

    def refresh(self, *, require_complete: bool = False) -> int:
        """Admit every newly corroborated Factory session."""

        with self._lock:
            admitted_session_ids = {
                session_id
                for session_id, relation in self._raw_relations.items()
                if relation.disposition == "mission_role"
            }
            mission_directory = self._mission_directory()
            if mission_directory is None:
                if require_complete or admitted_session_ids:
                    raise MissionCorrelationError(
                        "Factory Mission relation source disappeared"
                    )
                return 0
            directory_descriptor = self._selected_descriptor
            if directory_descriptor is None:
                raise MissionCorrelationError(
                    "Factory Mission directory descriptor is unavailable"
                )
            state_required = require_complete or bool(admitted_session_ids)
            state_value = _parse_json_file(
                mission_directory / "state.json",
                required=state_required,
                directory_descriptor=directory_descriptor,
            )
            if state_value is None:
                return 0
            try:
                state = _FactoryMissionState.model_validate(state_value)
            except ValueError as error:
                raise MissionCorrelationError(
                    "Factory Mission relation schema is invalid"
                ) from error
            try:
                working_directory = Path(state.working_directory).resolve(strict=True)
            except OSError as error:
                raise MissionCorrelationError(
                    "Factory Mission working directory is unavailable"
                ) from error
            if working_directory != self.project_root:
                raise MissionCorrelationError(
                    "Factory Mission belongs to another workspace"
                )
            if (
                self._factory_mission_id is not None
                and self._factory_mission_id != state.mission_id
            ):
                raise MissionCorrelationError("Factory Mission identity changed")
            self._factory_mission_id = state.mission_id
            admitted = self._allow_orchestrator(
                mission_directory.name, state.mission_id
            )
            features_value = _parse_json_file(
                mission_directory / "features.json",
                required=require_complete,
                directory_descriptor=directory_descriptor,
            )
            progress_payload = _secure_read(
                mission_directory / "progress_log.jsonl",
                required=require_complete,
                directory_descriptor=directory_descriptor,
            )
            if features_value is None or progress_payload is None:
                return admitted
            try:
                features = _FactoryMissionFeatures.model_validate(features_value)
            except ValueError as error:
                raise MissionCorrelationError(
                    "Factory Mission relation schema is invalid"
                ) from error
            selected, started = self._worker_log_relations(progress_payload)
            current_session_ids = {mission_directory.name}
            seen_sessions: set[str] = set()
            corroborated_workers: list[tuple[_FactoryMissionFeature, str, int]] = []
            for feature in features.features:
                for attempt, session_id in enumerate(feature.worker_session_ids, 1):
                    if session_id in seen_sessions:
                        raise MissionCorrelationError(
                            "Factory worker belongs to multiple features"
                        )
                    seen_sessions.add(session_id)
                    pair = (session_id, feature.feature_id)
                    if pair not in selected or pair not in started:
                        continue
                    current_session_ids.add(session_id)
                    corroborated_workers.append((feature, session_id, attempt))
            if not admitted_session_ids.issubset(
                current_session_ids | {mission_directory.name}
            ):
                raise MissionCorrelationError(
                    "Factory Mission relation evidence disappeared"
                )
            for feature, session_id, attempt in corroborated_workers:
                admitted += self._allow_worker(feature, session_id, attempt)
            return admitted


    def require_complete(self) -> Mapping[str, int]:
        """Require the configured live role inventory before release."""

        with self._lock:
            self.refresh(require_complete=True)
            mission_roles = tuple(
                relation
                for relation in self._raw_relations.values()
                if relation.disposition == "mission_role"
            )
            counts = {
                role: sum(relation.role_kind == role for relation in mission_roles)
                for role in ("orchestrator", "worker", "validator")
            }
            expected = self.expected_role_counts
            if counts["orchestrator"] != expected["orchestrator"]:
                raise MissionCorrelationError(
                    "Factory relation source has an invalid orchestrator count"
                )
            if counts["worker"] < expected["worker"]:
                raise MissionCorrelationError(
                    "Factory relation source has too few workers"
                )
            if counts["validator"] < expected["validator"]:
                raise MissionCorrelationError(
                    "Factory relation source has too few validators"
                )
            return counts

    def exclude(
        self,
        session_id: str,
        disposition: Literal["shadow_owned", "same_project_decoy"],
    ) -> None:
        """Record one explicit negative-control identity."""

        if not session_id:
            raise MissionCorrelationError("excluded Factory session is empty")
        with self._lock:
            source_digest = self._relation_digest(
                {"session_id": session_id, "disposition": disposition}
            )
            relation = FactorySessionRelation(
                session_id=session_id,
                disposition=disposition,
                source_digest=source_digest,
                relation_kind="mission_relation",
                confidence="none",
            )
            prior = self._raw_relations.get(session_id)
            if prior is not None and prior != relation:
                raise MissionCorrelationError("Factory session disposition changed")
            self._raw_relations[session_id] = relation
            self.binding.exclude_session(make_alias(self._secret, "session", session_id))

    def snapshot_record(self) -> dict[str, Any]:
        """Return one digest-bound snapshot of all observed Factory relations."""

        with self._lock:
            self.refresh()
            values = tuple(
                sorted(self._raw_relations.values(), key=lambda item: item.session_id)
            )
            mission_roles = tuple(
                relation
                for relation in values
                if relation.disposition == "mission_role"
            )
            observed = {
                role: sum(relation.role_kind == role for relation in mission_roles)
                for role in ("orchestrator", "worker", "validator")
            }
            expected = dict(self.expected_role_counts)
            shortfalls = sorted(
                role for role in expected if observed[role] < expected[role]
            )
            sessions: list[dict[str, Any]] = []
            for relation in values:
                sanitized = relation.model_dump(mode="json")
                sanitized["session_id"] = make_alias(
                    self._secret,
                    "session",
                    relation.session_id,
                )
                if relation.assignment_id is not None:
                    sanitized["assignment_id"] = make_alias(
                        self._secret,
                        "assignment",
                        relation.assignment_id,
                    )
                sessions.append(sanitized)
            value: dict[str, Any] = {
                "schema_version": "0.1",
                "source_class": "factory_mission_relations",
                "mission_id": make_alias(
                    self._secret,
                    "factory-mission",
                    self._factory_mission_id or "",
                ),
                "observed_at": int(self._clock()),
                "sessions": sessions,
                "role_inventory": {
                    "expected": expected,
                    "observed": observed,
                    "shortfalls": shortfalls,
                    "complete": not shortfalls,
                },
            }
            value["record_digest"] = correlation_record_digest(value)
            return value

    def finalize_record(self) -> FactoryMissionCorrelationRecord:
        """Freeze observed relation and required negative-control evidence."""

        try:
            return FactoryMissionCorrelationRecord.model_validate(
                self.snapshot_record()
            )
        except ValueError as error:
            raise MissionCorrelationError(
                "Factory relation record is invalid"
            ) from error

    def close(self) -> None:
        """Close the retained Factory relation directory descriptors."""

        with self._lock:
            if self._selected_descriptor is not None:
                os.close(self._selected_descriptor)
                self._selected_descriptor = None
            if self._root_descriptor >= 0:
                os.close(self._root_descriptor)
                self._root_descriptor = -1

    def _mission_directory(self) -> Path | None:
        if self._root_descriptor < 0:
            raise MissionCorrelationError("Factory Mission root descriptor is closed")
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory = getattr(os, "O_DIRECTORY", 0)
        try:
            current_root_descriptor = os.open(
                self.mission_root,
                os.O_RDONLY
                | nofollow
                | directory
                | getattr(os, "O_CLOEXEC", 0),
            )
            root_path_metadata = os.fstat(current_root_descriptor)
            root_descriptor_metadata = os.fstat(self._root_descriptor)
        except OSError as error:
            raise MissionCorrelationError(
                "Factory Mission root changed"
            ) from error
        finally:
            if "current_root_descriptor" in locals():
                os.close(current_root_descriptor)
        if (
            root_path_metadata.st_dev != root_descriptor_metadata.st_dev
            or root_path_metadata.st_ino != root_descriptor_metadata.st_ino
        ):
            raise MissionCorrelationError("Factory Mission root changed")
        current_names = snapshot_factory_mission_names(self._root_descriptor)
        new_names = tuple(
            sorted(name for name in current_names if name not in self._historical_names)
        )
        if self._selected_directory is not None:
            selected_name = self._selected_directory.name
            extras = tuple(name for name in new_names if name != selected_name)
            if extras or selected_name not in current_names:
                raise MissionCorrelationError(
                    "Factory Mission root has ambiguous active Missions"
                    if extras
                    else "Factory Mission directory changed"
                )
            name = selected_name
        else:
            if not new_names:
                return None
            if len(new_names) != 1:
                raise MissionCorrelationError(
                    "Factory Mission root has ambiguous active Missions"
                )
            name = new_names[0]
        if not name or len(name) > 512 or Path(name).name != name:
            raise MissionCorrelationError("Factory Mission directory is unsafe")
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY
                | nofollow
                | directory
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=self._root_descriptor,
            )
            metadata = os.fstat(descriptor)
        except OSError as error:
            raise MissionCorrelationError(
                "Factory Mission directory is unsafe"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            os.close(descriptor)
            raise MissionCorrelationError("Factory Mission directory is unsafe")
        selected = self.mission_root / name
        if self._selected_directory is None:
            self._selected_directory = selected
            self._selected_descriptor = descriptor
        else:
            prior = self._selected_descriptor
            assert prior is not None
            prior_metadata = os.fstat(prior)
            os.close(descriptor)
            if (
                selected != self._selected_directory
                or metadata.st_dev != prior_metadata.st_dev
                or metadata.st_ino != prior_metadata.st_ino
            ):
                raise MissionCorrelationError("Factory Mission directory changed")
        return selected

    def _allow_orchestrator(self, session_id: str, factory_mission_id: str) -> int:
        return self._allow_role(
            session_id=session_id,
            role_id="orchestrator",
            role_kind="orchestrator",
            assignment_id=factory_mission_id,
            relation_kind="mission_relation",
            evidence={
                "factory_mission_id": factory_mission_id,
                "base_session_id": session_id,
                "working_directory": str(self.project_root),
                "role": "orchestrator",
            },
        )

    def _allow_worker(
        self,
        feature: _FactoryMissionFeature,
        session_id: str,
        attempt: int,
    ) -> int:
        role_kind: Literal["worker", "validator"] = (
            "validator"
            if feature.skill_name in FACTORY_VALIDATOR_SKILLS
            else "worker"
        )
        feature_digest = hashlib.sha256(feature.feature_id.encode("utf-8")).hexdigest()[
            :16
        ]
        role_id = f"{role_kind}:{feature_digest}:{attempt}"
        return self._allow_role(
            session_id=session_id,
            role_id=role_id,
            role_kind=role_kind,
            assignment_id=feature.feature_id,
            relation_kind="assignment",
            evidence={
                "factory_mission_id": self._factory_mission_id,
                "base_session_id": self._selected_directory.name,
                "feature_id": feature.feature_id,
                "skill_name": feature.skill_name,
                "worker_session_id": session_id,
                "attempt": attempt,
                "role": role_kind,
                "corroboration": (
                    "features.workerSessionIds",
                    "progress.worker_selected_feature",
                    "progress.worker_started",
                ),
            },
        )

    def _allow_role(
        self,
        *,
        session_id: str,
        role_id: str,
        role_kind: Literal["orchestrator", "worker", "validator"],
        assignment_id: str,
        relation_kind: Literal["mission_relation", "assignment"],
        evidence: Mapping[str, Any],
    ) -> int:
        source_digest = self._relation_digest(evidence)
        raw_relation = FactorySessionRelation(
            session_id=session_id,
            disposition="mission_role",
            role_id=role_id,
            role_kind=role_kind,
            assignment_id=assignment_id,
            source_digest=source_digest,
            relation_kind=relation_kind,
            confidence="high",
            corroborating_role_ids=(role_id,),
        )
        prior = self._raw_relations.get(session_id)
        if prior is not None:
            if prior != raw_relation:
                raise MissionCorrelationError("Factory session relation changed")
            return 0
        alias = make_alias(self._secret, "session", session_id)
        relation = MissionRelation(
            session_alias=alias,
            mission_id=self.binding.mission_id,
            role_id=role_id,
            assignment_id=assignment_id,
            source_digest=source_digest,
            corroborating_role_ids=(role_id,),
            relation_kind=relation_kind,
        )
        self.binding.allow_relation(
            relation=relation,
            role=ConfiguredRole(role_id=role_id, kind=role_kind),
            evidence_digest=source_digest,
        )
        self._raw_relations[session_id] = raw_relation
        return 1

    def _relation_digest(self, evidence: Mapping[str, Any]) -> str:
        return hashlib.sha256(
            canonical_json(
                {
                    "source_digest": self.binding.source_digest,
                    "evidence": dict(evidence),
                }
            )
        ).hexdigest()

    @staticmethod
    def _worker_log_relations(
        payload: bytes,
    ) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
        selected: set[tuple[str, str]] = set()
        started: set[tuple[str, str]] = set()
        try:
            lines = payload.decode("utf-8").splitlines()
        except UnicodeError as error:
            raise MissionCorrelationError(
                "Factory Mission progress log is invalid"
            ) from error
        for line in lines:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as error:
                raise MissionCorrelationError(
                    "Factory Mission progress log is invalid"
                ) from error
            if not isinstance(entry, Mapping):
                raise MissionCorrelationError(
                    "Factory Mission progress entry is invalid"
                )
            event_type = entry.get("type")
            if event_type not in {"worker_selected_feature", "worker_started"}:
                continue
            session_id = entry.get("workerSessionId")
            feature_id = entry.get("featureId")
            if (
                not isinstance(session_id, str)
                or not session_id
                or len(session_id) > 512
                or not isinstance(feature_id, str)
                or not feature_id
                or len(feature_id) > 256
            ):
                raise MissionCorrelationError(
                    "Factory Mission worker progress is invalid"
                )
            target = selected if event_type == "worker_selected_feature" else started
            target.add((session_id, feature_id))
        selected_by_session: dict[str, set[str]] = {}
        started_by_session: dict[str, set[str]] = {}
        for target, grouped in (
            (selected, selected_by_session),
            (started, started_by_session),
        ):
            for session_id, feature_id in target:
                grouped.setdefault(session_id, set()).add(feature_id)
            if any(len(feature_ids) != 1 for feature_ids in grouped.values()):
                raise MissionCorrelationError(
                    "Factory Mission worker assignment is ambiguous"
                )
        for session_id in selected_by_session.keys() & started_by_session.keys():
            if selected_by_session[session_id] != started_by_session[session_id]:
                raise MissionCorrelationError(
                    "Factory Mission worker assignment changed during launch"
                )
        return selected, started

class FactoryMissionCorrelationAdapter:
    """Load host-held Factory relations and derive no raw persistent identity."""

    def __init__(
        self,
        record: FactoryMissionCorrelationRecord,
        *,
        expected_role_counts: Mapping[str, int],
    ) -> None:
        counts = {
            role_kind: sum(
                session.disposition == "mission_role"
                and session.role_kind == role_kind
                for session in record.sessions
            )
            for role_kind in ("orchestrator", "worker", "validator")
        }
        if counts["orchestrator"] != expected_role_counts["orchestrator"]:
            raise MissionCorrelationError(
                "Factory relation record has an invalid orchestrator count"
            )
        if counts["worker"] < expected_role_counts["worker"]:
            raise MissionCorrelationError("Factory relation record has too few workers")
        if counts["validator"] != expected_role_counts["validator"]:
            raise MissionCorrelationError(
                "Factory relation record has an invalid validator count"
            )
        self.record = record

    @property
    def digest(self) -> str:
        return self.record.record_digest

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        expected_digest: str,
        role_configuration: Mapping[str, Any],
    ) -> FactoryMissionCorrelationAdapter:
        try:
            payload = _secure_read(path, required=True)
        except MissionCorrelationError:
            raise
        if payload is None:
            raise MissionCorrelationError("cannot read Factory relation record")
        try:
            value = json.loads(payload)
            record = FactoryMissionCorrelationRecord.model_validate(value)
        except (UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise MissionCorrelationError("Factory relation record is invalid") from error
        if record.record_digest != expected_digest:
            raise MissionCorrelationError("Factory relation preflight binding differs")
        requirements = _configured_role_inventory(role_configuration)
        return cls(record, expected_role_counts=requirements)

    def materialize(self, secret: str) -> MissionCorrelationBinding:
        """Alias raw Factory identities only after the private run secret exists."""

        if not secret:
            raise MissionCorrelationError("run secret is unavailable")
        allowed: dict[str, str] = {}
        excluded: set[str] = set()
        relations: list[MissionRelation] = []
        roles: list[ConfiguredRole] = []
        assignments: dict[str, str] = {}
        for session in self.record.sessions:
            alias = make_alias(secret, "session", session.session_id)
            if session.disposition != "mission_role":
                excluded.add(alias)
                continue
            assert session.role_id is not None
            assert session.role_kind is not None
            assert session.assignment_id is not None
            allowed[alias] = session.source_digest
            assignments[session.role_id] = alias
            roles.append(
                ConfiguredRole(role_id=session.role_id, kind=session.role_kind)
            )
            relations.append(
                MissionRelation(
                    session_alias=alias,
                    mission_id=self.record.mission_id,
                    role_id=session.role_id,
                    assignment_id=session.assignment_id,
                    source_digest=session.source_digest,
                    corroborating_role_ids=session.corroborating_role_ids,
                    relation_kind=session.relation_kind,
                )
            )
        registry = MissionCorrelationRegistry(
            allowed=allowed,
            excluded=frozenset(excluded),
        )
        return MissionCorrelationBinding(
            mission_id=self.record.mission_id,
            source_digest=self.record.record_digest,
            registry=registry,
            relations=FrozenMissionRelations(
                self.record.mission_id,
                tuple(sorted(relations, key=lambda item: item.session_alias)),
            ),
            roles=tuple(sorted(roles, key=lambda item: item.role_id)),
            excluded_session_aliases=frozenset(excluded),
            role_assignments=dict(sorted(assignments.items())),
        )
