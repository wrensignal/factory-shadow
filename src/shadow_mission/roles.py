"""Fail-closed Mission role attribution from authoritative relations."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal, Mapping, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .protocol import HookEnvelope

RoleKind = Literal["orchestrator", "worker", "validator"]
RoleConfidence = Literal["high", "low", "none"]
RoleStatus = Literal["assigned", "candidate", "ignored", "quarantined"]


class RoleMappingError(ValueError):
    """Frozen role configuration or evidence is invalid."""


class ConfiguredRole(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role_id: str = Field(min_length=1)
    kind: RoleKind
    markers: tuple[str, ...] = ()

    @field_validator("markers")
    @classmethod
    def validate_markers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not marker or len(marker) > 256 for marker in value):
            raise ValueError("role markers must be bounded non-empty strings")
        return value


class MissionRelation(BaseModel):
    """One Factory-side session relation frozen outside hook prompt text."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    session_alias: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    role_id: str = Field(min_length=1)
    assignment_id: str = Field(min_length=1)
    source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    corroborating_role_ids: tuple[str, ...] = ()
    relation_kind: Literal["mission_relation", "assignment"]


@dataclass(frozen=True)
class RoleDecision:
    session_alias: str
    role_id: str | None
    kind: Literal["orchestrator", "worker", "validator", "unknown"]
    confidence: RoleConfidence
    status: RoleStatus
    reason: str
    evidence_digests: tuple[str, ...]


class MissionRelations(Protocol):
    """Lookup contract shared by frozen and live Factory relation inventories."""

    mission_id: str

    @property
    def digest(self) -> str: ...

    def get(self, session_alias: str) -> MissionRelation | None: ...


class FrozenMissionRelations:
    """Immutable externally observed relation inventory for one Mission."""

    def __init__(self, mission_id: str, relations: tuple[MissionRelation, ...]) -> None:
        if not mission_id:
            raise RoleMappingError("mission identity must not be empty")
        by_session: dict[str, MissionRelation] = {}
        for relation in relations:
            if relation.mission_id != mission_id:
                raise RoleMappingError("relation belongs to another Mission")
            if relation.session_alias in by_session:
                raise RoleMappingError("session has duplicate authoritative relations")
            by_session[relation.session_alias] = relation
        self.mission_id = mission_id
        self._by_session = by_session
        self._digest = _relations_digest(relations)

    @property
    def digest(self) -> str:
        return self._digest

    def get(self, session_alias: str) -> MissionRelation | None:
        return self._by_session.get(session_alias)


class LiveMissionRelations:
    """Append-only Factory relations discovered during one active Mission."""

    def __init__(self, mission_id: str) -> None:
        if not mission_id:
            raise RoleMappingError("mission identity must not be empty")
        self.mission_id = mission_id
        self._by_session: dict[str, MissionRelation] = {}

    @property
    def digest(self) -> str:
        return _relations_digest(tuple(self._by_session.values()))

    def allow(self, relation: MissionRelation) -> None:
        if relation.mission_id != self.mission_id:
            raise RoleMappingError("relation belongs to another Mission")
        prior = self._by_session.get(relation.session_alias)
        if prior is not None and prior != relation:
            raise RoleMappingError("session relation changed")
        self._by_session[relation.session_alias] = relation

    def get(self, session_alias: str) -> MissionRelation | None:
        return self._by_session.get(session_alias)


def _relations_digest(relations: tuple[MissionRelation, ...]) -> str:
    digest_input = "\n".join(
        relation.model_dump_json(exclude_none=False)
        for relation in sorted(relations, key=lambda item: item.session_alias)
    )
    return hashlib.sha256(digest_input.encode("utf-8")).hexdigest()

class RoleMapper:
    """Assign at most one high-confidence session to each configured role."""

    def __init__(
        self,
        roles: tuple[ConfiguredRole, ...],
        relations: MissionRelations,
        *,
        fallback_mode: bool = False,
        excluded_session_aliases: frozenset[str] = frozenset(),
    ) -> None:
        role_map: dict[str, ConfiguredRole] = {}
        marker_map: dict[str, str] = {}
        for role in roles:
            if role.role_id in role_map:
                raise RoleMappingError("configured role ID is duplicated")
            if fallback_mode and role.kind != "worker":
                continue
            role_map[role.role_id] = role
            for marker in role.markers:
                if marker in marker_map:
                    raise RoleMappingError("role marker is ambiguous")
                marker_map[marker] = role.role_id
        self.roles = role_map
        self.relations = relations
        self.fallback_mode = fallback_mode
        self.live_validation_overlap = not fallback_mode
        self.excluded_session_aliases = excluded_session_aliases
        self._marker_map = marker_map
        self._assigned_by_role: dict[str, str] = {}
        self._assigned_by_session: dict[str, str] = {}
        self._quarantined_sessions: set[str] = set()
        self._decisions: list[RoleDecision] = []

    def register_role(self, role: ConfiguredRole) -> None:
        """Add one Factory-derived role before its first hook event."""

        prior = self.roles.get(role.role_id)
        if prior is not None and prior != role:
            raise RoleMappingError("configured role ID changed")
        for marker in role.markers:
            marker_role = self._marker_map.get(marker)
            if marker_role is not None and marker_role != role.role_id:
                raise RoleMappingError("role marker is ambiguous")
        self.roles[role.role_id] = role
        for marker in role.markers:
            self._marker_map[marker] = role.role_id

    def exclude_session(self, session_alias: str) -> None:
        if not session_alias:
            raise RoleMappingError("excluded session alias must not be empty")
        self.excluded_session_aliases = frozenset(
            (*self.excluded_session_aliases, session_alias)
        )

    def observe(self, envelope: HookEnvelope) -> RoleDecision:
        if envelope.session_alias in self.excluded_session_aliases:
            return self._record(
                envelope.session_alias,
                None,
                "unknown",
                "none",
                "ignored",
                "session is Shadow-owned",
                (),
            )
        if envelope.hook_event_name not in {"SessionStart", "UserPromptSubmit"}:
            return self._observe_later_event(envelope)
        if envelope.session_alias in self._quarantined_sessions:
            return self._record(
                envelope.session_alias,
                None,
                "unknown",
                "none",
                "quarantined",
                "session was already quarantined",
                (),
            )

        prompt = envelope.payload.get("prompt")
        prompt_text = prompt if isinstance(prompt, str) else ""
        marker_roles = self._marker_roles(prompt_text)
        relation = self.relations.get(envelope.session_alias)

        if relation is None:
            if not marker_roles:
                return self._record(
                    envelope.session_alias,
                    None,
                    "unknown",
                    "none",
                    "ignored",
                    "no authoritative relation or role marker",
                    (),
                )
            if len(marker_roles) != 1:
                return self._quarantine(
                    envelope.session_alias,
                    None,
                    "ambiguous inherited role markers",
                    (),
                )
            role_id = next(iter(marker_roles))
            if role_id in self._assigned_by_role:
                return self._quarantine(
                    envelope.session_alias,
                    role_id,
                    "inherited marker duplicates an assigned role",
                    (),
                )
            role = self.roles.get(role_id)
            return self._record(
                envelope.session_alias,
                role_id,
                role.kind if role else "unknown",
                "low",
                "candidate",
                "static marker lacks authoritative relation",
                (),
            )

        role = self.roles.get(relation.role_id)
        if role is None:
            return self._quarantine(
                envelope.session_alias,
                relation.role_id,
                "authoritative relation names an unavailable role",
                (relation.source_digest,),
            )
        if marker_roles and marker_roles != {relation.role_id}:
            return self._quarantine(
                envelope.session_alias,
                relation.role_id,
                "prompt markers disagree with authoritative relation",
                (relation.source_digest,),
            )
        corroborated = (
            relation.role_id in relation.corroborating_role_ids
            or relation.role_id in marker_roles
        )
        if not corroborated:
            return self._record(
                envelope.session_alias,
                relation.role_id,
                role.kind,
                "low",
                "candidate",
                "authoritative relation lacks an agreeing signal",
                (relation.source_digest,),
            )

        prior_role = self._assigned_by_session.get(envelope.session_alias)
        if prior_role is not None and prior_role != relation.role_id:
            return self._quarantine(
                envelope.session_alias,
                relation.role_id,
                "one session claimed multiple roles",
                (relation.source_digest,),
            )
        prior_session = self._assigned_by_role.get(relation.role_id)
        if prior_session is not None and prior_session != envelope.session_alias:
            return self._quarantine(
                envelope.session_alias,
                relation.role_id,
                "configured role already has a session",
                (relation.source_digest,),
            )
        self._assigned_by_role[relation.role_id] = envelope.session_alias
        self._assigned_by_session[envelope.session_alias] = relation.role_id
        return self._record(
            envelope.session_alias,
            relation.role_id,
            role.kind,
            "high",
            "assigned",
            "authoritative relation and corroborating signal agree",
            (relation.source_digest,),
        )

    def assignments(self) -> Mapping[str, str]:
        return dict(sorted(self._assigned_by_role.items()))

    def decisions(self) -> tuple[RoleDecision, ...]:
        return tuple(self._decisions)

    def can_target(self, session_alias: str) -> bool:
        return (
            session_alias in self._assigned_by_session
            and session_alias not in self._quarantined_sessions
        )

    def _observe_later_event(self, envelope: HookEnvelope) -> RoleDecision:
        if envelope.session_alias in self._quarantined_sessions:
            return self._record(
                envelope.session_alias,
                None,
                "unknown",
                "none",
                "quarantined",
                "session was already quarantined",
                (),
            )
        prior_role = self._assigned_by_session.get(envelope.session_alias)
        if prior_role is not None:
            role = self.roles.get(prior_role)
            return self._record(
                envelope.session_alias,
                prior_role,
                role.kind if role else "unknown",
                "high",
                "assigned",
                "assigned role persists onto later tool events",
                (),
            )
        relation = self.relations.get(envelope.session_alias)
        if relation is None:
            return self._record(
                envelope.session_alias,
                None,
                "unknown",
                "none",
                "ignored",
                "event cannot claim a role",
                (),
            )
        role = self.roles.get(relation.role_id)
        if role is None:
            return self._quarantine(
                envelope.session_alias,
                relation.role_id,
                "authoritative relation names an unavailable role",
                (relation.source_digest,),
            )
        if relation.role_id not in relation.corroborating_role_ids:
            return self._record(
                envelope.session_alias,
                relation.role_id,
                role.kind,
                "low",
                "candidate",
                "authoritative relation lacks an agreeing signal",
                (relation.source_digest,),
            )
        prior_session = self._assigned_by_role.get(relation.role_id)
        if prior_session is not None and prior_session != envelope.session_alias:
            return self._quarantine(
                envelope.session_alias,
                relation.role_id,
                "configured role already has a session",
                (relation.source_digest,),
            )
        self._assigned_by_role[relation.role_id] = envelope.session_alias
        self._assigned_by_session[envelope.session_alias] = relation.role_id
        return self._record(
            envelope.session_alias,
            relation.role_id,
            role.kind,
            "high",
            "assigned",
            "authoritative relation persists onto later tool events",
            (relation.source_digest,),
        )

    def _marker_roles(self, prompt: str) -> set[str]:
        matches: set[str] = set()
        for marker, role_id in self._marker_map.items():
            if re.search(rf"(?<![A-Za-z0-9_-]){re.escape(marker)}(?![A-Za-z0-9_-])", prompt):
                matches.add(role_id)
        return matches

    def _quarantine(
        self,
        session_alias: str,
        role_id: str | None,
        reason: str,
        evidence_digests: tuple[str, ...],
    ) -> RoleDecision:
        self._quarantined_sessions.add(session_alias)
        role = self.roles.get(role_id) if role_id else None
        return self._record(
            session_alias,
            role_id,
            role.kind if role else "unknown",
            "none",
            "quarantined",
            reason,
            evidence_digests,
        )

    def _record(
        self,
        session_alias: str,
        role_id: str | None,
        kind: Literal["orchestrator", "worker", "validator", "unknown"],
        confidence: RoleConfidence,
        status: RoleStatus,
        reason: str,
        evidence_digests: tuple[str, ...],
    ) -> RoleDecision:
        decision = RoleDecision(
            session_alias=session_alias,
            role_id=role_id,
            kind=kind,
            confidence=confidence,
            status=status,
            reason=reason,
            evidence_digests=evidence_digests,
        )
        self._decisions.append(decision)
        return decision
