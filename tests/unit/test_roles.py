from __future__ import annotations

import hashlib

from shadow_mission.protocol import HookEnvelope
from shadow_mission.roles import (
    ConfiguredRole,
    FrozenMissionRelations,
    MissionRelation,
    RoleMapper,
)

ROLES = (
    ConfiguredRole(role_id="orchestrator", kind="orchestrator", markers=("ROLE_ORCH",)),
    ConfiguredRole(role_id="worker-a", kind="worker", markers=("ROLE_WORKER_A",)),
    ConfiguredRole(role_id="worker-b", kind="worker", markers=("ROLE_WORKER_B",)),
    ConfiguredRole(role_id="validator", kind="validator", markers=("ROLE_VALIDATOR",)),
)


def relation(
    session_alias: str,
    role_id: str,
    *,
    corroborated: bool = True,
) -> MissionRelation:
    return MissionRelation(
        session_alias=session_alias,
        mission_id="mission-1",
        role_id=role_id,
        assignment_id=f"assignment-{session_alias}",
        source_digest=hashlib.sha256(session_alias.encode()).hexdigest(),
        corroborating_role_ids=(role_id,) if corroborated else (),
        relation_kind="mission_relation",
    )


def event(
    session_alias: str,
    prompt: str,
    *,
    hook_event_name: str = "SessionStart",
) -> HookEnvelope:
    return HookEnvelope(provenance_status="untrusted_provenance",
    redaction_status="clean",
    event_id=f"event-{session_alias}-{hook_event_name}",
    source_fingerprint=f"source-{session_alias}",
    run_id="run-1",
    session_alias=session_alias,
    transcript_alias=f"transcript-{session_alias}",
    hook_event_name=hook_event_name, observed_at=1, message_digest="d" * 64, payload={"prompt": prompt},)


def mapper(*relations: MissionRelation, fallback: bool = False) -> RoleMapper:
    return RoleMapper(
        ROLES,
        FrozenMissionRelations("mission-1", tuple(relations)),
        fallback_mode=fallback,
    )


def test_authoritative_relation_plus_agreeing_signal_assigns_high_confidence() -> None:
    roles = mapper(relation("session-a", "worker-a"))

    decision = roles.observe(event("session-a", "Initial task"))

    assert decision.status == "assigned"
    assert decision.confidence == "high"
    assert roles.assignments() == {"worker-a": "session-a"}
    assert roles.can_target("session-a") is True


def test_static_marker_alone_is_low_confidence_and_cannot_target() -> None:
    roles = mapper()

    decision = roles.observe(event("session-decoy", "Do work ROLE_WORKER_A"))

    assert decision.status == "candidate"
    assert decision.confidence == "low"
    assert roles.assignments() == {}
    assert roles.can_target("session-decoy") is False


def test_inherited_marker_duplicate_is_quarantined_without_replacing_first() -> None:
    roles = mapper(relation("session-real", "worker-a"))
    roles.observe(event("session-real", "Worker task"))

    duplicate = roles.observe(event("session-inherited", "Inherited ROLE_WORKER_A"))

    assert duplicate.status == "quarantined"
    assert roles.assignments() == {"worker-a": "session-real"}
    assert roles.can_target("session-inherited") is False


def test_authoritative_duplicate_and_disagreeing_markers_are_quarantined() -> None:
    roles = mapper(
        relation("session-first", "worker-a"),
        relation("session-second", "worker-a"),
        relation("session-third", "worker-b"),
    )
    roles.observe(event("session-first", "Worker task"))

    duplicate = roles.observe(event("session-second", "Worker task"))
    ambiguous = roles.observe(
        event("session-third", "ROLE_WORKER_A and ROLE_WORKER_B")
    )

    assert duplicate.status == "quarantined"
    assert ambiguous.status == "quarantined"
    assert roles.assignments() == {"worker-a": "session-first"}


def test_later_tool_event_assigns_from_authoritative_relation() -> None:
    roles = mapper(relation("session-a", "worker-a"))

    decision = roles.observe(
        event("session-a", "Worker task", hook_event_name="PostToolUse")
    )

    assert decision.status == "assigned"
    assert decision.confidence == "high"
    assert roles.assignments() == {"worker-a": "session-a"}
    assert roles.can_target("session-a") is True


def test_later_tool_event_persists_assigned_role() -> None:
    roles = mapper(relation("session-a", "worker-a"))
    roles.observe(event("session-a", "[shadow-worker-a] start"))

    decision = roles.observe(
        event("session-a", "later tool", hook_event_name="PostToolUse")
    )

    assert decision.status == "assigned"
    assert decision.reason == "assigned role persists onto later tool events"
    assert roles.assignments() == {"worker-a": "session-a"}


def test_later_tool_event_without_relation_cannot_claim_from_markers() -> None:
    roles = mapper()

    decision = roles.observe(
        event("session-a", "[shadow-worker-a] Worker task", hook_event_name="PostToolUse")
    )

    assert decision.status == "ignored"
    assert roles.assignments() == {}


def test_fallback_maps_workers_only_and_disables_validation_overlap() -> None:
    roles = mapper(
        relation("session-a", "worker-a"),
        relation("session-v", "validator"),
        fallback=True,
    )

    worker = roles.observe(event("session-a", "Worker task"))
    validator = roles.observe(event("session-v", "Validation task"))

    assert worker.status == "assigned"
    assert validator.status == "quarantined"
    assert roles.live_validation_overlap is False
    assert roles.assignments() == {"worker-a": "session-a"}


def test_shadow_owned_session_is_excluded_even_with_authoritative_relation() -> None:
    relations = FrozenMissionRelations(
        "mission-1", (relation("session-internal", "worker-a"),)
    )
    roles = RoleMapper(
        ROLES,
        relations,
        excluded_session_aliases=frozenset({"session-internal"}),
    )

    decision = roles.observe(event("session-internal", "Worker task"))

    assert decision.status == "ignored"
    assert roles.assignments() == {}
