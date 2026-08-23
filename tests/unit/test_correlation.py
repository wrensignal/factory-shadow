from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadow_mission.auth import generate_run_secret, make_alias
from shadow_mission.correlation import (
    FactoryMissionCorrelationAdapter,
    FactoryMissionCorrelationWrapper,
    MissionCorrelationError,
    correlation_record_digest,
    correlation_wrapper_digest,
)
from shadow_mission.protocol import HookEnvelope


def relation_record(*, duplicate: bool = False, low_confidence: bool = False) -> dict:
    sessions = [
        {
            "session_id": "factory-orchestrator",
            "disposition": "mission_role",
            "role_id": "orchestrator",
            "role_kind": "orchestrator",
            "assignment_id": "assignment-orchestrator",
            "source_digest": "1" * 64,
            "relation_kind": "mission_relation",
            "confidence": "high",
            "corroborating_role_ids": ["orchestrator"],
        },
        {
            "session_id": "factory-worker-a",
            "disposition": "mission_role",
            "role_id": "worker-a",
            "role_kind": "worker",
            "assignment_id": "assignment-worker-a",
            "source_digest": "2" * 64,
            "relation_kind": "assignment",
            "confidence": "low" if low_confidence else "high",
            "corroborating_role_ids": ["worker-a"],
        },
        {
            "session_id": "factory-worker-b",
            "disposition": "mission_role",
            "role_id": "worker-b",
            "role_kind": "worker",
            "assignment_id": "assignment-worker-b",
            "source_digest": "3" * 64,
            "relation_kind": "assignment",
            "confidence": "high",
            "corroborating_role_ids": ["worker-b"],
        },
        {
            "session_id": "factory-validator",
            "disposition": "mission_role",
            "role_id": "validator",
            "role_kind": "validator",
            "assignment_id": "assignment-validator",
            "source_digest": "4" * 64,
            "relation_kind": "mission_relation",
            "confidence": "high",
            "corroborating_role_ids": ["validator"],
        },
        {
            "session_id": "shadow-probe",
            "disposition": "shadow_owned",
            "role_id": None,
            "role_kind": None,
            "assignment_id": None,
            "source_digest": "5" * 64,
            "relation_kind": "mission_relation",
            "confidence": "none",
            "corroborating_role_ids": [],
        },
        {
            "session_id": "same-project-decoy",
            "disposition": "same_project_decoy",
            "role_id": None,
            "role_kind": None,
            "assignment_id": None,
            "source_digest": "6" * 64,
            "relation_kind": "mission_relation",
            "confidence": "none",
            "corroborating_role_ids": [],
        },
    ]
    if duplicate:
        sessions.append({**sessions[1], "session_id": "factory-worker-duplicate"})
    value = {
        "schema_version": "0.1",
        "source_class": "factory_mission_relations",
        "mission_id": "mission-authoritative",
        "observed_at": 100,
        "sessions": sessions,
        "role_inventory": {
            "expected": {
                "orchestrator": 1,
                "worker": 2,
                "validator": 1,
            },
            "observed": {
                "orchestrator": 1,
                "worker": 2,
                "validator": 1,
            },
            "shortfalls": [],
            "complete": True,
        },
    }
    value["record_digest"] = correlation_record_digest(value)
    return value


def correlation_wrapper() -> dict:
    record = relation_record()
    value = {
        "schema_version": "0.1",
        "source_digest": "7" * 64,
        "mission_id": "run-1",
        "record": record,
        "role_counts": record["role_inventory"]["observed"],
        "role_assignments": {
            session["role_id"]: session["session_id"]
            for session in record["sessions"]
            if session["disposition"] == "mission_role"
        },
    }
    value["record_digest"] = correlation_wrapper_digest(value)
    return value


def write_record(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def load(
    path: Path,
    value: dict,
    *,
    validator_count: int = 1,
) -> FactoryMissionCorrelationAdapter:
    write_record(path, value)
    return FactoryMissionCorrelationAdapter.load(
        path,
        expected_digest=value["record_digest"],
        role_configuration={
            "orchestrator": {"count": 1},
            "worker": {"minimum": 2},
            "validator": {"count": validator_count},
        },
    )


def envelope(session_alias: str) -> HookEnvelope:
    return HookEnvelope(provenance_status="hook_authenticated",
    redaction_status="clean",
    event_id="event-1",
    source_fingerprint="source-1",
    run_id="run-1",
    session_alias=session_alias,
    transcript_alias="transcript-1",
    hook_event_name="SessionStart", observed_at=1, message_digest="d" * 64, payload={},)


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value.pop("record_digest"),
        lambda value: value["role_assignments"].update({"worker-a": "other-session"}),
        lambda value: value.update({"factory_session_id": "raw-session"}),
    ),
)
def test_correlation_wrapper_binds_exact_content(mutation) -> None:
    value = correlation_wrapper()
    mutation(value)
    if "record_digest" in value:
        value["record_digest"] = correlation_wrapper_digest(value)

    with pytest.raises(ValueError):
        FactoryMissionCorrelationWrapper.model_validate(value)


def test_adapter_materializes_exact_registry_and_role_relations(tmp_path: Path) -> None:
    adapter = load(tmp_path / "relations.json", relation_record())
    secret = generate_run_secret()

    binding = adapter.materialize(secret)

    worker_alias = make_alias(secret, "session", "factory-worker-a")
    assert binding.registry.accepts(envelope(worker_alias)) is True
    assert binding.role_assignments["worker-a"] == worker_alias
    assert binding.relations.get(worker_alias) is not None
    assert binding.relations.get(worker_alias).role_id == "worker-a"
    assert {role.kind for role in binding.roles} == {
        "orchestrator",
        "worker",
        "validator",
    }


def test_adapter_accepts_configured_zero_validators(tmp_path: Path) -> None:
    value = relation_record()
    value["sessions"] = [
        session
        for session in value["sessions"]
        if session["role_kind"] != "validator"
    ]
    value["role_inventory"]["expected"]["validator"] = 0
    value["role_inventory"]["observed"]["validator"] = 0
    value["record_digest"] = correlation_record_digest(value)

    adapter = load(
        tmp_path / "relations.json",
        value,
        validator_count=0,
    )
    binding = adapter.materialize(generate_run_secret())

    assert {role.kind for role in binding.roles} == {
        "orchestrator",
        "worker",
    }


def test_adapter_excludes_shadow_sessions_and_same_project_decoy(tmp_path: Path) -> None:
    adapter = load(tmp_path / "relations.json", relation_record())
    secret = generate_run_secret()

    binding = adapter.materialize(secret)

    for raw_id in ("shadow-probe", "same-project-decoy"):
        alias = make_alias(secret, "session", raw_id)
        assert alias in binding.excluded_session_aliases
        assert binding.registry.accepts(envelope(alias)) is False


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(record_digest="0" * 64), "invalid"),
        (
            lambda value: value["sessions"][1].update(confidence="low"),
            "invalid",
        ),
        (
            lambda value: value["sessions"].append(
                {**value["sessions"][1], "session_id": "duplicate-worker"}
            ),
            "invalid",
        ),
        (
            lambda value: value.update(
                sessions=[
                    session
                    for session in value["sessions"]
                    if session["disposition"] != "same_project_decoy"
                ]
            ),
            "invalid",
        ),
    ],
)
def test_adapter_rejects_untrusted_or_ambiguous_identity(
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    value = relation_record()
    mutation(value)
    if value["record_digest"] != "0" * 64:
        value["record_digest"] = correlation_record_digest(value)
    path = tmp_path / "relations.json"
    write_record(path, value)

    with pytest.raises(MissionCorrelationError, match=message):
        FactoryMissionCorrelationAdapter.load(
            path,
            expected_digest=value["record_digest"],
            role_configuration={
                "orchestrator": {"count": 1},
                "worker": {"minimum": 2},
                "validator": {"count": 1},
            },
        )


def test_marker_text_cannot_replace_authoritative_relation_record(
    tmp_path: Path,
) -> None:
    path = tmp_path / "relations.json"
    path.write_text(
        json.dumps(
            {
                "mission_id": "mission-authoritative",
                "prompt": "ROLE_WORKER_A inherited marker",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(MissionCorrelationError, match="invalid"):
        FactoryMissionCorrelationAdapter.load(
            path,
            expected_digest="0" * 64,
            role_configuration={
                "orchestrator": {"count": 1},
                "worker": {"minimum": 2},
                "validator": {"count": 1},
            },
        )
