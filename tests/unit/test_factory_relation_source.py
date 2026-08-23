from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from shadow_mission.auth import generate_run_secret, make_alias
from shadow_mission.correlation import (
    MissionCorrelationError,
    PinnedFactoryMissionRelationProducer,
    factory_relation_source_digest,
)
from shadow_mission.protocol import HookEnvelope


DROID_DIGEST = "d" * 64


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def write_progress(path: Path, entries: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(f"{json.dumps(entry)}\n" for entry in entries),
        encoding="utf-8",
    )
    path.chmod(0o600)


def make_producer(
    tmp_path: Path,
    *,
    minimum_workers: int = 3,
    validator_count: int = 1,
) -> tuple[PinnedFactoryMissionRelationProducer, Path, Path, str]:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    mission_root = tmp_path / "factory-missions"
    mission_root.mkdir(mode=0o700)
    secret = generate_run_secret()
    producer = PinnedFactoryMissionRelationProducer(
        mission_root=mission_root,
        project_root=project,
        droid_binary_digest=DROID_DIGEST,
        expected_source_digest=factory_relation_source_digest(DROID_DIGEST),
        secret=secret,
        correlation_id="run-correlation",
        role_configuration={
            "orchestrator": {"count": 1},
            "worker": {"minimum": minimum_workers},
            "validator": {"count": validator_count},
        },
        clock=lambda: 500,
    )
    return producer, mission_root, project, secret


def create_mission_files(
    mission_root: Path,
    project: Path,
    *,
    features: list[dict[str, object]],
    progress: list[dict[str, object]],
) -> Path:
    mission_dir = mission_root / "base-session"
    mission_dir.mkdir(mode=0o700)
    write_json(
        mission_dir / "state.json",
        {
            "missionId": "mis_12345678",
            "state": "running",
            "workingDirectory": str(project),
            "createdAt": "2026-08-18T00:00:00Z",
            "updatedAt": "2026-08-18T00:00:01Z",
        },
    )
    write_json(mission_dir / "features.json", {"features": features})
    write_progress(mission_dir / "progress_log.jsonl", progress)
    return mission_dir


def worker_feature(
    feature_id: str,
    session_id: str,
    *,
    skill_name: str | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "id": feature_id,
        "description": feature_id,
        "status": "in_progress",
        "workerSessionIds": [session_id],
    }
    if skill_name is not None:
        value["skillName"] = skill_name
    return value


def worker_progress(feature_id: str, session_id: str) -> list[dict[str, object]]:
    return [
        {
            "timestamp": "2026-08-18T00:00:02Z",
            "type": "worker_selected_feature",
            "workerSessionId": session_id,
            "featureId": feature_id,
        },
        {
            "timestamp": "2026-08-18T00:00:03Z",
            "type": "worker_started",
            "workerSessionId": session_id,
            "featureId": feature_id,
            "spawnId": f"spawn-{session_id}",
        },
    ]


def envelope(session_alias: str) -> HookEnvelope:
    return HookEnvelope(provenance_status="hook_authenticated",
    redaction_status="clean",
    event_id=f"event-{session_alias}",
    source_fingerprint="source",
    run_id="run-correlation",
    session_alias=session_alias,
    transcript_alias="transcript",
    hook_event_name="SessionStart", observed_at=1, message_digest="d" * 64, payload={},)


def test_orchestrator_is_admitted_from_state_before_features_exist(
    tmp_path: Path,
) -> None:
    producer, mission_root, project, secret = make_producer(
        tmp_path, minimum_workers=1
    )
    mission_dir = mission_root / "base-session"
    mission_dir.mkdir(mode=0o700)
    write_json(
        mission_dir / "state.json",
        {
            "missionId": "mis_12345678",
            "state": "planning",
            "workingDirectory": str(project),
            "createdAt": "2026-08-18T00:00:00Z",
            "updatedAt": "2026-08-18T00:00:01Z",
        },
    )

    assert producer.refresh() == 1
    orchestrator = make_alias(secret, "session", "base-session")
    assert producer.binding.registry.accepts(envelope(orchestrator)) is True
    assert producer.refresh() == 0

    write_json(
        mission_dir / "features.json",
        {"features": [worker_feature("api", "worker-api")]},
    )
    write_progress(
        mission_dir / "progress_log.jsonl",
        worker_progress("api", "worker-api"),
    )
    assert producer.refresh() == 1
    assert producer.binding.registry.accepts(
        envelope(make_alias(secret, "session", "worker-api"))
    )
    producer.close()


def test_pending_features_without_worker_sessions_admit_nothing(
    tmp_path: Path,
) -> None:
    """Factory writes features.json at mission accept, before any worker starts.

    Those pending features carry no `workerSessionIds`. Refresh must keep
    serving instead of failing the collector closed.
    """

    producer, mission_root, project, secret = make_producer(
        tmp_path, minimum_workers=1
    )
    mission_dir = create_mission_files(
        mission_root,
        project,
        features=[
            {
                "id": "api-payment-amount-contract",
                "description": "align the API cents contract",
                "skillName": "api-worker",
                "status": "pending",
            },
            {
                "id": "webhook-dollar-input",
                "description": "keep the documented dollar input",
                "status": "pending",
            },
        ],
        progress=[
            {
                "timestamp": "2026-08-18T00:00:02Z",
                "type": "mission_accepted",
                "title": "Payment amount unit correction",
            }
        ],
    )

    assert producer.refresh() == 1
    orchestrator = make_alias(secret, "session", "base-session")
    assert producer.binding.registry.accepts(envelope(orchestrator)) is True
    assert producer.refresh() == 0

    write_json(
        mission_dir / "features.json",
        {"features": [worker_feature("api-payment-amount-contract", "worker-api")]},
    )
    write_progress(
        mission_dir / "progress_log.jsonl",
        worker_progress("api-payment-amount-contract", "worker-api"),
    )
    assert producer.refresh() == 1
    assert producer.binding.registry.accepts(
        envelope(make_alias(secret, "session", "worker-api"))
    )
    producer.close()


def test_pinned_source_correlates_factory_workers_and_validator(tmp_path: Path) -> None:
    producer, mission_root, project, secret = make_producer(tmp_path)
    feature_sessions = (
        ("api", "worker-api", None),
        ("webhook", "worker-webhook", None),
        ("export", "worker-export", None),
        ("scrutiny-m1", "worker-validator", "scrutiny-validator"),
    )
    create_mission_files(
        mission_root,
        project,
        features=[
            worker_feature(feature, session, skill_name=skill)
            for feature, session, skill in feature_sessions
        ],
        progress=[
            entry
            for feature, session, _ in feature_sessions
            for entry in worker_progress(feature, session)
        ],
    )

    assert producer.refresh() == 5
    assert producer.refresh() == 0

    orchestrator = make_alias(secret, "session", "base-session")
    validator = make_alias(secret, "session", "worker-validator")
    assert producer.binding.registry.accepts(envelope(orchestrator)) is True
    assert producer.binding.registry.accepts(envelope(validator)) is True
    validator_relation = producer.binding.relations.get(validator)
    assert validator_relation is not None
    assert validator_relation.role_id.startswith("validator:")
    decision = producer.binding.role_mapper.observe(envelope(validator))
    assert decision.kind == "validator"
    assert decision.status == "assigned"

    producer.exclude("shadow-probe", "shadow_owned")
    producer.exclude("same-project-decoy", "same_project_decoy")
    record = producer.finalize_record()
    assert record.mission_id == make_alias(
        secret, "factory-mission", "mis_12345678"
    )
    assert record.observed_at == 500
    assert sum(item.role_kind == "worker" for item in record.sessions) == 3
    assert sum(item.role_kind == "validator" for item in record.sessions) == 1
    assert all(
        item.session_id
        not in {
            "base-session",
            "worker-api",
            "worker-webhook",
            "worker-export",
            "worker-validator",
            "shadow-probe",
            "same-project-decoy",
        }
        for item in record.sessions
    )


def test_shortened_mission_persists_inventory_but_fails_release_gate(
    tmp_path: Path,
) -> None:
    producer, mission_root, project, _ = make_producer(tmp_path)
    feature_sessions = (
        ("api", "worker-api"),
        ("webhook", "worker-webhook"),
    )
    create_mission_files(
        mission_root,
        project,
        features=[
            worker_feature(feature, session)
            for feature, session in feature_sessions
        ],
        progress=[
            entry
            for feature, session in feature_sessions
            for entry in worker_progress(feature, session)
        ],
    )
    assert producer.refresh() == 3
    producer.exclude("shadow-probe", "shadow_owned")
    producer.exclude("same-project-decoy", "same_project_decoy")

    record = producer.finalize_record()

    assert record.role_inventory.expected.model_dump(mode="json") == {
        "orchestrator": 1,
        "worker": 3,
        "validator": 1,
    }
    assert record.role_inventory.observed.model_dump(mode="json") == {
        "orchestrator": 1,
        "worker": 2,
        "validator": 0,
    }
    assert record.role_inventory.shortfalls == ["validator", "worker"]
    assert record.role_inventory.complete is False
    with pytest.raises(MissionCorrelationError, match="too few workers"):
        producer.require_complete()
    producer.close()


def test_pinned_source_accepts_configured_zero_validators(
    tmp_path: Path,
) -> None:
    producer, mission_root, project, _ = make_producer(
        tmp_path,
        minimum_workers=2,
        validator_count=0,
    )
    feature_sessions = (
        ("api", "worker-api"),
        ("webhook", "worker-webhook"),
    )
    create_mission_files(
        mission_root,
        project,
        features=[
            worker_feature(feature, session)
            for feature, session in feature_sessions
        ],
        progress=[
            entry
            for feature, session in feature_sessions
            for entry in worker_progress(feature, session)
        ],
    )
    assert producer.refresh() == 3
    producer.exclude("shadow-probe", "shadow_owned")
    producer.exclude("same-project-decoy", "same_project_decoy")

    record = producer.finalize_record()

    assert record.role_inventory.expected.validator == 0
    assert record.role_inventory.observed.validator == 0
    assert record.role_inventory.shortfalls == []
    assert record.role_inventory.complete is True
    assert producer.require_complete()["validator"] == 0
    producer.close()


def test_worker_waits_for_both_factory_assignment_records(tmp_path: Path) -> None:
    producer, mission_root, project, secret = make_producer(
        tmp_path, minimum_workers=1
    )
    mission_dir = create_mission_files(
        mission_root,
        project,
        features=[worker_feature("api", "worker-api")],
        progress=worker_progress("api", "worker-api")[:1],
    )

    assert producer.refresh() == 1
    worker_alias = make_alias(secret, "session", "worker-api")
    assert producer.binding.registry.accepts(envelope(worker_alias)) is False

    write_progress(
        mission_dir / "progress_log.jsonl", worker_progress("api", "worker-api")
    )
    assert producer.refresh() == 1
    assert producer.binding.registry.accepts(envelope(worker_alias)) is True


def test_pinned_source_rejects_role_drift_for_an_admitted_session(
    tmp_path: Path,
) -> None:
    producer, mission_root, project, _ = make_producer(
        tmp_path, minimum_workers=1
    )
    mission_dir = create_mission_files(
        mission_root,
        project,
        features=[worker_feature("api", "worker-api")],
        progress=worker_progress("api", "worker-api"),
    )
    assert producer.refresh() == 2
    write_json(
        mission_dir / "features.json",
        {
            "features": [
                worker_feature(
                    "api", "worker-api", skill_name="scrutiny-validator"
                )
            ]
        },
    )

    with pytest.raises(MissionCorrelationError, match="relation changed"):
        producer.refresh()


def test_pinned_source_rejects_ambiguous_factory_mission_root(
    tmp_path: Path,
) -> None:
    producer, mission_root, project, _ = make_producer(tmp_path)
    create_mission_files(mission_root, project, features=[], progress=[])
    (mission_root / "other-session").mkdir(mode=0o700)

    with pytest.raises(MissionCorrelationError, match="ambiguous"):
        producer.refresh()


def test_pinned_source_ignores_historical_mission_directories(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    mission_root = tmp_path / "factory-missions"
    mission_root.mkdir(mode=0o700)
    (mission_root / "old-session").mkdir(mode=0o700)
    secret = generate_run_secret()
    producer = PinnedFactoryMissionRelationProducer(
        mission_root=mission_root,
        project_root=project,
        droid_binary_digest=DROID_DIGEST,
        expected_source_digest=factory_relation_source_digest(DROID_DIGEST),
        secret=secret,
        correlation_id="run-correlation",
        role_configuration={
            "orchestrator": {"count": 1},
            "worker": {"minimum": 1},
            "validator": {"count": 1},
        },
        clock=lambda: 500,
    )
    create_mission_files(
        mission_root,
        project,
        features=[worker_feature("api", "worker-api")],
        progress=worker_progress("api", "worker-api"),
    )

    assert producer.refresh() == 2
    assert producer.binding.registry.accepts(
        envelope(make_alias(secret, "session", "base-session"))
    )
    producer.close()



def test_pinned_source_rejects_two_new_missions_beside_history(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    mission_root = tmp_path / "factory-missions"
    mission_root.mkdir(mode=0o700)
    (mission_root / "old-session").mkdir(mode=0o700)
    producer = PinnedFactoryMissionRelationProducer(
        mission_root=mission_root,
        project_root=project,
        droid_binary_digest=DROID_DIGEST,
        expected_source_digest=factory_relation_source_digest(DROID_DIGEST),
        secret=generate_run_secret(),
        correlation_id="run-correlation",
        role_configuration={
            "orchestrator": {"count": 1},
            "worker": {"minimum": 1},
            "validator": {"count": 1},
        },
        clock=lambda: 500,
    )
    create_mission_files(mission_root, project, features=[], progress=[])
    (mission_root / "other-session").mkdir(mode=0o700)

    with pytest.raises(MissionCorrelationError, match="ambiguous"):
        producer.refresh()
    producer.close()


def test_pinned_source_rejects_writable_factory_relation_file(
    tmp_path: Path,
) -> None:
    producer, mission_root, project, _ = make_producer(tmp_path)
    mission_dir = create_mission_files(mission_root, project, features=[], progress=[])
    os.chmod(mission_dir / "state.json", 0o666)

    with pytest.raises(MissionCorrelationError, match="unsafe"):
        producer.refresh()

def test_pinned_source_rejects_replaced_factory_mission_root(
    tmp_path: Path,
) -> None:
    producer, mission_root, project, _ = make_producer(tmp_path)
    displaced_root = tmp_path / "displaced-missions"
    mission_root.rename(displaced_root)
    mission_root.mkdir(mode=0o700)
    create_mission_files(mission_root, project, features=[], progress=[])

    try:
        with pytest.raises(MissionCorrelationError, match="root changed"):
            producer.refresh()
    finally:
        producer.close()


def test_pinned_source_rejects_replaced_mission_directory(
    tmp_path: Path,
) -> None:
    producer, mission_root, project, _ = make_producer(
        tmp_path, minimum_workers=1
    )
    feature_sessions = (
        ("api", "worker-api", None),
        ("scrutiny-m1", "worker-validator", "scrutiny-validator"),
    )
    mission_dir = create_mission_files(
        mission_root,
        project,
        features=[
            worker_feature(feature, session, skill_name=skill)
            for feature, session, skill in feature_sessions
        ],
        progress=[
            entry
            for feature, session, _ in feature_sessions
            for entry in worker_progress(feature, session)
        ],
    )
    assert producer.refresh() == 3
    displaced_directory = tmp_path / "displaced-mission"
    mission_dir.rename(displaced_directory)
    create_mission_files(
        mission_root,
        project,
        features=[
            worker_feature(feature, session, skill_name=skill)
            for feature, session, skill in feature_sessions
        ],
        progress=[
            entry
            for feature, session, _ in feature_sessions
            for entry in worker_progress(feature, session)
        ],
    )

    try:
        with pytest.raises(MissionCorrelationError, match="directory changed"):
            producer.refresh()
    finally:
        producer.close()


def test_pinned_source_rejects_malformed_relation_field(tmp_path: Path) -> None:
    producer, mission_root, project, _ = make_producer(
        tmp_path, minimum_workers=1
    )
    create_mission_files(
        mission_root,
        project,
        features=[{"skillName": None, "workerSessionIds": ["worker-api"]}],
        progress=[],
    )

    with pytest.raises(MissionCorrelationError, match="schema"):
        producer.refresh()
    producer.close()


@pytest.mark.parametrize(
    "worker_session_ids",
    [[""], ["worker-api", "worker-api"], ["w" * 513]],
)
def test_pinned_source_rejects_malformed_worker_session_ids(
    tmp_path: Path,
    worker_session_ids: list[str],
) -> None:
    producer, mission_root, project, _ = make_producer(
        tmp_path, minimum_workers=1
    )
    create_mission_files(
        mission_root,
        project,
        features=[
            {
                "id": "api",
                "description": "api",
                "status": "in_progress",
                "workerSessionIds": worker_session_ids,
            }
        ],
        progress=[],
    )

    with pytest.raises(MissionCorrelationError, match="schema"):
        producer.refresh()
    producer.close()


def test_pinned_source_rejects_ambiguous_progress_assignment(
    tmp_path: Path,
) -> None:
    producer, mission_root, project, _ = make_producer(
        tmp_path, minimum_workers=1
    )
    create_mission_files(
        mission_root,
        project,
        features=[worker_feature("api", "worker-api")],
        progress=[
            *worker_progress("api", "worker-api"),
            *worker_progress("webhook", "worker-api"),
        ],
    )

    with pytest.raises(MissionCorrelationError, match="ambiguous"):
        producer.refresh()


def test_pinned_source_rejects_removed_relation_evidence(
    tmp_path: Path,
) -> None:
    producer, mission_root, project, _ = make_producer(
        tmp_path, minimum_workers=1
    )
    feature_sessions = (
        ("api", "worker-api", None),
        ("scrutiny-m1", "worker-validator", "scrutiny-validator"),
    )
    mission_dir = create_mission_files(
        mission_root,
        project,
        features=[
            worker_feature(feature, session, skill_name=skill)
            for feature, session, skill in feature_sessions
        ],
        progress=[
            entry
            for feature, session, _ in feature_sessions
            for entry in worker_progress(feature, session)
        ],
    )
    assert producer.refresh() == 3
    (mission_dir / "features.json").unlink()

    with pytest.raises(MissionCorrelationError, match="missing"):
        producer.require_complete()


def test_pinned_source_enforces_configured_validator_count(
    tmp_path: Path,
) -> None:
    producer, mission_root, project, _ = make_producer(
        tmp_path, minimum_workers=1, validator_count=2
    )
    feature_sessions = (
        ("api", "worker-api", None),
        ("scrutiny-m1", "worker-validator", "scrutiny-validator"),
    )
    create_mission_files(
        mission_root,
        project,
        features=[
            worker_feature(feature, session, skill_name=skill)
            for feature, session, skill in feature_sessions
        ],
        progress=[
            entry
            for feature, session, _ in feature_sessions
            for entry in worker_progress(feature, session)
        ],
    )

    with pytest.raises(MissionCorrelationError, match="too few validators"):
        producer.require_complete()
    producer.close()


def test_host_factory_mission_root_requires_layout_and_sessions(
    tmp_path: Path,
) -> None:
    from shadow_mission.correlation import require_host_factory_mission_root

    factory = tmp_path / ".factory"
    missions = factory / "missions"
    factory.mkdir(mode=0o700)
    missions.mkdir(mode=0o700)
    with pytest.raises(MissionCorrelationError, match="session root"):
        require_host_factory_mission_root(missions)
    (factory / "sessions").mkdir(mode=0o700)
    assert require_host_factory_mission_root(missions) == missions.resolve()
    invalid = tmp_path / "factory-missions"
    invalid.mkdir(mode=0o700)
    with pytest.raises(MissionCorrelationError, match="host Factory missions"):
        require_host_factory_mission_root(invalid)
