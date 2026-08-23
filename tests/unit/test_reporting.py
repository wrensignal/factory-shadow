from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Callable

import pytest
import shadow_mission.reporting as reporting_module

from shadow_mission.auth import generate_run_secret
from shadow_mission.correlation import (
    PinnedFactoryMissionRelationProducer,
    correlation_record_digest,
    factory_relation_source_digest,
)

from shadow_mission.evaluation import EvaluationRecord
from shadow_mission.protocol import (
    RELEASE_REPORTABLE_RUNTIME_OUTCOMES,
    BaselineRunRecord,
    CapabilityFlags,
    HookEnvelope,
    HookExchangeRecord,
    HookResponseRecord,
    InterventionRecord,
    InterventionTransition,
    PreEvaluationRecord,
    RunRecord,
    canonical_json,
    hook_envelope_digest,
    hook_response_digest,
)
from shadow_mission.reporting import (
    _load_mission_relation_record,
    ReportCorruptionError,
    ReportInputError,
    ReportRecord,
    ReportWriteError,
    rebuild_report,
    render_markdown,
    write_report_outputs,
)
from shadow_mission.review_journal import JournalFinding, ReviewJournal
from shadow_mission.router import InterventionRouterDelta, InterventionRouterState
from shadow_mission.source_export import validate_source_archive
from tests.integration.test_source_export import export, make_repo
from tests.unit.test_evaluation import evaluator_result
from tests.unit.test_factory_relation_source import (
    create_mission_files,
    worker_feature,
    worker_progress,
)


def capabilities() -> CapabilityFlags:
    return CapabilityFlags(
        core_feasibility_verdict="pass",
        release_gate_verdict="fallback-pass",
        droid_version="0.197.0",
        plugin_version="0.1.0",
        droid_sdk_version="0.2.0",
        lima_version="2.2.0",
        vm_image_digest="sha256:" + "1" * 64,
        factory_profile_digest="2" * 64,
        isolation_digest="3" * 64,
        gate_surface_digest="4" * 64,
        installed_plugin_artifact_digest="5" * 64,
        transport_integrity="pass",
        hook_provenance="fallback",
        session_hooks="pass",
        identity="pass",
        transcript="pass",
        guidance="pass",
        worker_block="pass",
        mission_block="pass",
        worker_roles="pass",
        validator_roles="pass",
        self_session_exclusion="pass",
        sandbox_isolation="fallback",
        probe_boundary="pass",
        live_validation_overlap="fallback",
    )


def mission_relation_record(run_id: str) -> dict[str, object]:
    sessions: list[dict[str, object]] = []
    for index, role_kind in enumerate(
        ("orchestrator", "worker", "worker", "validator"),
        start=1,
    ):
        role_id = f"{role_kind}-{index}"
        sessions.append(
            {
                "session_id": f"session-{index}",
                "disposition": "mission_role",
                "role_id": role_id,
                "role_kind": role_kind,
                "assignment_id": f"assignment-{index}",
                "source_digest": f"{index}" * 64,
                "relation_kind": (
                    "mission_relation"
                    if role_kind == "orchestrator"
                    else "assignment"
                ),
                "confidence": "high",
                "corroborating_role_ids": [role_id],
            }
        )
    sessions.extend(
        (
            {
                "session_id": "shadow-owned-control",
                "disposition": "shadow_owned",
                "role_id": None,
                "role_kind": None,
                "assignment_id": None,
                "source_digest": "a" * 64,
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
                "source_digest": "b" * 64,
                "relation_kind": "mission_relation",
                "confidence": "none",
                "corroborating_role_ids": [],
            },
        )
    )
    role_counts = {
        "orchestrator": 1,
        "worker": 2,
        "validator": 1,
    }
    record: dict[str, object] = {
        "schema_version": "0.1",
        "source_class": "factory_mission_relations",
        "mission_id": f"factory-mission-{run_id}",
        "observed_at": 1,
        "sessions": sessions,
        "role_inventory": {
            "expected": role_counts,
            "observed": role_counts,
            "shortfalls": [],
            "complete": True,
        },
    }
    record["record_digest"] = correlation_record_digest(record)
    role_assignments = {
        session["role_id"]: session["session_id"]
        for session in sessions
        if session["disposition"] == "mission_role"
    }
    value: dict[str, object] = {
        "schema_version": "0.1",
        "source_digest": "c" * 64,
        "mission_id": run_id,
        "record": record,
        "role_counts": role_counts,
        "role_assignments": role_assignments,
    }
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    return value


def produced_mission_relation_record(
    tmp_path: Path,
    *,
    run_id: str,
    minimum_workers: int,
    include_validator: bool,
) -> dict[str, object]:
    fixture_root = tmp_path / f"{run_id}-factory-relation"
    fixture_root.mkdir(mode=0o700)
    project = fixture_root / "project"
    project.mkdir(mode=0o700)
    mission_root = fixture_root / "missions"
    mission_root.mkdir(mode=0o700)
    droid_digest = "d" * 64
    producer = PinnedFactoryMissionRelationProducer(
        mission_root=mission_root,
        project_root=project,
        droid_binary_digest=droid_digest,
        expected_source_digest=factory_relation_source_digest(droid_digest),
        secret=generate_run_secret(),
        correlation_id=run_id,
        role_configuration={
            "orchestrator": {"count": 1},
            "worker": {"minimum": minimum_workers},
            "validator": {"count": 1},
        },
        clock=lambda: 500,
    )
    feature_sessions = [
        ("api", "worker-api", None),
        ("webhook", "worker-webhook", None),
    ]
    if include_validator:
        feature_sessions.append(
            ("scrutiny-m1", "worker-validator", "scrutiny-validator")
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
    producer.refresh()
    producer.exclude("shadow-owned-control", "shadow_owned")
    producer.exclude("same-project-decoy", "same_project_decoy")
    record = producer.finalize_record()
    role_counts = {
        role_kind: sum(
            relation.disposition == "mission_role"
            and relation.role_kind == role_kind
            for relation in record.sessions
        )
        for role_kind in ("orchestrator", "worker", "validator")
    }
    value: dict[str, object] = {
        "schema_version": "0.1",
        "source_digest": producer.binding.source_digest,
        "mission_id": producer.binding.mission_id,
        "record": record.model_dump(mode="json"),
        "role_counts": role_counts,
        "role_assignments": dict(producer.binding.role_assignments),
    }
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    producer.close()
    return value


def final_run(
    run_id: str,
    *,
    relation_record: dict[str, object] | None = None,
    runtime_outcome: str = "mission-terminated",
) -> RunRecord:
    relation_record = relation_record or mission_relation_record(run_id)
    value = {
        "schema_version": "0.1",
        "provenance_status": "untrusted_provenance",
        "redaction_status": "clean",
        "run_id": run_id,
        "droid_version": "0.197.0",
        "plugin_version": "0.1.0",
        "droid_sdk_version": "0.2.0",
        "lima_version": "2.2.0",
        "droid_installation_channel": "exact-npm",
        "droid_binary_digest": "6" * 64,
        "droid_auto_update_control": "npm-build-disabled",
        "gate_surface_digest": "4" * 64,
        "installed_plugin_artifact_digest": "5" * 64,
        "full_run_artifact_digest": "7" * 64,
        "historical_launch_artifact_digest": "8" * 64,
        "resolved_plugin_source": "sha256:" + "5" * 64,
        "release_preflight_digest": "9" * 64,
        "factory_profile_digest": "2" * 64,
        "vm_image_digest": "sha256:" + "1" * 64,
        "isolation_digest": "3" * 64,
        "mission_digest": "a" * 64,
        "mission_role_config_digest": "b" * 64,
        "mission_relation_source_digest": relation_record["source_digest"],
        "mission_relation_record_digest": relation_record["record_digest"],
        "mission_outcome": (
            "mission-complete"
            if runtime_outcome == "mission-terminated"
            else "mission-failed"
        ),
        "runtime_outcome": runtime_outcome,
        "mission_process_stopped": True,
        "approved_evaluator_digest": "1" * 64,
        "source_exporter_digest": "2" * 64,
        "initial_commit": "d" * 40,
        "final_commit": "e" * 40,
        "final_source_archive_digest": "f" * 64,
        "started_at": 100,
        "ended_at": 110,
        "duration_seconds": 10.0,
        "changed_files": ["src/webhook.py"],
        "evaluator_outcome": runtime_outcome,
        "usage_data": {"status": "unavailable"},
        "budget_ledger": {"live_run_count": 3},
        "models": {
            "orchestrator": "model-o",
            "worker": "model-w",
            "validator": "model-v",
            "extractor": "model-e",
            "probe": "model-p",
        },
        "reasoning": {
            "orchestrator": "high",
            "worker": "high",
            "validator": "high",
            "extractor": "high",
            "probe": "high",
        },
        "baseline_id": None,
        "baseline_record_digest": None,
        "pre_evaluation_record_digest": None,
        "final_source_manifest_digest": None,
        "final_source_working_tree_digest": None,
        "evaluator_digest": None,
        "evaluation_record_digest": None,
        "evaluator_vm_deleted": None,
        "capabilities": capabilities().model_dump(mode="json"),
        "record_digest": "0" * 64,
    }
    material = dict(value)
    material.pop("record_digest")
    value["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    return RunRecord.model_validate(value)
def baseline_for(run: RunRecord) -> BaselineRunRecord:
    run_value = run.model_dump(mode="json")
    value = {
        field: run_value[field]
        for field in BaselineRunRecord.model_fields
        if field not in {"baseline_id", "record_digest"}
    }
    value["baseline_id"] = "baseline-demo"
    value["evaluator_outcome"] = "fail"
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    return BaselineRunRecord.model_validate(value)


def bind_baseline(run: RunRecord, baseline: BaselineRunRecord) -> RunRecord:
    value = run.model_dump(mode="json")
    value["baseline_id"] = baseline.baseline_id
    value["baseline_record_digest"] = baseline.record_digest
    value["record_digest"] = "0" * 64
    material = dict(value)
    material.pop("record_digest")
    value["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    return RunRecord.model_validate(value)




def with_record_digest(model_type: object, value: dict[str, object]) -> dict:
    result = model_type.model_construct(
        record_digest="0" * 64,
        **value,
    ).model_dump(mode="json")
    result.pop("record_digest")
    result["record_digest"] = hashlib.sha256(canonical_json(result)).hexdigest()
    return result


def report_exchange(run_id: str) -> HookExchangeRecord:
    envelope = HookEnvelope(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        event_id="event-guidance",
        source_fingerprint="source-guidance",
        run_id=run_id,
        session_alias="worker-a",
        transcript_alias="transcript-worker-a",
        hook_event_name="PostToolUse",
        observed_at=1,
        message_digest="d" * 64,
        payload={"tool_name": "ApplyPatch"},
    )
    body = canonical_json({}).decode()
    response = HookResponseRecord(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        response_id="response-guidance",
        run_id=run_id,
        event_id=envelope.event_id,
        request_digest=hook_envelope_digest(envelope),
        response_body=body,
        response_digest=hook_response_digest(
            response_body=body,
            guidance_ids=("guidance-1",),
            transition_ids=(),
            review_state=None,
        ),
        guidance_ids=("guidance-1",),
        transition_ids=(),
        decided_at=2,
    )
    return HookExchangeRecord(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        ledger_sequence=1,
        exchange_id="exchange-guidance",
        recorded_at=2,
        envelope=envelope,
        response=response,
    )


def report_intervention(
    run_id: str,
    *,
    target_session: str,
    resolved: bool,
) -> InterventionRecord:
    states = (
        ("queued", "delivered", "acknowledged", "corrected", "resolved")
        if resolved
        else ("queued",)
    )
    transitions = tuple(
        InterventionTransition(
            transition_id=f"transition-{target_session}-{state}",
            generation=index,
            state=state,
            action=state,
            observed_at=index,
        )
        for index, state in enumerate(states, start=1)
    )
    return InterventionRecord.model_validate(
        with_record_digest(
            InterventionRecord,
            {
                "schema_version": "0.1",
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "record_type": "intervention_record",
                "intervention_id": f"intervention-{target_session}",
                "run_id": run_id,
                "finding_id": "finding-mixed",
                "finding_dedup_key": "a" * 64,
                "target_session": target_session,
                "completion_session_alias": target_session,
                "rule": "cross_worker_conflict",
                "level": "concern",
                "risk_category": "public_contract",
                "claim_ids": ("claim-a", "claim-b"),
                "direct_evidence_ids": ("evidence-a", "evidence-b"),
                "direct_evidence_digests": ("1" * 64, "2" * 64),
                "correction_evidence_ids": (
                    ("evidence-correction",) if resolved else ()
                ),
                "correction_evidence_digests": (
                    ("3" * 64,) if resolved else ()
                ),
                "generation": len(states),
                "state": states[-1],
                "transition_history": transitions,
                "probe_id": "probe-mixed",
                "probe_digest": "4" * 64,
                "probe_status": "confirmed",
                "probe_snapshot_digest": "5" * 64,
                "blocking_scope": "worker",
                "attempts": 0,
            },
        )
    )


def append_mixed_finding(journal: ReviewJournal, run_id: str) -> None:
    interventions = (
        report_intervention(
            run_id,
            target_session="worker-a",
            resolved=True,
        ),
        report_intervention(
            run_id,
            target_session="worker-b",
            resolved=False,
        ),
    )
    base = InterventionRouterState.empty(run_id)
    final = InterventionRouterState.model_validate(
        with_record_digest(
            InterventionRouterState,
            {
                "schema_version": "0.1",
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "record_type": "intervention_router_state",
                "run_id": run_id,
                "generation": 5,
                "interventions": interventions,
            },
        )
    )
    delta = InterventionRouterDelta.model_validate(
        with_record_digest(
            InterventionRouterDelta,
            {
                "schema_version": "0.1",
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "record_type": "intervention_router_delta",
                "run_id": run_id,
                "base_generation": 0,
                "base_digest": base.record_digest,
                "generation": 5,
                "upserts": interventions,
                "result_digest": final.record_digest,
            },
        )
    )
    journal.append(
        "intervention_lineage",
        ledger_sequence=1,
        event_id="event-mixed",
        response_digest="6" * 64,
        delta=delta,
    )
    journal.append(
        "finding_snapshot",
        ledger_sequence=1,
        event_id="event-mixed",
        graph_digest="7" * 64,
        findings=(
            JournalFinding(
                finding_id="finding-mixed",
                dedup_key="a" * 64,
                rule="cross_worker_conflict",
                level="concern",
                target_sessions=("worker-a", "worker-b"),
                claim_ids=("claim-a", "claim-b"),
                evidence_ids=("evidence-a", "evidence-b"),
                evidence_digests=("1" * 64, "2" * 64),
                normalized_locators=("api.json#/amount",),
                normalized_properties=("unit",),
                normalized_units=("cents",),
                normalized_values=("cents", "dollars"),
                authority_status="resolved",
                authority_level=3,
                authority_value="cents",
                risk_category="public_contract",
                probe_status="confirmed",
                probe_id="probe-mixed",
            ),
        ),
        validation_overlap_status="active",
    )


def make_run_dir(
    tmp_path: Path,
    run_id: str = "run-report",
    *,
    relation_record: dict[str, object] | None = None,
    runtime_outcome: str = "mission-terminated",
    journal_setup: Callable[[ReviewJournal], None] | None = None,
    exchanges: tuple[HookExchangeRecord, ...] = (),
) -> Path:
    run_dir = tmp_path / run_id
    run_dir.mkdir(mode=0o700)
    relation_record = relation_record or mission_relation_record(run_id)
    run = final_run(
        run_id,
        relation_record=relation_record,
        runtime_outcome=runtime_outcome,
    )
    (run_dir / "run.json").write_bytes(
        canonical_json(run.model_dump(mode="json")) + b"\n"
    )
    (run_dir / "events.jsonl").write_bytes(
        b"".join(
            canonical_json(exchange.model_dump(mode="json")) + b"\n"
            for exchange in exchanges
        )
    )
    journal = ReviewJournal(run_dir / "review.jsonl", run_id=run_id)
    if journal_setup is not None:
        journal_setup(journal)
    (run_dir / "correlation.json").write_bytes(
        canonical_json(relation_record) + b"\n"
    )
    return run_dir

def make_final_run_dir(
    tmp_path: Path,
    run_id: str = "run-report",
    *,
    relation_record: dict[str, object] | None = None,
    runtime_outcome: str = "mission-terminated",
    journal_setup: Callable[[ReviewJournal], None] | None = None,
    exchanges: tuple[HookExchangeRecord, ...] = (),
) -> Path:
    relation_record = relation_record or mission_relation_record(run_id)
    run_dir = make_run_dir(
        tmp_path,
        run_id=run_id,
        relation_record=relation_record,
        runtime_outcome=runtime_outcome,
        journal_setup=journal_setup,
        exchanges=exchanges,
    )
    source_root = tmp_path / f"{run_id}-source"
    source_root.mkdir()
    source_repo = make_repo(source_root)
    archive, manifest, exported = export(
        source_repo,
        tmp_path / f"{run_id}-source-artifacts",
    )
    assert exported.returncode == 0
    source = validate_source_archive(archive, manifest)
    evaluation = EvaluationRecord.model_validate(evaluator_result(archive, manifest))
    evaluator_digest = "1" * 64
    preliminary_value = final_run(
        run_id,
        relation_record=relation_record,
        runtime_outcome=runtime_outcome,
    ).model_dump(mode="json")
    preliminary_value.update(
        {
            "evaluator_outcome": runtime_outcome,
            "final_commit": source.manifest.final_commit,
            "final_source_archive_digest": None,
            "record_digest": "0" * 64,
        }
    )
    preliminary_value["record_digest"] = hashlib.sha256(
        canonical_json(
            {
                key: value
                for key, value in preliminary_value.items()
                if key != "record_digest"
            }
        )
    ).hexdigest()
    preliminary = RunRecord.model_validate(preliminary_value)
    (run_dir / "run.json").write_bytes(
        canonical_json(preliminary.model_dump(mode="json")) + b"\n"
    )
    pre_evaluation_value = {
        "schema_version": "0.1",
        "run_id": run_id,
        "pre_evaluation_run_record_digest": preliminary.record_digest,
        "event_ledger_digest": hashlib.sha256(
            (run_dir / "events.jsonl").read_bytes()
        ).hexdigest(),
        "event_ledger_record_count": len(exchanges),
        "review_journal_digest": hashlib.sha256(
            (run_dir / "review.jsonl").read_bytes()
        ).hexdigest(),
        "source_archive_digest": source.archive_digest,
        "source_manifest_digest": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "source_working_tree_digest": source.manifest.working_tree_digest,
        "evaluator_digest": evaluator_digest,
        "mission_process_stopped": True,
    }
    pre_evaluation_value["record_digest"] = hashlib.sha256(
        canonical_json(pre_evaluation_value)
    ).hexdigest()
    pre_evaluation = PreEvaluationRecord.model_validate(pre_evaluation_value)
    run_value = preliminary.model_dump(mode="json")
    run_value.update(
        {
            "final_source_archive_digest": source.archive_digest,
            "evaluator_outcome": evaluation.model_dump(mode="json"),
            "pre_evaluation_record_digest": pre_evaluation.record_digest,
            "final_source_manifest_digest": pre_evaluation.source_manifest_digest,
            "final_source_working_tree_digest": source.manifest.working_tree_digest,
            "evaluator_digest": evaluator_digest,
            "evaluation_record_digest": evaluation.record_digest,
            "evaluator_vm_deleted": True,
            "record_digest": "0" * 64,
        }
    )
    run_value["record_digest"] = hashlib.sha256(
        canonical_json(
            {key: value for key, value in run_value.items() if key != "record_digest"}
        )
    ).hexdigest()
    shutil.copyfile(run_dir / "run.json", run_dir / "pre-evaluation-run.json")
    run = RunRecord.model_validate(run_value)
    (run_dir / "run.json").write_bytes(
        canonical_json(run.model_dump(mode="json")) + b"\n"
    )
    (run_dir / "pre-evaluation.json").write_bytes(
        canonical_json(pre_evaluation.model_dump(mode="json")) + b"\n"
    )
    (run_dir / "evaluation.json").write_bytes(
        canonical_json(evaluation.model_dump(mode="json")) + b"\n"
    )
    final_source = run_dir / "final-source"
    final_source.mkdir()
    shutil.copyfile(archive, final_source / "final-source.tar")
    shutil.copyfile(manifest, final_source / "final-source-manifest.json")
    return run_dir


def test_failed_final_run_still_requires_relation_binding(tmp_path: Path) -> None:
    run_dir = make_final_run_dir(tmp_path, run_id="run-failed-relation")
    value = json.loads((run_dir / "run.json").read_bytes())
    value.update(
        {
            "mission_outcome": "mission-failed",
            "runtime_outcome": "cleanup-failed",
            "mission_relation_record_digest": None,
        }
    )
    value.pop("record_digest")
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()

    with pytest.raises(ValueError, match="final run relation record binding"):
        RunRecord.model_validate(value)


def test_finalized_run_requires_successful_mission_outcome(tmp_path: Path) -> None:
    run_dir = make_final_run_dir(tmp_path)

    value = json.loads((run_dir / "run.json").read_bytes())
    value["mission_outcome"] = "mission-failed"
    value.pop("record_digest")
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()

    with pytest.raises(ValueError, match="coarse Mission outcome"):
        RunRecord.model_validate(value)


def test_runtime_outcome_allowlist_accepts_only_reportable_process_results() -> None:
    assert "mission-terminated" in RELEASE_REPORTABLE_RUNTIME_OUTCOMES
    assert "completion-blocked" in RELEASE_REPORTABLE_RUNTIME_OUTCOMES
    assert "mission-exit-17" in RELEASE_REPORTABLE_RUNTIME_OUTCOMES
    assert "mission-exit--9" in RELEASE_REPORTABLE_RUNTIME_OUTCOMES
    assert "cleanup-failed" not in RELEASE_REPORTABLE_RUNTIME_OUTCOMES
    assert "mission-exit-not-a-number" not in RELEASE_REPORTABLE_RUNTIME_OUTCOMES



def test_runtime_shaped_complete_relation_envelope_loads(
    tmp_path: Path,
) -> None:
    relation = produced_mission_relation_record(
        tmp_path,
        run_id="run-complete-correlation",
        minimum_workers=2,
        include_validator=True,
    )
    relation_path = tmp_path / "complete-correlation.json"
    relation_path.write_bytes(canonical_json(relation) + b"\n")

    assert relation["mission_id"] != relation["record"]["mission_id"]
    mission_roles = [
        item
        for item in relation["record"]["sessions"]
        if item["disposition"] == "mission_role"
    ]
    assert relation["role_assignments"] == {
        item["role_id"]: item["session_id"] for item in mission_roles
    }
    assert relation["role_assignments"] != {
        item["role_id"]: item["assignment_id"] for item in mission_roles
    }
    loaded_envelope, loaded_record = _load_mission_relation_record(relation_path)
    assert loaded_envelope["mission_id"] == "run-complete-correlation"
    assert loaded_record.role_inventory.complete is True


def test_shortened_mission_relation_rebuilds_all_other_report_sections(
    tmp_path: Path,
) -> None:
    relation = produced_mission_relation_record(
        tmp_path,
        run_id="run-shortened-correlation",
        minimum_workers=3,
        include_validator=False,
    )
    run_dir = make_final_run_dir(
        tmp_path,
        run_id="run-shortened-correlation",
        relation_record=relation,
    )

    report = rebuild_report(run_dir)

    persisted = json.loads((run_dir / "correlation.json").read_bytes())
    inventory = persisted["record"]["role_inventory"]
    assert inventory["complete"] is False
    assert inventory["shortfalls"] == ["validator", "worker"]
    assert report.unavailable_fields == (
        "mission_role_inventory",
        "per_run_usage_and_cost",
    )
    assert report.frozen_configuration
    assert report.capabilities
    assert report.changed_files == ("src/webhook.py",)
    assert all(report.final_source.values())
    assert report.evaluator["status"] == "pass"
    assert report.usage
    assert report.budget_ledger
    assert report.commits["initial"]
    assert report.commits["final"]
    assert report.metrics.model_dump(mode="json")


def test_report_rebuild_uses_authoritative_jsonl_not_cached_prose(tmp_path: Path) -> None:
    run_dir = make_final_run_dir(tmp_path)
    (run_dir / "report.md").write_text("stale cached prose", encoding="utf-8")

    report = rebuild_report(run_dir)
    json_path, markdown_path = write_report_outputs(report, run_dir)

    assert report.run_id == "run-report"
    assert report.metrics.conflict_escape_count.value == 0
    assert report.unavailable_fields == ("per_run_usage_and_cost",)
    assert report.changed_files == ("src/webhook.py",)
    assert json.loads(json_path.read_text())["record_digest"] == report.record_digest
    assert markdown_path.read_text() == render_markdown(report)
    assert "stale cached prose" not in markdown_path.read_text()


def _revised_report(report: ReportRecord) -> ReportRecord:
    value = report.model_dump(mode="json")
    value["duration_seconds"] = (report.duration_seconds or 0.0) + 1.0
    value.pop("record_digest")
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    return ReportRecord.model_validate(value)


def test_report_staging_failure_preserves_prior_valid_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = make_final_run_dir(tmp_path)
    prior_report = rebuild_report(run_dir)
    json_path, markdown_path = write_report_outputs(prior_report, run_dir)
    prior_json = json_path.read_bytes()
    prior_markdown = markdown_path.read_text(encoding="utf-8")
    report = _revised_report(prior_report)

    def fail_fsync(_descriptor: int) -> None:
        raise OSError("injected staging failure")

    monkeypatch.setattr(reporting_module.os, "fsync", fail_fsync)

    with pytest.raises(ReportWriteError, match="publication failed"):
        write_report_outputs(report, run_dir)

    assert json_path.read_bytes() == prior_json
    assert markdown_path.read_text(encoding="utf-8") == prior_markdown
    assert tuple(run_dir.glob(".report.*.tmp")) == ()


def test_report_directory_fsync_failure_keeps_completed_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = make_final_run_dir(tmp_path)
    prior_report = rebuild_report(run_dir)
    write_report_outputs(prior_report, run_dir)
    report = _revised_report(prior_report)

    def fail_directory_fsync(_path: Path) -> None:
        raise OSError("injected directory fsync failure")

    monkeypatch.setattr(
        reporting_module,
        "_fsync_directory",
        fail_directory_fsync,
    )

    with pytest.raises(ReportWriteError, match="publication failed"):
        write_report_outputs(report, run_dir)

    json_path = run_dir / "report.json"
    markdown_path = run_dir / "report.md"
    assert json.loads(json_path.read_bytes())["record_digest"] == report.record_digest
    assert markdown_path.read_text(encoding="utf-8") == render_markdown(report)


def test_second_report_replace_failure_restores_prior_valid_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = make_final_run_dir(tmp_path)
    prior_report = rebuild_report(run_dir)
    json_path, markdown_path = write_report_outputs(prior_report, run_dir)
    prior_json = json_path.read_bytes()
    prior_markdown = markdown_path.read_text(encoding="utf-8")
    report = _revised_report(prior_report)
    replace = reporting_module.os.replace

    def fail_markdown_replace(source: object, destination: object) -> None:
        if Path(destination) == markdown_path and str(source).endswith(".tmp"):
            raise OSError("injected second replace failure")
        replace(source, destination)

    monkeypatch.setattr(reporting_module.os, "replace", fail_markdown_replace)

    with pytest.raises(ReportWriteError, match="publication failed"):
        write_report_outputs(report, run_dir)

    assert json_path.read_bytes() == prior_json
    assert markdown_path.read_text(encoding="utf-8") == prior_markdown
    assert tuple(run_dir.glob(".report.*.tmp")) == ()
    assert tuple(run_dir.glob(".report.*.bak")) == ()




def test_report_accepts_nonempty_guidance_exchange(tmp_path: Path) -> None:
    run_id = "run-guidance-report"
    run_dir = make_final_run_dir(
        tmp_path,
        run_id=run_id,
        exchanges=(report_exchange(run_id),),
    )

    report = rebuild_report(run_dir)

    assert report.ledger_record_count == 1
    assert report.metrics.intervention_precision.status == "unavailable"


def test_mixed_target_states_remain_unresolved_in_report(tmp_path: Path) -> None:
    run_id = "run-mixed-report"
    run_dir = make_final_run_dir(
        tmp_path,
        run_id=run_id,
        journal_setup=lambda journal: append_mixed_finding(journal, run_id),
    )

    report = rebuild_report(run_dir)

    assert report.detections[0]["completion_state"] == "unresolved"
    assert report.unresolved_risks == ("a" * 64,)
    assert report.metrics.conflict_escape_count.value == 1


def test_report_rebuild_and_render_are_byte_deterministic(tmp_path: Path) -> None:
    run_dir = make_final_run_dir(tmp_path)

    first = rebuild_report(run_dir)
    first_json = canonical_json(first.model_dump(mode="json"))
    first_markdown = render_markdown(first)
    second = rebuild_report(run_dir)

    assert canonical_json(second.model_dump(mode="json")) == first_json
    assert render_markdown(second) == first_markdown


def test_report_rejects_unknown_or_corrupt_run(tmp_path: Path) -> None:
    with pytest.raises(ReportInputError, match="unknown"):
        rebuild_report(tmp_path / "missing")

    run_dir = make_final_run_dir(tmp_path)
    (run_dir / "events.jsonl").write_bytes(b"{\"partial\":true}")
    with pytest.raises(ReportCorruptionError, match="replay"):
        rebuild_report(run_dir)

    incomplete_run_dir = make_run_dir(tmp_path, run_id="run-incomplete")
    with pytest.raises(ReportCorruptionError, match="finalization is incomplete"):
        rebuild_report(incomplete_run_dir)


def test_report_rejects_rewritten_mission_relation_record(
    tmp_path: Path,
) -> None:
    run_dir = make_final_run_dir(tmp_path)
    relation_path = run_dir / "correlation.json"
    value = json.loads(relation_path.read_bytes())
    value["role_counts"]["worker"] = 99
    value.pop("record_digest")
    value["record_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    relation_path.write_bytes(canonical_json(value) + b"\n")

    with pytest.raises(ReportCorruptionError, match="Mission relation record is invalid"):
        rebuild_report(run_dir)


def test_report_requires_and_validates_exact_bound_baseline(tmp_path: Path) -> None:
    run_dir = make_final_run_dir(tmp_path)
    run = RunRecord.model_validate(json.loads((run_dir / "run.json").read_bytes()))
    baseline = baseline_for(run)
    preliminary_path = run_dir / "pre-evaluation-run.json"
    preliminary = RunRecord.model_validate(json.loads(preliminary_path.read_bytes()))
    bound_preliminary = bind_baseline(preliminary, baseline)
    preliminary_path.write_bytes(
        canonical_json(bound_preliminary.model_dump(mode="json")) + b"\n"
    )
    pre_evaluation_path = run_dir / "pre-evaluation.json"
    pre_evaluation_value = json.loads(pre_evaluation_path.read_bytes())
    pre_evaluation_value["pre_evaluation_run_record_digest"] = (
        bound_preliminary.record_digest
    )
    pre_evaluation_value["record_digest"] = "0" * 64
    pre_evaluation_material = dict(pre_evaluation_value)
    pre_evaluation_material.pop("record_digest")
    pre_evaluation_value["record_digest"] = hashlib.sha256(
        canonical_json(pre_evaluation_material)
    ).hexdigest()
    pre_evaluation_path.write_bytes(
        canonical_json(pre_evaluation_value) + b"\n"
    )
    bound_run_value = bind_baseline(run, baseline).model_dump(mode="json")
    bound_run_value["pre_evaluation_record_digest"] = pre_evaluation_value[
        "record_digest"
    ]
    bound_run_value["record_digest"] = "0" * 64
    bound_run_material = dict(bound_run_value)
    bound_run_material.pop("record_digest")
    bound_run_value["record_digest"] = hashlib.sha256(
        canonical_json(bound_run_material)
    ).hexdigest()
    bound_run = RunRecord.model_validate(bound_run_value)
    (run_dir / "run.json").write_bytes(
        canonical_json(bound_run.model_dump(mode="json")) + b"\n"
    )
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_bytes(
        canonical_json(baseline.model_dump(mode="json")) + b"\n"
    )

    with pytest.raises(ReportInputError, match="bound baseline"):
        rebuild_report(run_dir)

    report = rebuild_report(run_dir, baseline_record_path=baseline_path)
    assert report.baseline_linkage["baseline_id"] == "baseline-demo"
    assert report.baseline_linkage["baseline_record_digest"] == baseline.record_digest

    changed = baseline.model_dump(mode="json")
    changed["initial_commit"] = "0" * 40
    changed["record_digest"] = "0" * 64
    changed_material = dict(changed)
    changed_material.pop("record_digest")
    changed["record_digest"] = hashlib.sha256(
        canonical_json(changed_material)
    ).hexdigest()
    baseline_path.write_bytes(canonical_json(changed) + b"\n")
    with pytest.raises(ReportInputError, match="record binding differs"):
        rebuild_report(run_dir, baseline_record_path=baseline_path)

    changed_baseline = BaselineRunRecord.model_validate(changed)
    changed_bound_run = bind_baseline(run, changed_baseline)
    (run_dir / "run.json").write_bytes(
        canonical_json(changed_bound_run.model_dump(mode="json")) + b"\n"
    )
    with pytest.raises(ReportInputError, match="comparison binding differs"):
        rebuild_report(run_dir, baseline_record_path=baseline_path)
