from __future__ import annotations

import hashlib
from pathlib import Path

from shadow_mission.metrics import compute_outcome_metrics, validate_baseline_binding
from shadow_mission.protocol import (
    HookEnvelope,
    HookExchangeRecord,
    HookResponseRecord,
    InterventionRecord,
    InterventionTransition,
    canonical_json,
    hook_envelope_digest,
    hook_response_digest,
)
from shadow_mission.review_journal import (
    JournalFinding,
    ReviewJournal,
    project_intervention_router_state,
)
from shadow_mission.router import InterventionRouterDelta, InterventionRouterState

RUN_ID = "run-metrics"


def with_digest(model_type, value: dict) -> dict:
    result = model_type.model_construct(
        record_digest="0" * 64,
        **value,
    ).model_dump(mode="json")
    result.pop("record_digest")
    result["record_digest"] = hashlib.sha256(canonical_json(result)).hexdigest()
    return result


def finding(rule: str, suffix: str) -> JournalFinding:
    return JournalFinding(
        finding_id=f"finding-{suffix}",
        dedup_key=hashlib.sha256(suffix.encode()).hexdigest(),
        rule=rule,
        level="concern",
        target_sessions=("worker-a", "worker-b"),
        claim_ids=(f"claim-{suffix}-a", f"claim-{suffix}-b"),
        evidence_ids=(f"evidence-{suffix}-a", f"evidence-{suffix}-b"),
        evidence_digests=("1" * 64, "2" * 64),
        normalized_locators=("api-schema.json#/payment/amount",),
        normalized_properties=("unit",),
        normalized_units=("cents",),
        normalized_values=("cents", "dollars"),
        authority_status="resolved",
        authority_level=3,
        authority_value="cents",
        risk_category="public_contract",
        probe_status="confirmed",
        probe_id=f"probe-{suffix}",
    )


def intervention(
    *,
    target_session: str = "worker-a",
    final_state: str = "delivered",
    probe_status: str = "confirmed",
) -> InterventionRecord:
    states_by_final = {
        "queued": ("queued",),
        "delivered": ("queued", "delivered"),
        "resolved": ("queued", "delivered", "acknowledged", "corrected", "resolved"),
    }
    states = states_by_final[final_state]
    transitions = tuple(
        InterventionTransition(
            transition_id=f"transition-{target_session}-{state}",
            generation=index,
            state=state,
            action=state,
            observed_at=9 + index,
        )
        for index, state in enumerate(states, start=1)
    )
    generation = len(states)
    resolved = final_state == "resolved"
    return InterventionRecord.model_validate(
        with_digest(
            InterventionRecord,
            {
                "schema_version": "0.1",
                "provenance_status": "independent_frozen",
                "redaction_status": "clean",
                "record_type": "intervention_record",
                "intervention_id": f"intervention-{target_session}",
                "run_id": RUN_ID,
                "finding_id": "finding-conflict",
                "finding_dedup_key": hashlib.sha256(b"conflict").hexdigest(),
                "target_session": target_session,
                "completion_session_alias": target_session,
                "rule": "cross_worker_conflict",
                "level": "concern",
                "risk_category": "public_contract",
                "claim_ids": ("claim-conflict-a", "claim-conflict-b"),
                "direct_evidence_ids": ("evidence-a", "evidence-b"),
                "direct_evidence_digests": ("1" * 64, "2" * 64),
                "correction_evidence_ids": ("evidence-correction",) if resolved else (),
                "correction_evidence_digests": ("6" * 64,) if resolved else (),
                "generation": generation,
                "state": states[-1],
                "transition_history": transitions,
                "probe_id": "probe-conflict",
                "probe_digest": "3" * 64,
                "probe_status": probe_status,
                "probe_snapshot_digest": "4" * 64,
                "blocking_scope": "worker",
                "attempts": 0,
            }
        )
    )


def append_delta(
    journal: ReviewJournal,
    *,
    resolved: bool = False,
    items: tuple[InterventionRecord, ...] | None = None,
    record_type: str = "intervention_lineage",
) -> None:
    base = InterventionRouterState.empty(RUN_ID)
    if items is None:
        items = (
            (
                intervention(target_session="worker-a", final_state="resolved"),
                intervention(target_session="worker-b", final_state="resolved"),
            )
            if resolved
            else (intervention(),)
        )
    generation = max(item.generation for item in items)
    final = InterventionRouterState.model_validate(
        with_digest(
            InterventionRouterState,
            {
                "schema_version": "0.1",
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "record_type": "intervention_router_state",
                "run_id": RUN_ID,
                "generation": generation,
                "interventions": items,
            }
        )
    )
    delta = InterventionRouterDelta.model_validate(
        with_digest(
            InterventionRouterDelta,
            {
                "schema_version": "0.1",
                "provenance_status": "hook_authenticated",
                "redaction_status": "clean",
                "record_type": "intervention_router_delta",
                "run_id": RUN_ID,
                "base_generation": 0,
                "base_digest": base.record_digest,
                "generation": generation,
                "upserts": items,
                "result_digest": final.record_digest,
            }
        )
    )
    if record_type == "intervention_lineage":
        journal.append(
            record_type,
            ledger_sequence=1,
            event_id="event-1",
            response_digest="5" * 64,
            delta=delta,
        )
    else:
        journal.append(
            record_type,
            observed_at=1,
            delta=delta,
        )


def test_router_projection_applies_outage_reconciliation(tmp_path: Path) -> None:
    journal = ReviewJournal(tmp_path / "review.jsonl", run_id=RUN_ID)
    append_delta(journal, record_type="outage_reconciliation")

    state = project_intervention_router_state(RUN_ID, journal.records())

    assert state.generation == 2
    assert state.interventions == (intervention(),)


def run_record(*, usage: dict, archive: str = "a" * 64) -> dict:
    return {
        "initial_commit": "1" * 40,
        "mission_digest": "2" * 64,
        "mission_role_config_digest": "3" * 64,
        "factory_profile_digest": "4" * 64,
        "droid_version": "0.197.0",
        "vm_image_digest": "sha256:" + "5" * 64,
        "isolation_digest": "6" * 64,
        "gate_surface_digest": "7" * 64,
        "installed_plugin_artifact_digest": "8" * 64,
        "final_source_archive_digest": archive,
        "usage_data": usage,
    }


def append_snapshot(journal: ReviewJournal, *findings: JournalFinding, active: bool = True) -> None:
    journal.append(
        "finding_snapshot",
        ledger_sequence=1,
        event_id="event-1",
        graph_digest="9" * 64,
        findings=findings,
        validation_overlap_status="active" if active else "disabled_by_role_fallback",
    )


def exchange_with_guidance(guidance_id: str) -> HookExchangeRecord:
    envelope = HookEnvelope(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        event_id="event-guidance",
        source_fingerprint="source-guidance",
        run_id=RUN_ID,
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
        run_id=RUN_ID,
        event_id=envelope.event_id,
        request_digest=hook_envelope_digest(envelope),
        response_body=body,
        response_digest=hook_response_digest(
            response_body=body,
            guidance_ids=(guidance_id,),
            transition_ids=(),
            review_state=None,
        ),
        guidance_ids=(guidance_id,),
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


def test_metrics_compute_escapes_precision_propagation_and_bound_deltas(
    tmp_path: Path,
) -> None:
    journal = ReviewJournal(tmp_path / "review.jsonl", run_id=RUN_ID)
    append_delta(journal)
    append_snapshot(
        journal,
        finding("cross_worker_conflict", "conflict"),
        finding("shared_assumption", "shared"),
    )
    baseline = run_record(
        usage={"status": "available", "basis": "factory-attributed", "total_tokens": 100, "cost_cents": 20},
        archive="b" * 64,
    )
    shadow = run_record(
        usage={"status": "available", "basis": "factory-attributed", "total_tokens": 140, "cost_cents": 25},
    )

    metrics = compute_outcome_metrics(
        run_id=RUN_ID,
        journal_records=journal.records(),
        exchanges=(),
        baseline_record=baseline,
        shadow_record=shadow,
    )

    assert metrics.conflict_escape_count.value == 1
    assert metrics.shared_assumption_escape_count.value == 1
    assert metrics.validation_overlap_escape_count.value == 0
    assert metrics.intervention_precision.value == 1.0
    assert metrics.false_intervention_count.value == 0
    assert metrics.propagation_radius.value["detection"]["sessions"] == 2
    assert metrics.added_usage.value == 40
    assert metrics.added_cost_cents.value == 5
    assert metrics.baseline_archive_digest == "b" * 64
    assert metrics.shadow_archive_digest == "a" * 64


def test_resolved_finding_does_not_escape(tmp_path: Path) -> None:
    journal = ReviewJournal(tmp_path / "review.jsonl", run_id=RUN_ID)
    append_delta(journal, resolved=True)
    append_snapshot(journal, finding("cross_worker_conflict", "conflict"))

    metrics = compute_outcome_metrics(
        run_id=RUN_ID,
        journal_records=journal.records(),
        exchanges=(),
        baseline_record=None,
        shadow_record=run_record(usage={"status": "unavailable"}),
    )

    assert metrics.conflict_escape_count.value == 0


def test_mixed_target_states_leave_finding_as_escape(tmp_path: Path) -> None:
    journal = ReviewJournal(tmp_path / "review.jsonl", run_id=RUN_ID)
    append_delta(
        journal,
        items=(
            intervention(target_session="worker-a", final_state="resolved"),
            intervention(target_session="worker-b", final_state="queued"),
        ),
    )
    append_snapshot(journal, finding("cross_worker_conflict", "conflict"))

    metrics = compute_outcome_metrics(
        run_id=RUN_ID,
        journal_records=journal.records(),
        exchanges=(),
        baseline_record=None,
        shadow_record=run_record(usage={"status": "unavailable"}),
    )

    assert metrics.conflict_escape_count.value == 1


def test_metrics_accept_nonempty_exchange_guidance_lineage(tmp_path: Path) -> None:
    journal = ReviewJournal(tmp_path / "review.jsonl", run_id=RUN_ID)

    metrics = compute_outcome_metrics(
        run_id=RUN_ID,
        journal_records=journal.records(),
        exchanges=(exchange_with_guidance("guidance-1"),),
        baseline_record=None,
        shadow_record=run_record(usage={"status": "unavailable"}),
    )

    assert metrics.intervention_precision.status == "unavailable"


def test_metrics_withhold_probe_metrics_without_a_verdict(tmp_path: Path) -> None:
    for probe_status in ("missing", "pending", "inconclusive"):
        journal = ReviewJournal(
            tmp_path / f"review-{probe_status}.jsonl",
            run_id=RUN_ID,
        )
        append_delta(journal, items=(intervention(probe_status=probe_status),))

        metrics = compute_outcome_metrics(
            run_id=RUN_ID,
            journal_records=journal.records(),
            exchanges=(),
            baseline_record=None,
            shadow_record=run_record(usage={"status": "unavailable"}),
        )

        assert metrics.intervention_precision.status == "unavailable"
        assert metrics.intervention_precision.reason == "no independent probe verdict"
        assert metrics.false_intervention_count.status == "unavailable"
        assert metrics.false_intervention_count.reason == (
            "no independent probe verdict"
        )


def test_metrics_omit_disabled_overlap_and_propagate_unavailable_usage(
    tmp_path: Path,
) -> None:
    journal = ReviewJournal(tmp_path / "review.jsonl", run_id=RUN_ID)
    append_snapshot(journal, active=False)
    baseline = run_record(usage={"status": "unavailable"})
    shadow = run_record(usage={"status": "unavailable"})

    metrics = compute_outcome_metrics(
        run_id=RUN_ID,
        journal_records=journal.records(),
        exchanges=(),
        baseline_record=baseline,
        shadow_record=shadow,
    )

    assert metrics.validation_overlap_escape_count is None
    assert metrics.intervention_precision.status == "unavailable"
    assert metrics.added_usage.status == "unavailable"
    assert metrics.added_cost_cents.status == "unavailable"


def test_baseline_binding_rejects_every_material_mismatch() -> None:
    baseline = run_record(usage={"status": "unavailable"})
    for field in (
        "initial_commit",
        "mission_digest",
        "mission_role_config_digest",
        "factory_profile_digest",
        "mission_relation_source_digest",
        "droid_version",
        "vm_image_digest",
        "isolation_digest",
        "gate_surface_digest",
        "installed_plugin_artifact_digest",
        "approved_evaluator_digest",
        "source_exporter_digest",
    ):
        changed = dict(baseline)
        changed[field] = "different"
        matches, mismatch = validate_baseline_binding(baseline, changed)
        assert matches is False
        assert mismatch == field
