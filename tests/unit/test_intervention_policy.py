from __future__ import annotations

import hashlib
import json
import os

import pytest

from shadow_mission.auth import (
    AuthenticationError,
    generate_run_secret,
    write_signed_private_state,
)
from shadow_mission.protocol import RepairAssignment, canonical_json
from shadow_mission.router import (
    InterventionLatchStore,
    InterventionPolicyError,
    InterventionRouter,
    InterventionRouterDelta,
    InterventionRouterState,
)
from shadow_mission.storage import review_state_component
from tests.unit.test_router import (
    RUN_ID,
    VERIFIER,
    add_role,
    commit,
    event,
    make_capabilities,
    make_finding,
    make_graph,
    make_probe,
    stored_evidence,
)


def latched_router(tmp_path, *, graph=None, capabilities=None):
    store = InterventionLatchStore(
        tmp_path / "private", run_id=RUN_ID, secret=generate_run_secret()
    )
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=graph or make_graph(),
        capabilities=capabilities or make_capabilities(),
        probe_verifier=VERIFIER,
        latch_store=store,
    )
    return router, store


def repair_assignment(
    intervention_id: str,
    *,
    worker: str = "repair-worker",
    feature: str = "feature-checkout",
    assigned_at: int = 102,
) -> RepairAssignment:
    return RepairAssignment(
        assignment_id=f"assignment-{intervention_id}-{worker}",
        intervention_id=intervention_id,
        run_id=RUN_ID,
        original_feature=feature,
        worker_session=worker,
        worker_role_id=f"role-{worker}",
        assigned_at=assigned_at,
    )


def test_ordered_history_supports_repeated_state_and_rejects_invalid_skip() -> None:
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=make_graph(),
        capabilities=make_capabilities(),
        probe_verifier=VERIFIER,
    )
    finding = make_finding(level="blocker", probe_status="confirmed")
    probe = make_probe(finding)
    plan = router.plan_response(
        event("worker-target", "Stop", 100), findings=(finding,), probes=(probe,)
    )
    commit(plan)
    item = router.snapshot().interventions[0]
    assert tuple(entry.action for entry in item.transition_history) == (
        "queued",
        "delivered",
        "blocked_attempt",
    )
    assert item.transition_history[-1].state == item.transition_history[-2].state





def test_collector_observed_target_evidence_advances_intervention() -> None:
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=make_graph(),
        capabilities=make_capabilities(),
        probe_verifier=VERIFIER,
    )
    finding = make_finding(level="concern", probe_status="inconclusive")
    probe = make_probe(finding, status="inconclusive")
    delivered = router.plan_response(
        event("worker-target", "PostToolUse", 100),
        findings=(finding,),
        probes=(probe,),
    )
    commit(delivered)
    intervention_id = delivered.guidance_ids[0]
    acknowledgment = stored_evidence(
        evidence_id="collector-observed-ack",
        kind="target_acknowledgment",
        source="target_assistant_transcript",
        observed_at=101,
        intervention_id=intervention_id,
    ).model_copy(update={"provenance_status": "collector_observed"})

    acknowledged = router.plan_response(
        event("worker-target", "PostToolUse", 101),
        findings=(finding,),
        probes=(probe,),
        stored_evidence=(acknowledgment,),
    )
    commit(acknowledged)

    assert router.snapshot().interventions[0].state == "acknowledged"


def test_acknowledged_concern_defers_completion_for_source_correction() -> None:
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=make_graph(),
        capabilities=make_capabilities(),
        probe_verifier=VERIFIER,
    )
    finding = make_finding(level="concern", probe_status="inconclusive")
    probe = make_probe(finding, status="inconclusive")
    delivered = router.plan_response(
        event("worker-target", "PostToolUse", 100),
        findings=(finding,),
        probes=(probe,),
    )
    commit(delivered)
    intervention_id = delivered.guidance_ids[0]
    acknowledgment = stored_evidence(
        evidence_id="target-ack",
        kind="target_acknowledgment",
        source="target_assistant_transcript",
        observed_at=101,
        intervention_id=intervention_id,
    )

    first_stop = router.plan_response(
        event("worker-target", "Stop", 101),
        findings=(finding,),
        probes=(probe,),
        stored_evidence=(acknowledgment,),
    )
    assert first_stop.body["decision"] == "block"
    assert "do not stop after acknowledgment" in first_stop.body["reason"]
    assert "make or delegate source changes" in first_stop.body["reason"]
    commit(first_stop)

    second_stop = router.plan_response(
        event("worker-target", "Stop", 102),
        findings=(finding,),
        probes=(probe,),
    )
    assert second_stop.body["decision"] == "block"
    commit(second_stop)

    released = router.plan_response(
        event("worker-target", "Stop", 103),
        findings=(finding,),
        probes=(probe,),
    )
    assert released.body == {}
    assert router.intervention(intervention_id).attempts == 2


def test_acknowledged_concern_hold_expires_after_600_seconds() -> None:
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=make_graph(),
        capabilities=make_capabilities(),
        probe_verifier=VERIFIER,
    )
    finding = make_finding(level="concern", probe_status="inconclusive")
    probe = make_probe(finding, status="inconclusive")
    delivered = router.plan_response(
        event("worker-target", "PostToolUse", 100),
        findings=(finding,),
        probes=(probe,),
    )
    commit(delivered)
    intervention_id = delivered.guidance_ids[0]
    acknowledgment = stored_evidence(
        evidence_id="target-ack-deadline",
        kind="target_acknowledgment",
        source="target_assistant_transcript",
        observed_at=101,
        intervention_id=intervention_id,
    )
    first_stop = router.plan_response(
        event("worker-target", "Stop", 101),
        findings=(finding,),
        probes=(probe,),
        stored_evidence=(acknowledgment,),
    )
    commit(first_stop)

    expired = router.plan_response(
        event("worker-target", "Stop", 701),
        findings=(finding,),
        probes=(probe,),
    )

    assert expired.body == {}
    assert router.intervention(intervention_id).attempts == 1

def test_two_attempts_then_terminal_failure_blocks_fourth_stop_until_ack() -> None:
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=make_graph(),
        capabilities=make_capabilities(),
        probe_verifier=VERIFIER,
    )
    finding = make_finding(level="blocker", probe_status="confirmed")
    probe = make_probe(finding)
    first = router.plan_response(
        event("worker-target", "Stop", 100), findings=(finding,), probes=(probe,)
    )
    assert first.body["decision"] == "block"
    commit(first)
    item = router.snapshot().interventions[0]
    assert item.attempts == 1
    assert item.deadline == 700
    second = router.plan_response(
        event("worker-target", "Stop", 101), findings=(finding,), probes=(probe,)
    )
    commit(second)
    assert router.snapshot().interventions[0].attempts == 2
    terminal = router.plan_response(
        event("worker-target", "Stop", 102), findings=(finding,), probes=(probe,)
    )
    assert "mandatory Mission termination and failure" in terminal.body["reason"]
    commit(terminal)
    item = router.snapshot().interventions[0]
    assert item.state == "expired"
    assert item.terminal_outcome == "mission_termination_required"

    fourth = router.plan_response(
        event("worker-target", "Stop", 103), findings=(finding,), probes=(probe,)
    )
    assert "mandatory Mission termination and failure" in fourth.body["reason"]
    commit(fourth)
    assert router.snapshot().interventions[0].state == "expired"

    wrong_ack = stored_evidence(
        evidence_id="termination-wrong",
        kind="child_termination_acknowledgment",
        source="hook_event",
        observed_at=104,
        intervention_id="intervention-unrelated",
    )
    ignored = router.plan_response(
        event("worker-target", "PostToolUse", 104),
        findings=(finding,),
        probes=(probe,),
        stored_evidence=(wrong_ack,),
    )
    commit(ignored)
    assert router.snapshot().interventions[0].state == "expired"

    exact_ack = stored_evidence(
        evidence_id="termination-exact",
        kind="child_termination_acknowledgment",
        source="hook_event",
        observed_at=105,
        intervention_id=item.intervention_id,
    )
    acknowledged = router.plan_response(
        event("worker-target", "PostToolUse", 105),
        findings=(finding,),
        probes=(probe,),
        stored_evidence=(exact_ack,),
    )
    commit(acknowledged)
    item = router.snapshot().interventions[0]
    assert item.state == "termination_acknowledged"
    assert item.termination_acknowledgment_evidence_id == "termination-exact"
    released = router.plan_response(
        event("worker-target", "Stop", 106), findings=(finding,), probes=(probe,)
    )
    assert released.body == {}


def test_deadline_expires_at_exactly_600_seconds() -> None:
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=make_graph(),
        capabilities=make_capabilities(),
        probe_verifier=VERIFIER,
    )
    finding = make_finding(level="blocker", probe_status="confirmed")
    probe = make_probe(finding)
    first = router.plan_response(
        event("worker-target", "Stop", 100), findings=(finding,), probes=(probe,)
    )
    commit(first)
    deadline = router.plan_response(
        event("worker-target", "Stop", 700), findings=(finding,), probes=(probe,)
    )
    assert "mandatory Mission termination and failure" in deadline.body["reason"]
    commit(deadline)
    assert router.snapshot().interventions[0].deadline == 700
    assert router.snapshot().interventions[0].state == "expired"


def test_out_of_order_event_timestamps_do_not_break_generation_cas(tmp_path) -> None:
    router, store = latched_router(tmp_path)
    finding = make_finding(level="blocker", probe_status="confirmed")
    probe = make_probe(finding)
    first = router.plan_response(
        event("worker-target", "Stop", 100), findings=(finding,), probes=(probe,)
    )
    commit(first)
    second = router.plan_response(
        event("worker-target", "Stop", 90), findings=(finding,), probes=(probe,)
    )
    commit(second)
    state = store.load(expected_generation=router.snapshot().generation)
    assert state.interventions[0].deadline == 700
    assert [entry.observed_at for entry in state.interventions[0].transition_history][-1] == 90


def test_notification_cancellation_is_terminal_and_never_restarts() -> None:
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=make_graph(),
        capabilities=make_capabilities(),
        probe_verifier=VERIFIER,
    )
    finding = make_finding()
    queued = router.plan_response(
        event("worker-sibling", "PostToolUse", 10), findings=(finding,)
    )
    commit(queued)
    intervention_id = router.snapshot().interventions[0].intervention_id
    cancelled = router.plan_response(
        event("worker-sibling", "PostToolUse", 11),
        findings=(finding,),
        cancelled_interventions=(intervention_id,),
    )
    commit(cancelled)
    assert router.intervention(intervention_id).state == "quarantined"
    retry = router.plan_response(
        event("worker-target", "PostToolUse", 12), findings=(finding,)
    )
    assert retry.body == {}
    commit(retry)
    assert len(router.snapshot().interventions) == 1


def test_mission_fallback_accepts_strict_exact_fresh_repair_assignment() -> None:
    graph = make_graph(repair=True)
    capabilities = make_capabilities(worker_block="fallback", mission_block="pass")
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=graph,
        capabilities=capabilities,
        probe_verifier=VERIFIER,
    )
    finding = make_finding(level="blocker", probe_status="confirmed")
    probe = make_probe(finding)
    worker_stop = router.plan_response(
        event("worker-target", "SubagentStop", 100),
        findings=(finding,),
        probes=(probe,),
        original_features={finding.finding_id: "feature-checkout"},
    )
    assert worker_stop.body == {}
    commit(worker_stop)
    request = router.plan_response(
        event("orchestrator", "Stop", 101),
        findings=(finding,),
        probes=(probe,),
        original_features={finding.finding_id: "feature-checkout"},
    )
    assert "create exactly one repair worker" in request.body["reason"]
    commit(request)
    intervention_id = router.snapshot().interventions[0].intervention_id
    assignment = router.plan_response(
        event("orchestrator", "PostToolUse", 102),
        findings=(finding,),
        probes=(probe,),
        original_features={finding.finding_id: "feature-checkout"},
        repair_assignments=(repair_assignment(intervention_id),),
    )
    commit(assignment)
    assert router.intervention(intervention_id).state == "repair_assigned"
    repair_guidance = router.plan_response(
        event("repair-worker", "PostToolUse", 104),
        findings=(finding,),
        probes=(probe,),
    )
    context = repair_guidance.body["hookSpecificOutput"]["additionalContext"]
    assert "pause this path" in context


def test_orchestrator_stop_applies_exact_stored_repair_worker_correction() -> None:
    graph = make_graph(repair=True)
    capabilities = make_capabilities(worker_block="fallback", mission_block="pass")
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=graph,
        capabilities=capabilities,
        probe_verifier=VERIFIER,
    )
    finding = make_finding(
        level="blocker",
        probe_status="confirmed",
        suffix="repair-stop-evidence",
    )
    probe = make_probe(finding)
    requested = router.plan_response(
        event("orchestrator", "Stop", 100),
        findings=(finding,),
        probes=(probe,),
        original_features={finding.finding_id: "feature-checkout"},
    )
    commit(requested)
    intervention_id = router.snapshot().interventions[0].intervention_id
    assigned = router.plan_response(
        event("orchestrator", "PostToolUse", 102),
        findings=(finding,),
        probes=(probe,),
        repair_assignments=(repair_assignment(intervention_id),),
    )
    commit(assigned)
    commit(
        router.plan_response(
            event("repair-worker", "PostToolUse", 103),
            findings=(finding,),
            probes=(probe,),
        )
    )
    acknowledgment = stored_evidence(
        evidence_id="repair-stop-ack",
        kind="target_acknowledgment",
        source="target_assistant_transcript",
        observed_at=104,
        session="repair-worker",
        intervention_id=intervention_id,
    )
    commit(
        router.plan_response(
            event("repair-worker", "PostToolUse", 104),
            findings=(finding,),
            probes=(probe,),
            stored_evidence=(acknowledgment,),
        )
    )
    correction = stored_evidence(
        evidence_id="repair-stop-correction",
        kind="target_correction",
        source="target_test_transcript",
        observed_at=105,
        session="repair-worker",
        intervention_id=intervention_id,
    )
    sibling = stored_evidence(
        evidence_id="repair-stop-sibling",
        kind="target_correction",
        source="target_test_transcript",
        observed_at=105,
        session="worker-sibling",
        intervention_id=intervention_id,
    )

    source_change = stored_evidence(
        evidence_id="repair-stop-diff",
        kind="target_correction",
        source="target_diff_transcript",
        observed_at=105,
        session="repair-worker",
        intervention_id=intervention_id,
    )

    stop = router.plan_response(
        event("orchestrator", "Stop", 105),
        findings=(finding,),
        probes=(probe,),
        stored_evidence=(sibling, correction, source_change),
    )

    assert stop.body == {}
    commit(stop)
    intervention = router.intervention(intervention_id)
    assert intervention.state == "resolved"
    assert intervention.correction_evidence_ids == (
        "repair-stop-correction",
        "repair-stop-diff",
        "repair-stop-sibling",
    )


def test_repair_assignment_rejects_feature_mismatch_low_confidence_and_reuse() -> None:
    graph = make_graph(repair=True)
    add_role(graph, "repair-low", "worker", confidence="low")
    capabilities = make_capabilities(worker_block="fallback", mission_block="pass")

    def requested_router(suffix: str):
        router = InterventionRouter(
            run_id=RUN_ID,
            graph=graph,
            capabilities=capabilities,
            probe_verifier=VERIFIER,
        )
        finding = make_finding(
            level="blocker", probe_status="confirmed", suffix=suffix
        )
        probe = make_probe(finding)
        plan = router.plan_response(
            event("orchestrator", "Stop", 100),
            findings=(finding,),
            probes=(probe,),
            original_features={finding.finding_id: f"feature-{suffix}"},
        )
        commit(plan)
        return router, finding, probe, router.snapshot().interventions[0].intervention_id

    mismatch_router, finding, probe, intervention_id = requested_router("mismatch")
    with pytest.raises(InterventionPolicyError, match="feature binding"):
        mismatch_router.plan_response(
            event("orchestrator", "PostToolUse", 102),
            findings=(finding,),
            probes=(probe,),
            repair_assignments=(
                repair_assignment(intervention_id, feature="feature-unrelated"),
            ),
        )

    low_router, finding, probe, intervention_id = requested_router("low")
    with pytest.raises(InterventionPolicyError, match="high-confidence"):
        low_router.plan_response(
            event("orchestrator", "PostToolUse", 102),
            findings=(finding,),
            probes=(probe,),
            repair_assignments=(
                repair_assignment(
                    intervention_id,
                    worker="repair-low",
                    feature="feature-low",
                ),
            ),
        )

    findings = (
        make_finding(level="blocker", probe_status="confirmed", suffix="reuse-a"),
        make_finding(level="blocker", probe_status="confirmed", suffix="reuse-b"),
    )
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=graph,
        capabilities=capabilities,
        probe_verifier=VERIFIER,
    )
    features = {item.finding_id: f"feature-{item.finding_id}" for item in findings}
    requested = router.plan_response(
        event("orchestrator", "Stop", 100),
        findings=findings,
        probes=tuple(make_probe(item) for item in findings),
        original_features=features,
    )
    commit(requested)
    first = next(item for item in router.snapshot().interventions if item.state == "repair_requested")
    assigned = router.plan_response(
        event("orchestrator", "PostToolUse", 102),
        findings=findings,
        probes=tuple(make_probe(item) for item in findings),
        original_features=features,
        repair_assignments=(
            repair_assignment(
                first.intervention_id,
                feature=first.original_feature,
            ),
        ),
    )
    commit(assigned)
    guidance = router.plan_response(
        event("repair-worker", "PostToolUse", 103),
        findings=findings,
        probes=tuple(make_probe(item) for item in findings),
    )
    commit(guidance)
    acknowledgment = stored_evidence(
        evidence_id="reuse-ack",
        kind="target_acknowledgment",
        source="target_assistant_transcript",
        observed_at=104,
        session="repair-worker",
        intervention_id=first.intervention_id,
    )
    acknowledged = router.plan_response(
        event("repair-worker", "PostToolUse", 104),
        findings=findings,
        probes=tuple(make_probe(item) for item in findings),
        stored_evidence=(acknowledgment,),
    )
    commit(acknowledged)
    correction = stored_evidence(
        evidence_id="reuse-correction",
        kind="target_correction",
        source="target_test_transcript",
        observed_at=105,
        session="repair-worker",
        intervention_id=first.intervention_id,
    )
    source_change = stored_evidence(
        evidence_id="reuse-diff",
        kind="target_correction",
        source="target_diff_transcript",
        observed_at=105,
        session="repair-worker",
        intervention_id=first.intervention_id,
    )
    corrected = router.plan_response(
        event("repair-worker", "PostToolUse", 105),
        findings=findings,
        probes=tuple(make_probe(item) for item in findings),
        stored_evidence=(correction, source_change),
    )
    commit(corrected)
    resolved = router.plan_response(
        event("repair-worker", "PostToolUse", 106),
        findings=findings,
        probes=tuple(make_probe(item) for item in findings),
    )
    commit(resolved)
    second_request = router.plan_response(
        event("orchestrator", "Stop", 107),
        findings=findings,
        probes=tuple(make_probe(item) for item in findings),
        original_features=features,
    )
    commit(second_request)
    second = next(
        item for item in router.snapshot().interventions
        if item.state == "repair_requested"
    )
    with pytest.raises(InterventionPolicyError, match="reused"):
        router.plan_response(
            event("orchestrator", "PostToolUse", 108),
            findings=findings,
            probes=tuple(make_probe(item) for item in findings),
            original_features=features,
            repair_assignments=(
                repair_assignment(
                    second.intervention_id,
                    feature=second.original_feature,
                ),
            ),
        )


def test_two_targets_keep_independent_deadlines_and_expiry() -> None:
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=make_graph(),
        capabilities=make_capabilities(),
        probe_verifier=VERIFIER,
    )
    finding = make_finding(
        level="blocker",
        probe_status="confirmed",
        suffix="two-targets",
        targets=("worker-target", "worker-sibling"),
    )
    probe = make_probe(finding)
    first = router.plan_response(
        event("worker-target", "Stop", 100), findings=(finding,), probes=(probe,)
    )
    commit(first)
    sibling = router.plan_response(
        event("worker-sibling", "Stop", 200), findings=(finding,), probes=(probe,)
    )
    commit(sibling)
    expired = router.plan_response(
        event("worker-target", "Stop", 700), findings=(finding,), probes=(probe,)
    )
    assert "mandatory Mission termination" in expired.body["reason"]
    commit(expired)
    sibling_later = router.plan_response(
        event("worker-sibling", "Stop", 700), findings=(finding,), probes=(probe,)
    )
    assert sibling_later.body["decision"] == "block"
    assert "mandatory Mission termination" not in sibling_later.body["reason"]


def test_signed_latch_rejects_forgery_cross_run_stale_and_replay(tmp_path) -> None:
    secret = generate_run_secret()
    private_root = tmp_path / "private"
    store = InterventionLatchStore(private_root, run_id=RUN_ID, secret=secret)
    router = InterventionRouter(
        run_id=RUN_ID,
        graph=make_graph(),
        capabilities=make_capabilities(),
        probe_verifier=VERIFIER,
        latch_store=store,
    )
    finding = make_finding(level="blocker", probe_status="confirmed")
    probe = make_probe(finding)
    first = router.plan_response(
        event("worker-target", "Stop", 100), findings=(finding,), probes=(probe,)
    )
    commit(first)
    first_bytes = store.path.read_bytes()
    first_head_bytes = store.head_path.read_bytes()
    first_generation = router.snapshot().generation
    assert store.load(expected_generation=first_generation) == router.snapshot()
    baseline_head = json.loads(first_head_bytes)

    store.head_path.unlink()
    with pytest.raises(AuthenticationError, match="private file"):
        store.load()
    store.head_path.write_bytes(first_head_bytes)
    os.chmod(store.head_path, 0o600)

    forged_head = dict(baseline_head)
    forged_head["state_digest"] = "0" * 64
    store.head_path.write_text(json.dumps(forged_head))
    os.chmod(store.head_path, 0o600)
    with pytest.raises(AuthenticationError, match="signature"):
        store.load()

    for field, mismatch in (
        ("generation", first_generation - 1),
        ("generation", first_generation + 1),
        ("run_id", "run-other"),
    ):
        mismatched_head = {
            key: value for key, value in baseline_head.items() if key != "signature"
        }
        mismatched_head[field] = mismatch
        write_signed_private_state(store.head_path, secret, mismatched_head)
        with pytest.raises(AuthenticationError, match="does not match"):
            store.load()

    store.head_path.unlink()
    store.head_path.symlink_to(store.path)
    with pytest.raises(AuthenticationError, match="unsafe"):
        store.load()
    store.head_path.unlink()
    store.head_path.write_bytes(first_head_bytes)
    os.chmod(store.head_path, 0o644)
    with pytest.raises(AuthenticationError, match="unsafe"):
        store.load()

    malformed_latch = json.loads(first_bytes)
    malformed_latch.pop("signature")
    malformed_latch["state"]["record_digest"] = "0" * 64
    write_signed_private_state(store.path, secret, malformed_latch)
    malformed_head = {
        key: value for key, value in baseline_head.items() if key != "signature"
    }
    malformed_head["state_digest"] = hashlib.sha256(
        canonical_json(malformed_latch["state"])
    ).hexdigest()
    write_signed_private_state(store.head_path, secret, malformed_head)
    with pytest.raises(AuthenticationError, match="state is invalid"):
        store.load()

    store.path.write_bytes(first_bytes)
    store.head_path.write_bytes(first_head_bytes)
    os.chmod(store.path, 0o600)
    os.chmod(store.head_path, 0o600)
    with pytest.raises(AuthenticationError, match="stale or replayed"):
        store.load(expected_generation=first_generation - 1)
    cross_run = InterventionLatchStore(private_root, run_id="run-other", secret=secret)
    with pytest.raises(AuthenticationError, match="run binding"):
        cross_run.load()
    value = json.loads(store.path.read_text())
    value["state"]["generation"] += 1
    store.path.write_text(json.dumps(value))
    os.chmod(store.path, 0o600)
    with pytest.raises(AuthenticationError, match="signature"):
        store.load()
    invalid_fields = json.loads(first_bytes)
    invalid_fields.pop("signature")
    invalid_fields.pop("written_at")
    write_signed_private_state(store.path, secret, invalid_fields)
    with pytest.raises(AuthenticationError, match="fields"):
        store.load()

    store.path.write_bytes(first_bytes)
    os.chmod(store.path, 0o600)
    second = router.plan_response(
        event("worker-target", "Stop", 101), findings=(finding,), probes=(probe,)
    )
    commit(second)
    current_generation = router.snapshot().generation
    store.path.write_bytes(first_bytes)
    os.chmod(store.path, 0o600)
    with pytest.raises(AuthenticationError, match="replayed"):
        store.load(expected_generation=current_generation)


def test_latch_rejects_unsafe_path(tmp_path) -> None:
    with pytest.raises(AuthenticationError, match="unsafe"):
        InterventionLatchStore(
            tmp_path / "private",
            run_id=RUN_ID,
            secret=generate_run_secret(),
            filename="../escape.json",
        )


def test_latch_initialization_requires_new_exact_private_pair(tmp_path: Path) -> None:
    store = InterventionLatchStore(
        tmp_path / "private",
        run_id=RUN_ID,
        secret=generate_run_secret(),
    )

    state = store.initialize(observed_at=100)

    assert state.generation == 0
    assert store.load(expected_generation=0) == state
    assert store.termination_required is False
    with pytest.raises(AuthenticationError, match="already initialized"):
        store.initialize(observed_at=101)
    store.head_path.unlink()
    assert store.termination_required is True


def test_latch_rejects_non_private_root(tmp_path: Path) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o755)
    private_root.chmod(0o755)
    with pytest.raises(AuthenticationError, match="not private"):
        InterventionLatchStore(
            private_root,
            run_id=RUN_ID,
            secret=generate_run_secret(),
        )


def test_outage_advance_is_reconciled_into_next_replayable_delta(tmp_path) -> None:
    router, store = latched_router(tmp_path)
    finding = make_finding(
        level="blocker",
        probe_status="confirmed",
        suffix="outage-recovery",
    )
    probe = make_probe(finding)
    commit(
        router.plan_response(
            event("worker-target", "Stop", 100),
            findings=(finding,),
            probes=(probe,),
        )
    )
    authoritative = router.snapshot()
    before = authoritative.interventions[0]
    generation = authoritative.generation + 1
    intervention_value = before.model_dump(mode="json")
    intervention_value.update(
        {
            "generation": generation,
            "attempts": before.attempts + 1,
            "transition_history": (
                *intervention_value["transition_history"],
                {
                    "transition_id": f"outage-{generation}",
                    "generation": generation,
                    "state": intervention_value["state"],
                    "action": "blocked_attempt",
                    "observed_at": 101,
                },
            ),
        }
    )
    intervention_value.pop("record_digest")
    intervention_value["record_digest"] = hashlib.sha256(
        canonical_json(intervention_value)
    ).hexdigest()
    advanced_intervention = type(before).model_validate(intervention_value)
    state_value = {
        "schema_version": "0.1",
        "record_type": "intervention_router_state",
        "provenance_status": "hook_authenticated",
        "redaction_status": "clean",
        "run_id": RUN_ID,
        "generation": generation,
        "interventions": (
            advanced_intervention.model_dump(mode="json"),
        ),
    }
    state_value["record_digest"] = hashlib.sha256(
        canonical_json(state_value)
    ).hexdigest()
    outage_state = InterventionRouterState.model_validate(state_value)
    store.write(
        outage_state,
        expected_generation=authoritative.generation,
        observed_at=101,
    )

    recovery = router.plan_response(
        event("worker-target", "Stop", 102),
        findings=(finding,),
        probes=(probe,),
    )
    component = review_state_component(
        recovery.review_state,
        run_id=RUN_ID,
        record_type="intervention_router_delta",
    )
    assert component is not None
    delta = InterventionRouterDelta.model_validate(component)
    assert delta.base_generation == authoritative.generation
    replayed = delta.apply(authoritative)
    assert replayed.generation == outage_state.generation + 1
    assert tuple(
        item.action for item in replayed.interventions[0].transition_history[-2:]
    ) == ("blocked_attempt", "terminal_failure")

    commit(recovery)
    assert router.snapshot() == replayed
    assert store.load(expected_generation=replayed.generation) == replayed
