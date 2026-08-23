from __future__ import annotations

import hashlib
import fcntl
import os
import threading
import time
from dataclasses import replace
from typing import Literal

import pytest
import shadow_mission.router as router_module
from shadow_mission.auth import generate_run_secret

from shadow_mission.graph import MissionGraph
from shadow_mission.protocol import (
    CapabilityFlags,
    EvidenceRecord,
    HookEnvelope,
    RepairAssignment,
)
from shadow_mission.roles import RoleDecision
from shadow_mission.router import (
    InterventionLatchStore,
    InterventionLatchLockTimeout,
    InterventionPolicyError,
    InterventionRouter,
)
from shadow_mission.rules import (
    AuthorityResolution,
    EvidenceAuthority,
    Finding,
    ProbeAssessment,
    ProbeVerifier,
)
from shadow_mission.storage import ResponsePlan

RUN_ID = "run-router"
PROBE_KEY = b"router-independent-probe-signing-key"
BOUNDARY_DIGEST = "9" * 64
SNAPSHOT_DIGEST = "8" * 64
VERIFIER = ProbeVerifier(PROBE_KEY, boundary_digest=BOUNDARY_DIGEST)


def make_capabilities(
    *, worker_block: str = "pass", mission_block: str = "pass"
) -> CapabilityFlags:
    return CapabilityFlags(
        core_feasibility_verdict="pass",
        release_gate_verdict="fallback-pass",
        droid_version="0.197.0",
        plugin_version="0.1.0",
        droid_sdk_version="0.2.0",
        lima_version="2.2.0",
        vm_image_digest="1" * 64,
        factory_profile_digest="2" * 64,
        isolation_digest="3" * 64,
        gate_surface_digest="4" * 64,
        installed_plugin_artifact_digest="5" * 64,
        transport_integrity="pass",
        hook_provenance="pass",
        session_hooks="pass",
        identity="pass",
        transcript="pass",
        guidance="pass",
        worker_block=worker_block,
        mission_block=mission_block,
        worker_roles="pass",
        validator_roles="pass",
        self_session_exclusion="pass",
        sandbox_isolation="pass",
        probe_boundary="pass",
        live_validation_overlap="pass",
    )


def add_role(
    graph: MissionGraph,
    session: str,
    kind: Literal["orchestrator", "worker", "validator"],
    *,
    confidence: str = "high",
) -> None:
    graph.add_role_decision(
        RoleDecision(
            session_alias=session,
            role_id=f"role-{session}",
            kind=kind,
            confidence=confidence,
            status="assigned",
            reason="recorded role",
            evidence_digests=("0" * 64,),
        )
    )


def make_graph(*, high_target: bool = True, repair: bool = False) -> MissionGraph:
    graph = MissionGraph(RUN_ID)
    add_role(
        graph,
        "worker-target",
        "worker",
        confidence="high" if high_target else "low",
    )
    add_role(graph, "worker-sibling", "worker")
    add_role(graph, "orchestrator", "orchestrator")
    if repair:
        add_role(graph, "repair-worker", "worker")
        add_role(graph, "repair-worker-two", "worker")
    return graph


def make_finding(
    *,
    level: str = "concern",
    probe_status: str = "pending",
    suffix: str = "router",
    targets: tuple[str, ...] = ("worker-target",),
    risk_category: str = "public_contract",
) -> Finding:
    dedup_key = hashlib.sha256(f"router-finding-{suffix}".encode()).hexdigest()
    return Finding(
        finding_id=f"finding-{suffix}",
        dedup_key=dedup_key,
        rule="cross_worker_conflict",
        level=level,
        target_sessions=targets,
        claim_ids=(f"claim-{suffix}-a", f"claim-{suffix}-b"),
        evidence_ids=(f"direct-{suffix}-a", f"direct-{suffix}-b"),
        evidence_digests=("a" * 64, "b" * 64),
        normalized_locators=("schema.json#/amount",),
        normalized_properties=("unit",),
        normalized_units=("cents",),
        normalized_values=("cents", "dollars"),
        authority=AuthorityResolution(
            "resolved", EvidenceAuthority.AUTHORITATIVE, "cents"
        ),
        risk_category=risk_category,
        probe_status=probe_status,
        probe_id=f"probe-{suffix}" if probe_status != "missing" else None,
    )


def make_probe(
    finding: Finding, *, status: str = "confirmed", run_id: str = RUN_ID
) -> ProbeAssessment:
    return ProbeAssessment.create(
        probe_id=f"probe-{finding.finding_id}",
        run_id=run_id,
        finding_dedup_key=finding.dedup_key,
        claim_ids=finding.claim_ids,
        evidence_digests=finding.evidence_digests,
        risk_category=finding.risk_category,
        recommended_level=finding.level,
        status=status,
        authoritative_value="cents" if status == "confirmed" else None,
        snapshot_digest=SNAPSHOT_DIGEST,
        boundary_digest=BOUNDARY_DIGEST,
        boundary_policy_digest=BOUNDARY_DIGEST,
        signing_key=PROBE_KEY,
        observed_at=5,
    )


def event(
    session: str, name: str, observed_at: int, *, event_id: str | None = None
) -> HookEnvelope:
    return HookEnvelope(provenance_status="hook_authenticated",
    redaction_status="clean",
    event_id=event_id or f"event-{session}-{name}-{observed_at}",
    source_fingerprint=f"source-{session}",
    run_id=RUN_ID,
    session_alias=session,
    transcript_alias=f"transcript-{session}",
    cwd_alias="cwd-a",
    hook_event_name=name, observed_at=observed_at, message_digest="d" * 64, payload={},)


def stored_evidence(
    *,
    evidence_id: str,
    kind: str,
    source: str,
    observed_at: int,
    session: str = "worker-target",
    intervention_id: str | None = None,
) -> EvidenceRecord:
    return EvidenceRecord(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        evidence_id=evidence_id,
        run_id=RUN_ID,
        session_alias=session,
        kind=kind,
        source=source,
        locator=f"event:{evidence_id}",
        digest=hashlib.sha256(evidence_id.encode()).hexdigest(),
        intervention_id=intervention_id,
        observed_at=observed_at,
    )


def make_router(
    *, graph: MissionGraph | None = None, capabilities: CapabilityFlags | None = None
) -> InterventionRouter:
    actual_graph = graph or make_graph()
    return InterventionRouter(
        run_id=RUN_ID,
        graph=actual_graph,
        capabilities=capabilities or make_capabilities(),
        probe_verifier=VERIFIER,
    )


def commit(plan) -> None:
    assert plan.commit is not None
    plan.commit()


def test_post_tool_use_is_exact_and_target_only() -> None:
    router = make_router()
    finding = make_finding()
    sibling = router.plan_response(
        event("worker-sibling", "PostToolUse", 10), findings=(finding,)
    )
    assert sibling.body == {}
    commit(sibling)
    target = router.plan_response(
        event("worker-target", "PostToolUse", 11), findings=(finding,)
    )
    context = target.body["hookSpecificOutput"]["additionalContext"]
    marker = context.split()[0]
    assert target.body == {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": (
                f"{marker} cross_worker_conflict concern: pause this path. "
                f"Repeat {marker} in your next response and state which source "
                "you will inspect. The mixed values are the defect; do not preserve "
                "a per-boundary split. Change the source files named in the "
                "evidence below, not the record that reports the disagreement. "
                "Before validation, make or delegate source changes that use one "
                "unit and one declared type for this property across every listed "
                "locator and affected consumer. Convert values at each boundary "
                "instead of rejecting inputs, and keep the field names every "
                "consumer already reads. Documentation, acknowledgment, or "
                "validation alone does not resolve this intervention. Run one "
                "end-to-end test that carries a single amount through every "
                "listed locator and consumer, and assert its value and type at "
                "each boundary before completion."
                " Evidence: locator schema.json#/amount; property unit; "
                "observed values cents, dollars; units cents; "
                "authoritative value cents."
            ),
        }
    }
    assert marker.startswith("[shadow:intervention-")
    commit(target)


def test_low_confidence_role_receives_no_intervention() -> None:
    router = make_router(graph=make_graph(high_target=False))
    plan = router.plan_response(
        event("worker-target", "PostToolUse", 10), findings=(make_finding(),)
    )
    assert plan.body == {}
    assert plan.guidance_ids == ()
    commit(plan)
    assert router.snapshot().interventions == ()


def test_evidence_requires_exact_intervention_and_two_same_session_do_not_cross() -> None:
    router = make_router()
    findings = (
        make_finding(suffix="one"),
        make_finding(suffix="two"),
    )
    first = router.plan_response(
        event("worker-target", "PostToolUse", 10), findings=findings
    )
    commit(first)
    first_id = first.guidance_ids[0]
    second = router.plan_response(
        event("worker-target", "PostToolUse", 11), findings=findings
    )
    commit(second)
    second_id = second.guidance_ids[0]
    assert first_id != second_id

    unrelated = stored_evidence(
        evidence_id="ack-unbound",
        kind="acknowledgment",
        source="hook_event",
        observed_at=12,
    )
    ignored = router.plan_response(
        event("worker-target", "PostToolUse", 12),
        findings=findings,
        stored_evidence=(unrelated,),
    )
    commit(ignored)
    assert router.intervention(first_id).state == "delivered"
    assert router.intervention(second_id).state == "delivered"

    exact = stored_evidence(
        evidence_id="ack-one",
        kind="target_acknowledgment",
        source="target_assistant_transcript",
        observed_at=13,
        intervention_id=first_id,
    )
    acknowledged = router.plan_response(
        event("worker-target", "PostToolUse", 13),
        findings=findings,
        stored_evidence=(exact,),
    )
    commit(acknowledged)
    assert router.intervention(first_id).state == "acknowledged"
    assert router.intervention(second_id).state == "delivered"


def test_growing_evidence_extends_one_intervention_for_one_conflict() -> None:
    router = make_router()
    finding = make_finding(suffix="growing")
    grown = replace(
        finding,
        claim_ids=(*finding.claim_ids, "claim-growing-c"),
        evidence_ids=(*finding.evidence_ids, "direct-growing-c"),
        evidence_digests=(*finding.evidence_digests, "c" * 64),
    )
    first = router.plan_response(
        event("worker-target", "PostToolUse", 10), findings=(finding,)
    )
    commit(first)
    intervention_id = first.guidance_ids[0]
    assert router.intervention(intervention_id).direct_evidence_digests == (
        "a" * 64,
        "b" * 64,
    )

    extended = router.plan_response(
        event("worker-target", "PostToolUse", 11), findings=(grown,)
    )
    commit(extended)
    record = router.intervention(intervention_id)

    assert len(router.snapshot().interventions) == 1
    assert record.state == "delivered"
    assert record.claim_ids == grown.claim_ids
    assert record.direct_evidence_ids == grown.evidence_ids
    assert record.direct_evidence_digests == grown.evidence_digests
    assert "evidence_extended" in {
        transition.action for transition in record.transition_history
    }


def test_cross_session_correction_proof_resolves_the_intervention() -> None:
    router = make_router()
    finding = make_finding(suffix="cross")
    delivered = router.plan_response(
        event("worker-target", "PostToolUse", 10), findings=(finding,)
    )
    commit(delivered)
    intervention_id = delivered.guidance_ids[0]
    sibling_proof = (
        stored_evidence(
            evidence_id="cross-diff",
            kind="target_correction",
            source="target_diff_transcript",
            observed_at=11,
            session="worker-sibling",
            intervention_id=intervention_id,
        ),
        stored_evidence(
            evidence_id="cross-test",
            kind="target_correction",
            source="target_test_transcript",
            observed_at=11,
            session="worker-sibling",
            intervention_id=intervention_id,
        ),
    )

    closed = router.plan_response(
        event("worker-target", "PostToolUse", 12),
        findings=(finding,),
        stored_evidence=sibling_proof,
    )
    commit(closed)
    record = router.intervention(intervention_id)

    assert record.state == "resolved"
    assert record.terminal_outcome == "corrected"
    assert record.correction_evidence_ids == ("cross-diff", "cross-test")


def test_an_acknowledgment_still_requires_the_target_session() -> None:
    router = make_router()
    finding = make_finding(suffix="ack-session")
    delivered = router.plan_response(
        event("worker-target", "PostToolUse", 10), findings=(finding,)
    )
    commit(delivered)
    intervention_id = delivered.guidance_ids[0]
    foreign = stored_evidence(
        evidence_id="foreign-ack",
        kind="target_acknowledgment",
        source="target_assistant_transcript",
        observed_at=11,
        session="worker-sibling",
        intervention_id=intervention_id,
    )

    ignored = router.plan_response(
        event("worker-target", "PostToolUse", 12),
        findings=(finding,),
        stored_evidence=(foreign,),
    )
    commit(ignored)

    assert router.intervention(intervention_id).state == "delivered"


def test_a_resolved_locus_keeps_one_record_and_never_reopens() -> None:
    """One conflict keeps one intervention per target for the whole Mission.

    A successor record after a terminal state would leave the finding
    permanently unresolved, so later evidence at a resolved locus is ignored.
    """

    router = make_router()
    finding = make_finding(suffix="recurring")
    delivered = router.plan_response(
        event("worker-target", "PostToolUse", 10), findings=(finding,)
    )
    commit(delivered)
    first_id = delivered.guidance_ids[0]
    proof = (
        stored_evidence(
            evidence_id="rec-diff",
            kind="target_correction",
            source="target_diff_transcript",
            observed_at=11,
            intervention_id=first_id,
        ),
        stored_evidence(
            evidence_id="rec-test",
            kind="target_correction",
            source="target_test_transcript",
            observed_at=11,
            intervention_id=first_id,
        ),
    )
    closed = router.plan_response(
        event("worker-target", "PostToolUse", 12),
        findings=(finding,),
        stored_evidence=proof,
    )
    commit(closed)
    assert router.intervention(first_id).state == "resolved"
    resolved_history = router.intervention(first_id).transition_history

    later = replace(
        finding,
        claim_ids=(*finding.claim_ids, "claim-recurring-c"),
        evidence_ids=(*finding.evidence_ids, "direct-recurring-c"),
        evidence_digests=(*finding.evidence_digests, "c" * 64),
    )
    again = router.plan_response(
        event("worker-target", "PostToolUse", 13), findings=(later,)
    )
    commit(again)
    records = router.snapshot().interventions
    record = router.intervention(first_id)

    assert len(records) == 1
    assert record.state == "resolved"
    assert record.transition_history == resolved_history
    assert record.direct_evidence_digests == finding.evidence_digests


def test_exact_acknowledgment_then_correction_clears() -> None:
    router = make_router()
    finding = make_finding(level="blocker", probe_status="confirmed")
    probe = make_probe(finding)
    delivered = router.plan_response(
        event("worker-target", "PostToolUse", 10),
        findings=(finding,),
        probes=(probe,),
    )
    commit(delivered)
    intervention_id = router.snapshot().interventions[0].intervention_id
    shared = stored_evidence(
        evidence_id="ack-shared",
        kind="target_acknowledgment",
        source="repository_output",
        observed_at=11,
        intervention_id=intervention_id,
    )
    ignored = router.plan_response(
        event("worker-target", "PostToolUse", 12),
        findings=(finding,),
        probes=(probe,),
        stored_evidence=(shared,),
    )
    commit(ignored)
    assert router.intervention(intervention_id).state == "delivered"
    acknowledgment = stored_evidence(
        evidence_id="ack-direct",
        kind="target_acknowledgment",
        source="target_assistant_transcript",
        observed_at=15,
        intervention_id=intervention_id,
    )
    acknowledged = router.plan_response(
        event("worker-target", "PostToolUse", 16),
        findings=(finding,),
        probes=(probe,),
        stored_evidence=(acknowledgment,),
    )
    commit(acknowledged)
    generic_tool_result = stored_evidence(
        evidence_id="generic-command",
        kind="command_result",
        source="tool",
        observed_at=17,
        intervention_id=intervention_id,
    )
    ignored_tool = router.plan_response(
        event("worker-target", "PostToolUse", 17),
        findings=(finding,),
        probes=(probe,),
        stored_evidence=(generic_tool_result,),
    )
    commit(ignored_tool)
    assert router.intervention(intervention_id).state == "acknowledged"
    correction = stored_evidence(
        evidence_id="correction-direct",
        kind="target_correction",
        source="target_diff_transcript",
        observed_at=17,
        intervention_id=intervention_id,
    )
    corrected = router.plan_response(
        event("worker-target", "PostToolUse", 18),
        findings=(finding,),
        probes=(probe,),
        stored_evidence=(correction,),
    )
    commit(corrected)
    # A source change alone never resolves the finding.
    assert router.intervention(intervention_id).state == "acknowledged"
    intervention = router.intervention(intervention_id)
    assert intervention is not None
    assert intervention.correction_evidence_ids == ("correction-direct",)
    assert intervention.correction_evidence_digests == (correction.digest,)
    passing_test = stored_evidence(
        evidence_id="correction-test",
        kind="target_correction",
        source="target_test_transcript",
        observed_at=18,
        intervention_id=intervention_id,
    )
    proven = router.plan_response(
        event("worker-target", "PostToolUse", 19),
        findings=(finding,),
        probes=(probe,),
        stored_evidence=(correction, passing_test),
    )
    commit(proven)
    completion = router.plan_response(
        event("worker-target", "Stop", 20), findings=(finding,), probes=(probe,)
    )
    assert completion.body == {}
    commit(completion)
    assert router.intervention(intervention_id).state == "resolved"


def test_direct_correction_without_acknowledgment_resolves() -> None:
    router = make_router()
    finding = make_finding(suffix="direct-correction")
    delivered = router.plan_response(
        event("worker-target", "PostToolUse", 10),
        findings=(finding,),
    )
    commit(delivered)
    intervention_id = delivered.guidance_ids[0]
    source_change = stored_evidence(
        evidence_id="direct-source-change",
        kind="target_correction",
        source="target_diff_transcript",
        observed_at=11,
        intervention_id=intervention_id,
    )
    passing_test = stored_evidence(
        evidence_id="direct-passing-test",
        kind="target_correction",
        source="target_test_transcript",
        observed_at=11,
        intervention_id=intervention_id,
    )

    corrected = router.plan_response(
        event("worker-target", "PostToolUse", 12),
        findings=(finding,),
        stored_evidence=(source_change, passing_test),
    )
    commit(corrected)

    intervention = router.intervention(intervention_id)
    assert intervention is not None
    assert intervention.state == "resolved"
    assert intervention.correction_evidence_ids == (
        "direct-passing-test",
        "direct-source-change",
    )
    assert tuple(
        transition.state for transition in intervention.transition_history[-2:]
    ) == ("corrected", "resolved")


def test_incomplete_proof_records_bind_without_claiming_correction() -> None:
    router = make_router()
    test_findings = tuple(
        make_finding(suffix=f"test-only-{index}") for index in range(5)
    )
    source_finding = make_finding(suffix="source-only")
    findings = (*test_findings, source_finding)
    for update in range(len(findings)):
        commit(
            router.plan_response(
                event("worker-target", "PostToolUse", 10 + update),
                findings=findings,
            )
        )
    interventions_by_finding = {
        item.finding_dedup_key: item for item in router.snapshot().interventions
    }
    corrections = tuple(
        stored_evidence(
            evidence_id=f"passing-test-{index}",
            kind="target_correction",
            source="target_test_transcript",
            observed_at=20,
            intervention_id=interventions_by_finding[
                finding.dedup_key
            ].intervention_id,
        )
        for index, finding in enumerate(test_findings)
    ) + (
        stored_evidence(
            evidence_id="source-change",
            kind="target_correction",
            source="target_diff_transcript",
            observed_at=20,
            intervention_id=interventions_by_finding[
                source_finding.dedup_key
            ].intervention_id,
        ),
    )
    acknowledged_findings = (*test_findings[:3], source_finding)
    acknowledgments = tuple(
        stored_evidence(
            evidence_id=f"acknowledgment-{index}",
            kind="target_acknowledgment",
            source="target_assistant_transcript",
            observed_at=20,
            intervention_id=interventions_by_finding[
                finding.dedup_key
            ].intervention_id,
        )
        for index, finding in enumerate(acknowledged_findings)
    )
    acknowledged_ids = {
        item.intervention_id for item in acknowledgments
    }
    persisted = []
    before_reconciliation = router.snapshot()
    all_evidence = (*corrections, *acknowledgments)

    delta = router.reconcile_evidence(
        all_evidence,
        persisted.append,
        observed_at=21,
    )

    assert delta is persisted[0]
    final_by_id = {
        item.intervention_id: item for item in router.snapshot().interventions
    }
    for correction in corrections:
        intervention = final_by_id[correction.intervention_id]
        expected_state = (
            "acknowledged"
            if intervention.intervention_id in acknowledged_ids
            else "delivered"
        )
        assert intervention.state == expected_state
        assert intervention.correction_evidence_ids == (correction.evidence_id,)
        assert intervention.correction_evidence_digests == (correction.digest,)
        assert intervention.transition_history[-1].action == "correction_evidence_bound"
    replayed = InterventionRouter(
        run_id=RUN_ID,
        graph=router.graph,
        capabilities=router.capabilities,
        probe_verifier=VERIFIER,
        state=before_reconciliation,
    )
    replayed.replay_evidence_reconciliation(
        delta,
        all_evidence,
        observed_at=21,
    )
    assert replayed.snapshot().record_digest == router.snapshot().record_digest


def test_same_second_evidence_requires_an_earlier_committed_state() -> None:
    router = make_router()
    finding = make_finding(level="blocker", probe_status="confirmed")
    probe = make_probe(finding)
    delivered = router.plan_response(
        event("worker-target", "PostToolUse", 10),
        findings=(finding,),
        probes=(probe,),
    )
    commit(delivered)
    intervention_id = router.snapshot().interventions[0].intervention_id
    acknowledgment = stored_evidence(
        evidence_id="same-second-ack",
        kind="target_acknowledgment",
        source="target_assistant_transcript",
        observed_at=10,
        intervention_id=intervention_id,
    )
    premature_correction = stored_evidence(
        evidence_id="same-second-premature-correction",
        kind="target_correction",
        source="target_diff_transcript",
        observed_at=10,
        intervention_id=intervention_id,
    )
    commit(
        router.plan_response(
            event("worker-target", "PostToolUse", 10),
            findings=(finding,),
            probes=(probe,),
            stored_evidence=(acknowledgment, premature_correction),
        )
    )
    assert router.intervention(intervention_id).state == "acknowledged"
    correction = premature_correction.model_copy(
        update={"evidence_id": "same-second-committed-correction"}
    )
    passing_test = premature_correction.model_copy(
        update={
            "evidence_id": "same-second-committed-test",
            "source": "target_test_transcript",
        }
    )

    commit(
        router.plan_response(
            event("worker-target", "PostToolUse", 10),
            findings=(finding,),
            probes=(probe,),
            stored_evidence=(correction, passing_test),
        )
    )

    intervention = router.intervention(intervention_id)
    assert intervention.state == "resolved"
    assert intervention.correction_evidence_ids == (
        "same-second-committed-correction",
        "same-second-committed-test",
        "same-second-premature-correction",
    )


def test_stop_requires_deterministic_critical_finding_and_exact_confirmed_probe() -> None:
    finding = make_finding(level="blocker", probe_status="confirmed")
    router = make_router()
    confirmed = router.plan_response(
        event("worker-target", "Stop", 100),
        findings=(finding,),
        probes=(make_probe(finding),),
    )
    assert confirmed.body["decision"] == "block"
    commit(confirmed)
    state = router.snapshot().interventions[0]
    assert state.probe_snapshot_digest == SNAPSHOT_DIGEST
    assert state.claim_ids == finding.claim_ids

    forged = replace(make_probe(finding), signature="0" * 64)
    with pytest.raises(InterventionPolicyError, match="authentication"):
        make_router().plan_response(
            event("worker-target", "Stop", 100),
            findings=(finding,),
            probes=(forged,),
        )

    concern = make_finding(level="concern", probe_status="confirmed", suffix="concern")
    concern_plan = make_router().plan_response(
        event("worker-target", "Stop", 100),
        findings=(concern,),
        probes=(make_probe(concern),),
    )
    assert concern_plan.body == {}


def test_confirmed_noncritical_risk_is_not_promoted() -> None:
    finding = make_finding(
        level="blocker",
        probe_status="confirmed",
        suffix="noncritical",
        risk_category="none",
    )
    router = make_router()
    plan = router.plan_response(
        event("worker-target", "Stop", 100),
        findings=(finding,),
        probes=(make_probe(finding),),
    )
    assert plan.body == {}
    commit(plan)
    assert router.snapshot().interventions[0].level == "concern"


def test_dynamic_providers_observe_late_probe_and_evidence() -> None:
    finding = make_finding(level="blocker", probe_status="pending", suffix="dynamic")
    current_probes: list[ProbeAssessment] = []
    current_evidence: list[EvidenceRecord] = []
    router = make_router()
    decide = router.response_decider(
        findings=lambda: (finding,),
        probes=lambda: tuple(current_probes),
        stored_evidence=lambda: tuple(current_evidence),
        original_features=lambda: {},
        repair_assignments=lambda: (),
        cancelled_interventions=lambda: (),
    )
    delivered = decide(event("worker-target", "PostToolUse", 10))
    commit(delivered)
    intervention_id = router.snapshot().interventions[0].intervention_id
    current_probes.append(make_probe(finding))
    blocked = decide(event("worker-target", "Stop", 11))
    assert blocked.body["decision"] == "block"
    commit(blocked)
    current_evidence.append(
        stored_evidence(
            evidence_id="dynamic-ack",
            kind="target_acknowledgment",
            source="target_assistant_transcript",
            observed_at=12,
            intervention_id=intervention_id,
        )
    )
    acknowledged = decide(event("worker-target", "PostToolUse", 12))
    commit(acknowledged)
    assert router.intervention(intervention_id).state == "acknowledged"

def test_pending_and_inconclusive_probe_allow_completion() -> None:
    for status in ("missing", "pending", "inconclusive", "rejected", "not_confirmed"):
        router = make_router()
        finding = make_finding(level="concern", probe_status=status, suffix=status)
        probes = () if status == "missing" else (make_probe(finding, status=status),)
        plan = router.plan_response(
            event("worker-target", "Stop", 100),
            findings=(finding,),
            probes=probes,
        )
        assert plan.body == {}
        commit(plan)
        state = router.snapshot().interventions[0]
        assert state.level == "concern"
        assert state.probe_pending_at_completion == (
            100 if status in {"missing", "pending"} else None
        )



def test_post_tool_guidance_requires_the_exact_selected_delivery_key() -> None:
    router = make_router()
    first = make_finding(suffix="cooldown-first")
    second = make_finding(suffix="cooldown-second")
    findings = (first, second)
    selected = router.plan_response(
        event("worker-target", "PostToolUse", 10),
        findings=findings,
        selected_delivery_keys=((first.dedup_key, "worker-target"),),
    )
    commit(selected)
    assert selected.guidance_ids

    for observed_at in (11, 12, 13):
        suppressed = router.plan_response(
            event("worker-target", "PostToolUse", observed_at),
            findings=findings,
            selected_delivery_keys=(),
        )
        commit(suppressed)
        assert suppressed.body == {}

    next_selected = router.plan_response(
        event("worker-target", "PostToolUse", 14),
        findings=findings,
        selected_delivery_keys=((second.dedup_key, "worker-target"),),
    )
    commit(next_selected)
    assert next_selected.guidance_ids
    assert next_selected.guidance_ids != selected.guidance_ids


def test_unacknowledged_guidance_repeats_up_to_the_bound() -> None:
    router = make_router()
    finding = make_finding()
    key = ((finding.dedup_key, "worker-target"),)
    first = router.plan_response(
        event("worker-target", "PostToolUse", 10),
        findings=(finding,),
        selected_delivery_keys=key,
    )
    commit(first)
    assert first.body["hookSpecificOutput"]["hookEventName"] == "PostToolUse"

    repeats = []
    for observed_at in (11, 12):
        repeat = router.plan_response(
            event("worker-target", "PostToolUse", observed_at),
            findings=(finding,),
            selected_delivery_keys=key,
        )
        commit(repeat)
        repeats.append(repeat)

    assert [item.body for item in repeats] == [first.body, first.body]
    assert len({item.guidance_ids for item in (first, *repeats)}) == 3

    exhausted = router.plan_response(
        event("worker-target", "PostToolUse", 13),
        findings=(finding,),
        selected_delivery_keys=key,
    )
    commit(exhausted)

    assert exhausted.body == {}
    assert router.repeatable_delivery_keys() == frozenset()


def test_acknowledged_guidance_never_repeats() -> None:
    router = make_router()
    finding = make_finding()
    key = ((finding.dedup_key, "worker-target"),)
    delivered = router.plan_response(
        event("worker-target", "PostToolUse", 10),
        findings=(finding,),
        selected_delivery_keys=key,
    )
    commit(delivered)
    intervention_id = router.snapshot().interventions[0].intervention_id
    acknowledgment = stored_evidence(
        evidence_id="repeat-ack",
        kind="target_acknowledgment",
        source="target_assistant_transcript",
        observed_at=11,
        intervention_id=intervention_id,
    )
    acknowledged = router.plan_response(
        event("worker-target", "PostToolUse", 11),
        findings=(finding,),
        selected_delivery_keys=key,
        stored_evidence=(acknowledgment,),
    )
    commit(acknowledged)

    assert router.intervention(intervention_id).state == "acknowledged"
    assert router.repeatable_delivery_keys() == frozenset()
    later = router.plan_response(
        event("worker-target", "PostToolUse", 12),
        findings=(finding,),
        selected_delivery_keys=key,
    )
    commit(later)
    assert later.body == {}



def test_fresh_same_feature_repair_and_cancellation_are_idempotent() -> None:
    router = make_router(
        graph=make_graph(repair=True),
        capabilities=make_capabilities(worker_block="fallback", mission_block="pass"),
    )
    finding = make_finding(level="blocker", probe_status="confirmed", suffix="repair")
    probe = make_probe(finding)
    requested = router.plan_response(
        event("orchestrator", "Stop", 10),
        findings=(finding,),
        probes=(probe,),
        original_features={finding.finding_id: "feature-checkout"},
    )
    commit(requested)
    intervention = router.snapshot().interventions[0]
    assert intervention.state == "repair_requested"
    assignment = RepairAssignment(
        assignment_id="assignment-repair",
        intervention_id=intervention.intervention_id,
        run_id=RUN_ID,
        original_feature="feature-checkout",
        worker_session="repair-worker",
        worker_role_id="role-repair-worker",
        assigned_at=11,
    )

    routed = router.plan_response(
        event("repair-worker", "PostToolUse", 12),
        findings=(finding,),
        probes=(probe,),
        original_features={finding.finding_id: "feature-checkout"},
        repair_assignments=(assignment,),
    )
    commit(routed)
    assert "pause this path" in routed.body["hookSpecificOutput"]["additionalContext"]
    assert router.intervention(intervention.intervention_id).state == "repair_assigned"

    cancelled = router.plan_response(
        event("repair-worker", "PostToolUse", 13),
        findings=(finding,),
        probes=(probe,),
        original_features={finding.finding_id: "feature-checkout"},
        repair_assignments=(assignment,),
        cancelled_interventions=(intervention.intervention_id,),
    )
    commit(cancelled)
    assert router.intervention(intervention.intervention_id).state == "quarantined"

    repeated = router.plan_response(
        event("repair-worker", "PostToolUse", 14),
        findings=(finding,),
        probes=(probe,),
        original_features={finding.finding_id: "feature-checkout"},
        repair_assignments=(assignment,),
        cancelled_interventions=(intervention.intervention_id,),
    )
    commit(repeated)
    assert repeated.body == {}
    assert router.intervention(intervention.intervention_id).state == "quarantined"


def test_probe_bound_risk_transition_promotes_pending_concern() -> None:
    router = make_router()
    pending = make_finding(
        level="concern",
        probe_status="pending",
        suffix="risk-transition",
        risk_category="none",
    )
    initial = router.plan_response(
        event("worker-target", "PostToolUse", 10),
        findings=(pending,),
        selected_delivery_keys=((pending.dedup_key, "worker-target"),),
    )
    commit(initial)
    confirmed = replace(
        pending,
        level="blocker",
        risk_category="public_contract",
        probe_status="confirmed",
        probe_id="probe-risk-transition",
    )
    probe = make_probe(confirmed)

    blocked = router.plan_response(
        event("worker-target", "Stop", 11),
        findings=(confirmed,),
        probes=(probe,),
    )

    assert blocked.body["decision"] == "block"
    commit(blocked)
    intervention = router.snapshot().interventions[0]
    assert intervention.level == "blocker"
    assert intervention.risk_category == "public_contract"
    assert intervention.probe_digest == probe.record_digest
    assert "blocker_confirmed" in {
        item.action for item in intervention.transition_history
    }


def test_risk_transition_without_exact_confirmed_probe_is_rejected() -> None:
    router = make_router()
    initial = make_finding(
        level="concern",
        probe_status="missing",
        suffix="unverified-risk-transition",
        risk_category="none",
    )
    commit(
        router.plan_response(
            event("worker-target", "PostToolUse", 10),
            findings=(initial,),
        )
    )
    changed = replace(
        initial,
        level="blocker",
        risk_category="public_contract",
        probe_status="confirmed",
        probe_id="probe-unverified",
    )

    with pytest.raises(InterventionPolicyError, match="lineage changed"):
        router.plan_response(
            event("worker-target", "Stop", 11),
            findings=(changed,),
        )


def test_evidence_identity_and_digest_sets_are_independently_canonical() -> None:
    finding = replace(
        make_finding(
            level="blocker",
            probe_status="confirmed",
            suffix="independent-evidence-sets",
        ),
        evidence_digests=("a" * 64,),
    )
    router = make_router()
    plan = router.plan_response(
        event("worker-target", "Stop", 10),
        findings=(finding,),
        probes=(make_probe(finding),),
    )

    assert plan.body["decision"] == "block"
    commit(plan)
    intervention = router.snapshot().interventions[0]
    assert len(intervention.direct_evidence_ids) == 2
    assert len(intervention.direct_evidence_digests) == 1


def test_selected_note_is_target_only_context_without_intervention() -> None:
    router = make_router()
    note = make_finding(
        level="note",
        probe_status="missing",
        suffix="selected-note",
        risk_category="none",
    )
    committed: list[str] = []
    base = ResponsePlan(
        body={},
        guidance_ids=("delivery-selected-note",),
        commit=lambda: committed.append("selector"),
    )
    plan = router.plan_response(
        event("worker-target", "PostToolUse", 10),
        findings=(note,),
        selected_delivery_keys=((note.dedup_key, "worker-target"),),
        base_plan=base,
    )

    context = plan.body["hookSpecificOutput"]["additionalContext"]
    assert context.startswith("[shadow:note-")
    assert "Shadow review note" in context
    assert plan.guidance_ids == ("delivery-selected-note",)
    assert router.snapshot().interventions == ()
    assert committed == []
    commit(plan)
    assert committed == ["selector"]
    assert router.snapshot().interventions == ()


def test_mission_scope_binds_exactly_one_orchestrator_alias() -> None:
    capabilities = make_capabilities(worker_block="fallback", mission_block="pass")
    router = make_router(capabilities=capabilities)
    finding = make_finding(
        level="blocker",
        probe_status="confirmed",
        suffix="mission-alias",
    )
    commit(
        router.plan_response(
            event("worker-target", "SubagentStop", 10),
            findings=(finding,),
            probes=(make_probe(finding),),
        )
    )
    intervention = router.snapshot().interventions[0]
    assert intervention.target_session == "worker-target"
    assert intervention.completion_session_alias == "orchestrator"

    ambiguous_graph = make_graph()
    add_role(ambiguous_graph, "orchestrator-two", "orchestrator")
    ambiguous = make_router(
        graph=ambiguous_graph,
        capabilities=capabilities,
    )
    with pytest.raises(InterventionPolicyError, match="one exact"):
        ambiguous.plan_response(
            event("worker-target", "SubagentStop", 10),
            findings=(finding,),
            probes=(make_probe(finding),),
        )


def test_stop_correction_resolves_before_completion_selection() -> None:
    router = make_router()
    finding = make_finding(
        level="blocker",
        probe_status="confirmed",
        suffix="stop-correction",
    )
    probe = make_probe(finding)
    delivered = router.plan_response(
        event("worker-target", "PostToolUse", 10),
        findings=(finding,),
        probes=(probe,),
    )
    commit(delivered)
    intervention_id = router.snapshot().interventions[0].intervention_id
    acknowledgment = stored_evidence(
        evidence_id="stop-correction-ack",
        kind="target_acknowledgment",
        source="target_assistant_transcript",
        observed_at=11,
        intervention_id=intervention_id,
    )
    commit(
        router.plan_response(
            event("worker-target", "PostToolUse", 11),
            findings=(finding,),
            probes=(probe,),
            stored_evidence=(acknowledgment,),
        )
    )
    correction = stored_evidence(
        evidence_id="stop-correction-diff",
        kind="target_correction",
        source="target_diff_transcript",
        observed_at=12,
        intervention_id=intervention_id,
    )
    second_correction = stored_evidence(
        evidence_id="stop-correction-test",
        kind="target_correction",
        source="target_test_transcript",
        observed_at=12,
        intervention_id=intervention_id,
    ).model_copy(update={"digest": correction.digest})

    completion = router.plan_response(
        event("worker-target", "Stop", 12),
        findings=(finding,),
        probes=(probe,),
        stored_evidence=(correction, second_correction),
    )

    assert completion.body == {}
    commit(completion)
    intervention = router.intervention(intervention_id)
    assert intervention is not None
    assert intervention.state == "resolved"
    assert intervention.correction_evidence_ids == (
        "stop-correction-diff",
        "stop-correction-test",
    )
    assert intervention.correction_evidence_digests == (correction.digest,)


def test_post_tool_guidance_names_the_required_correction_work() -> None:
    router = make_router()
    finding = make_finding(suffix="actionable")
    plan = router.plan_response(
        event("worker-target", "PostToolUse", 10), findings=(finding,)
    )
    context = plan.body["hookSpecificOutput"]["additionalContext"]
    assert context.startswith("[shadow:intervention-")
    assert "pause this path" in context
    assert "Repeat [shadow:intervention-" in context
    assert "do not preserve a per-boundary split" in context
    assert "make or delegate source changes" in context
    assert "Documentation, acknowledgment, or validation alone" in context
    assert "Change the source files named in the evidence below" in context
    assert "one unit and one declared type" in context
    assert "carries a single amount through every listed locator" in context
    assert "assert its value and type at each boundary" in context
    assert "Evidence: locator schema.json#/amount" in context
    assert "property unit" in context
    assert "observed values cents, dollars" in context
    assert "authoritative value cents" in context
    assert len(context.encode("utf-8")) < 8_192
    commit(plan)


def test_guidance_names_the_source_file_the_session_declared() -> None:
    router = make_router()
    finding = replace(
        make_finding(suffix="declared"),
        related_declarations=(
            ("src/webhook.py", "type", '{"type":"string","value":"float"}'),
        ),
    )
    plan = router.plan_response(
        event("worker-target", "PostToolUse", 10), findings=(finding,)
    )
    context = plan.body["hookSpecificOutput"]["additionalContext"]

    assert 'these sessions also declared src/webhook.py declares type "float"' in context
    assert len(context.encode("utf-8")) < 8_192
    commit(plan)


@pytest.mark.parametrize(
    ("rule", "required", "forbidden"),
    (
        (
            "shared_assumption",
            "shared unverified premise is the defect",
            "mixed values are the defect",
        ),
        (
            "validation_overlap",
            "validator reused worker evidence",
            "mixed values are the defect",
        ),
    ),
)
def test_post_tool_guidance_matches_the_rule(
    rule: Literal["shared_assumption", "validation_overlap"],
    required: str,
    forbidden: str,
) -> None:
    router = make_router()
    finding = replace(make_finding(suffix=rule), rule=rule)

    plan = router.plan_response(
        event("worker-target", "PostToolUse", 10), findings=(finding,)
    )
    context = plan.body["hookSpecificOutput"]["additionalContext"]

    assert required in context
    assert forbidden not in context
    commit(plan)


def test_guidance_detail_is_bounded_and_redacted() -> None:
    from shadow_mission.router import _guidance_detail

    assert _guidance_detail(None) == ""
    noisy = make_finding(suffix="noisy")
    detail = _guidance_detail(
        replace(
            noisy,
            normalized_locators=tuple(f"file-{index}.json" for index in range(12)),
            normalized_properties=("x" * 400,),
        )
    )
    assert detail.count("file-") == 4
    assert "x" * 97 not in detail


def test_completion_never_delivers_a_concern_to_any_session() -> None:
    """Factory only honors decision block on Stop and SubagentStop.

    A concern must never claim a completion-hook delivery, because Factory
    ignores additionalContext on those events.
    """

    finding = make_finding(suffix="no-completion-delivery")
    for session in ("worker-target", "worker-sibling", "orchestrator"):
        for name in ("Stop", "SubagentStop"):
            router = make_router()
            plan = router.plan_response(
                event(session, name, 100), findings=(finding,)
            )
            assert plan.body == {}
            assert plan.guidance_ids == ()


def test_latch_lock_contention_expires_with_typed_error(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = InterventionLatchStore(
        tmp_path / "private",
        run_id=RUN_ID,
        secret=generate_run_secret(),
    )
    descriptor = os.open(store.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    monkeypatch.setattr(
        router_module,
        "_LATCH_LOCK_TIMEOUT_SECONDS",
        0.05,
        raising=False,
    )
    release = threading.Timer(
        0.5,
        lambda: fcntl.flock(descriptor, fcntl.LOCK_UN),
    )
    release.start()
    started = time.monotonic()
    try:
        with pytest.raises(InterventionLatchLockTimeout) as captured:
            store.initialize(observed_at=100)
        elapsed = time.monotonic() - started
    finally:
        release.join(timeout=1.0)
        os.close(descriptor)

    assert isinstance(captured.value, InterventionLatchLockTimeout)
    assert 0.04 <= elapsed < 0.25
