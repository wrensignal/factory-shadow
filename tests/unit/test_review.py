from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Literal

import pytest
import shadow_mission.review as review_module
import shadow_mission.review_journal as review_journal_module

from shadow_mission.extractor import (
    BrokerAttempt,
    ClaimExtractor,
    ExtractionRequest,
    ExtractionOutcome,
    QuarantineRecord,
    RecordedExtractionBroker,
)
from shadow_mission.graph import MissionGraph
from shadow_mission.probe import ProbeOutcome, ProbeQuarantine, ProbeUsage
from shadow_mission.protocol import (
    CapabilityFlags,
    ClaimRecord,
    EvidenceRecord,
    HookEnvelope,
    HookExchangeRecord,
    HookRequest,
    HookResponseRecord,
    QueueCapacityError,
    RepairAssignment,
    canonical_json,
    hook_response_digest,
    hook_envelope_digest,
)
from shadow_mission.review import (
    MissionReviewController,
    MissionReviewError,
    _ProbeIdentity,
)
from shadow_mission.review_journal import (
    ControllerDegradedRecord,
    ExchangeProjectionRecord,
    ExtractionOutcomeRecord,
    JournalFinding,
    ProbeCancellationRecord,
    ReviewJournal,
    ReviewJournalError,
    ReviewJournalCorruptionError,
    RoleDecisionRecord,
    InterventionLineageRecord,
    TranscriptBatchRecord,
)
from shadow_mission.roles import (
    ConfiguredRole,
    FrozenMissionRelations,
    LiveMissionRelations,
    MissionRelation,
    MissionRelations,
    RoleDecision,
    RoleMapper,
)
from shadow_mission.rules import (
    AuthorityResolution,
    DeterministicRules,
    EvidenceAuthority,
    Finding,
    ProbeVerifier,
)
from shadow_mission.router import (
    InterventionRouter,
    InterventionRouterState,
    _new_intervention,
    _router_delta,
    _router_state,
)
from shadow_mission.storage import EventLedger, ResponsePlan
from shadow_mission.transcript import (
    TranscriptError,
    TranscriptObservation,
    TranscriptReader,
)

RUN_ID = "run-review-controller"


class _NoProbeScheduler:
    def __init__(self) -> None:
        self.enqueue_calls = 0
        self.run_calls = 0

    def enqueue(self, _job: object) -> None:
        self.enqueue_calls += 1

    def run_next(self) -> None:
        self.run_calls += 1
        return None

    def abort(self) -> bool:
        return True


class _SnapshotRouter:
    def __init__(self, graph: MissionGraph) -> None:
        self.run_id = graph.run_id
        self.graph = graph
        self.calls = 0
        self.values: list[dict[str, object]] = []

    def plan_response(self, _envelope: HookEnvelope, **values: object) -> ResponsePlan:
        self.calls += 1
        self.values.append(values)
        base_plan = values.get("base_plan")
        return base_plan if isinstance(base_plan, ResponsePlan) else ResponsePlan(body={})

    def snapshot(self) -> SimpleNamespace:
        return SimpleNamespace(interventions=())

    def repeatable_delivery_keys(self) -> frozenset[tuple[str, str]]:
        return frozenset()

    def undelivered_target_sessions(
        self,
        _plan: ResponsePlan | None = None,
    ) -> frozenset[str]:
        return frozenset()


def _envelope(
    sequence: int,
    *,
    event_id: str | None = None,
    hook_event_name: str = "UserPromptSubmit",
    session_alias: str = "session-worker",
    prompt: str | None = None,
) -> HookEnvelope:
    return HookEnvelope(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        event_id=event_id or f"event-{sequence}",
        source_fingerprint=f"source-{sequence}",
        run_id=RUN_ID,
        session_alias=session_alias,
        transcript_alias=f"transcript-{session_alias.removeprefix('session-')}",
        hook_event_name=hook_event_name,
        observed_at=sequence,
        message_digest="d" * 64,
        payload={"prompt": prompt if prompt is not None else f"prompt {sequence}"},
    )


def _exchange(
    sequence: int,
    *,
    event_id: str | None = None,
    guidance_ids: tuple[str, ...] = (),
    transition_ids: tuple[str, ...] = (),
    hook_event_name: str = "UserPromptSubmit",
    response_body: dict[str, object] | None = None,
    session_alias: str = "session-worker",
    review_state: dict[str, object] | None = None,
    prompt: str | None = None,
) -> HookExchangeRecord:
    envelope = _envelope(
        sequence,
        event_id=event_id,
        hook_event_name=hook_event_name,
        session_alias=session_alias,
        prompt=prompt,
    )
    body = canonical_json(response_body or {}).decode()
    response_digest = hook_response_digest(
        response_body=body,
        guidance_ids=guidance_ids,
        transition_ids=transition_ids,
        review_state=review_state,
    )
    response = HookResponseRecord(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        response_id=f"response-{sequence}",
        run_id=RUN_ID,
        event_id=envelope.event_id,
        request_digest=hook_envelope_digest(envelope),
        response_body=body,
        response_digest=response_digest,
        guidance_ids=guidance_ids,
        transition_ids=transition_ids,
        decided_at=sequence,
        review_state=review_state,
    )
    return HookExchangeRecord(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        ledger_sequence=sequence,
        exchange_id=f"exchange-{sequence}",
        recorded_at=sequence,
        envelope=envelope,
        response=response,
    )


def _controller(
    tmp_path: Path,
    *,
    max_queue_items: int = 16,
    max_queue_bytes: int = 1 << 20,
    original_features: dict[str, str] | None = None,
    repair_assignments: Callable[[], tuple[RepairAssignment, ...]] | None = None,
    cancelled_interventions: Callable[[], tuple[str, ...]] | None = None,
    transcript_mode: str = "fallback",
    relations: MissionRelations | None = None,
    roles: tuple[ConfiguredRole, ...] = (),
    clock: Callable[[], float] | None = None,
) -> MissionReviewController:
    tmp_path.mkdir(parents=True, exist_ok=True)
    transcript_root = tmp_path / "transcripts"
    transcript_root.mkdir(exist_ok=True)
    relation_inventory = relations or FrozenMissionRelations("mission-review", ())
    graph = MissionGraph(RUN_ID)
    return MissionReviewController(
        run_id=RUN_ID,
        run_dir=tmp_path / "run",
        relations=relation_inventory,
        role_mapper=RoleMapper(roles, relation_inventory),
        transcript_reader=TranscriptReader(
            transcript_root,
            run_id=RUN_ID,
            mode=transcript_mode,
            provenance_status="hook_authenticated",
            fallback_semantic_equivalence=False,
        ),
        claim_extractor=ClaimExtractor(
            RecordedExtractionBroker(
                BrokerAttempt(boundary={}, output=None)
            )
        ),
        graph=graph,
        rules=DeterministicRules(),
        probe_scheduler=_NoProbeScheduler(),
        router=_SnapshotRouter(graph),
        probe_risk_classifier=lambda finding: finding.risk_category,
        repository_root=tmp_path,
        original_features=original_features,
        repair_assignments=repair_assignments,
        cancelled_interventions=cancelled_interventions,
        max_queue_items=max_queue_items,
        max_queue_bytes=max_queue_bytes,
        clock=clock or (lambda: 100),
    )


def _assign_role(
    controller: MissionReviewController,
    kind: Literal["orchestrator", "worker", "validator"] = "worker",
) -> None:
    controller.graph.add_role_decision(
        RoleDecision(
            session_alias="session-worker",
            role_id=f"role-{kind}",
            kind=kind,
            confidence="high",
            status="assigned",
            reason="recorded role",
            evidence_digests=("0" * 64,),
        )
    )


def _finding(suffix: str = "restart") -> Finding:
    dedup_key = hashlib.sha256(suffix.encode()).hexdigest()
    return Finding(
        finding_id=f"finding-{suffix}",
        dedup_key=dedup_key,
        rule="cross_worker_conflict",
        level="concern",
        target_sessions=("session-worker",),
        claim_ids=("claim-a", "claim-b"),
        evidence_ids=("evidence-a", "evidence-b"),
        evidence_digests=("a" * 64, "b" * 64),
        normalized_locators=("schema.json#/amount",),
        normalized_properties=("unit",),
        normalized_units=("cents",),
        normalized_values=("cents", "dollars"),
        authority=AuthorityResolution(
            "resolved",
            EvidenceAuthority.AUTHORITATIVE,
            "cents",
        ),
        risk_category="public_contract",
        probe_status="pending",
    )


_REAL_PROBE_KEY = b"review-controller-real-probe-key"
_REAL_BOUNDARY_DIGEST = "9" * 64
_REAL_PROBE_VERIFIER = ProbeVerifier(
    _REAL_PROBE_KEY,
    boundary_digest=_REAL_BOUNDARY_DIGEST,
)


def _real_capabilities() -> CapabilityFlags:
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
        worker_block="pass",
        mission_block="pass",
        worker_roles="pass",
        validator_roles="pass",
        self_session_exclusion="pass",
        sandbox_isolation="pass",
        probe_boundary="pass",
        live_validation_overlap="pass",
    )


def test_new_review_journal_fsyncs_parent_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory_syncs = 0
    real_fsync = os.fsync

    def record_fsync(descriptor: int) -> None:
        nonlocal directory_syncs
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_syncs += 1
        real_fsync(descriptor)

    monkeypatch.setattr(review_journal_module.os, "fsync", record_fsync)

    ReviewJournal(tmp_path / "run/review.jsonl", run_id=RUN_ID)

    assert directory_syncs == 1


def _conflict_graph(*, finding_count: int = 1) -> MissionGraph:
    graph = MissionGraph(RUN_ID)
    for session_alias, role_id in (
        ("session-worker", "role-worker"),
        ("session-peer", "role-peer"),
    ):
        graph.add_role_decision(
            RoleDecision(
                session_alias=session_alias,
                role_id=role_id,
                kind="worker",
                confidence="high",
                status="assigned",
                reason="authoritative test relation",
                evidence_digests=(
                    hashlib.sha256(session_alias.encode()).hexdigest(),
                ),
            )
        )
    for finding_index in range(finding_count):
        locator = f"contracts/contract-{finding_index}.json#/amount"
        for session_index, (session_alias, value) in enumerate(
            (
                ("session-worker", "cents"),
                ("session-peer", "dollars"),
            )
        ):
            evidence_id = f"conflict-{finding_index}-{session_alias}"
            evidence = EvidenceRecord(
                provenance_status="hook_authenticated",
                redaction_status="clean",
                evidence_id=evidence_id,
                run_id=RUN_ID,
                session_alias=session_alias,
                kind="repository_contract",
                source="repository_contract",
                locator=locator,
                digest=hashlib.sha256(evidence_id.encode()).hexdigest(),
                observed_at=finding_index * 10 + session_index + 1,
            )
            graph.add_evidence(evidence)
            graph.add_claim(
                ClaimRecord(
                    provenance_status="hook_authenticated",
                    redaction_status="clean",
                    claim_id=f"claim-{finding_index}-{session_alias}",
                    run_id=RUN_ID,
                    session_alias=session_alias,
                    subject=f"amount-{finding_index}",
                    subject_locator=locator,
                    property="storage unit",
                    value=value,
                    unit="cents",
                    confidence=0.95,
                    evidence_ids=(evidence_id,),
                    observed_at=finding_index * 10 + session_index + 3,
                )
            )
    return graph


def _real_controller(
    tmp_path: Path,
    *,
    graph: MissionGraph | None = None,
    router: InterventionRouter | None = None,
    transcript_mode: str = "fallback",
    max_queue_items: int = 128,
) -> MissionReviewController:
    tmp_path.mkdir(parents=True, exist_ok=True)
    transcript_root = tmp_path / "transcripts"
    transcript_root.mkdir(exist_ok=True)
    actual_graph = graph or _conflict_graph()
    capabilities = _real_capabilities()
    actual_router = router or InterventionRouter(
        run_id=RUN_ID,
        graph=actual_graph,
        capabilities=capabilities,
        probe_verifier=_REAL_PROBE_VERIFIER,
    )
    relations = FrozenMissionRelations("mission-review-real", ())
    return MissionReviewController(
        run_id=RUN_ID,
        run_dir=tmp_path / "run",
        relations=relations,
        role_mapper=RoleMapper((), relations),
        transcript_reader=TranscriptReader(
            transcript_root,
            run_id=RUN_ID,
            mode=transcript_mode,
            provenance_status="untrusted_provenance",
            fallback_semantic_equivalence=False,
        ),
        claim_extractor=ClaimExtractor(
            RecordedExtractionBroker(
                BrokerAttempt(
                    boundary={
                        "factory_home": "clean",
                        "enabled_tools": [],
                        "timeout_seconds": 30,
                        "shadow_activation_stripped": True,
                        "mission_correlation_stripped": True,
                        "internal_session_alias": "session-extractor",
                        "environment_keys": ["PATH"],
                    },
                    output=[],
                )
            )
        ),
        graph=actual_graph,
        rules=DeterministicRules(
            capabilities=capabilities,
            probe_verifier=_REAL_PROBE_VERIFIER,
        ),
        probe_scheduler=_NoProbeScheduler(),
        router=actual_router,
        probe_risk_classifier=lambda finding: finding.risk_category,
        repository_root=tmp_path,
        max_queue_items=max_queue_items,
        clock=lambda: 100,
    )


def _intervention_delta_state() -> dict[str, object]:
    before = InterventionRouterState.empty(RUN_ID)
    intervention = _new_intervention(
        run_id=RUN_ID,
        finding=_finding("lineage"),
        target_session="session-worker",
        completion_session_alias="session-worker",
        level="concern",
        probe=None,
        generation=1,
        observed_at=1,
        blocking_scope="worker",
        original_feature=None,
    )
    after = _router_state(RUN_ID, 1, (intervention,))
    return _router_delta(before, after, (intervention,)).model_dump(mode="json")


def _plan_bytes(plan: ResponsePlan) -> bytes:
    return canonical_json(
        {
            "body": dict(plan.body),
            "guidance_ids": plan.guidance_ids,
            "transition_ids": plan.transition_ids,
            "review_state": plan.review_state,
            "redaction_status": plan.redaction_status,
        }
    )


def test_decide_cached_findings_match_full_evaluation_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cached = _controller(tmp_path / "cached")
    full = _controller(tmp_path / "full")
    findings = (_finding("cached-equivalence"),)
    calls = {"cached": 0, "full": 0}

    monkeypatch.setattr(cached.rules, "detect", lambda *_args, **_kwargs: findings)
    monkeypatch.setattr(full.rules, "detect", lambda *_args, **_kwargs: findings)
    cached._publish_findings(_exchange(1))
    full._publish_findings(_exchange(1))
    cached._findings_snapshot_available = True
    full._findings_snapshot_available = False

    def cached_detect(*_args: object, **_kwargs: object) -> tuple[Finding, ...]:
        calls["cached"] += 1
        return findings

    def full_detect(*_args: object, **_kwargs: object) -> tuple[Finding, ...]:
        calls["full"] += 1
        return findings

    monkeypatch.setattr(cached.rules, "detect", cached_detect)
    monkeypatch.setattr(full.rules, "detect", full_detect)
    sequence = (
        _envelope(2, hook_event_name="PostToolUse"),
        _envelope(3, hook_event_name="UserPromptSubmit"),
        _envelope(4, hook_event_name="PostToolUse"),
        _envelope(5, hook_event_name="PostToolUse"),
        _envelope(6, hook_event_name="PostToolUse"),
    )

    for envelope in sequence:
        cached_plan = cached.decide(envelope)
        full_plan = full.decide(envelope)
        assert _plan_bytes(cached_plan) == _plan_bytes(full_plan)
        assert cached_plan.commit is not None
        assert full_plan.commit is not None
        cached_plan.commit()
        full_plan.commit()

    assert calls == {"cached": 0, "full": len(sequence)}


def test_response_path_only_enqueues_lineage_projection(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    ledger = EventLedger(controller.run_dir, run_id=RUN_ID)
    ledger.add_after_append(controller.after_append)
    ledger.start()
    envelope = _envelope(1)
    review_state = _intervention_delta_state()

    response = ledger.submit(
        envelope,
        request_digest=hook_envelope_digest(envelope),
        decide=lambda _envelope: ResponsePlan(
            body={},
            review_state=review_state,
        ),
        timeout=1.0,
    )

    assert response.review_state == review_state
    assert controller.journal.records() == ()
    ledger.stop()

    controller.start()
    assert controller.drain(timeout=2.0)
    records = controller.journal.records()
    lineage_index = next(
        index
        for index, record in enumerate(records)
        if isinstance(record, InterventionLineageRecord)
    )
    projection_index = next(
        index
        for index, record in enumerate(records)
        if isinstance(record, ExchangeProjectionRecord)
    )
    assert lineage_index < projection_index
    assert controller.stop(timeout=2.0)


def test_replay_rebuilds_missing_intervention_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exchange = _exchange(1, review_state=_intervention_delta_state())
    controller = _controller(tmp_path)
    monkeypatch.setattr(
        controller,
        "_journal_intervention_lineage",
        lambda _exchange: None,
    )
    controller.after_append(exchange)
    controller.start()
    assert controller.drain(timeout=2.0)
    assert controller.stop(timeout=2.0)
    assert not any(
        isinstance(record, InterventionLineageRecord)
        for record in controller.journal.records()
    )

    replayed = _controller(tmp_path)
    replayed.replay((exchange,))
    lineage = tuple(
        record
        for record in replayed.journal.records()
        if isinstance(record, InterventionLineageRecord)
    )

    assert len(lineage) == 1
    replayed._validate_intervention_lineage(exchange, lineage[0])


def test_decide_uses_only_snapshots_and_does_not_call_sdk_work(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    probe = controller.probe_scheduler
    extractor_broker = controller.claim_extractor._broker

    plan = controller.decide(_envelope(1))
    assert plan.review_state is not None
    assert plan.commit is not None
    plan.commit()

    assert plan.body == {}
    assert probe.enqueue_calls == 0
    assert probe.run_calls == 0
    assert extractor_broker.requests == []


def test_worker_stop_waits_once_for_pending_same_session_review(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path / "live")
    _assign_role(controller)
    controller.after_append(
        _exchange(1, hook_event_name="PostToolUse")
    )

    first = controller.decide(_envelope(2, hook_event_name="Stop"))

    assert first.body["decision"] == "block"
    assert str(first.body["reason"]).startswith("[shadow:review-pending]")
    assert first.commit is not None
    first.commit()
    assert controller.decide(
        _envelope(3, hook_event_name="Stop")
    ).body == {}


    replayed = _controller(tmp_path / "replayed")
    _assign_role(replayed)
    replayed.replay(
        (
            _exchange(1, hook_event_name="PostToolUse"),
            _exchange(
                2,
                hook_event_name="Stop",
                response_body=dict(first.body),
            ),
        )
    )

    assert replayed.decide(
        _envelope(3, hook_event_name="Stop")
    ).body == {}


def test_triggered_extraction_boundary_failure_is_not_releasable(
    tmp_path: Path,
) -> None:
    class FailingExtractor:
        def extract(self, *_: object, **__: object) -> object:
            raise RuntimeError("boundary failed")

    controller = _controller(tmp_path)
    _assign_role(controller)
    failing_extractor = FailingExtractor()
    failing_extractor._classifier = (  # type: ignore[attr-defined]
        controller.claim_extractor._classifier  # type: ignore[attr-defined]
    )
    controller.claim_extractor = failing_extractor  # type: ignore[assignment]

    outcome = controller._extract(
        _exchange(1, hook_event_name="Stop"),
        (),
        transcript_available=True,
    )

    assert outcome.status == "failed"
    assert outcome.quarantine_reason == "boundary_fault"
    assert controller.non_releasable_reason == "extraction_boundary_failed"
    assert [
        record.reason
        for record in controller.journal.records()
        if isinstance(record, ControllerDegradedRecord)
    ] == ["extraction_boundary_failed"]


def test_triggered_sealed_session_setup_failure_is_not_releasable(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)

    outcome = controller._extract(
        _exchange(1, hook_event_name="Stop"),
        (),
        transcript_available=True,
    )

    assert outcome.status == "failed"
    assert outcome.quarantine_reason == "unsafe_boundary"
    assert controller.non_releasable_reason == "extraction_boundary_failed"
    assert [
        record.reason
        for record in controller.journal.records()
        if isinstance(record, ControllerDegradedRecord)
    ] == ["extraction_boundary_failed"]


def test_triggered_transcript_unavailable_quarantine_does_not_end_mission(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)

    exchange = _exchange(1, hook_event_name="PostToolUse")
    exchange = exchange.model_copy(
        update={
            "envelope": exchange.envelope.model_copy(
                update={
                    "payload": {
                        "tool_name": "Execute",
                        "tool_response": {"exit_code": 1},
                    }
                }
            )
        }
    )
    outcome = controller._extract(
        exchange,
        (),
        transcript_available=False,
    )

    assert outcome.status == "quarantined"
    assert outcome.quarantine_reason == "transcript_unavailable"
    assert controller.releasable is True
    assert not [
        record
        for record in controller.journal.records()
        if isinstance(record, ControllerDegradedRecord)
    ]


@pytest.mark.parametrize(
    ("reason", "expected_status", "expected_degradation"),
    [
        ("missing_output", "failed", "extraction_boundary_failed"),
        ("malformed_output", "failed", "extraction_boundary_failed"),
        ("timeout", "failed", "extraction_boundary_failed"),
        ("unsafe_boundary", "failed", "extraction_boundary_failed"),
        ("self_observed", "failed", "extraction_boundary_failed"),
        ("unknown_evidence", "failed", "extraction_boundary_failed"),
        ("cross_run_evidence", "failed", "extraction_boundary_failed"),
        ("cross_session_evidence", "failed", "extraction_boundary_failed"),
        ("unredacted_output", "failed", "extraction_boundary_failed"),
        ("unanchored_locator", "quarantined", None),
        ("untrusted_provenance", "quarantined", None),
        ("criterion_mismatch", "quarantined", None),
    ],
)
def test_extraction_reason_classifies_only_boundary_failures_as_failed(
    tmp_path: Path,
    reason: str,
    expected_status: str,
    expected_degradation: str | None,
) -> None:
    controller = _controller(tmp_path / reason)

    class QuarantiningExtractor:
        def __init__(self) -> None:
            self._classifier = controller.claim_extractor._classifier

        def extract(self, *_: object, **__: object) -> ExtractionOutcome:
            return ExtractionOutcome(
                trigger_kinds=("completion_attempt",),
                quarantine=QuarantineRecord(reason=reason),
            )

    controller.claim_extractor = QuarantiningExtractor()  # type: ignore[assignment]

    outcome = controller._extract(
        _exchange(1, hook_event_name="Stop"),
        (),
        transcript_available=True,
    )

    assert outcome.status == expected_status
    assert outcome.quarantine_reason == reason
    assert controller.non_releasable_reason == expected_degradation



def test_extraction_journals_only_graph_accepted_claims_and_replays_exactly(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    projected = EvidenceRecord(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        evidence_id="evidence-projected",
        run_id=RUN_ID,
        session_alias="session-worker",
        kind="diff",
        source="transcript",
        locator="src/payment.py",
        digest="a" * 64,
        observed_at=1,
    )
    accepted = ClaimRecord(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        claim_id="claim-accepted",
        run_id=RUN_ID,
        session_alias="session-worker",
        subject="payment amount",
        subject_locator="src/payment.py",
        property="storage unit",
        value="cents",
        unit="cents",
        confidence=0.95,
        evidence_ids=(projected.evidence_id,),
        observed_at=1,
    )
    rejected = accepted.model_copy(
        update={
            "claim_id": "claim-rejected",
            "run_id": "run-other",
        }
    )

    class PartlyInvalidExtractor:
        def __init__(self) -> None:
            self._classifier = controller.claim_extractor._classifier

        def extract(self, *_: object, **__: object) -> ExtractionOutcome:
            return ExtractionOutcome(
                trigger_kinds=("completion_attempt",),
                claims=(accepted, rejected),
                derived_evidence=(projected,),
            )

    controller.claim_extractor = PartlyInvalidExtractor()  # type: ignore[assignment]
    exchange = _exchange(1, hook_event_name="Stop")

    record = controller._extract(
        exchange,
        (),
        transcript_available=True,
    )

    assert record.status == "accepted"
    assert record.claims == (accepted,)
    assert controller.graph.claims() == record.claims
    degradation = tuple(
        item
        for item in controller.journal.records()
        if isinstance(item, ControllerDegradedRecord)
    )
    assert len(degradation) == 1
    assert "claim-rejected" in degradation[0].reason
    assert "belongs_to_another_run" in degradation[0].reason

    restarted = _controller(tmp_path)
    restarted.replay((exchange,))

    assert restarted.graph.snapshot() == controller.graph.snapshot()
    assert restarted.non_releasable_reason == degradation[0].reason

def test_replay_recovers_unpersisted_triggered_extraction_degradation(
    tmp_path: Path,
) -> None:
    exchange = _exchange(1, hook_event_name="Stop")
    writer = _controller(tmp_path)
    writer.journal.append(
        "extraction_outcome",
        ledger_sequence=exchange.ledger_sequence,
        event_id=exchange.envelope.event_id,
        trigger_kinds=("completion_attempt",),
        status="failed",
        quarantine_reason="boundary_fault",
        claims=(),
        derived_evidence=(),
    )

    restarted = _controller(tmp_path)
    restarted.replay((exchange,))

    assert restarted.non_releasable_reason == "extraction_boundary_failed"
    assert [
        record.reason
        for record in restarted.journal.records()
        if isinstance(record, ControllerDegradedRecord)
    ] == ["extraction_boundary_failed"]

def test_replay_preserves_transcript_unavailable_quarantine_without_degradation(
    tmp_path: Path,
) -> None:
    exchange = _exchange(1, hook_event_name="PostToolUse")
    exchange = exchange.model_copy(
        update={
            "envelope": exchange.envelope.model_copy(
                update={
                    "payload": {
                        "tool_name": "Execute",
                        "tool_response": {"exit_code": 1},
                    }
                }
            )
        }
    )
    writer = _controller(tmp_path)
    writer.after_append(exchange)
    writer.start()
    assert writer.drain(timeout=2.0)
    assert writer.stop(timeout=2.0)
    extraction = next(
        record
        for record in writer.journal.records()
        if isinstance(record, ExtractionOutcomeRecord)
    )
    expected = (
        writer.graph.snapshot(),
        writer.cursor_offsets(),
        writer.findings(),
        writer.role_mapper.decisions(),
        writer.router.snapshot().interventions,
        writer.releasable,
        writer.non_releasable_reason,
    )

    restarted = _controller(tmp_path)
    restarted.replay((exchange,))

    assert extraction.status == "quarantined"
    assert extraction.quarantine_reason == "transcript_unavailable"
    assert (
        restarted.graph.snapshot(),
        restarted.cursor_offsets(),
        restarted.findings(),
        restarted.role_mapper.decisions(),
        restarted.router.snapshot().interventions,
        restarted.releasable,
        restarted.non_releasable_reason,
    ) == expected
    assert restarted.non_releasable_reason is None
    assert not any(
        isinstance(record, ControllerDegradedRecord)
        for record in restarted.journal.records()
    )


def test_not_triggered_extraction_remains_releasable_after_replay(
    tmp_path: Path,
) -> None:
    exchange = _exchange(1)
    controller = _controller(tmp_path)

    outcome = controller._extract(
        exchange,
        (),
        transcript_available=True,
    )

    assert outcome.status == "not_triggered"
    assert controller.releasable is True

    restarted = _controller(tmp_path)
    restarted.replay((exchange,))

    assert restarted.releasable is True
    assert not any(
        isinstance(record, ControllerDegradedRecord)
        for record in restarted.journal.records()
    )


def test_validator_stop_never_waits_for_pending_review(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    _assign_role(controller, "validator")
    controller.after_append(
        _exchange(1, hook_event_name="PostToolUse")
    )

    assert controller.decide(
        _envelope(2, hook_event_name="Stop")
    ).body == {}


def test_orchestrator_stop_waits_once_for_pending_same_session_review(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path / "live")
    _assign_role(controller, "orchestrator")
    controller.after_append(
        _exchange(1, hook_event_name="PostToolUse")
    )

    first = controller.decide(_envelope(2, hook_event_name="Stop"))

    assert first.body["decision"] == "block"
    assert str(first.body["reason"]).startswith("[shadow:review-pending]")
    assert first.commit is not None
    first.commit()
    assert controller.decide(
        _envelope(3, hook_event_name="Stop")
    ).body == {}

    replayed = _controller(tmp_path / "replayed")
    _assign_role(replayed, "orchestrator")
    replayed.replay(
        (
            _exchange(1, hook_event_name="PostToolUse"),
            _exchange(
                2,
                hook_event_name="Stop",
                response_body=dict(first.body),
            ),
        )
    )

    assert replayed.decide(
        _envelope(3, hook_event_name="Stop")
    ).body == {}


def test_worker_stop_does_not_wait_for_non_tool_projection(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    _assign_role(controller)
    controller.after_append(_exchange(1))

    assert controller.decide(
        _envelope(2, hook_event_name="Stop")
    ).body == {}


def test_worker_stop_does_not_wait_after_review_drains(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    _assign_role(controller)
    controller.after_append(
        _exchange(1, hook_event_name="PostToolUse")
    )
    controller.start()
    assert controller.drain(timeout=2.0)

    assert controller.decide(
        _envelope(2, hook_event_name="Stop")
    ).body == {}
    assert controller.stop(timeout=2.0)


def test_controller_freezes_features_and_snapshots_dynamic_router_inputs(
    tmp_path: Path,
) -> None:
    features = {"finding-a": "feature-original"}
    assignments: list[RepairAssignment] = []
    cancellations: list[str] = []
    controller = _controller(
        tmp_path,
        original_features=features,
        repair_assignments=lambda: tuple(assignments),
        cancelled_interventions=lambda: tuple(cancellations),
    )
    features["finding-a"] = "feature-mutated"
    cancellations.append("intervention-cancelled")

    plan = controller.decide(_envelope(1))
    assert plan.commit is not None
    plan.commit()
    captured = controller.router.values[-1]

    assert dict(captured["original_features"]) == {
        "finding-a": "feature-original"
    }
    assert captured["repair_assignments"] == ()
    assert captured["cancelled_interventions"] == (
        "intervention-cancelled",
    )



def test_authenticated_raw_path_is_consumed_by_matching_commit_and_not_persisted(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "transcripts" / "worker.jsonl"
    transcript.parent.mkdir()
    transcript.write_text(
        json.dumps({"type": "user", "content": "visible text"}) + "\n",
        encoding="utf-8",
    )
    controller = _controller(tmp_path, transcript_mode="primary")
    exchange = _exchange(1)
    raw_session_id = "raw-session-must-not-persist"
    controller.capture_request(
        HookRequest(
            run_id=RUN_ID,
            event_id=exchange.envelope.event_id,
            observed_at=exchange.envelope.observed_at,
            hook_event_name=exchange.envelope.hook_event_name,
            session_id=raw_session_id,
            transcript_path=str(transcript),
            cwd=str(tmp_path),
        ),
        exchange.envelope,
    )

    controller.after_append(exchange)
    controller.start()
    assert controller.drain(timeout=2.0)
    assert controller.stop(timeout=2.0)

    persisted = controller.journal.path.read_bytes()
    assert str(transcript).encode() not in persisted
    assert raw_session_id.encode() not in persisted
    assert controller.cursor_offsets()[exchange.envelope.transcript_alias] > 0


def test_rejected_primary_record_advances_cursor_and_fails_release_closed(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "transcripts" / "worker.jsonl"
    transcript.parent.mkdir()
    transcript.write_text(
        "{not-json}\n"
        + json.dumps({"type": "user", "content": "visible text"})
        + "\n",
        encoding="utf-8",
    )
    controller = _controller(tmp_path, transcript_mode="primary")
    exchange = _exchange(1, hook_event_name="Stop")
    controller.capture_request(
        HookRequest(
            run_id=RUN_ID,
            event_id=exchange.envelope.event_id,
            observed_at=exchange.envelope.observed_at,
            hook_event_name=exchange.envelope.hook_event_name,
            session_id="raw-session",
            transcript_path=str(transcript),
            cwd=str(tmp_path),
        ),
        exchange.envelope,
    )

    controller.after_append(exchange)
    controller.start()
    assert controller.drain(timeout=2.0)
    assert controller.stop(timeout=2.0) is False

    batch = next(
        record
        for record in controller.journal.records()
        if isinstance(record, TranscriptBatchRecord)
    )
    assert batch.status == "rejected"
    assert batch.failure_reason == "transcript_rejected"
    assert batch.cursor_after == transcript.stat().st_size
    assert batch.evidence
    assert controller.non_releasable_reason == "transcript_incomplete"


def test_rejected_active_transcript_is_quarantined_without_ending_mission(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "transcripts" / "worker.jsonl"
    transcript.parent.mkdir()
    transcript.write_text(
        "{not-json}\n"
        + json.dumps({"type": "user", "content": "visible text"})
        + "\n",
        encoding="utf-8",
    )
    controller = _controller(tmp_path, transcript_mode="primary")
    exchange = _exchange(1, hook_event_name="PostToolUse")
    controller.capture_request(
        HookRequest(
            run_id=RUN_ID,
            event_id=exchange.envelope.event_id,
            observed_at=exchange.envelope.observed_at,
            hook_event_name=exchange.envelope.hook_event_name,
            session_id="raw-session",
            transcript_path=str(transcript),
            cwd=str(tmp_path),
        ),
        exchange.envelope,
    )

    controller.after_append(exchange)
    controller.start()
    assert controller.drain(timeout=2.0)
    assert controller.non_releasable_reason is None
    assert controller.stop(timeout=2.0) is True

    batch = next(
        record
        for record in controller.journal.records()
        if isinstance(record, TranscriptBatchRecord)
    )
    assert batch.status == "rejected"
    assert batch.failure_reason == "transcript_rejected"


def test_replay_recovers_unpersisted_primary_transcript_degradation(
    tmp_path: Path,
) -> None:
    exchange = _exchange(1, hook_event_name="Stop")
    writer = _controller(tmp_path, transcript_mode="primary")
    writer.journal.append(
        "transcript_batch",
        ledger_sequence=exchange.ledger_sequence,
        event_id=exchange.envelope.event_id,
        session_alias=exchange.envelope.session_alias,
        transcript_alias=exchange.envelope.transcript_alias,
        cursor_before=0,
        cursor_after=12,
        status="rejected",
        failure_reason="transcript_rejected",
        evidence=(),
    )
    writer.transcript_reader.close()

    restarted = _controller(tmp_path, transcript_mode="primary")
    restarted.replay((exchange,))

    assert restarted.non_releasable_reason == "transcript_incomplete"
    assert [
        record.reason
        for record in restarted.journal.records()
        if isinstance(record, ControllerDegradedRecord)
    ] == ["transcript_incomplete"]


def test_out_of_order_concurrent_intake_projects_in_ledger_order_and_once(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    second_arrived = threading.Event()

    def submit_second() -> None:
        controller.after_append(_exchange(2))
        second_arrived.set()

    thread = threading.Thread(target=submit_second)
    thread.start()
    assert second_arrived.wait(1.0)
    controller.after_append(_exchange(1))
    thread.join(1.0)
    controller.after_append(_exchange(1))
    controller.start()
    assert controller.drain(timeout=2.0)
    assert controller.stop(timeout=2.0)

    projected = [
        record.ledger_sequence
        for record in controller.journal.records()
        if isinstance(record, ExchangeProjectionRecord)
    ]
    assert projected == [1, 2]


def test_review_queue_item_and_byte_overflow_fail_closed(tmp_path: Path) -> None:
    item_limited = _controller(tmp_path / "items", max_queue_items=1)
    item_limited.after_append(_exchange(2))
    with pytest.raises(QueueCapacityError, match="item limit"):
        item_limited.after_append(_exchange(3))
    assert not item_limited.releasable

    byte_limited = _controller(tmp_path / "bytes", max_queue_bytes=8)
    with pytest.raises(QueueCapacityError, match="byte limit"):
        byte_limited.after_append(_exchange(1))
    assert not byte_limited.releasable


@pytest.mark.parametrize("failure", ["digest", "sequence", "chain"])
def test_review_journal_rejects_digest_sequence_and_chain_corruption(
    tmp_path: Path,
    failure: str,
) -> None:
    path = tmp_path / "run" / "review.jsonl"
    journal = ReviewJournal(path, run_id=RUN_ID)
    journal.append("controller_degraded", reason="first", observed_at=1)
    if failure == "chain":
        journal.append("controller_degraded", reason="second", observed_at=2)
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    target = rows[-1]
    if failure == "digest":
        target["reason"] = "changed"
    elif failure == "sequence":
        target["journal_sequence"] += 1
        material = dict(target)
        material.pop("record_digest")
        target["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    else:
        target["previous_digest"] = "f" * 64
        material = dict(target)
        material.pop("record_digest")
        target["record_digest"] = hashlib.sha256(canonical_json(material)).hexdigest()
    path.write_bytes(b"".join(canonical_json(row) + b"\n" for row in rows))

    with pytest.raises(ReviewJournalCorruptionError):
        ReviewJournal(path, run_id=RUN_ID)


def test_review_journal_append_rejects_replaced_symlink(tmp_path: Path) -> None:
    path = tmp_path / "run" / "review.jsonl"
    journal = ReviewJournal(path, run_id=RUN_ID)
    sentinel = tmp_path / "sentinel"
    original = b"must remain unchanged\n"
    sentinel.write_bytes(original)
    sentinel.chmod(0o600)
    path.unlink()
    path.symlink_to(sentinel)

    with pytest.raises(ReviewJournalError):
        journal.append("controller_degraded", reason="first", observed_at=1)

    assert sentinel.read_bytes() == original
    assert journal.records() == ()


def test_restart_replays_identical_graph_cursor_findings_and_probe_dedup(
    tmp_path: Path,
) -> None:
    first = _controller(tmp_path)
    exchanges = (_exchange(1), _exchange(2))
    for exchange in exchanges:
        first.after_append(exchange)
    first.start()
    assert first.drain(timeout=2.0)
    assert first.stop(timeout=2.0)
    expected = (
        first.graph.snapshot(),
        first.cursor_offsets(),
        first.findings(),
    )

    restarted = _controller(tmp_path)
    restarted.replay(exchanges)

    assert (
        restarted.graph.snapshot(),
        restarted.cursor_offsets(),
        restarted.findings(),
    ) == expected
    assert restarted.claim_extractor._broker.requests == []


def test_replay_accepts_three_historical_relation_inventories_and_restores_roles(
    tmp_path: Path,
) -> None:
    roles = (
        ConfiguredRole(
            role_id="orchestrator",
            kind="orchestrator",
            markers=("role-orchestrator",),
        ),
        ConfiguredRole(
            role_id="worker-a",
            kind="worker",
            markers=("role-worker-a",),
        ),
        ConfiguredRole(
            role_id="worker-b",
            kind="worker",
            markers=("role-worker-b",),
        ),
    )
    relation_inventory = (
        MissionRelation(
            session_alias="session-orchestrator",
            mission_id="mission-review",
            role_id="orchestrator",
            assignment_id="assignment-orchestrator",
            source_digest="1" * 64,
            corroborating_role_ids=("orchestrator",),
            relation_kind="mission_relation",
        ),
        MissionRelation(
            session_alias="session-worker-a",
            mission_id="mission-review",
            role_id="worker-a",
            assignment_id="assignment-worker-a",
            source_digest="2" * 64,
            corroborating_role_ids=("worker-a",),
            relation_kind="assignment",
        ),
        MissionRelation(
            session_alias="session-worker-b",
            mission_id="mission-review",
            role_id="worker-b",
            assignment_id="assignment-worker-b",
            source_digest="3" * 64,
            corroborating_role_ids=("worker-b",),
            relation_kind="assignment",
        ),
    )
    exchanges = (
        _exchange(
            1,
            hook_event_name="SessionStart",
            session_alias="session-orchestrator",
            prompt="role-orchestrator",
        ),
        _exchange(
            2,
            hook_event_name="SessionStart",
            session_alias="session-worker-a",
            prompt="role-worker-a",
        ),
        _exchange(
            3,
            hook_event_name="SessionStart",
            session_alias="session-worker-b",
            prompt="role-worker-b",
        ),
        _exchange(
            4,
            hook_event_name="SessionStart",
            session_alias="session-quarantined",
            prompt="role-worker-a role-worker-b",
        ),
    )
    live_relations = LiveMissionRelations("mission-review")
    live_relations.allow(relation_inventory[0])
    historical_digests = [live_relations.digest]
    live = _controller(
        tmp_path,
        relations=live_relations,
        roles=roles,
    )
    live.start()
    try:
        live.after_append(exchanges[0])
        assert live.drain(timeout=2.0)
        live_relations.allow(relation_inventory[1])
        historical_digests.append(live_relations.digest)
        live.after_append(exchanges[1])
        assert live.drain(timeout=2.0)
        live_relations.allow(relation_inventory[2])
        historical_digests.append(live_relations.digest)
        live.after_append(exchanges[2])
        assert live.drain(timeout=2.0)
        live.after_append(exchanges[3])
        assert live.drain(timeout=2.0)
    finally:
        assert live.stop(timeout=2.0)

    role_records = tuple(
        record
        for record in live.journal.records()
        if isinstance(record, RoleDecisionRecord)
    )
    assert tuple(record.relations_digest for record in role_records) == (
        *historical_digests,
        historical_digests[-1],
    )
    assert len(set(historical_digests)) == 3
    assert live.role_mapper.assignments() == {
        "orchestrator": "session-orchestrator",
        "worker-a": "session-worker-a",
        "worker-b": "session-worker-b",
    }
    assert live.role_mapper.decisions()[-1].status == "quarantined"

    final_relations = FrozenMissionRelations(
        "mission-review",
        relation_inventory,
    )
    replayed = _controller(
        tmp_path,
        relations=final_relations,
        roles=roles,
    )
    replayed.replay(exchanges)

    assert replayed.role_mapper.assignments() == live.role_mapper.assignments()
    assert replayed.role_mapper.decisions() == live.role_mapper.decisions()
    assert {
        alias: replayed.role_mapper.can_target(alias)
        for alias in (
            "session-orchestrator",
            "session-worker-a",
            "session-worker-b",
            "session-quarantined",
        )
    } == {
        alias: live.role_mapper.can_target(alias)
        for alias in (
            "session-orchestrator",
            "session-worker-a",
            "session-worker-b",
            "session-quarantined",
        )
    }


def test_replay_rejects_role_decision_when_cited_relation_is_absent(
    tmp_path: Path,
) -> None:
    role = ConfiguredRole(
        role_id="worker-a",
        kind="worker",
        markers=("role-worker-a",),
    )
    missing_relation = MissionRelation(
        session_alias="session-worker-a",
        mission_id="mission-review",
        role_id=role.role_id,
        assignment_id="assignment-worker-a",
        source_digest="a" * 64,
        corroborating_role_ids=(role.role_id,),
        relation_kind="assignment",
    )
    historical_relations = FrozenMissionRelations(
        "mission-review",
        (missing_relation,),
    )
    final_relations = FrozenMissionRelations("mission-review", ())
    exchange = _exchange(
        1,
        hook_event_name="SessionStart",
        session_alias=missing_relation.session_alias,
        prompt="role-worker-a",
    )
    persisted = RoleMapper((role,), historical_relations).observe(exchange.envelope)
    assert persisted.status == "assigned"
    assert persisted.evidence_digests == (missing_relation.source_digest,)
    assert final_relations.get(missing_relation.session_alias) is None

    writer = _controller(
        tmp_path,
        relations=final_relations,
        roles=(role,),
    )
    writer.journal.append(
        "role_decision",
        ledger_sequence=exchange.ledger_sequence,
        event_id=exchange.envelope.event_id,
        relations_digest=historical_relations.digest,
        **RoleDecisionRecord.decision_fields(persisted),
    )

    replayed = _controller(
        tmp_path,
        relations=final_relations,
        roles=(role,),
    )
    with pytest.raises(
        ReviewJournalCorruptionError,
        match="role decision relation inventory diverged",
    ):
        replayed.replay((exchange,))


def test_replay_rejects_forged_role_decision_relations_digest(
    tmp_path: Path,
) -> None:
    role = ConfiguredRole(
        role_id="worker-a",
        kind="worker",
        markers=("role-worker-a",),
    )
    relation = MissionRelation(
        session_alias="session-worker-a",
        mission_id="mission-review",
        role_id=role.role_id,
        assignment_id="assignment-worker-a",
        source_digest="a" * 64,
        corroborating_role_ids=(role.role_id,),
        relation_kind="assignment",
    )
    relations = FrozenMissionRelations("mission-review", (relation,))
    exchange = _exchange(
        1,
        hook_event_name="SessionStart",
        session_alias=relation.session_alias,
        prompt="role-worker-a",
    )
    persisted = RoleMapper((role,), relations).observe(exchange.envelope)
    writer = _controller(
        tmp_path,
        relations=relations,
        roles=(role,),
    )
    writer.journal.append(
        "role_decision",
        ledger_sequence=exchange.ledger_sequence,
        event_id=exchange.envelope.event_id,
        relations_digest="f" * 64,
        **RoleDecisionRecord.decision_fields(persisted),
    )

    replayed = _controller(
        tmp_path,
        relations=relations,
        roles=(role,),
    )
    with pytest.raises(
        ReviewJournalCorruptionError,
        match="role decision relation inventory diverged",
    ):
        replayed.replay((exchange,))


def test_replay_persists_degradation_byte_identically_without_wall_clock(
    tmp_path: Path,
) -> None:
    exchange = _exchange(1, hook_event_name="Stop")
    roots = (tmp_path / "first", tmp_path / "second")
    for root in roots:
        writer = _controller(root)
        writer.journal.append(
            "extraction_outcome",
            ledger_sequence=exchange.ledger_sequence,
            event_id=exchange.envelope.event_id,
            trigger_kinds=("completion_attempt",),
            status="failed",
            quarantine_reason="boundary_fault",
            claims=(),
            derived_evidence=(),
        )
    journal_paths = tuple(root / "run" / "review.jsonl" for root in roots)
    assert journal_paths[0].read_bytes() == journal_paths[1].read_bytes()

    first = _controller(roots[0], clock=lambda: 101)
    second = _controller(roots[1], clock=lambda: 202)
    first.replay((exchange,))
    second.replay((exchange,))

    assert journal_paths[0].read_bytes() == journal_paths[1].read_bytes()
    degraded = tuple(
        record
        for record in first.journal.records()
        if isinstance(record, ControllerDegradedRecord)
    )
    assert len(degraded) == 1
    assert degraded[0].observed_at == exchange.envelope.observed_at


def test_primary_replay_without_ephemeral_handoff_fails_closed(
    tmp_path: Path,
) -> None:
    exchange = _exchange(1)
    controller = _controller(tmp_path, transcript_mode="primary")
    controller.journal.append(
        "exchange_projection",
        ledger_sequence=1,
        event_id=exchange.envelope.event_id,
        exchange_id=exchange.exchange_id,
        response_digest=exchange.response.response_digest,
    )

    restarted = _controller(tmp_path, transcript_mode="primary")
    restarted.replay((exchange,))

    assert restarted.non_releasable_reason == "missing_ephemeral_context_replay"
    assert not any(
        isinstance(record, TranscriptBatchRecord)
        for record in restarted.journal.records()
    )


@pytest.mark.parametrize("completed", [False, True])
def test_probe_restart_cancels_pending_once_and_never_reruns_completed(
    tmp_path: Path,
    completed: bool,
) -> None:
    exchange = _exchange(1)
    first = _controller(tmp_path)
    first.after_append(exchange)
    first.start()
    assert first.drain(timeout=2.0)
    assert first.stop(timeout=2.0)
    finding = _finding("completed" if completed else "pending")
    snapshot_digest = "7" * 64
    probe_id = f"probe-{finding.dedup_key[:16]}"
    first.journal.append(
        "finding_snapshot",
        ledger_sequence=1,
        event_id=exchange.envelope.event_id,
        graph_digest=first.graph.digest(),
        findings=(JournalFinding.from_finding(finding),),
        validation_overlap_status="active",
    )
    first.journal.append(
        "probe_job",
        ledger_sequence=1,
        event_id=exchange.envelope.event_id,
        probe_id=probe_id,
        finding_dedup_key=finding.dedup_key,
        snapshot_digest=snapshot_digest,
        risk_category="public_contract",
        observed_at=1,
    )
    if completed:
        first.journal.append(
            "probe_outcome",
            ledger_sequence=1,
            event_id=exchange.envelope.event_id,
            probe_id=probe_id,
            finding_dedup_key=finding.dedup_key,
            snapshot_digest=snapshot_digest,
            assessment=None,
            usage={"status": "unavailable"},
            quarantine_reason="timeout",
        )

    restarted = _controller(tmp_path)
    restarted.replay((exchange,))
    cancellations = tuple(
        record
        for record in restarted.journal.records()
        if isinstance(record, ProbeCancellationRecord)
        and record.finding_dedup_key == finding.dedup_key
    )

    assert restarted.probe_scheduler.enqueue_calls == 0
    assert restarted.probe_scheduler.run_calls == 0
    assert len(cancellations) == (0 if completed else 1)
    if cancellations:
        assert cancellations[0].reason == "restart_pending"

    replayed_again = _controller(tmp_path)
    replayed_again.replay((exchange,))
    repeated_cancellations = tuple(
        record
        for record in replayed_again.journal.records()
        if isinstance(record, ProbeCancellationRecord)
        and record.finding_dedup_key == finding.dedup_key
    )
    assert len(repeated_cancellations) == len(cancellations)


def test_unsafe_probe_outcome_journals_boundary_disable_first(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    controller.probe_scheduler._runner = SimpleNamespace(
        _approved_boundary_policy_digest="a" * 64
    )
    identity = _ProbeIdentity(
        ledger_sequence=1,
        event_id="event-1",
        probe_id="probe-unsafe-order",
        finding_dedup_key="b" * 64,
        snapshot_digest="c" * 64,
        risk_category="security",
    )
    outcome = ProbeOutcome(
        snapshot_digest=identity.snapshot_digest,
        assessment=None,
        usage=ProbeUsage(status="unavailable"),
        quarantine=ProbeQuarantine(reason="unsafe_boundary"),
    )

    controller._record_probe_outcome(_exchange(1), identity, outcome)

    record_types = tuple(
        record.record_type for record in controller.journal.records()
    )
    assert record_types == ("probe_boundary_disabled", "probe_outcome")
    assert controller.probe_boundary_disabled is True


def test_replay_after_boundary_disable_before_outcome_stays_disabled(
    tmp_path: Path,
) -> None:
    exchange = _exchange(1)
    first = _controller(tmp_path)
    first.after_append(exchange)
    first.start()
    assert first.drain(timeout=2.0)
    assert first.stop(timeout=2.0)
    finding = _finding("boundary-disable-crash")
    snapshot_digest = "9" * 64
    probe_id = f"probe-{finding.dedup_key[:16]}"
    first.journal.append(
        "finding_snapshot",
        ledger_sequence=1,
        event_id=exchange.envelope.event_id,
        graph_digest=first.graph.digest(),
        findings=(JournalFinding.from_finding(finding),),
        validation_overlap_status="active",
    )
    first.journal.append(
        "probe_job",
        ledger_sequence=1,
        event_id=exchange.envelope.event_id,
        probe_id=probe_id,
        finding_dedup_key=finding.dedup_key,
        snapshot_digest=snapshot_digest,
        risk_category="public_contract",
        observed_at=1,
    )
    first.journal.append(
        "probe_boundary_disabled",
        ledger_sequence=1,
        event_id=exchange.envelope.event_id,
        boundary_digest="a" * 64,
        stopped_at=1,
    )

    restarted = _controller(tmp_path)
    restarted.probe_scheduler._runner = SimpleNamespace(
        _approved_boundary_policy_digest="a" * 64
    )
    restarted.replay((exchange,))
    records = restarted.journal.records()
    record_types = tuple(record.record_type for record in records)

    assert restarted.probe_boundary_disabled is True
    assert restarted.probe_scheduler.enqueue_calls == 0
    assert restarted.probe_scheduler.run_calls == 0
    assert "probe_outcome" not in record_types
    assert record_types.index("probe_boundary_disabled") < record_types.index(
        "probe_cancellation"
    )


def test_stop_cancels_only_pending_completion_probe_without_degradation(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    finding = _finding("completion")
    identity = _ProbeIdentity(
        ledger_sequence=1,
        event_id="event-1",
        probe_id=f"probe-{finding.dedup_key[:16]}",
        finding_dedup_key=finding.dedup_key,
        snapshot_digest="8" * 64,
        risk_category="public_contract",
    )
    controller.journal.append(
        "probe_job",
        ledger_sequence=identity.ledger_sequence,
        event_id=identity.event_id,
        probe_id=identity.probe_id,
        finding_dedup_key=identity.finding_dedup_key,
        snapshot_digest=identity.snapshot_digest,
        risk_category=identity.risk_category,
        observed_at=1,
    )
    controller._probe_jobs[identity.finding_dedup_key] = identity
    controller._known_probe_risks.add(identity.finding_dedup_key)
    aborted = threading.Event()
    ready = threading.Event()

    class BlockingScheduler:
        def abort(self) -> bool:
            aborted.set()
            return True

    controller.probe_scheduler = BlockingScheduler()

    def pending_probe() -> None:
        with controller._drain_condition:
            controller._active_items = 1
            controller._active_probe = identity
            ready.set()
            controller._drain_condition.notify_all()
        aborted.wait(2.0)
        with controller._drain_condition:
            controller._active_probe = None
            controller._active_items = 0
            controller._drain_condition.notify_all()

    controller._worker = threading.Thread(target=pending_probe)
    controller._worker.start()
    assert ready.wait(1.0)
    assert controller.drain(timeout=0.1) is True

    assert controller.stop(timeout=1.0) is True
    cancellations = tuple(
        record
        for record in controller.journal.records()
        if isinstance(record, ProbeCancellationRecord)
    )
    assert len(cancellations) == 1
    assert cancellations[0].reason == "probe_pending_at_completion"
    assert controller.releasable is True
    with pytest.raises(TranscriptError, match="closed"):
        controller.transcript_reader.read_fallback(_envelope(2))


def test_stop_aborts_extraction_and_probe_before_worker_join(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    events: list[str] = []

    class ExtractionBoundary:
        def abort(self) -> bool:
            events.append("extraction_abort")
            return True

    class ProbeBoundary:
        def abort(self) -> bool:
            events.append("probe_abort")
            return True

    class JoinedWorker:
        def join(self, _timeout: float) -> None:
            assert events == ["extraction_abort", "probe_abort"]
            events.append("join")

        def is_alive(self) -> bool:
            return False

    controller.claim_extractor = ExtractionBoundary()
    controller.probe_scheduler = ProbeBoundary()
    controller._worker = JoinedWorker()

    assert controller.stop(timeout=1.0) is True
    assert events == ["extraction_abort", "probe_abort", "join"]


def test_stop_does_not_record_truthful_completion_cancellation_without_ack(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    identity = _ProbeIdentity(
        ledger_sequence=1,
        event_id="event-1",
        probe_id="probe-no-ack",
        finding_dedup_key="d" * 64,
        snapshot_digest="e" * 64,
        risk_category="security",
    )
    controller._active_items = 1
    controller._active_probe = identity

    class UnacknowledgedScheduler:
        def abort(self) -> bool:
            return False

    controller.probe_scheduler = UnacknowledgedScheduler()

    assert controller.stop(timeout=0.1) is False
    assert not any(
        isinstance(record, ProbeCancellationRecord)
        and record.reason == "probe_pending_at_completion"
        for record in controller.journal.records()
    )


def test_stop_timeout_keeps_shutdown_non_releasable(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    abort_entered = threading.Event()
    release_abort = threading.Event()

    class BlockingAbortScheduler:
        def abort(self) -> bool:
            abort_entered.set()
            release_abort.wait(1.0)
            return True

    controller.probe_scheduler = BlockingAbortScheduler()

    assert controller.stop(timeout=0.01) is False
    assert abort_entered.is_set()
    assert controller.releasable is False
    release_abort.set()


def test_acknowledgment_binding_uses_projection_order_not_wall_time(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    intervention_id = "intervention-same-second"
    intervention = SimpleNamespace(
        intervention_id=intervention_id,
        target_session="session-worker",
        repair_assignment=None,
        state="delivered",
        transition_history=(
            SimpleNamespace(
                observed_at=20,
                action="delivered",
                transition_id="transition-delivered",
            ),
        ),
    )
    controller.router = SimpleNamespace(
        snapshot=lambda: SimpleNamespace(interventions=(intervention,))
    )
    observation = TranscriptObservation(
        evidence=EvidenceRecord(
            provenance_status="hook_authenticated",
            redaction_status="clean",
            evidence_id="evidence-same-second-ack",
            run_id=RUN_ID,
            session_alias="session-worker",
            kind="assistant",
            source="transcript",
            locator="transcript-worker@same-second",
            digest="a" * 64,
            observed_at=20,
        ),
        content={"kind": "assistant", "text": "Acknowledged"},
        shadow_marker_ids=(intervention_id,),
    )
    transition_exchange = _exchange(
        20,
        guidance_ids=(intervention_id,),
        transition_ids=("transition-delivered",),
    )

    assert controller._bind_transcript_interventions(
        transition_exchange, (observation,)
    ) == ()
    bound = controller._bind_transcript_interventions(
        _exchange(20), (observation,)
    )
    assert len(bound) == 1
    assert bound[0].kind == "target_acknowledgment"


def test_correction_binding_uses_locator_or_owning_session(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    finding = _finding("correction-binding")
    intervention = SimpleNamespace(
        intervention_id="intervention-correction",
        finding_dedup_key=finding.dedup_key,
        target_session="session-worker",
        repair_assignment=None,
        state="acknowledged",
        transition_history=(
            SimpleNamespace(
                observed_at=20,
                action="acknowledged",
                transition_id="transition-acknowledged",
            ),
        ),
    )
    controller.router = SimpleNamespace(
        snapshot=lambda: SimpleNamespace(interventions=(intervention,))
    )
    controller._findings = (finding,)
    exchange = _exchange(20)

    def observation(
        suffix: str,
        *,
        kind: str,
        content: dict[str, object],
    ) -> TranscriptObservation:
        return TranscriptObservation(
            evidence=EvidenceRecord(
                provenance_status="hook_authenticated",
                redaction_status="clean",
                evidence_id=f"evidence-{suffix}",
                run_id=RUN_ID,
                session_alias="session-worker",
                kind=kind,
                source="transcript",
                locator=f"transcript-worker@{suffix}",
                digest=hashlib.sha256(suffix.encode()).hexdigest(),
                observed_at=20,
            ),
            content=content,
            correction_candidate=True,
        )

    unbound_test = observation(
        "unbound-test",
        kind="test",
        content={
            "kind": "test",
            "command": "pytest",
            "result": {"success": True},
        },
    )
    unrelated_diff = observation(
        "unrelated-diff",
        kind="diff",
        content={
            "kind": "diff",
            "file": "src/unrelated.py",
            "diff": "+ unrelated",
        },
    )
    matching_diff = observation(
        "matching-diff",
        kind="diff",
        content={
            "kind": "diff",
            "file": " SCHEMA.JSON#/AMOUNT ",
            "diff": "+ corrected",
        },
    )
    explicit_test = observation(
        "explicit-test",
        kind="test",
        content={
            "kind": "test",
            "intervention_id": intervention.intervention_id,
            "command": "pytest",
            "result": {"success": True},
        },
    )

    assert controller._bind_transcript_interventions(
        exchange, (unrelated_diff,)
    ) == ()
    current_ack_exchange = _exchange(
        20, transition_ids=("transition-acknowledged",)
    )
    assert controller._bind_transcript_interventions(
        current_ack_exchange, (matching_diff,)
    ) == ()
    diff_binding = controller._bind_transcript_interventions(
        exchange, (matching_diff,)
    )
    assert len(diff_binding) == 1
    assert diff_binding[0].intervention_id == intervention.intervention_id
    assert diff_binding[0].source == "target_diff_transcript"
    test_binding = controller._bind_transcript_interventions(
        exchange, (unbound_test,)
    )
    assert len(test_binding) == 1
    assert test_binding[0].intervention_id == intervention.intervention_id
    assert test_binding[0].source == "target_test_transcript"
    explicit_binding = controller._bind_transcript_interventions(
        exchange, (explicit_test,)
    )
    assert len(explicit_binding) == 1
    assert explicit_binding[0].intervention_id == intervention.intervention_id


def test_correction_binding_accepts_real_factory_edit_and_test_records(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    finding = replace(
        _finding("real-correction"), normalized_locators=("src/webhook.py",)
    )
    intervention = SimpleNamespace(
        intervention_id="intervention-real",
        finding_dedup_key=finding.dedup_key,
        target_session="session-worker",
        repair_assignment=None,
        state="acknowledged",
        transition_history=(
            SimpleNamespace(
                observed_at=20,
                action="acknowledged",
                transition_id="transition-acknowledged",
            ),
        ),
    )
    controller.router = SimpleNamespace(
        snapshot=lambda: SimpleNamespace(interventions=(intervention,))
    )
    controller._findings = (finding,)
    exchange = _exchange(20)

    def tool_observation(
        suffix: str, content: dict[str, object]
    ) -> TranscriptObservation:
        return TranscriptObservation(
            evidence=EvidenceRecord(
                provenance_status="hook_authenticated",
                redaction_status="clean",
                evidence_id=f"evidence-{suffix}",
                run_id=RUN_ID,
                session_alias="session-worker",
                kind="tool",
                source="transcript",
                locator=f"transcript-worker@{suffix}",
                digest=hashlib.sha256(suffix.encode()).hexdigest(),
                observed_at=20,
            ),
            content={"kind": "tool", **content},
            correction_candidate=True,
        )

    edit_record = tool_observation(
        "real-edit",
        {
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/webhook.py"},
            "tool_response": {"exit_code": 0},
        },
    )
    test_record = tool_observation(
        "real-test",
        {
            "tool_name": "Execute",
            "tool_input": {"command": "python3 -m pytest -q src/webhook.py"},
            "tool_response": {"exit_code": 0},
        },
    )
    unrelated_edit = tool_observation(
        "unrelated-edit",
        {
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/unrelated.py"},
            "tool_response": {"exit_code": 0},
        },
    )

    bound = controller._bind_transcript_interventions(
        exchange, (edit_record, test_record, unrelated_edit)
    )

    assert [item.source for item in bound] == [
        "target_diff_transcript",
        "target_test_transcript",
    ]
    assert all(
        item.intervention_id == intervention.intervention_id for item in bound
    )
    assert all(item.kind == "target_correction" for item in bound)


def _sibling_observation(
    suffix: str, content: dict[str, object], session: str
) -> TranscriptObservation:
    return TranscriptObservation(
        evidence=EvidenceRecord(
            provenance_status="hook_authenticated",
            redaction_status="clean",
            evidence_id=f"evidence-{suffix}",
            run_id=RUN_ID,
            session_alias=session,
            kind="tool",
            source="transcript",
            locator=f"transcript-{session}@{suffix}",
            digest=hashlib.sha256(suffix.encode()).hexdigest(),
            observed_at=21,
        ),
        content={"kind": "tool", **content},
        correction_candidate=True,
    )


def _delivered_intervention(finding: Finding) -> SimpleNamespace:
    return SimpleNamespace(
        intervention_id="intervention-cross",
        finding_dedup_key=finding.dedup_key,
        target_session="session-worker",
        repair_assignment=None,
        state="delivered",
        transition_history=(
            SimpleNamespace(
                observed_at=20,
                action="delivered",
                transition_id="transition-delivered",
            ),
        ),
    )


def test_correction_binding_accepts_proof_from_another_finding_session(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    finding = replace(
        _finding("cross-session"),
        normalized_locators=("src/webhook.py",),
        target_sessions=("session-sibling", "session-worker"),
    )
    intervention = _delivered_intervention(finding)
    controller.router = SimpleNamespace(
        snapshot=lambda: SimpleNamespace(interventions=(intervention,))
    )
    controller._findings = (finding,)
    exchange = _exchange(21, session_alias="session-sibling")
    edit_record = _sibling_observation(
        "sibling-edit",
        {
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/webhook.py"},
            "tool_response": {"exit_code": 0},
        },
        "session-sibling",
    )
    test_record = _sibling_observation(
        "sibling-test",
        {
            "tool_name": "Execute",
            "tool_input": {"command": "python3 -m pytest -q"},
            "tool_response": {"exit_code": 0},
        },
        "session-sibling",
    )

    bound = controller._bind_transcript_interventions(
        exchange, (edit_record, test_record)
    )

    assert [item.source for item in bound] == [
        "target_diff_transcript",
        "target_test_transcript",
    ]
    assert all(item.intervention_id == "intervention-cross" for item in bound)


def test_a_test_outside_the_finding_sessions_never_binds(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    finding = replace(
        _finding("outsider"),
        normalized_locators=("src/webhook.py",),
        target_sessions=("session-worker",),
    )
    intervention = _delivered_intervention(finding)
    controller.router = SimpleNamespace(
        snapshot=lambda: SimpleNamespace(interventions=(intervention,))
    )
    controller._findings = (finding,)
    exchange = _exchange(21, session_alias="session-outsider")
    test_record = _sibling_observation(
        "outsider-test",
        {
            "tool_name": "Execute",
            "tool_input": {"command": "python3 -m pytest -q"},
            "tool_response": {"exit_code": 0},
        },
        "session-outsider",
    )

    bound = controller._bind_transcript_interventions(exchange, (test_record,))

    assert bound == ()


def test_correction_binding_accepts_absolute_factory_paths_after_delivery(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    finding = replace(
        _finding("absolute-correction"), normalized_locators=("src/webhook.py",)
    )
    intervention = SimpleNamespace(
        intervention_id="intervention-absolute",
        finding_dedup_key=finding.dedup_key,
        target_session="session-worker",
        repair_assignment=None,
        state="delivered",
        transition_history=(
            SimpleNamespace(
                observed_at=20,
                action="delivered",
                transition_id="transition-delivered",
            ),
        ),
    )
    controller.router = SimpleNamespace(
        snapshot=lambda: SimpleNamespace(interventions=(intervention,))
    )
    controller._findings = (finding,)
    absolute = f"{tmp_path}/src/webhook.py"
    observation = TranscriptObservation(
        evidence=EvidenceRecord(
            provenance_status="hook_authenticated",
            redaction_status="clean",
            evidence_id="evidence-absolute",
            run_id=RUN_ID,
            session_alias="session-worker",
            kind="tool",
            source="transcript",
            locator="transcript-worker@absolute",
            digest=hashlib.sha256(b"absolute").hexdigest(),
            observed_at=20,
        ),
        content={
            "kind": "tool",
            "tool_name": "ApplyPatch",
            "tool_input": {
                "input": f"*** Begin Patch\n*** Update File: {absolute}\n"
            },
            "tool_response": {"success": True},
        },
        correction_candidate=True,
    )

    bound = controller._bind_transcript_interventions(_exchange(20), (observation,))

    assert [item.source for item in bound] == ["target_diff_transcript"]
    assert bound[0].intervention_id == "intervention-absolute"



@pytest.mark.parametrize(
    ("transcript_kind", "state", "transition_action", "bound_source"),
    [
        (
            "assistant",
            "delivered",
            "delivered",
            "target_assistant_transcript",
        ),
        (
            "diff",
            "acknowledged",
            "acknowledged",
            "target_diff_transcript",
        ),
        (
            "test",
            "acknowledged",
            "acknowledged",
            "target_test_transcript",
        ),
    ],
)
def test_intervention_bound_evidence_stays_out_of_untrusted_extraction(
    tmp_path: Path,
    transcript_kind: str,
    state: str,
    transition_action: str,
    bound_source: str,
) -> None:
    controller = _controller(tmp_path, transcript_mode="primary")
    controller.transcript_reader.provenance_status = "untrusted_provenance"
    intervention_id = f"intervention-{transcript_kind}"
    intervention = SimpleNamespace(
        intervention_id=intervention_id,
        target_session="session-worker",
        repair_assignment=None,
        state=state,
        transition_history=(
            SimpleNamespace(
                action=transition_action,
                transition_id=f"transition-{transition_action}",
            ),
        ),
    )
    router = _SnapshotRouter(controller.graph)
    router.snapshot = lambda: SimpleNamespace(interventions=(intervention,))
    controller.router = router

    transcript_record: dict[str, object]
    if transcript_kind == "assistant":
        transcript_record = {
            "kind": "assistant",
            "text": f"[shadow:{intervention_id}] correcting now",
            "observed_at": 20,
        }
    elif transcript_kind == "diff":
        transcript_record = {
            "kind": "diff",
            "file": "src/api/schema.py",
            "diff": "+ corrected",
            "intervention_id": intervention_id,
            "observed_at": 20,
        }
    else:
        transcript_record = {
            "kind": "test",
            "command": "python -m pytest tests/test_schema.py -q",
            "result": {"success": True},
            "intervention_id": intervention_id,
            "observed_at": 20,
        }
    transcript = tmp_path / "transcripts" / "worker.jsonl"
    transcript.write_text(
        json.dumps(transcript_record) + "\n",
        encoding="utf-8",
    )

    base_exchange = _exchange(20, hook_event_name="PostToolUse")
    envelope = base_exchange.envelope.model_copy(
        update={
            "provenance_status": "untrusted_provenance",
            "payload": {
                "tool_name": "Edit",
                "tool_input": {
                    "file_path": str(tmp_path / "src/api/schema.py"),
                },
                "tool_response": {"exit_code": 0},
            },
        }
    )
    response = base_exchange.response.model_copy(
        update={
            "provenance_status": "untrusted_provenance",
            "request_digest": hook_envelope_digest(envelope),
        }
    )
    exchange = HookExchangeRecord.model_validate(
        base_exchange.model_copy(
            update={
                "provenance_status": "untrusted_provenance",
                "envelope": envelope,
                "response": response,
            }
        ).model_dump(mode="python")
    )

    class TranscriptAnchoredBroker:
        def __init__(self) -> None:
            self.requests: list[ExtractionRequest] = []

        def extract(self, request: ExtractionRequest) -> BrokerAttempt:
            self.requests.append(request)
            request_evidence = request.evidence
            transcript_evidence = next(
                item for item in request_evidence if item.source == "transcript"
            )
            return BrokerAttempt(
                boundary={
                    "factory_home": "clean",
                    "enabled_tools": [],
                    "timeout_seconds": 30,
                    "shadow_activation_stripped": True,
                    "mission_correlation_stripped": True,
                    "internal_session_alias": "session-extractor",
                    "environment_keys": ["PATH"],
                },
                output=[
                    {
                        "subject": "payment contract",
                        "subject_locator": transcript_evidence.locator,
                        "property": "storage unit",
                        "value": "cents",
                        "unit": "cents",
                        "confidence": 0.95,
                        "evidence_ids": [transcript_evidence.evidence_id],
                    }
                ],
            )

        def abort(self) -> bool:
            return True

    broker = TranscriptAnchoredBroker()
    controller.claim_extractor = ClaimExtractor(broker)
    raw_context = SimpleNamespace(
        event_id=envelope.event_id,
        session_alias=envelope.session_alias,
        transcript_alias=envelope.transcript_alias,
        transcript_path=str(transcript),
    )

    try:
        controller._process_exchange(
            SimpleNamespace(exchange=exchange, raw_context=raw_context)
        )

        batch = next(
            record
            for record in controller.journal.records()
            if isinstance(record, TranscriptBatchRecord)
            and record.event_id == envelope.event_id
        )
        bound = tuple(
            item
            for item in batch.evidence
            if item.intervention_id == intervention_id
        )
        assert tuple(item.source for item in bound) == (bound_source,)

        extraction = next(
            record
            for record in controller.journal.records()
            if isinstance(record, ExtractionOutcomeRecord)
            and record.event_id == envelope.event_id
        )
        assert extraction.status == "accepted"
        assert extraction.quarantine_reason is None
        assert len(extraction.claims) == 1
        assert len(broker.requests) == 1
        assert all(
            item.intervention_id is None
            for item in broker.requests[0].evidence
        )

        controller.decide(_envelope(21))
        routed_evidence = router.values[-1]["stored_evidence"]
        assert {
            item.evidence_id for item in bound
        }.issubset(
            item.evidence_id for item in routed_evidence
        )
    finally:
        controller.transcript_reader.close()

def test_stop_defers_guidance_first_planned_in_its_response(
    tmp_path: Path,
) -> None:
    controller = _real_controller(tmp_path)
    ledger = EventLedger(tmp_path / "ledger", run_id=RUN_ID, clock=lambda: 100)
    ledger.start()
    try:
        stop = _envelope(1, hook_event_name="Stop")
        first = ledger.submit(
            stop,
            request_digest=hook_envelope_digest(stop),
            decide=controller.decide,
        )
        first_body = json.loads(first.response_body)

        assert first_body["decision"] == "block"
        assert str(first_body["reason"]).startswith("[shadow:review-pending]")
        queued = controller.router.snapshot().interventions
        assert len(queued) == 2
        assert {item.state for item in queued} == {"queued"}

        post_tool = _envelope(2, hook_event_name="PostToolUse")
        delivered = ledger.submit(
            post_tool,
            request_digest=hook_envelope_digest(post_tool),
            decide=controller.decide,
        )
        context = json.loads(delivered.response_body)["hookSpecificOutput"][
            "additionalContext"
        ]
        assert context.startswith("[shadow:intervention-")
        target = tuple(
            item
            for item in controller.router.snapshot().interventions
            if item.target_session == "session-worker"
        )
        assert len(target) == 1
        assert target[0].state == "delivered"
    finally:
        ledger.stop()


def test_two_findings_use_bounded_delivery_windows_and_completion(
    tmp_path: Path,
) -> None:
    controller = _real_controller(
        tmp_path,
        graph=_conflict_graph(finding_count=2),
    )
    ledger = EventLedger(tmp_path / "ledger", run_id=RUN_ID, clock=lambda: 100)
    ledger.start()
    sequence = 0

    def submit(session_alias: str, hook_event_name: str) -> HookResponseRecord:
        nonlocal sequence
        sequence += 1
        envelope = _envelope(
            sequence,
            hook_event_name=hook_event_name,
            session_alias=session_alias,
        )
        return ledger.submit(
            envelope,
            request_digest=hook_envelope_digest(envelope),
            decide=controller.decide,
        )

    try:
        first_stops = {
            session_alias: submit(session_alias, "Stop")
            for session_alias in ("session-worker", "session-peer")
        }
        for response in first_stops.values():
            body = json.loads(response.response_body)
            assert body["decision"] == "block"
            assert str(body["reason"]).startswith("[shadow:review-pending]")

        queued = controller.router.snapshot().interventions
        assert len(queued) == 4
        assert {item.state for item in queued} == {"queued"}

        delivery_responses = []
        for session_alias in ("session-worker", "session-peer"):
            for _ in range(22):
                delivery_responses.append(submit(session_alias, "PostToolUse"))
        interventions = controller.router.snapshot().interventions
        intervention_ids = {
            item.intervention_id for item in interventions
        }
        assert all(
            sum(
                guidance_id in intervention_ids
                for guidance_id in response.guidance_ids
            )
            <= 1
            for response in delivery_responses
        )
        assert {item.state for item in interventions} == {"delivered"}
        assert {
            sum(
                transition.action == "delivered"
                for transition in item.transition_history
            )
            for item in interventions
        } == {3}

        acknowledged = next(
            item
            for item in interventions
            if item.target_session == "session-worker"
        )
        acknowledgment = EvidenceRecord(
            provenance_status="collector_observed",
            redaction_status="clean",
            evidence_id="bounded-window-acknowledgment",
            run_id=RUN_ID,
            session_alias="session-worker",
            kind="target_acknowledgment",
            source="target_assistant_transcript",
            locator="transcript-worker@bounded-window",
            digest=hashlib.sha256(b"bounded-window-acknowledgment").hexdigest(),
            observed_at=sequence + 1,
            intervention_id=acknowledged.intervention_id,
        )
        with controller._state_lock:
            controller.graph.add_evidence(acknowledgment)
            controller._evidence[acknowledgment.evidence_id] = acknowledgment

        correction_holds = [
            submit("session-worker", "Stop"),
            submit("session-worker", "Stop"),
        ]
        assert all(
            json.loads(response.response_body).get("decision") == "block"
            for response in correction_holds
        )
        assert all(
            not str(
                json.loads(response.response_body).get("reason", "")
            ).startswith("[shadow:review-pending]")
            for response in correction_holds
        )
        assert json.loads(
            submit("session-worker", "Stop").response_body
        ) == {}
        assert json.loads(
            submit("session-peer", "Stop").response_body
        ) == {}
        assert controller.completion_blocked is False
        assert controller.termination_required is False

        def is_deferral(exchange: HookExchangeRecord) -> bool:
            body = json.loads(exchange.response.response_body)
            return (
                body.get("decision") == "block"
                and str(body.get("reason", "")).startswith(
                    "[shadow:review-pending]"
                )
            )

        for session_alias in ("session-worker", "session-peer"):
            assert sum(
                is_deferral(exchange)
                for exchange in ledger.exchanges()
                if exchange.envelope.session_alias == session_alias
            ) == 1
    finally:
        ledger.stop()



def test_drain_reconciles_journaled_correction_without_an_extra_response(
    tmp_path: Path,
) -> None:
    controller = _real_controller(tmp_path, transcript_mode="primary")
    transcript = tmp_path / "transcripts" / "worker.jsonl"
    transcript.touch()
    ledger = EventLedger(tmp_path / "ledger", run_id=RUN_ID, clock=lambda: 100)
    ledger.add_after_append(controller.after_append)
    controller.start()
    ledger.start()
    ledger_stopped = False

    def submit(sequence: int, hook_event_name: str) -> HookResponseRecord:
        envelope = _envelope(sequence, hook_event_name=hook_event_name)
        controller.capture_request(
            HookRequest(
                run_id=RUN_ID,
                event_id=envelope.event_id,
                observed_at=envelope.observed_at,
                hook_event_name=envelope.hook_event_name,
                session_id=f"raw-session-{sequence}",
                transcript_path=str(transcript),
                cwd=str(tmp_path),
            ),
            envelope,
        )
        return ledger.submit(
            envelope,
            request_digest=hook_envelope_digest(envelope),
            decide=controller.decide,
        )

    try:
        submit(1, "Stop")
        assert controller.drain(timeout=2.0)
        delivered_response = submit(2, "PostToolUse")
        assert controller.drain(timeout=2.0)
        intervention_id = next(
            item.intervention_id
            for item in controller.router.snapshot().interventions
            if item.target_session == "session-worker"
        )
        assert intervention_id in delivered_response.guidance_ids

        transcript.write_text(
            "\n".join(
                (
                    json.dumps(
                        {
                            "kind": "assistant",
                            "text": f"[shadow:{intervention_id}] correcting now",
                            "observed_at": 3,
                        }
                    ),
                    json.dumps(
                        {
                            "kind": "diff",
                            "file": "src/webhook.py",
                            "diff": "+ corrected",
                            "intervention_id": intervention_id,
                            "observed_at": 3,
                        }
                    ),
                    json.dumps(
                        {
                            "kind": "test",
                            "command": "python -m pytest tests/test_webhook.py -q",
                            "result": {"success": True},
                            "intervention_id": intervention_id,
                            "observed_at": 3,
                        }
                    ),
                )
            )
            + "\n",
            encoding="utf-8",
        )
        final_response = submit(3, "PostToolUse")
        assert json.loads(final_response.response_body) == {}
        assert controller.drain(timeout=2.0)
        ledger.stop()
        ledger_stopped = True

        before_reconciliation = controller.router.intervention(intervention_id)
        assert before_reconciliation is not None
        assert before_reconciliation.state == "delivered"
        target_evidence = tuple(
            evidence
            for record in controller.journal.records()
            if isinstance(record, TranscriptBatchRecord)
            and record.event_id == "event-3"
            for evidence in record.evidence
            if evidence.kind
            in {"target_acknowledgment", "target_correction"}
        )
        assert {evidence.kind for evidence in target_evidence} == {
            "target_acknowledgment",
            "target_correction",
        }
        assert {
            evidence.provenance_status for evidence in target_evidence
        } == {"collector_observed"}
        response_count = len(ledger.exchanges())

        delta = controller.reconcile_final_outage()

        assert delta is not None
        assert len(ledger.exchanges()) == response_count
        resolved = controller.router.intervention(intervention_id)
        assert resolved is not None
        assert resolved.state == "resolved"
        assert resolved.correction_evidence_ids
        assert tuple(
            transition.action for transition in resolved.transition_history[-2:]
        ) == ("corrected", "resolved")
        generation = controller.router.snapshot().generation
        assert controller.reconcile_final_outage() is None
        assert controller.router.snapshot().generation == generation
        delivery_order = tuple(
            guidance_id
            for exchange in ledger.exchanges()
            for guidance_id in exchange.response.guidance_ids
        )
        final_ids = tuple(
            item.intervention_id
            for item in controller.router.snapshot().interventions
        )
        assert controller.stop(timeout=2.0)

        recovered = EventLedger(
            tmp_path / "ledger",
            run_id=RUN_ID,
            clock=lambda: 100,
        )
        replay_graph = _conflict_graph()
        replay_router = InterventionRouter.from_ledger(
            recovered,
            graph=replay_graph,
            capabilities=_real_capabilities(),
            probe_verifier=_REAL_PROBE_VERIFIER,
            now=100,
        )
        replayed = _real_controller(
            tmp_path,
            graph=replay_graph,
            router=replay_router,
            transcript_mode="primary",
        )
        replayed.replay(recovered.exchanges())

        assert tuple(
            guidance_id
            for exchange in recovered.exchanges()
            for guidance_id in exchange.response.guidance_ids
        ) == delivery_order
        assert tuple(
            item.intervention_id
            for item in replayed.router.snapshot().interventions
        ) == final_ids
        assert replayed.router.snapshot().generation == generation
        assert replayed.router.snapshot() == controller.router.snapshot()
        assert replayed.stop(timeout=2.0)
    finally:
        if not ledger_stopped:
            ledger.stop()
        if controller._worker is not None and controller._worker.is_alive():
            controller.stop(timeout=2.0)


def test_repository_changes_require_containment_and_successful_edits(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    root = str(tmp_path)

    def edit_envelope(
        sequence: int, path: str, response: object
    ) -> HookEnvelope:
        return HookEnvelope(
            provenance_status="hook_authenticated",
            redaction_status="clean",
            event_id=f"event-edit-{sequence}",
            source_fingerprint=f"source-edit-{sequence}",
            run_id=RUN_ID,
            session_alias="session-worker",
            transcript_alias="transcript-worker",
            hook_event_name="PostToolUse",
            observed_at=sequence,
            message_digest="e" * 64,
            payload={
                "tool_name": "Edit",
                "tool_input": {"file_path": path},
                "tool_response": response,
            },
        )

    controller._derive_repository_changes(
        edit_envelope(1, f"{root}-evil/src/leak.py", {"exit_code": 0})
    )
    assert controller._observed_repository_changes == {}

    controller._derive_repository_changes(
        edit_envelope(2, f"{root}/src/failed.py", {"exit_code": 1})
    )
    assert controller._observed_repository_changes == {}

    controller._derive_repository_changes(
        edit_envelope(3, f"{root}/src/webhook.py", {"exit_code": 0})
    )

    assert [
        item.locator for item in controller._observed_repository_changes.values()
    ] == ["src/webhook.py"]



def test_probe_configuration_preserves_automatic_paths_and_policy_digest(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    assert controller._probe_repository_paths is None
    controller.probe_scheduler._runner = SimpleNamespace(
        _approved_boundary_policy_digest="a" * 64
    )
    assert controller._approved_probe_boundary_digest() == "a" * 64


def test_disabled_probe_boundary_replays_only_same_approved_policy(
    tmp_path: Path,
) -> None:
    exchange = _exchange(1)
    first = _controller(tmp_path)
    first.journal.append(
        "exchange_projection",
        ledger_sequence=1,
        event_id=exchange.envelope.event_id,
        exchange_id=exchange.exchange_id,
        response_digest=exchange.response.response_digest,
    )
    first.journal.append(
        "probe_boundary_disabled",
        ledger_sequence=1,
        event_id=exchange.envelope.event_id,
        boundary_digest="a" * 64,
        stopped_at=exchange.envelope.observed_at,
    )

    restarted = _controller(tmp_path)
    restarted.probe_scheduler._runner = SimpleNamespace(
        _approved_boundary_policy_digest="a" * 64
    )
    restarted.replay((exchange,))
    assert restarted._boundary_disabled is True

    changed_policy = _controller(tmp_path)
    changed_policy.probe_scheduler._runner = SimpleNamespace(
        _approved_boundary_policy_digest="b" * 64
    )
    with pytest.raises(
        ReviewJournalCorruptionError,
        match="boundary policy changed",
    ):
        changed_policy.replay((exchange,))


def test_probe_waits_for_queue_and_pending_order_at_any_deferral_count(
    tmp_path: Path,
) -> None:
    """Every later projection stays ahead of one costly sealed probe."""

    controller = _real_controller(tmp_path, max_queue_items=64)
    ledger = EventLedger(tmp_path / "ledger", run_id=RUN_ID, clock=lambda: 100)
    ledger.start()
    try:
        for sequence in range(1, 13):
            envelope = _envelope(sequence)
            ledger.submit(
                envelope,
                request_digest=hook_envelope_digest(envelope),
                decide=controller.decide,
            )
    finally:
        ledger.stop()

    exchanges = ledger.exchanges()
    probed: list[int] = []
    controller._schedule_probes = lambda exchange: probed.append(
        exchange.ledger_sequence
    )
    controller.after_append(exchanges[0])
    for exchange in exchanges[2:]:
        controller.after_append(exchange)
    assert controller._queue.item_count == 1
    assert len(controller._pending_order) == 10

    controller._process_exchange(controller._queue.get(timeout=1.0))
    assert probed == []

    controller.after_append(exchanges[1])
    assert controller._queue.item_count == 11
    assert controller._pending_order == {}
    while controller._queue.item_count:
        controller._process_exchange(controller._queue.get(timeout=1.0))

    assert probed == [12]
    controller.transcript_reader.close()


def test_probe_window_reservation_is_atomic_with_projection_intake(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)

    assert controller._reserve_probe_window() is True
    controller.after_append(_exchange(1))
    assert controller._reserve_probe_window() is False
    controller._release_probe_window()
    assert controller._reserve_probe_window() is False

    controller.transcript_reader.close()


def test_unexpected_probe_scheduler_error_is_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = _controller(tmp_path)
    controller._findings = (_finding("scheduler-error"),)
    snapshot = SimpleNamespace(digest="d" * 64)
    monkeypatch.setattr(
        review_module.ProbeSnapshot,
        "from_finding",
        classmethod(lambda _cls, *_args, **_kwargs: snapshot),
    )
    expected = RuntimeError("probe runner failed")

    class FailingScheduler:
        def enqueue(self, _job: object) -> None:
            return None

        def run_next(self) -> None:
            raise expected

    controller.probe_scheduler = FailingScheduler()

    with pytest.raises(RuntimeError) as raised:
        controller._schedule_probes(_exchange(1))

    assert raised.value is expected
    assert controller._probe_window_reserved is False
    assert controller._active_probe is None
    controller.transcript_reader.close()


def test_degraded_controller_rejects_queued_projection_explicitly(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    controller.after_append(_exchange(1))
    item = controller._queue.get(timeout=1.0)
    controller._mark_degraded("injected_degradation")

    with pytest.raises(
        MissionReviewError,
        match="already degraded",
    ):
        controller._process_exchange(item)

    controller.transcript_reader.close()


def test_worker_contains_base_exception_and_records_degradation(
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    controller.after_append(_exchange(1))

    def interrupt(_item: object) -> None:
        raise KeyboardInterrupt("injected worker interruption")

    controller._process_exchange = interrupt
    controller.start()

    assert controller.drain(timeout=1.0) is True
    assert controller.non_releasable_reason == (
        "projection_KeyboardInterrupt"
    )
    assert controller.stop(timeout=1.0) is False
    failure_log = controller.run_dir / "controller-failures.jsonl"
    assert "KeyboardInterrupt" in failure_log.read_text(encoding="utf-8")
