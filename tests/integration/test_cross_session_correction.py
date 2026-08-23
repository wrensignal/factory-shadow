from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from shadow_mission.extractor import (
    BrokerAttempt,
    ClaimExtractor,
    RecordedExtractionBroker,
)
from shadow_mission.graph import MissionGraph
from shadow_mission.protocol import (
    CapabilityFlags,
    ClaimRecord,
    EvidenceRecord,
    HookEnvelope,
    HookRequest,
    HookResponseRecord,
    InterventionRecord,
    hook_envelope_digest,
)
from shadow_mission.review import MissionReviewController
from shadow_mission.review_journal import TranscriptBatchRecord
from shadow_mission.roles import FrozenMissionRelations, RoleDecision, RoleMapper
from shadow_mission.rules import DeterministicRules, Finding, ProbeVerifier
from shadow_mission.router import InterventionRouter
from shadow_mission.storage import EventLedger
from shadow_mission.transcript import TranscriptReader

RUN_ID = "run-cross-session-correction"
LOCATOR = "src/webhook.py"
_PROBE_KEY = b"cross-session-correction-probe-key"
_PROBE_VERIFIER = ProbeVerifier(_PROBE_KEY, boundary_digest="9" * 64)


class _NoProbeScheduler:
    def enqueue(self, _job: object) -> None:
        return None

    def run_next(self) -> None:
        return None

    def abort(self) -> bool:
        return True


@dataclass(frozen=True)
class _ScenarioResult:
    finding: Finding
    delivered_response: HookResponseRecord
    before_reconciliation: InterventionRecord
    final_intervention: InterventionRecord
    transcript_batch: TranscriptBatchRecord
    reconciliation_changed: bool


def _capabilities() -> CapabilityFlags:
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


def _conflict_graph() -> MissionGraph:
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
                reason="authoritative integration relation",
                evidence_digests=(
                    hashlib.sha256(session_alias.encode()).hexdigest(),
                ),
            )
        )

    for sequence, (session_alias, value) in enumerate(
        (
            ("session-worker", "cents"),
            ("session-peer", "dollars"),
        ),
        start=1,
    ):
        evidence_id = f"conflict-{session_alias}"
        graph.add_evidence(
            EvidenceRecord(
                provenance_status="hook_authenticated",
                redaction_status="clean",
                evidence_id=evidence_id,
                run_id=RUN_ID,
                session_alias=session_alias,
                kind="repository_contract",
                source="repository_contract",
                locator=LOCATOR,
                digest=hashlib.sha256(evidence_id.encode()).hexdigest(),
                observed_at=sequence,
            )
        )
        graph.add_claim(
            ClaimRecord(
                provenance_status="hook_authenticated",
                redaction_status="clean",
                claim_id=f"claim-{session_alias}",
                run_id=RUN_ID,
                session_alias=session_alias,
                subject="payment amount",
                subject_locator=LOCATOR,
                property="storage unit",
                value=value,
                unit="cents",
                confidence=0.95,
                evidence_ids=(evidence_id,),
                observed_at=sequence + 2,
            )
        )
    return graph


def _controller(tmp_path: Path) -> MissionReviewController:
    transcript_root = tmp_path / "transcripts"
    transcript_root.mkdir(parents=True)
    graph = _conflict_graph()
    capabilities = _capabilities()
    relations = FrozenMissionRelations("cross-session-correction", ())
    return MissionReviewController(
        run_id=RUN_ID,
        run_dir=tmp_path / "run",
        relations=relations,
        role_mapper=RoleMapper((), relations),
        transcript_reader=TranscriptReader(
            transcript_root,
            run_id=RUN_ID,
            mode="primary",
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
        graph=graph,
        rules=DeterministicRules(
            capabilities=capabilities,
            probe_verifier=_PROBE_VERIFIER,
        ),
        probe_scheduler=_NoProbeScheduler(),
        router=InterventionRouter(
            run_id=RUN_ID,
            graph=graph,
            capabilities=capabilities,
            probe_verifier=_PROBE_VERIFIER,
        ),
        probe_risk_classifier=lambda finding: finding.risk_category,
        repository_root=tmp_path,
        clock=lambda: 100,
    )


def _envelope(
    sequence: int,
    *,
    hook_event_name: str,
    session_alias: str,
) -> HookEnvelope:
    return HookEnvelope(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        event_id=f"event-{sequence}",
        source_fingerprint=f"source-{sequence}",
        run_id=RUN_ID,
        session_alias=session_alias,
        transcript_alias=f"transcript-{session_alias.removeprefix('session-')}",
        hook_event_name=hook_event_name,
        observed_at=sequence,
        message_digest="d" * 64,
        payload={"prompt": f"prompt {sequence}"},
    )


def _write_proof_transcript(
    transcript: Path,
    *,
    include_diff: bool,
    include_test: bool,
) -> None:
    def factory_message(
        content: dict[str, object],
        *,
        role: str = "assistant",
    ) -> dict[str, object]:
        return {
            "type": "message",
            "message": {"role": role, "content": [content]},
            "observed_at": 3,
        }

    records: list[dict[str, object]] = []
    if include_diff:
        records.extend(
            (
                factory_message(
                    {
                        "type": "tool_use",
                        "id": "tool-edit-success",
                        "name": "Edit",
                        "input": {"file_path": LOCATOR},
                    }
                ),
                factory_message(
                    {
                        "type": "tool_result",
                        "tool_use_id": "tool-edit-success",
                        "content": {"status": "success"},
                        "is_error": False,
                    },
                    role="user",
                ),
            )
        )
    if include_test:
        records.extend(
            (
                factory_message(
                    {
                        "type": "tool_use",
                        "id": "tool-test-pass",
                        "name": "Execute",
                        "input": {
                            "command": (
                                "python -m pytest tests/test_webhook.py -q"
                            )
                        },
                    }
                ),
                factory_message(
                    {
                        "type": "tool_result",
                        "tool_use_id": "tool-test-pass",
                        "content": {"exit_code": 0},
                        "is_error": False,
                    },
                    role="user",
                ),
            )
        )
    transcript.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )


def _run_scenario(
    tmp_path: Path,
    *,
    proof_session: str,
    include_diff: bool,
    include_test: bool,
) -> _ScenarioResult:
    controller = _controller(tmp_path)
    transcripts = {
        session_alias: tmp_path / "transcripts" / f"{session_alias}.jsonl"
        for session_alias in (
            "session-worker",
            "session-peer",
            "session-outsider",
        )
    }
    for transcript in transcripts.values():
        transcript.touch()

    ledger = EventLedger(tmp_path / "ledger", run_id=RUN_ID, clock=lambda: 100)
    ledger.add_after_append(controller.after_append)
    controller.start()
    ledger.start()
    ledger_stopped = False
    controller_stopped = False

    def submit(
        sequence: int,
        hook_event_name: str,
        session_alias: str,
    ) -> HookResponseRecord:
        envelope = _envelope(
            sequence,
            hook_event_name=hook_event_name,
            session_alias=session_alias,
        )
        controller.capture_request(
            HookRequest(
                run_id=RUN_ID,
                event_id=envelope.event_id,
                observed_at=envelope.observed_at,
                hook_event_name=envelope.hook_event_name,
                session_id=f"raw-{session_alias}-{sequence}",
                transcript_path=str(transcripts[session_alias]),
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
        submit(1, "Stop", "session-worker")
        assert controller.drain(timeout=2.0)
        delivered_response = submit(2, "PostToolUse", "session-worker")
        assert controller.drain(timeout=2.0)
        intervention = next(
            item
            for item in controller.router.snapshot().interventions
            if item.target_session == "session-worker"
        )
        assert intervention.intervention_id in delivered_response.guidance_ids
        finding = next(
            item
            for item in controller.findings()
            if item.dedup_key == intervention.finding_dedup_key
        )

        _write_proof_transcript(
            transcripts[proof_session],
            include_diff=include_diff,
            include_test=include_test,
        )
        submit(3, "PostToolUse", proof_session)
        assert controller.drain(timeout=2.0)
        ledger.stop()
        ledger_stopped = True

        before_reconciliation = controller.router.intervention(
            intervention.intervention_id
        )
        assert before_reconciliation is not None
        transcript_batch = next(
            record
            for record in controller.journal.records()
            if isinstance(record, TranscriptBatchRecord)
            and record.event_id == "event-3"
        )
        reconciliation = controller.reconcile_final_outage()
        final_intervention = controller.router.intervention(
            intervention.intervention_id
        )
        assert final_intervention is not None
        assert controller.stop(timeout=2.0)
        controller_stopped = True
        return _ScenarioResult(
            finding=finding,
            delivered_response=delivered_response,
            before_reconciliation=before_reconciliation,
            final_intervention=final_intervention,
            transcript_batch=transcript_batch,
            reconciliation_changed=reconciliation is not None,
        )
    finally:
        if not ledger_stopped:
            ledger.stop()
        if not controller_stopped:
            controller.stop(timeout=2.0)


def _raw_transcript_evidence(
    result: _ScenarioResult,
) -> tuple[EvidenceRecord, ...]:
    return tuple(
        evidence
        for evidence in result.transcript_batch.evidence
        if evidence.source == "transcript"
    )


def _bound_corrections(
    result: _ScenarioResult,
) -> tuple[EvidenceRecord, ...]:
    return tuple(
        evidence
        for evidence in result.transcript_batch.evidence
        if evidence.kind == "target_correction"
        and evidence.intervention_id
        == result.final_intervention.intervention_id
    )


def test_cross_session_source_and_test_proof_resolve_intervention(
    tmp_path: Path,
) -> None:
    result = _run_scenario(
        tmp_path,
        proof_session="session-peer",
        include_diff=True,
        include_test=True,
    )

    assert set(result.finding.target_sessions) == {
        "session-worker",
        "session-peer",
    }
    assert result.finding.normalized_locators == (LOCATOR,)
    assert result.final_intervention.target_session == "session-worker"
    assert result.final_intervention.intervention_id in (
        result.delivered_response.guidance_ids
    )
    assert result.before_reconciliation.state == "delivered"
    assert result.before_reconciliation.correction_evidence_ids == ()
    raw_evidence = _raw_transcript_evidence(result)
    assert len(raw_evidence) == 4
    assert {item.kind for item in raw_evidence} == {"tool"}

    corrections = _bound_corrections(result)
    assert {item.session_alias for item in corrections} == {"session-peer"}
    assert {item.source for item in corrections} == {
        "target_diff_transcript",
        "target_test_transcript",
    }
    assert result.reconciliation_changed is True
    assert result.final_intervention.state == "resolved"
    assert result.final_intervention.terminal_outcome == "corrected"
    assert set(result.final_intervention.correction_evidence_ids) == {
        item.evidence_id for item in corrections
    }
    assert len(result.final_intervention.correction_evidence_ids) == 2
    assert tuple(
        transition.action
        for transition in result.final_intervention.transition_history[-2:]
    ) == ("corrected", "resolved")


def test_cross_session_test_proof_alone_does_not_resolve_intervention(
    tmp_path: Path,
) -> None:
    result = _run_scenario(
        tmp_path,
        proof_session="session-peer",
        include_diff=False,
        include_test=True,
    )

    raw_evidence = _raw_transcript_evidence(result)
    assert len(raw_evidence) == 2
    assert {item.kind for item in raw_evidence} == {"tool"}
    corrections = _bound_corrections(result)
    assert {item.source for item in corrections} == {
        "target_test_transcript"
    }
    assert result.reconciliation_changed is True
    assert result.final_intervention.state == "delivered"
    assert result.final_intervention.state not in {"corrected", "resolved"}
    assert result.final_intervention.terminal_outcome is None
    assert result.final_intervention.correction_evidence_ids == tuple(
        sorted(item.evidence_id for item in corrections)
    )
    assert len(result.final_intervention.correction_evidence_ids) == 1
    assert result.final_intervention.transition_history[-1].action == (
        "correction_evidence_bound"
    )


def test_test_proof_from_non_target_session_does_not_bind(
    tmp_path: Path,
) -> None:
    result = _run_scenario(
        tmp_path,
        proof_session="session-outsider",
        include_diff=False,
        include_test=True,
    )

    assert "session-outsider" not in result.finding.target_sessions
    raw_evidence = _raw_transcript_evidence(result)
    assert len(raw_evidence) == 2
    assert {item.kind for item in raw_evidence} == {"tool"}
    assert _bound_corrections(result) == ()
    assert result.final_intervention.state == "delivered"
    assert result.final_intervention.state not in {"corrected", "resolved"}
    assert result.final_intervention.terminal_outcome is None
    assert result.final_intervention.correction_evidence_ids == ()
