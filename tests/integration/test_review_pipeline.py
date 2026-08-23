from __future__ import annotations

import hashlib

from shadow_mission.extractor import (
    BrokerAttempt,
    ClaimExtractor,
    RecordedExtractionBroker,
)
from shadow_mission.graph import MissionGraph
from shadow_mission.protocol import EvidenceRecord, HookEnvelope
from shadow_mission.roles import RoleDecision
from shadow_mission.rules import (
    DeterministicRules,
    ProbeAssessment,
    ProbeVerifier,
    normalize_value,
)


def boundary(session_alias: str) -> dict[str, object]:
    return {
        "factory_home": "clean",
        "enabled_tools": [],
        "timeout_seconds": 30,
        "shadow_activation_stripped": True,
        "mission_correlation_stripped": True,
        "internal_session_alias": f"extractor-{session_alias}",
        "environment_keys": ["HOME", "PATH"],
    }


def envelope(session_alias: str, observed_at: int) -> HookEnvelope:
    return HookEnvelope(provenance_status="hook_authenticated",
    redaction_status="clean",
    event_id=f"event-{session_alias}",
    source_fingerprint=f"source-{session_alias}",
    run_id="run-review",
    session_alias=session_alias,
    transcript_alias=f"transcript-{session_alias}",
    hook_event_name="Stop", observed_at=observed_at, message_digest="d" * 64, payload={},)


def evidence(session_alias: str, source: str, observed_at: int) -> EvidenceRecord:
    evidence_id = f"evidence-{session_alias}"
    return EvidenceRecord(
        provenance_status="hook_authenticated",
        redaction_status="clean",
        evidence_id=evidence_id,
        run_id="run-review",
        session_alias=session_alias,
        kind=source,
        source=source,
        locator="api-schema.json#/properties/amount",
        digest=hashlib.sha256(evidence_id.encode()).hexdigest(),
        observed_at=observed_at,
    )


def assigned_worker(session_alias: str) -> RoleDecision:
    return RoleDecision(
        session_alias=session_alias,
        role_id=f"role-{session_alias}",
        kind="worker",
        confidence="high",
        status="assigned",
        reason="authoritative replay relation",
        evidence_digests=(hashlib.sha256(session_alias.encode()).hexdigest(),),
    )


def output(value: str, evidence_id: str) -> list[dict[str, object]]:
    return [
        {
            "subject": "payment amount",
            "subject_locator": "api-schema.json#/properties/amount",
            "property": "storage unit",
            "value": value,
            "unit": "cents",
            "confidence": 0.95,
            "evidence_ids": [evidence_id],
        }
    ]


def test_recorded_extraction_projects_to_conflict_and_confirmed_blocker() -> None:
    graph = MissionGraph("run-review")
    claims = []
    for position, (session_alias, value, source) in enumerate(
        (
            ("worker-a", "cents", "database_schema"),
            ("worker-b", "dollars", "repository_contract"),
        ),
        start=1,
    ):
        record = evidence(session_alias, source, position)
        broker = RecordedExtractionBroker(
            BrokerAttempt(
                boundary=boundary(session_alias),
                output=output(value, record.evidence_id),
            )
        )
        outcome = ClaimExtractor(broker).extract(
            envelope(session_alias, position + 10),
            (record,),
        )
        assert outcome.quarantine is None
        assert len(outcome.claims) == 1
        graph.add_role_decision(assigned_worker(session_alias))
        graph.add_evidence(record)
        graph.add_claim(outcome.claims[0])
        claims.extend(outcome.claims)

    signing_key = b"phase-three-integration-probe-key"
    rules = DeterministicRules(
        probe_verifier=ProbeVerifier(signing_key, boundary_digest="9" * 64)
    )
    concern = rules.detect(graph)
    assert tuple(item.rule for item in concern) == ("cross_worker_conflict",)
    assert concern[0].level == "concern"
    assert concern[0].authority.status == "unresolved_same_authority"

    confirmed = ProbeAssessment.create(
        probe_id="probe-payment-contract",
        run_id="run-review",
        finding_dedup_key=concern[0].dedup_key,
        claim_ids=tuple(item.claim_id for item in claims),
        evidence_digests=concern[0].evidence_digests,
        risk_category="money",
        recommended_level="blocker",
        status="confirmed",
        authoritative_value=normalize_value("cents"),
        snapshot_digest="7" * 64,
        boundary_digest="9" * 64,
        boundary_policy_digest="9" * 64,
        signing_key=signing_key,
        observed_at=20,
    )
    evaluation = rules.evaluate(
        graph,
        updated_session="worker-a",
        stored_update=1,
        probes=(confirmed,),
    )
    assert evaluation.matches[0].level == "blocker"
    assert evaluation.deliveries[0].target_session == "worker-a"
    assert evaluation.deliveries[0].finding.probe_status == "confirmed"


def test_quarantined_extraction_cannot_enter_review_graph() -> None:
    record = evidence("worker-a", "database_schema", 1)
    broker = RecordedExtractionBroker(
        BrokerAttempt(
            boundary=boundary("worker-a"),
            output=[{"subject": "missing required fields"}],
        )
    )

    outcome = ClaimExtractor(broker).extract(envelope("worker-a", 2), (record,))
    graph = MissionGraph("run-review")
    graph.add_role_decision(assigned_worker("worker-a"))
    graph.add_evidence(record)

    assert outcome.claims == ()
    assert outcome.quarantine is not None
    assert outcome.quarantine.reason == "malformed_output"
    assert DeterministicRules().detect(graph) == ()
